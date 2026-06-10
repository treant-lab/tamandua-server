defmodule TamanduaServer.Registries.DownloadHook do
  @moduledoc """
  Download event handler for AI model registries.

  Automatically triggers security scanning when models are downloaded from
  registries (HuggingFace, MLflow, W&B, Ollama) and creates alerts for
  malicious or suspicious models.

  ## Flow

  1. Download event received → Create pending ModelProvenance record
  2. Spawn async scan task via Task.Supervisor
  3. Scan model using registry's scan_model callback
  4. Update provenance with scan results and risk score
  5. Determine status: clean (< 0.1), suspicious (0.1-0.3), malicious (> 0.3)
  6. If malicious, create alert and broadcast to PubSub
  7. Broadcast scan completion event

  ## Examples

      # Handle model download
      {:ok, provenance_id} = DownloadHook.handle_download(
        "meta-llama/Llama-2-7b-chat-hf",
        TamanduaServer.Registries.HuggingFace
      )

      # Provenance record created with status "pending"
      # Async scan task spawned automatically
  """

  require Logger
  alias TamanduaServer.Registries.ModelProvenance
  alias TamanduaServer.Alerts
  alias TamanduaServer.Repo

  @doc """
  Handles a model download event.

  Creates a pending ModelProvenance record and spawns an async task to scan
  the model. The scan task runs under the application's Task.Supervisor.

  ## Parameters

  - `model_id` - Registry model identifier (e.g., "meta-llama/Llama-2-7b")
  - `registry` - Registry module implementing Registry.Behaviour

  ## Returns

  - `{:ok, provenance_id}` - Provenance record created, scan task started
  - `{:error, changeset}` - Failed to create provenance record
  """
  @spec handle_download(String.t(), module(), map()) :: {:ok, String.t()} | {:error, Ecto.Changeset.t()}
  def handle_download(model_id, registry, opts \\ %{}) do
    registry_name = registry_module_to_name(registry)

    attrs = %{
      model_id: model_id,
      registry: registry_name,
      downloaded_at: DateTime.utc_now(),
      status: "pending"
    }

    # Add optional fields from opts
    attrs =
      attrs
      |> maybe_put(:sha256, opts[:sha256])
      |> maybe_put(:version, opts[:version])
      |> maybe_put(:metadata, opts[:metadata])
      |> maybe_put(:organization_id, opts[:organization_id])

    case create_provenance(attrs) do
      {:ok, provenance} ->
        # Spawn async scan task
        spawn_scan_task(provenance, registry, opts[:config] || %{})
        {:ok, provenance.id}

      {:error, changeset} ->
        Logger.error("Failed to create provenance for #{model_id}: #{inspect(changeset.errors)}")
        {:error, changeset}
    end
  end

  # Creates provenance record
  defp create_provenance(attrs) do
    %ModelProvenance{}
    |> ModelProvenance.changeset(attrs)
    |> Repo.insert()
  end

  # Spawns async scan task
  defp spawn_scan_task(provenance, registry, config) do
    # Use Task.Supervisor for supervised async execution
    # Falls back to Task.async if supervisor not available
    task_supervisor = Application.get_env(:tamandua_server, :task_supervisor, Task)

    case task_supervisor do
      Task ->
        Task.async(fn -> do_scan(provenance, registry, config) end)

      supervisor ->
        Task.Supervisor.start_child(supervisor, fn ->
          do_scan(provenance, registry, config)
        end)
    end
  end

  @doc """
  Performs the actual model scan (async worker).

  This function runs in a separate process and:
  1. Updates status to "scanning"
  2. Calls registry.scan_model/2
  3. Updates provenance with scan result
  4. Broadcasts events
  5. Creates alert if malicious

  ## Parameters

  - `provenance` - ModelProvenance struct
  - `registry` - Registry module
  - `config` - Registry configuration map
  """
  @spec do_scan(ModelProvenance.t(), module(), map()) :: :ok
  def do_scan(provenance, registry, config) do
    # Update status to scanning
    provenance
    |> ModelProvenance.changeset(%{status: "scanning"})
    |> Repo.update()

    # Perform scan
    case registry.scan_model(provenance.model_id, config) do
      {:ok, scan_result} ->
        handle_scan_success(provenance, scan_result)

      {:error, reason} ->
        handle_scan_error(provenance, reason)
    end
  end

  # Handles successful scan
  defp handle_scan_success(provenance, scan_result) do
    risk_score = scan_result.risk_score
    findings = scan_result[:findings] || []
    status = determine_status(risk_score)

    # Update provenance with scan results
    {:ok, updated_provenance} =
      provenance
      |> ModelProvenance.update_scan_result(%{
        scanned_at: DateTime.utc_now(),
        scan_result: scan_result,
        risk_score: risk_score,
        findings_count: length(findings),
        status: status
      })
      |> Repo.update()

    # Broadcast scan completion
    broadcast_scan_completion(updated_provenance)

    # Create alert if malicious
    if status == "malicious" do
      create_alert(updated_provenance, scan_result)
    end

    :ok
  rescue
    error ->
      Logger.error("Error handling scan success for #{provenance.model_id}: #{inspect(error)}")
      :error
  end

  # Handles scan error
  defp handle_scan_error(provenance, reason) do
    Logger.error("Scan failed for #{provenance.model_id}: #{inspect(reason)}")

    provenance
    |> ModelProvenance.update_scan_result(%{
      scanned_at: DateTime.utc_now(),
      scan_result: %{error: inspect(reason)},
      status: "error"
    })
    |> Repo.update()

    # Broadcast error event
    broadcast_scan_error(provenance, reason)

    :ok
  rescue
    error ->
      Logger.error("Error handling scan error for #{provenance.model_id}: #{inspect(error)}")
      :error
  end

  # Determines status from risk score
  defp determine_status(risk_score) when risk_score < 0.1, do: "clean"
  defp determine_status(risk_score) when risk_score < 0.3, do: "suspicious"
  defp determine_status(_risk_score), do: "malicious"

  @doc """
  Creates an alert for a malicious model.

  Alert severity is determined by risk score:
  - > 0.7: critical
  - > 0.5: high
  - else: medium
  """
  @spec create_alert(ModelProvenance.t(), map()) :: {:ok, map()} | {:error, term()}
  def create_alert(provenance, scan_result) do
    risk_score = provenance.risk_score
    findings = scan_result[:findings] || []

    severity = calculate_severity(risk_score)

    alert_attrs = %{
      severity: severity,
      title: "Malicious AI model detected: #{provenance.model_id}",
      description: build_alert_description(provenance, findings),
      mitre_techniques: ["T1059", "T1027"],
      status: "new",
      source_event_id: provenance.id,
      threat_score: risk_score,
      enrichment: %{
        model_id: provenance.model_id,
        registry: provenance.registry,
        risk_score: risk_score,
        findings_count: length(findings),
        provenance_id: provenance.id
      },
      detection_metadata: %{
        source: "model_registry",
        registry: provenance.registry,
        scan_result: scan_result
      }
    }

    # Add organization_id if present
    alert_attrs =
      if provenance.organization_id do
        Map.put(alert_attrs, :organization_id, provenance.organization_id)
      else
        alert_attrs
      end

    case Alerts.create_alert(alert_attrs) do
      {:ok, alert} ->
        Logger.warning("Alert created for malicious model #{provenance.model_id}: #{alert.id}")
        broadcast_alert_created(alert)
        {:ok, alert}

      {:error, changeset} ->
        Logger.error("Failed to create alert for #{provenance.model_id}: #{inspect(changeset.errors)}")
        {:error, changeset}
    end
  end

  # Calculates alert severity from risk score
  defp calculate_severity(risk_score) when risk_score > 0.7, do: "critical"
  defp calculate_severity(risk_score) when risk_score > 0.5, do: "high"
  defp calculate_severity(_risk_score), do: "medium"

  # Builds alert description
  defp build_alert_description(provenance, findings) when is_list(findings) do
    finding_count = length(findings)

    base = "Model scan detected #{finding_count} security finding(s) with risk score #{Float.round(provenance.risk_score, 2)}."

    if finding_count > 0 do
      finding_summary =
        findings
        |> Enum.take(3)
        |> Enum.map(fn f -> "- #{f[:type] || "Unknown"}: #{f[:description] || "No description"}" end)
        |> Enum.join("\n")

      "#{base}\n\nFindings:\n#{finding_summary}"
    else
      base
    end
  end

  defp build_alert_description(provenance, _findings) do
    "Model scan detected security issues with risk score #{Float.round(provenance.risk_score, 2)}."
  end

  # PubSub broadcasting
  defp broadcast_scan_completion(provenance) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "registries:downloads",
      {:model_scanned, provenance.model_id, provenance.status, provenance.risk_score}
    )
  end

  defp broadcast_scan_error(provenance, reason) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "registries:downloads",
      {:scan_error, provenance.model_id, reason}
    )
  end

  defp broadcast_alert_created(alert) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "registries:downloads",
      {:alert_created, alert.id}
    )
  end

  # Helper to convert registry module to name
  defp registry_module_to_name(TamanduaServer.Registries.HuggingFace), do: "huggingface"
  defp registry_module_to_name(TamanduaServer.Registries.MLflow), do: "mlflow"
  defp registry_module_to_name(TamanduaServer.Registries.WandB), do: "wandb"
  defp registry_module_to_name(TamanduaServer.Registries.Ollama), do: "ollama"
  defp registry_module_to_name(module), do: module |> to_string() |> String.split(".") |> List.last() |> String.downcase()

  # Helper to conditionally put values in map
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
