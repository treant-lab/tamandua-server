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
  5. Determine risk status: clean (< 0.1), suspicious (0.1-0.3), malicious (>= 0.3)
     and record the Model Guard enforcement decision in scan_result.model_guard
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

  @suspicious_threshold 0.1
  @block_threshold 0.3

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
  @spec handle_download(String.t(), module(), map()) ::
          {:ok, String.t()} | {:error, Ecto.Changeset.t()}
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
        handle_scan_success(provenance, scan_result, config)

      {:error, reason} ->
        handle_scan_error(provenance, reason, config)
    end
  end

  # Handles successful scan
  defp handle_scan_success(provenance, scan_result, config) do
    risk_score = scan_result.risk_score
    findings = scan_result[:findings] || []
    status = determine_status(risk_score)
    model_guard = build_model_guard_evidence(provenance, scan_result, risk_score, findings, status, config)
    scan_result = Map.put(scan_result, :model_guard, model_guard)

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
  defp handle_scan_error(provenance, reason, config) do
    Logger.error("Scan failed for #{provenance.model_id}: #{inspect(reason)}")

    model_guard = build_model_guard_error_evidence(provenance, reason, config)

    provenance
    |> ModelProvenance.update_scan_result(%{
      scanned_at: DateTime.utc_now(),
      scan_result: %{error: inspect(reason), model_guard: model_guard},
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
  defp determine_status(risk_score) when risk_score < @suspicious_threshold, do: "clean"
  defp determine_status(risk_score) when risk_score < @block_threshold, do: "suspicious"
  defp determine_status(_risk_score), do: "malicious"

  defp build_model_guard_evidence(provenance, scan_result, risk_score, findings, status, config) do
    enforcement = model_guard_enforcement(config)
    decision = model_guard_decision(risk_score)
    findings_count = length(findings)
    package_findings = scan_result_value(scan_result, :package_findings, [])
    external_model_scores = scan_result_value(scan_result, :external_model_scores, [])
    model_consensus = scan_result_value(scan_result, :model_consensus, %{})

    %{
      decision: decision,
      enforcement: enforcement,
      action: model_guard_action(decision, enforcement),
      status: status,
      thresholds: %{
        suspicious: @suspicious_threshold,
        block: @block_threshold
      },
      fp_rationale: fp_rationale(decision, findings_count),
      evidence: %{
        model_id: provenance.model_id,
        registry: provenance.registry,
        risk_score: risk_score,
        findings_count: findings_count,
        highest_severity: highest_severity(findings),
        finding_types: finding_types(findings),
        package_findings: package_findings,
        package_findings_count: evidence_count(package_findings),
        package_scanner: package_scanner_state(package_findings),
        external_model_scores: external_model_scores,
        external_model_scores_count: evidence_count(external_model_scores),
        model_consensus: model_consensus,
        model_consensus_state: model_consensus_state(model_consensus),
        enforcement_note: enforcement_note(enforcement)
      }
    }
  end

  defp model_guard_enforcement(config) do
    value =
      config[:model_guard_enforcement] ||
        config["model_guard_enforcement"] ||
        Application.get_env(:tamandua_server, :model_guard_enforcement, :enforced)

    case value do
      :decision_only -> "decision_only"
      "decision_only" -> "decision_only"
      _ -> "enforced"
    end
  end

  defp build_model_guard_error_evidence(provenance, reason, config) do
    status = model_guard_error_status(reason)
    enforcement = model_guard_enforcement(config)

    %{
      decision: "block",
      enforcement: enforcement,
      action: model_guard_action("block", enforcement),
      status: status,
      thresholds: %{
        suspicious: @suspicious_threshold,
        block: @block_threshold
      },
      fp_rationale:
        "Model Guard could not inspect the artifact; loading fails closed until a clean scan exists.",
      evidence: %{
        model_id: provenance.model_id,
        registry: provenance.registry,
        error: inspect(reason),
        requested_enforcement: model_guard_enforcement(config),
        package_scanner: "not_collected",
        package_findings: [],
        package_findings_count: 0,
        external_model_scores: [],
        external_model_scores_count: 0,
        model_consensus: %{},
        model_consensus_state: "not_collected",
        enforcement_note: "Model Guard scan did not complete; no package scanner or external model consensus evidence was collected."
      }
    }
  end

  defp model_guard_error_status(reason)
       when reason in [:unsupported, :unsupported_registry, :unsupported_platform],
       do: "unsupported"

  defp model_guard_error_status(reason) when is_tuple(reason) do
    reason
    |> Tuple.to_list()
    |> Enum.any?(&(&1 in [:unsupported, :unsupported_registry, :unsupported_platform]))
    |> case do
      true -> "unsupported"
      false -> "failed"
    end
  end

  defp model_guard_error_status(_), do: "failed"

  defp scan_result_value(scan_result, key, default) when is_map(scan_result) do
    Map.get(scan_result, key) || Map.get(scan_result, to_string(key)) || default
  end

  defp scan_result_value(_, _key, default), do: default

  defp package_scanner_state(package_findings) when is_list(package_findings) do
    if Enum.empty?(package_findings), do: "not_collected", else: "collected"
  end

  defp package_scanner_state(_), do: "not_collected"

  defp evidence_count(items) when is_list(items), do: length(items)
  defp evidence_count(items) when is_map(items), do: map_size(items)
  defp evidence_count(_), do: 0

  defp model_consensus_state(consensus) when is_map(consensus) and map_size(consensus) > 0 do
    consensus[:state] || consensus["state"] || consensus[:verdict] || consensus["verdict"] || "collected"
  end

  defp model_consensus_state(_), do: "not_collected"

  defp enforcement_note("decision_only"),
    do: "Model Guard is decision-only; findings are recorded as evidence and no load block is enforced."

  defp enforcement_note("enforced"), do: "Model Guard enforcement is enabled for block decisions."
  defp enforcement_note(_), do: "Model Guard enforcement state is unavailable."

  defp model_guard_decision(risk_score) when risk_score < @suspicious_threshold, do: "allow"
  defp model_guard_decision(risk_score) when risk_score < @block_threshold, do: "review"
  defp model_guard_decision(_risk_score), do: "block"

  defp model_guard_action("block", "enforced"), do: "block_load"
  defp model_guard_action("block", "decision_only"), do: "report_only"
  defp model_guard_action("review", _enforcement), do: "allow_with_review"
  defp model_guard_action("allow", _enforcement), do: "allow"

  defp fp_rationale("block", 0),
    do: "High risk score without discrete findings; review model lineage before permanent block."

  defp fp_rationale("block", _findings_count),
    do:
      "High risk score meets enforced block threshold; validate findings before closing as true positive."

  defp fp_rationale("review", _findings_count),
    do:
      "Intermediate risk band is review-only to reduce false positives from weak or contextual signals."

  defp fp_rationale("allow", _findings_count),
    do: "Below suspicious threshold; no Model Guard action required."

  defp highest_severity(findings) do
    findings
    |> Enum.map(&severity/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.max_by(&severity_rank/1, fn -> nil end)
  end

  defp severity(finding), do: finding[:severity] || finding["severity"]

  defp severity_rank("critical"), do: 4
  defp severity_rank("high"), do: 3
  defp severity_rank("medium"), do: 2
  defp severity_rank("low"), do: 1
  defp severity_rank(_), do: 0

  defp finding_types(findings) do
    findings
    |> Enum.map(fn finding -> finding[:type] || finding["type"] end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

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
        provenance_id: provenance.id,
        model_guard: scan_result[:model_guard] || scan_result["model_guard"],
        package_findings: scan_result[:package_findings] || scan_result["package_findings"] || [],
        external_model_scores: scan_result[:external_model_scores] || scan_result["external_model_scores"] || [],
        model_consensus: scan_result[:model_consensus] || scan_result["model_consensus"] || %{}
      },
      detection_metadata: %{
        source: "model_registry",
        registry: provenance.registry,
        scan_result: scan_result,
        model_guard: scan_result[:model_guard] || scan_result["model_guard"],
        package_findings: scan_result[:package_findings] || scan_result["package_findings"] || [],
        external_model_scores: scan_result[:external_model_scores] || scan_result["external_model_scores"] || [],
        model_consensus: scan_result[:model_consensus] || scan_result["model_consensus"] || %{}
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
        Logger.error(
          "Failed to create alert for #{provenance.model_id}: #{inspect(changeset.errors)}"
        )

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

    base =
      "Model scan detected #{finding_count} security finding(s) with risk score #{Float.round(provenance.risk_score, 2)}."

    if finding_count > 0 do
      finding_summary =
        findings
        |> Enum.take(3)
        |> Enum.map(fn f ->
          "- #{f[:type] || "Unknown"}: #{f[:description] || "No description"}"
        end)
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

  defp registry_module_to_name(module),
    do: module |> to_string() |> String.split(".") |> List.last() |> String.downcase()

  # Helper to conditionally put values in map
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
