defmodule TamanduaServer.AI.LicenseCompliance do
  @moduledoc """
  AI Model License Compliance tracking and management.

  Tracks license compliance status for AI models used across agents:
  - HuggingFace models (Llama 2/3, Gemma, GPT-like models)
  - Local models
  - Third-party APIs

  Detects:
  - Commercial use restrictions (CC-BY-NC, research-only)
  - Copyleft requirements (GPL, AGPL, LGPL)
  - Attribution requirements
  - Model-specific licenses (OpenRAIL, Llama Community License)

  MITRE ATLAS: AML.T0049 (IP Theft), AML.T0051 (Model Supply Chain)
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub
  alias TamanduaServer.Detection.ML.Client, as: MLClient
  alias TamanduaServer.Alerts

  @ets_table :license_compliance_registry
  @check_interval :timer.hours(24)

  # ============================================================================
  # Types
  # ============================================================================

  @type license_type ::
          :mit
          | :apache_2
          | :bsd_2
          | :bsd_3
          | :gpl_2
          | :gpl_3
          | :lgpl_3
          | :agpl_3
          | :cc_by_nc
          | :cc_by_nc_sa
          | :cc_by_nc_nd
          | :openrail
          | :openrail_m
          | :llama_2
          | :llama_3
          | :gemma
          | :proprietary
          | :unknown

  @type compliance_level ::
          :compliant
          | :attribution_required
          | :copyleft_risk
          | :commercial_restricted
          | :high_risk
          | :blocked

  @type model_entry :: %{
          model_id: String.t(),
          model_hash: String.t() | nil,
          license_type: license_type(),
          license_name: String.t(),
          compliance_level: compliance_level(),
          use_case: String.t(),
          commercial_allowed: boolean(),
          requires_attribution: boolean(),
          requires_source_disclosure: boolean(),
          issues: [String.t()],
          recommendations: [String.t()],
          checked_at: DateTime.t(),
          agent_ids: [String.t()]
        }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check license compliance for a model.

  Calls the ML service to detect and analyze the model's license.

  ## Parameters
    - model_id: HuggingFace model ID (e.g., "meta-llama/Llama-2-7b") or local path
    - opts: Additional options
      - use_case: "commercial", "research", or "internal" (default: "commercial")
      - agent_id: Optional agent ID to track usage
      - generate_alerts: Whether to create alerts for issues (default: true)

  ## Returns
    {:ok, compliance_report} | {:error, reason}
  """
  @spec check_model(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def check_model(model_id, opts \\ []) do
    GenServer.call(__MODULE__, {:check_model, model_id, opts}, 30_000)
  end

  @doc """
  Check license compliance for multiple models.

  ## Parameters
    - model_ids: List of model IDs to check
    - opts: Additional options (same as check_model/2)

  ## Returns
    {:ok, batch_results} | {:error, reason}
  """
  @spec check_models([String.t()], keyword()) :: {:ok, map()} | {:error, term()}
  def check_models(model_ids, opts \\ []) do
    GenServer.call(__MODULE__, {:check_models, model_ids, opts}, 120_000)
  end

  @doc """
  Get compliance status for a registered model.
  """
  @spec get_model_status(String.t()) :: {:ok, model_entry()} | {:error, :not_found}
  def get_model_status(model_id) do
    GenServer.call(__MODULE__, {:get_model_status, model_id})
  end

  @doc """
  List all registered models with compliance status.
  """
  @spec list_models() :: [model_entry()]
  def list_models do
    GenServer.call(__MODULE__, :list_models)
  end

  @doc """
  List models with compliance issues.
  """
  @spec list_non_compliant() :: [model_entry()]
  def list_non_compliant do
    GenServer.call(__MODULE__, :list_non_compliant)
  end

  @doc """
  Register an agent as using a model.
  """
  @spec register_usage(String.t(), String.t()) :: :ok | {:error, term()}
  def register_usage(model_id, agent_id) do
    GenServer.call(__MODULE__, {:register_usage, model_id, agent_id})
  end

  @doc """
  Unregister an agent from model usage.
  """
  @spec unregister_usage(String.t(), String.t()) :: :ok
  def unregister_usage(model_id, agent_id) do
    GenServer.call(__MODULE__, {:unregister_usage, model_id, agent_id})
  end

  @doc """
  Remove a model from the registry.
  """
  @spec remove_model(String.t()) :: :ok | {:error, :not_found}
  def remove_model(model_id) do
    GenServer.call(__MODULE__, {:remove_model, model_id})
  end

  @doc """
  Get compliance statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Force re-check all registered models.
  """
  @spec refresh_all() :: {:ok, map()}
  def refresh_all do
    GenServer.call(__MODULE__, :refresh_all, 300_000)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    table =
      :ets.new(@ets_table, [
        :set,
        :named_table,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])

    # Schedule periodic compliance check
    Process.send_after(self(), :periodic_check, @check_interval)

    state = %{
      table: table,
      stats: %{
        total_checks: 0,
        compliant: 0,
        attribution_required: 0,
        copyleft_risk: 0,
        commercial_restricted: 0,
        high_risk: 0,
        blocked: 0,
        alerts_generated: 0
      }
    }

    Logger.info("[LicenseCompliance] Started")
    {:ok, state}
  end

  @impl true
  def handle_call({:check_model, model_id, opts}, _from, state) do
    use_case = Keyword.get(opts, :use_case, "commercial")
    agent_id = Keyword.get(opts, :agent_id)
    generate_alerts = Keyword.get(opts, :generate_alerts, true)

    case call_ml_service(model_id, use_case) do
      {:ok, report} ->
        # Store in registry
        entry = build_entry(report, agent_id)
        :ets.insert(@ets_table, {model_id, entry})

        # Update stats
        state = update_stats(state, entry)

        # Generate alerts for issues
        state =
          if generate_alerts && entry.compliance_level not in [:compliant, :attribution_required] do
            generate_compliance_alert(entry, agent_id)
            update_in(state, [:stats, :alerts_generated], &(&1 + 1))
          else
            state
          end

        # Broadcast update
        broadcast_compliance_update(entry)

        {:reply, {:ok, report}, state}

      {:error, reason} = error ->
        Logger.error("[LicenseCompliance] Check failed for #{model_id}: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:check_models, model_ids, opts}, _from, state) do
    use_case = Keyword.get(opts, :use_case, "commercial")

    case call_ml_service_batch(model_ids, use_case) do
      {:ok, batch_result} ->
        # Process results
        Enum.each(batch_result["results"], fn result ->
          if result["compliance_level"] != "error" do
            model_id = result["model_id"]
            entry = build_entry_from_batch(result)
            :ets.insert(@ets_table, {model_id, entry})
          end
        end)

        {:reply, {:ok, batch_result}, state}

      {:error, reason} = error ->
        Logger.error("[LicenseCompliance] Batch check failed: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_model_status, model_id}, _from, state) do
    result =
      case :ets.lookup(@ets_table, model_id) do
        [{^model_id, entry}] -> {:ok, entry}
        [] -> {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call(:list_models, _from, state) do
    models =
      :ets.foldl(
        fn {_id, entry}, acc -> [entry | acc] end,
        [],
        @ets_table
      )

    {:reply, Enum.reverse(models), state}
  end

  @impl true
  def handle_call(:list_non_compliant, _from, state) do
    non_compliant =
      :ets.foldl(
        fn {_id, entry}, acc ->
          if entry.compliance_level not in [:compliant, :attribution_required] do
            [entry | acc]
          else
            acc
          end
        end,
        [],
        @ets_table
      )

    {:reply, Enum.reverse(non_compliant), state}
  end

  @impl true
  def handle_call({:register_usage, model_id, agent_id}, _from, state) do
    result =
      case :ets.lookup(@ets_table, model_id) do
        [{^model_id, entry}] ->
          updated_entry = %{entry | agent_ids: Enum.uniq([agent_id | entry.agent_ids])}
          :ets.insert(@ets_table, {model_id, updated_entry})
          :ok

        [] ->
          {:error, :model_not_registered}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:unregister_usage, model_id, agent_id}, _from, state) do
    case :ets.lookup(@ets_table, model_id) do
      [{^model_id, entry}] ->
        updated_entry = %{entry | agent_ids: List.delete(entry.agent_ids, agent_id)}
        :ets.insert(@ets_table, {model_id, updated_entry})

      [] ->
        :ok
    end

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:remove_model, model_id}, _from, state) do
    result =
      case :ets.lookup(@ets_table, model_id) do
        [{^model_id, _}] ->
          :ets.delete(@ets_table, model_id)
          :ok

        [] ->
          {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    model_count = :ets.info(@ets_table, :size)
    stats = Map.put(state.stats, :registered_models, model_count)
    {:reply, stats, state}
  end

  @impl true
  def handle_call(:refresh_all, _from, state) do
    model_ids =
      :ets.foldl(
        fn {model_id, _entry}, acc -> [model_id | acc] end,
        [],
        @ets_table
      )

    results =
      Enum.map(model_ids, fn model_id ->
        case call_ml_service(model_id, "commercial") do
          {:ok, report} ->
            entry = build_entry(report, nil)
            :ets.insert(@ets_table, {model_id, entry})
            {:ok, model_id}

          {:error, reason} ->
            {:error, model_id, reason}
        end
      end)

    success_count = Enum.count(results, &match?({:ok, _}, &1))
    error_count = Enum.count(results, &match?({:error, _, _}, &1))

    {:reply, {:ok, %{refreshed: success_count, errors: error_count}}, state}
  end

  @impl true
  def handle_info(:periodic_check, state) do
    Logger.info("[LicenseCompliance] Running periodic compliance check")

    # Find models that haven't been checked recently
    cutoff = DateTime.add(DateTime.utc_now(), -86_400, :second)

    stale_models =
      :ets.foldl(
        fn {model_id, entry}, acc ->
          if DateTime.compare(entry.checked_at, cutoff) == :lt do
            [model_id | acc]
          else
            acc
          end
        end,
        [],
        @ets_table
      )

    # Re-check stale models (in background)
    Task.start(fn ->
      Enum.each(Enum.take(stale_models, 10), fn model_id ->
        case call_ml_service(model_id, "commercial") do
          {:ok, report} ->
            entry = build_entry(report, nil)
            :ets.insert(@ets_table, {model_id, entry})

          {:error, _reason} ->
            :ok
        end

        Process.sleep(1000)
      end)
    end)

    Process.send_after(self(), :periodic_check, @check_interval)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp call_ml_service(model_id, use_case) do
    payload = %{
      "model_id" => model_id,
      "use_case" => use_case
    }

    MLClient.post("/ai-security/license/check", payload, timeout: 30_000)
  end

  defp call_ml_service_batch(model_ids, use_case) do
    payload = %{
      "model_ids" => model_ids,
      "use_case" => use_case
    }

    MLClient.post("/ai-security/license/check-batch", payload, timeout: 120_000)
  end

  defp build_entry(report, agent_id) do
    license_info = report["license_info"] || %{}

    agent_ids = if agent_id, do: [agent_id], else: []

    %{
      model_id: report["model_id"],
      model_hash: report["model_hash"],
      license_type: parse_license_type(license_info["license_type"]),
      license_name: license_info["license_name"] || "Unknown",
      compliance_level: parse_compliance_level(report["compliance_level"]),
      use_case: report["use_case"] || "commercial",
      commercial_allowed: report["commercial_allowed"] || false,
      requires_attribution: report["requires_attribution"] || false,
      requires_source_disclosure: report["requires_source_disclosure"] || false,
      issues: report["issues"] || [],
      recommendations: report["recommendations"] || [],
      checked_at: DateTime.utc_now(),
      agent_ids: agent_ids
    }
  end

  defp build_entry_from_batch(result) do
    %{
      model_id: result["model_id"],
      model_hash: nil,
      license_type: parse_license_type(result["license_type"]),
      license_name: result["license_type"] || "Unknown",
      compliance_level: parse_compliance_level(result["compliance_level"]),
      use_case: "commercial",
      commercial_allowed: result["commercial_allowed"] || false,
      requires_attribution: false,
      requires_source_disclosure: false,
      issues: result["issues"] || [],
      recommendations: [],
      checked_at: DateTime.utc_now(),
      agent_ids: []
    }
  end

  defp parse_license_type(nil), do: :unknown
  defp parse_license_type("mit"), do: :mit
  defp parse_license_type("apache-2.0"), do: :apache_2
  defp parse_license_type("bsd-2-clause"), do: :bsd_2
  defp parse_license_type("bsd-3-clause"), do: :bsd_3
  defp parse_license_type("gpl-2.0"), do: :gpl_2
  defp parse_license_type("gpl-3.0"), do: :gpl_3
  defp parse_license_type("lgpl-3.0"), do: :lgpl_3
  defp parse_license_type("agpl-3.0"), do: :agpl_3
  defp parse_license_type("cc-by-nc-4.0"), do: :cc_by_nc
  defp parse_license_type("cc-by-nc-sa-4.0"), do: :cc_by_nc_sa
  defp parse_license_type("cc-by-nc-nd-4.0"), do: :cc_by_nc_nd
  defp parse_license_type("openrail"), do: :openrail
  defp parse_license_type("openrail++"), do: :openrail_m
  defp parse_license_type("llama2"), do: :llama_2
  defp parse_license_type("llama3"), do: :llama_3
  defp parse_license_type("gemma"), do: :gemma
  defp parse_license_type("proprietary"), do: :proprietary
  defp parse_license_type(_), do: :unknown

  defp parse_compliance_level(nil), do: :unknown
  defp parse_compliance_level("compliant"), do: :compliant
  defp parse_compliance_level("attribution_required"), do: :attribution_required
  defp parse_compliance_level("copyleft_risk"), do: :copyleft_risk
  defp parse_compliance_level("commercial_restricted"), do: :commercial_restricted
  defp parse_compliance_level("high_risk"), do: :high_risk
  defp parse_compliance_level("blocked"), do: :blocked
  defp parse_compliance_level(_), do: :unknown

  defp update_stats(state, entry) do
    key =
      case entry.compliance_level do
        :compliant -> :compliant
        :attribution_required -> :attribution_required
        :copyleft_risk -> :copyleft_risk
        :commercial_restricted -> :commercial_restricted
        :high_risk -> :high_risk
        :blocked -> :blocked
        _ -> :compliant
      end

    state
    |> update_in([:stats, :total_checks], &(&1 + 1))
    |> update_in([:stats, key], &(&1 + 1))
  end

  defp generate_compliance_alert(entry, agent_id) do
    severity =
      case entry.compliance_level do
        :blocked -> :critical
        :commercial_restricted -> :high
        :high_risk -> :high
        :copyleft_risk -> :medium
        _ -> :low
      end

    alert_params = %{
      type: :license_compliance,
      severity: severity,
      agent_id: agent_id,
      title: "License Compliance Issue: #{entry.model_id}",
      description: build_alert_description(entry),
      metadata: %{
        model_id: entry.model_id,
        license_type: entry.license_type,
        compliance_level: entry.compliance_level,
        commercial_allowed: entry.commercial_allowed,
        issues: entry.issues
      },
      mitre_techniques: ["AML.T0049", "AML.T0051"]
    }

    case Alerts.create_alert(alert_params) do
      {:ok, alert} ->
        Logger.info("[LicenseCompliance] Alert created: #{alert.id} for #{entry.model_id}")

      {:error, reason} ->
        Logger.error("[LicenseCompliance] Failed to create alert: #{inspect(reason)}")
    end
  end

  defp build_alert_description(entry) do
    issues_text =
      entry.issues
      |> Enum.take(5)
      |> Enum.map(&"- #{&1}")
      |> Enum.join("\n")

    recommendations_text =
      entry.recommendations
      |> Enum.take(3)
      |> Enum.map(&"- #{&1}")
      |> Enum.join("\n")

    """
    License compliance issue detected for model: #{entry.model_id}

    **License:** #{entry.license_name}
    **Compliance Level:** #{entry.compliance_level}
    **Commercial Use Allowed:** #{entry.commercial_allowed}

    **Issues:**
    #{issues_text}

    **Recommendations:**
    #{recommendations_text}
    """
  end

  defp broadcast_compliance_update(entry) do
    PubSub.broadcast(
      TamanduaServer.PubSub,
      "license_compliance:updates",
      {:compliance_update, entry}
    )
  end
end
