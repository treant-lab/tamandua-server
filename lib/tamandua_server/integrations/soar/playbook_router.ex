defmodule TamanduaServer.Integrations.SOAR.PlaybookRouter do
  @moduledoc """
  Routes playbook triggers to configured SOAR platforms.

  Supports parallel dispatch to multiple platforms when `soar_platform: "both"`.
  Logs all executions for tracking and audit.

  ## Supported Platforms

  - **xsoar** - Palo Alto XSOAR (Cortex XSOAR / Demisto)
  - **tines** - Tines no-code automation

  ## Usage

      PlaybookRouter.route_to_playbook("xsoar", alert, playbook_name: "investigate_alert")
      PlaybookRouter.route_to_playbook("both", alert, playbook_name: "critical_response")
  """

  require Logger

  alias TamanduaServer.Integrations.SOAR.{XSOAR, Tines, ExecutionLog}

  @soar_modules %{
    "xsoar" => XSOAR,
    "tines" => Tines
  }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Route an alert to the specified SOAR platform(s) to trigger a playbook.

  ## Parameters

  - `platform` - "xsoar", "tines", or "both"
  - `alert` - Alert map with id, title, severity, etc.
  - `opts` - Keyword list:
    - `:playbook_name` - Name of the playbook to trigger (required)
    - `:webhook_url` - Webhook URL for Tines (optional)
    - `:params` - Additional parameters to pass to the playbook
    - `:rule_id` - ID of the trigger rule that matched

  ## Returns

  `{:ok, execution_ids}` - List of execution IDs from each platform
  `{:error, reason}` - If all dispatches failed
  """
  @spec route_to_playbook(String.t(), map(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def route_to_playbook(platform, alert, opts \\ []) do
    playbook_name = Keyword.fetch!(opts, :playbook_name)
    platforms = expand_platform(platform)

    if platforms == [] do
      {:error, :no_platforms_specified}
    else
      results = platforms
      |> Task.async_stream(fn plat ->
        dispatch_to_platform(plat, alert, playbook_name, opts)
      end, timeout: 60_000, on_timeout: :kill_task)
      |> Enum.map(fn
        {:ok, result} -> result
        {:exit, reason} -> {:error, {:timeout, reason}}
      end)

      successful = Enum.filter(results, &match?({:ok, _}, &1))

      if successful == [] do
        errors = Enum.filter(results, &match?({:error, _}, &1))
        {:error, {:all_failed, errors}}
      else
        execution_ids = Enum.map(successful, fn {:ok, data} -> data end)
        {:ok, execution_ids}
      end
    end
  end

  @doc """
  Get list of enabled SOAR integrations with their health status.

  ## Returns

  List of maps with :platform, :enabled, :status, :last_check.
  """
  @spec get_enabled_soar_integrations() :: [map()]
  def get_enabled_soar_integrations do
    Map.keys(@soar_modules)
    |> Enum.map(fn platform ->
      module = @soar_modules[platform]
      config = get_platform_config(platform)

      enabled = config != nil and config[:enabled] == true

      status = if enabled do
        try do
          case module.test_connection() do
            {:ok, _} -> :healthy
            {:error, _} -> :unhealthy
          end
        catch
          _, _ -> :unknown
        end
      else
        :disabled
      end

      %{
        platform: platform,
        enabled: enabled,
        status: status,
        module: module
      }
    end)
  end

  @doc """
  Get execution status from SOAR platform.

  ## Parameters

  - `log_id` - ExecutionLog ID
  - `platform` - SOAR platform ("xsoar" or "tines")

  ## Returns

  `{:ok, status}` or `{:error, reason}`.
  """
  @spec get_execution_status(binary(), String.t()) :: {:ok, map()} | {:error, term()}
  def get_execution_status(log_id, platform) do
    case ExecutionLog.get(log_id) do
      nil ->
        {:error, :not_found}

      log ->
        module = @soar_modules[platform]
        if module do
          module.get_playbook_status(log.execution_id)
        else
          {:error, :unknown_platform}
        end
    end
  end

  @doc """
  Get execution statistics for SOAR integrations.

  ## Options

  - `:since` - DateTime to start counting from (default: last 24 hours)

  ## Returns

  Map with statistics by platform.
  """
  @spec get_stats(keyword()) :: map()
  def get_stats(opts \\ []) do
    ExecutionLog.get_stats(opts)
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp expand_platform("both"), do: ["xsoar", "tines"]
  defp expand_platform(platform) when platform in ["xsoar", "tines"], do: [platform]
  defp expand_platform(_), do: []

  defp dispatch_to_platform("xsoar", alert, playbook_name, opts) do
    Logger.info("[PlaybookRouter] Dispatching to XSOAR: #{playbook_name}")

    # Create execution log
    {:ok, log} = ExecutionLog.create(%{
      alert_id: alert[:id] || alert["id"],
      trigger_rule_id: opts[:rule_id],
      soar_platform: "xsoar",
      playbook_name: playbook_name
    })

    # Build incident data for XSOAR
    incident_data = build_xsoar_incident(alert, playbook_name, opts)

    try do
      case XSOAR.create_incident(incident_data) do
        {:ok, incident_id} ->
          # Trigger the playbook on the incident
          case XSOAR.trigger_playbook(playbook_name, %{incident_id: incident_id}) do
            {:ok, run_id} ->
              ExecutionLog.update_status(log, "running", %{execution_id: run_id})
              {:ok, %{platform: "xsoar", log_id: log.id, execution_id: run_id, incident_id: incident_id}}

            {:error, reason} ->
              ExecutionLog.update_status(log, "failed", %{error_message: inspect(reason)})
              {:error, {:playbook_trigger_failed, reason}}
          end

        {:error, reason} ->
          ExecutionLog.update_status(log, "failed", %{error_message: inspect(reason)})
          {:error, {:incident_creation_failed, reason}}
      end
    catch
      kind, error ->
        ExecutionLog.update_status(log, "failed", %{error_message: "#{kind}: #{inspect(error)}"})
        {:error, {kind, error}}
    end
  end

  defp dispatch_to_platform("tines", alert, playbook_name, opts) do
    Logger.info("[PlaybookRouter] Dispatching to Tines: #{playbook_name}")

    # Create execution log
    {:ok, log} = ExecutionLog.create(%{
      alert_id: alert[:id] || alert["id"],
      trigger_rule_id: opts[:rule_id],
      soar_platform: "tines",
      playbook_name: playbook_name
    })

    # Get webhook URL - from opts or from registered webhooks
    webhook_url = opts[:webhook_url]

    try do
      if webhook_url do
        # Direct webhook trigger
        payload = build_tines_payload(alert, playbook_name, log.id, opts)

        case Tines.send_event(webhook_url, payload) do
          {:ok, response} ->
            execution_id = response["event_id"] || generate_execution_id()
            ExecutionLog.update_status(log, "running", %{execution_id: execution_id})
            {:ok, %{platform: "tines", log_id: log.id, execution_id: execution_id}}

          {:error, reason} ->
            ExecutionLog.update_status(log, "failed", %{error_message: inspect(reason)})
            {:error, {:webhook_failed, reason}}
        end
      else
        # Use registered playbook trigger
        case Tines.trigger_playbook(playbook_name, %{alert: alert}) do
          {:ok, run_id} ->
            ExecutionLog.update_status(log, "running", %{execution_id: run_id})
            {:ok, %{platform: "tines", log_id: log.id, execution_id: run_id}}

          {:error, reason} ->
            ExecutionLog.update_status(log, "failed", %{error_message: inspect(reason)})
            {:error, {:playbook_trigger_failed, reason}}
        end
      end
    catch
      kind, error ->
        ExecutionLog.update_status(log, "failed", %{error_message: "#{kind}: #{inspect(error)}"})
        {:error, {kind, error}}
    end
  end

  defp dispatch_to_platform(platform, _alert, _playbook_name, _opts) do
    {:error, {:unknown_platform, platform}}
  end

  defp build_xsoar_incident(alert, playbook_name, opts) do
    %{
      title: alert[:title] || alert["title"] || "Tamandua Alert",
      description: alert[:description] || alert["description"],
      severity: alert[:severity] || alert["severity"],
      hostname: alert[:hostname] || alert["hostname"],
      agent_id: alert[:agent_id] || alert["agent_id"],
      mitre_tactics: alert[:mitre_tactics] || alert["mitre_tactics"] || [],
      mitre_techniques: alert[:mitre_techniques] || alert["mitre_techniques"] || [],
      threat_score: alert[:threat_score] || alert["threat_score"],
      id: alert[:id] || alert["id"],
      playbook: playbook_name,
      custom_fields: opts[:params] || %{}
    }
  end

  defp build_tines_payload(alert, playbook_name, log_id, opts) do
    %{
      source: "tamandua-edr",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      tamandua_execution_id: log_id,
      playbook: playbook_name,
      alert: %{
        id: alert[:id] || alert["id"],
        title: alert[:title] || alert["title"],
        description: alert[:description] || alert["description"],
        severity: alert[:severity] || alert["severity"],
        hostname: alert[:hostname] || alert["hostname"],
        agent_id: alert[:agent_id] || alert["agent_id"],
        mitre_tactics: alert[:mitre_tactics] || alert["mitre_tactics"] || [],
        mitre_techniques: alert[:mitre_techniques] || alert["mitre_techniques"] || [],
        threat_score: alert[:threat_score] || alert["threat_score"]
      },
      params: opts[:params] || %{}
    }
  end

  defp get_platform_config("xsoar") do
    Application.get_env(:tamandua_server, TamanduaServer.Integrations.SOAR.XSOAR, [])
  end

  defp get_platform_config("tines") do
    Application.get_env(:tamandua_server, TamanduaServer.Integrations.SOAR.Tines, [])
  end

  defp generate_execution_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end
end
