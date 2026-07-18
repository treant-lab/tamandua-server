defmodule TamanduaServer.Integrations.TicketingRouter do
  @moduledoc """
  Unified router for dispatching alerts to configured ticketing integrations.

  Supports Jira and ServiceNow with:
  - Severity-based routing (only create tickets above min_severity)
  - Deduplication (check for existing tickets via JQL/sysparm_query)
  - Async dispatch using Task.async_stream
  - Per-organization configuration

  ## Routing Logic

  - **Critical/High severity** - Create ticket immediately if above min_severity
  - **Medium/Low/Info severity** - Only create if org has lower min_severity configured

  ## Configuration

  Per-organization configurations are stored in the `ticketing_configs` table.
  Each config specifies the ticketing system type, credentials, min_severity,
  and deduplication settings.

  ## Example

      # Route a single alert
      TicketingRouter.route_alert(%{
        id: "alert-123",
        organization_id: "org-456",
        title: "Suspicious process detected",
        severity: "high",
        description: "...",
        hostname: "workstation-01"
      })

      # Get enabled integrations for an org
      TicketingRouter.get_enabled_integrations("org-456")
  """

  use GenServer
  require Logger

  alias TamanduaServer.Integrations.Ticketing.{Config, Jira, ServiceNow}

  @severity_order %{"critical" => 4, "high" => 3, "medium" => 2, "low" => 1, "info" => 0}

  defstruct [:stats]

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the TicketingRouter GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Route a single alert to all enabled ticketing integrations for the organization.

  ## Parameters

  - `alert` - Alert map with :id, :organization_id, :title, :severity, :description, etc.
  - `opts` - Optional:
    - `:force` - Skip min_severity check (default: false)
    - `:skip_dedup` - Skip deduplication check (default: false)

  ## Returns

  `{:ok, results}` list of {type, result} tuples, `{:error, reason}` on failure.
  """
  @spec route_alert(map(), keyword()) :: {:ok, [tuple()]} | {:error, term()}
  def route_alert(alert, opts \\ []) do
    GenServer.call(__MODULE__, {:route_alert, alert, opts}, 60_000)
  catch
    :exit, {:noproc, _} ->
      # GenServer not started, dispatch directly
      do_route_alert(alert, opts)
  end

  @doc """
  Route multiple alerts as a batch to all enabled ticketing integrations.

  ## Parameters

  - `alerts` - List of alert maps
  - `opts` - Optional configuration

  ## Returns

  `{:ok, results}` with dispatch results per alert, `{:error, reason}` on failure.
  """
  @spec route_batch([map()], keyword()) :: {:ok, [tuple()]} | {:error, term()}
  def route_batch(alerts, opts \\ []) when is_list(alerts) do
    GenServer.call(__MODULE__, {:route_batch, alerts, opts}, 120_000)
  catch
    :exit, {:noproc, _} ->
      # Process each alert individually
      results = Enum.map(alerts, fn alert ->
        case do_route_alert(alert, opts) do
          {:ok, r} -> r
          {:error, reason} -> [{:error, reason}]
        end
      end)
      {:ok, List.flatten(results)}
  end

  @doc """
  Get list of enabled ticketing integrations for an organization.

  ## Parameters

  - `organization_id` - Organization UUID

  ## Returns

  List of config maps with decrypted credentials.
  """
  @spec get_enabled_integrations(binary()) :: [map()]
  def get_enabled_integrations(organization_id) do
    Config.list_enabled(organization_id)
  end

  @doc """
  Get routing statistics.

  ## Returns

  Map with tickets_created, errors, by_type counts.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  catch
    :exit, {:noproc, _} ->
      %{tickets_created: 0, errors: 0, dedup_hits: 0, by_type: %{}}
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("[TicketingRouter] Starting ticketing router")

    state = %__MODULE__{
      stats: %{
        tickets_created: 0,
        errors: 0,
        dedup_hits: 0,
        severity_skipped: 0,
        by_type: %{},
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:route_alert, alert, opts}, _from, state) do
    {results, new_stats} = do_route_alert_with_stats(alert, opts, state.stats)
    {:reply, {:ok, results}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:route_batch, alerts, opts}, _from, state) do
    {all_results, new_stats} =
      Enum.reduce(alerts, {[], state.stats}, fn alert, {acc_results, acc_stats} ->
        {results, updated_stats} = do_route_alert_with_stats(alert, opts, acc_stats)
        {acc_results ++ results, updated_stats}
      end)

    {:reply, {:ok, all_results}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp do_route_alert(alert, opts) do
    {results, _stats} = do_route_alert_with_stats(alert, opts, %{
      tickets_created: 0,
      errors: 0,
      dedup_hits: 0,
      severity_skipped: 0,
      by_type: %{}
    })
    {:ok, results}
  end

  defp do_route_alert_with_stats(alert, opts, stats) do
    org_id = get_org_id(alert)

    if is_nil(org_id) do
      Logger.warning("[TicketingRouter] Alert missing organization_id: #{inspect(alert[:id])}")
      {[], stats}
    else
      enabled_configs = get_enabled_integrations(org_id)

      if length(enabled_configs) == 0 do
        Logger.debug("[TicketingRouter] No ticketing integrations enabled for org #{org_id}")
        {[], stats}
      else
        # Process each config in parallel
        results =
          enabled_configs
          |> Task.async_stream(
            fn config ->
              result = dispatch_to_integration(alert, config, opts)
              {String.to_atom(config.type), result}
            end,
            timeout: 30_000,
            on_timeout: :kill_task
          )
          |> Enum.map(fn
            {:ok, result} -> result
            {:exit, reason} -> {:unknown, {:error, {:timeout, reason}}}
          end)

        new_stats = update_stats(stats, results)
        {results, new_stats}
      end
    end
  end

  defp dispatch_to_integration(alert, config, opts) do
    force = Keyword.get(opts, :force, false)
    skip_dedup = Keyword.get(opts, :skip_dedup, false)

    cond do
      # Check severity threshold
      not force and not should_create_ticket?(alert, config) ->
        {:skipped, :below_severity_threshold}

      # Check deduplication
      not skip_dedup and config.dedupe_enabled and ticket_exists?(alert, config) ->
        {:skipped, :duplicate}

      # Create the ticket
      true ->
        create_ticket(alert, config)
    end
  rescue
    e ->
      Logger.error("[TicketingRouter] Error dispatching to #{config.type}: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  @doc false
  def should_create_ticket?(alert, config) do
    alert_severity = get_severity(alert)
    min_severity = config.min_severity || "high"

    alert_level = @severity_order[alert_severity] || 0
    min_level = @severity_order[min_severity] || 3

    alert_level >= min_level
  end

  defp ticket_exists?(alert, config) do
    alert_id = get_alert_id(alert)

    case config.type do
      "jira" -> check_duplicate_jira(alert_id, config)
      "servicenow" -> check_duplicate_servicenow(alert_id, config)
      _ -> false
    end
  end

  @doc false
  def check_duplicate_jira(alert_id, config) do
    decrypted = config.decrypted_config || %{}
    project_key = decrypted["project_key"] || "SEC"
    jql = "project = #{project_key} AND labels = tamandua-alert-#{alert_id}"

    case Jira.search_issues(jql, max_results: 1) do
      {:ok, [_ | _]} ->
        Logger.debug("[TicketingRouter] Found existing Jira ticket for alert #{alert_id}")
        true

      {:ok, []} ->
        false

      {:error, reason} ->
        Logger.warning("[TicketingRouter] Jira dedup check failed: #{inspect(reason)}")
        false
    end
  end

  @doc false
  def check_duplicate_servicenow(alert_id, _config) do
    query = %{
      sysparm_query: "u_tamandua_alert_id=#{alert_id}",
      limit: 1,
      fields: ["sys_id"]
    }

    case ServiceNow.search_incidents(query) do
      {:ok, [_ | _]} ->
        Logger.debug("[TicketingRouter] Found existing ServiceNow incident for alert #{alert_id}")
        true

      {:ok, []} ->
        false

      {:error, reason} ->
        Logger.warning("[TicketingRouter] ServiceNow dedup check failed: #{inspect(reason)}")
        false
    end
  end

  defp create_ticket(alert, config) do
    case config.type do
      "jira" -> create_jira_ticket(alert, config)
      "servicenow" -> create_servicenow_incident(alert, config)
      type ->
        Logger.warning("[TicketingRouter] Unknown ticketing type: #{type}")
        {:error, :unknown_type}
    end
  end

  defp create_jira_ticket(alert, config) do
    decrypted = config.decrypted_config || %{}

    issue_data = %{
      title: "[Tamandua] #{get_title(alert)}",
      description: get_description(alert),
      severity: get_severity(alert),
      project_key: decrypted["project_key"],
      issue_type: decrypted["issue_type"] || "Security Incident",
      labels: [
        "tamandua",
        "tamandua-alert-#{get_alert_id(alert)}",
        "severity-#{get_severity(alert)}"
      ],
      id: get_alert_id(alert),
      hostname: get_field(alert, :hostname),
      agent_id: get_field(alert, :agent_id),
      mitre_tactics: get_field(alert, :mitre_tactics) || [],
      mitre_techniques: get_field(alert, :mitre_techniques) || [],
      threat_score: get_field(alert, :threat_score)
    }

    case Jira.create_issue(issue_data) do
      {:ok, issue_key} ->
        Logger.info("[TicketingRouter] Created Jira ticket #{issue_key} for alert #{get_alert_id(alert)}")
        {:ok, issue_key}

      {:error, reason} ->
        Logger.error("[TicketingRouter] Failed to create Jira ticket: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp create_servicenow_incident(alert, config) do
    decrypted = config.decrypted_config || %{}

    incident_data = %{
      title: "[Tamandua] #{get_title(alert)}",
      description: get_description(alert),
      severity: get_severity(alert),
      table: decrypted["table"] || "sn_si_incident",
      id: get_alert_id(alert),
      hostname: get_field(alert, :hostname),
      agent_id: get_field(alert, :agent_id),
      mitre_tactics: get_field(alert, :mitre_tactics) || [],
      mitre_techniques: get_field(alert, :mitre_techniques) || [],
      threat_score: get_field(alert, :threat_score)
    }

    case ServiceNow.create_incident(incident_data) do
      {:ok, incident_id} ->
        Logger.info("[TicketingRouter] Created ServiceNow incident #{incident_id} for alert #{get_alert_id(alert)}")
        {:ok, incident_id}

      {:error, reason} ->
        Logger.error("[TicketingRouter] Failed to create ServiceNow incident: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # Field extraction helpers (support both atom and string keys)
  defp get_org_id(alert) do
    alert[:organization_id] || alert["organization_id"]
  end

  defp get_alert_id(alert) do
    alert[:id] || alert["id"]
  end

  defp get_title(alert) do
    alert[:title] || alert["title"] || "Tamandua Alert"
  end

  defp get_description(alert) do
    alert[:description] || alert["description"] || ""
  end

  defp get_severity(alert) do
    severity = alert[:severity] || alert["severity"] || "medium"
    String.downcase(to_string(severity))
  end

  defp get_field(alert, key) when is_atom(key) do
    alert[key] || alert[to_string(key)]
  end

  defp update_stats(stats, results) do
    {successes, others} = Enum.split_with(results, fn
      {_, {:ok, _}} -> true
      _ -> false
    end)

    {dedup_hits, _} = Enum.split_with(others, fn
      {_, {:skipped, :duplicate}} -> true
      _ -> false
    end)

    {errors, _} = Enum.split_with(others, fn
      {_, {:error, _}} -> true
      _ -> false
    end)

    by_type = Enum.reduce(results, stats.by_type, fn {type, result}, acc ->
      current = Map.get(acc, type, %{success: 0, failure: 0, skipped: 0})

      updated =
        case result do
          {:ok, _} -> %{current | success: current.success + 1}
          {:error, _} -> %{current | failure: current.failure + 1}
          {:skipped, _} -> %{current | skipped: current.skipped + 1}
        end

      Map.put(acc, type, updated)
    end)

    %{stats |
      tickets_created: stats.tickets_created + length(successes),
      errors: stats.errors + length(errors),
      dedup_hits: stats.dedup_hits + length(dedup_hits),
      by_type: by_type,
      last_activity: DateTime.utc_now()
    }
  end
end
