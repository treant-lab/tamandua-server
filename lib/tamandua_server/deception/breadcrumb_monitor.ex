defmodule TamanduaServer.Deception.BreadcrumbMonitor do
  @moduledoc """
  Breadcrumb Access Monitoring and Alerting System

  This module handles:
  - File access event monitoring for deployed breadcrumbs
  - High-severity alert generation on breadcrumb access
  - Tamper detection (modifications, moves, deletions)
  - Policy-gated automated response planning
  - Access analytics and effectiveness tracking

  Comparable to Attivo/SentinelOne Singularity Hologram detection capabilities.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts
  alias TamanduaServer.Response.Playbook
  alias TamanduaServer.Response.HoneyfileAutoResponse
  alias TamanduaServer.Deception.BreadcrumbAccessLog
  alias TamanduaServer.Deception.BreadcrumbDeployment

  # ============================================================================
  # Types
  # ============================================================================

  @type access_event :: %{
          file_path: String.t(),
          agent_id: String.t(),
          process_name: String.t(),
          pid: integer(),
          user: String.t(),
          access_type: String.t(),
          timestamp: DateTime.t(),
          file_hash: String.t() | nil
        }

  @type response_config :: %{
          isolate_agent: boolean(),
          kill_process: boolean(),
          create_snapshot: boolean(),
          escalate_to_soc: boolean(),
          dry_run: boolean(),
          mode: atom() | String.t(),
          allow_autonomous_containment: boolean(),
          trigger_playbook_id: String.t() | nil
        }

  # ============================================================================
  # State
  # ============================================================================

  defstruct breadcrumbs_cache: %{},
            access_stats: %{
              total_accesses: 0,
              by_type: %{},
              by_agent: %{},
              time_to_detection: []
            },
            response_config: %{}

  # ============================================================================
  # GenServer API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Handle file access event from agent FIM collector.
  """
  def handle_file_access(event) do
    GenServer.cast(__MODULE__, {:file_access, event})
  end

  @doc """
  Handle breadcrumb access (called by Breadcrumbs module).
  """
  def handle_breadcrumb_access(event) do
    GenServer.cast(__MODULE__, {:breadcrumb_access, event})
  end

  @doc """
  Update response configuration.
  """
  def configure_response(config) do
    GenServer.call(__MODULE__, {:configure_response, config})
  end

  @doc """
  Get access statistics.
  """
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Get access history for a breadcrumb.
  """
  def get_access_history(breadcrumb_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_access_history, breadcrumb_id, opts})
  end

  @doc """
  Get effectiveness report for breadcrumb types.
  """
  def get_effectiveness_report do
    GenServer.call(__MODULE__, :get_effectiveness_report)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting Breadcrumb Access Monitor")

    # Load active breadcrumbs into cache
    breadcrumbs_cache = load_breadcrumbs_cache()

    state = %__MODULE__{
      breadcrumbs_cache: breadcrumbs_cache,
      response_config: HoneyfileAutoResponse.normalize_config(%{})
    }

    # Schedule periodic cache refresh
    schedule_cache_refresh()

    {:ok, state}
  end

  @impl true
  def handle_cast({:file_access, event}, state) do
    # Check if the accessed file matches a deployed breadcrumb
    case find_breadcrumb_by_path(state.breadcrumbs_cache, event.file_path, event.agent_id) do
      nil ->
        {:noreply, state}

      breadcrumb ->
        Logger.warning("DECEPTION TRIGGERED: File access on breadcrumb #{breadcrumb.id}")
        new_state = process_breadcrumb_access(breadcrumb, event, state)
        {:noreply, new_state}
    end
  end

  @impl true
  def handle_cast({:breadcrumb_access, event}, state) do
    # Direct breadcrumb access event (from agent canary token trigger)
    case find_breadcrumb_by_token(state.breadcrumbs_cache, event.canary_token) do
      nil ->
        Logger.warning("Unknown canary token accessed: #{event.canary_token}")
        {:noreply, state}

      breadcrumb ->
        Logger.warning("DECEPTION TRIGGERED: Canary token #{event.canary_token} accessed")
        new_state = process_breadcrumb_access(breadcrumb, event, state)
        {:noreply, new_state}
    end
  end

  @impl true
  def handle_call({:configure_response, config}, _from, state) do
    new_config =
      state.response_config
      |> Map.merge(config)
      |> HoneyfileAutoResponse.normalize_config()

    new_state = %{state | response_config: new_config}

    Logger.info("Updated breadcrumb response configuration: #{inspect(new_config)}")
    {:reply, {:ok, new_config}, new_state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = build_statistics(state)
    {:reply, {:ok, stats}, state}
  end

  @impl true
  def handle_call({:get_access_history, breadcrumb_id, opts}, _from, state) do
    history = load_access_history(breadcrumb_id, opts)
    {:reply, {:ok, history}, state}
  end

  @impl true
  def handle_call(:get_effectiveness_report, _from, state) do
    report = generate_effectiveness_report(state)
    {:reply, {:ok, report}, state}
  end

  @impl true
  def handle_info(:refresh_cache, state) do
    Logger.debug("Refreshing breadcrumbs cache")
    new_cache = load_breadcrumbs_cache()
    schedule_cache_refresh()

    {:noreply, %{state | breadcrumbs_cache: new_cache}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp process_breadcrumb_access(breadcrumb, event, state) do
    # 1. Log the access event
    access_log = log_breadcrumb_access(breadcrumb, event)

    # 2. Detect tampering
    tamper_detected = detect_tamper(breadcrumb, event)

    if tamper_detected do
      Logger.error("TAMPER DETECTED on breadcrumb #{breadcrumb.id}")
      update_access_log_tamper(access_log.id, event)
    end

    # 3. Create high-severity alert
    alert = create_breadcrumb_alert(breadcrumb, event, access_log, tamper_detected)

    # 4. Update breadcrumb access tracking
    update_breadcrumb_access(breadcrumb)

    # 5. Trigger automated response
    trigger_automated_response(breadcrumb, event, alert, state.response_config)

    # 6. Update statistics
    update_statistics(state, breadcrumb, event)
  end

  defp log_breadcrumb_access(breadcrumb, event) do
    attrs = %{
      breadcrumb_id: breadcrumb.id,
      agent_id: event[:agent_id] || breadcrumb.agent_id,
      accessed_at: event[:timestamp] || DateTime.utc_now(),
      process_name: event[:process_name],
      pid: event[:pid],
      user: event[:user],
      access_type: event[:access_type] || "read",
      tamper_detected: false,
      original_hash: breadcrumb.content_hash,
      new_hash: event[:file_hash],
      additional_data: %{
        breadcrumb_type: breadcrumb.type,
        breadcrumb_path: breadcrumb.path,
        event_data: event
      }
    }

    case Repo.insert(BreadcrumbAccessLog.changeset(%BreadcrumbAccessLog{}, attrs)) do
      {:ok, log} ->
        Logger.info("Logged breadcrumb access: #{log.id}")
        log

      {:error, changeset} ->
        Logger.error("Failed to log breadcrumb access: #{inspect(changeset.errors)}")
        nil
    end
  end

  defp detect_tamper(breadcrumb, event) do
    cond do
      # File deleted
      event[:access_type] == "delete" ->
        true

      # File moved/renamed
      event[:access_type] == "rename" || event[:access_type] == "move" ->
        true

      # Content modified (hash changed)
      event[:file_hash] && event[:file_hash] != breadcrumb.content_hash ->
        true

      # File written to
      event[:access_type] == "write" || event[:access_type] == "modify" ->
        true

      true ->
        false
    end
  end

  defp update_access_log_tamper(log_id, event) do
    import Ecto.Query

    from(l in BreadcrumbAccessLog, where: l.id == ^log_id)
    |> Repo.update_all(
      set: [
        tamper_detected: true,
        new_hash: event[:file_hash],
        updated_at: DateTime.utc_now()
      ]
    )
  end

  defp create_breadcrumb_alert(breadcrumb, event, access_log, tamper_detected) do
    title = build_alert_title(breadcrumb, tamper_detected)
    description = build_alert_description(breadcrumb, event, tamper_detected)

    alert_attrs = %{
      title: title,
      severity: "high",
      description: description,
      agent_id: event[:agent_id] || breadcrumb.agent_id,
      mitre_techniques: ["T1083"],
      mitre_tactics: ["discovery"],
      evidence: %{
        file_path: breadcrumb.path,
        process: event[:process_name],
        pid: event[:pid],
        user: event[:user],
        access_type: event[:access_type] || "read",
        breadcrumb_type: breadcrumb.type,
        canary_token: breadcrumb.canary_token,
        tamper_detected: tamper_detected,
        original_hash: breadcrumb.content_hash,
        new_hash: event[:file_hash]
      },
      detection_metadata: %{
        detection_type: "honeypot",
        detection_source: "breadcrumb_monitor",
        breadcrumb_id: breadcrumb.id,
        access_log_id: access_log && access_log.id,
        deployed_at: breadcrumb.deployed_at,
        time_to_detection: calculate_time_to_detection(breadcrumb)
      }
    }

    case Alerts.create_alert(alert_attrs) do
      {:ok, alert} ->
        Logger.info("Created breadcrumb alert: #{alert.id}")

        # Update access log with alert reference
        if access_log do
          update_access_log_with_alert(access_log.id, alert.id)
        end

        alert

      {:error, changeset} ->
        Logger.error("Failed to create breadcrumb alert: #{inspect(changeset.errors)}")
        nil
    end
  end

  defp update_access_log_with_alert(log_id, alert_id) do
    import Ecto.Query

    from(l in BreadcrumbAccessLog, where: l.id == ^log_id)
    |> Repo.update_all(set: [alert_id: alert_id, updated_at: DateTime.utc_now()])
  end

  defp build_alert_title(breadcrumb, tamper_detected) do
    action = if tamper_detected, do: "Tampered With", else: "Accessed"
    "Honeyfile #{action}: #{format_breadcrumb_type(breadcrumb.type)}"
  end

  defp build_alert_description(breadcrumb, event, tamper_detected) do
    base = """
    A breadcrumb honeypot file was accessed, indicating potential adversary activity.

    **Breadcrumb Details:**
    - Type: #{format_breadcrumb_type(breadcrumb.type)}
    - Path: #{breadcrumb.path}
    - Deployed: #{format_datetime(breadcrumb.deployed_at)}
    - Access Count: #{breadcrumb.access_count + 1}

    **Access Details:**
    - Process: #{event[:process_name] || "Unknown"}
    - PID: #{event[:pid] || "N/A"}
    - User: #{event[:user] || "Unknown"}
    - Access Type: #{event[:access_type] || "read"}
    - Timestamp: #{format_datetime(event[:timestamp])}
    """

    if tamper_detected do
      base <>
        """

        **⚠️ TAMPER DETECTED:**
        The breadcrumb file was modified, moved, or deleted, indicating active adversary interaction.
        - Original Hash: #{breadcrumb.content_hash}
        - New Hash: #{event[:file_hash] || "N/A"}
        """
    else
      base
    end
  end

  defp format_breadcrumb_type(type) do
    type
    |> to_string()
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp format_datetime(nil), do: "N/A"

  defp format_datetime(dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp calculate_time_to_detection(breadcrumb) do
    now = DateTime.utc_now()
    DateTime.diff(now, breadcrumb.deployed_at, :second)
  end

  defp update_breadcrumb_access(breadcrumb) do
    import Ecto.Query

    from(b in BreadcrumbDeployment, where: b.id == ^breadcrumb.id)
    |> Repo.update_all(
      inc: [access_count: 1],
      set: [status: "accessed", updated_at: DateTime.utc_now()]
    )
  end

  defp trigger_automated_response(breadcrumb, event, alert, config) do
    plan = HoneyfileAutoResponse.plan(breadcrumb, event, alert, config)
    audit_honeyfile_response_plan(plan)
    broadcast_honeyfile_response_plan(plan)

    if HoneyfileAutoResponse.executable?(plan) do
      execute_honeyfile_response_plan(plan)
    else
      Logger.info(
        "Honeyfile response planned in #{plan.policy_gate} mode " <>
          "(dry_run=#{plan.dry_run}, actions=#{length(plan.actions)})"
      )
    end

    if config.trigger_playbook_id && alert do
      Logger.info("Triggering playbook #{config.trigger_playbook_id} for breadcrumb access")

      spawn(fn ->
        Playbook.trigger_for_alert(alert)
      end)
    end

    if config.escalate_to_soc do
      Logger.info("Escalating breadcrumb access to SOC")
      escalate_to_soc(breadcrumb, event, alert)
    end
  end

  defp execute_honeyfile_response_plan(%{actions: actions}) do
    Enum.each(actions, fn action ->
      spawn(fn -> execute_honeyfile_action(action) end)
    end)
  end

  defp execute_honeyfile_action(%{action_type: "kill_process", agent_id: agent_id, params: %{pid: pid}}) do
    case TamanduaServer.Response.Executor.kill_process(agent_id, pid, force: true, actor: :system) do
      {:ok, _} -> Logger.info("Successfully killed honeyfile-touching process #{pid}")
      {:error, reason} -> Logger.error("Failed to kill honeyfile-touching process: #{inspect(reason)}")
    end
  end

  defp execute_honeyfile_action(%{action_type: "isolate_network", agent_id: agent_id, params: params}) do
    opts = [
      allowed_ips: Map.get(params, :allowed_ips, []),
      duration: Map.get(params, :duration_seconds, 0),
      actor: :system
    ]

    case TamanduaServer.Response.Executor.isolate_network(agent_id, opts) do
      {:ok, _} -> Logger.info("Successfully isolated agent #{agent_id} after honeyfile access")
      {:error, reason} -> Logger.error("Failed to isolate agent after honeyfile access: #{inspect(reason)}")
    end
  end

  defp execute_honeyfile_action(%{action_type: "collect_forensics", agent_id: agent_id, params: params}) do
    TamanduaServer.Response.Executor.collect_forensics(agent_id, Map.put(params, :actor, :system))
  end

  defp execute_honeyfile_action(action) do
    Logger.warning("Unsupported honeyfile response action: #{inspect(action)}")
  end

  defp audit_honeyfile_response_plan(plan) do
    TamanduaServer.Response.Audit.log_action(
      "honeyfile_auto_response_planned",
      %{
        dry_run: plan.dry_run,
        policy_gate: to_string(plan.policy_gate),
        trigger: to_string(plan.trigger),
        confidence: plan.confidence,
        actions: Enum.map(plan.actions, &Map.take(&1, [:action_type, :params, :reason])),
        metadata: plan.metadata
      },
      plan.metadata.agent_id,
      :system
    )
  rescue
    e ->
      Logger.warning("Failed to audit honeyfile response plan: #{inspect(e)}")
      :ok
  end

  defp broadcast_honeyfile_response_plan(plan) do
    :telemetry.execute(
      [:tamandua, :response, :honeyfile_auto_response, :planned],
      %{actions: length(plan.actions), confidence: plan.confidence},
      %{
        dry_run: plan.dry_run,
        policy_gate: plan.policy_gate,
        agent_id: plan.metadata.agent_id,
        alert_id: plan.metadata.alert_id
      }
    )

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "autonomous_response:decisions",
      {:autonomous_decision, plan}
    )
  rescue
    _ -> :ok
  end

  defp escalate_to_soc(breadcrumb, event, alert) do
    # Send notification to configured channels (Slack, email, etc.)
    message = """
    🚨 CRITICAL: Breadcrumb Honeypot Accessed

    Type: #{format_breadcrumb_type(breadcrumb.type)}
    Agent: #{event[:agent_id] || breadcrumb.agent_id}
    Process: #{event[:process_name] || "Unknown"}
    User: #{event[:user] || "Unknown"}

    Alert ID: #{alert && alert.id}
    """

    # Trigger notification via configured channels
    # This would integrate with the notification system
    broadcast_notification(message, %{
      severity: "critical",
      type: "breadcrumb_access",
      alert_id: alert && alert.id,
      breadcrumb_id: breadcrumb.id
    })
  end

  defp broadcast_notification(message, metadata) do
    # Publish to Phoenix PubSub for real-time dashboard updates
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:breadcrumb",
      {:breadcrumb_access, message, metadata}
    )
  end

  defp update_statistics(state, breadcrumb, event) do
    new_stats =
      state.access_stats
      |> Map.update!(:total_accesses, &(&1 + 1))
      |> update_in([:by_type, breadcrumb.type], fn count -> (count || 0) + 1 end)
      |> update_in([:by_agent, event[:agent_id] || breadcrumb.agent_id], fn count ->
        (count || 0) + 1
      end)
      |> update_in([:time_to_detection], fn ttd_list ->
        ttd = calculate_time_to_detection(breadcrumb)
        [ttd | Enum.take(ttd_list, 99)]
      end)

    %{state | access_stats: new_stats}
  end

  # ============================================================================
  # Cache Management
  # ============================================================================

  defp load_breadcrumbs_cache do
    import Ecto.Query

    from(b in BreadcrumbDeployment,
      where: b.status in ["active", "accessed"],
      select: b
    )
    |> Repo.all()
    |> Map.new(fn breadcrumb -> {breadcrumb.id, breadcrumb} end)
  rescue
    _ -> %{}
  end

  defp find_breadcrumb_by_path(cache, file_path, agent_id) do
    cache
    |> Map.values()
    |> Enum.find(fn bc ->
      bc.agent_id == agent_id && normalize_path(bc.path) == normalize_path(file_path)
    end)
  end

  defp find_breadcrumb_by_token(cache, canary_token) do
    cache
    |> Map.values()
    |> Enum.find(fn bc -> bc.canary_token == canary_token end)
  end

  defp normalize_path(path) do
    path
    |> String.downcase()
    |> String.replace("\\", "/")
    |> String.trim_trailing("/")
  end

  defp schedule_cache_refresh do
    # Refresh cache every 5 minutes
    Process.send_after(self(), :refresh_cache, :timer.minutes(5))
  end

  # ============================================================================
  # Analytics and Reporting
  # ============================================================================

  defp build_statistics(state) do
    stats = state.access_stats

    avg_ttd =
      if length(stats.time_to_detection) > 0 do
        Enum.sum(stats.time_to_detection) / length(stats.time_to_detection)
      else
        0
      end

    %{
      total_accesses: stats.total_accesses,
      accesses_by_type: stats.by_type,
      accesses_by_agent: stats.by_agent,
      average_time_to_detection_seconds: avg_ttd,
      most_accessed_type: find_most_accessed_type(stats.by_type),
      active_breadcrumbs: map_size(state.breadcrumbs_cache)
    }
  end

  defp find_most_accessed_type(by_type) do
    case Enum.max_by(by_type, fn {_type, count} -> count end, fn -> nil end) do
      {type, count} -> %{type: type, count: count}
      nil -> nil
    end
  end

  defp load_access_history(breadcrumb_id, opts) do
    import Ecto.Query

    limit = Keyword.get(opts, :limit, 100)

    from(l in BreadcrumbAccessLog,
      where: l.breadcrumb_id == ^breadcrumb_id,
      order_by: [desc: l.accessed_at],
      limit: ^limit
    )
    |> Repo.all()
  rescue
    _ -> []
  end

  defp generate_effectiveness_report(_state) do
    import Ecto.Query

    # Get deployment and access counts by type
    deployment_counts =
      from(b in BreadcrumbDeployment,
        group_by: b.type,
        select: {b.type, count(b.id)}
      )
      |> Repo.all()
      |> Map.new()

    access_counts =
      from(b in BreadcrumbDeployment,
        where: b.status == "accessed",
        group_by: b.type,
        select: {b.type, count(b.id)}
      )
      |> Repo.all()
      |> Map.new()

    # Calculate effectiveness (access rate)
    effectiveness =
      deployment_counts
      |> Enum.map(fn {type, deployed} ->
        accessed = Map.get(access_counts, type, 0)

        effectiveness_rate =
          if deployed > 0 do
            Float.round(accessed / deployed * 100, 2)
          else
            0.0
          end

        %{
          type: type,
          deployed: deployed,
          accessed: accessed,
          effectiveness_rate: effectiveness_rate,
          status:
            cond do
              effectiveness_rate > 10 -> "high"
              effectiveness_rate > 5 -> "medium"
              true -> "low"
            end
        }
      end)
      |> Enum.sort_by(& &1.effectiveness_rate, :desc)

    %{
      by_type: effectiveness,
      total_deployed: Enum.sum(Map.values(deployment_counts)),
      total_accessed: Enum.sum(Map.values(access_counts)),
      overall_effectiveness:
        if(Enum.sum(Map.values(deployment_counts)) > 0,
          do:
            Float.round(
              Enum.sum(Map.values(access_counts)) /
                Enum.sum(Map.values(deployment_counts)) * 100,
              2
            ),
          else: 0.0
        ),
      generated_at: DateTime.utc_now()
    }
  rescue
    e ->
      Logger.error("Error generating effectiveness report: #{inspect(e)}")
      %{error: "Failed to generate report"}
  end
end
