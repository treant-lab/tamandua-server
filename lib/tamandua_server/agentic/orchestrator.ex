defmodule TamanduaServer.Agentic.Orchestrator do
  @moduledoc """
  Agentic Workflow Orchestrator

  Central orchestration layer connecting custom AI agents, workflows, and human
  analysts. Manages the complete lifecycle of agent-driven security operations:

  - Routes alerts to appropriate agents based on type, severity, and org
  - Manages agent collaboration (one agent's output triggers another)
  - Enforces human-in-the-loop checkpoints for high-severity actions
  - Priority queue for action execution
  - Conflict resolution when multiple agents recommend contradictory actions
  - Real-time dashboard state for monitoring the agent fleet

  ## Routing Logic

  Alerts are routed based on:
  1. Severity level -> determines priority queue position
  2. Detection type -> maps to agent specialization
  3. Organization -> multi-tenant scoping
  4. Current agent load -> capacity-aware routing

  ## Conflict Resolution

  When multiple agents produce contradictory recommendations:
  1. Higher-confidence recommendation wins
  2. More conservative action wins on ties
  3. Human escalation for unresolvable conflicts
  """

  use GenServer
  require Logger

  alias TamanduaServer.Agentic.{AgentBuilder, AgentRuntime}

  # ETS tables
  @routing_table :orchestrator_routing
  @queue_table :orchestrator_priority_queue
  @conflicts_table :orchestrator_conflicts
  @dashboard_table :orchestrator_dashboard

  # Severity -> priority mapping (lower number = higher priority)
  @severity_priority %{
    critical: 1,
    high: 2,
    medium: 3,
    low: 4
  }

  # Action conservatism ranking (higher = more conservative = preferred on ties)
  @action_conservatism %{
    enrich_context: 10,
    enrich_hash: 10,
    enrich_ip: 10,
    threat_intel_lookup: 10,
    notify: 9,
    create_ticket: 9,
    send_slack: 9,
    collect_evidence: 8,
    scan_yara: 8,
    quarantine_file: 5,
    kill_process: 4,
    block_ip: 3,
    block_domain: 3,
    isolate_host: 2,
    disable_user: 1
  }

  # ============================================================================
  # Types
  # ============================================================================

  defmodule QueueEntry do
    @moduledoc "An entry in the priority action queue"
    defstruct [
      :id,
      :priority,
      :agent_id,
      :execution_id,
      :action,
      :params,
      :context,
      :requires_approval,
      :created_at,
      :status
    ]
  end

  defmodule ConflictRecord do
    @moduledoc "Records a conflict between agent recommendations"
    defstruct [
      :id,
      :alert_id,
      :agents_involved,
      :recommendations,
      :resolution_method,
      :resolved_action,
      :resolved_at,
      :status
    ]
  end

  # ============================================================================
  # GenServer State
  # ============================================================================

  defstruct [
    :stats,
    :routing_rules
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Route an alert to the appropriate agent(s) based on type and severity.
  Returns the list of agent IDs that will handle the alert.
  """
  @spec route_alert(map()) :: {:ok, [String.t()]} | {:error, term()}
  def route_alert(alert) do
    GenServer.call(__MODULE__, {:route_alert, alert})
  end

  @doc """
  Submit an action to the priority queue for execution.
  """
  @spec enqueue_action(map()) :: {:ok, String.t()} | {:error, term()}
  def enqueue_action(action_spec) do
    GenServer.call(__MODULE__, {:enqueue_action, action_spec})
  end

  @doc """
  Approve a queued action that requires human approval.
  """
  @spec approve_action(String.t(), String.t()) :: :ok | {:error, term()}
  def approve_action(queue_entry_id, approver_id) do
    GenServer.call(__MODULE__, {:approve_action, queue_entry_id, approver_id})
  end

  @doc """
  Reject a queued action.
  """
  @spec reject_action(String.t(), String.t(), String.t()) :: :ok | {:error, term()}
  def reject_action(queue_entry_id, rejector_id, reason) do
    GenServer.call(__MODULE__, {:reject_action, queue_entry_id, rejector_id, reason})
  end

  @doc """
  Report a conflict between agent recommendations.
  """
  @spec report_conflict(String.t(), [map()]) :: {:ok, String.t()} | {:error, term()}
  def report_conflict(alert_id, conflicting_recommendations) do
    GenServer.call(__MODULE__, {:report_conflict, alert_id, conflicting_recommendations})
  end

  @doc """
  Get current dashboard state for the agent fleet.
  """
  @spec get_dashboard_state() :: map()
  def get_dashboard_state do
    GenServer.call(__MODULE__, :get_dashboard_state)
  end

  @doc """
  Get the priority action queue.
  """
  @spec get_action_queue(keyword()) :: [QueueEntry.t()]
  def get_action_queue(opts \\ []) do
    status = Keyword.get(opts, :status)

    :ets.tab2list(@queue_table)
    |> Enum.map(fn {_id, entry} -> entry end)
    |> Enum.filter(fn entry ->
      is_nil(status) or entry.status == status
    end)
    |> Enum.sort_by(fn entry -> {entry.priority, entry.created_at} end)
  end

  @doc """
  Get pending conflicts.
  """
  @spec get_conflicts(keyword()) :: [ConflictRecord.t()]
  def get_conflicts(opts \\ []) do
    :ets.tab2list(@conflicts_table)
    |> Enum.map(fn {_id, conflict} -> conflict end)
    |> Enum.filter(fn c ->
      case Keyword.get(opts, :status) do
        nil -> true
        status -> c.status == status
      end
    end)
    |> Enum.sort_by(& &1.resolved_at || &1.id)
  end

  @doc """
  Get orchestrator statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("[Orchestrator] Starting Agentic Workflow Orchestrator")

    :ets.new(@routing_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@queue_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@conflicts_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@dashboard_table, [:named_table, :set, :public, read_concurrency: true])

    # Subscribe to agent events
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agentic:orchestrator")
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:new")

    # Schedule periodic queue processing and dashboard refresh
    Process.send_after(self(), :process_queue, 5_000)
    Process.send_after(self(), :refresh_dashboard, 10_000)
    Process.send_after(self(), :check_conflicts, 30_000)

    state = %__MODULE__{
      stats: %{
        alerts_routed: 0,
        actions_queued: 0,
        actions_executed: 0,
        actions_approved: 0,
        actions_rejected: 0,
        conflicts_detected: 0,
        conflicts_resolved: 0
      },
      routing_rules: default_routing_rules()
    }

    {:ok, state}
  end

  # Handle new alerts for routing
  @impl true
  def handle_info({:new_alert, alert}, state) do
    # Auto-route alerts to matching agents
    case do_route_alert(alert) do
      {:ok, agent_ids} when agent_ids != [] ->
        new_stats = Map.update!(state.stats, :alerts_routed, &(&1 + 1))
        {:noreply, %{state | stats: new_stats}}

      _ ->
        {:noreply, state}
    end
  end

  # Handle completed agent executions for collaboration chains
  @impl true
  def handle_info({:execution_completed, exec_id, agent_id, status, context}, state) do
    # Check for collaboration triggers (one agent's output -> another's input)
    handle_collaboration_trigger(agent_id, status, context)

    # Check for conflicts with other pending actions
    check_action_conflicts(exec_id, context)

    # Update dashboard
    update_dashboard_entry(:execution, %{
      execution_id: exec_id,
      agent_id: agent_id,
      status: status,
      completed_at: DateTime.utc_now()
    })

    {:noreply, state}
  end

  # Process the priority queue
  @impl true
  def handle_info(:process_queue, state) do
    new_state = process_action_queue(state)
    Process.send_after(self(), :process_queue, 5_000)
    {:noreply, new_state}
  end

  # Refresh dashboard state
  @impl true
  def handle_info(:refresh_dashboard, state) do
    refresh_dashboard_state()
    Process.send_after(self(), :refresh_dashboard, 10_000)
    {:noreply, state}
  end

  # Check for and resolve conflicts
  @impl true
  def handle_info(:check_conflicts, state) do
    new_state = auto_resolve_conflicts(state)
    Process.send_after(self(), :check_conflicts, 30_000)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Route an alert to matching agents
  @impl true
  def handle_call({:route_alert, alert}, _from, state) do
    case do_route_alert(alert) do
      {:ok, agent_ids} ->
        new_stats = Map.update!(state.stats, :alerts_routed, &(&1 + 1))
        {:reply, {:ok, agent_ids}, %{state | stats: new_stats}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:enqueue_action, action_spec}, _from, state) do
    entry_id = Ecto.UUID.generate()
    severity = action_spec[:severity] || :medium
    priority = Map.get(@severity_priority, severity_to_atom(severity), 3)

    entry = %QueueEntry{
      id: entry_id,
      priority: priority,
      agent_id: action_spec[:agent_id],
      execution_id: action_spec[:execution_id],
      action: action_spec[:action],
      params: action_spec[:params] || %{},
      context: action_spec[:context] || %{},
      requires_approval: action_spec[:requires_approval] || false,
      created_at: DateTime.utc_now(),
      status: if(action_spec[:requires_approval], do: :pending_approval, else: :queued)
    }

    :ets.insert(@queue_table, {entry_id, entry})

    new_stats = Map.update!(state.stats, :actions_queued, &(&1 + 1))

    Logger.info(
      "[Orchestrator] Enqueued action #{entry.action} with priority #{priority}" <>
      if(entry.requires_approval, do: " (requires approval)", else: "")
    )

    {:reply, {:ok, entry_id}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:approve_action, entry_id, approver_id}, _from, state) do
    case :ets.lookup(@queue_table, entry_id) do
      [{^entry_id, entry}] when entry.status == :pending_approval ->
        updated = %{entry | status: :queued}
        :ets.insert(@queue_table, {entry_id, updated})

        Logger.info("[Orchestrator] Action #{entry_id} approved by #{approver_id}")
        new_stats = Map.update!(state.stats, :actions_approved, &(&1 + 1))
        {:reply, :ok, %{state | stats: new_stats}}

      [{^entry_id, _}] ->
        {:reply, {:error, :not_pending_approval}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:reject_action, entry_id, rejector_id, reason}, _from, state) do
    case :ets.lookup(@queue_table, entry_id) do
      [{^entry_id, entry}] ->
        updated = %{entry | status: :rejected}
        :ets.insert(@queue_table, {entry_id, updated})

        Logger.info("[Orchestrator] Action #{entry_id} rejected by #{rejector_id}: #{reason}")
        new_stats = Map.update!(state.stats, :actions_rejected, &(&1 + 1))
        {:reply, :ok, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:report_conflict, alert_id, recommendations}, _from, state) do
    conflict_id = Ecto.UUID.generate()

    conflict = %ConflictRecord{
      id: conflict_id,
      alert_id: alert_id,
      agents_involved: Enum.map(recommendations, & &1[:agent_id]),
      recommendations: recommendations,
      status: :pending,
      resolution_method: nil,
      resolved_action: nil,
      resolved_at: nil
    }

    :ets.insert(@conflicts_table, {conflict_id, conflict})

    Logger.warning(
      "[Orchestrator] Conflict detected for alert #{alert_id}: " <>
      "#{length(recommendations)} agents have conflicting recommendations"
    )

    new_stats = Map.update!(state.stats, :conflicts_detected, &(&1 + 1))

    # Broadcast for UI
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "agentic:conflicts",
      {:conflict_detected, conflict_id, alert_id}
    )

    {:reply, {:ok, conflict_id}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call(:get_dashboard_state, _from, state) do
    dashboard = build_dashboard_state()
    {:reply, dashboard, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # ============================================================================
  # Routing Logic
  # ============================================================================

  defp do_route_alert(alert) do
    org_id = alert_value(alert, :org_id) || alert_value(alert, :organization_id)

    # Get all enabled agents
    agents = if org_id do
      AgentBuilder.list_agents(org_id) |> Enum.filter(& &1.enabled)
    else
      AgentBuilder.list_enabled_agents()
    end

    # Find agents with matching triggers
    matching_agents = Enum.filter(agents, fn agent ->
      Enum.any?(agent.triggers, fn trigger ->
        trigger_matches_alert?(trigger, alert)
      end)
    end)

    # Sort by specialization match quality
    sorted = Enum.sort_by(matching_agents, fn agent ->
      score_agent_for_alert(agent, alert)
    end, :desc)

    # Trigger matched agents via Runtime
    triggered = Enum.map(sorted, fn agent ->
      case AgentRuntime.trigger_agent(agent.id, alert) do
        {:ok, _exec_id} -> agent.id
        {:error, _} -> nil
      end
    end)
    |> Enum.reject(&is_nil/1)

    {:ok, triggered}
  end

  defp trigger_matches_alert?(trigger, alert) do
    case trigger.type do
      :alert ->
        conditions_match_alert?(trigger.conditions, alert)
      _ ->
        false
    end
  end

  defp conditions_match_alert?(conditions, _alert) when map_size(conditions) == 0, do: true

  defp conditions_match_alert?(conditions, alert) do
    Enum.all?(conditions, fn {key, expected} ->
      actual = alert_value(alert, key)
      match_value?(actual, expected)
    end)
  end

  defp match_value?(actual, expected) when is_list(expected), do: actual in expected
  defp match_value?(actual, expected) when is_atom(expected), do: actual == expected or actual == Atom.to_string(expected)
  defp match_value?(actual, expected), do: actual == expected

  defp score_agent_for_alert(agent, alert) do
    score = 0.0

    # Score based on trigger specificity
    score = score + Enum.max(Enum.map(agent.triggers, fn trigger ->
      map_size(trigger.conditions) * 10.0
    end), fn -> 0.0 end)

    # Score based on data source relevance
    detection_type = to_string(alert_value(alert, :detection_type) || "")
    score = score + if(:alerts in agent.data_sources, do: 5.0, else: 0.0)
    score = score + if(:telemetry in agent.data_sources, do: 3.0, else: 0.0)
    score = score + if(:threat_intel in agent.data_sources and String.length(detection_type) > 0, do: 4.0, else: 0.0)

    # Score based on past performance
    metrics = agent.metrics
    if metrics.executions > 0 do
      success_rate = metrics.successes / max(metrics.executions, 1)
      score + success_rate * 20.0
    else
      score
    end
  end

  defp alert_value(alert, key) when is_atom(key) do
    Map.get(alert, key) || Map.get(alert, to_string(key))
  end

  defp alert_value(alert, key) when is_binary(key) do
    Map.get(alert, key) || Map.get(alert, String.to_existing_atom(key))
  rescue
    ArgumentError -> Map.get(alert, key)
  end

  # ============================================================================
  # Collaboration Handling
  # ============================================================================

  defp handle_collaboration_trigger(completed_agent_id, :completed, context) do
    # Check if any agents should be triggered by this completion
    all_agents = AgentBuilder.list_enabled_agents()

    Enum.each(all_agents, fn agent ->
      # Check for collaboration triggers (agent triggered by another agent's output)
      if has_collaboration_trigger?(agent, completed_agent_id) do
        Logger.info(
          "[Orchestrator] Triggering collaboration: agent '#{agent.name}' " <>
          "triggered by completion of agent #{completed_agent_id}"
        )
        AgentRuntime.trigger_agent(agent.id, Map.put(context, :triggered_by_agent, completed_agent_id))
      end
    end)
  end

  defp handle_collaboration_trigger(_agent_id, _status, _context), do: :ok

  defp has_collaboration_trigger?(agent, source_agent_id) do
    Enum.any?(agent.triggers, fn trigger ->
      trigger.type == :alert and
        Map.get(trigger.conditions, :triggered_by_agent) == source_agent_id
    end)
  end

  # ============================================================================
  # Conflict Detection & Resolution
  # ============================================================================

  defp check_action_conflicts(_exec_id, _context) do
    # Check if there are pending actions from multiple agents for the same target
    queued = :ets.tab2list(@queue_table)
    |> Enum.map(fn {_id, entry} -> entry end)
    |> Enum.filter(&(&1.status == :queued))

    # Group by target (agent_id in context)
    by_target = Enum.group_by(queued, fn entry ->
      entry.context[:agent_id] || entry.params[:agent_id]
    end)

    # Find targets with conflicting actions
    Enum.each(by_target, fn {target_id, entries} ->
      if target_id && length(entries) > 1 do
        actions = Enum.map(entries, & &1.action)
        if has_conflicts?(actions) do
          recommendations = Enum.map(entries, fn e ->
            %{
              agent_id: e.agent_id,
              action: e.action,
              confidence: e.context[:confidence] || 0.5,
              queue_entry_id: e.id
            }
          end)

          report_conflict(target_id, recommendations)
        end
      end
    end)
  end

  defp has_conflicts?(actions) do
    # Detect contradictory actions
    has_isolate = :isolate_host in actions
    has_allow = :unisolate_host in actions

    has_block = Enum.any?(actions, &(&1 in [:block_ip, :block_domain]))
    has_allow_network = :allow_network in actions

    (has_isolate and has_allow) or (has_block and has_allow_network)
  end

  defp auto_resolve_conflicts(state) do
    pending_conflicts = :ets.tab2list(@conflicts_table)
    |> Enum.filter(fn {_id, c} -> c.status == :pending end)

    Enum.reduce(pending_conflicts, state, fn {id, conflict}, acc_state ->
      case resolve_conflict(conflict) do
        {:ok, resolved} ->
          :ets.insert(@conflicts_table, {id, resolved})
          new_stats = Map.update!(acc_state.stats, :conflicts_resolved, &(&1 + 1))
          %{acc_state | stats: new_stats}

        :escalate ->
          # Cannot auto-resolve, leave for human
          Logger.warning("[Orchestrator] Conflict #{id} requires human resolution")
          acc_state
      end
    end)
  end

  defp resolve_conflict(conflict) do
    recommendations = conflict.recommendations

    # Strategy 1: Higher confidence wins
    by_confidence = Enum.sort_by(recommendations, & &1.confidence, :desc)
    top = List.first(by_confidence)

    if top.confidence > 0.8 do
      resolved = %{conflict |
        status: :resolved,
        resolution_method: :highest_confidence,
        resolved_action: top.action,
        resolved_at: DateTime.utc_now()
      }

      # Remove losing entries from queue
      Enum.each(recommendations, fn rec ->
        if rec.queue_entry_id != top[:queue_entry_id] do
          case :ets.lookup(@queue_table, rec.queue_entry_id) do
            [{entry_id, entry}] ->
              :ets.insert(@queue_table, {entry_id, %{entry | status: :superseded}})
            _ -> :ok
          end
        end
      end)

      {:ok, resolved}
    else
      # Strategy 2: Most conservative action wins
      by_conservatism = Enum.sort_by(recommendations, fn rec ->
        Map.get(@action_conservatism, rec.action, 5)
      end, :desc)

      most_conservative = List.first(by_conservatism)

      if most_conservative do
        resolved = %{conflict |
          status: :resolved,
          resolution_method: :most_conservative,
          resolved_action: most_conservative.action,
          resolved_at: DateTime.utc_now()
        }
        {:ok, resolved}
      else
        :escalate
      end
    end
  end

  # ============================================================================
  # Priority Queue Processing
  # ============================================================================

  defp process_action_queue(state) do
    # Get queued actions sorted by priority
    queued = :ets.tab2list(@queue_table)
    |> Enum.map(fn {_id, entry} -> entry end)
    |> Enum.filter(&(&1.status == :queued))
    |> Enum.sort_by(fn entry -> {entry.priority, entry.created_at} end)

    Enum.reduce(Enum.take(queued, 10), state, fn entry, acc_state ->
      case execute_queued_action(entry) do
        :ok ->
          updated = %{entry | status: :executed}
          :ets.insert(@queue_table, {entry.id, updated})
          new_stats = Map.update!(acc_state.stats, :actions_executed, &(&1 + 1))
          %{acc_state | stats: new_stats}

        {:error, reason} ->
          Logger.warning("[Orchestrator] Failed to execute queued action #{entry.id}: #{inspect(reason)}")
          updated = %{entry | status: :failed}
          :ets.insert(@queue_table, {entry.id, updated})
          acc_state
      end
    end)
  end

  defp execute_queued_action(entry) do
    agent_id = entry.params[:agent_id] || entry.context[:agent_id]

    if agent_id do
      case TamanduaServer.Response.Executor.execute_action(
        agent_id,
        to_string(entry.action),
        Map.delete(entry.params, :agent_id)
      ) do
        {:ok, _result} -> :ok
        {:error, reason} -> {:error, reason}
      end
    else
      Logger.debug("[Orchestrator] No agent_id for queued action #{entry.id}, marking as executed")
      :ok
    end
  end

  # ============================================================================
  # Dashboard State
  # ============================================================================

  defp build_dashboard_state do
    agents = AgentBuilder.list_enabled_agents()
    active_executions = AgentRuntime.list_active_executions()
    runtime_stats = AgentRuntime.get_stats()

    queued_actions = :ets.tab2list(@queue_table)
    |> Enum.map(fn {_id, entry} -> entry end)

    pending_approvals = Enum.filter(queued_actions, &(&1.status == :pending_approval))
    pending_conflicts = :ets.tab2list(@conflicts_table)
    |> Enum.filter(fn {_id, c} -> c.status == :pending end)
    |> Enum.map(fn {_id, c} -> c end)

    %{
      agents: %{
        total: length(agents),
        active: length(active_executions),
        by_status: %{
          running: runtime_stats[:active_executions] || 0,
          awaiting_approval: runtime_stats[:awaiting_approval] || 0,
          idle: length(agents) - length(active_executions)
        }
      },
      queue: %{
        total: length(queued_actions),
        pending: Enum.count(queued_actions, &(&1.status == :queued)),
        pending_approval: length(pending_approvals),
        executed: Enum.count(queued_actions, &(&1.status == :executed)),
        failed: Enum.count(queued_actions, &(&1.status == :failed))
      },
      conflicts: %{
        pending: length(pending_conflicts),
        total: :ets.info(@conflicts_table, :size)
      },
      recent_activity: recent_activity(),
      updated_at: DateTime.utc_now()
    }
  end

  defp refresh_dashboard_state do
    dashboard = build_dashboard_state()
    :ets.insert(@dashboard_table, {:current, dashboard})

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "agentic:dashboard",
      {:dashboard_updated, dashboard}
    )
  end

  defp update_dashboard_entry(type, data) do
    :ets.insert(@dashboard_table, {{:event, Ecto.UUID.generate()}, %{
      type: type,
      data: data,
      timestamp: DateTime.utc_now()
    }})
  end

  defp recent_activity do
    :ets.tab2list(@dashboard_table)
    |> Enum.filter(fn
      {{:event, _}, _} -> true
      _ -> false
    end)
    |> Enum.map(fn {_key, entry} -> entry end)
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(20)
  end

  # ============================================================================
  # Routing Rules
  # ============================================================================

  defp default_routing_rules do
    %{
      # Route ransomware alerts to ransomware-tagged agents
      ransomware: %{
        detection_types: ["ransomware", "encryption_behavior"],
        tags: ["ransomware"],
        min_severity: :medium
      },
      # Route phishing to phishing-tagged agents
      phishing: %{
        detection_types: ["phishing", "suspicious_email"],
        tags: ["phishing"],
        min_severity: :low
      },
      # Route lateral movement
      lateral_movement: %{
        detection_types: ["lateral_movement", "remote_execution"],
        mitre_tactics: ["lateral-movement"],
        tags: ["lateral-movement"],
        min_severity: :medium
      },
      # Route credential access
      credential_access: %{
        detection_types: ["credential_theft", "credential_dumping"],
        mitre_tactics: ["credential-access"],
        tags: ["credential-access"],
        min_severity: :high
      }
    }
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp severity_to_atom(s) when is_atom(s), do: s
  defp severity_to_atom("critical"), do: :critical
  defp severity_to_atom("high"), do: :high
  defp severity_to_atom("medium"), do: :medium
  defp severity_to_atom("low"), do: :low
  defp severity_to_atom(_), do: :medium
end
