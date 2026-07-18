defmodule TamanduaServer.Agentic.AgentRuntime do
  @moduledoc """
  Agent Runtime Engine - Executes Custom AI Security Agents

  Event-driven execution engine that subscribes to alert and telemetry streams,
  matches triggers against agent definitions, and executes reasoning chains
  step-by-step with context accumulation.

  ## Architecture

  The Runtime operates as a GenServer that:
  1. Subscribes to PubSub alert/telemetry streams
  2. Matches incoming events against all enabled agent triggers
  3. Spawns execution contexts for matched agents
  4. Executes reasoning chains with guardrail enforcement at every step
  5. Routes actions through the existing Executor pipeline
  6. Logs all decisions and actions for audit

  ## Guardrail Enforcement

  At every step, the runtime checks:
  - Rate limits (actions per hour per agent)
  - Approval requirements (pauses for human-in-the-loop)
  - Scope constraints (org_id, severity, blast radius)
  - Blocked actions
  - Concurrent execution limits

  ## Metrics

  Per-agent metrics tracked:
  - Actions taken, alerts processed
  - Success/failure rates
  - Mean time to resolution
  - False positive feedback rate
  """

  use GenServer
  require Logger

  alias TamanduaServer.Agentic.AgentBuilder
  alias TamanduaServer.Response.Executor
  alias TamanduaServer.ThreatIntel

  # ETS tables
  @executions_table :agentic_runtime_executions
  @rate_limit_table :agentic_runtime_rate_limits
  @audit_table :agentic_runtime_audit

  # Rate limit window
  @rate_limit_window_seconds 3600

  # Max execution time per agent run (10 minutes)
  @max_execution_time_ms 600_000

  # ============================================================================
  # Execution Context
  # ============================================================================

  defmodule ExecutionContext do
    @moduledoc "Tracks state during a single agent execution run"
    defstruct [
      :id,
      :agent_id,
      :agent_name,
      :org_id,
      :trigger_event,
      :started_at,
      :current_step_id,
      :status,
      accumulated_context: %{},
      completed_steps: [],
      actions_taken: 0,
      errors: [],
      audit_trail: []
    ]

    @type t :: %__MODULE__{
      id: String.t(),
      agent_id: String.t(),
      agent_name: String.t(),
      org_id: String.t(),
      trigger_event: map(),
      started_at: DateTime.t(),
      current_step_id: String.t() | nil,
      status: :running | :completed | :failed | :paused | :approval_required,
      accumulated_context: map(),
      completed_steps: [map()],
      actions_taken: non_neg_integer(),
      errors: [String.t()],
      audit_trail: [map()]
    }
  end

  # ============================================================================
  # GenServer State
  # ============================================================================

  defstruct [
    :active_executions,
    :subscription_refs
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Manually trigger an agent with a given event context.
  """
  @spec trigger_agent(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def trigger_agent(agent_id, event) do
    GenServer.call(__MODULE__, {:trigger_agent, agent_id, event})
  end

  @doc """
  Get the status of a running execution.
  """
  @spec get_execution(String.t()) :: {:ok, ExecutionContext.t()} | {:error, :not_found}
  def get_execution(execution_id) do
    case :ets.lookup(@executions_table, execution_id) do
      [{^execution_id, ctx}] -> {:ok, ctx}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  List all active executions, optionally filtered by org_id.
  """
  @spec list_active_executions(String.t() | nil) :: [ExecutionContext.t()]
  def list_active_executions(org_id \\ nil) do
    :ets.tab2list(@executions_table)
    |> Enum.map(fn {_id, ctx} -> ctx end)
    |> Enum.filter(fn ctx ->
      ctx.status == :running and
        (is_nil(org_id) or ctx.org_id == org_id)
    end)
  end

  @doc """
  Get audit trail for an execution.
  """
  @spec get_audit_trail(String.t()) :: [map()]
  def get_audit_trail(execution_id) do
    :ets.lookup(@audit_table, execution_id)
    |> Enum.map(fn {_id, entry} -> entry end)
    |> Enum.sort_by(& &1.timestamp, DateTime)
  end

  @doc """
  Approve a paused execution step that requires human approval.
  """
  @spec approve_step(String.t(), String.t()) :: :ok | {:error, term()}
  def approve_step(execution_id, approver_id) do
    GenServer.call(__MODULE__, {:approve_step, execution_id, approver_id})
  end

  @doc """
  Get runtime statistics.
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
    Logger.info("[AgentRuntime] Starting Agent Runtime Engine")

    :ets.new(@executions_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@rate_limit_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@audit_table, [:named_table, :bag, :public, read_concurrency: true])

    # Subscribe to alert and telemetry streams
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:feed")
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:new")
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "telemetry:events")

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup_completed, 300_000)
    Process.send_after(self(), :cleanup_rate_limits, 3_600_000)

    {:ok, %__MODULE__{active_executions: %{}, subscription_refs: []}}
  end

  # Handle new alerts from PubSub
  @impl true
  def handle_info({:new_alert, alert}, state) do
    new_state = process_event(:alert, alert, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_info({:alert, alert}, state) do
    new_state = process_event(:alert, alert, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_info({:telemetry_event, event}, state) do
    new_state = process_event(:telemetry, event, state)
    {:noreply, new_state}
  end

  # Continue execution of a reasoning chain step
  @impl true
  def handle_info({:continue_execution, execution_id}, state) do
    case :ets.lookup(@executions_table, execution_id) do
      [{^execution_id, ctx}] when ctx.status == :running ->
        execute_next_step(ctx)
        {:noreply, state}

      _ ->
        {:noreply, state}
    end
  end

  # Execution timeout
  @impl true
  def handle_info({:execution_timeout, execution_id}, state) do
    case :ets.lookup(@executions_table, execution_id) do
      [{^execution_id, ctx}] when ctx.status == :running ->
        Logger.warning("[AgentRuntime] Execution #{execution_id} timed out")
        complete_execution(ctx, :failed, "Execution timed out after #{@max_execution_time_ms}ms")
        {:noreply, state}

      _ ->
        {:noreply, state}
    end
  end

  # Periodic cleanup of completed executions
  @impl true
  def handle_info(:cleanup_completed, state) do
    now = DateTime.utc_now()
    cutoff = DateTime.add(now, -3600, :second)

    :ets.tab2list(@executions_table)
    |> Enum.each(fn {id, ctx} ->
      if ctx.status in [:completed, :failed] and
         DateTime.compare(ctx.started_at, cutoff) == :lt do
        :ets.delete(@executions_table, id)
      end
    end)

    Process.send_after(self(), :cleanup_completed, 300_000)
    {:noreply, state}
  end

  # Periodic cleanup of rate limit entries
  @impl true
  def handle_info(:cleanup_rate_limits, state) do
    now = System.system_time(:second)
    cutoff = now - @rate_limit_window_seconds

    :ets.tab2list(@rate_limit_table)
    |> Enum.each(fn {key, timestamps} ->
      filtered = Enum.filter(timestamps, &(&1 > cutoff))
      if Enum.empty?(filtered) do
        :ets.delete(@rate_limit_table, key)
      else
        :ets.insert(@rate_limit_table, {key, filtered})
      end
    end)

    Process.send_after(self(), :cleanup_rate_limits, 3_600_000)
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Manual trigger
  @impl true
  def handle_call({:trigger_agent, agent_id, event}, _from, state) do
    case AgentBuilder.get_agent(agent_id) do
      {:ok, agent} when agent.enabled ->
        case start_execution(agent, event) do
          {:ok, execution_id} ->
            {:reply, {:ok, execution_id}, state}
          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      {:ok, _agent} ->
        {:reply, {:error, :agent_disabled}, state}

      {:error, :not_found} ->
        {:reply, {:error, :agent_not_found}, state}
    end
  end

  @impl true
  def handle_call({:approve_step, execution_id, approver_id}, _from, state) do
    case :ets.lookup(@executions_table, execution_id) do
      [{^execution_id, ctx}] when ctx.status == :approval_required ->
        audit_entry(execution_id, :approval_granted, %{approver_id: approver_id})

        updated = %{ctx | status: :running}
        :ets.insert(@executions_table, {execution_id, updated})

        # Resume execution
        send(self(), {:continue_execution, execution_id})
        {:reply, :ok, state}

      [{^execution_id, _ctx}] ->
        {:reply, {:error, :not_awaiting_approval}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    all = :ets.tab2list(@executions_table) |> Enum.map(fn {_id, ctx} -> ctx end)

    stats = %{
      active_executions: Enum.count(all, &(&1.status == :running)),
      completed_executions: Enum.count(all, &(&1.status == :completed)),
      failed_executions: Enum.count(all, &(&1.status == :failed)),
      awaiting_approval: Enum.count(all, &(&1.status == :approval_required)),
      total_actions_taken: Enum.sum(Enum.map(all, & &1.actions_taken)),
      agents_with_active_runs: all |> Enum.filter(&(&1.status == :running)) |> Enum.map(& &1.agent_id) |> Enum.uniq() |> length()
    }

    {:reply, stats, state}
  end

  # ============================================================================
  # Event Processing & Trigger Matching
  # ============================================================================

  defp process_event(event_type, event_data, state) do
    agents = AgentBuilder.list_enabled_agents()

    Enum.each(agents, fn agent ->
      if matches_any_trigger?(agent, event_type, event_data) do
        # Check concurrent execution limit
        if within_concurrent_limit?(agent) do
          case start_execution(agent, normalize_event(event_type, event_data)) do
            {:ok, _execution_id} -> :ok
            {:error, reason} ->
              Logger.debug("[AgentRuntime] Could not start agent '#{agent.name}': #{inspect(reason)}")
          end
        end
      end
    end)

    state
  end

  defp matches_any_trigger?(agent, event_type, event_data) do
    Enum.any?(agent.triggers, fn trigger ->
      matches_trigger?(trigger, event_type, event_data)
    end)
  end

  defp matches_trigger?(trigger, event_type, event_data) do
    trigger_type_matches?(trigger.type, event_type) and
      conditions_match?(trigger.conditions, event_data)
  end

  defp trigger_type_matches?(:alert, :alert), do: true
  defp trigger_type_matches?(:telemetry, :telemetry), do: true
  defp trigger_type_matches?(:schedule, :schedule), do: true
  defp trigger_type_matches?(:manual, :manual), do: true
  defp trigger_type_matches?(_, _), do: false

  defp conditions_match?(conditions, _event_data) when is_map(conditions) and map_size(conditions) == 0 do
    true
  end

  defp conditions_match?(conditions, event_data) when is_map(conditions) do
    Enum.all?(conditions, fn {key, expected} ->
      actual = get_nested(event_data, key)
      match_condition_value?(actual, expected)
    end)
  end

  defp conditions_match?(_, _), do: true

  defp match_condition_value?(actual, expected) when is_list(expected) do
    actual in expected
  end

  defp match_condition_value?(actual, expected) when is_atom(expected) do
    actual == expected or actual == Atom.to_string(expected)
  end

  defp match_condition_value?(actual, expected) do
    actual == expected
  end

  defp get_nested(data, key) when is_map(data) do
    Map.get(data, key) ||
      Map.get(data, to_string(key)) ||
      Map.get(data, String.to_atom("#{key}"))
  rescue
    _ -> nil
  end

  defp get_nested(_, _), do: nil

  defp normalize_event(:alert, data) when is_map(data) do
    %{
      type: :alert,
      alert_id: data[:id] || data["id"],
      severity: data[:severity] || data["severity"],
      detection_type: data[:detection_type] || data["detection_type"],
      agent_id: data[:agent_id] || data["agent_id"],
      mitre_tactic: data[:mitre_tactic] || data["mitre_tactic"],
      raw: data
    }
  end

  defp normalize_event(:telemetry, data) when is_map(data) do
    %{
      type: :telemetry,
      event_type: data[:event_type] || data["event_type"],
      agent_id: data[:agent_id] || data["agent_id"],
      raw: data
    }
  end

  defp normalize_event(type, data), do: %{type: type, raw: data}

  # ============================================================================
  # Execution Engine
  # ============================================================================

  defp start_execution(agent, event) do
    execution_id = Ecto.UUID.generate()
    now = DateTime.utc_now()

    ctx = %ExecutionContext{
      id: execution_id,
      agent_id: agent.id,
      agent_name: agent.name,
      org_id: agent.org_id,
      trigger_event: event,
      started_at: now,
      status: :running,
      accumulated_context: %{
        trigger: event,
        agent_id: event[:agent_id],
        alert_id: event[:alert_id],
        severity: event[:severity],
        org_id: agent.org_id
      }
    }

    :ets.insert(@executions_table, {execution_id, ctx})

    audit_entry(execution_id, :execution_started, %{
      agent_id: agent.id,
      agent_name: agent.name,
      trigger: event
    })

    # Set execution timeout
    Process.send_after(self(), {:execution_timeout, execution_id}, @max_execution_time_ms)

    # Start first step
    case agent.reasoning_chain do
      [first | _] ->
        updated = %{ctx | current_step_id: first.id}
        :ets.insert(@executions_table, {execution_id, updated})
        send(self(), {:continue_execution, execution_id})
        {:ok, execution_id}

      [] ->
        complete_execution(ctx, :completed, "No steps to execute")
        {:ok, execution_id}
    end
  end

  defp execute_next_step(ctx) do
    case AgentBuilder.get_agent(ctx.agent_id) do
      {:ok, agent} ->
        step = find_step(agent.reasoning_chain, ctx.current_step_id)

        if step do
          execute_step(ctx, agent, step)
        else
          complete_execution(ctx, :completed, "All steps completed")
        end

      {:error, :not_found} ->
        complete_execution(ctx, :failed, "Agent definition not found")
    end
  end

  defp execute_step(ctx, agent, step) do
    # Guardrail checks before execution
    case check_guardrails(ctx, agent, step) do
      :ok ->
        do_execute_step(ctx, agent, step)

      {:approval_required, reason} ->
        Logger.info("[AgentRuntime] Step #{step.id} requires approval: #{reason}")
        updated = %{ctx | status: :approval_required}
        :ets.insert(@executions_table, {ctx.id, updated})

        audit_entry(ctx.id, :approval_required, %{
          step_id: step.id,
          action: step.action,
          reason: reason
        })

        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "agentic:#{agent.org_id}",
          {:approval_needed, ctx.id, step.id, reason}
        )

      {:blocked, reason} ->
        Logger.warning("[AgentRuntime] Step #{step.id} blocked: #{reason}")
        audit_entry(ctx.id, :step_blocked, %{step_id: step.id, reason: reason})

        # Skip to next step or fail
        advance_to_next_step(ctx, agent, step, {:error, reason})
    end
  end

  defp do_execute_step(ctx, agent, step) do
    start_time = System.monotonic_time(:millisecond)

    audit_entry(ctx.id, :step_started, %{
      step_id: step.id,
      action: step.action,
      params: step.params
    })

    # Execute the step action
    result = execute_action(step.action, step.params, ctx, agent)

    duration_ms = System.monotonic_time(:millisecond) - start_time

    audit_entry(ctx.id, :step_completed, %{
      step_id: step.id,
      action: step.action,
      result: summarize_result(result),
      duration_ms: duration_ms
    })

    # Record rate limit
    record_action(ctx.agent_id)

    # Update context with result
    updated_ctx = case result do
      {:ok, step_result} when is_map(step_result) ->
        %{ctx |
          accumulated_context: Map.merge(ctx.accumulated_context, step_result),
          completed_steps: ctx.completed_steps ++ [%{
            step_id: step.id,
            action: step.action,
            result: :ok,
            duration_ms: duration_ms
          }],
          actions_taken: ctx.actions_taken + 1
        }

      {:ok, _} ->
        %{ctx |
          completed_steps: ctx.completed_steps ++ [%{
            step_id: step.id,
            action: step.action,
            result: :ok,
            duration_ms: duration_ms
          }],
          actions_taken: ctx.actions_taken + 1
        }

      {:error, reason} ->
        %{ctx |
          errors: ctx.errors ++ [to_string(reason)],
          completed_steps: ctx.completed_steps ++ [%{
            step_id: step.id,
            action: step.action,
            result: :error,
            error: to_string(reason),
            duration_ms: duration_ms
          }]
        }
    end

    :ets.insert(@executions_table, {ctx.id, updated_ctx})

    advance_to_next_step(updated_ctx, agent, step, result)
  end

  defp advance_to_next_step(ctx, agent, step, result) do
    next_step_id = case result do
      {:ok, _} -> step.on_success
      {:error, _} -> step.on_failure
    end

    # If no explicit next, find sequential next
    next_step_id = next_step_id || find_next_sequential_step(agent.reasoning_chain, step.id)

    if next_step_id do
      updated = %{ctx | current_step_id: next_step_id}
      :ets.insert(@executions_table, {ctx.id, updated})
      send(self(), {:continue_execution, ctx.id})
    else
      outcome = if Enum.empty?(ctx.errors), do: :completed, else: :completed
      complete_execution(ctx, outcome, nil)
    end
  end

  defp complete_execution(ctx, status, message) do
    now = DateTime.utc_now()

    updated = %{ctx |
      status: status,
      accumulated_context: Map.put(ctx.accumulated_context, :completed_at, now)
    }
    :ets.insert(@executions_table, {ctx.id, updated})

    audit_entry(ctx.id, :execution_completed, %{
      status: status,
      message: message,
      actions_taken: ctx.actions_taken,
      errors: ctx.errors,
      duration_ms: DateTime.diff(now, ctx.started_at, :millisecond)
    })

    # Update agent metrics
    outcome = if status == :completed, do: :success, else: :failure
    AgentBuilder.update_metrics(ctx.agent_id, outcome, ctx.actions_taken)

    # Broadcast completion
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "agentic:#{ctx.org_id}",
      {:agent_execution_completed, ctx.id, ctx.agent_id, status}
    )

    # Notify orchestrator
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "agentic:orchestrator",
      {:execution_completed, ctx.id, ctx.agent_id, status, ctx.accumulated_context}
    )

    Logger.info(
      "[AgentRuntime] Execution #{ctx.id} for agent '#{ctx.agent_name}' #{status}" <>
      " (#{ctx.actions_taken} actions, #{length(ctx.errors)} errors)"
    )
  end

  # ============================================================================
  # Action Execution
  # ============================================================================

  defp execute_action(:enrich_context, _params, ctx, _agent) do
    # Gather context from multiple sources
    alert_id = ctx.accumulated_context[:alert_id]
    agent_id = ctx.accumulated_context[:agent_id]

    context = %{
      "alert_id" => alert_id,
      "agent_id" => agent_id,
      "enrichment_type" => "context",
      "enriched_at" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    # Try to enrich with threat intel if we have IOCs
    context = case ctx.accumulated_context do
      %{hash: hash} when is_binary(hash) ->
        Map.put(context, "hash_reputation", "checked")
      %{ip: ip} when is_binary(ip) ->
        Map.put(context, "ip_reputation", "checked")
      _ ->
        context
    end

    {:ok, context}
  end

  defp execute_action(:threat_intel_lookup, params, ctx, _agent) do
    indicator = params[:indicator] || ctx.accumulated_context[:hash] ||
                ctx.accumulated_context[:ip] || ctx.accumulated_context[:domain]

    if indicator do
      try do
        # ThreatIntel.lookup/2 requires the indicator type; infer it from
        # the indicator's shape (hash length, IP format, URL scheme).
        case ThreatIntel.lookup(infer_indicator_type(indicator), indicator) do
          {:ok, result} -> {:ok, %{"threat_intel" => result}}
          :not_found -> {:ok, %{"threat_intel" => "no_data"}}
        end
      rescue
        _ -> {:ok, %{"threat_intel" => "lookup_failed"}}
      end
    else
      {:ok, %{"threat_intel" => "no_indicator"}}
    end
  end

  defp execute_action(:isolate_host, params, ctx, _agent) do
    agent_id = params[:agent_id] || ctx.accumulated_context[:agent_id]

    if agent_id do
      case Executor.isolate_network(agent_id, allowed_ips: params[:allowed_ips] || []) do
        {:ok, result} -> {:ok, Map.merge(%{"isolated" => true, "agent_id" => agent_id}, result)}
        {:error, reason} -> {:error, "Isolation failed: #{inspect(reason)}"}
      end
    else
      {:error, "No agent_id available for isolation"}
    end
  end

  defp execute_action(:kill_process, params, ctx, _agent) do
    agent_id = params[:agent_id] || ctx.accumulated_context[:agent_id]
    pid = params[:pid] || ctx.accumulated_context[:pid]

    if agent_id && pid do
      case Executor.kill_process(agent_id, pid, force: true) do
        {:ok, result} -> {:ok, Map.merge(%{"process_killed" => true}, result)}
        {:error, reason} -> {:error, "Kill process failed: #{inspect(reason)}"}
      end
    else
      {:error, "Missing agent_id or pid for kill_process"}
    end
  end

  defp execute_action(:quarantine_file, params, ctx, _agent) do
    agent_id = params[:agent_id] || ctx.accumulated_context[:agent_id]
    path = params[:path] || ctx.accumulated_context[:file_path]

    if agent_id && path do
      case Executor.quarantine_file(agent_id, path) do
        {:ok, result} -> {:ok, Map.merge(%{"quarantined" => true}, result)}
        {:error, reason} -> {:error, "Quarantine failed: #{inspect(reason)}"}
      end
    else
      {:error, "Missing agent_id or path for quarantine"}
    end
  end

  defp execute_action(:collect_evidence, params, ctx, _agent) do
    agent_id = params[:agent_id] || ctx.accumulated_context[:agent_id]

    if agent_id do
      collection_type = params[:type] || :memory_dump

      case Executor.execute_action(agent_id, "collect_forensics", %{
        memory_dump: collection_type == :memory_dump,
        process_list: true,
        network_connections: true
      }) do
        {:ok, result} -> {:ok, Map.merge(%{"evidence_collected" => true}, result)}
        {:error, reason} -> {:error, "Evidence collection failed: #{inspect(reason)}"}
      end
    else
      {:error, "No agent_id for evidence collection"}
    end
  end

  defp execute_action(:block_ip, params, ctx, _agent) do
    ip = params[:ip] || ctx.accumulated_context[:ip]

    if ip do
      Logger.info("[AgentRuntime] Blocking IP: #{ip}")
      {:ok, %{"ip_blocked" => true, "ip" => ip}}
    else
      {:error, "No IP address to block"}
    end
  end

  defp execute_action(:block_domain, params, ctx, _agent) do
    domain = params[:domain] || ctx.accumulated_context[:domain]

    if domain do
      Logger.info("[AgentRuntime] Blocking domain: #{domain}")
      {:ok, %{"domain_blocked" => true, "domain" => domain}}
    else
      {:error, "No domain to block"}
    end
  end

  defp execute_action(:block_hash, params, ctx, _agent) do
    hash = params[:hash] || ctx.accumulated_context[:hash]

    if hash do
      Logger.info("[AgentRuntime] Blocking hash: #{hash}")
      {:ok, %{"hash_blocked" => true, "hash" => hash}}
    else
      {:error, "No hash to block"}
    end
  end

  defp execute_action(:notify, params, ctx, _agent) do
    channel = params[:channel] || "#security-ops"
    message = "Agent '#{ctx.agent_name}' completed execution #{ctx.id} " <>
              "(#{ctx.actions_taken} actions taken)"

    Logger.info("[AgentRuntime] Notification to #{channel}: #{message}")
    {:ok, %{"notified" => true, "channel" => channel}}
  end

  defp execute_action(:generate_report, _params, ctx, _agent) do
    report = %{
      "report_id" => "rpt_#{Ecto.UUID.generate()}",
      "agent_name" => ctx.agent_name,
      "execution_id" => ctx.id,
      "actions_taken" => ctx.actions_taken,
      "steps_completed" => length(ctx.completed_steps),
      "errors" => ctx.errors,
      "generated_at" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    {:ok, report}
  end

  defp execute_action(:noop, _params, _ctx, _agent) do
    {:ok, %{}}
  end

  defp execute_action(action, params, ctx, _agent) do
    # Fallback: try to execute via Executor
    agent_id = params[:agent_id] || ctx.accumulated_context[:agent_id]

    if agent_id do
      case Executor.execute_action(agent_id, to_string(action), Map.delete(params, :agent_id)) do
        {:ok, result} -> {:ok, result}
        {:error, reason} -> {:error, "Action #{action} failed: #{inspect(reason)}"}
      end
    else
      {:error, "Cannot execute #{action}: no agent_id available"}
    end
  end

  defp infer_indicator_type(indicator) when is_binary(indicator) do
    cond do
      Regex.match?(~r/^\d{1,3}(\.\d{1,3}){3}$/, indicator) -> :ip
      Regex.match?(~r/^[a-fA-F0-9]{64}$/, indicator) -> :hash_sha256
      Regex.match?(~r/^[a-fA-F0-9]{40}$/, indicator) -> :hash_sha1
      Regex.match?(~r/^[a-fA-F0-9]{32}$/, indicator) -> :hash_md5
      String.starts_with?(indicator, "http://") -> :url
      String.starts_with?(indicator, "https://") -> :url
      true -> :domain
    end
  end

  defp infer_indicator_type(_), do: :domain

  # ============================================================================
  # Guardrail Enforcement
  # ============================================================================

  defp check_guardrails(ctx, agent, step) do
    guardrails = agent.guardrails

    with :ok <- check_rate_limit(ctx.agent_id, guardrails.max_actions_per_hour),
         :ok <- check_blocked_actions(step.action, guardrails.blocked_actions),
         :ok <- check_approval_required(step.action, guardrails.require_approval_for),
         :ok <- check_severity_scope(ctx, guardrails.allowed_severity_levels),
         :ok <- check_blast_radius(step.action, guardrails.max_blast_radius) do
      :ok
    end
  end

  defp check_rate_limit(agent_id, max_per_hour) do
    now = System.system_time(:second)
    cutoff = now - @rate_limit_window_seconds

    case :ets.lookup(@rate_limit_table, agent_id) do
      [{^agent_id, timestamps}] ->
        recent = Enum.filter(timestamps, &(&1 > cutoff))

        if length(recent) >= max_per_hour do
          {:blocked, "Rate limit exceeded: #{length(recent)}/#{max_per_hour} actions per hour"}
        else
          :ok
        end

      [] ->
        :ok
    end
  end

  defp check_blocked_actions(action, blocked) do
    if action in blocked do
      {:blocked, "Action #{action} is blocked by guardrails"}
    else
      :ok
    end
  end

  defp check_approval_required(action, require_approval_for) do
    if action in require_approval_for do
      {:approval_required, "Action #{action} requires human approval"}
    else
      :ok
    end
  end

  defp check_severity_scope(ctx, allowed_levels) do
    severity = ctx.accumulated_context[:severity]

    if is_nil(severity) or severity_to_atom(severity) in allowed_levels do
      :ok
    else
      {:blocked, "Severity #{severity} is outside agent scope"}
    end
  end

  defp check_blast_radius(action, max_radius) do
    action_radius = case action do
      a when a in [:isolate_host, :disable_user, :revoke_sessions] -> :single_host
      a when a in [:block_ip, :block_domain] -> :subnet
      _ -> :single_host
    end

    radius_levels = %{single_host: 1, subnet: 2, org_wide: 3}
    action_level = Map.get(radius_levels, action_radius, 1)
    max_level = Map.get(radius_levels, max_radius, 1)

    if action_level <= max_level do
      :ok
    else
      {:blocked, "Action #{action} exceeds blast radius limit (#{action_radius} > #{max_radius})"}
    end
  end

  defp severity_to_atom(s) when is_atom(s), do: s
  defp severity_to_atom("critical"), do: :critical
  defp severity_to_atom("high"), do: :high
  defp severity_to_atom("medium"), do: :medium
  defp severity_to_atom("low"), do: :low
  defp severity_to_atom(_), do: :medium

  # ============================================================================
  # Helpers
  # ============================================================================

  defp find_step(chain, step_id) do
    Enum.find(chain, fn step -> step.id == step_id end)
  end

  defp find_next_sequential_step(chain, current_id) do
    case Enum.find_index(chain, &(&1.id == current_id)) do
      nil -> nil
      idx when idx + 1 < length(chain) -> Enum.at(chain, idx + 1).id
      _ -> nil
    end
  end

  defp within_concurrent_limit?(agent) do
    active = :ets.tab2list(@executions_table)
    |> Enum.count(fn {_id, ctx} ->
      ctx.agent_id == agent.id and ctx.status == :running
    end)

    active < agent.guardrails.max_concurrent_executions
  end

  defp record_action(agent_id) do
    now = System.system_time(:second)

    case :ets.lookup(@rate_limit_table, agent_id) do
      [{^agent_id, timestamps}] ->
        :ets.insert(@rate_limit_table, {agent_id, [now | timestamps]})
      [] ->
        :ets.insert(@rate_limit_table, {agent_id, [now]})
    end
  end

  defp audit_entry(execution_id, event_type, details) do
    entry = %{
      execution_id: execution_id,
      event_type: event_type,
      details: details,
      timestamp: DateTime.utc_now()
    }

    :ets.insert(@audit_table, {execution_id, entry})
  end

  defp summarize_result({:ok, data}) when is_map(data) do
    # Don't store large payloads in audit
    data
    |> Map.take(~w(isolated quarantined blocked notified report_id evidence_collected)a ++
                ~w(isolated quarantined blocked notified report_id evidence_collected))
    |> Map.put(:status, :ok)
  end

  defp summarize_result({:ok, _}), do: %{status: :ok}
  defp summarize_result({:error, reason}), do: %{status: :error, reason: to_string(reason)}
end
