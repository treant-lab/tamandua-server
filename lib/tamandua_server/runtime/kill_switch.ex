defmodule TamanduaServer.Runtime.KillSwitch do
  @moduledoc """
  Kill switch controller for rapid model isolation on threat detection.

  Provides emergency response capability to isolate compromised ML models
  within 1 second of trigger, preventing further damage from prompt injection,
  data exfiltration, or harmful outputs.

  ## Features

  - Manual and automatic trigger support
  - Sub-second isolation latency (<1s SLA)
  - Armed/disarmed state per model
  - Rate limiting (max 10 triggers/minute per model)
  - Integration with ModelIsolation state machine
  - Agent command dispatch for local enforcement

  ## Usage

      # Arm kill switch for a model
      KillSwitch.arm("model-123")

      # Trigger isolation
      {:ok, result} = KillSwitch.trigger("model-123", "Critical output violation")

      # Check status
      {:armed, state} = KillSwitch.status("model-123")

      # Release after investigation
      KillSwitch.release("model-123")
  """

  use GenServer
  require Logger

  alias TamanduaServer.Runtime.ModelIsolation
  alias TamanduaServer.Response.Executor
  alias TamanduaServer.Agents.Registry, as: AgentRegistry

  @pubsub TamanduaServer.PubSub
  @ets_table :kill_switch_state
  @history_table :kill_switch_history

  # Rate limiting: max 10 triggers per model per minute
  @rate_limit_window_ms 60_000
  @rate_limit_max_triggers 10

  # Agent acknowledgment timeout (500ms as per spec)
  @agent_ack_timeout 500

  @type trigger_result :: %{
          model_id: String.t(),
          status: :triggered | :already_triggered | :rate_limited,
          latency_ms: non_neg_integer(),
          isolation_mode: atom(),
          agent_acked: boolean()
        }

  @type status_result :: {:armed | :disarmed | :triggered, map()}

  # ── Client API ─────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger kill switch for a model.

  Isolates the model within 1 second and dispatches agent command.

  ## Options

  - `:mode` - Isolation mode (`:network`, `:process`, `:memory`, `:full`). Default: `:full`
  - `:triggered_by` - User/system identifier
  - `:alert_id` - Associated alert ID if triggered by detection
  - `:skip_confirmation` - Skip confirmation for manual triggers (default: false)

  ## Returns

  - `{:ok, trigger_result}` - Kill switch triggered successfully
  - `{:error, :model_not_armed}` - Model is not armed (for auto-triggers)
  - `{:error, :rate_limited}` - Too many triggers in window
  - `{:error, reason}` - Other error
  """
  @spec trigger(String.t(), String.t(), keyword()) :: {:ok, trigger_result()} | {:error, atom()}
  def trigger(model_id, reason, opts \\ []) do
    GenServer.call(__MODULE__, {:trigger, model_id, reason, opts}, 5_000)
  end

  @doc """
  Trigger kill switch for ALL models on an agent.

  Use for agent-wide emergencies (e.g., agent compromise detected).
  """
  @spec trigger_for_agent(String.t(), String.t(), keyword()) :: {:ok, [trigger_result()]} | {:error, atom()}
  def trigger_for_agent(agent_id, reason, opts \\ []) do
    GenServer.call(__MODULE__, {:trigger_for_agent, agent_id, reason, opts}, 10_000)
  end

  @doc """
  Get kill switch status for a model.

  ## Returns

  - `{:armed, state_details}` - Model is armed for auto-trigger
  - `{:disarmed, state_details}` - Model is not armed
  - `{:triggered, state_details}` - Model is currently isolated
  """
  @spec status(String.t()) :: status_result()
  def status(model_id) do
    case :ets.lookup(@ets_table, model_id) do
      [{^model_id, state}] ->
        case state.triggered do
          true -> {:triggered, state}
          false -> if state.armed, do: {:armed, state}, else: {:disarmed, state}
        end

      [] ->
        {:disarmed, %{model_id: model_id, armed: false, triggered: false}}
    end
  end

  @doc """
  Arm kill switch for a model (enables auto-trigger on critical alerts).
  """
  @spec arm(String.t()) :: :ok
  def arm(model_id) do
    GenServer.call(__MODULE__, {:arm, model_id})
  end

  @doc """
  Disarm kill switch for a model (disables auto-trigger).
  """
  @spec disarm(String.t()) :: :ok
  def disarm(model_id) do
    GenServer.call(__MODULE__, {:disarm, model_id})
  end

  @doc """
  Release an isolated model (calls ModelIsolation.release).
  """
  @spec release(String.t()) :: {:ok, map()} | {:error, atom()}
  def release(model_id) do
    GenServer.call(__MODULE__, {:release, model_id})
  end

  @doc """
  Get trigger history for a model.

  ## Options

  - `:limit` - Maximum entries to return (default: 100)
  - `:since` - Only entries after this DateTime
  """
  @spec history(String.t(), keyword()) :: [map()]
  def history(model_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    since = Keyword.get(opts, :since)

    :ets.lookup(@history_table, model_id)
    |> Enum.flat_map(fn {_id, entries} -> entries end)
    |> filter_since(since)
    |> Enum.take(limit)
  end

  # ── Server Callbacks ───────────────────────────────────────────────

  @impl true
  def init(_opts) do
    :ets.new(@ets_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@history_table, [:set, :named_table, :public])

    # Subscribe to critical alerts for auto-trigger
    Phoenix.PubSub.subscribe(@pubsub, "alerts:critical")

    Logger.info("[KillSwitch] Started - auto-trigger on critical alerts: #{auto_trigger_enabled?()}")

    {:ok, %{rate_limits: %{}}}
  end

  @impl true
  def handle_call({:trigger, model_id, reason, opts}, _from, state) do
    start_time = System.monotonic_time(:millisecond)

    result = do_trigger(model_id, reason, opts, state)

    latency_ms = System.monotonic_time(:millisecond) - start_time

    # Emit telemetry
    case result do
      {:ok, trigger_result} ->
        emit_trigger_telemetry(model_id, latency_ms, trigger_result, opts)

      _ ->
        :ok
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:trigger_for_agent, agent_id, reason, opts}, _from, state) do
    models = ModelIsolation.list_by_agent(agent_id)

    results =
      Enum.map(models, fn model_state ->
        case do_trigger(model_state.model_id, reason, opts, state) do
          {:ok, result} -> result
          {:error, _} = error -> error
        end
      end)

    successful = Enum.filter(results, &is_map/1)

    {:reply, {:ok, successful}, state}
  end

  @impl true
  def handle_call({:arm, model_id}, _from, state) do
    current = get_or_init_state(model_id)
    new_state = %{current | armed: true}
    :ets.insert(@ets_table, {model_id, new_state})

    Logger.info("[KillSwitch] Armed model #{model_id}")
    broadcast_status_change(model_id, :armed)

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:disarm, model_id}, _from, state) do
    current = get_or_init_state(model_id)
    new_state = %{current | armed: false}
    :ets.insert(@ets_table, {model_id, new_state})

    Logger.info("[KillSwitch] Disarmed model #{model_id}")
    broadcast_status_change(model_id, :disarmed)

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:release, model_id}, _from, state) do
    case ModelIsolation.release(model_id) do
      {:ok, _model_state} = result ->
        # Update kill switch state
        current = get_or_init_state(model_id)
        new_state = %{current | triggered: false, triggered_at: nil}
        :ets.insert(@ets_table, {model_id, new_state})

        Logger.info("[KillSwitch] Released model #{model_id}")
        broadcast_status_change(model_id, :released)

        {:reply, result, state}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_info({:alert_critical, alert}, state) do
    # Auto-trigger on critical alerts if enabled
    if auto_trigger_enabled?() and should_auto_trigger?(alert) do
      model_id = extract_model_id(alert)

      if model_id do
        case status(model_id) do
          {:armed, _} ->
            Logger.info("[KillSwitch] Auto-triggering for model #{model_id} due to critical alert")

            do_trigger(
              model_id,
              "Critical alert: #{alert[:title] || "output validation violation"}",
              [
                mode: determine_isolation_mode(alert),
                triggered_by: "detection_engine",
                alert_id: alert[:id]
              ],
              state
            )

          _ ->
            Logger.debug("[KillSwitch] Model #{model_id} not armed, skipping auto-trigger")
        end
      end
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ── Private Functions ──────────────────────────────────────────────

  defp do_trigger(model_id, reason, opts, _state) do
    start_time = System.monotonic_time(:millisecond)
    mode = Keyword.get(opts, :mode, :full)
    triggered_by = Keyword.get(opts, :triggered_by, "manual")
    alert_id = Keyword.get(opts, :alert_id)

    # Step 1: Check rate limiting
    case check_rate_limit(model_id) do
      :ok ->
        :ok

      {:error, :rate_limited} = error ->
        Logger.warning("[KillSwitch] Rate limited for model #{model_id}")
        return_error(error)
    end

    # Step 2: Check if already triggered (idempotent)
    current_state = get_or_init_state(model_id)

    if current_state.triggered do
      latency_ms = System.monotonic_time(:millisecond) - start_time

      {:ok,
       %{
         model_id: model_id,
         status: :already_triggered,
         latency_ms: latency_ms,
         isolation_mode: current_state.isolation_mode,
         agent_acked: true
       }}
    else
      # Step 3: Get agent_id for the model
      agent_id = get_agent_id(model_id)

      # Step 4: Call ModelIsolation.isolate
      case ModelIsolation.isolate(model_id, agent_id || "unknown",
             mode: mode,
             reason: reason,
             isolated_by: triggered_by
           ) do
        {:ok, _isolation_state} ->
          # Step 5: Dispatch agent command
          agent_acked = dispatch_agent_command(agent_id, model_id, mode)

          # Step 6: Update kill switch state
          now = DateTime.utc_now()

          new_state = %{
            model_id: model_id,
            armed: current_state.armed,
            triggered: true,
            triggered_at: now,
            triggered_by: triggered_by,
            reason: reason,
            alert_id: alert_id,
            isolation_mode: mode
          }

          :ets.insert(@ets_table, {model_id, new_state})

          # Step 7: Record history
          record_trigger_history(model_id, new_state)

          # Step 8: Record rate limit
          record_rate_limit(model_id)

          # Step 9: Create audit log
          create_audit_log(model_id, reason, triggered_by, alert_id, mode)

          # Step 10: Broadcast event
          broadcast_status_change(model_id, :triggered)

          latency_ms = System.monotonic_time(:millisecond) - start_time

          Logger.info(
            "[KillSwitch] Triggered for model #{model_id} in #{latency_ms}ms (mode: #{mode}, agent_acked: #{agent_acked})"
          )

          {:ok,
           %{
             model_id: model_id,
             status: :triggered,
             latency_ms: latency_ms,
             isolation_mode: mode,
             agent_acked: agent_acked
           }}

        {:error, reason} = error ->
          Logger.error("[KillSwitch] Failed to isolate model #{model_id}: #{inspect(reason)}")
          error
      end
    end
  end

  defp return_error(error), do: error

  defp get_or_init_state(model_id) do
    case :ets.lookup(@ets_table, model_id) do
      [{^model_id, state}] ->
        state

      [] ->
        %{
          model_id: model_id,
          armed: false,
          triggered: false,
          triggered_at: nil,
          triggered_by: nil,
          reason: nil,
          alert_id: nil,
          isolation_mode: nil
        }
    end
  end

  defp get_agent_id(model_id) do
    # First check ModelIsolation for tracked agent
    case ModelIsolation.get_state(model_id) do
      {:ok, state} -> state.agent_id
      {:error, _} -> nil
    end
  end

  defp dispatch_agent_command(nil, _model_id, _mode), do: false

  defp dispatch_agent_command(agent_id, model_id, mode) do
    # Check if agent is online
    case AgentRegistry.get(agent_id) do
      {:ok, _agent_info} ->
        # Dispatch isolate_model command with timeout
        task =
          Task.async(fn ->
            Executor.execute_action(agent_id, "isolate_model", %{
              model_id: model_id,
              mode: to_string(mode),
              reason: "Kill switch triggered"
            })
          end)

        case Task.yield(task, @agent_ack_timeout) || Task.shutdown(task) do
          {:ok, {:ok, _}} ->
            true

          {:ok, {:error, reason}} ->
            Logger.warning("[KillSwitch] Agent command failed: #{inspect(reason)}")
            false

          nil ->
            Logger.warning("[KillSwitch] Agent acknowledgment timed out")
            false
        end

      _ ->
        Logger.warning("[KillSwitch] Agent #{agent_id} not found/offline")
        false
    end
  rescue
    e ->
      Logger.warning("[KillSwitch] Agent command error: #{Exception.message(e)}")
      false
  end

  defp check_rate_limit(model_id) do
    now = System.monotonic_time(:millisecond)
    window_start = now - @rate_limit_window_ms

    # Get existing timestamps from ETS
    key = {:rate_limit, model_id}

    timestamps =
      case :ets.lookup(@ets_table, key) do
        [{^key, ts}] -> ts
        [] -> []
      end

    # Filter to window
    recent = Enum.filter(timestamps, fn t -> t > window_start end)

    if length(recent) >= @rate_limit_max_triggers do
      {:error, :rate_limited}
    else
      :ok
    end
  end

  defp record_rate_limit(model_id) do
    now = System.monotonic_time(:millisecond)
    key = {:rate_limit, model_id}

    timestamps =
      case :ets.lookup(@ets_table, key) do
        [{^key, ts}] -> ts
        [] -> []
      end

    # Keep only recent timestamps + new one
    window_start = now - @rate_limit_window_ms
    recent = Enum.filter(timestamps, fn t -> t > window_start end)
    :ets.insert(@ets_table, {key, [now | recent]})
  end

  defp record_trigger_history(model_id, trigger_state) do
    entry = %{
      triggered_at: trigger_state.triggered_at,
      triggered_by: trigger_state.triggered_by,
      reason: trigger_state.reason,
      alert_id: trigger_state.alert_id,
      mode: trigger_state.isolation_mode
    }

    existing =
      case :ets.lookup(@history_table, model_id) do
        [{^model_id, entries}] -> entries
        [] -> []
      end

    # Keep last 1000 entries
    updated = [entry | existing] |> Enum.take(1000)
    :ets.insert(@history_table, {model_id, updated})
  end

  defp filter_since(entries, nil), do: entries

  defp filter_since(entries, since) do
    Enum.filter(entries, fn e ->
      DateTime.compare(e.triggered_at, since) == :gt
    end)
  end

  defp create_audit_log(model_id, reason, triggered_by, alert_id, mode) do
    Task.start(fn ->
      try do
        # Use Audit module if available
        TamanduaServer.Audit.log(%{
          action: "kill_switch:trigger",
          model_id: model_id,
          triggered_by: triggered_by,
          reason: reason,
          alert_id: alert_id,
          isolation_mode: to_string(mode),
          timestamp: DateTime.utc_now()
        })
      rescue
        _ -> :ok
      end
    end)
  end

  defp broadcast_status_change(model_id, event) do
    Phoenix.PubSub.broadcast(
      @pubsub,
      "kill_switch:#{model_id}",
      {:kill_switch, event, model_id}
    )

    Phoenix.PubSub.broadcast(
      @pubsub,
      "kill_switch:all",
      {:kill_switch, model_id, event}
    )
  end

  defp emit_trigger_telemetry(model_id, latency_ms, result, opts) do
    mode = Keyword.get(opts, :mode, :full)

    :telemetry.execute(
      [:tamandua, :kill_switch, :trigger],
      %{latency_ms: latency_ms},
      %{
        model_id: model_id,
        mode: mode,
        status: result.status,
        agent_acked: result.agent_acked,
        triggered_by: Keyword.get(opts, :triggered_by, "manual")
      }
    )
  end

  defp auto_trigger_enabled? do
    Application.get_env(:tamandua_server, :kill_switch, [])
    |> Keyword.get(:auto_trigger_on_critical, true)
  end

  defp should_auto_trigger?(alert) do
    # Auto-trigger conditions:
    # 1. Output validation returned :critical risk
    # 2. Category is output_validation or prompt_injection with critical severity
    category = alert[:category] || alert["category"]
    severity = alert[:severity] || alert["severity"]

    cond do
      category in ["output_validation_violation", "output_validation"] and severity == "critical" ->
        true

      category == "prompt_injection" and severity == "critical" ->
        true

      # Check detection metadata for overall_risk
      get_in(alert, [:detection_metadata, "overall_risk"]) == "critical" ->
        true

      true ->
        false
    end
  end

  defp extract_model_id(alert) do
    # Try multiple sources for model ID
    cond do
      model_id = get_in(alert, [:detection_metadata, "model_id"]) ->
        model_id

      model_id = alert[:model_id] || alert["model_id"] ->
        model_id

      # Generate from session info if available
      session_id = get_in(alert, [:detection_metadata, "session_id"]) ->
        "session:#{session_id}"

      # Fallback: generate from alert metadata
      _agent_id = alert[:agent_id] ->
        process_path = get_in(alert, [:raw_event, "process_path"]) || "unknown"
        api_endpoint = get_in(alert, [:raw_event, "api_endpoint"]) || "unknown"

        components = [process_path, api_endpoint]
        |> Enum.join(":")

        :crypto.hash(:sha256, components) |> Base.encode16(case: :lower) |> String.slice(0, 16)

      true ->
        nil
    end
  end

  defp determine_isolation_mode(alert) do
    severity = alert[:severity] || alert["severity"]
    overall_risk = get_in(alert, [:detection_metadata, "overall_risk"])

    cond do
      severity == "critical" or overall_risk == "critical" -> :full
      severity == "high" or overall_risk == "high" -> :network
      true -> :network
    end
  end
end
