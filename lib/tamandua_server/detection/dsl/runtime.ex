defmodule TamanduaServer.Detection.DSL.Runtime do
  @moduledoc """
  Runtime execution engine for compiled DSL detections.

  Maintains state for sequence tracking and aggregation windows,
  executes compiled detections against events, and triggers alerts.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.DSL.{Parser, Compiler}
  alias TamanduaServer.Alerts

  @table_name :dsl_detection_state
  @compiled_detections :dsl_compiled_detections
  @event_buffer :dsl_event_buffer
  @max_buffer_size 100_000
  @cleanup_interval :timer.minutes(5)

  # ─────────────────────────────────────────────────────────────────────
  # Client API
  # ─────────────────────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Load and compile a DSL detection from source code.
  """
  @spec load_detection(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def load_detection(source) do
    GenServer.call(__MODULE__, {:load_detection, source}, 30_000)
  end

  @doc """
  Load multiple detections from a list of sources.
  """
  @spec load_detections([String.t()]) :: {:ok, [String.t()]} | {:error, String.t()}
  def load_detections(sources) when is_list(sources) do
    GenServer.call(__MODULE__, {:load_detections, sources}, 60_000)
  end

  @doc """
  Unload a detection by name.
  """
  @spec unload_detection(String.t()) :: :ok
  def unload_detection(name) do
    GenServer.call(__MODULE__, {:unload_detection, name})
  end

  @doc """
  Get list of loaded detection names.
  """
  @spec list_detections() :: [String.t()]
  def list_detections do
    GenServer.call(__MODULE__, :list_detections)
  end

  @doc """
  Get detection details by name.
  """
  @spec get_detection(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_detection(name) do
    GenServer.call(__MODULE__, {:get_detection, name})
  end

  @doc """
  Process an event through all loaded detections.

  Returns list of triggered detections with their actions.
  """
  @spec process_event(map()) :: {:ok, [map()]}
  def process_event(event) do
    GenServer.call(__MODULE__, {:process_event, event}, 10_000)
  end

  @doc """
  Get runtime statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Clear all state (useful for testing).
  """
  @spec clear_state() :: :ok
  def clear_state do
    GenServer.call(__MODULE__, :clear_state)
  end

  # ─────────────────────────────────────────────────────────────────────
  # Server Callbacks
  # ─────────────────────────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@table_name, [:named_table, :public, :set, read_concurrency: true])
    :ets.new(@compiled_detections, [:named_table, :public, :set, read_concurrency: true])
    :ets.new(@event_buffer, [:named_table, :public, :bag, read_concurrency: true])

    # Schedule cleanup
    Process.send_after(self(), :cleanup, @cleanup_interval)

    state = %{
      stats: %{
        events_processed: 0,
        detections_triggered: 0,
        alerts_created: 0,
        compilation_errors: 0
      }
    }

    Logger.info("[DSL Runtime] Started with ETS state tables")
    {:ok, state}
  end

  @impl true
  def handle_call({:load_detection, source}, _from, state) do
    case compile_and_store(source) do
      {:ok, name} ->
        Logger.info("[DSL Runtime] Loaded detection: #{name}")
        {:reply, {:ok, name}, state}

      {:error, reason} = error ->
        Logger.error("[DSL Runtime] Failed to load detection: #{reason}")
        new_stats = update_in(state.stats.compilation_errors, &(&1 + 1))
        {:reply, error, %{state | stats: new_stats}}
    end
  end

  @impl true
  def handle_call({:load_detections, sources}, _from, state) do
    results =
      Enum.map(sources, fn source ->
        case compile_and_store(source) do
          {:ok, name} -> {:ok, name}
          {:error, reason} -> {:error, reason}
        end
      end)

    successes = Enum.filter(results, &match?({:ok, _}, &1))
    errors = Enum.filter(results, &match?({:error, _}, &1))

    if Enum.empty?(errors) do
      names = Enum.map(successes, fn {:ok, name} -> name end)
      Logger.info("[DSL Runtime] Loaded #{length(names)} detections")
      {:reply, {:ok, names}, state}
    else
      error_messages = Enum.map(errors, fn {:error, msg} -> msg end)
      {:reply, {:error, "Failed to load some detections: #{Enum.join(error_messages, "; ")}"}, state}
    end
  end

  @impl true
  def handle_call({:unload_detection, name}, _from, state) do
    :ets.delete(@compiled_detections, name)
    Logger.info("[DSL Runtime] Unloaded detection: #{name}")
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:list_detections, _from, state) do
    names =
      :ets.tab2list(@compiled_detections)
      |> Enum.map(fn {name, _compiled} -> name end)

    {:reply, names, state}
  end

  @impl true
  def handle_call({:get_detection, name}, _from, state) do
    case :ets.lookup(@compiled_detections, name) do
      [{^name, compiled}] ->
        details = %{
          name: compiled.name,
          metadata: compiled.metadata,
          has_sequence: compiled.sequence_matcher != nil,
          has_aggregation: compiled.aggregator != nil,
          ast: compiled.ast
        }

        {:reply, {:ok, details}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:process_event, event}, _from, state) do
    # Get all compiled detections
    detections = :ets.tab2list(@compiled_detections)

    # Track event in buffer
    buffer_event(event)

    # Process through each detection
    results =
      Enum.flat_map(detections, fn {_name, compiled} ->
        case evaluate_detection(compiled, event) do
          {:ok, actions} when length(actions) > 0 ->
            # Execute actions
            execute_actions(compiled, actions, event)
            [%{detection: compiled.name, actions: actions}]

          _ ->
            []
        end
      end)

    # Update stats
    new_stats = %{
      state.stats
      | events_processed: state.stats.events_processed + 1,
        detections_triggered: state.stats.detections_triggered + length(results)
    }

    {:reply, {:ok, results}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = %{
      state.stats
      | loaded_detections: :ets.info(@compiled_detections, :size) || 0,
        active_sequences: :ets.info(@table_name, :size) || 0,
        buffered_events: :ets.info(@event_buffer, :size) || 0
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_call(:clear_state, _from, state) do
    :ets.delete_all_objects(@table_name)
    :ets.delete_all_objects(@event_buffer)
    Logger.info("[DSL Runtime] Cleared all state")
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_state()
    cleanup_event_buffer()
    Process.send_after(self(), :cleanup, @cleanup_interval)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ─────────────────────────────────────────────────────────────────────
  # Private Functions
  # ─────────────────────────────────────────────────────────────────────

  defp compile_and_store(source) do
    with {:ok, ast} <- Parser.parse(source),
         {:ok, compiled} <- Compiler.compile(ast) do
      :ets.insert(@compiled_detections, {compiled.name, compiled})
      {:ok, compiled.name}
    end
  end

  defp evaluate_detection(compiled, event) do
    # Get current state for this detection
    state_key = compiled.state_key
    agent_id = event["agent_id"] || event[:agent_id]
    full_key = {state_key, agent_id}

    state =
      case :ets.lookup(@table_name, full_key) do
        [{^full_key, s}] -> s
        [] -> %{}
      end

    # Evaluate sequence matcher if present
    {matched, new_state} =
      if compiled.sequence_matcher do
        case compiled.sequence_matcher.(event, state) do
          {:ok, matched?, updated_state} ->
            {matched?, updated_state}

          _ ->
            {false, state}
        end
      else
        # No sequence - use simple evaluator
        case compiled.evaluator.(event, state) do
          {:ok, matched?, updated_state} -> {matched?, updated_state}
          _ -> {false, state}
        end
      end

    # Update state
    :ets.insert(@table_name, {full_key, new_state})

    # If matched, check aggregation rules
    if matched do
      if compiled.aggregator do
        # Get recent events for aggregation
        events = get_buffered_events(agent_id)
        compiled.aggregator.(events, new_state)
      else
        # No aggregation - just return basic alert action
        {:ok, [%{type: :create_alert, message: "Detection matched: #{compiled.metadata["name"]}"}]}
      end
    else
      {:ok, []}
    end
  end

  defp execute_actions(compiled, actions, event) do
    Enum.each(actions, fn action ->
      case action.type do
        :create_alert ->
          create_alert(compiled, action, event)

        :escalate ->
          escalate_alert(compiled, action, event)

        :execute ->
          execute_command(compiled, action, event)

        _ ->
          Logger.warning("[DSL Runtime] Unknown action type: #{action.type}")
      end
    end)
  end

  defp create_alert(compiled, action, event) do
    alert_params = %{
      title: action.message || compiled.metadata["name"],
      description: compiled.metadata["description"] || "",
      severity: compiled.metadata["severity"],
      confidence: 85,
      agent_id: event["agent_id"] || event[:agent_id],
      detection_type: "dsl_#{compiled.name}",
      detection_source: "dsl",
      event_data: event,
      mitre_techniques: compiled.metadata["mitre"] || [],
      status: "open"
    }

    case Alerts.create_alert(alert_params) do
      {:ok, alert} ->
        Logger.info("[DSL Runtime] Created alert #{alert.id} for detection #{compiled.name}")
        :ok

      {:error, reason} ->
        Logger.error("[DSL Runtime] Failed to create alert: #{inspect(reason)}")
        :error
    end
  rescue
    e ->
      Logger.error("[DSL Runtime] Alert creation error: #{Exception.message(e)}")
      :error
  end

  defp escalate_alert(compiled, action, event) do
    # Create alert with escalated severity
    alert_params = %{
      title: "ESCALATED: #{compiled.metadata["name"]}",
      description: "Escalated to #{action.severity}: #{compiled.metadata["description"]}",
      severity: action.severity,
      confidence: 95,
      agent_id: event["agent_id"] || event[:agent_id],
      detection_type: "dsl_#{compiled.name}_escalated",
      detection_source: "dsl",
      event_data: event,
      mitre_techniques: compiled.metadata["mitre"] || [],
      status: "open",
      escalated: true
    }

    case Alerts.create_alert(alert_params) do
      {:ok, alert} ->
        Logger.warning("[DSL Runtime] ESCALATED alert #{alert.id} to #{action.severity}")
        :ok

      {:error, reason} ->
        Logger.error("[DSL Runtime] Failed to escalate alert: #{inspect(reason)}")
        :error
    end
  rescue
    e ->
      Logger.error("[DSL Runtime] Alert escalation error: #{Exception.message(e)}")
      :error
  end

  defp execute_command(compiled, action, _event) do
    Logger.info("[DSL Runtime] Would execute command for #{compiled.name}: #{action.command}")
    # TODO: Implement command execution via playbook system
    :ok
  end

  defp buffer_event(event) do
    timestamp = System.system_time(:second)
    agent_id = event["agent_id"] || event[:agent_id]
    event_with_ts = Map.put(event, :buffered_at, timestamp)

    :ets.insert(@event_buffer, {agent_id, event_with_ts})

    # Limit buffer size
    size = :ets.info(@event_buffer, :size) || 0

    if size > @max_buffer_size do
      # Remove oldest 10%
      cleanup_event_buffer(div(@max_buffer_size, 10))
    end
  end

  defp get_buffered_events(agent_id) do
    :ets.lookup(@event_buffer, agent_id)
    |> Enum.map(fn {_key, event} -> event end)
    |> Enum.sort_by(& &1[:buffered_at], :desc)
  end

  defp cleanup_old_state do
    # Remove state entries older than 24 hours
    cutoff = System.system_time(:second) - 86400

    deleted =
      :ets.tab2list(@table_name)
      |> Enum.filter(fn {_key, state} ->
        started_at = get_in(state, [:started_at])
        started_at && started_at < cutoff
      end)
      |> Enum.each(fn {key, _state} ->
        :ets.delete(@table_name, key)
      end)
      |> length()

    if deleted > 0 do
      Logger.debug("[DSL Runtime] Cleaned up #{deleted} old sequence states")
    end
  end

  defp cleanup_event_buffer(limit \\ nil) do
    cutoff = System.system_time(:second) - 3600  # 1 hour

    all_events =
      :ets.tab2list(@event_buffer)
      |> Enum.sort_by(fn {_key, event} -> event[:buffered_at] || 0 end)

    to_delete =
      if limit do
        Enum.take(all_events, limit)
      else
        Enum.filter(all_events, fn {_key, event} ->
          (event[:buffered_at] || 0) < cutoff
        end)
      end

    Enum.each(to_delete, fn {key, event} ->
      :ets.delete_object(@event_buffer, {key, event})
    end)

    if length(to_delete) > 0 do
      Logger.debug("[DSL Runtime] Cleaned up #{length(to_delete)} buffered events")
    end
  end
end
