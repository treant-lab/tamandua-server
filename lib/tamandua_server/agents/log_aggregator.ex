defmodule TamanduaServer.Agents.LogAggregator do
  @moduledoc """
  Aggregates logs from multiple agents and streams to connected viewers.

  This GenServer manages:
  - Registration of log stream subscribers
  - Buffering of incoming agent logs
  - Distribution to matching subscribers
  - Error pattern detection
  - Performance metrics extraction
  """

  use GenServer
  require Logger

  alias TamanduaServer.Logs.Storage
  alias TamanduaServer.Alerts

  @table :log_streams
  @pattern_table :log_patterns
  @metrics_table :log_metrics

  # Error patterns to detect
  @error_patterns [
    %{pattern: "panic", severity: :critical, category: :panic},
    %{pattern: "segmentation fault", severity: :critical, category: :crash},
    %{pattern: "out of memory", severity: :critical, category: :resource},
    %{pattern: "connection refused", severity: :high, category: :network},
    %{pattern: "timeout", severity: :medium, category: :timeout},
    %{pattern: "permission denied", severity: :medium, category: :permission},
    %{pattern: "file not found", severity: :low, category: :file_system}
  ]

  ## Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Register a log stream subscriber.
  """
  def register_stream(stream_id, pid, filters) do
    GenServer.call(__MODULE__, {:register_stream, stream_id, pid, filters})
  end

  @doc """
  Update stream filters.
  """
  def update_stream(stream_id, filters) do
    GenServer.call(__MODULE__, {:update_stream, stream_id, filters})
  end

  @doc """
  Unregister a log stream subscriber.
  """
  def unregister_stream(stream_id) do
    GenServer.call(__MODULE__, {:unregister_stream, stream_id})
  end

  @doc """
  Process incoming log entry from agent.
  """
  def process_log(agent_id, log_entry) do
    GenServer.cast(__MODULE__, {:log_entry, agent_id, log_entry})
  end

  @doc """
  Process batch of log entries from agent.
  """
  def process_log_batch(agent_id, log_entries) do
    GenServer.cast(__MODULE__, {:log_batch, agent_id, log_entries})
  end

  @doc """
  Get aggregated metrics from logs.
  """
  def get_metrics(time_window_seconds \\ 300) do
    GenServer.call(__MODULE__, {:get_metrics, time_window_seconds})
  end

  @doc """
  Get detected error patterns.
  """
  def get_error_patterns(limit \\ 100) do
    GenServer.call(__MODULE__, {:get_patterns, limit})
  end

  ## Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@pattern_table, [:ordered_set, :named_table, :public])
    :ets.new(@metrics_table, [:set, :named_table, :public])

    # Schedule periodic cleanup
    schedule_cleanup()
    schedule_metrics_aggregation()

    {:ok, %{
      stream_count: 0,
      total_logs_processed: 0,
      error_count: 0
    }}
  end

  @impl true
  def handle_call({:register_stream, stream_id, pid, filters}, _from, state) do
    # Monitor the subscriber process
    ref = Process.monitor(pid)

    # Store stream registration
    :ets.insert(@table, {stream_id, %{
      pid: pid,
      ref: ref,
      filters: filters,
      registered_at: System.system_time(:millisecond),
      log_count: 0
    }})

    Logger.info("Log stream registered: #{stream_id}")

    {:reply, :ok, %{state | stream_count: state.stream_count + 1}}
  end

  @impl true
  def handle_call({:update_stream, stream_id, filters}, _from, state) do
    case :ets.lookup(@table, stream_id) do
      [{^stream_id, stream_info}] ->
        updated_info = %{stream_info | filters: filters}
        :ets.insert(@table, {stream_id, updated_info})
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:unregister_stream, stream_id}, _from, state) do
    case :ets.lookup(@table, stream_id) do
      [{^stream_id, stream_info}] ->
        Process.demonitor(stream_info.ref, [:flush])
        :ets.delete(@table, stream_id)
        Logger.info("Log stream unregistered: #{stream_id}")
        {:reply, :ok, %{state | stream_count: max(0, state.stream_count - 1)}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_metrics, time_window}, _from, state) do
    cutoff = System.system_time(:millisecond) - (time_window * 1000)

    metrics =
      :ets.tab2list(@metrics_table)
      |> Enum.filter(fn {timestamp, _} -> timestamp >= cutoff end)
      |> aggregate_metrics()

    {:reply, {:ok, metrics}, state}
  end

  @impl true
  def handle_call({:get_patterns, limit}, _from, state) do
    patterns =
      :ets.tab2list(@pattern_table)
      |> Enum.sort_by(fn {timestamp, _} -> timestamp end, :desc)
      |> Enum.take(limit)
      |> Enum.map(fn {_, pattern} -> pattern end)

    {:reply, {:ok, patterns}, state}
  end

  @impl true
  def handle_cast({:log_entry, agent_id, log_entry}, state) do
    # Enrich log entry with agent_id
    enriched_log = Map.put(log_entry, :agent_id, agent_id)

    # Store in ClickHouse (async)
    Task.start(fn ->
      Storage.store_log(enriched_log)
    end)

    # Detect error patterns
    detect_error_patterns(enriched_log)

    # Extract metrics
    extract_metrics(enriched_log)

    # Broadcast to matching streams
    broadcast_to_streams(enriched_log)

    {:noreply, %{state | total_logs_processed: state.total_logs_processed + 1}}
  end

  @impl true
  def handle_cast({:log_batch, agent_id, log_entries}, state) do
    # Process batch
    enriched_logs = Enum.map(log_entries, &Map.put(&1, :agent_id, agent_id))

    # Store batch in ClickHouse (async)
    Task.start(fn ->
      Storage.store_log_batch(enriched_logs)
    end)

    # Detect patterns and extract metrics
    Enum.each(enriched_logs, fn log ->
      detect_error_patterns(log)
      extract_metrics(log)
    end)

    # Broadcast batch to matching streams
    broadcast_batch_to_streams(enriched_logs)

    {:noreply, %{state | total_logs_processed: state.total_logs_processed + length(log_entries)}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    # Cleanup old entries from pattern and metrics tables
    cutoff = System.system_time(:millisecond) - (24 * 60 * 60 * 1000) # 24 hours

    cleanup_table(@pattern_table, cutoff)
    cleanup_table(@metrics_table, cutoff)

    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(:aggregate_metrics, state) do
    # Aggregate and flush metrics periodically
    aggregate_and_flush_metrics()

    schedule_metrics_aggregation()
    {:noreply, state}
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    # Find and remove stream by ref
    case find_stream_by_ref(ref) do
      {stream_id, _stream_info} ->
        :ets.delete(@table, stream_id)
        Logger.debug("Log stream removed (process down): #{stream_id}")
        {:noreply, %{state | stream_count: max(0, state.stream_count - 1)}}

      nil ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  ## Private Functions

  defp broadcast_to_streams(log_entry) do
    :ets.tab2list(@table)
    |> Enum.each(fn {stream_id, stream_info} ->
      if matches_filters?(log_entry, stream_info.filters) do
        send(stream_info.pid, {:log_entry, log_entry})

        # Update log count
        updated_info = %{stream_info | log_count: stream_info.log_count + 1}
        :ets.insert(@table, {stream_id, updated_info})
      end
    end)
  end

  defp broadcast_batch_to_streams(log_entries) do
    :ets.tab2list(@table)
    |> Enum.each(fn {stream_id, stream_info} ->
      matching_logs = Enum.filter(log_entries, &matches_filters?(&1, stream_info.filters))

      if not Enum.empty?(matching_logs) do
        send(stream_info.pid, {:log_batch, matching_logs})

        # Update log count
        updated_info = %{stream_info | log_count: stream_info.log_count + length(matching_logs)}
        :ets.insert(@table, {stream_id, updated_info})
      end
    end)
  end

  defp matches_filters?(log, filters) do
    agent_match = Enum.empty?(filters.agent_ids) or log.agent_id in filters.agent_ids
    level_match = Enum.empty?(filters.levels) or log.level in filters.levels
    component_match = Enum.empty?(filters.components) or log.component in filters.components

    keyword_match = is_nil(filters.keyword) or String.contains?(log.message, filters.keyword)

    regex_match =
      if filters.regex do
        case Regex.compile(filters.regex) do
          {:ok, regex} -> Regex.match?(regex, log.message)
          _ -> true
        end
      else
        true
      end

    time_match =
      (is_nil(filters.time_start) or log.timestamp >= filters.time_start) and
      (is_nil(filters.time_end) or log.timestamp <= filters.time_end)

    agent_match and level_match and component_match and keyword_match and regex_match and time_match
  end

  defp detect_error_patterns(log) do
    # Only check error and warn level logs
    if log.level in ["error", "warn"] do
      Enum.each(error_patterns(), fn pattern_def ->
        if Regex.match?(pattern_def.pattern, log.message) do
          pattern_entry = %{
            timestamp: log.timestamp,
            agent_id: log.agent_id,
            category: pattern_def.category,
            severity: pattern_def.severity,
            message: log.message,
            component: log.component
          }

          # Store pattern detection
          :ets.insert(@pattern_table, {log.timestamp, pattern_entry})

          # Create alert for critical patterns
          if pattern_def.severity == :critical do
            create_pattern_alert(pattern_entry)
          end
        end
      end)
    end
  end

  defp error_patterns do
    Enum.map(@error_patterns, fn pattern_def ->
      %{pattern_def | pattern: Regex.compile!(pattern_def.pattern, "i")}
    end)
  end

  defp create_pattern_alert(pattern) do
    Task.start(fn ->
      Alerts.create_alert(%{
        title: "Critical error pattern detected: #{pattern.category}",
        severity: "critical",
        agent_id: pattern.agent_id,
        source: "log_analysis",
        description: "Critical error pattern detected in agent logs",
        details: %{
          category: pattern.category,
          message: pattern.message,
          component: pattern.component,
          timestamp: pattern.timestamp
        }
      })
    end)
  end

  defp extract_metrics(log) do
    timestamp = div(log.timestamp, 60_000) * 60_000 # Round to minute

    # Extract performance metrics from log message
    metrics = parse_metrics_from_log(log)

    if not Enum.empty?(metrics) do
      case :ets.lookup(@metrics_table, timestamp) do
        [{^timestamp, existing_metrics}] ->
          merged = merge_metrics(existing_metrics, metrics)
          :ets.insert(@metrics_table, {timestamp, merged})

        [] ->
          :ets.insert(@metrics_table, {timestamp, metrics})
      end
    end
  end

  defp parse_metrics_from_log(log) do
    metrics = %{}

    # Extract CPU usage
    metrics = case Regex.run(~r/cpu[:\s]+(\d+(?:\.\d+)?)[%\s]?/i, log.message) do
      [_, cpu] -> Map.put(metrics, :cpu_usage, to_float(cpu))
      _ -> metrics
    end

    # Extract memory usage
    metrics = case Regex.run(~r/memory[:\s]+(\d+(?:\.\d+)?)\s*(MB|GB|%)?/i, log.message) do
      [_, mem, unit] ->
        value = to_float(mem)
        normalized = if unit == "GB", do: value * 1024, else: value
        Map.put(metrics, :memory_usage, normalized)
      _ -> metrics
    end

    # Extract event rate
    metrics = case Regex.run(~r/(\d+)\s+events?\/(sec|min)/i, log.message) do
      [_, count, unit] ->
        rate = String.to_integer(count)
        normalized = if unit == "min", do: rate / 60, else: rate
        Map.put(metrics, :event_rate, normalized)
      _ -> metrics
    end

    # Extract duration/latency
    metrics = case Regex.run(~r/duration[:\s]+(\d+(?:\.\d+)?)\s*(ms|s)?/i, log.message) do
      [_, duration, unit] ->
        value = to_float(duration)
        normalized = if unit == "s", do: value * 1000, else: value
        Map.put(metrics, :duration_ms, normalized)
      _ -> metrics
    end

    metrics
  end

  # Parse a numeric string to float, tolerating integer forms ("50") that
  # String.to_float/1 would reject with an ArgumentError (crashing the
  # GenServer on agent-supplied log text like "cpu: 50%").
  defp to_float(str) do
    case Float.parse(str) do
      {value, _rest} -> value
      :error -> 0.0
    end
  end

  defp merge_metrics(existing, new) do
    Map.merge(existing, new, fn _key, v1, v2 ->
      # Average the values
      (v1 + v2) / 2
    end)
  end

  defp aggregate_metrics(metric_entries) do
    metric_entries
    |> Enum.reduce(%{}, fn {_timestamp, metrics}, acc ->
      Map.merge(acc, metrics, fn _key, v1, v2 ->
        (v1 + v2) / 2
      end)
    end)
  end

  defp aggregate_and_flush_metrics do
    # Aggregate recent metrics and potentially flush to time-series DB
    # For now, just log the aggregated metrics
    case get_metrics(60) do
      {:ok, metrics} when map_size(metrics) > 0 ->
        Logger.debug("Aggregated log metrics: #{inspect(metrics)}")
      _ ->
        :ok
    end
  end

  defp cleanup_table(table, cutoff) do
    # Delete entries older than cutoff
    :ets.select_delete(table, [
      {
        {:"$1", :_},
        [{:<, :"$1", cutoff}],
        [true]
      }
    ])
  end

  defp find_stream_by_ref(ref) do
    :ets.tab2list(@table)
    |> Enum.find(fn {_stream_id, stream_info} ->
      stream_info.ref == ref
    end)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, :timer.hours(1))
  end

  defp schedule_metrics_aggregation do
    Process.send_after(self(), :aggregate_metrics, :timer.minutes(5))
  end
end
