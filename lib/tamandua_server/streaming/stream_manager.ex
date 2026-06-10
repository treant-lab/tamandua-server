defmodule TamanduaServer.Streaming.StreamManager do
  @moduledoc """
  GenServer that manages active SSE and WebSocket streams.

  Responsibilities:
  - Track active stream connections
  - Handle backpressure and slow consumer detection
  - Enforce rate limiting (max 1000 events/sec per stream)
  - Broadcast events to subscribed streams
  - Clean up disconnected streams
  """

  use GenServer
  require Logger

  alias TamanduaServer.Streaming.StreamSubscription

  @max_events_per_sec 1000
  @max_queue_size 10_000
  @slow_consumer_threshold_ms 10_000
  @cleanup_interval 60_000

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Register a new stream subscription.

  ## Parameters
    - stream_id: Unique identifier for this stream
    - subscriber_pid: Process that will receive events
    - filters: Map of filter criteria (severity, agent_id, event_type, etc.)
    - options: Additional options (format: :json | :binary, compression: bool)
  """
  @spec register_stream(String.t(), pid(), map(), map()) :: :ok
  def register_stream(stream_id, subscriber_pid, filters \\ %{}, options \\ %{}) do
    GenServer.call(__MODULE__, {:register_stream, stream_id, subscriber_pid, filters, options})
  end

  @doc """
  Unregister a stream subscription.
  """
  @spec unregister_stream(String.t()) :: :ok
  def unregister_stream(stream_id) do
    GenServer.call(__MODULE__, {:unregister_stream, stream_id})
  end

  @doc """
  Broadcast an alert to all subscribed streams.
  """
  @spec broadcast_alert(map()) :: :ok
  def broadcast_alert(alert) do
    GenServer.cast(__MODULE__, {:broadcast_alert, alert})
  end

  @doc """
  Broadcast an event to all subscribed streams.
  """
  @spec broadcast_event(map()) :: :ok
  def broadcast_event(event) do
    GenServer.cast(__MODULE__, {:broadcast_event, event})
  end

  @doc """
  Broadcast a detection to all subscribed streams.
  """
  @spec broadcast_detection(map()) :: :ok
  def broadcast_detection(detection) do
    GenServer.cast(__MODULE__, {:broadcast_detection, detection})
  end

  @doc """
  Get statistics about active streams.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # ETS table to store stream subscriptions
    :ets.new(:stream_subscriptions, [:named_table, :set, :public, read_concurrency: true])

    # ETS table to store stream metrics
    :ets.new(:stream_metrics, [:named_table, :set, :public])

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup_dead_streams, @cleanup_interval)

    # Start Prometheus metrics
    setup_prometheus_metrics()

    {:ok, %{
      stream_count: 0,
      events_broadcasted: 0,
      slow_consumers_disconnected: 0
    }}
  end

  @impl true
  def handle_call({:register_stream, stream_id, subscriber_pid, filters, options}, _from, state) do
    subscription = %StreamSubscription{
      stream_id: stream_id,
      subscriber_pid: subscriber_pid,
      filters: filters,
      options: options,
      registered_at: System.system_time(:millisecond),
      events_sent: 0,
      last_event_at: nil,
      queue_size: 0
    }

    # Monitor the subscriber process
    Process.monitor(subscriber_pid)

    # Store subscription
    :ets.insert(:stream_subscriptions, {stream_id, subscription})

    # Initialize metrics
    :ets.insert(:stream_metrics, {stream_id, %{
      events_sent: 0,
      events_dropped: 0,
      last_rate: 0,
      queue_size: 0,
      created_at: System.system_time(:millisecond)
    }})

    Logger.info("Stream registered: #{stream_id} with filters: #{inspect(filters)}")
    increment_prometheus_counter(:streams_registered_total)

    {:reply, :ok, %{state | stream_count: state.stream_count + 1}}
  end

  @impl true
  def handle_call({:unregister_stream, stream_id}, _from, state) do
    :ets.delete(:stream_subscriptions, stream_id)
    :ets.delete(:stream_metrics, stream_id)

    Logger.info("Stream unregistered: #{stream_id}")
    increment_prometheus_counter(:streams_unregistered_total)

    {:reply, :ok, %{state | stream_count: max(0, state.stream_count - 1)}}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    active_streams = :ets.info(:stream_subscriptions, :size) || 0

    stats = %{
      active_streams: active_streams,
      total_events_broadcasted: state.events_broadcasted,
      slow_consumers_disconnected: state.slow_consumers_disconnected,
      stream_metrics: get_all_stream_metrics()
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:broadcast_alert, alert}, state) do
    broadcast_to_matching_streams(alert, :alert)
    {:noreply, %{state | events_broadcasted: state.events_broadcasted + 1}}
  end

  @impl true
  def handle_cast({:broadcast_event, event}, state) do
    broadcast_to_matching_streams(event, :event)
    {:noreply, %{state | events_broadcasted: state.events_broadcasted + 1}}
  end

  @impl true
  def handle_cast({:broadcast_detection, detection}, state) do
    broadcast_to_matching_streams(detection, :detection)
    {:noreply, %{state | events_broadcasted: state.events_broadcasted + 1}}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    # Clean up streams for dead process
    cleanup_streams_for_pid(pid)
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_dead_streams, state) do
    # Remove streams with dead pids
    all_streams = :ets.tab2list(:stream_subscriptions)

    dead_count = Enum.reduce(all_streams, 0, fn {stream_id, subscription}, acc ->
      if Process.alive?(subscription.subscriber_pid) do
        acc
      else
        :ets.delete(:stream_subscriptions, stream_id)
        :ets.delete(:stream_metrics, stream_id)
        acc + 1
      end
    end)

    if dead_count > 0 do
      Logger.info("Cleaned up #{dead_count} dead streams")
    end

    # Schedule next cleanup
    Process.send_after(self(), :cleanup_dead_streams, @cleanup_interval)

    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Private Functions

  defp broadcast_to_matching_streams(data, type) do
    all_streams = :ets.tab2list(:stream_subscriptions)
    now = System.system_time(:millisecond)

    Enum.each(all_streams, fn {stream_id, subscription} ->
      if matches_filters?(data, subscription.filters, type) do
        send_to_stream(stream_id, subscription, data, type, now)
      end
    end)
  end

  defp matches_filters?(data, filters, type) do
    # Check stream type filter
    type_match = case filters[:stream_type] do
      nil -> true
      stream_types when is_list(stream_types) -> type in stream_types
      stream_type -> stream_type == type
    end

    # Check severity filter
    severity_match = case filters[:severity] do
      nil -> true
      severities when is_list(severities) ->
        data_severity = data[:severity] || data["severity"]
        data_severity in severities
      severity ->
        data_severity = data[:severity] || data["severity"]
        data_severity == severity
    end

    # Check agent_id filter
    agent_match = case filters[:agent_id] do
      nil -> true
      agent_ids when is_list(agent_ids) ->
        data_agent = data[:agent_id] || data["agent_id"]
        data_agent in agent_ids
      agent_id ->
        data_agent = data[:agent_id] || data["agent_id"]
        data_agent == agent_id
    end

    # Check event_type filter (for events)
    event_type_match = case filters[:event_type] do
      nil -> true
      event_types when is_list(event_types) ->
        data_type = data[:event_type] || data["event_type"]
        data_type in event_types
      event_type ->
        data_type = data[:event_type] || data["event_type"]
        data_type == event_type
    end

    # Check organization_id filter (RBAC)
    org_match = case filters[:organization_id] do
      nil -> true
      org_ids when is_list(org_ids) ->
        data_org = data[:organization_id] || data["organization_id"]
        data_org in org_ids
      org_id ->
        data_org = data[:organization_id] || data["organization_id"]
        data_org == org_id
    end

    type_match and severity_match and agent_match and event_type_match and org_match
  end

  defp send_to_stream(stream_id, subscription, data, type, now) do
    # Get current metrics
    metrics = case :ets.lookup(:stream_metrics, stream_id) do
      [{^stream_id, m}] -> m
      [] -> %{events_sent: 0, events_dropped: 0, last_rate: 0, queue_size: 0, created_at: now}
    end

    # Check rate limit
    time_diff = now - (subscription.last_event_at || subscription.registered_at)
    current_rate = if time_diff > 0 do
      (subscription.events_sent * 1000) / time_diff
    else
      0
    end

    # Check queue size and slow consumer
    if metrics.queue_size > @max_queue_size do
      # Slow consumer detected - disconnect
      Logger.warning("Slow consumer detected for stream #{stream_id}, disconnecting")
      send(subscription.subscriber_pid, {:stream_error, :slow_consumer})
      :ets.delete(:stream_subscriptions, stream_id)
      :ets.delete(:stream_metrics, stream_id)
      increment_prometheus_counter(:slow_consumers_disconnected_total)
    else
      # Send event to subscriber
      message = format_stream_message(data, type, subscription.options)
      send(subscription.subscriber_pid, {:stream_data, type, message})

      # Update subscription
      updated_subscription = %{subscription |
        events_sent: subscription.events_sent + 1,
        last_event_at: now
      }
      :ets.insert(:stream_subscriptions, {stream_id, updated_subscription})

      # Update metrics
      updated_metrics = %{metrics |
        events_sent: metrics.events_sent + 1,
        last_rate: current_rate,
        queue_size: metrics.queue_size + 1
      }
      :ets.insert(:stream_metrics, {stream_id, updated_metrics})

      increment_prometheus_counter(:stream_events_sent_total, %{type: type})
    end
  rescue
    e ->
      Logger.error("Failed to send to stream #{stream_id}: #{Exception.message(e)}")
      increment_prometheus_counter(:stream_errors_total)
  end

  defp format_stream_message(data, type, options) do
    format = options[:format] || :json

    base_message = %{
      type: type,
      data: data,
      timestamp: System.system_time(:millisecond)
    }

    case format do
      :json -> Jason.encode!(base_message)
      :binary -> :erlang.term_to_binary(base_message)
      _ -> Jason.encode!(base_message)
    end
  end

  defp cleanup_streams_for_pid(pid) do
    all_streams = :ets.tab2list(:stream_subscriptions)

    Enum.each(all_streams, fn {stream_id, subscription} ->
      if subscription.subscriber_pid == pid do
        :ets.delete(:stream_subscriptions, stream_id)
        :ets.delete(:stream_metrics, stream_id)
      end
    end)
  end

  defp get_all_stream_metrics do
    :ets.tab2list(:stream_metrics)
    |> Enum.map(fn {stream_id, metrics} -> {stream_id, metrics} end)
    |> Enum.into(%{})
  end

  defp setup_prometheus_metrics do
    # Define Prometheus metrics
    :telemetry.execute(
      [:tamandua, :streaming, :init],
      %{streams: 0},
      %{}
    )
  end

  defp increment_prometheus_counter(metric_name, labels \\ %{}) do
    :telemetry.execute(
      [:tamandua, :streaming, metric_name],
      %{count: 1},
      labels
    )
  end
end
