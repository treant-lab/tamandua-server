defmodule TamanduaServer.Observability.SLAMonitor do
  @moduledoc """
  SLA monitoring and reporting for Tamandua EDR.

  Tracks:
  - System availability (target: 99.99%)
  - Event processing latency
  - Detection time (event to alert)
  - Response action execution time
  - API response times
  """

  use GenServer
  require Logger

  @sla_targets %{
    availability_percent: 99.99,
    event_latency_p95_ms: 100,
    detection_latency_p95_ms: 500,
    response_latency_p95_ms: 1000,
    api_latency_p95_ms: 200
  }

  @collection_interval :timer.minutes(1)
  @retention_hours 24 * 30  # 30 days

  defstruct [
    metrics: %{},
    history: [],
    alerts: [],
    current_period_start: nil
  ]

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record an event processing latency.
  """
  @spec record_event_latency(integer()) :: :ok
  def record_event_latency(latency_ms) do
    GenServer.cast(__MODULE__, {:record, :event_latency, latency_ms})
  end

  @doc """
  Record a detection latency (time from event to alert).
  """
  @spec record_detection_latency(integer()) :: :ok
  def record_detection_latency(latency_ms) do
    GenServer.cast(__MODULE__, {:record, :detection_latency, latency_ms})
  end

  @doc """
  Record a response action latency.
  """
  @spec record_response_latency(integer()) :: :ok
  def record_response_latency(latency_ms) do
    GenServer.cast(__MODULE__, {:record, :response_latency, latency_ms})
  end

  @doc """
  Record an API request latency.
  """
  @spec record_api_latency(integer()) :: :ok
  def record_api_latency(latency_ms) do
    GenServer.cast(__MODULE__, {:record, :api_latency, latency_ms})
  end

  @doc """
  Record system availability (1 = up, 0 = down).
  """
  @spec record_availability(0 | 1) :: :ok
  def record_availability(status) do
    GenServer.cast(__MODULE__, {:record, :availability, status})
  end

  @doc """
  Get current SLA status.
  """
  @spec current_status() :: map()
  def current_status do
    GenServer.call(__MODULE__, :current_status)
  end

  @doc """
  Get SLA report for a time period.
  """
  @spec report(DateTime.t(), DateTime.t()) :: map()
  def report(from, to) do
    GenServer.call(__MODULE__, {:report, from, to})
  end

  @doc """
  Get SLA alerts (violations).
  """
  @spec alerts() :: [map()]
  def alerts do
    GenServer.call(__MODULE__, :alerts)
  end

  @doc """
  Check if all SLAs are being met.
  """
  @spec meeting_sla?() :: boolean()
  def meeting_sla? do
    GenServer.call(__MODULE__, :meeting_sla?)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %__MODULE__{
      metrics: init_metrics(),
      current_period_start: System.system_time(:millisecond)
    }

    # Schedule periodic aggregation
    schedule_aggregation()

    Logger.info("SLA Monitor initialized with targets: #{inspect(@sla_targets)}")
    {:ok, state}
  end

  @impl true
  def handle_cast({:record, metric_type, value}, state) do
    metrics = Map.update(state.metrics, metric_type, [value], fn values ->
      # Keep last 10000 values
      Enum.take([value | values], 10000)
    end)

    {:noreply, %{state | metrics: metrics}}
  end

  @impl true
  def handle_call(:current_status, _from, state) do
    status = calculate_current_status(state)
    {:reply, status, state}
  end

  @impl true
  def handle_call({:report, from, to}, _from, state) do
    report = generate_report(state, from, to)
    {:reply, report, state}
  end

  @impl true
  def handle_call(:alerts, _from, state) do
    {:reply, state.alerts, state}
  end

  @impl true
  def handle_call(:meeting_sla?, _from, state) do
    status = calculate_current_status(state)
    meeting = Enum.all?(status.metrics, fn {_name, data} ->
      data.meeting_sla
    end)
    {:reply, meeting, state}
  end

  @impl true
  def handle_info(:aggregate, state) do
    # Aggregate metrics and check for violations
    state = aggregate_metrics(state)
    state = check_sla_violations(state)

    # Clean old history
    state = clean_old_history(state)

    schedule_aggregation()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp init_metrics do
    %{
      event_latency: [],
      detection_latency: [],
      response_latency: [],
      api_latency: [],
      availability: []
    }
  end

  defp schedule_aggregation do
    Process.send_after(self(), :aggregate, @collection_interval)
  end

  defp calculate_current_status(state) do
    %{
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      period_start: format_timestamp(state.current_period_start),
      targets: @sla_targets,
      metrics: %{
        availability: calculate_availability_metric(state.metrics.availability),
        event_latency: calculate_latency_metric(state.metrics.event_latency, @sla_targets.event_latency_p95_ms),
        detection_latency: calculate_latency_metric(state.metrics.detection_latency, @sla_targets.detection_latency_p95_ms),
        response_latency: calculate_latency_metric(state.metrics.response_latency, @sla_targets.response_latency_p95_ms),
        api_latency: calculate_latency_metric(state.metrics.api_latency, @sla_targets.api_latency_p95_ms)
      },
      overall_meeting_sla: meeting_all_slas?(state)
    }
  end

  defp calculate_availability_metric(values) do
    count = length(values)

    if count > 0 do
      uptime_count = Enum.count(values, &(&1 == 1))
      availability = (uptime_count / count) * 100

      %{
        current: Float.round(availability, 4),
        target: @sla_targets.availability_percent,
        meeting_sla: availability >= @sla_targets.availability_percent,
        sample_count: count
      }
    else
      %{
        current: 100.0,
        target: @sla_targets.availability_percent,
        meeting_sla: true,
        sample_count: 0
      }
    end
  end

  defp calculate_latency_metric(values, target) do
    count = length(values)

    if count > 0 do
      sorted = Enum.sort(values)
      p50 = percentile(sorted, 50)
      p95 = percentile(sorted, 95)
      p99 = percentile(sorted, 99)

      %{
        p50: p50,
        p95: p95,
        p99: p99,
        target_p95: target,
        meeting_sla: p95 <= target,
        sample_count: count,
        min: Enum.min(sorted),
        max: Enum.max(sorted),
        avg: Enum.sum(sorted) / count
      }
    else
      %{
        p50: 0,
        p95: 0,
        p99: 0,
        target_p95: target,
        meeting_sla: true,
        sample_count: 0
      }
    end
  end

  defp percentile(sorted_list, p) do
    count = length(sorted_list)
    if count == 0 do
      0
    else
      index = round(p / 100 * count) - 1
      index = max(0, min(index, count - 1))
      Enum.at(sorted_list, index)
    end
  end

  defp meeting_all_slas?(state) do
    metrics = state.metrics

    availability_ok = calculate_availability_metric(metrics.availability).meeting_sla
    event_ok = calculate_latency_metric(metrics.event_latency, @sla_targets.event_latency_p95_ms).meeting_sla
    detection_ok = calculate_latency_metric(metrics.detection_latency, @sla_targets.detection_latency_p95_ms).meeting_sla
    response_ok = calculate_latency_metric(metrics.response_latency, @sla_targets.response_latency_p95_ms).meeting_sla
    api_ok = calculate_latency_metric(metrics.api_latency, @sla_targets.api_latency_p95_ms).meeting_sla

    availability_ok and event_ok and detection_ok and response_ok and api_ok
  end

  defp aggregate_metrics(state) do
    now = System.system_time(:millisecond)

    # Create history entry
    history_entry = %{
      timestamp: now,
      metrics: %{
        availability: calculate_availability_metric(state.metrics.availability),
        event_latency: calculate_latency_metric(state.metrics.event_latency, @sla_targets.event_latency_p95_ms),
        detection_latency: calculate_latency_metric(state.metrics.detection_latency, @sla_targets.detection_latency_p95_ms),
        response_latency: calculate_latency_metric(state.metrics.response_latency, @sla_targets.response_latency_p95_ms),
        api_latency: calculate_latency_metric(state.metrics.api_latency, @sla_targets.api_latency_p95_ms)
      }
    }

    history = [history_entry | state.history]

    # Reset metrics for new period
    %{state |
      metrics: init_metrics(),
      history: history,
      current_period_start: now
    }
  end

  defp check_sla_violations(state) do
    latest = List.first(state.history)

    if latest do
      new_alerts = Enum.flat_map(latest.metrics, fn {name, data} ->
        if not data.meeting_sla do
          [%{
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
            metric: name,
            current_value: get_metric_value(data),
            target: get_target_value(data),
            severity: :warning
          }]
        else
          []
        end
      end)

      if length(new_alerts) > 0 do
        Logger.warning("SLA violations detected: #{inspect(new_alerts)}")

        # Broadcast alert
        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "system:alerts",
          {:sla_violation, new_alerts}
        )
      end

      # Keep last 100 alerts
      alerts = (new_alerts ++ state.alerts) |> Enum.take(100)
      %{state | alerts: alerts}
    else
      state
    end
  end

  defp get_metric_value(%{current: value}), do: value
  defp get_metric_value(%{p95: value}), do: value
  defp get_metric_value(_), do: nil

  defp get_target_value(%{target: value}), do: value
  defp get_target_value(%{target_p95: value}), do: value
  defp get_target_value(_), do: nil

  defp clean_old_history(state) do
    cutoff = System.system_time(:millisecond) - (@retention_hours * 60 * 60 * 1000)

    history = Enum.filter(state.history, fn entry ->
      entry.timestamp > cutoff
    end)

    %{state | history: history}
  end

  defp generate_report(state, from, to) do
    from_ms = DateTime.to_unix(from, :millisecond)
    to_ms = DateTime.to_unix(to, :millisecond)

    # Filter history for the period
    period_history = Enum.filter(state.history, fn entry ->
      entry.timestamp >= from_ms and entry.timestamp <= to_ms
    end)

    # Calculate aggregates
    %{
      period: %{
        from: DateTime.to_iso8601(from),
        to: DateTime.to_iso8601(to)
      },
      targets: @sla_targets,
      samples: length(period_history),
      aggregates: aggregate_history(period_history),
      violations: count_violations(period_history),
      meeting_all_slas: count_violations(period_history) == 0
    }
  end

  defp aggregate_history([]), do: %{}
  defp aggregate_history(history) do
    # Aggregate metrics across all history entries
    metrics = [:availability, :event_latency, :detection_latency, :response_latency, :api_latency]

    Enum.map(metrics, fn metric ->
      values = Enum.map(history, fn entry ->
        entry.metrics[metric]
      end)

      aggregate = case metric do
        :availability ->
          # Average availability
          avg = Enum.sum(Enum.map(values, & &1.current)) / length(values)
          %{average_percent: Float.round(avg, 4)}

        _ ->
          # Average P95 latency
          avg_p95 = Enum.sum(Enum.map(values, & &1.p95)) / length(values)
          %{average_p95_ms: Float.round(avg_p95, 2)}
      end

      {metric, aggregate}
    end)
    |> Map.new()
  end

  defp count_violations(history) do
    Enum.reduce(history, 0, fn entry, acc ->
      violations = Enum.count(entry.metrics, fn {_name, data} ->
        not data.meeting_sla
      end)
      acc + violations
    end)
  end

  defp format_timestamp(nil), do: nil
  defp format_timestamp(ms) do
    ms
    |> DateTime.from_unix!(:millisecond)
    |> DateTime.to_iso8601()
  end
end
