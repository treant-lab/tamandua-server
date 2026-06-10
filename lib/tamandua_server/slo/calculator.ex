defmodule TamanduaServer.SLO.Calculator do
  @moduledoc """
  SLO (Service Level Objective) calculator for Tamandua EDR.

  Calculates SLIs (Service Level Indicators) and evaluates against SLO targets:
  - Availability (uptime %)
  - Latency (p50, p95, p99)
  - Error rate (% of requests with errors)
  - Throughput (requests/sec, events/sec)

  SLO Targets:
  - 99.9% availability (43.2 minutes downtime/month)
  - p95 latency < 500ms
  - Error rate < 0.1%
  - Throughput: >= 1000 events/sec
  """

  require Logger

  @type sli_type :: :availability | :latency | :error_rate | :throughput
  @type time_window :: :minute | :hour | :day | :week | :month

  # SLO Targets
  @slo_targets %{
    availability_percent: 99.9,
    latency_p95_ms: 500,
    latency_p99_ms: 1000,
    error_rate_percent: 0.1,
    throughput_events_per_sec: 1000
  }

  @doc """
  Get SLO targets.
  """
  def targets, do: @slo_targets

  @doc """
  Calculate availability SLI from uptime/downtime data.

  ## Parameters
  - `uptime_samples` - List of 1 (up) or 0 (down) samples
  - `time_window` - Time window for calculation

  ## Returns
  %{
    value: 99.95,           # Current availability %
    target: 99.9,           # Target availability %
    compliant: true,        # Meeting SLO?
    uptime_count: 1439,     # Number of up samples
    total_count: 1440,      # Total samples
    downtime_minutes: 1.0   # Estimated downtime
  }
  """
  @spec calculate_availability([0 | 1], time_window()) :: map()
  def calculate_availability(uptime_samples, time_window \\ :hour) do
    total_count = length(uptime_samples)

    if total_count == 0 do
      %{
        value: 100.0,
        target: @slo_targets.availability_percent,
        compliant: true,
        uptime_count: 0,
        total_count: 0,
        downtime_minutes: 0.0,
        time_window: time_window
      }
    else
      uptime_count = Enum.count(uptime_samples, &(&1 == 1))
      availability = (uptime_count / total_count) * 100

      # Calculate downtime in minutes
      sample_interval = window_to_sample_interval(time_window)
      downtime_minutes = (total_count - uptime_count) * sample_interval

      %{
        value: Float.round(availability, 4),
        target: @slo_targets.availability_percent,
        compliant: availability >= @slo_targets.availability_percent,
        uptime_count: uptime_count,
        total_count: total_count,
        downtime_minutes: Float.round(downtime_minutes, 2),
        time_window: time_window
      }
    end
  end

  @doc """
  Calculate latency SLI from latency measurements.

  ## Parameters
  - `latencies_ms` - List of latency measurements in milliseconds
  - `service` - Service name (e.g., :api, :event_processing, :detection)

  ## Returns
  %{
    p50: 120.5,
    p95: 450.2,
    p99: 890.1,
    max: 1200.0,
    min: 10.0,
    avg: 200.5,
    target_p95: 500,
    target_p99: 1000,
    compliant: true,
    sample_count: 5000
  }
  """
  @spec calculate_latency([number()], atom()) :: map()
  def calculate_latency(latencies_ms, service \\ :api) do
    count = length(latencies_ms)

    if count == 0 do
      %{
        p50: 0.0,
        p95: 0.0,
        p99: 0.0,
        max: 0.0,
        min: 0.0,
        avg: 0.0,
        target_p95: @slo_targets.latency_p95_ms,
        target_p99: @slo_targets.latency_p99_ms,
        compliant: true,
        sample_count: 0,
        service: service
      }
    else
      sorted = Enum.sort(latencies_ms)
      p50 = percentile(sorted, 50)
      p95 = percentile(sorted, 95)
      p99 = percentile(sorted, 99)
      min_val = Enum.min(sorted)
      max_val = Enum.max(sorted)
      avg = Enum.sum(sorted) / count

      %{
        p50: Float.round(p50, 2),
        p95: Float.round(p95, 2),
        p99: Float.round(p99, 2),
        max: Float.round(max_val, 2),
        min: Float.round(min_val, 2),
        avg: Float.round(avg, 2),
        target_p95: @slo_targets.latency_p95_ms,
        target_p99: @slo_targets.latency_p99_ms,
        compliant: p95 <= @slo_targets.latency_p95_ms,
        sample_count: count,
        service: service
      }
    end
  end

  @doc """
  Calculate error rate SLI from success/error counts.

  ## Parameters
  - `total_requests` - Total number of requests
  - `error_requests` - Number of failed requests

  ## Returns
  %{
    value: 0.05,          # Current error rate %
    target: 0.1,          # Target error rate %
    compliant: true,      # Meeting SLO?
    total_requests: 10000,
    error_requests: 5,
    success_requests: 9995
  }
  """
  @spec calculate_error_rate(non_neg_integer(), non_neg_integer()) :: map()
  def calculate_error_rate(total_requests, error_requests) do
    if total_requests == 0 do
      %{
        value: 0.0,
        target: @slo_targets.error_rate_percent,
        compliant: true,
        total_requests: 0,
        error_requests: 0,
        success_requests: 0
      }
    else
      error_rate = (error_requests / total_requests) * 100

      %{
        value: Float.round(error_rate, 4),
        target: @slo_targets.error_rate_percent,
        compliant: error_rate <= @slo_targets.error_rate_percent,
        total_requests: total_requests,
        error_requests: error_requests,
        success_requests: total_requests - error_requests
      }
    end
  end

  @doc """
  Calculate throughput SLI from event counts and time window.

  ## Parameters
  - `event_count` - Number of events processed
  - `time_window` - Time window for measurement
  - `service` - Service name

  ## Returns
  %{
    value: 1250.5,              # Current events/sec
    target: 1000,               # Target events/sec
    compliant: true,            # Meeting SLO?
    total_events: 4502000,
    time_window: :hour,
    time_window_seconds: 3600
  }
  """
  @spec calculate_throughput(non_neg_integer(), time_window(), atom()) :: map()
  def calculate_throughput(event_count, time_window \\ :hour, service \\ :telemetry) do
    window_seconds = window_to_seconds(time_window)
    throughput = if window_seconds > 0, do: event_count / window_seconds, else: 0.0

    %{
      value: Float.round(throughput, 2),
      target: @slo_targets.throughput_events_per_sec,
      compliant: throughput >= @slo_targets.throughput_events_per_sec,
      total_events: event_count,
      time_window: time_window,
      time_window_seconds: window_seconds,
      service: service
    }
  end

  @doc """
  Calculate composite SLI score from multiple SLIs.

  Weighted average of all SLI compliance scores.
  """
  @spec calculate_composite_sli(map()) :: map()
  def calculate_composite_sli(slis) do
    # Extract compliance values
    compliance_scores = [
      {get_in(slis, [:availability, :compliant]), 0.3},   # 30% weight
      {get_in(slis, [:latency, :compliant]), 0.25},       # 25% weight
      {get_in(slis, [:error_rate, :compliant]), 0.25},    # 25% weight
      {get_in(slis, [:throughput, :compliant]), 0.2}      # 20% weight
    ]

    # Calculate weighted score
    weighted_sum = Enum.reduce(compliance_scores, 0.0, fn {compliant, weight}, acc ->
      score = if compliant, do: 1.0, else: 0.0
      acc + (score * weight)
    end)

    composite_score = weighted_sum * 100

    %{
      score: Float.round(composite_score, 2),
      compliant: composite_score >= 99.9,
      breakdown: %{
        availability: get_in(slis, [:availability, :compliant]) || false,
        latency: get_in(slis, [:latency, :compliant]) || false,
        error_rate: get_in(slis, [:error_rate, :compliant]) || false,
        throughput: get_in(slis, [:throughput, :compliant]) || false
      }
    }
  end

  @doc """
  Check if all SLOs are being met.
  """
  @spec all_slos_met?(map()) :: boolean()
  def all_slos_met?(slis) do
    Enum.all?(slis, fn {_key, sli} ->
      Map.get(sli, :compliant, false)
    end)
  end

  @doc """
  Calculate SLI trend (improving, degrading, stable).

  Compares current SLI values with historical averages.
  """
  @spec calculate_trend(map(), [map()]) :: :improving | :degrading | :stable
  def calculate_trend(current_sli, historical_slis) when is_list(historical_slis) do
    if length(historical_slis) < 2 do
      :stable
    else
      # Calculate average of historical values
      historical_avg = Enum.reduce(historical_slis, 0.0, fn sli, acc ->
        acc + Map.get(sli, :value, 0.0)
      end) / length(historical_slis)

      current_value = Map.get(current_sli, :value, 0.0)

      # For availability and throughput, higher is better
      # For latency and error_rate, lower is better
      sli_type = determine_sli_type(current_sli)

      diff = current_value - historical_avg
      threshold = 0.05  # 0.05% threshold for change detection

      case sli_type do
        type when type in [:availability, :throughput] ->
          cond do
            diff > threshold -> :improving
            diff < -threshold -> :degrading
            true -> :stable
          end

        type when type in [:latency, :error_rate] ->
          cond do
            diff < -threshold -> :improving
            diff > threshold -> :degrading
            true -> :stable
          end

        _ -> :stable
      end
    end
  end

  # Private Functions

  defp percentile(sorted_list, p) do
    count = length(sorted_list)
    if count == 0 do
      0.0
    else
      index = round(p / 100 * count) - 1
      index = max(0, min(index, count - 1))
      Enum.at(sorted_list, index) * 1.0
    end
  end

  defp window_to_seconds(:minute), do: 60
  defp window_to_seconds(:hour), do: 3600
  defp window_to_seconds(:day), do: 86400
  defp window_to_seconds(:week), do: 604800
  defp window_to_seconds(:month), do: 2592000  # 30 days
  defp window_to_seconds(_), do: 3600  # Default to hour

  defp window_to_sample_interval(:minute), do: 1.0
  defp window_to_sample_interval(:hour), do: 1.0
  defp window_to_sample_interval(:day), do: 1.0
  defp window_to_sample_interval(:week), do: 1.0
  defp window_to_sample_interval(:month), do: 1.0
  defp window_to_sample_interval(_), do: 1.0

  defp determine_sli_type(%{target: target}) when is_number(target) do
    cond do
      target > 90 -> :availability  # High target = availability
      target < 10 -> :error_rate    # Low target = error rate
      target > 100 -> :latency       # High value = latency
      true -> :throughput
    end
  end
  defp determine_sli_type(_), do: :unknown
end
