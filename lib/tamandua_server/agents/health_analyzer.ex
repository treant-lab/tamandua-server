defmodule TamanduaServer.Agents.HealthAnalyzer do
  @moduledoc """
  Anomaly Detection for Agent Health Metrics

  Provides statistical anomaly detection for agent health monitoring:
  - Baseline calculation (moving averages, standard deviations)
  - Anomaly detection algorithms (Z-score, IQR, rate of change)
  - Trend analysis (regression, seasonality)
  - Predictive alerts (memory leaks, CPU spikes)
  - Fleet-wide anomaly comparison

  ## Detection Methods

  1. **Z-Score**: Detects outliers beyond N standard deviations from mean
  2. **IQR (Interquartile Range)**: Robust outlier detection
  3. **Rate of Change**: Detects sudden spikes or drops
  4. **Moving Average**: Smoothed trend-based detection
  5. **Fleet Comparison**: Detects agents deviating from fleet average
  """

  require Logger
  alias TamanduaServer.Agents.HealthMetrics
  alias TamanduaServer.Repo

  import Ecto.Query

  # Anomaly detection thresholds
  @z_score_threshold 3.0
  @iqr_multiplier 1.5
  @rate_of_change_threshold 50.0  # 50% change
  @moving_average_window 20
  @memory_leak_detection_window 60  # minutes
  @memory_growth_threshold 5.0  # MB/min

  @doc """
  Analyze health metrics for anomalies.

  Returns a list of detected anomalies with details.
  """
  def analyze_metrics(agent_id) do
    recent_metrics = HealthMetrics.get_recent(agent_id, 100)

    if length(recent_metrics) < 10 do
      # Not enough data for analysis
      []
    else
      []
      |> detect_cpu_anomalies(recent_metrics)
      |> detect_memory_anomalies(recent_metrics)
      |> detect_disk_anomalies(recent_metrics)
      |> detect_network_anomalies(recent_metrics)
      |> detect_event_processing_anomalies(recent_metrics)
      |> detect_error_rate_anomalies(recent_metrics)
      |> detect_memory_leaks(recent_metrics)
    end
  end

  @doc """
  Compare agent metrics against fleet average.

  Returns anomalies where agent significantly deviates from fleet.
  """
  def compare_to_fleet(agent_id) do
    agent_stats = HealthMetrics.aggregate_metrics(
      agent_id,
      DateTime.utc_now() |> DateTime.add(-3600, :second),
      DateTime.utc_now()
    )

    fleet_stats = calculate_fleet_statistics()

    anomalies = []

    # CPU comparison
    anomalies = if agent_stats.avg_cpu > fleet_stats.avg_cpu + 2 * fleet_stats.std_cpu do
      [%{
        type: :cpu_deviation,
        severity: :warning,
        message: "CPU usage significantly higher than fleet average",
        agent_value: agent_stats.avg_cpu,
        fleet_average: fleet_stats.avg_cpu,
        deviation_score: calculate_z_score(agent_stats.avg_cpu, fleet_stats.avg_cpu, fleet_stats.std_cpu)
      } | anomalies]
    else
      anomalies
    end

    # Memory comparison
    anomalies = if agent_stats.avg_memory > fleet_stats.avg_memory + 2 * fleet_stats.std_memory do
      [%{
        type: :memory_deviation,
        severity: :warning,
        message: "Memory usage significantly higher than fleet average",
        agent_value: agent_stats.avg_memory,
        fleet_average: fleet_stats.avg_memory,
        deviation_score: calculate_z_score(agent_stats.avg_memory, fleet_stats.avg_memory, fleet_stats.std_memory)
      } | anomalies]
    else
      anomalies
    end

    # Health score comparison
    anomalies = if agent_stats.avg_health_score < fleet_stats.avg_health_score - 2 * fleet_stats.std_health_score do
      [%{
        type: :health_score_deviation,
        severity: :critical,
        message: "Health score significantly lower than fleet average",
        agent_value: agent_stats.avg_health_score,
        fleet_average: fleet_stats.avg_health_score,
        deviation_score: calculate_z_score(agent_stats.avg_health_score, fleet_stats.avg_health_score, fleet_stats.std_health_score)
      } | anomalies]
    else
      anomalies
    end

    anomalies
  end

  @doc """
  Detect memory leak patterns.

  Analyzes memory growth over time to identify potential leaks.
  """
  def detect_memory_leak(agent_id) do
    cutoff = DateTime.utc_now() |> DateTime.add(-@memory_leak_detection_window * 60, :second)

    metrics = from(m in HealthMetrics,
      where: m.agent_id == ^agent_id,
      where: m.timestamp >= ^cutoff,
      order_by: [asc: m.timestamp],
      select: %{timestamp: m.timestamp, memory_used: m.memory_used}
    )
    |> Repo.all()

    if length(metrics) < 10 do
      nil
    else
      # Calculate linear regression slope
      slope = calculate_linear_regression_slope(metrics)

      # Convert slope to MB/min
      slope_mb_per_min = slope * 60 / (1024 * 1024)

      if slope_mb_per_min > @memory_growth_threshold do
        %{
          type: :memory_leak,
          severity: :critical,
          message: "Potential memory leak detected",
          growth_rate_mb_per_min: Float.round(slope_mb_per_min, 2),
          threshold: @memory_growth_threshold,
          recommendation: "Investigate memory usage patterns and consider restarting agent"
        }
      else
        nil
      end
    end
  end

  @doc """
  Calculate health trend (improving, stable, degrading).
  """
  def calculate_health_trend(agent_id, window_minutes \\ 60) do
    cutoff = DateTime.utc_now() |> DateTime.add(-window_minutes * 60, :second)

    health_scores = from(m in HealthMetrics,
      where: m.agent_id == ^agent_id,
      where: m.timestamp >= ^cutoff,
      order_by: [asc: m.timestamp],
      select: %{timestamp: m.timestamp, health_score: m.health_score}
    )
    |> Repo.all()

    if length(health_scores) < 5 do
      :insufficient_data
    else
      slope = calculate_linear_regression_slope(health_scores)

      cond do
        slope > 0.1 -> :improving
        slope < -0.1 -> :degrading
        true -> :stable
      end
    end
  end

  # Private Functions

  defp detect_cpu_anomalies(anomalies, metrics) do
    cpu_values = Enum.map(metrics, & &1.cpu_usage)

    mean = Enum.sum(cpu_values) / length(cpu_values)
    std_dev = calculate_std_dev(cpu_values, mean)

    latest = hd(metrics)

    # Z-score anomaly detection
    z_score = if std_dev > 0, do: abs(latest.cpu_usage - mean) / std_dev, else: 0

    if z_score > @z_score_threshold do
      [%{
        type: :cpu_spike,
        severity: :warning,
        message: "CPU usage spike detected (#{Float.round(latest.cpu_usage, 1)}%)",
        value: latest.cpu_usage,
        baseline: mean,
        z_score: z_score,
        timestamp: latest.timestamp
      } | anomalies]
    else
      anomalies
    end
  end

  defp detect_memory_anomalies(anomalies, metrics) do
    memory_values = Enum.map(metrics, & &1.memory_usage)

    mean = Enum.sum(memory_values) / length(memory_values)
    std_dev = calculate_std_dev(memory_values, mean)

    latest = hd(metrics)

    z_score = if std_dev > 0, do: abs(latest.memory_usage - mean) / std_dev, else: 0

    if z_score > @z_score_threshold do
      [%{
        type: :memory_spike,
        severity: :warning,
        message: "Memory usage spike detected (#{Float.round(latest.memory_usage, 1)}%)",
        value: latest.memory_usage,
        baseline: mean,
        z_score: z_score,
        timestamp: latest.timestamp
      } | anomalies]
    else
      anomalies
    end
  end

  defp detect_disk_anomalies(anomalies, metrics) do
    disk_values = Enum.map(metrics, & &1.disk_usage)

    {q1, q3} = calculate_quartiles(disk_values)
    iqr = q3 - q1

    latest = hd(metrics)

    # IQR outlier detection
    lower_bound = q1 - @iqr_multiplier * iqr
    upper_bound = q3 + @iqr_multiplier * iqr

    if latest.disk_usage > upper_bound do
      [%{
        type: :disk_spike,
        severity: :warning,
        message: "Disk usage spike detected (#{Float.round(latest.disk_usage, 1)}%)",
        value: latest.disk_usage,
        upper_bound: upper_bound,
        timestamp: latest.timestamp
      } | anomalies]
    else
      anomalies
    end
  end

  defp detect_network_anomalies(anomalies, metrics) do
    network_rx_values = Enum.map(metrics, & &1.network_rx_bytes_per_sec)

    mean = Enum.sum(network_rx_values) / length(network_rx_values)

    latest = hd(metrics)

    # Rate of change detection
    if mean > 0 do
      rate_of_change = abs((latest.network_rx_bytes_per_sec - mean) / mean * 100)

      if rate_of_change > @rate_of_change_threshold do
        [%{
          type: :network_traffic_spike,
          severity: :info,
          message: "Network traffic spike detected",
          value: latest.network_rx_bytes_per_sec,
          baseline: mean,
          rate_of_change_percent: rate_of_change,
          timestamp: latest.timestamp
        } | anomalies]
      else
        anomalies
      end
    else
      anomalies
    end
  end

  defp detect_event_processing_anomalies(anomalies, metrics) do
    dropped_events = Enum.map(metrics, & &1.events_dropped)

    latest = hd(metrics)

    # Check if events are being dropped
    if latest.events_dropped > 0 do
      [%{
        type: :events_dropped,
        severity: :critical,
        message: "Agent is dropping events - queue overflow detected",
        value: latest.events_dropped,
        events_queued: latest.events_queued,
        recommendation: "Increase event queue size or reduce collector intervals",
        timestamp: latest.timestamp
      } | anomalies]
    else
      anomalies
    end
  end

  defp detect_error_rate_anomalies(anomalies, metrics) do
    error_counts = Enum.map(metrics, & &1.error_count)

    mean = if length(error_counts) > 0, do: Enum.sum(error_counts) / length(error_counts), else: 0

    latest = hd(metrics)

    # Check if error rate is significantly higher
    if latest.error_count > max(mean * 2, 10) do
      [%{
        type: :high_error_rate,
        severity: :warning,
        message: "High error rate detected",
        value: latest.error_count,
        baseline: mean,
        error_breakdown: latest.error_by_component,
        timestamp: latest.timestamp
      } | anomalies]
    else
      anomalies
    end
  end

  defp detect_memory_leaks(anomalies, metrics) do
    # Take recent window for leak detection
    recent_window = Enum.take(metrics, min(30, length(metrics)))

    if length(recent_window) < 10 do
      anomalies
    else
      memory_data = Enum.map(recent_window, fn m ->
        %{
          timestamp: m.timestamp,
          memory_used: m.memory_used
        }
      end)

      slope = calculate_linear_regression_slope(memory_data)

      # Convert to MB/min
      slope_mb_per_min = slope * 60 / (1024 * 1024)

      if slope_mb_per_min > @memory_growth_threshold do
        [%{
          type: :memory_leak_detected,
          severity: :critical,
          message: "Potential memory leak: sustained memory growth",
          growth_rate_mb_per_min: Float.round(slope_mb_per_min, 2),
          threshold: @memory_growth_threshold,
          recommendation: "Restart agent or investigate memory usage patterns"
        } | anomalies]
      else
        anomalies
      end
    end
  end

  defp calculate_fleet_statistics do
    stats = HealthMetrics.fleet_stats(60)

    if length(stats) == 0 do
      %{
        avg_cpu: 0,
        std_cpu: 0,
        avg_memory: 0,
        std_memory: 0,
        avg_health_score: 100,
        std_health_score: 0
      }
    else
      cpu_values = Enum.map(stats, & &1.avg_cpu)
      memory_values = Enum.map(stats, & &1.avg_memory)
      health_values = Enum.map(stats, & &1.avg_health_score)

      avg_cpu = Enum.sum(cpu_values) / length(cpu_values)
      avg_memory = Enum.sum(memory_values) / length(memory_values)
      avg_health = Enum.sum(health_values) / length(health_values)

      %{
        avg_cpu: avg_cpu,
        std_cpu: calculate_std_dev(cpu_values, avg_cpu),
        avg_memory: avg_memory,
        std_memory: calculate_std_dev(memory_values, avg_memory),
        avg_health_score: avg_health,
        std_health_score: calculate_std_dev(health_values, avg_health)
      }
    end
  end

  defp calculate_std_dev(values, mean) do
    variance = Enum.reduce(values, 0, fn value, acc ->
      acc + :math.pow(value - mean, 2)
    end) / length(values)

    :math.sqrt(variance)
  end

  defp calculate_z_score(value, mean, std_dev) do
    if std_dev > 0 do
      (value - mean) / std_dev
    else
      0
    end
  end

  defp calculate_quartiles(values) do
    sorted = Enum.sort(values)
    len = length(sorted)

    q1_index = div(len, 4)
    q3_index = div(len * 3, 4)

    {Enum.at(sorted, q1_index), Enum.at(sorted, q3_index)}
  end

  defp calculate_linear_regression_slope(data) do
    n = length(data)

    indexed_data = Enum.with_index(data, 1)

    sum_x = Enum.reduce(indexed_data, 0, fn {_, x}, acc -> acc + x end)
    sum_y = Enum.reduce(indexed_data, 0, fn {point, _}, acc ->
      value = case point do
        %{memory_used: v} -> v
        %{health_score: v} -> v
        _ -> 0
      end
      acc + value
    end)

    sum_xy = Enum.reduce(indexed_data, 0, fn {point, x}, acc ->
      value = case point do
        %{memory_used: v} -> v
        %{health_score: v} -> v
        _ -> 0
      end
      acc + x * value
    end)

    sum_x2 = Enum.reduce(indexed_data, 0, fn {_, x}, acc -> acc + x * x end)

    # Calculate slope: (n*sum_xy - sum_x*sum_y) / (n*sum_x2 - sum_x^2)
    numerator = n * sum_xy - sum_x * sum_y
    denominator = n * sum_x2 - sum_x * sum_x

    if denominator != 0 do
      numerator / denominator
    else
      0
    end
  end
end
