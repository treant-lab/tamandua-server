defmodule TamanduaServer.Agents.HealthPredictor do
  @moduledoc """
  Predictive Maintenance for Agent Health

  Uses statistical and ML-based methods to predict:
  - Health degradation before it happens
  - Resource exhaustion warnings
  - Agent failure predictions
  - Maintenance recommendations

  ## Prediction Methods

  1. **Linear Regression**: Predicts resource usage trends
  2. **Exponential Smoothing**: Short-term forecasting
  3. **Threshold-based Alerts**: Resource exhaustion warnings
  4. **Pattern Recognition**: Detects recurring health issues

  ## Alerts

  - Health score drop >20 points in 1 hour
  - Resource exhaustion predicted within 24 hours
  - Recurring pattern of failures detected
  """

  require Logger
  alias TamanduaServer.Agents.{HealthMetrics}
  alias TamanduaServer.Repo

  import Ecto.Query

  @doc """
  Predict health degradation for an agent.

  Returns predictions for:
  - Next hour health score
  - Next 24 hours health score
  - Time until resource exhaustion
  - Recommended maintenance actions
  """
  def predict_health_degradation(agent_id) do
    # Get historical health scores
    health_history = get_health_history(agent_id, 168) # 7 days

    if length(health_history) < 10 do
      {:error, :insufficient_data}
    else
      # Calculate health trend
      trend = calculate_health_trend(health_history)

      # Predict future scores
      current_score = List.first(health_history).health_score
      next_hour_score = predict_next_hour_score(health_history)
      next_day_score = predict_next_day_score(health_history)

      # Check for sudden degradation
      sudden_drop = detect_sudden_drop(health_history)

      # Resource exhaustion predictions
      resource_warnings = predict_resource_exhaustion(agent_id)

      # Maintenance recommendations
      recommendations = generate_maintenance_recommendations(
        trend,
        next_hour_score,
        next_day_score,
        resource_warnings
      )

      {:ok, %{
        current_score: current_score,
        predicted_next_hour: next_hour_score,
        predicted_next_day: next_day_score,
        trend: trend,
        sudden_drop_detected: sudden_drop != nil,
        sudden_drop: sudden_drop,
        resource_warnings: resource_warnings,
        recommendations: recommendations,
        confidence: calculate_confidence(health_history)
      }}
    end
  end

  @doc """
  Predict resource exhaustion.

  Returns time estimates for when resources will be exhausted:
  - CPU at 100%
  - Memory at 100%
  - Disk at 100%
  """
  def predict_resource_exhaustion(agent_id) do
    warnings = []

    # Memory exhaustion
    memory_warning = predict_memory_exhaustion(agent_id)
    warnings = if memory_warning, do: [memory_warning | warnings], else: warnings

    # Disk exhaustion
    disk_warning = predict_disk_exhaustion(agent_id)
    warnings = if disk_warning, do: [disk_warning | warnings], else: warnings

    # CPU sustained high usage
    cpu_warning = predict_cpu_issues(agent_id)
    warnings = if cpu_warning, do: [cpu_warning | warnings], else: warnings

    warnings
  end

  @doc """
  Detect health anomalies and patterns.

  Identifies:
  - Recurring failures at specific times
  - Cyclical degradation patterns
  - Correlation between metrics
  """
  def detect_health_patterns(agent_id) do
    metrics = HealthMetrics.get_recent(agent_id, 168) # Last 7 days

    if length(metrics) < 24 do
      {:error, :insufficient_data}
    else
      patterns = []

      # Check for time-based patterns
      time_patterns = detect_time_based_patterns(metrics)
      patterns = patterns ++ time_patterns

      # Check for cyclical patterns
      cyclical = detect_cyclical_patterns(metrics)
      patterns = if cyclical, do: [cyclical | patterns], else: patterns

      # Check for correlated degradation
      correlations = detect_metric_correlations(metrics)
      patterns = patterns ++ correlations

      {:ok, patterns}
    end
  end

  @doc """
  Calculate time until maintenance is required.

  Returns estimated hours until intervention is needed.
  """
  def time_until_maintenance_required(agent_id) do
    case predict_health_degradation(agent_id) do
      {:ok, prediction} ->
        cond do
          # If health score will drop below 50 in next hour
          prediction.predicted_next_hour < 50 ->
            {:urgent, 1, "Immediate action required"}

          # If health score will drop below 50 in next day
          prediction.predicted_next_day < 50 ->
            # Estimate hours until score drops below 50
            hours = estimate_hours_to_threshold(
              prediction.current_score,
              prediction.predicted_next_day,
              50,
              24
            )
            {:warning, hours, "Maintenance required within #{hours} hours"}

          # Trending down but not critical yet
          prediction.trend == :degrading ->
            {:info, 72, "Schedule maintenance within 3 days"}

          true ->
            {:ok, nil, "No immediate maintenance required"}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Private Functions

  defp get_health_history(agent_id, hours) do
    cutoff = DateTime.utc_now() |> DateTime.add(-hours * 3600, :second)

    from(m in HealthMetrics,
      where: m.agent_id == ^agent_id,
      where: m.timestamp >= ^cutoff,
      order_by: [desc: m.timestamp],
      select: %{
        timestamp: m.timestamp,
        health_score: m.health_score,
        cpu_usage: m.cpu_usage,
        memory_usage: m.memory_usage,
        disk_usage: m.disk_usage
      }
    )
    |> Repo.all()
  end

  defp calculate_health_trend(history) do
    if length(history) < 2 do
      :stable
    else
      scores = Enum.map(history, & &1.health_score)
      slope = calculate_linear_regression_slope(scores)

      cond do
        slope < -0.5 -> :degrading
        slope > 0.5 -> :improving
        true -> :stable
      end
    end
  end

  defp predict_next_hour_score(history) do
    # Use exponential smoothing for short-term prediction
    scores = Enum.map(history, & &1.health_score) |> Enum.reverse()

    alpha = 0.3 # Smoothing factor
    smoothed = exponential_smoothing(scores, alpha)

    # Predict next value
    last_smoothed = List.last(smoothed)
    last_actual = List.last(scores)

    predicted = alpha * last_actual + (1 - alpha) * last_smoothed
    round(max(0, min(100, predicted)))
  end

  defp predict_next_day_score(history) do
    # Use linear regression for longer-term prediction
    scores = Enum.map(history, & &1.health_score)
    slope = calculate_linear_regression_slope(scores)

    current = List.first(scores)
    predicted = current + (slope * 24) # 24 hours

    round(max(0, min(100, predicted)))
  end

  defp detect_sudden_drop(history) do
    # Check for >20 point drop in last hour
    if length(history) >= 2 do
      recent = Enum.take(history, 2)
      [current, previous] = recent

      time_diff = DateTime.diff(current.timestamp, previous.timestamp, :second)
      score_diff = current.health_score - previous.health_score

      if time_diff <= 3600 and score_diff < -20 do
        %{
          severity: :critical,
          drop: abs(score_diff),
          time_window: "#{div(time_diff, 60)} minutes",
          message: "Health score dropped #{abs(score_diff)} points in #{div(time_diff, 60)} minutes"
        }
      else
        nil
      end
    else
      nil
    end
  end

  defp predict_memory_exhaustion(agent_id) do
    # Get memory usage over last 24 hours
    cutoff = DateTime.utc_now() |> DateTime.add(-86400, :second)

    metrics = from(m in HealthMetrics,
      where: m.agent_id == ^agent_id,
      where: m.timestamp >= ^cutoff,
      order_by: [asc: m.timestamp],
      select: %{timestamp: m.timestamp, memory_usage: m.memory_usage}
    )
    |> Repo.all()

    if length(metrics) < 10 do
      nil
    else
      # Calculate growth rate
      memory_values = Enum.map(metrics, & &1.memory_usage)
      slope = calculate_linear_regression_slope(memory_values)

      # If memory is growing
      if slope > 0.1 do
        current = List.last(memory_values)
        hours_to_100 = (100 - current) / slope

        if hours_to_100 < 24 do
          %{
            resource: :memory,
            severity: :critical,
            current_usage: current,
            growth_rate: slope,
            estimated_hours_to_exhaustion: Float.round(hours_to_100, 1),
            message: "Memory exhaustion predicted in #{Float.round(hours_to_100, 1)} hours",
            recommendation: "Plan agent restart or memory increase"
          }
        else
          nil
        end
      else
        nil
      end
    end
  end

  defp predict_disk_exhaustion(agent_id) do
    # Get disk usage over last 7 days
    cutoff = DateTime.utc_now() |> DateTime.add(-604800, :second)

    metrics = from(m in HealthMetrics,
      where: m.agent_id == ^agent_id,
      where: m.timestamp >= ^cutoff,
      order_by: [asc: m.timestamp],
      select: %{timestamp: m.timestamp, disk_usage: m.disk_usage}
    )
    |> Repo.all()

    if length(metrics) < 10 do
      nil
    else
      disk_values = Enum.map(metrics, & &1.disk_usage)
      slope = calculate_linear_regression_slope(disk_values)

      if slope > 0.05 do
        current = List.last(disk_values)
        hours_to_100 = (100 - current) / slope

        if hours_to_100 < 168 do # Less than 7 days
          %{
            resource: :disk,
            severity: if(hours_to_100 < 24, do: :critical, else: :warning),
            current_usage: current,
            growth_rate: slope,
            estimated_hours_to_exhaustion: Float.round(hours_to_100, 1),
            message: "Disk exhaustion predicted in #{Float.round(hours_to_100 / 24, 1)} days",
            recommendation: "Clean up old logs or increase disk space"
          }
        else
          nil
        end
      else
        nil
      end
    end
  end

  defp predict_cpu_issues(agent_id) do
    # Check for sustained high CPU usage
    cutoff = DateTime.utc_now() |> DateTime.add(-3600, :second)

    avg_cpu = from(m in HealthMetrics,
      where: m.agent_id == ^agent_id,
      where: m.timestamp >= ^cutoff,
      select: avg(m.cpu_usage)
    )
    |> Repo.one()

    if avg_cpu && avg_cpu > 85 do
      %{
        resource: :cpu,
        severity: :warning,
        current_usage: avg_cpu,
        message: "Sustained high CPU usage (#{Float.round(avg_cpu, 1)}%) detected",
        recommendation: "Review collector configuration or increase CPU allocation"
      }
    else
      nil
    end
  end

  defp detect_time_based_patterns(metrics) do
    # Group by hour of day
    by_hour = Enum.group_by(metrics, fn m ->
      Calendar.strftime(m.timestamp, "%H")
    end)

    # Find hours with consistently high resource usage
    Enum.reduce(by_hour, [], fn {hour, hour_metrics}, acc ->
      avg_cpu = Enum.sum(Enum.map(hour_metrics, & &1.cpu_usage)) / length(hour_metrics)
      avg_memory = Enum.sum(Enum.map(hour_metrics, & &1.memory_usage)) / length(hour_metrics)

      if avg_cpu > 80 or avg_memory > 85 do
        [%{
          type: :time_based,
          hour: hour,
          avg_cpu: avg_cpu,
          avg_memory: avg_memory,
          message: "Recurring high resource usage at hour #{hour}:00",
          recommendation: "Schedule maintenance or resource scaling at #{hour}:00"
        } | acc]
      else
        acc
      end
    end)
  end

  defp detect_cyclical_patterns(metrics) do
    # Detect daily/weekly cycles using simple period detection
    # This is a simplified version - a real implementation would use FFT

    health_scores = Enum.map(metrics, & &1.health_score)

    if length(health_scores) >= 24 do
      # Check for 24-hour cycle
      first_half = Enum.take(health_scores, div(length(health_scores), 2))
      second_half = Enum.drop(health_scores, div(length(health_scores), 2))

      correlation = calculate_correlation(first_half, second_half)

      if correlation > 0.7 do
        %{
          type: :cyclical,
          period: "daily",
          correlation: correlation,
          message: "Daily health pattern detected",
          recommendation: "Optimize for known daily usage patterns"
        }
      else
        nil
      end
    else
      nil
    end
  end

  defp detect_metric_correlations(metrics) do
    # Check if CPU and memory degrade together
    cpu_values = Enum.map(metrics, & &1.cpu_usage)
    memory_values = Enum.map(metrics, & &1.memory_usage)

    correlation = calculate_correlation(cpu_values, memory_values)

    if correlation > 0.8 do
      [%{
        type: :correlation,
        metrics: [:cpu, :memory],
        correlation: correlation,
        message: "CPU and memory usage are highly correlated",
        recommendation: "Resource constraints may be linked - consider scaling both"
      }]
    else
      []
    end
  end

  defp generate_maintenance_recommendations(trend, next_hour, next_day, resource_warnings) do
    recommendations = []

    # Based on trend
    recommendations = case trend do
      :degrading ->
        [%{
          priority: :high,
          action: "investigate_degradation",
          message: "Health is trending down - investigate root cause",
          timeline: "within 24 hours"
        } | recommendations]

      :stable ->
        recommendations

      :improving ->
        [%{
          priority: :low,
          action: "monitor",
          message: "Health is improving - continue monitoring",
          timeline: "routine check"
        } | recommendations]
    end

    # Based on predictions
    recommendations = cond do
      next_hour < 50 ->
        [%{
          priority: :critical,
          action: "immediate_intervention",
          message: "Critical health predicted within 1 hour",
          timeline: "immediate"
        } | recommendations]

      next_day < 50 ->
        [%{
          priority: :high,
          action: "scheduled_maintenance",
          message: "Health will degrade to critical within 24 hours",
          timeline: "within 8 hours"
        } | recommendations]

      true ->
        recommendations
    end

    # Based on resource warnings
    recommendations = Enum.reduce(resource_warnings, recommendations, fn warning, acc ->
      [%{
        priority: warning.severity,
        action: "resource_management",
        message: warning.message,
        resource: warning.resource,
        timeline: "within #{warning.estimated_hours_to_exhaustion} hours"
      } | acc]
    end)

    recommendations
  end

  defp calculate_confidence(history) do
    # Confidence based on data quality and quantity
    data_points = length(history)
    time_span = if data_points > 1 do
      DateTime.diff(List.first(history).timestamp, List.last(history).timestamp, :second) / 3600
    else
      0
    end

    cond do
      data_points >= 168 and time_span >= 168 -> :high
      data_points >= 48 and time_span >= 48 -> :medium
      true -> :low
    end
  end

  defp estimate_hours_to_threshold(current, predicted_24h, threshold, hours) do
    # Linear interpolation to find when score crosses threshold
    if predicted_24h >= threshold do
      nil
    else
      rate_of_decline = (current - predicted_24h) / hours
      hours_to_threshold = (current - threshold) / rate_of_decline
      round(hours_to_threshold)
    end
  end

  defp exponential_smoothing(values, alpha) do
    Enum.reduce(values, [], fn value, acc ->
      if Enum.empty?(acc) do
        [value]
      else
        last_smoothed = List.last(acc)
        smoothed = alpha * value + (1 - alpha) * last_smoothed
        acc ++ [smoothed]
      end
    end)
  end

  defp calculate_linear_regression_slope(values) when length(values) < 2, do: 0.0

  defp calculate_linear_regression_slope(values) do
    n = length(values)
    indexed_values = Enum.with_index(values, 1)

    sum_x = Enum.sum(1..n)
    sum_y = Enum.sum(values)
    sum_xy = Enum.reduce(indexed_values, 0, fn {val, idx}, acc -> acc + idx * val end)
    sum_x2 = Enum.reduce(1..n, 0, fn x, acc -> acc + x * x end)

    numerator = n * sum_xy - sum_x * sum_y
    denominator = n * sum_x2 - sum_x * sum_x

    if denominator != 0 do
      numerator / denominator
    else
      0.0
    end
  end

  defp calculate_correlation(list1, list2) when length(list1) != length(list2), do: 0.0
  defp calculate_correlation(list1, _list2) when length(list1) < 2, do: 0.0

  defp calculate_correlation(list1, list2) do
    n = length(list1)
    mean1 = Enum.sum(list1) / n
    mean2 = Enum.sum(list2) / n

    sum_product_deviations = Enum.zip(list1, list2)
    |> Enum.reduce(0, fn {x, y}, acc ->
      acc + (x - mean1) * (y - mean2)
    end)

    sum_sq_dev1 = Enum.reduce(list1, 0, fn x, acc -> acc + :math.pow(x - mean1, 2) end)
    sum_sq_dev2 = Enum.reduce(list2, 0, fn y, acc -> acc + :math.pow(y - mean2, 2) end)

    denominator = :math.sqrt(sum_sq_dev1 * sum_sq_dev2)

    if denominator > 0 do
      sum_product_deviations / denominator
    else
      0.0
    end
  end
end
