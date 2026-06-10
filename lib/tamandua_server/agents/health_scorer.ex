defmodule TamanduaServer.Agents.HealthScorer do
  @moduledoc """
  Comprehensive Agent Health Scoring System

  Calculates a 0-100 health score based on multiple dimensions:

  ## Scoring Components (Total: 100 points)

  1. **Uptime (20 points)**
     - >99% uptime = 20 points
     - 95-99% uptime = 15 points
     - <95% uptime = 0 points

  2. **CPU Usage (15 points)**
     - <50% = 15 points
     - 50-80% = 10 points
     - >80% = 0 points

  3. **Memory Usage (15 points)**
     - <70% = 15 points
     - 70-90% = 10 points
     - >90% = 0 points

  4. **Event Throughput (15 points)**
     - Within baseline ±20% = 15 points
     - Outside baseline = 0 points

  5. **Error Rate (15 points)**
     - <1% = 15 points
     - 1-5% = 10 points
     - >5% = 0 points

  6. **Detection Coverage (10 points)**
     - All collectors active = 10 points
     - Partial coverage = proportional

  7. **Configuration Compliance (10 points)**
     - No drift = 10 points
     - Drift detected = 0 points

  ## Health Categories

  - **Excellent (90-100)**: Green, no action needed
  - **Good (70-89)**: Yellow, monitor
  - **Fair (50-69)**: Orange, investigate
  - **Poor (<50)**: Red, urgent action required
  """

  require Logger
  alias TamanduaServer.Agents.{Agent, HealthMetrics}
  alias TamanduaServer.Repo

  import Ecto.Query

  # Expected collectors for full coverage
  @expected_collectors [
    "process",
    "file",
    "network",
    "dns",
    "registry"
  ]

  @doc """
  Calculate comprehensive health score for an agent.

  Returns a map with:
  - `score`: Overall health score (0-100)
  - `category`: :excellent | :good | :fair | :poor
  - `breakdown`: Score breakdown by component
  - `issues`: List of detected issues
  """
  def calculate_health_score(agent_id, opts \\ []) do
    window_minutes = Keyword.get(opts, :window_minutes, 60)
    cutoff = DateTime.utc_now() |> DateTime.add(-window_minutes * 60, :second)

    # Get agent data
    agent = Repo.get(Agent, agent_id)

    unless agent do
      {:error, :agent_not_found}
    else
      # Get recent metrics
      metrics = from(m in HealthMetrics,
        where: m.agent_id == ^agent_id,
        where: m.timestamp >= ^cutoff,
        order_by: [desc: m.timestamp]
      )
      |> Repo.all()

      latest_metrics = List.first(metrics) || default_metrics()

      # Calculate baseline for event throughput
      baseline_events_per_sec = calculate_baseline_events_per_sec(agent_id)

      # Calculate component scores
      uptime_score = score_uptime(agent, metrics, window_minutes)
      cpu_score = score_cpu_usage(latest_metrics)
      memory_score = score_memory_usage(latest_metrics)
      throughput_score = score_event_throughput(latest_metrics, baseline_events_per_sec)
      error_rate_score = score_error_rate(latest_metrics, metrics)
      coverage_score = score_detection_coverage(latest_metrics)
      compliance_score = score_config_compliance(agent)

      # Total score
      total_score = uptime_score + cpu_score + memory_score +
                    throughput_score + error_rate_score +
                    coverage_score + compliance_score

      # Categorize
      category = categorize_health(total_score)

      # Identify issues
      issues = identify_issues(
        %{
          uptime: uptime_score,
          cpu: cpu_score,
          memory: memory_score,
          throughput: throughput_score,
          error_rate: error_rate_score,
          coverage: coverage_score,
          compliance: compliance_score
        },
        latest_metrics,
        baseline_events_per_sec
      )

      {:ok, %{
        score: total_score,
        category: category,
        breakdown: %{
          uptime: uptime_score,
          cpu: cpu_score,
          memory: memory_score,
          throughput: throughput_score,
          error_rate: error_rate_score,
          coverage: coverage_score,
          compliance: compliance_score
        },
        issues: issues,
        timestamp: DateTime.utc_now()
      }}
    end
  end

  @doc """
  Score uptime (20 points max).

  Calculates uptime percentage based on agent online/offline status.
  """
  def score_uptime(agent, metrics, window_minutes) do
    # Calculate uptime from heartbeat data
    total_minutes = window_minutes
    offline_minutes = count_offline_minutes(metrics, window_minutes)
    uptime_percent = (total_minutes - offline_minutes) / total_minutes * 100

    cond do
      uptime_percent > 99 -> 20
      uptime_percent >= 95 -> 15
      true -> 0
    end
  end

  @doc """
  Score CPU usage (15 points max).
  """
  def score_cpu_usage(metrics) do
    cpu_usage = metrics.cpu_usage || 0

    cond do
      cpu_usage < 50 -> 15
      cpu_usage < 80 -> 10
      true -> 0
    end
  end

  @doc """
  Score memory usage (15 points max).
  """
  def score_memory_usage(metrics) do
    memory_usage = metrics.memory_usage || 0

    cond do
      memory_usage < 70 -> 15
      memory_usage < 90 -> 10
      true -> 0
    end
  end

  @doc """
  Score event throughput (15 points max).

  Compares current throughput to baseline ±20%.
  """
  def score_event_throughput(metrics, baseline) do
    current = metrics.events_per_sec || 0

    if baseline == 0 do
      # No baseline yet, assume healthy
      15
    else
      lower_bound = baseline * 0.8
      upper_bound = baseline * 1.2

      if current >= lower_bound and current <= upper_bound do
        15
      else
        0
      end
    end
  end

  @doc """
  Score error rate (15 points max).

  Calculates error rate as errors / total events processed.
  """
  def score_error_rate(latest_metrics, all_metrics) do
    # Calculate error rate from recent metrics
    total_events = Enum.sum(Enum.map(all_metrics, &(&1.events_processed || 0)))
    total_errors = Enum.sum(Enum.map(all_metrics, &(&1.error_count || 0)))

    error_rate_percent = if total_events > 0 do
      total_errors / total_events * 100
    else
      0.0
    end

    cond do
      error_rate_percent < 1 -> 15
      error_rate_percent < 5 -> 10
      true -> 0
    end
  end

  @doc """
  Score detection coverage (10 points max).

  All collectors active = 10 points, proportional otherwise.
  """
  def score_detection_coverage(metrics) do
    collector_metrics = metrics.collector_metrics || %{}

    active_collectors = Enum.count(collector_metrics, fn {_name, data} ->
      data["enabled"] == true
    end)

    total_expected = length(@expected_collectors)

    if total_expected > 0 do
      round(active_collectors / total_expected * 10)
    else
      10
    end
  end

  @doc """
  Score configuration compliance (10 points max).

  Checks if agent config matches expected configuration.
  """
  def score_config_compliance(agent) do
    # Check for config drift
    # In a real implementation, this would compare agent.config
    # against a gold standard configuration

    # For now, assume no drift if config exists
    if map_size(agent.config || %{}) > 0 do
      10
    else
      0
    end
  end

  @doc """
  Categorize health score into color-coded categories.
  """
  def categorize_health(score) do
    cond do
      score >= 90 -> :excellent
      score >= 70 -> :good
      score >= 50 -> :fair
      true -> :poor
    end
  end

  @doc """
  Get color for health category (for UI rendering).
  """
  def category_color(:excellent), do: "green"
  def category_color(:good), do: "yellow"
  def category_color(:fair), do: "orange"
  def category_color(:poor), do: "red"

  @doc """
  Get badge class for health category (Bootstrap/Tailwind compatible).
  """
  def category_badge(:excellent), do: "badge-success"
  def category_badge(:good), do: "badge-warning"
  def category_badge(:fair), do: "badge-orange"
  def category_badge(:poor), do: "badge-danger"

  # Private Functions

  defp count_offline_minutes(metrics, window_minutes) do
    # Calculate offline time based on gaps in metrics
    # If metrics are collected every minute, gaps indicate offline time

    if length(metrics) == 0 do
      window_minutes
    else
      # Sort by timestamp
      sorted = Enum.sort_by(metrics, & &1.timestamp, DateTime)

      # Calculate gaps between consecutive metrics
      gaps = sorted
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.map(fn [older, newer] ->
        DateTime.diff(newer.timestamp, older.timestamp, :second) / 60
      end)
      |> Enum.filter(&(&1 > 2)) # Gaps > 2 minutes indicate offline
      |> Enum.sum()

      round(gaps)
    end
  end

  defp calculate_baseline_events_per_sec(agent_id) do
    # Calculate baseline from last 24 hours
    cutoff = DateTime.utc_now() |> DateTime.add(-86400, :second)

    avg = from(m in HealthMetrics,
      where: m.agent_id == ^agent_id,
      where: m.timestamp >= ^cutoff,
      select: avg(m.events_per_sec)
    )
    |> Repo.one()

    avg || 0.0
  end

  defp identify_issues(scores, metrics, baseline) do
    issues = []

    # Check each component
    issues = if scores.uptime < 20 do
      [%{
        component: :uptime,
        severity: :critical,
        message: "Agent uptime is below 99%",
        recommendation: "Investigate agent stability and restart if necessary"
      } | issues]
    else
      issues
    end

    issues = if scores.cpu == 0 do
      [%{
        component: :cpu,
        severity: :critical,
        message: "CPU usage is critically high (>80%)",
        value: metrics.cpu_usage,
        recommendation: "Reduce collector intervals or increase CPU resources"
      } | issues]
    else
      issues
    end

    issues = if scores.memory == 0 do
      [%{
        component: :memory,
        severity: :critical,
        message: "Memory usage is critically high (>90%)",
        value: metrics.memory_usage,
        recommendation: "Investigate memory leaks or increase available memory"
      } | issues]
    else
      issues
    end

    issues = if scores.throughput == 0 do
      deviation = if baseline > 0 do
        abs(metrics.events_per_sec - baseline) / baseline * 100
      else
        0
      end

      [%{
        component: :throughput,
        severity: :warning,
        message: "Event throughput deviates from baseline by #{Float.round(deviation, 1)}%",
        value: metrics.events_per_sec,
        baseline: baseline,
        recommendation: "Check collector health and network connectivity"
      } | issues]
    else
      issues
    end

    issues = if scores.error_rate < 15 do
      [%{
        component: :error_rate,
        severity: if(scores.error_rate == 0, do: :critical, else: :warning),
        message: "Error rate is elevated",
        recommendation: "Review agent logs for error patterns"
      } | issues]
    else
      issues
    end

    issues = if scores.coverage < 10 do
      [%{
        component: :coverage,
        severity: :warning,
        message: "Not all collectors are active",
        recommendation: "Enable all required collectors for full detection coverage"
      } | issues]
    else
      issues
    end

    issues = if scores.compliance == 0 do
      [%{
        component: :compliance,
        severity: :warning,
        message: "Configuration drift detected",
        recommendation: "Re-deploy configuration to ensure compliance"
      } | issues]
    else
      issues
    end

    issues
  end

  defp default_metrics do
    %{
      cpu_usage: 0,
      memory_usage: 0,
      disk_usage: 0,
      events_per_sec: 0,
      events_processed: 0,
      error_count: 0,
      collector_metrics: %{},
      timestamp: DateTime.utc_now()
    }
  end
end
