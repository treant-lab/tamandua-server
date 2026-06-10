defmodule TamanduaServerWeb.API.V1.AISIEMController do
  @moduledoc """
  AI SIEM endpoints for intelligent log analysis, pattern discovery,
  alert correlation, and natural language querying of security events.
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Integrations.AISIEM

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Get AI-discovered patterns in security logs and events.

  The AI continuously analyzes logs to discover new patterns,
  anomalies, and potential threats that may not match existing rules.

  ## Parameters
    - time_range: Time range for pattern discovery (e.g., "1h", "24h", "7d")
    - pattern_type: Filter by type (anomaly, trend, correlation, baseline_deviation)
    - min_confidence: Minimum confidence score (0.0-1.0)
    - data_sources: List of data sources to include
    - limit: Number of results (default 50)
  """
  def discovered_patterns(conn, params) do
    time_range = Map.get(params, "time_range", "24h")
    pattern_type = Map.get(params, "pattern_type")
    min_confidence = Map.get(params, "min_confidence", 0.7)
    data_sources = Map.get(params, "data_sources")
    limit = Map.get(params, "limit", 50)

    opts = [
      time_range: time_range,
      min_confidence: min_confidence,
      limit: limit
    ]

    opts = if pattern_type, do: Keyword.put(opts, :pattern_type, pattern_type), else: opts
    opts = if data_sources, do: Keyword.put(opts, :data_sources, data_sources), else: opts

    with {:ok, patterns} <- AISIEM.discovered_patterns(opts) do
      json(conn, %{
        status: "success",
        data: %{
          patterns: patterns.items,
          total: patterns.total,
          discovery_stats: %{
            new_patterns_24h: patterns.stats.new_patterns_24h,
            actionable_count: patterns.stats.actionable_count,
            avg_confidence: patterns.stats.avg_confidence
          },
          time_range: time_range
        }
      })
    end
  end

  @doc """
  Get AI-correlated alerts grouped by attack chain or incident.

  The AI automatically correlates related alerts to identify
  multi-stage attacks and reduce alert fatigue.

  ## Parameters
    - time_range: Time range for correlation analysis
    - min_alerts: Minimum number of alerts in a correlation group
    - include_single: Whether to include uncorrelated single alerts
    - severity_filter: Filter by severity (low, medium, high, critical)
  """
  def alert_correlations(conn, params) do
    time_range = Map.get(params, "time_range", "24h")
    min_alerts = Map.get(params, "min_alerts", 2)
    include_single = Map.get(params, "include_single", false)
    severity_filter = Map.get(params, "severity_filter")

    opts = [
      time_range: time_range,
      min_alerts: min_alerts,
      include_single: include_single
    ]

    opts = if severity_filter, do: Keyword.put(opts, :severity_filter, severity_filter), else: opts

    with {:ok, correlations} <- AISIEM.alert_correlations(opts) do
      json(conn, %{
        status: "success",
        data: %{
          correlation_groups: correlations.groups,
          total_groups: correlations.total_groups,
          total_alerts_correlated: correlations.total_alerts_correlated,
          attack_chains_detected: correlations.attack_chains_detected,
          reduction_rate: correlations.reduction_rate,
          time_range: time_range
        }
      })
    end
  end

  @doc """
  Execute a natural language query against security logs.

  Translates natural language questions into log queries and
  returns relevant results with AI-generated insights.

  ## Parameters
    - query: The natural language query
    - time_range: Time range to search (default "24h")
    - max_results: Maximum number of log entries to return
    - include_insights: Whether to include AI-generated insights
  """
  def natural_language_log_query(conn, %{"query" => query} = params) do
    time_range = Map.get(params, "time_range", "24h")
    max_results = Map.get(params, "max_results", 100)
    include_insights = Map.get(params, "include_insights", true)

    opts = [
      time_range: time_range,
      max_results: max_results,
      include_insights: include_insights
    ]

    with {:ok, result} <- AISIEM.natural_language_log_query(query, opts) do
      json(conn, %{
        status: "success",
        data: %{
          original_query: query,
          translated_query: result.translated_query,
          query_language: result.query_language,
          results: result.log_entries,
          result_count: length(result.log_entries),
          insights: result[:insights],
          execution_time_ms: result.execution_time_ms
        }
      })
    end
  end

  def natural_language_log_query(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "query is required"})
  end

  @doc """
  Get noise metrics and alert quality statistics.

  Provides insights into alert noise, false positive rates,
  and recommendations for tuning detection rules.

  ## Parameters
    - time_range: Time range for metrics calculation
    - group_by: Group metrics by (rule, source, severity, category)
    - include_recommendations: Whether to include tuning recommendations
  """
  def noise_metrics(conn, params) do
    time_range = Map.get(params, "time_range", "7d")
    group_by = Map.get(params, "group_by", "rule")
    include_recommendations = Map.get(params, "include_recommendations", true)

    opts = [
      time_range: time_range,
      group_by: group_by,
      include_recommendations: include_recommendations
    ]

    with {:ok, metrics} <- AISIEM.noise_metrics(opts) do
      json(conn, %{
        status: "success",
        data: %{
          overall: %{
            total_alerts: metrics.overall.total_alerts,
            true_positives: metrics.overall.true_positives,
            false_positives: metrics.overall.false_positives,
            unknown: metrics.overall.unknown,
            noise_ratio: metrics.overall.noise_ratio,
            mean_time_to_triage: metrics.overall.mean_time_to_triage
          },
          breakdown: metrics.breakdown,
          top_noisy_rules: metrics.top_noisy_rules,
          recommendations: metrics[:recommendations],
          trend: %{
            noise_trend: metrics.trend.noise_trend,
            improvement_rate: metrics.trend.improvement_rate
          },
          time_range: time_range
        }
      })
    end
  end
end
