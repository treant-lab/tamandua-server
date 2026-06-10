defmodule TamanduaServerWeb.API.V1.DetectionAnalyticsController do
  @moduledoc """
  API controller for Detection Analytics & Tuning endpoints.

  Provides access to per-rule detection metrics, pipeline performance,
  detection blind spots, and tuning recommendations.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Detection.{
    Analytics,
    CollectorCoverage,
    EffectiveCoverage,
    PrecisionMetrics
  }

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  GET /api/v1/detection-analytics/overview

  Returns summary metrics for the detection analytics dashboard:
  total rules, avg effectiveness, FP rate, detection rate, pipeline throughput.
  """
  def overview(conn, _params) do
    overview = Analytics.get_overview()

    json(conn, %{
      data: %{
        totalRules: overview.total_rules,
        activeRules: overview.active_rules,
        totalDetections: overview.total_detections,
        avgEffectiveness: overview.avg_effectiveness,
        falsePositiveRate: overview.false_positive_rate,
        truePositiveRate: overview.true_positive_rate,
        detectionRate: overview.detection_rate,
        totalEventsProcessed: overview.total_events_processed,
        avgPipelineLatencyMs: overview.avg_pipeline_latency_ms,
        totalRecommendations: overview.total_recommendations,
        totalBlindSpots: overview.total_blind_spots
      }
    })
  end

  @doc """
  GET /api/v1/detection-analytics/rules

  Returns per-rule performance metrics. Supports sorting via query params:
  - sort_by: effectiveness_score, fp_rate, total_hits, tp_rate (default: effectiveness_score)
  - sort_order: asc, desc (default: desc)
  - limit: max number of results (default: unlimited)
  """
  def rules(conn, params) do
    sort_by = parse_sort_by(params["sort_by"])
    sort_order = if params["sort_order"] == "asc", do: :asc, else: :desc
    limit = parse_int(params["limit"])

    opts = [sort_by: sort_by, sort_order: sort_order]
    opts = if limit, do: Keyword.put(opts, :limit, limit), else: opts

    metrics = Analytics.get_rule_metrics(opts)

    json(conn, %{
      data: Enum.map(metrics, fn m ->
        %{
          ruleId: m.rule_id,
          ruleName: m.rule_name,
          ruleType: m.rule_type,
          totalHits: m.total_hits,
          truePositives: m.true_positives,
          falsePositives: m.false_positives,
          benignCount: m.benign_count,
          avgConfidence: m.avg_confidence,
          fpRate: m.fp_rate,
          tpRate: m.tp_rate,
          effectivenessScore: m.effectiveness_score,
          meanTriageSeconds: m.mean_triage_seconds,
          detectionToAlertRatio: m.detection_to_alert_ratio,
          mitreTechniques: m.mitre_techniques,
          firstHitAt: m.first_hit_at,
          lastHitAt: m.last_hit_at
        }
      end),
      meta: %{
        total: length(metrics),
        sortBy: to_string(sort_by),
        sortOrder: to_string(sort_order)
      }
    })
  end

  @doc """
  GET /api/v1/detection-analytics/pipeline

  Returns pipeline performance metrics per stage:
  total events, avg latency, p95 latency, error rates.
  """
  def pipeline(conn, _params) do
    pipeline = Analytics.get_pipeline_metrics()

    json(conn, %{
      data: %{
        totalEventsProcessed: pipeline.total_events_processed,
        stages: Enum.map(pipeline.stages_summary, fn s ->
          %{
            stage: s.stage,
            totalEvents: s.total_events,
            avgLatencyMs: s.avg_latency_ms,
            p95LatencyMs: s.p95_latency_ms,
            errorCount: s.error_count,
            errorRate: s.error_rate
          }
        end)
      }
    })
  end

  @doc """
  GET /api/v1/detection-analytics/blind-spots

  Returns detection blind spots analysis:
  - MITRE technique gaps (uncovered techniques)
  - Event type gaps (uncovered event types)
  - Time-of-day coverage gaps
  """
  def blind_spots(conn, _params) do
    spots = Analytics.get_blind_spots()

    mitre = spots.mitre_gaps || %{}
    event_types = spots.event_type_gaps || %{}
    time_gaps = spots.time_of_day_gaps || %{}

    json(conn, %{
      data: %{
        mitre: %{
          totalTechniques: mitre[:total_techniques] || 0,
          coveredTechniques: mitre[:covered_techniques] || 0,
          coveragePercent: mitre[:coverage_percent] || 0.0,
          uncoveredTechniques: mitre[:uncovered_techniques] || [],
          coveredByRuleType: Enum.map(mitre[:covered_by_rule_type] || [], fn t ->
            %{type: t.type, techniqueCount: t.technique_count}
          end)
        },
        eventTypes: %{
          totalEventTypes: event_types[:total_event_types] || 0,
          coveredEventTypes: event_types[:covered_event_types] || 0,
          uncoveredEventTypes: event_types[:uncovered_event_types] || []
        },
        timeOfDay: %{
          hourlyDistribution: Enum.map(time_gaps[:hourly_distribution] || [], fn h ->
            %{hour: h.hour, count: h.count}
          end),
          gapHours: time_gaps[:gap_hours] || [],
          avgHourlyCount: time_gaps[:avg_hourly_count] || 0.0
        }
      }
    })
  end

  @doc """
  GET /api/v1/detection-analytics/recommendations

  Returns tuning recommendations: high FP rules, dormant rules,
  correlated rules, ML threshold adjustments.
  """
  def recommendations(conn, _params) do
    recs = Analytics.get_recommendations()

    json(conn, %{
      data: Enum.map(recs, fn r ->
        %{
          id: r.id,
          type: r.type,
          priority: r.priority,
          ruleId: r[:rule_id],
          ruleName: r[:rule_name],
          title: r.title,
          description: r.description,
          impact: r[:impact],
          action: r[:action],
          metrics: r[:metrics] || %{}
        }
      end),
      meta: %{
        total: length(recs),
        byCritical: Enum.count(recs, &(&1.priority == "critical")),
        byHigh: Enum.count(recs, &(&1.priority == "high")),
        byMedium: Enum.count(recs, &(&1.priority == "medium")),
        byLow: Enum.count(recs, &(&1.priority == "low"))
      }
    })
  end

  @doc """
  GET /api/v1/detection-analytics/trends

  Returns time-series metrics for detection trends.
  Query params:
  - time_range: 24h, 7d, 30d, 90d (default: 7d)
  """
  def trends(conn, params) do
    time_range = params["time_range"] || "7d"
    trends = Analytics.get_trends(time_range)

    json(conn, %{
      data: %{
        timeRange: trends.time_range,
        alertTrend: trends.alert_trend,
        fpTrend: trends.fp_trend,
        severityTrend: trends.severity_trend
      }
    })
  end

  @doc """
  GET /api/v1/detection-analytics/precision-metrics

  Returns runtime precision, latency, event-loss, and collector degradation
  metrics from live detection telemetry.
  """
  def precision_metrics(conn, params) do
    json(conn, %{data: PrecisionMetrics.summary(metric_filters(params))})
  end

  @doc """
  GET /api/v1/detection-analytics/collector-coverage

  Returns the declared collector-to-MITRE coverage matrix and summary.
  """
  def collector_coverage(conn, params) do
    filters = metric_filters(params)
    entries = collector_coverage_entries(filters)

    json(conn, %{
      data: %{
        summary: CollectorCoverage.summary(coverage_scope(filters)),
        entries: Enum.map(entries, &serialize_coverage_entry/1)
      },
      meta: %{
        total: length(entries)
      }
    })
  end

  @doc """
  GET /api/v1/detection-analytics/effective-coverage

  Returns declared coverage joined with runtime telemetry so operators can see
  possible, configured, and active collector/MITRE coverage.
  """
  def effective_coverage(conn, params) do
    json(conn, %{data: EffectiveCoverage.summary(params)})
  end

  # =========================================================================
  # Private Helpers
  # =========================================================================

  defp collector_coverage_entries(%{collector: collector}), do: CollectorCoverage.for_collector(collector)
  defp collector_coverage_entries(%{profile: profile}), do: CollectorCoverage.for_profile(profile)
  defp collector_coverage_entries(_filters), do: CollectorCoverage.matrix()

  defp coverage_scope(filters) when map_size(filters) == 0, do: :all
  defp coverage_scope(filters), do: filters

  defp metric_filters(params) do
    [:collector, :profile, :family]
    |> Enum.reduce(%{}, fn key, acc ->
      case Map.get(params, to_string(key)) do
        nil -> acc
        "" -> acc
        value -> Map.put(acc, key, value)
      end
    end)
  end

  defp serialize_coverage_entry(entry) do
    %{
      collector: entry.collector,
      profiles: entry.profiles,
      tacticId: entry.tactic_id,
      tactic: entry.tactic,
      techniqueId: entry.technique_id,
      technique: entry.technique,
      coverageLevel: entry.coverage_level,
      telemetryRequirements: entry.telemetry_requirements,
      notes: entry[:notes]
    }
  end

  defp parse_sort_by("fp_rate"), do: :fp_rate
  defp parse_sort_by("tp_rate"), do: :tp_rate
  defp parse_sort_by("total_hits"), do: :total_hits
  defp parse_sort_by("avg_confidence"), do: :avg_confidence
  defp parse_sort_by("rule_name"), do: :rule_name
  defp parse_sort_by("rule_type"), do: :rule_type
  defp parse_sort_by(_), do: :effectiveness_score

  defp parse_int(nil), do: nil
  defp parse_int(val) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_int(val) when is_integer(val), do: val
  defp parse_int(_), do: nil
end
