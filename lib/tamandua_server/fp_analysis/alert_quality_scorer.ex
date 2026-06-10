defmodule TamanduaServer.FPAnalysis.AlertQualityScorer do
  @moduledoc """
  Alert Quality Scorer - Scores rule quality based on FP/TP rates.

  Provides a unified quality assessment for detection rules across all
  detection sources (YARA, Sigma, ML, Behavioral, IOC).

  ## Scoring Methodology

  The quality score is a composite metric based on:
  1. **Precision** (40%) - TP / (TP + FP)
  2. **Volume Efficiency** (20%) - Alerts per day within acceptable range
  3. **Trend** (20%) - FP rate improving/degrading over time
  4. **Coverage** (10%) - Does rule detect diverse threats?
  5. **Actionability** (10%) - Do analysts take action on alerts?

  ## Score Ranges

  - 0.9-1.0: Excellent - High quality, low FP rate
  - 0.7-0.9: Good - Acceptable quality, minor tuning may help
  - 0.5-0.7: Moderate - Needs attention, tuning recommended
  - 0.3-0.5: Poor - High FP rate, tuning required
  - 0.0-0.3: Critical - Very high FP rate, consider disabling

  ## Usage

      # Score a single rule
      score = AlertQualityScorer.score_rule(organization_id, "sigma", "rule_123")
      # => %{score: 0.75, grade: "B", breakdown: {...}, recommendations: [...]}

      # Get dashboard of rule quality
      dashboard = AlertQualityScorer.get_quality_dashboard(organization_id)
  """

  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.FPAnalysis.{RuleQualityMetrics, FPReport, TuningRecommendation}

  # Score weights
  @precision_weight 0.40
  @volume_weight 0.20
  @trend_weight 0.20
  @coverage_weight 0.10
  @actionability_weight 0.10

  # Thresholds
  @ideal_alerts_per_day_min 1
  @ideal_alerts_per_day_max 50

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Calculate quality score for a specific rule.
  """
  @spec score_rule(String.t(), String.t(), String.t()) :: map()
  def score_rule(organization_id, detection_source, rule_id) do
    case Repo.get_by(RuleQualityMetrics,
           organization_id: organization_id,
           detection_source: detection_source,
           rule_id: rule_id
         ) do
      nil ->
        %{
          score: nil,
          grade: "N/A",
          message: "No quality metrics available for this rule",
          breakdown: %{},
          recommendations: []
        }

      metrics ->
        calculate_score(metrics)
    end
  end

  @doc """
  Get quality dashboard for an organization.
  """
  @spec get_quality_dashboard(String.t(), keyword()) :: map()
  def get_quality_dashboard(organization_id, opts \\ []) do
    min_alerts = Keyword.get(opts, :min_alerts, 10)

    # Get all rules with sufficient data
    metrics =
      from(m in RuleQualityMetrics,
        where: m.organization_id == ^organization_id,
        where: m.total_alerts >= ^min_alerts
      )
      |> Repo.all()

    # Score each rule
    scored_rules =
      Enum.map(metrics, fn m ->
        score_data = calculate_score(m)
        Map.merge(score_data, %{
          rule_id: m.rule_id,
          rule_name: m.rule_name,
          detection_source: m.detection_source,
          total_alerts: m.total_alerts,
          fp_count: m.false_positives,
          tp_count: m.true_positives
        })
      end)
      |> Enum.sort_by(& &1.score || 0, :asc)  # Worst first

    # Calculate summary statistics
    scores = Enum.map(scored_rules, & &1.score) |> Enum.reject(&is_nil/1)

    avg_score = if length(scores) > 0, do: Enum.sum(scores) / length(scores), else: nil

    # Grade distribution
    grade_dist = Enum.reduce(scored_rules, %{}, fn rule, acc ->
      Map.update(acc, rule.grade, 1, &(&1 + 1))
    end)

    # Rules needing attention
    rules_needing_attention =
      scored_rules
      |> Enum.filter(fn r -> r.score && r.score < 0.5 end)
      |> Enum.take(10)

    # Detection source breakdown
    by_source =
      scored_rules
      |> Enum.group_by(& &1.detection_source)
      |> Enum.map(fn {source, rules} ->
        source_scores = Enum.map(rules, & &1.score) |> Enum.reject(&is_nil/1)
        avg = if length(source_scores) > 0, do: Enum.sum(source_scores) / length(source_scores), else: nil
        %{
          source: source,
          rule_count: length(rules),
          average_score: avg && Float.round(avg, 2),
          grade: score_to_grade(avg)
        }
      end)

    %{
      summary: %{
        total_rules: length(scored_rules),
        average_score: avg_score && Float.round(avg_score, 2),
        overall_grade: score_to_grade(avg_score),
        grade_distribution: grade_dist
      },
      by_source: by_source,
      rules_needing_attention: rules_needing_attention,
      all_rules: scored_rules
    }
  end

  @doc """
  Get quality trend over time.
  """
  @spec get_quality_trend(String.t(), keyword()) :: [map()]
  def get_quality_trend(organization_id, opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    start_time = DateTime.add(DateTime.utc_now(), -days * 24 * 3600, :second)

    # Get daily FP report counts
    daily_reports =
      from(r in FPReport,
        where: r.organization_id == ^organization_id,
        where: r.inserted_at >= ^start_time,
        group_by: [fragment("date_trunc('day', ?)", r.inserted_at), r.classification],
        select: {fragment("date_trunc('day', ?)", r.inserted_at), r.classification, count(r.id)},
        order_by: [asc: fragment("date_trunc('day', ?)", r.inserted_at)]
      )
      |> Repo.all()

    # Group by date
    daily_reports
    |> Enum.group_by(fn {date, _, _} -> date end)
    |> Enum.map(fn {date, reports} ->
      counts = Map.new(reports, fn {_, class, count} -> {class, count} end)
      total = Enum.sum(Map.values(counts))
      fp_count = Map.get(counts, "false_positive", 0)
      tp_count = Map.get(counts, "true_positive", 0)

      fp_rate = if total > 0, do: fp_count / total, else: 0
      precision = if tp_count + fp_count > 0, do: tp_count / (tp_count + fp_count), else: nil

      %{
        date: date,
        total_reports: total,
        fp_count: fp_count,
        tp_count: tp_count,
        fp_rate: Float.round(fp_rate, 3),
        precision: precision && Float.round(precision, 3)
      }
    end)
    |> Enum.sort_by(& &1.date)
  end

  @doc """
  Compare rule quality across detection sources.
  """
  @spec compare_sources(String.t()) :: map()
  def compare_sources(organization_id) do
    sources = ~w(yara sigma ml behavioral ioc)

    source_stats =
      Enum.map(sources, fn source ->
        metrics =
          from(m in RuleQualityMetrics,
            where: m.organization_id == ^organization_id,
            where: m.detection_source == ^source,
            where: m.total_alerts >= 10
          )
          |> Repo.all()

        if length(metrics) > 0 do
          scores = Enum.map(metrics, fn m ->
            score_data = calculate_score(m)
            score_data.score
          end) |> Enum.reject(&is_nil/1)

          avg_score = if length(scores) > 0, do: Enum.sum(scores) / length(scores), else: nil
          total_fps = Enum.sum(Enum.map(metrics, & &1.false_positives || 0))
          total_tps = Enum.sum(Enum.map(metrics, & &1.true_positives || 0))
          total_alerts = Enum.sum(Enum.map(metrics, & &1.total_alerts || 0))

          %{
            source: source,
            rule_count: length(metrics),
            average_quality_score: avg_score && Float.round(avg_score, 2),
            grade: score_to_grade(avg_score),
            total_alerts: total_alerts,
            total_fps: total_fps,
            total_tps: total_tps,
            overall_fp_rate: if(total_alerts > 0, do: Float.round(total_fps / total_alerts, 3), else: 0),
            overall_precision: if(total_tps + total_fps > 0, do: Float.round(total_tps / (total_tps + total_fps), 3), else: nil)
          }
        else
          %{
            source: source,
            rule_count: 0,
            average_quality_score: nil,
            grade: "N/A",
            total_alerts: 0,
            total_fps: 0,
            total_tps: 0,
            overall_fp_rate: 0,
            overall_precision: nil
          }
        end
      end)

    # Calculate overall stats
    total_rules = Enum.sum(Enum.map(source_stats, & &1.rule_count))
    total_alerts = Enum.sum(Enum.map(source_stats, & &1.total_alerts))

    %{
      by_source: source_stats,
      totals: %{
        rule_count: total_rules,
        alert_count: total_alerts
      }
    }
  end

  # ---------------------------------------------------------------------------
  # Private - Score Calculation
  # ---------------------------------------------------------------------------

  defp calculate_score(%RuleQualityMetrics{} = metrics) do
    # Component scores
    precision_score = calculate_precision_score(metrics)
    volume_score = calculate_volume_score(metrics)
    trend_score = calculate_trend_score(metrics)
    coverage_score = calculate_coverage_score(metrics)
    actionability_score = calculate_actionability_score(metrics)

    # Weighted composite
    composite =
      precision_score * @precision_weight +
      volume_score * @volume_weight +
      trend_score * @trend_weight +
      coverage_score * @coverage_weight +
      actionability_score * @actionability_weight

    # Ensure valid range
    score = composite |> max(0.0) |> min(1.0) |> Float.round(3)
    grade = score_to_grade(score)

    # Generate recommendations based on weak areas
    recommendations = generate_recommendations(metrics, %{
      precision: precision_score,
      volume: volume_score,
      trend: trend_score,
      coverage: coverage_score,
      actionability: actionability_score
    })

    %{
      score: score,
      grade: grade,
      breakdown: %{
        precision: %{
          score: Float.round(precision_score, 2),
          weight: @precision_weight,
          value: metrics.precision && Float.round(metrics.precision, 3)
        },
        volume: %{
          score: Float.round(volume_score, 2),
          weight: @volume_weight,
          alerts_per_day: calculate_alerts_per_day(metrics)
        },
        trend: %{
          score: Float.round(trend_score, 2),
          weight: @trend_weight,
          direction: metrics.fp_rate_trend || "unknown"
        },
        coverage: %{
          score: Float.round(coverage_score, 2),
          weight: @coverage_weight
        },
        actionability: %{
          score: Float.round(actionability_score, 2),
          weight: @actionability_weight
        }
      },
      recommendations: recommendations
    }
  end

  defp calculate_precision_score(metrics) do
    case metrics.precision do
      nil -> 0.5  # Unknown precision
      p when p >= 0.9 -> 1.0
      p when p >= 0.8 -> 0.9
      p when p >= 0.7 -> 0.8
      p when p >= 0.6 -> 0.7
      p when p >= 0.5 -> 0.5
      p when p >= 0.3 -> 0.3
      _ -> 0.1
    end
  end

  defp calculate_volume_score(metrics) do
    alerts_per_day = calculate_alerts_per_day(metrics)

    cond do
      is_nil(alerts_per_day) -> 0.5
      alerts_per_day >= @ideal_alerts_per_day_min and alerts_per_day <= @ideal_alerts_per_day_max -> 1.0
      alerts_per_day < @ideal_alerts_per_day_min -> 0.7  # Too few alerts
      alerts_per_day <= @ideal_alerts_per_day_max * 2 -> 0.6  # Somewhat high volume
      alerts_per_day <= @ideal_alerts_per_day_max * 5 -> 0.4  # High volume
      true -> 0.2  # Very high volume (likely noisy)
    end
  end

  defp calculate_trend_score(metrics) do
    case metrics.fp_rate_trend do
      "improving" -> 1.0
      "stable" -> 0.7
      "degrading" -> 0.3
      _ -> 0.5
    end
  end

  defp calculate_coverage_score(metrics) do
    # Based on how many different contexts trigger the rule
    # Using FP context data as a proxy
    contexts = 0

    # Count unique process patterns
    if metrics.top_fp_processes && length(metrics.top_fp_processes) > 0 do
      contexts = contexts + min(1.0, length(metrics.top_fp_processes) / 5)
    end

    # Count unique path patterns
    if metrics.top_fp_paths && length(metrics.top_fp_paths) > 0 do
      contexts = contexts + min(1.0, length(metrics.top_fp_paths) / 5)
    end

    # Normalize
    min(1.0, contexts / 2)
  end

  defp calculate_actionability_score(metrics) do
    # Based on TP rate and whether analysts take action
    tp_rate = if metrics.total_alerts && metrics.total_alerts > 0 do
      (metrics.true_positives || 0) / metrics.total_alerts
    else
      0
    end

    cond do
      tp_rate >= 0.7 -> 1.0  # High TP rate = highly actionable
      tp_rate >= 0.5 -> 0.8
      tp_rate >= 0.3 -> 0.6
      tp_rate >= 0.1 -> 0.4
      true -> 0.2
    end
  end

  defp calculate_alerts_per_day(metrics) do
    if metrics.first_alert_at && metrics.total_alerts do
      days = max(1, DateTime.diff(DateTime.utc_now(), metrics.first_alert_at, :day))
      metrics.total_alerts / days
    else
      nil
    end
  end

  defp score_to_grade(nil), do: "N/A"
  defp score_to_grade(score) when score >= 0.9, do: "A"
  defp score_to_grade(score) when score >= 0.8, do: "B"
  defp score_to_grade(score) when score >= 0.7, do: "C"
  defp score_to_grade(score) when score >= 0.5, do: "D"
  defp score_to_grade(_), do: "F"

  defp generate_recommendations(metrics, scores) do
    recommendations = []

    # Low precision
    recommendations = if scores.precision < 0.5 do
      rec = %{
        type: :tune_threshold,
        priority: :high,
        message: "Rule has low precision (#{Float.round((metrics.precision || 0) * 100, 1)}%). " <>
                 "Consider increasing detection threshold or adding exclusions."
      }
      [rec | recommendations]
    else
      recommendations
    end

    # High volume
    recommendations = if scores.volume < 0.5 do
      alerts_per_day = calculate_alerts_per_day(metrics)
      rec = %{
        type: :reduce_volume,
        priority: :medium,
        message: "Rule generates #{round(alerts_per_day || 0)} alerts/day, which may cause alert fatigue."
      }
      [rec | recommendations]
    else
      recommendations
    end

    # Degrading trend
    recommendations = if scores.trend < 0.5 do
      rec = %{
        type: :investigate_trend,
        priority: :medium,
        message: "FP rate is increasing. Investigate recent changes in the environment."
      }
      [rec | recommendations]
    else
      recommendations
    end

    # Low actionability
    recommendations = if scores.actionability < 0.4 do
      rec = %{
        type: :review_value,
        priority: :low,
        message: "Few alerts from this rule are confirmed as true positives. " <>
                 "Consider if this rule provides security value."
      }
      [rec | recommendations]
    else
      recommendations
    end

    Enum.reverse(recommendations)
  end
end
