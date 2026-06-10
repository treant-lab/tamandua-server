defmodule TamanduaServer.FPAnalysis do
  @moduledoc """
  False Positive Analysis and Tuning System.

  This module provides a comprehensive system for tracking, analyzing, and
  reducing false positive alerts in Tamandua EDR.

  ## Features

  - **FP Tracking**: Track analyst feedback on alerts (TP/FP/Benign/Suspicious)
  - **Pattern Detection**: Automatically identify recurring FP patterns
  - **Auto-Tuning**: Generate and optionally auto-apply suppression rules
  - **Baseline Learning**: Learn what is "normal" for an environment
  - **Quality Scoring**: Score rule quality based on FP/TP rates
  - **Recommendations**: AI-generated tuning suggestions

  ## Quick Start

      # Report a false positive
      {:ok, report} = FPAnalysis.report_false_positive(alert_id, user_id, %{
        reason: "known_good_software",
        reason_detail: "Chrome auto-update is expected"
      })

      # Get rule quality score
      score = FPAnalysis.get_rule_quality(org_id, "sigma", "rule_123")
      # => %{score: 0.75, grade: "B", recommendations: [...]}

      # Get tuning recommendations
      recommendations = FPAnalysis.get_recommendations(org_id)

      # Get FP patterns
      patterns = FPAnalysis.get_fp_patterns(org_id)

  ## Architecture

  ```
  FPAnalysis (Main API)
      |
      +-- FPTracker (Report submission and tracking)
      |
      +-- FPPatterns (Pattern detection)
      |
      +-- AutoTuner (Automatic suppression rule generation)
      |
      +-- BaselineLearner (Environment baseline)
      |
      +-- AlertQualityScorer (Rule quality metrics)
  ```

  ## Database Tables

  - `fp_reports` - Analyst feedback on alerts
  - `rule_quality_metrics` - Per-rule FP/TP statistics
  - `baseline_profiles` - Environment baselines
  - `fp_patterns` - Detected FP patterns
  - `tuning_recommendations` - AI-generated suggestions
  """

  alias TamanduaServer.FPAnalysis.{
    FPTracker,
    FPPatterns,
    AutoTuner,
    BaselineLearner,
    AlertQualityScorer,
    FPReport,
    RuleQualityMetrics,
    BaselineProfile,
    FPPattern,
    TuningRecommendation
  }

  # ===========================================================================
  # FP Reporting
  # ===========================================================================

  @doc """
  Report an alert as a false positive.

  ## Options

  - `:reason` - Reason category (e.g., "known_good_software", "authorized_activity")
  - `:reason_detail` - Detailed explanation
  - `:confidence` - Analyst confidence (0.0-1.0, default 1.0)
  - `:tags` - List of tags for categorization
  """
  @spec report_false_positive(String.t(), String.t() | nil, map()) ::
          {:ok, FPReport.t()} | {:error, term()}
  defdelegate report_false_positive(alert_id, user_id, opts \\ %{}), to: FPTracker

  @doc """
  Report an alert as a true positive.
  """
  @spec report_true_positive(String.t(), String.t() | nil, map()) ::
          {:ok, FPReport.t()} | {:error, term()}
  defdelegate report_true_positive(alert_id, user_id, opts \\ %{}), to: FPTracker

  @doc """
  Report an alert as benign (not malicious but also not a detection error).
  """
  @spec report_benign(String.t(), String.t() | nil, map()) ::
          {:ok, FPReport.t()} | {:error, term()}
  defdelegate report_benign(alert_id, user_id, opts \\ %{}), to: FPTracker

  @doc """
  Report an alert as suspicious (requires further investigation).
  """
  @spec report_suspicious(String.t(), String.t() | nil, map()) ::
          {:ok, FPReport.t()} | {:error, term()}
  defdelegate report_suspicious(alert_id, user_id, opts \\ %{}), to: FPTracker

  @doc """
  Get FP reports for a specific alert.
  """
  @spec get_alert_reports(String.t()) :: [FPReport.t()]
  defdelegate get_alert_reports(alert_id), to: FPTracker

  @doc """
  Get FP statistics for an organization.

  ## Options

  - `:days` - Number of days to include (default 30)
  """
  @spec get_organization_stats(String.t(), keyword()) :: map()
  defdelegate get_organization_stats(organization_id, opts \\ []), to: FPTracker

  @doc """
  Get top FP-generating rules.

  ## Options

  - `:limit` - Maximum number of rules (default 10)
  - `:days` - Number of days to include (default 30)
  """
  @spec get_top_fp_rules(String.t(), keyword()) :: [map()]
  defdelegate get_top_fp_rules(organization_id, opts \\ []), to: FPTracker

  @doc """
  Get pending FP reports for review.
  """
  @spec get_pending_reviews(String.t(), keyword()) :: [FPReport.t()]
  defdelegate get_pending_reviews(organization_id, opts \\ []), to: FPTracker

  @doc """
  Mark an FP report as reviewed.
  """
  @spec review_report(String.t(), String.t(), map()) ::
          {:ok, FPReport.t()} | {:error, term()}
  defdelegate review_report(report_id, reviewer_id, opts \\ %{}), to: FPTracker

  # ===========================================================================
  # Rule Quality
  # ===========================================================================

  @doc """
  Get quality score for a specific rule.

  Returns a map with:
  - `:score` - Quality score (0.0-1.0)
  - `:grade` - Letter grade (A-F)
  - `:breakdown` - Component scores
  - `:recommendations` - Improvement suggestions
  """
  @spec get_rule_quality(String.t(), String.t(), String.t()) :: map()
  defdelegate get_rule_quality(organization_id, detection_source, rule_id),
    to: AlertQualityScorer, as: :score_rule

  @doc """
  Get quality dashboard for all rules in an organization.
  """
  @spec get_quality_dashboard(String.t(), keyword()) :: map()
  defdelegate get_quality_dashboard(organization_id, opts \\ []), to: AlertQualityScorer

  @doc """
  Get rule quality trend over time.
  """
  @spec get_quality_trend(String.t(), keyword()) :: [map()]
  defdelegate get_quality_trend(organization_id, opts \\ []), to: AlertQualityScorer

  @doc """
  Compare quality across detection sources.
  """
  @spec compare_sources(String.t()) :: map()
  defdelegate compare_sources(organization_id), to: AlertQualityScorer

  @doc """
  Get statistics for a specific rule.
  """
  @spec get_rule_stats(String.t(), String.t(), String.t()) :: map()
  defdelegate get_rule_stats(organization_id, detection_source, rule_id), to: FPTracker

  # ===========================================================================
  # FP Patterns
  # ===========================================================================

  @doc """
  Get detected FP patterns for an organization.

  ## Options

  - `:status` - Filter by status ("detected", "confirmed", "rejected", "tuned")
  - `:pattern_type` - Filter by type ("process", "path", "rule", etc.)
  - `:min_confidence` - Minimum FP confidence (default 0.5)
  - `:limit` - Maximum patterns to return (default 50)
  """
  @spec get_fp_patterns(String.t(), keyword()) :: [FPPattern.t()]
  defdelegate get_fp_patterns(organization_id, opts \\ []), to: FPPatterns, as: :get_patterns

  @doc """
  Get patterns ready for auto-tuning.
  """
  @spec get_tunable_patterns(String.t()) :: [FPPattern.t()]
  defdelegate get_tunable_patterns(organization_id), to: FPPatterns

  @doc """
  Confirm a pattern as valid for suppression.
  """
  @spec confirm_pattern(String.t(), String.t(), map()) ::
          {:ok, FPPattern.t()} | {:error, term()}
  defdelegate confirm_pattern(pattern_id, user_id, opts \\ %{}), to: FPPatterns

  @doc """
  Reject a pattern as not suitable for suppression.
  """
  @spec reject_pattern(String.t(), String.t(), String.t() | nil) ::
          {:ok, FPPattern.t()} | {:error, term()}
  defdelegate reject_pattern(pattern_id, user_id, reason \\ nil), to: FPPatterns

  @doc """
  Run full pattern analysis for an organization.
  """
  @spec analyze_patterns(String.t()) :: {:ok, [FPPattern.t()]}
  defdelegate analyze_patterns(organization_id), to: FPPatterns, as: :analyze_organization

  # ===========================================================================
  # Auto-Tuning
  # ===========================================================================

  @doc """
  Get pending tuning recommendations.
  """
  @spec get_recommendations(String.t(), keyword()) :: [TuningRecommendation.t()]
  defdelegate get_recommendations(organization_id, opts \\ []), to: AutoTuner

  @doc """
  Apply a tuning recommendation.
  """
  @spec apply_recommendation(String.t(), String.t()) ::
          {:ok, TuningRecommendation.t()} | {:error, term()}
  defdelegate apply_recommendation(recommendation_id, user_id), to: AutoTuner

  @doc """
  Create a suppression rule from a detected pattern.
  """
  @spec create_suppression_for_pattern(FPPattern.t(), keyword()) ::
          {:ok, term()} | {:error, term()}
  defdelegate create_suppression_for_pattern(pattern, opts \\ []), to: AutoTuner

  @doc """
  Get auto-tuning statistics.
  """
  @spec get_tuning_stats(String.t()) :: map()
  defdelegate get_tuning_stats(organization_id), to: AutoTuner, as: :get_stats

  @doc """
  Run full evaluation for an organization.
  """
  @spec evaluate_organization(String.t()) :: {:ok, map()}
  defdelegate evaluate_organization(organization_id), to: AutoTuner

  # ===========================================================================
  # Baseline Learning
  # ===========================================================================

  @doc """
  Start learning baseline for an entity.

  ## Entity Types

  - `:organization` - Organization-wide baseline
  - `:agent` - Specific agent baseline
  - `:user` - User behavior baseline
  - `:agent_group` - Agent group baseline
  """
  @spec start_baseline_learning(String.t(), atom(), String.t() | nil) ::
          {:ok, BaselineProfile.t()} | {:error, term()}
  defdelegate start_baseline_learning(entity_key, entity_type, organization_id \\ nil),
    to: BaselineLearner, as: :start_learning

  @doc """
  Get baseline profile for an entity.
  """
  @spec get_baseline(String.t(), atom(), String.t() | nil) :: BaselineProfile.t() | nil
  defdelegate get_baseline(entity_key, entity_type, organization_id \\ nil), to: BaselineLearner

  @doc """
  Check if a detection is expected based on baseline.
  """
  @spec is_expected_detection?(String.t(), String.t(), map()) :: boolean()
  defdelegate is_expected_detection?(organization_id, rule_id, context \\ %{}), to: BaselineLearner

  @doc """
  Get anomaly score for a detection (0.0 = normal, 1.0 = highly anomalous).
  """
  @spec get_detection_anomaly_score(String.t(), map()) :: float()
  defdelegate get_detection_anomaly_score(organization_id, detection), to: BaselineLearner

  @doc """
  Get baseline learning statistics.
  """
  @spec get_baseline_stats() :: map()
  defdelegate get_baseline_stats(), to: BaselineLearner, as: :get_stats

  # ===========================================================================
  # Aggregate Analytics
  # ===========================================================================

  @doc """
  Get comprehensive FP analysis summary for an organization.
  """
  @spec get_analysis_summary(String.t()) :: map()
  def get_analysis_summary(organization_id) do
    %{
      organization_id: organization_id,
      fp_stats: get_organization_stats(organization_id),
      quality_summary: get_quality_dashboard(organization_id).summary,
      source_comparison: compare_sources(organization_id),
      tuning_stats: get_tuning_stats(organization_id),
      baseline_stats: get_baseline_stats(),
      top_fp_rules: get_top_fp_rules(organization_id, limit: 5),
      pending_patterns: length(get_tunable_patterns(organization_id)),
      pending_recommendations: length(get_recommendations(organization_id, status: "pending")),
      generated_at: DateTime.utc_now()
    }
  end

  @doc """
  Get actionable insights for reducing FPs.
  """
  @spec get_actionable_insights(String.t()) :: [map()]
  def get_actionable_insights(organization_id) do
    insights = []

    # Check for high FP rules
    top_fp_rules = get_top_fp_rules(organization_id, limit: 3)
    insights = Enum.reduce(top_fp_rules, insights, fn rule, acc ->
      if rule.fp_count >= 10 do
        insight = %{
          type: :high_fp_rule,
          priority: :high,
          title: "High FP rule: #{rule.rule_name || rule.rule_id}",
          description: "#{rule.fp_count} false positives in the last 30 days",
          action: "Review and tune this rule",
          data: rule
        }
        [insight | acc]
      else
        acc
      end
    end)

    # Check for tunable patterns
    patterns = get_tunable_patterns(organization_id) |> Enum.take(3)
    insights = Enum.reduce(patterns, insights, fn pattern, acc ->
      insight = %{
        type: :tunable_pattern,
        priority: :medium,
        title: "FP Pattern detected: #{pattern.pattern_type}",
        description: "#{pattern.fp_count} FPs match this pattern with #{Float.round(pattern.fp_confidence * 100, 1)}% confidence",
        action: "Review and create suppression rule",
        data: %{pattern_id: pattern.id, pattern_type: pattern.pattern_type}
      }
      [insight | acc]
    end)

    # Check for pending recommendations
    recommendations = get_recommendations(organization_id, limit: 3)
    insights = Enum.reduce(recommendations, insights, fn rec, acc ->
      insight = %{
        type: :pending_recommendation,
        priority: String.to_atom(rec.priority),
        title: rec.title,
        description: rec.description,
        action: "Review and apply recommendation",
        data: %{recommendation_id: rec.id}
      }
      [insight | acc]
    end)

    # Sort by priority
    priority_order = %{critical: 0, high: 1, medium: 2, low: 3}
    Enum.sort_by(insights, fn i -> Map.get(priority_order, i.priority, 4) end)
  end
end
