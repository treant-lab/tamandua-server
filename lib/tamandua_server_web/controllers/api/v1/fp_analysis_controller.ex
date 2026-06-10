defmodule TamanduaServerWeb.API.V1.FPAnalysisController do
  @moduledoc """
  API Controller for False Positive Analysis and Tuning System.

  Provides REST endpoints for:
  - Submitting FP/TP reports
  - Viewing rule quality metrics
  - Managing detected patterns
  - Applying tuning recommendations
  - Viewing baseline profiles
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.FPAnalysis
  alias TamanduaServer.AuditLog

  action_fallback TamanduaServerWeb.FallbackController

  # ===========================================================================
  # FP Reporting
  # ===========================================================================

  @doc """
  Submit a classification report for an alert.

  POST /api/v1/fp-analysis/reports
  Body: {
    "alert_id": "...",
    "classification": "false_positive|true_positive|benign|suspicious",
    "reason": "known_good_software",
    "reason_detail": "Chrome auto-update is expected behavior",
    "confidence": 1.0,
    "tags": ["scheduled_task", "auto_update"]
  }
  """
  def create_report(conn, %{"alert_id" => alert_id, "classification" => classification} = params) do
    user = conn.assigns[:current_user]
    user_id = user && user.id

    opts = %{
      reason: params["reason"],
      reason_detail: params["reason_detail"],
      confidence: params["confidence"],
      tags: params["tags"]
    }

    result = case classification do
      "false_positive" -> FPAnalysis.report_false_positive(alert_id, user_id, opts)
      "true_positive" -> FPAnalysis.report_true_positive(alert_id, user_id, opts)
      "benign" -> FPAnalysis.report_benign(alert_id, user_id, opts)
      "suspicious" -> FPAnalysis.report_suspicious(alert_id, user_id, opts)
      _ -> {:error, :invalid_classification}
    end

    case result do
      {:ok, report} ->
        AuditLog.log_action(user, "fp_report_created", %{
          alert_id: alert_id,
          classification: classification
        })

        conn
        |> put_status(:created)
        |> json(%{data: serialize_report(report), message: "Report submitted successfully"})

      {:error, :invalid_classification} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid classification. Must be one of: false_positive, true_positive, benign, suspicious"})

      {:error, :alert_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Alert not found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: format_changeset_errors(changeset)})
    end
  end

  @doc """
  Get reports for an alert.

  GET /api/v1/fp-analysis/alerts/:alert_id/reports
  """
  def list_alert_reports(conn, %{"alert_id" => alert_id}) do
    reports = FPAnalysis.get_alert_reports(alert_id)
    json(conn, %{data: Enum.map(reports, &serialize_report/1)})
  end

  @doc """
  Get pending reports for review.

  GET /api/v1/fp-analysis/reports/pending
  """
  def list_pending_reports(conn, params) do
    organization_id = conn.assigns[:organization_id]
    limit = parse_int(params["limit"], 50)

    reports = FPAnalysis.get_pending_reviews(organization_id, limit: limit)
    json(conn, %{data: Enum.map(reports, &serialize_report/1)})
  end

  @doc """
  Review an FP report.

  POST /api/v1/fp-analysis/reports/:id/review
  """
  def review_report(conn, %{"id" => report_id} = params) do
    user = conn.assigns[:current_user]
    user_id = user && user.id

    case FPAnalysis.review_report(report_id, user_id, params) do
      {:ok, report} ->
        json(conn, %{data: serialize_report(report), message: "Report reviewed"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Report not found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: format_changeset_errors(changeset)})
    end
  end

  # ===========================================================================
  # Statistics
  # ===========================================================================

  @doc """
  Get FP statistics for the organization.

  GET /api/v1/fp-analysis/stats
  """
  def stats(conn, params) do
    organization_id = conn.assigns[:organization_id]
    days = parse_int(params["days"], 30)

    stats = FPAnalysis.get_organization_stats(organization_id, days: days)
    json(conn, %{data: stats})
  end

  @doc """
  Get comprehensive analysis summary.

  GET /api/v1/fp-analysis/summary
  """
  def summary(conn, _params) do
    organization_id = conn.assigns[:organization_id]
    summary = FPAnalysis.get_analysis_summary(organization_id)
    json(conn, %{data: summary})
  end

  @doc """
  Get actionable insights.

  GET /api/v1/fp-analysis/insights
  """
  def insights(conn, _params) do
    organization_id = conn.assigns[:organization_id]
    insights = FPAnalysis.get_actionable_insights(organization_id)
    json(conn, %{data: insights})
  end

  @doc """
  Get top FP-generating rules.

  GET /api/v1/fp-analysis/top-fp-rules
  """
  def top_fp_rules(conn, params) do
    organization_id = conn.assigns[:organization_id]
    limit = parse_int(params["limit"], 10)
    days = parse_int(params["days"], 30)

    rules = FPAnalysis.get_top_fp_rules(organization_id, limit: limit, days: days)
    json(conn, %{data: rules})
  end

  # ===========================================================================
  # Rule Quality
  # ===========================================================================

  @doc """
  Get quality score for a specific rule.

  GET /api/v1/fp-analysis/rules/:detection_source/:rule_id/quality
  """
  def rule_quality(conn, %{"detection_source" => source, "rule_id" => rule_id}) do
    organization_id = conn.assigns[:organization_id]
    quality = FPAnalysis.get_rule_quality(organization_id, source, rule_id)
    json(conn, %{data: quality})
  end

  @doc """
  Get rule quality dashboard.

  GET /api/v1/fp-analysis/rules/quality-dashboard
  """
  def quality_dashboard(conn, params) do
    organization_id = conn.assigns[:organization_id]
    min_alerts = parse_int(params["min_alerts"], 10)

    dashboard = FPAnalysis.get_quality_dashboard(organization_id, min_alerts: min_alerts)
    json(conn, %{data: dashboard})
  end

  @doc """
  Get rule quality trend.

  GET /api/v1/fp-analysis/rules/quality-trend
  """
  def quality_trend(conn, params) do
    organization_id = conn.assigns[:organization_id]
    days = parse_int(params["days"], 30)

    trend = FPAnalysis.get_quality_trend(organization_id, days: days)
    json(conn, %{data: trend})
  end

  @doc """
  Compare quality across detection sources.

  GET /api/v1/fp-analysis/rules/compare-sources
  """
  def compare_sources(conn, _params) do
    organization_id = conn.assigns[:organization_id]
    comparison = FPAnalysis.compare_sources(organization_id)
    json(conn, %{data: comparison})
  end

  # ===========================================================================
  # FP Patterns
  # ===========================================================================

  @doc """
  Get detected FP patterns.

  GET /api/v1/fp-analysis/patterns
  """
  def list_patterns(conn, params) do
    organization_id = conn.assigns[:organization_id]

    opts = [
      status: params["status"],
      pattern_type: params["pattern_type"],
      min_confidence: parse_float(params["min_confidence"], 0.5),
      limit: parse_int(params["limit"], 50)
    ]

    patterns = FPAnalysis.get_fp_patterns(organization_id, opts)
    json(conn, %{data: Enum.map(patterns, &serialize_pattern/1)})
  end

  @doc """
  Get patterns ready for auto-tuning.

  GET /api/v1/fp-analysis/patterns/tunable
  """
  def tunable_patterns(conn, _params) do
    organization_id = conn.assigns[:organization_id]
    patterns = FPAnalysis.get_tunable_patterns(organization_id)
    json(conn, %{data: Enum.map(patterns, &serialize_pattern/1)})
  end

  @doc """
  Confirm a pattern for suppression.

  POST /api/v1/fp-analysis/patterns/:id/confirm
  """
  def confirm_pattern(conn, %{"id" => pattern_id} = params) do
    user = conn.assigns[:current_user]
    user_id = user && user.id
    create_suppression = params["create_suppression"] == true || params["create_suppression"] == "true"

    case FPAnalysis.confirm_pattern(pattern_id, user_id, %{create_suppression: create_suppression}) do
      {:ok, pattern} ->
        AuditLog.log_action(user, "fp_pattern_confirmed", %{pattern_id: pattern_id})
        json(conn, %{data: serialize_pattern(pattern), message: "Pattern confirmed"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Pattern not found"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to confirm pattern: #{inspect(reason)}"})
    end
  end

  @doc """
  Reject a pattern.

  POST /api/v1/fp-analysis/patterns/:id/reject
  """
  def reject_pattern(conn, %{"id" => pattern_id} = params) do
    user = conn.assigns[:current_user]
    user_id = user && user.id
    reason = params["reason"]

    case FPAnalysis.reject_pattern(pattern_id, user_id, reason) do
      {:ok, pattern} ->
        AuditLog.log_action(user, "fp_pattern_rejected", %{pattern_id: pattern_id})
        json(conn, %{data: serialize_pattern(pattern), message: "Pattern rejected"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Pattern not found"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to reject pattern: #{inspect(reason)}"})
    end
  end

  @doc """
  Run pattern analysis for the organization.

  POST /api/v1/fp-analysis/patterns/analyze
  """
  def analyze_patterns(conn, _params) do
    organization_id = conn.assigns[:organization_id]

    case FPAnalysis.analyze_patterns(organization_id) do
      {:ok, patterns} ->
        json(conn, %{
          data: Enum.map(patterns, &serialize_pattern/1),
          message: "Analysis complete. Found #{length(patterns)} patterns."
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Analysis failed: #{inspect(reason)}"})
    end
  end

  # ===========================================================================
  # Tuning Recommendations
  # ===========================================================================

  @doc """
  Get pending tuning recommendations.

  GET /api/v1/fp-analysis/recommendations
  """
  def list_recommendations(conn, params) do
    organization_id = conn.assigns[:organization_id]
    status = params["status"] || "pending"
    limit = parse_int(params["limit"], 50)

    recommendations = FPAnalysis.get_recommendations(organization_id, status: status, limit: limit)
    json(conn, %{data: Enum.map(recommendations, &serialize_recommendation/1)})
  end

  @doc """
  Apply a tuning recommendation.

  POST /api/v1/fp-analysis/recommendations/:id/apply
  """
  def apply_recommendation(conn, %{"id" => recommendation_id}) do
    user = conn.assigns[:current_user]
    user_id = user && user.id

    case FPAnalysis.apply_recommendation(recommendation_id, user_id) do
      {:ok, recommendation} ->
        AuditLog.log_action(user, "tuning_recommendation_applied", %{
          recommendation_id: recommendation_id
        })
        json(conn, %{data: serialize_recommendation(recommendation), message: "Recommendation applied"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Recommendation not found"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to apply recommendation: #{inspect(reason)}"})
    end
  end

  @doc """
  Get tuning statistics.

  GET /api/v1/fp-analysis/tuning/stats
  """
  def tuning_stats(conn, _params) do
    organization_id = conn.assigns[:organization_id]
    stats = FPAnalysis.get_tuning_stats(organization_id)
    json(conn, %{data: stats})
  end

  @doc """
  Run organization evaluation.

  POST /api/v1/fp-analysis/tuning/evaluate
  """
  def evaluate_organization(conn, _params) do
    organization_id = conn.assigns[:organization_id]

    case FPAnalysis.evaluate_organization(organization_id) do
      {:ok, result} ->
        json(conn, %{data: result, message: "Evaluation complete"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Evaluation failed: #{inspect(reason)}"})
    end
  end

  # ===========================================================================
  # Baselines
  # ===========================================================================

  @doc """
  Get baseline profile for the organization.

  GET /api/v1/fp-analysis/baselines/:profile_type/:profile_key
  """
  def get_baseline(conn, %{"profile_type" => profile_type, "profile_key" => profile_key}) do
    organization_id = conn.assigns[:organization_id]
    entity_type = String.to_existing_atom(profile_type)

    case FPAnalysis.get_baseline(profile_key, entity_type, organization_id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Baseline not found"})

      baseline ->
        json(conn, %{data: serialize_baseline(baseline)})
    end
  rescue
    ArgumentError ->
      conn
      |> put_status(:bad_request)
      |> json(%{error: "Invalid profile type"})
  end

  @doc """
  Start baseline learning.

  POST /api/v1/fp-analysis/baselines
  """
  def start_baseline(conn, %{"profile_type" => profile_type, "profile_key" => profile_key}) do
    organization_id = conn.assigns[:organization_id]
    entity_type = String.to_existing_atom(profile_type)

    case FPAnalysis.start_baseline_learning(profile_key, entity_type, organization_id) do
      {:ok, baseline} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_baseline(baseline), message: "Baseline learning started"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: format_changeset_errors(changeset)})
    end
  rescue
    ArgumentError ->
      conn
      |> put_status(:bad_request)
      |> json(%{error: "Invalid profile type"})
  end

  @doc """
  Get baseline statistics.

  GET /api/v1/fp-analysis/baselines/stats
  """
  def baseline_stats(conn, _params) do
    stats = FPAnalysis.get_baseline_stats()
    json(conn, %{data: stats})
  end

  # ===========================================================================
  # Helpers
  # ===========================================================================

  defp serialize_report(report) do
    %{
      id: report.id,
      alert_id: report.alert_id,
      classification: report.classification,
      confidence: report.confidence,
      reason: report.reason,
      reason_detail: report.reason_detail,
      tags: report.tags,
      detection_source: report.detection_source,
      rule_id: report.rule_id,
      rule_name: report.rule_name,
      process_name: report.process_name,
      file_path: report.file_path,
      hostname: report.hostname,
      reviewed: report.reviewed,
      reviewed_at: report.reviewed_at && DateTime.to_iso8601(report.reviewed_at),
      created_at: report.inserted_at && DateTime.to_iso8601(report.inserted_at)
    }
  end

  defp serialize_pattern(pattern) do
    %{
      id: pattern.id,
      pattern_type: pattern.pattern_type,
      pattern_key: pattern.pattern_key,
      pattern_data: pattern.pattern_data,
      description: pattern.description,
      detection_source: pattern.detection_source,
      associated_rules: pattern.associated_rules,
      fp_count: pattern.fp_count,
      tp_count: pattern.tp_count,
      total_matches: pattern.total_matches,
      fp_confidence: pattern.fp_confidence,
      status: pattern.status,
      suppression_created: pattern.suppression_created,
      reviewed: pattern.reviewed,
      first_seen_at: pattern.first_seen_at && DateTime.to_iso8601(pattern.first_seen_at),
      last_seen_at: pattern.last_seen_at && DateTime.to_iso8601(pattern.last_seen_at)
    }
  end

  defp serialize_recommendation(recommendation) do
    %{
      id: recommendation.id,
      recommendation_type: recommendation.recommendation_type,
      target_type: recommendation.target_type,
      target_id: recommendation.target_id,
      target_name: recommendation.target_name,
      title: recommendation.title,
      description: recommendation.description,
      rationale: recommendation.rationale,
      impact_assessment: recommendation.impact_assessment,
      action_data: recommendation.action_data,
      confidence: recommendation.confidence,
      priority: recommendation.priority,
      estimated_fp_reduction: recommendation.estimated_fp_reduction,
      status: recommendation.status,
      applied_at: recommendation.applied_at && DateTime.to_iso8601(recommendation.applied_at),
      expires_at: recommendation.expires_at && DateTime.to_iso8601(recommendation.expires_at),
      created_at: recommendation.inserted_at && DateTime.to_iso8601(recommendation.inserted_at)
    }
  end

  defp serialize_baseline(baseline) do
    %{
      id: baseline.id,
      profile_type: baseline.profile_type,
      profile_key: baseline.profile_key,
      profile_name: baseline.profile_name,
      status: baseline.status,
      learning_started_at: baseline.learning_started_at && DateTime.to_iso8601(baseline.learning_started_at),
      learning_completed_at: baseline.learning_completed_at && DateTime.to_iso8601(baseline.learning_completed_at),
      learning_days: baseline.learning_days,
      total_events_processed: baseline.total_events_processed,
      events_per_day_avg: baseline.events_per_day_avg,
      normal_processes_count: length(baseline.normal_processes || []),
      expected_rules_count: length(baseline.expected_rules || []),
      last_updated_at: baseline.last_updated_at && DateTime.to_iso8601(baseline.last_updated_at)
    }
  end

  defp parse_int(nil, default), do: default
  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_float(nil, default), do: default
  defp parse_float(val, _default) when is_float(val), do: val
  defp parse_float(val, default) when is_binary(val) do
    case Float.parse(val) do
      {f, _} -> f
      :error -> default
    end
  end

  defp format_changeset_errors(changeset) when is_map(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
  defp format_changeset_errors(error), do: inspect(error)
end
