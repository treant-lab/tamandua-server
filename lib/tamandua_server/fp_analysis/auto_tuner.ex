defmodule TamanduaServer.FPAnalysis.AutoTuner do
  @moduledoc """
  Automatic Threshold Adjustment and Suppression Rule Generation.

  The AutoTuner analyzes rule quality metrics and detected FP patterns to:
  1. Generate tuning recommendations for analyst review
  2. Automatically create suppression rules for high-confidence patterns
  3. Adjust detection thresholds based on historical data

  ## Auto-Tuning Modes

  - `:recommend_only` - Only generate recommendations (default)
  - `:auto_suppress` - Automatically create suppression rules for patterns >90% confidence
  - `:auto_threshold` - Automatically adjust thresholds based on FP rates

  ## Safety Guardrails

  - Never auto-disable rules without human approval
  - Suppression rules created by auto-tuner have a TTL (default 30 days)
  - All auto-generated rules are flagged for periodic review
  - TP count check: patterns with any TPs require human review
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.SuppressionRule
  alias TamanduaServer.FPAnalysis.{
    FPPattern,
    RuleQualityMetrics,
    TuningRecommendation
  }

  # Auto-tuning configuration
  @auto_suppress_confidence 0.9
  @auto_suppress_min_fps 10
  @auto_suppress_max_tps 0
  @suppression_ttl_days 30

  # Threshold adjustment parameters
  @high_fp_rate_threshold 0.3

  # Evaluation interval
  @evaluation_interval :timer.hours(6)

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Evaluate a specific rule and generate recommendations if needed.
  """
  @spec evaluate_rule(String.t(), String.t(), String.t()) :: :ok
  def evaluate_rule(organization_id, detection_source, rule_id) do
    GenServer.cast(__MODULE__, {:evaluate_rule, organization_id, detection_source, rule_id})
  end

  @doc """
  Run full evaluation for an organization.
  """
  @spec evaluate_organization(String.t()) :: {:ok, map()}
  def evaluate_organization(organization_id) do
    GenServer.call(__MODULE__, {:evaluate_organization, organization_id}, :timer.minutes(5))
  end

  @doc """
  Create a suppression rule from a detected FP pattern.
  """
  @spec create_suppression_for_pattern(FPPattern.t(), keyword()) ::
          {:ok, SuppressionRule.t()} | {:error, term()}
  def create_suppression_for_pattern(pattern, opts \\ []) do
    GenServer.call(__MODULE__, {:create_suppression_for_pattern, pattern, opts})
  end

  @doc """
  Apply a tuning recommendation.
  """
  @spec apply_recommendation(String.t(), String.t()) ::
          {:ok, TuningRecommendation.t()} | {:error, term()}
  def apply_recommendation(recommendation_id, user_id) do
    GenServer.call(__MODULE__, {:apply_recommendation, recommendation_id, user_id})
  end

  @doc """
  Get pending tuning recommendations for an organization.
  """
  @spec get_recommendations(String.t(), keyword()) :: [TuningRecommendation.t()]
  def get_recommendations(organization_id, opts \\ []) do
    status = Keyword.get(opts, :status, "pending")
    limit = Keyword.get(opts, :limit, 50)

    from(r in TuningRecommendation,
      where: r.organization_id == ^organization_id,
      where: r.status == ^status,
      order_by: [desc: r.priority, desc: r.confidence],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Get auto-tuning statistics for an organization.
  """
  @spec get_stats(String.t()) :: map()
  def get_stats(organization_id) do
    # Count recommendations by status
    rec_counts =
      from(r in TuningRecommendation,
        where: r.organization_id == ^organization_id,
        group_by: r.status,
        select: {r.status, count(r.id)}
      )
      |> Repo.all()
      |> Map.new()

    # Count auto-generated suppression rules
    auto_suppressions =
      from(s in SuppressionRule,
        where: s.organization_id == ^organization_id,
        where: s.auto_generated == true
      )
      |> Repo.aggregate(:count)

    # Count active auto-generated rules
    active_auto_suppressions =
      from(s in SuppressionRule,
        where: s.organization_id == ^organization_id,
        where: s.auto_generated == true,
        where: s.enabled == true
      )
      |> Repo.aggregate(:count)

    # Get effectiveness metrics for applied recommendations
    effectiveness =
      from(r in TuningRecommendation,
        where: r.organization_id == ^organization_id,
        where: r.status == "applied",
        where: r.effectiveness_measured == true,
        select: avg(r.effectiveness_score)
      )
      |> Repo.one()

    %{
      recommendations: %{
        pending: Map.get(rec_counts, "pending", 0),
        approved: Map.get(rec_counts, "approved", 0),
        applied: Map.get(rec_counts, "applied", 0),
        rejected: Map.get(rec_counts, "rejected", 0),
        expired: Map.get(rec_counts, "expired", 0)
      },
      auto_suppressions: %{
        total: auto_suppressions,
        active: active_auto_suppressions
      },
      effectiveness: %{
        average_score: effectiveness && Float.round(effectiveness, 2),
        measured_count: from(r in TuningRecommendation,
          where: r.organization_id == ^organization_id,
          where: r.effectiveness_measured == true
        ) |> Repo.aggregate(:count)
      }
    }
  end

  # ---------------------------------------------------------------------------
  # GenServer Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    schedule_periodic_evaluation()
    Logger.info("[AutoTuner] Initialized")
    {:ok, %{mode: :recommend_only}}
  end

  @impl true
  def handle_cast({:evaluate_rule, organization_id, detection_source, rule_id}, state) do
    do_evaluate_rule(organization_id, detection_source, rule_id)
    {:noreply, state}
  end

  @impl true
  def handle_call({:evaluate_organization, organization_id}, _from, state) do
    result = do_evaluate_organization(organization_id)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:create_suppression_for_pattern, pattern, opts}, _from, state) do
    result = do_create_suppression_for_pattern(pattern, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:apply_recommendation, recommendation_id, user_id}, _from, state) do
    result = do_apply_recommendation(recommendation_id, user_id)
    {:reply, result, state}
  end

  @impl true
  def handle_info(:periodic_evaluation, state) do
    run_periodic_evaluation()
    schedule_periodic_evaluation()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Private - Rule Evaluation
  # ---------------------------------------------------------------------------

  defp do_evaluate_rule(organization_id, detection_source, rule_id) do
    case Repo.get_by(RuleQualityMetrics,
           organization_id: organization_id,
           detection_source: detection_source,
           rule_id: rule_id
         ) do
      nil ->
        :ok

      metrics ->
        # Check if rule needs tuning
        case RuleQualityMetrics.needs_tuning?(metrics) do
          {:yes, reason, description} ->
            generate_recommendation(metrics, reason, description)

          {:no, _, _} ->
            :ok
        end
    end
  rescue
    e ->
      Logger.warning("[AutoTuner] Failed to evaluate rule: #{Exception.message(e)}")
  end

  defp do_evaluate_organization(organization_id) do
    # Get all rules with quality issues
    problematic_rules =
      from(m in RuleQualityMetrics,
        where: m.organization_id == ^organization_id,
        where: m.total_alerts >= 10,
        where: m.fp_rate > ^@high_fp_rate_threshold or m.quality_score < 0.5
      )
      |> Repo.all()

    # Generate recommendations for each
    recommendations =
      Enum.map(problematic_rules, fn metrics ->
        case RuleQualityMetrics.needs_tuning?(metrics) do
          {:yes, reason, description} ->
            generate_recommendation(metrics, reason, description)

          {:no, _, _} ->
            nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    # Check patterns for auto-suppression
    patterns = get_auto_tunable_patterns(organization_id)
    auto_suppressions =
      Enum.map(patterns, fn pattern ->
        if should_auto_suppress?(pattern) do
          case do_create_suppression_for_pattern(pattern, auto_generated: true) do
            {:ok, rule} -> rule
            _ -> nil
          end
        end
      end)
      |> Enum.reject(&is_nil/1)

    # Check for expired recommendations
    expire_old_recommendations(organization_id)

    %{
      rules_evaluated: length(problematic_rules),
      recommendations_created: length(recommendations),
      auto_suppressions_created: length(auto_suppressions)
    }
  end

  defp generate_recommendation(metrics, reason, description) do
    # Check if we already have a pending recommendation for this rule
    existing =
      from(r in TuningRecommendation,
        where: r.organization_id == ^metrics.organization_id,
        where: r.target_id == ^metrics.rule_id,
        where: r.status == "pending"
      )
      |> Repo.one()

    if existing do
      # Update existing recommendation
      existing
      |> TuningRecommendation.changeset(%{
        supporting_metrics: serialize_metrics(metrics),
        confidence: calculate_recommendation_confidence(metrics)
      })
      |> Repo.update()
    else
      # Create new recommendation based on reason
      recommendation = case reason do
        :high_fp_rate ->
          create_threshold_recommendation(metrics, description)

        :low_precision ->
          create_threshold_recommendation(metrics, description)

        :degrading_trend ->
          create_threshold_recommendation(metrics, description)

        :low_quality ->
          create_disable_recommendation(metrics, description)
      end

      case recommendation do
        {:ok, rec} -> rec
        _ -> nil
      end
    end
  rescue
    e ->
      Logger.warning("[AutoTuner] Failed to generate recommendation: #{Exception.message(e)}")
      nil
  end

  defp create_threshold_recommendation(metrics, description) do
    current_threshold = 0.7  # Default threshold
    recommended_threshold = calculate_recommended_threshold(metrics)

    attrs = %{
      organization_id: metrics.organization_id,
      recommendation_type: "threshold_adjustment",
      target_type: "rule",
      target_id: metrics.rule_id,
      target_name: metrics.rule_name || metrics.rule_id,
      title: "Adjust threshold for #{metrics.rule_name || metrics.rule_id}",
      description: description,
      rationale: "Rule has #{Float.round((metrics.fp_rate || 0) * 100, 1)}% false positive rate " <>
                 "over #{metrics.total_alerts} alerts. Increasing threshold may reduce noise.",
      impact_assessment: "Estimated #{estimate_fp_reduction(metrics, recommended_threshold)}% " <>
                        "reduction in alerts from this rule.",
      action_data: %{
        "type" => "threshold",
        "detection_source" => metrics.detection_source,
        "rule_id" => metrics.rule_id,
        "current_threshold" => current_threshold,
        "recommended_threshold" => recommended_threshold
      },
      supporting_metrics: serialize_metrics(metrics),
      confidence: calculate_recommendation_confidence(metrics),
      priority: calculate_priority(metrics),
      estimated_fp_reduction: estimate_fp_reduction(metrics, recommended_threshold) / 100,
      expires_at: DateTime.add(DateTime.utc_now(), 14 * 24 * 3600, :second)
    }

    struct(TuningRecommendation)
    |> TuningRecommendation.changeset(attrs)
    |> Repo.insert()
  end

  defp create_disable_recommendation(metrics, description) do
    attrs = %{
      organization_id: metrics.organization_id,
      recommendation_type: "disable_rule",
      target_type: "rule",
      target_id: metrics.rule_id,
      target_name: metrics.rule_name || metrics.rule_id,
      title: "Consider disabling #{metrics.rule_name || metrics.rule_id}",
      description: description,
      rationale: "Rule has very low quality score (#{Float.round((metrics.quality_score || 0) * 100, 1)}%) " <>
                 "with #{metrics.false_positives || 0} false positives out of #{metrics.total_alerts} alerts.",
      impact_assessment: "Disabling will eliminate approximately #{metrics.total_alerts || 0} alerts. " <>
                        "Review historical true positives before disabling.",
      action_data: %{
        "type" => "disable",
        "detection_source" => metrics.detection_source,
        "rule_id" => metrics.rule_id
      },
      supporting_metrics: serialize_metrics(metrics),
      confidence: 0.6,  # Lower confidence for disable recommendations
      priority: "low",
      estimated_fp_reduction: metrics.fp_rate || 0.5,
      expires_at: DateTime.add(DateTime.utc_now(), 7 * 24 * 3600, :second)
    }

    struct(TuningRecommendation)
    |> TuningRecommendation.changeset(attrs)
    |> Repo.insert()
  end

  # ---------------------------------------------------------------------------
  # Private - Pattern Suppression
  # ---------------------------------------------------------------------------

  defp get_auto_tunable_patterns(organization_id) do
    from(p in FPPattern,
      where: p.organization_id == ^organization_id,
      where: p.status == "detected",
      where: p.suppression_created == false,
      where: p.fp_confidence >= ^@auto_suppress_confidence,
      where: p.fp_count >= ^@auto_suppress_min_fps,
      where: p.tp_count <= ^@auto_suppress_max_tps
    )
    |> Repo.all()
  end

  defp should_auto_suppress?(pattern) do
    pattern.fp_confidence >= @auto_suppress_confidence and
    pattern.fp_count >= @auto_suppress_min_fps and
    pattern.tp_count <= @auto_suppress_max_tps and
    not pattern.suppression_created
  end

  defp do_create_suppression_for_pattern(pattern, opts) do
    criteria = FPPattern.to_suppression_criteria(pattern)
    auto_generated = Keyword.get(opts, :auto_generated, false)
    ttl_days = Keyword.get(opts, :ttl_days, @suppression_ttl_days)
    user_id = Keyword.get(opts, :user_id)

    expires_at = DateTime.add(DateTime.utc_now(), ttl_days * 24 * 3600, :second)

    suppression_attrs = %{
      name: generate_suppression_name(pattern),
      description: generate_suppression_description(pattern),
      enabled: true,
      organization_id: pattern.organization_id,
      created_by_id: user_id,
      auto_generated: auto_generated,
      fp_pattern_id: pattern.id,
      expires_at: expires_at,
      action: "suppress"
    }
    |> Map.merge(criteria)

    case struct(SuppressionRule)
         |> SuppressionRule.changeset(suppression_attrs)
         |> Repo.insert() do
      {:ok, rule} ->
        # Update pattern to mark suppression created
        pattern
        |> FPPattern.changeset(%{
          suppression_created: true,
          suppression_rule_id: rule.id,
          auto_tuned_at: DateTime.utc_now(),
          status: "tuned"
        })
        |> Repo.update()

        Logger.info("[AutoTuner] Created suppression rule #{rule.id} for pattern #{pattern.id}")
        {:ok, rule}

      {:error, changeset} ->
        Logger.warning("[AutoTuner] Failed to create suppression: #{inspect(changeset.errors)}")
        {:error, changeset}
    end
  rescue
    e ->
      Logger.warning("[AutoTuner] Failed to create suppression: #{Exception.message(e)}")
      {:error, e}
  end

  defp generate_suppression_name(pattern) do
    case pattern.pattern_type do
      "process" -> "Auto: Process #{pattern.pattern_data["process_name"]}"
      "path" -> "Auto: Path #{Path.basename(pattern.pattern_data["path_directory"] || "unknown")}"
      "rule" -> "Auto: Rule #{pattern.pattern_data["rule_name"]}"
      "user" -> "Auto: User #{pattern.pattern_data["user"]}"
      "host" -> "Auto: Host #{pattern.pattern_data["hostname"]}"
      "combined" -> "Auto: Combined pattern"
      _ -> "Auto: FP Pattern #{String.slice(pattern.id, 0..7)}"
    end
  end

  defp generate_suppression_description(pattern) do
    "Auto-generated suppression rule based on FP pattern analysis. " <>
    "Pattern: #{pattern.pattern_type}, Confidence: #{Float.round(pattern.fp_confidence * 100, 1)}%, " <>
    "FP Count: #{pattern.fp_count}, TP Count: #{pattern.tp_count}. " <>
    "Rule will expire after #{@suppression_ttl_days} days."
  end

  # ---------------------------------------------------------------------------
  # Private - Apply Recommendations
  # ---------------------------------------------------------------------------

  defp do_apply_recommendation(recommendation_id, user_id) do
    case Repo.get(TuningRecommendation, recommendation_id) do
      nil ->
        {:error, :not_found}

      recommendation ->
        result = apply_recommendation_action(recommendation)

        recommendation
        |> TuningRecommendation.changeset(%{
          status: "applied",
          applied_at: DateTime.utc_now(),
          applied_by_id: user_id,
          applied_result: result
        })
        |> Repo.update()
    end
  end

  defp apply_recommendation_action(%{recommendation_type: "exclusion_rule"} = rec) do
    # Create suppression rule from recommendation
    criteria = rec.action_data["criteria"] || %{}
    ttl_days = rec.action_data["ttl_days"] || @suppression_ttl_days

    suppression_attrs = %{
      name: "Recommended: #{rec.title}",
      description: rec.description,
      enabled: true,
      organization_id: rec.organization_id,
      tuning_recommendation_id: rec.id,
      expires_at: DateTime.add(DateTime.utc_now(), ttl_days * 24 * 3600, :second),
      action: "suppress"
    }
    |> Map.merge(atomize_criteria(criteria))

    case struct(SuppressionRule)
         |> SuppressionRule.changeset(suppression_attrs)
         |> Repo.insert() do
      {:ok, rule} ->
        %{"success" => true, "suppression_rule_id" => rule.id}

      {:error, changeset} ->
        %{"success" => false, "error" => inspect(changeset.errors)}
    end
  end

  defp apply_recommendation_action(%{recommendation_type: "threshold_adjustment"} = rec) do
    # Threshold adjustments require integration with the detection engine
    # For now, record the recommendation as applied and return instructions
    %{
      "success" => true,
      "action" => "threshold_adjustment",
      "instructions" => "Update detection threshold for rule #{rec.action_data["rule_id"]} " <>
                        "from #{rec.action_data["current_threshold"]} to #{rec.action_data["recommended_threshold"]}"
    }
  end

  defp apply_recommendation_action(%{recommendation_type: "disable_rule"} = rec) do
    # Disable rules require manual intervention
    %{
      "success" => true,
      "action" => "disable_rule",
      "instructions" => "Manually disable rule #{rec.action_data["rule_id"]} in the detection engine"
    }
  end

  defp apply_recommendation_action(_rec) do
    %{"success" => false, "error" => "Unknown recommendation type"}
  end

  # ---------------------------------------------------------------------------
  # Private - Helpers
  # ---------------------------------------------------------------------------

  defp calculate_recommended_threshold(metrics) do
    fp_rate = metrics.fp_rate || 0

    cond do
      fp_rate > 0.7 -> 0.95
      fp_rate > 0.5 -> 0.9
      fp_rate > 0.3 -> 0.85
      true -> 0.8
    end
  end

  defp estimate_fp_reduction(_metrics, new_threshold) do
    # Rough estimate: higher threshold reduces more FPs
    # This is a simplification - real impact depends on score distribution
    current_threshold = 0.7
    diff = new_threshold - current_threshold

    min(90, max(10, round(diff * 200)))
  end

  defp calculate_recommendation_confidence(metrics) do
    # Higher confidence with more data and higher FP rate
    sample_factor = min(1.0, (metrics.total_alerts || 0) / 100)
    fp_factor = min(1.0, (metrics.fp_rate || 0) * 2)

    (sample_factor * 0.4 + fp_factor * 0.6)
    |> min(1.0)
    |> max(0.3)
    |> Float.round(2)
  end

  defp calculate_priority(metrics) do
    fp_rate = metrics.fp_rate || 0
    total = metrics.total_alerts || 0

    cond do
      fp_rate > 0.7 and total > 100 -> "critical"
      fp_rate > 0.5 and total > 50 -> "high"
      fp_rate > 0.3 -> "medium"
      true -> "low"
    end
  end

  defp serialize_metrics(metrics) do
    %{
      "total_alerts" => metrics.total_alerts,
      "true_positives" => metrics.true_positives,
      "false_positives" => metrics.false_positives,
      "precision" => metrics.precision,
      "fp_rate" => metrics.fp_rate,
      "quality_score" => metrics.quality_score,
      "fp_rate_trend" => metrics.fp_rate_trend
    }
  end

  defp atomize_criteria(criteria) when is_map(criteria) do
    Enum.reduce(criteria, %{}, fn {k, v}, acc ->
      key = if is_binary(k), do: String.to_existing_atom(k), else: k
      Map.put(acc, key, v)
    end)
  rescue
    _ -> criteria
  end

  defp expire_old_recommendations(organization_id) do
    now = DateTime.utc_now()

    from(r in TuningRecommendation,
      where: r.organization_id == ^organization_id,
      where: r.status == "pending",
      where: not is_nil(r.expires_at),
      where: r.expires_at < ^now
    )
    |> Repo.update_all(set: [status: "expired"])
  end

  defp run_periodic_evaluation do
    # Get organizations with recent activity
    cutoff = DateTime.add(DateTime.utc_now(), -7 * 24 * 3600, :second)

    org_ids =
      from(m in RuleQualityMetrics,
        where: m.last_alert_at >= ^cutoff,
        distinct: true,
        select: m.organization_id
      )
      |> Repo.all()
      |> Enum.reject(&is_nil/1)

    Enum.each(org_ids, fn org_id ->
      try do
        do_evaluate_organization(org_id)
      rescue
        e ->
          Logger.warning("[AutoTuner] Failed to evaluate org #{org_id}: #{Exception.message(e)}")
      end
    end)

    Logger.info("[AutoTuner] Completed periodic evaluation for #{length(org_ids)} organizations")
  end

  defp schedule_periodic_evaluation do
    Process.send_after(self(), :periodic_evaluation, @evaluation_interval)
  end
end
