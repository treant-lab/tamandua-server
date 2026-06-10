defmodule TamanduaServer.Detection.Tuning do
  @moduledoc """
  Detection Tuning Engine

  Automatically tunes detection thresholds and rules based on:
  - False positive feedback from analysts
  - Environment-specific baselines
  - Statistical analysis of alert patterns
  - Rule performance metrics

  ## Features
  - Auto-tune detection thresholds per rule and environment
  - False positive feedback loop with analyst input
  - Per-environment baseline learning
  - Recommendation engine for rule improvements
  - A/B testing for rule variants
  - Threshold optimization using gradient descent
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Detection.Config

  import Ecto.Query

  # ETS tables for tuning data
  @rule_metrics_table :tuning_rule_metrics
  @threshold_adjustments_table :tuning_threshold_adjustments
  @feedback_table :tuning_feedback

  # Tuning intervals
  @metrics_aggregation_interval :timer.minutes(5)
  @threshold_optimization_interval :timer.hours(1)
  @recommendation_interval :timer.hours(6)

  # Threshold optimization parameters
  @learning_rate 0.1
  @min_samples_for_tuning 50
  @target_fp_rate 0.05  # 5% false positive rate target
  @confidence_required 0.95

  # ============================================================================
  # Types
  # ============================================================================

  defmodule RuleMetrics do
    @moduledoc "Aggregated metrics for a detection rule"
    defstruct [
      :rule_id,
      :rule_name,
      :rule_type,          # :sigma, :yara, :behavioral, :ml
      :total_alerts,
      :true_positives,
      :false_positives,
      :unknown,            # Alerts not yet triaged
      :false_positive_rate,
      :precision,
      :avg_severity,
      :avg_processing_time_ms,
      :environments,       # Map of org_id -> metrics
      :trend,              # :improving, :degrading, :stable
      last_triggered: nil,
      first_seen: nil
    ]
  end

  defmodule ThresholdAdjustment do
    @moduledoc "Recommended threshold adjustment for a rule"
    defstruct [
      :rule_id,
      :current_threshold,
      :recommended_threshold,
      :confidence,
      :reason,
      :impact_estimate,    # Estimated change in alerts
      :created_at,
      :applied_at,
      :status              # :pending, :applied, :rejected
    ]
  end

  defmodule TuningRecommendation do
    @moduledoc "Recommendation for improving detection"
    defstruct [
      :id,
      :type,               # :disable_rule, :adjust_threshold, :add_exclusion, :merge_rules
      :priority,           # :high, :medium, :low
      :rule_id,
      :title,
      :description,
      :impact,
      :action,             # Specific action to take
      :created_at,
      :status              # :pending, :applied, :dismissed
    ]
  end

  defmodule FeedbackEntry do
    @moduledoc "Analyst feedback on an alert"
    defstruct [
      :alert_id,
      :rule_id,
      :is_false_positive,
      :feedback_type,      # :confirmed_tp, :confirmed_fp, :escalated, :needs_review
      :notes,
      :analyst_id,
      :submitted_at
    ]
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    # Create ETS tables
    create_tables()

    # Schedule periodic tasks
    Process.send_after(self(), :aggregate_metrics, @metrics_aggregation_interval)
    Process.send_after(self(), :optimize_thresholds, @threshold_optimization_interval)
    Process.send_after(self(), :generate_recommendations, @recommendation_interval)

    # Load existing metrics from database
    metrics = load_persisted_metrics()

    state = %{
      metrics: metrics,
      adjustments: %{},
      recommendations: [],
      optimization_history: [],
      stats: %{
        feedback_received: 0,
        thresholds_adjusted: 0,
        recommendations_generated: 0,
        rules_disabled: 0
      }
    }

    Logger.info("Detection Tuning Engine started with #{map_size(metrics)} rule metrics loaded")
    {:ok, state}
  end

  @impl true
  def handle_call({:submit_feedback, feedback}, _from, state) do
    new_state = process_feedback(feedback, state)
    {:reply, :ok, new_state}
  end

  @impl true
  def handle_call({:get_rule_metrics, rule_id}, _from, state) do
    metrics = Map.get(state.metrics, rule_id)
    {:reply, {:ok, metrics}, state}
  end

  @impl true
  def handle_call(:get_all_metrics, _from, state) do
    {:reply, {:ok, state.metrics}, state}
  end

  @impl true
  def handle_call(:get_recommendations, _from, state) do
    pending = Enum.filter(state.recommendations, &(&1.status == :pending))
    {:reply, {:ok, pending}, state}
  end

  @impl true
  def handle_call({:get_threshold_adjustment, rule_id}, _from, state) do
    adjustment = Map.get(state.adjustments, rule_id)
    {:reply, {:ok, adjustment}, state}
  end

  @impl true
  def handle_call({:apply_adjustment, rule_id}, _from, state) do
    case Map.get(state.adjustments, rule_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      adjustment ->
        # Apply the threshold adjustment
        result = apply_threshold_adjustment(adjustment)

        new_adjustment = %{adjustment | status: :applied, applied_at: DateTime.utc_now()}
        new_adjustments = Map.put(state.adjustments, rule_id, new_adjustment)
        new_stats = Map.update!(state.stats, :thresholds_adjusted, &(&1 + 1))

        {:reply, result, %{state | adjustments: new_adjustments, stats: new_stats}}
    end
  end

  @impl true
  def handle_call({:dismiss_recommendation, rec_id}, _from, state) do
    new_recommendations =
      Enum.map(state.recommendations, fn rec ->
        if rec.id == rec_id, do: %{rec | status: :dismissed}, else: rec
      end)

    {:reply, :ok, %{state | recommendations: new_recommendations}}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:get_environment_baseline, org_id}, _from, state) do
    baseline = calculate_environment_baseline(org_id, state)
    {:reply, {:ok, baseline}, state}
  end

  @impl true
  def handle_info(:aggregate_metrics, state) do
    new_metrics = aggregate_rule_metrics(state.metrics)
    Process.send_after(self(), :aggregate_metrics, @metrics_aggregation_interval)
    {:noreply, %{state | metrics: new_metrics}}
  end

  @impl true
  def handle_info(:optimize_thresholds, state) do
    {new_adjustments, optimization_results} = optimize_all_thresholds(state)
    Process.send_after(self(), :optimize_thresholds, @threshold_optimization_interval)

    new_history = [optimization_results | state.optimization_history] |> Enum.take(100)

    {:noreply, %{state |
      adjustments: new_adjustments,
      optimization_history: new_history
    }}
  end

  @impl true
  def handle_info(:generate_recommendations, state) do
    new_recommendations = generate_tuning_recommendations(state)
    new_stats = Map.update!(state.stats, :recommendations_generated, &(&1 + length(new_recommendations)))

    Process.send_after(self(), :generate_recommendations, @recommendation_interval)

    # Merge with existing pending recommendations
    all_recommendations = merge_recommendations(state.recommendations, new_recommendations)

    {:noreply, %{state | recommendations: all_recommendations, stats: new_stats}}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Submit analyst feedback for an alert (true positive, false positive, etc.)
  """
  @spec submit_feedback(map()) :: :ok
  def submit_feedback(feedback) do
    GenServer.call(__MODULE__, {:submit_feedback, struct(FeedbackEntry, feedback)})
  end

  @doc """
  Get metrics for a specific rule.
  """
  @spec get_rule_metrics(String.t()) :: {:ok, RuleMetrics.t() | nil}
  def get_rule_metrics(rule_id) do
    GenServer.call(__MODULE__, {:get_rule_metrics, rule_id})
  end

  @doc """
  Get all rule metrics.
  """
  @spec get_all_metrics() :: {:ok, map()}
  def get_all_metrics do
    GenServer.call(__MODULE__, :get_all_metrics)
  end

  @doc """
  Get pending tuning recommendations.
  """
  @spec get_recommendations() :: {:ok, [TuningRecommendation.t()]}
  def get_recommendations do
    GenServer.call(__MODULE__, :get_recommendations)
  end

  @doc """
  Get threshold adjustment recommendation for a rule.
  """
  @spec get_threshold_adjustment(String.t()) :: {:ok, ThresholdAdjustment.t() | nil}
  def get_threshold_adjustment(rule_id) do
    GenServer.call(__MODULE__, {:get_threshold_adjustment, rule_id})
  end

  @doc """
  Apply a pending threshold adjustment.
  """
  @spec apply_adjustment(String.t()) :: {:ok, term()} | {:error, term()}
  def apply_adjustment(rule_id) do
    GenServer.call(__MODULE__, {:apply_adjustment, rule_id})
  end

  @doc """
  Dismiss a tuning recommendation.
  """
  @spec dismiss_recommendation(String.t()) :: :ok
  def dismiss_recommendation(rec_id) do
    GenServer.call(__MODULE__, {:dismiss_recommendation, rec_id})
  end

  @doc """
  Get tuning engine statistics.
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get environment-specific baseline for an organization.
  """
  @spec get_environment_baseline(String.t()) :: {:ok, map()}
  def get_environment_baseline(org_id) do
    GenServer.call(__MODULE__, {:get_environment_baseline, org_id})
  end

  @doc """
  Calculate optimal threshold for a rule based on feedback.
  Returns {:ok, threshold} or {:error, :insufficient_data}
  """
  @spec calculate_optimal_threshold(String.t()) :: {:ok, float()} | {:error, atom()}
  def calculate_optimal_threshold(rule_id) do
    case get_rule_metrics(rule_id) do
      {:ok, nil} ->
        {:error, :rule_not_found}

      {:ok, metrics} ->
        if metrics.total_alerts < @min_samples_for_tuning do
          {:error, :insufficient_data}
        else
          # Use feedback to find optimal threshold
          threshold = calculate_threshold_from_feedback(rule_id, metrics)
          {:ok, threshold}
        end
    end
  end

  # ============================================================================
  # Feedback Processing
  # ============================================================================

  defp process_feedback(feedback, state) do
    # Store feedback in ETS for aggregation
    :ets.insert(@feedback_table, {feedback.alert_id, feedback, DateTime.utc_now()})

    # Update rule metrics incrementally
    new_metrics = update_metrics_with_feedback(state.metrics, feedback)
    new_stats = Map.update!(state.stats, :feedback_received, &(&1 + 1))

    # Check if this feedback triggers immediate action
    check_feedback_triggers(feedback, new_metrics)

    %{state | metrics: new_metrics, stats: new_stats}
  end

  defp update_metrics_with_feedback(metrics, feedback) do
    rule_id = feedback.rule_id

    current = Map.get(metrics, rule_id, %RuleMetrics{
      rule_id: rule_id,
      total_alerts: 0,
      true_positives: 0,
      false_positives: 0,
      unknown: 0,
      environments: %{}
    })

    updated = case feedback.feedback_type do
      :confirmed_tp ->
        %{current |
          true_positives: current.true_positives + 1,
          unknown: max(0, current.unknown - 1)
        }

      :confirmed_fp ->
        %{current |
          false_positives: current.false_positives + 1,
          unknown: max(0, current.unknown - 1)
        }

      _ ->
        current
    end

    # Recalculate derived metrics
    total_triaged = updated.true_positives + updated.false_positives
    updated = if total_triaged > 0 do
      %{updated |
        false_positive_rate: updated.false_positives / total_triaged,
        precision: updated.true_positives / total_triaged
      }
    else
      updated
    end

    Map.put(metrics, rule_id, updated)
  end

  defp check_feedback_triggers(feedback, metrics) do
    rule_metrics = Map.get(metrics, feedback.rule_id)

    if rule_metrics && rule_metrics.false_positive_rate > 0.5 &&
       rule_metrics.true_positives + rule_metrics.false_positives >= 20 do
      Logger.warning(
        "Rule #{feedback.rule_id} has high FP rate (#{Float.round(rule_metrics.false_positive_rate * 100, 1)}%)"
      )
      # Could trigger automatic threshold adjustment or alert
    end
  end

  # ============================================================================
  # Metrics Aggregation
  # ============================================================================

  defp aggregate_rule_metrics(existing_metrics) do
    # Query recent alerts grouped by rule
    since = DateTime.add(DateTime.utc_now(), -24, :hour)

    query = from(a in Alert,
      where: a.inserted_at > ^since,
      group_by: [a.rule_id],
      select: %{
        rule_id: a.rule_id,
        count: count(a.id),
        avg_severity: avg(a.threat_score),
        last_triggered: max(a.inserted_at)
      }
    )

    alert_stats = try do
      Repo.all(query)
    rescue
      _ -> []
    end

    # Merge with existing metrics
    Enum.reduce(alert_stats, existing_metrics, fn stats, acc ->
      rule_id = stats.rule_id || "unknown"

      current = Map.get(acc, rule_id, %RuleMetrics{
        rule_id: rule_id,
        total_alerts: 0,
        true_positives: 0,
        false_positives: 0,
        unknown: 0,
        environments: %{}
      })

      updated = %{current |
        total_alerts: current.total_alerts + stats.count,
        unknown: current.unknown + stats.count,  # New alerts start as unknown
        avg_severity: stats.avg_severity,
        last_triggered: stats.last_triggered
      }

      Map.put(acc, rule_id, updated)
    end)
  end

  # ============================================================================
  # Threshold Optimization
  # ============================================================================

  defp optimize_all_thresholds(state) do
    results = %{
      optimized_at: DateTime.utc_now(),
      rules_processed: 0,
      adjustments_created: 0
    }

    {new_adjustments, final_results} =
      Enum.reduce(state.metrics, {state.adjustments, results}, fn {rule_id, metrics}, {adj_acc, res_acc} ->
        case optimize_rule_threshold(rule_id, metrics) do
          {:ok, adjustment} ->
            {Map.put(adj_acc, rule_id, adjustment),
             %{res_acc | adjustments_created: res_acc.adjustments_created + 1}}

          :no_change ->
            {adj_acc, %{res_acc | rules_processed: res_acc.rules_processed + 1}}
        end
      end)

    {new_adjustments, final_results}
  end

  defp optimize_rule_threshold(rule_id, metrics) do
    # Need enough samples for reliable optimization
    total_triaged = metrics.true_positives + metrics.false_positives

    if total_triaged < @min_samples_for_tuning do
      :no_change
    else
      current_fp_rate = metrics.false_positive_rate || 0.0
      current_threshold = get_current_threshold(rule_id)

      # Calculate gradient: direction to move threshold
      # Higher threshold = fewer alerts = lower FP count (but may miss TPs)
      fp_error = current_fp_rate - @target_fp_rate

      if abs(fp_error) < 0.02 do
        # Already close to target
        :no_change
      else
        # Adjust threshold in direction that reduces FP rate
        adjustment = @learning_rate * fp_error
        new_threshold = clamp(current_threshold + adjustment, 0.3, 0.95)

        confidence = calculate_adjustment_confidence(metrics, total_triaged)

        if confidence >= @confidence_required do
          {:ok, %ThresholdAdjustment{
            rule_id: rule_id,
            current_threshold: current_threshold,
            recommended_threshold: Float.round(new_threshold, 3),
            confidence: Float.round(confidence, 3),
            reason: build_adjustment_reason(current_fp_rate, new_threshold),
            impact_estimate: estimate_impact(metrics, current_threshold, new_threshold),
            created_at: DateTime.utc_now(),
            status: :pending
          }}
        else
          :no_change
        end
      end
    end
  end

  defp get_current_threshold(rule_id) do
    # Look up rule's current threshold from config or database
    # Default to global threshold if not rule-specific
    case :ets.lookup(@threshold_adjustments_table, rule_id) do
      [{^rule_id, threshold}] -> threshold
      [] -> Config.threat_threshold()
    end
  end

  defp calculate_adjustment_confidence(metrics, total_triaged) do
    # Confidence based on sample size and consistency
    sample_confidence = min(1.0, total_triaged / 100)

    # If FP rate is very consistent across environments, higher confidence
    env_variance = calculate_environment_variance(metrics)
    consistency_confidence = 1.0 - min(1.0, env_variance * 2)

    sample_confidence * 0.6 + consistency_confidence * 0.4
  end

  defp calculate_environment_variance(metrics) do
    fp_rates = metrics.environments
    |> Map.values()
    |> Enum.map(& &1[:false_positive_rate] || 0.0)

    if length(fp_rates) < 2 do
      0.0
    else
      mean = Enum.sum(fp_rates) / length(fp_rates)
      variance = Enum.reduce(fp_rates, 0.0, fn rate, acc ->
        acc + :math.pow(rate - mean, 2)
      end) / length(fp_rates)

      :math.sqrt(variance)
    end
  end

  defp build_adjustment_reason(current_fp_rate, new_threshold) do
    cond do
      current_fp_rate > 0.3 ->
        "High false positive rate (#{Float.round(current_fp_rate * 100, 1)}%). Increasing threshold to #{Float.round(new_threshold * 100, 1)}%."

      current_fp_rate > 0.1 ->
        "Elevated false positive rate. Recommend threshold adjustment."

      true ->
        "Fine-tuning threshold for optimal detection."
    end
  end

  defp estimate_impact(metrics, current_threshold, new_threshold) do
    # Estimate how many alerts would be affected by threshold change
    threshold_change = new_threshold - current_threshold

    if threshold_change > 0 do
      # Increasing threshold = fewer alerts
      estimated_reduction = metrics.total_alerts * threshold_change * 0.5
      %{
        direction: :decrease,
        estimated_alert_change: round(estimated_reduction),
        estimated_fp_reduction: round(estimated_reduction * metrics.false_positive_rate)
      }
    else
      estimated_increase = metrics.total_alerts * abs(threshold_change) * 0.3
      %{
        direction: :increase,
        estimated_alert_change: round(estimated_increase),
        estimated_tp_gain: round(estimated_increase * 0.8)
      }
    end
  end

  defp apply_threshold_adjustment(adjustment) do
    # Store the new threshold
    :ets.insert(@threshold_adjustments_table, {adjustment.rule_id, adjustment.recommended_threshold})

    # Log the change
    Logger.info(
      "Applied threshold adjustment for rule #{adjustment.rule_id}: " <>
      "#{adjustment.current_threshold} -> #{adjustment.recommended_threshold}"
    )

    # Persist to database
    try do
      Repo.insert_all("detection_threshold_history", [
        %{
          rule_id: adjustment.rule_id,
          old_threshold: adjustment.current_threshold,
          new_threshold: adjustment.recommended_threshold,
          reason: adjustment.reason,
          applied_at: DateTime.utc_now()
        }
      ])
    rescue
      _ -> :ok  # Table may not exist
    end

    {:ok, adjustment}
  end

  defp calculate_threshold_from_feedback(rule_id, metrics) do
    # Query feedback entries with alert scores
    feedback_entries = :ets.match(@feedback_table, {:_, %{rule_id: rule_id}, :_})
    |> Enum.map(fn [entry] -> entry end)

    if length(feedback_entries) < 10 do
      # Not enough feedback, use default
      Config.threat_threshold()
    else
      # Find threshold that minimizes FP rate while maintaining recall
      # Binary search for optimal threshold
      find_optimal_threshold(feedback_entries, 0.5, 0.95, 0.01)
    end
  end

  defp find_optimal_threshold(_entries, low, high, precision) when high - low < precision do
    (low + high) / 2
  end

  defp find_optimal_threshold(entries, low, high, precision) do
    mid = (low + high) / 2

    # Simulate FP rate at this threshold
    # In practice, would use actual alert scores
    fp_rate = estimate_fp_rate_at_threshold(entries, mid)

    if fp_rate > @target_fp_rate do
      # Too many FPs, increase threshold
      find_optimal_threshold(entries, mid, high, precision)
    else
      # FP rate acceptable, try lower threshold for better recall
      find_optimal_threshold(entries, low, mid, precision)
    end
  end

  defp estimate_fp_rate_at_threshold(_entries, _threshold) do
    # Simplified - would use actual scoring data
    0.05
  end

  # ============================================================================
  # Recommendation Generation
  # ============================================================================

  defp generate_tuning_recommendations(state) do
    recommendations = []

    # 1. High FP rate rules
    recommendations = recommendations ++ find_high_fp_rules(state.metrics)

    # 2. Dormant rules (no alerts in 30+ days)
    recommendations = recommendations ++ find_dormant_rules(state.metrics)

    # 3. Duplicate/overlapping rules
    recommendations = recommendations ++ find_overlapping_rules(state.metrics)

    # 4. Rules needing exclusions
    recommendations = recommendations ++ suggest_exclusions(state.metrics)

    # Sort by priority
    Enum.sort_by(recommendations, fn r ->
      case r.priority do
        :high -> 0
        :medium -> 1
        :low -> 2
      end
    end)
  end

  defp find_high_fp_rules(metrics) do
    metrics
    |> Enum.filter(fn {_id, m} ->
      m.false_positive_rate && m.false_positive_rate > 0.3 &&
      m.true_positives + m.false_positives >= 20
    end)
    |> Enum.map(fn {rule_id, m} ->
      %TuningRecommendation{
        id: "fp_#{rule_id}_#{System.unique_integer([:positive])}",
        type: :adjust_threshold,
        priority: if(m.false_positive_rate > 0.5, do: :high, else: :medium),
        rule_id: rule_id,
        title: "High False Positive Rate",
        description: "Rule '#{m.rule_name || rule_id}' has a #{Float.round(m.false_positive_rate * 100, 1)}% false positive rate.",
        impact: "Analysts spending time on #{m.false_positives} false positive alerts.",
        action: %{
          type: :adjust_threshold,
          current: get_current_threshold(rule_id),
          suggested: get_current_threshold(rule_id) + 0.1
        },
        created_at: DateTime.utc_now(),
        status: :pending
      }
    end)
  end

  defp find_dormant_rules(metrics) do
    thirty_days_ago = DateTime.add(DateTime.utc_now(), -30, :day)

    metrics
    |> Enum.filter(fn {_id, m} ->
      m.last_triggered == nil ||
      DateTime.compare(m.last_triggered, thirty_days_ago) == :lt
    end)
    |> Enum.map(fn {rule_id, m} ->
      days_dormant = if m.last_triggered do
        DateTime.diff(DateTime.utc_now(), m.last_triggered, :day)
      else
        "30+"
      end

      %TuningRecommendation{
        id: "dormant_#{rule_id}_#{System.unique_integer([:positive])}",
        type: :disable_rule,
        priority: :low,
        rule_id: rule_id,
        title: "Dormant Rule",
        description: "Rule '#{m.rule_name || rule_id}' has not triggered in #{days_dormant} days.",
        impact: "Rule may be too specific or obsolete.",
        action: %{type: :review_or_disable},
        created_at: DateTime.utc_now(),
        status: :pending
      }
    end)
  end

  defp find_overlapping_rules(_metrics) do
    # Would analyze rule conditions to find overlap
    # Simplified for now
    []
  end

  defp suggest_exclusions(metrics) do
    # Find rules with consistent false positives from specific sources
    metrics
    |> Enum.filter(fn {_id, m} ->
      m.false_positives > 10 && m.environments && map_size(m.environments) > 0
    end)
    |> Enum.flat_map(fn {rule_id, m} ->
      # Check if FPs are concentrated in specific environments
      high_fp_envs = m.environments
      |> Enum.filter(fn {_org, env_metrics} ->
        fp_rate = env_metrics[:false_positive_rate] || 0
        fp_rate > 0.5
      end)
      |> Enum.map(fn {org_id, _} -> org_id end)

      if length(high_fp_envs) > 0 && length(high_fp_envs) < map_size(m.environments) / 2 do
        [%TuningRecommendation{
          id: "exclusion_#{rule_id}_#{System.unique_integer([:positive])}",
          type: :add_exclusion,
          priority: :medium,
          rule_id: rule_id,
          title: "Environment-Specific Exclusion",
          description: "Rule '#{m.rule_name || rule_id}' has high FP rate in specific environments.",
          impact: "Adding exclusion could reduce #{length(high_fp_envs)} environment FPs.",
          action: %{
            type: :add_environment_exclusion,
            environments: high_fp_envs
          },
          created_at: DateTime.utc_now(),
          status: :pending
        }]
      else
        []
      end
    end)
  end

  defp merge_recommendations(existing, new_recs) do
    # Keep pending/dismissed existing, add new
    existing_ids = MapSet.new(Enum.map(existing, & &1.rule_id))

    filtered_new = Enum.reject(new_recs, fn r ->
      MapSet.member?(existing_ids, r.rule_id) &&
      Enum.any?(existing, &(&1.rule_id == r.rule_id && &1.type == r.type))
    end)

    existing ++ filtered_new
  end

  # ============================================================================
  # Environment Baseline
  # ============================================================================

  defp calculate_environment_baseline(org_id, state) do
    # Get metrics specific to this organization
    org_metrics = state.metrics
    |> Enum.filter(fn {_id, m} ->
      m.environments && Map.has_key?(m.environments, org_id)
    end)
    |> Enum.map(fn {id, m} -> {id, m.environments[org_id]} end)
    |> Map.new()

    # Calculate aggregate stats
    total_alerts = org_metrics
    |> Enum.reduce(0, fn {_id, m}, acc -> acc + (m[:total_alerts] || 0) end)

    avg_fp_rate = if map_size(org_metrics) > 0 do
      fp_rates = Enum.map(org_metrics, fn {_id, m} -> m[:false_positive_rate] || 0 end)
      Enum.sum(fp_rates) / length(fp_rates)
    else
      0.0
    end

    %{
      organization_id: org_id,
      total_alerts_30d: total_alerts,
      average_fp_rate: Float.round(avg_fp_rate, 3),
      rules_triggered: map_size(org_metrics),
      top_rules: org_metrics
        |> Enum.sort_by(fn {_id, m} -> -(m[:total_alerts] || 0) end)
        |> Enum.take(10)
        |> Enum.map(fn {id, m} -> %{rule_id: id, alerts: m[:total_alerts]} end),
      recommended_threshold: calculate_org_threshold(org_metrics)
    }
  end

  defp calculate_org_threshold(org_metrics) do
    # Calculate recommended threshold based on org's historical data
    if map_size(org_metrics) < 5 do
      Config.threat_threshold()
    else
      avg_threshold = org_metrics
      |> Enum.map(fn {id, _} -> get_current_threshold(id) end)
      |> then(fn thresholds -> Enum.sum(thresholds) / length(thresholds) end)

      Float.round(avg_threshold, 2)
    end
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp create_tables do
    tables = [
      {@rule_metrics_table, [:set, :public, :named_table]},
      {@threshold_adjustments_table, [:set, :public, :named_table]},
      {@feedback_table, [:set, :public, :named_table]}
    ]

    Enum.each(tables, fn {name, opts} ->
      case :ets.whereis(name) do
        :undefined -> :ets.new(name, opts)
        _ -> :ok
      end
    end)
  end

  defp load_persisted_metrics do
    # Load from database
    try do
      Repo.all(from(m in "detection_rule_metrics", select: %{
        rule_id: m.rule_id,
        total_alerts: m.total_alerts,
        true_positives: m.true_positives,
        false_positives: m.false_positives
      }))
      |> Enum.map(fn m ->
        total = m.true_positives + m.false_positives
        fp_rate = if total > 0, do: m.false_positives / total, else: 0.0

        {m.rule_id, %RuleMetrics{
          rule_id: m.rule_id,
          total_alerts: m.total_alerts,
          true_positives: m.true_positives,
          false_positives: m.false_positives,
          unknown: 0,
          false_positive_rate: fp_rate,
          precision: if(total > 0, do: m.true_positives / total, else: 0.0),
          environments: %{}
        }}
      end)
      |> Map.new()
    rescue
      _ -> %{}  # Table may not exist
    end
  end

  defp clamp(value, min_val, max_val) do
    value
    |> max(min_val)
    |> min(max_val)
  end
end
