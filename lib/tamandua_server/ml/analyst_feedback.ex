defmodule TamanduaServer.ML.AnalystFeedback do
  @moduledoc """
  Feedback loop from analyst actions to improve ML model performance.

  Collects and processes analyst verdicts on alerts, severity changes,
  storyline resolutions, and autonomous response approvals/rejections.
  Aggregates feedback per model version, calculates ongoing FP/TP rates,
  generates training signals for the retraining dataset, and triggers
  retraining when thresholds are crossed.

  ## Feedback Sources

  1. Alert verdict (true_positive / false_positive)
  2. Alert severity change (analyst override)
  3. Storyline resolution (confirmed / dismissed)
  4. Autonomous response approval / rejection

  ## Retraining Triggers

  - FPR exceeds `@fpr_retrain_threshold` (default 2%)
  - Accumulated labeled samples exceeds `@sample_retrain_threshold` (default 500)
  - Weekly scheduled check
  - Manual trigger via API

  ## ETS Tables

  - `:ml_analyst_feedback`        - {feedback_id, feedback_record}
  - `:ml_retraining_dataset`      - {{model_type, sample_hash}, labeled_sample}
  - `:ml_feedback_aggregates`     - {{model_type, version}, aggregate_stats}
  """

  use GenServer
  require Logger

  alias TamanduaServer.ML.ModelManager

  # ── Configuration ────────────────────────────────────────────────────

  @fpr_retrain_threshold 0.02
  @sample_retrain_threshold 500
  @weekly_check_interval_ms :timer.hours(168)
  @aggregate_check_interval_ms :timer.minutes(15)

  @feedback_table :ml_analyst_feedback
  @dataset_table :ml_retraining_dataset
  @aggregates_table :ml_feedback_aggregates

  # ── State ─────────────────────────────────────────────────────────────

  defstruct [
    :stats,
    :last_retrain_check,
    :retrain_in_progress
  ]

  # ── Client API ───────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record an analyst verdict for a specific alert.

  `verdict` should be one of:
  - :true_positive
  - :false_positive
  - :true_negative
  - :false_negative
  - :severity_changed
  - :storyline_confirmed
  - :storyline_dismissed
  - :response_approved
  - :response_rejected
  """
  @spec record_verdict(String.t(), atom(), String.t(), map()) :: :ok
  def record_verdict(alert_id, verdict, analyst_id, opts \\ %{}) do
    GenServer.cast(__MODULE__, {:record_verdict, alert_id, verdict, analyst_id, opts})
  end

  @doc """
  Get feedback statistics for a model type and version.
  Returns aggregated counts and rates.
  """
  @spec get_feedback_stats(String.t(), String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_feedback_stats(model_type, version) do
    key = {model_type, version}
    case :ets.lookup(@aggregates_table, key) do
      [{^key, stats}] -> {:ok, stats}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Get all feedback stats across all model types and versions.
  """
  @spec get_all_feedback_stats() :: [map()]
  def get_all_feedback_stats do
    @aggregates_table
    |> :ets.tab2list()
    |> Enum.map(fn {{model_type, version}, stats} ->
      Map.merge(stats, %{model_type: model_type, version: version})
    end)
  end

  @doc """
  Get the retraining dataset for a model type.
  Returns a list of labeled samples suitable for retraining.
  """
  @spec get_retraining_dataset(String.t()) :: [map()]
  def get_retraining_dataset(model_type) do
    @dataset_table
    |> :ets.tab2list()
    |> Enum.filter(fn {{type, _hash}, _sample} -> type == model_type end)
    |> Enum.map(fn {_key, sample} -> sample end)
    |> Enum.sort_by(& &1.recorded_at, {:desc, DateTime})
  end

  @doc """
  Check whether a model type should be retrained. Returns `{true, reason}` or `{false, nil}`.

  Reasons:
  - :fpr_exceeded       - FPR is above the threshold
  - :sample_threshold   - Enough new labeled samples accumulated
  - :scheduled          - Weekly scheduled check triggered
  """
  @spec should_retrain?(String.t()) :: {boolean(), atom() | nil}
  def should_retrain?(model_type) do
    GenServer.call(__MODULE__, {:should_retrain, model_type})
  end

  @doc """
  Manually trigger retraining for a model type.
  Delegates to TrainingScheduler if available.
  """
  @spec trigger_retraining(String.t()) :: {:ok, String.t()} | {:error, term()}
  def trigger_retraining(model_type) do
    GenServer.call(__MODULE__, {:trigger_retraining, model_type})
  end

  @doc """
  Get overall feedback system stats.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # ── Server callbacks ──────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    :ets.new(@feedback_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@dataset_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@aggregates_table, [:named_table, :set, :public, read_concurrency: true])

    schedule_aggregate_check()
    schedule_weekly_retrain_check()

    state = %__MODULE__{
      stats: %{
        verdicts_recorded: 0,
        samples_queued: 0,
        retrains_triggered: 0,
        fpr_retrain_triggers: 0,
        sample_retrain_triggers: 0,
        scheduled_retrain_triggers: 0
      },
      last_retrain_check: DateTime.utc_now(),
      retrain_in_progress: false
    }

    Logger.info("[AnalystFeedback] Started (FPR threshold=#{@fpr_retrain_threshold * 100}%, sample threshold=#{@sample_retrain_threshold})")
    {:ok, state}
  end

  @impl true
  def handle_cast({:record_verdict, alert_id, verdict, analyst_id, opts}, state) do
    now = DateTime.utc_now()
    feedback_id = generate_feedback_id()

    # Extract model info from opts or from the alert
    model_type = opts[:model_type] || "malware_smell"
    model_version = opts[:model_version] || "unknown"
    sample_hash = opts[:sample_hash]
    confidence = opts[:confidence]
    original_severity = opts[:original_severity]
    new_severity = opts[:new_severity]

    feedback = %{
      feedback_id: feedback_id,
      alert_id: alert_id,
      verdict: verdict,
      analyst_id: analyst_id,
      model_type: model_type,
      model_version: model_version,
      sample_hash: sample_hash,
      confidence: confidence,
      original_severity: original_severity,
      new_severity: new_severity,
      recorded_at: now
    }

    :ets.insert(@feedback_table, {feedback_id, feedback})

    # Update aggregate stats for this model version
    update_aggregates(model_type, model_version, verdict)

    # Forward verdict to ModelManager for live metric tracking
    ml_verdict = normalize_verdict_for_ml(verdict)
    if ml_verdict do
      ModelManager.record_feedback(model_type, model_version, alert_id, ml_verdict)
    end

    # Queue sample for retraining if we have a hash
    state = if sample_hash do
      queue_training_sample(model_type, sample_hash, verdict, confidence, now)
      stats = Map.update!(state.stats, :samples_queued, &(&1 + 1))
      %{state | stats: stats}
    else
      state
    end

    stats = Map.update!(state.stats, :verdicts_recorded, &(&1 + 1))
    {:noreply, %{state | stats: stats}}
  end

  @impl true
  def handle_call({:should_retrain, model_type}, _from, state) do
    result = check_retrain_conditions(model_type)
    {:reply, result, state}
  end

  def handle_call({:trigger_retraining, model_type}, _from, state) do
    if state.retrain_in_progress do
      {:reply, {:error, :retrain_already_in_progress}, state}
    else
      result = do_trigger_retraining(model_type, :manual)
      stats = Map.update!(state.stats, :retrains_triggered, &(&1 + 1))
      {:reply, result, %{state | stats: stats, retrain_in_progress: true}}
    end
  end

  def handle_call(:stats, _from, state) do
    feedback_count = :ets.info(@feedback_table, :size) || 0
    dataset_count = :ets.info(@dataset_table, :size) || 0
    aggregate_count = :ets.info(@aggregates_table, :size) || 0

    result = Map.merge(state.stats, %{
      feedback_count: feedback_count,
      dataset_count: dataset_count,
      aggregate_count: aggregate_count,
      retrain_in_progress: state.retrain_in_progress,
      last_retrain_check: state.last_retrain_check
    })

    {:reply, result, state}
  end

  @impl true
  def handle_info(:check_aggregates, state) do
    check_all_retrain_conditions(state)
    schedule_aggregate_check()
    {:noreply, state}
  end

  def handle_info(:weekly_retrain_check, state) do
    Logger.info("[AnalystFeedback] Weekly retraining check")

    # Check all model types for scheduled retraining
    model_types = get_distinct_model_types()

    state =
      Enum.reduce(model_types, state, fn model_type, acc ->
        dataset_size = length(get_retraining_dataset(model_type))
        if dataset_size > 0 do
          Logger.info("[AnalystFeedback] Scheduled retraining for #{model_type} (#{dataset_size} samples)")
          do_trigger_retraining(model_type, :scheduled)
          stats = Map.update!(acc.stats, :scheduled_retrain_triggers, &(&1 + 1))
          %{acc | stats: stats}
        else
          acc
        end
      end)

    schedule_weekly_retrain_check()
    {:noreply, %{state | last_retrain_check: DateTime.utc_now()}}
  end

  def handle_info({:retrain_complete, _model_type}, state) do
    {:noreply, %{state | retrain_in_progress: false}}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ── Private: aggregation ──────────────────────────────────────────────

  defp update_aggregates(model_type, version, verdict) do
    key = {model_type, version}

    current = case :ets.lookup(@aggregates_table, key) do
      [{^key, stats}] -> stats
      [] -> initial_aggregate()
    end

    updated = case verdict do
      :true_positive ->
        %{current |
          true_positives: current.true_positives + 1,
          total: current.total + 1
        }
      :false_positive ->
        %{current |
          false_positives: current.false_positives + 1,
          total: current.total + 1
        }
      :true_negative ->
        %{current |
          true_negatives: current.true_negatives + 1,
          total: current.total + 1
        }
      :false_negative ->
        %{current |
          false_negatives: current.false_negatives + 1,
          total: current.total + 1
        }
      :severity_changed ->
        %{current | severity_changes: current.severity_changes + 1, total: current.total + 1}
      :storyline_confirmed ->
        %{current | storylines_confirmed: current.storylines_confirmed + 1, total: current.total + 1}
      :storyline_dismissed ->
        %{current | storylines_dismissed: current.storylines_dismissed + 1, total: current.total + 1}
      :response_approved ->
        %{current | responses_approved: current.responses_approved + 1, total: current.total + 1}
      :response_rejected ->
        %{current | responses_rejected: current.responses_rejected + 1, total: current.total + 1}
      _ ->
        %{current | total: current.total + 1}
    end

    # Recalculate rates
    updated = recalculate_rates(updated)
    :ets.insert(@aggregates_table, {key, updated})
  end

  defp initial_aggregate do
    %{
      true_positives: 0,
      false_positives: 0,
      true_negatives: 0,
      false_negatives: 0,
      severity_changes: 0,
      storylines_confirmed: 0,
      storylines_dismissed: 0,
      responses_approved: 0,
      responses_rejected: 0,
      total: 0,
      tp_rate: 0.0,
      fp_rate: 0.0,
      fn_rate: 0.0,
      precision: 0.0,
      recall: 0.0,
      last_updated: DateTime.utc_now()
    }
  end

  defp recalculate_rates(agg) do
    tp = agg.true_positives
    fp = agg.false_positives
    tn = agg.true_negatives
    fn_ = agg.false_negatives
    total_classified = tp + fp + tn + fn_

    tp_rate = safe_div(tp, total_classified)
    fp_rate = safe_div(fp, fp + tn)
    fn_rate = safe_div(fn_, total_classified)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn_)

    %{agg |
      tp_rate: Float.round(tp_rate, 6),
      fp_rate: Float.round(fp_rate, 6),
      fn_rate: Float.round(fn_rate, 6),
      precision: Float.round(precision, 6),
      recall: Float.round(recall, 6),
      last_updated: DateTime.utc_now()
    }
  end

  defp safe_div(_num, 0), do: 0.0
  defp safe_div(_num, 0.0), do: 0.0
  defp safe_div(num, denom), do: num / denom

  # ── Private: training dataset ─────────────────────────────────────────

  defp queue_training_sample(model_type, sample_hash, verdict, confidence, now) do
    label = case verdict do
      v when v in [:true_positive, :storyline_confirmed] -> :malicious
      v when v in [:false_positive, :true_negative, :storyline_dismissed] -> :benign
      _ -> :unknown
    end

    if label != :unknown do
      sample = %{
        sample_hash: sample_hash,
        label: label,
        verdict: verdict,
        confidence: confidence,
        recorded_at: now
      }

      :ets.insert(@dataset_table, {{model_type, sample_hash}, sample})
    end
  end

  defp normalize_verdict_for_ml(verdict) do
    case verdict do
      :true_positive -> :true_positive
      :false_positive -> :false_positive
      :true_negative -> :true_negative
      :false_negative -> :false_negative
      :storyline_confirmed -> :true_positive
      :storyline_dismissed -> :false_positive
      _ -> nil
    end
  end

  # ── Private: retrain conditions ───────────────────────────────────────

  defp check_retrain_conditions(model_type) do
    # Check FPR
    case get_latest_aggregate(model_type) do
      %{fp_rate: fpr} when fpr > @fpr_retrain_threshold ->
        {true, :fpr_exceeded}

      _ ->
        # Check sample count
        dataset_size = length(get_retraining_dataset(model_type))
        if dataset_size >= @sample_retrain_threshold do
          {true, :sample_threshold}
        else
          {false, nil}
        end
    end
  end

  defp check_all_retrain_conditions(state) do
    model_types = get_distinct_model_types()

    Enum.each(model_types, fn model_type ->
      case check_retrain_conditions(model_type) do
        {true, reason} ->
          Logger.info("[AnalystFeedback] Retraining condition met for #{model_type}: #{reason}")

          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "ml:feedback",
            {:retrain_recommended, model_type, reason}
          )

        {false, _} ->
          :ok
      end
    end)

    state
  end

  defp get_latest_aggregate(model_type) do
    @aggregates_table
    |> :ets.tab2list()
    |> Enum.filter(fn {{type, _version}, _stats} -> type == model_type end)
    |> Enum.map(fn {_key, stats} -> stats end)
    |> Enum.sort_by(& &1.last_updated, {:desc, DateTime})
    |> List.first()
  end

  defp get_distinct_model_types do
    @aggregates_table
    |> :ets.tab2list()
    |> Enum.map(fn {{type, _version}, _} -> type end)
    |> Enum.uniq()
  end

  # ── Private: trigger retraining ───────────────────────────────────────

  defp do_trigger_retraining(model_type, reason) do
    dataset = get_retraining_dataset(model_type)

    if length(dataset) == 0 do
      {:error, :no_training_data}
    else
      # Try to delegate to TrainingScheduler
      try do
        TamanduaServer.ML.TrainingScheduler.schedule_retraining(model_type, %{
          reason: reason,
          dataset_size: length(dataset),
          triggered_at: DateTime.utc_now()
        })
      rescue
        _ ->
          Logger.warning("[AnalystFeedback] TrainingScheduler not available, broadcasting retrain request")

          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "ml:training",
            {:retrain_requested, model_type, reason, length(dataset)}
          )

          {:ok, "retrain_broadcast_sent"}
      end
    end
  end

  # ── Private: scheduling ───────────────────────────────────────────────

  defp schedule_aggregate_check do
    Process.send_after(self(), :check_aggregates, @aggregate_check_interval_ms)
  end

  defp schedule_weekly_retrain_check do
    Process.send_after(self(), :weekly_retrain_check, @weekly_check_interval_ms)
  end

  # ── Private: utility ──────────────────────────────────────────────────

  defp generate_feedback_id do
    :crypto.strong_rand_bytes(12) |> Base.encode16(case: :lower)
  end
end
