defmodule TamanduaServer.ML.ModelManager do
  @moduledoc """
  GenServer for ML model lifecycle management.

  Tracks all ML models through their lifecycle:
    training -> validating -> canary -> active -> retired

  Provides:
  - Model registry with ETS-backed fast lookups
  - Semantic versioning with auto-increment
  - Canary deployment with configurable traffic split
  - Per-model performance tracking (TP/FP/TN/FN, precision, recall, F1, FPR)
  - Hourly metric snapshots
  - Automatic rollback on metric degradation
  - Automatic canary promotion when outperforming active model

  ## ETS Tables

  - `:ml_model_registry`     - {model_key, model_record}
  - `:ml_model_metrics`      - {{model_type, version}, metrics_map}
  - `:ml_model_predictions`  - {{model_type, version, prediction_id}, prediction_record}
  - `:ml_metric_snapshots`   - {{model_type, version, timestamp}, snapshot}
  """

  use GenServer
  require Logger

  # ── Configuration ────────────────────────────────────────────────────

  @canary_traffic_pct 10
  @canary_eval_window_ms :timer.minutes(30)
  @metric_snapshot_interval_ms :timer.hours(1)
  @canary_check_interval_ms :timer.minutes(5)
  @fpr_alert_threshold 0.02
  @canary_fpr_tolerance 1.2
  @canary_tpr_tolerance 0.95

  @registry_table :ml_model_registry
  @metrics_table :ml_model_metrics
  @predictions_table :ml_model_predictions
  @snapshots_table :ml_metric_snapshots

  # ── Model record ─────────────────────────────────────────────────────

  @type model_status :: :training | :validating | :canary | :active | :retired
  @type version :: String.t()

  @type model_record :: %{
          model_type: String.t(),
          version: version(),
          status: model_status(),
          registered_at: DateTime.t(),
          promoted_at: DateTime.t() | nil,
          retired_at: DateTime.t() | nil,
          metadata: map()
        }

  # ── State ─────────────────────────────────────────────────────────────

  defstruct [
    :canary_traffic_pct,
    :canary_started_at,
    :stats
  ]

  # ── Client API ───────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Register a new model version in the registry.

  `metadata` should include training metrics such as:
  - :training_date, :dataset_info, :tpr, :fpr, :precision, :recall, :f1
  """
  @spec register_model(String.t(), version(), map()) :: {:ok, model_record()} | {:error, term()}
  def register_model(model_type, version, metadata \\ %{}) do
    GenServer.call(__MODULE__, {:register_model, model_type, version, metadata})
  end

  @doc """
  Promote a model to canary status. It will start receiving
  `canary_traffic_pct`% of prediction traffic alongside the active model.
  """
  @spec promote_to_canary(String.t(), version()) :: :ok | {:error, term()}
  def promote_to_canary(model_type, version) do
    GenServer.call(__MODULE__, {:promote_to_canary, model_type, version})
  end

  @doc """
  Promote a model directly to active, retiring the current active model.
  """
  @spec promote_to_active(String.t(), version()) :: :ok | {:error, term()}
  def promote_to_active(model_type, version) do
    GenServer.call(__MODULE__, {:promote_to_active, model_type, version})
  end

  @doc """
  Rollback the active model to the most recent retired version.
  """
  @spec rollback(String.t()) :: {:ok, version()} | {:error, term()}
  def rollback(model_type) do
    GenServer.call(__MODULE__, {:rollback, model_type})
  end

  @doc """
  Record a prediction made by a specific model version.
  `actual` is nil until analyst feedback provides the ground truth.
  """
  @spec record_prediction(String.t(), version(), map(), atom() | nil) :: :ok
  def record_prediction(model_type, version, prediction, actual \\ nil) do
    GenServer.cast(__MODULE__, {:record_prediction, model_type, version, prediction, actual})
  end

  @doc """
  Record analyst feedback for a previous prediction, updating TP/FP/TN/FN counters.

  `analyst_verdict` should be :true_positive | :false_positive | :true_negative | :false_negative
  """
  @spec record_feedback(String.t(), version(), String.t(), atom()) :: :ok
  def record_feedback(model_type, version, prediction_id, analyst_verdict) do
    GenServer.cast(__MODULE__, {:record_feedback, model_type, version, prediction_id, analyst_verdict})
  end

  @doc """
  Get the currently active model for a given model type.
  """
  @spec get_active_model(String.t()) :: {:ok, model_record()} | {:error, :not_found}
  def get_active_model(model_type) do
    case find_models_by_status(model_type, :active) do
      [model | _] -> {:ok, model}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Get performance metrics for a specific model version.
  """
  @spec get_model_metrics(String.t(), version()) :: {:ok, map()} | {:error, :not_found}
  def get_model_metrics(model_type, version) do
    case :ets.lookup(@metrics_table, {model_type, version}) do
      [{_, metrics}] -> {:ok, metrics}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Get the full version history for a model type, ordered by registration date descending.
  """
  @spec get_model_history(String.t()) :: [model_record()]
  def get_model_history(model_type) do
    @registry_table
    |> :ets.tab2list()
    |> Enum.filter(fn {{type, _version}, _record} -> type == model_type end)
    |> Enum.map(fn {_key, record} -> record end)
    |> Enum.sort_by(& &1.registered_at, {:desc, DateTime})
  end

  @doc """
  Get current canary deployment status for a model type.
  """
  @spec get_canary_status(String.t()) :: {:ok, map()} | {:error, :no_canary}
  def get_canary_status(model_type) do
    GenServer.call(__MODULE__, {:get_canary_status, model_type})
  end

  @doc """
  Determine whether the current request should be routed to the canary model.
  Returns true approximately `canary_traffic_pct`% of the time when a canary exists.
  """
  @spec should_use_canary?() :: boolean()
  def should_use_canary? do
    :rand.uniform(100) <= @canary_traffic_pct
  end

  @doc """
  Aggregate stats for the model manager.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  @doc """
  List all registered models across all types.
  """
  @spec list_all_models() :: [model_record()]
  def list_all_models do
    @registry_table
    |> :ets.tab2list()
    |> Enum.map(fn {_key, record} -> record end)
    |> Enum.sort_by(& &1.registered_at, {:desc, DateTime})
  end

  # ── Server callbacks ──────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@registry_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@metrics_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@predictions_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@snapshots_table, [:named_table, :ordered_set, :public, read_concurrency: true])

    # Schedule periodic tasks
    schedule_metric_snapshot()
    schedule_canary_check()

    state = %__MODULE__{
      canary_traffic_pct: @canary_traffic_pct,
      canary_started_at: nil,
      stats: %{
        models_registered: 0,
        promotions: 0,
        rollbacks: 0,
        predictions_recorded: 0,
        feedback_recorded: 0,
        canary_promotions: 0,
        canary_rollbacks: 0,
        fpr_alerts: 0
      }
    }

    Logger.info("[ModelManager] Started with #{@canary_traffic_pct}% canary traffic split")
    {:ok, state}
  end

  @impl true
  def handle_call({:register_model, model_type, version, metadata}, _from, state) do
    now = DateTime.utc_now()

    record = %{
      model_type: model_type,
      version: version,
      status: :training,
      registered_at: now,
      promoted_at: nil,
      retired_at: nil,
      metadata: metadata
    }

    key = {model_type, version}
    :ets.insert(@registry_table, {key, record})

    # Initialize empty metrics
    metrics = initial_metrics(now)
    :ets.insert(@metrics_table, {key, metrics})

    stats = Map.update!(state.stats, :models_registered, &(&1 + 1))

    Logger.info("[ModelManager] Registered model #{model_type} v#{version}")
    {:reply, {:ok, record}, %{state | stats: stats}}
  end

  def handle_call({:promote_to_canary, model_type, version}, _from, state) do
    key = {model_type, version}

    case :ets.lookup(@registry_table, key) do
      [{^key, record}] ->
        # Retire any existing canary
        retire_canaries(model_type)

        updated = %{record | status: :canary, promoted_at: DateTime.utc_now()}
        :ets.insert(@registry_table, {key, updated})

        Logger.info("[ModelManager] Promoted #{model_type} v#{version} to canary")
        {:reply, :ok, %{state | canary_started_at: DateTime.utc_now()}}

      [] ->
        {:reply, {:error, :model_not_found}, state}
    end
  end

  def handle_call({:promote_to_active, model_type, version}, _from, state) do
    key = {model_type, version}

    case :ets.lookup(@registry_table, key) do
      [{^key, record}] ->
        # Retire current active model
        retire_active_models(model_type)

        updated = %{record | status: :active, promoted_at: DateTime.utc_now()}
        :ets.insert(@registry_table, {key, updated})

        stats = Map.update!(state.stats, :promotions, &(&1 + 1))

        Logger.info("[ModelManager] Promoted #{model_type} v#{version} to active")
        {:reply, :ok, %{state | stats: stats, canary_started_at: nil}}

      [] ->
        {:reply, {:error, :model_not_found}, state}
    end
  end

  def handle_call({:rollback, model_type}, _from, state) do
    # Find the most recently retired version
    retired =
      get_model_history(model_type)
      |> Enum.filter(&(&1.status == :retired))
      |> Enum.sort_by(& &1.retired_at, {:desc, DateTime})

    case retired do
      [prev | _] ->
        # Retire current active
        retire_active_models(model_type)
        # Also retire any canary
        retire_canaries(model_type)

        # Re-activate previous version
        key = {model_type, prev.version}
        updated = %{prev | status: :active, promoted_at: DateTime.utc_now(), retired_at: nil}
        :ets.insert(@registry_table, {key, updated})

        stats = Map.update!(state.stats, :rollbacks, &(&1 + 1))

        Logger.warning("[ModelManager] Rolled back #{model_type} to v#{prev.version}")
        {:reply, {:ok, prev.version}, %{state | stats: stats, canary_started_at: nil}}

      [] ->
        {:reply, {:error, :no_previous_version}, state}
    end
  end

  def handle_call({:get_canary_status, model_type}, _from, state) do
    case find_models_by_status(model_type, :canary) do
      [canary | _] ->
        canary_metrics = get_metrics_for(model_type, canary.version)

        active_metrics =
          case find_models_by_status(model_type, :active) do
            [active | _] -> get_metrics_for(model_type, active.version)
            [] -> nil
          end

        elapsed_ms =
          if state.canary_started_at do
            DateTime.diff(DateTime.utc_now(), state.canary_started_at, :millisecond)
          else
            0
          end

        result = %{
          canary_version: canary.version,
          canary_metrics: canary_metrics,
          active_metrics: active_metrics,
          traffic_pct: state.canary_traffic_pct,
          elapsed_ms: elapsed_ms,
          eval_window_ms: @canary_eval_window_ms,
          progress_pct: min(100, round(elapsed_ms / @canary_eval_window_ms * 100))
        }

        {:reply, {:ok, result}, state}

      [] ->
        {:reply, {:error, :no_canary}, state}
    end
  end

  def handle_call(:stats, _from, state) do
    model_count = :ets.info(@registry_table, :size) || 0
    metrics_count = :ets.info(@metrics_table, :size) || 0
    prediction_count = :ets.info(@predictions_table, :size) || 0
    snapshot_count = :ets.info(@snapshots_table, :size) || 0

    # Count models by status
    all_models = list_all_models()
    status_counts =
      all_models
      |> Enum.group_by(& &1.status)
      |> Map.new(fn {status, models} -> {status, length(models)} end)

    result = Map.merge(state.stats, %{
      model_count: model_count,
      metrics_count: metrics_count,
      prediction_count: prediction_count,
      snapshot_count: snapshot_count,
      models_by_status: status_counts,
      canary_traffic_pct: state.canary_traffic_pct
    })

    {:reply, result, state}
  end

  @impl true
  def handle_cast({:record_prediction, model_type, version, prediction, actual}, state) do
    prediction_id = generate_prediction_id()
    now = DateTime.utc_now()

    pred_record = %{
      prediction_id: prediction_id,
      model_type: model_type,
      version: version,
      prediction: prediction,
      actual: actual,
      recorded_at: now
    }

    :ets.insert(@predictions_table, {{model_type, version, prediction_id}, pred_record})

    # Update running metrics if actual is known
    if actual do
      update_metrics_with_outcome(model_type, version, prediction, actual)
    end

    stats = Map.update!(state.stats, :predictions_recorded, &(&1 + 1))
    {:noreply, %{state | stats: stats}}
  end

  def handle_cast({:record_feedback, model_type, version, _prediction_id, analyst_verdict}, state) do
    # Update metrics based on analyst verdict
    update_metrics_with_verdict(model_type, version, analyst_verdict)

    # Check FPR threshold after feedback
    check_fpr_alert(model_type, version)

    stats = Map.update!(state.stats, :feedback_recorded, &(&1 + 1))
    {:noreply, %{state | stats: stats}}
  end

  @impl true
  def handle_info(:take_metric_snapshot, state) do
    take_all_snapshots()
    schedule_metric_snapshot()
    {:noreply, state}
  end

  def handle_info(:check_canary, state) do
    state = evaluate_all_canaries(state)
    schedule_canary_check()
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ── Private: metrics helpers ──────────────────────────────────────────

  defp initial_metrics(now) do
    %{
      true_positives: 0,
      false_positives: 0,
      true_negatives: 0,
      false_negatives: 0,
      total_predictions: 0,
      precision: 0.0,
      recall: 0.0,
      f1: 0.0,
      fpr: 0.0,
      last_updated: now
    }
  end

  defp update_metrics_with_verdict(model_type, version, verdict) do
    key = {model_type, version}

    case :ets.lookup(@metrics_table, key) do
      [{^key, metrics}] ->
        updated =
          case verdict do
            :true_positive ->
              %{metrics | true_positives: metrics.true_positives + 1, total_predictions: metrics.total_predictions + 1}
            :false_positive ->
              %{metrics | false_positives: metrics.false_positives + 1, total_predictions: metrics.total_predictions + 1}
            :true_negative ->
              %{metrics | true_negatives: metrics.true_negatives + 1, total_predictions: metrics.total_predictions + 1}
            :false_negative ->
              %{metrics | false_negatives: metrics.false_negatives + 1, total_predictions: metrics.total_predictions + 1}
            _ ->
              metrics
          end

        updated = recalculate_derived_metrics(updated)
        :ets.insert(@metrics_table, {key, updated})

      [] ->
        :ok
    end
  end

  defp update_metrics_with_outcome(model_type, version, prediction, actual) do
    verdict = derive_verdict(prediction, actual)
    update_metrics_with_verdict(model_type, version, verdict)
  end

  defp derive_verdict(prediction, actual) do
    predicted_positive = prediction[:result] in ["malicious", "suspicious"] or prediction[:malicious] == true
    actually_positive = actual in [:malicious, :true_positive, true]

    cond do
      predicted_positive and actually_positive -> :true_positive
      predicted_positive and not actually_positive -> :false_positive
      not predicted_positive and actually_positive -> :false_negative
      true -> :true_negative
    end
  end

  defp recalculate_derived_metrics(m) do
    tp = m.true_positives
    fp = m.false_positives
    tn = m.true_negatives
    fn_ = m.false_negatives

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn_)
    f1 = safe_div(2 * precision * recall, precision + recall)
    fpr = safe_div(fp, fp + tn)

    %{m |
      precision: Float.round(precision, 6),
      recall: Float.round(recall, 6),
      f1: Float.round(f1, 6),
      fpr: Float.round(fpr, 6),
      last_updated: DateTime.utc_now()
    }
  end

  defp safe_div(_num, 0), do: 0.0
  defp safe_div(_num, 0.0), do: 0.0
  defp safe_div(num, denom), do: num / denom

  defp get_metrics_for(model_type, version) do
    case :ets.lookup(@metrics_table, {model_type, version}) do
      [{_, metrics}] -> metrics
      [] -> nil
    end
  end

  defp check_fpr_alert(model_type, version) do
    case get_metrics_for(model_type, version) do
      %{fpr: fpr, total_predictions: total} when total > 50 and fpr > @fpr_alert_threshold ->
        Logger.warning(
          "[ModelManager] FPR alert: #{model_type} v#{version} FPR=#{Float.round(fpr * 100, 2)}% " <>
          "(threshold=#{@fpr_alert_threshold * 100}%, predictions=#{total})"
        )

        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "ml:alerts",
          {:fpr_alert, model_type, version, fpr}
        )

      _ ->
        :ok
    end
  end

  # ── Private: canary evaluation ────────────────────────────────────────

  defp evaluate_all_canaries(state) do
    all_models = list_all_models()
    model_types = all_models |> Enum.map(& &1.model_type) |> Enum.uniq()

    Enum.reduce(model_types, state, fn model_type, acc ->
      evaluate_canary(model_type, acc)
    end)
  end

  defp evaluate_canary(model_type, state) do
    canaries = find_models_by_status(model_type, :canary)
    actives = find_models_by_status(model_type, :active)

    case {canaries, actives} do
      {[canary | _], [active | _]} ->
        # Check if evaluation window has elapsed
        if state.canary_started_at &&
           DateTime.diff(DateTime.utc_now(), state.canary_started_at, :millisecond) >= @canary_eval_window_ms do
          compare_and_decide(model_type, canary, active, state)
        else
          state
        end

      _ ->
        state
    end
  end

  defp compare_and_decide(model_type, canary, active, state) do
    canary_metrics = get_metrics_for(model_type, canary.version)
    active_metrics = get_metrics_for(model_type, active.version)

    cond do
      canary_metrics == nil or active_metrics == nil ->
        Logger.info("[ModelManager] Canary evaluation skipped: insufficient metrics for #{model_type}")
        state

      canary_metrics.total_predictions < 20 ->
        Logger.info("[ModelManager] Canary evaluation skipped: insufficient predictions (#{canary_metrics.total_predictions})")
        state

      # Canary FPR is too high (more than tolerance * active FPR)
      canary_metrics.fpr > active_metrics.fpr * @canary_fpr_tolerance and active_metrics.fpr > 0 ->
        Logger.warning(
          "[ModelManager] Canary #{model_type} v#{canary.version} rolled back: " <>
          "FPR #{Float.round(canary_metrics.fpr * 100, 2)}% vs active #{Float.round(active_metrics.fpr * 100, 2)}%"
        )
        rollback_canary(model_type, canary)
        stats = Map.update!(state.stats, :canary_rollbacks, &(&1 + 1))
        %{state | stats: stats, canary_started_at: nil}

      # Canary TPR dropped below tolerance
      canary_metrics.recall < active_metrics.recall * @canary_tpr_tolerance and active_metrics.recall > 0 ->
        Logger.warning(
          "[ModelManager] Canary #{model_type} v#{canary.version} rolled back: " <>
          "TPR #{Float.round(canary_metrics.recall * 100, 2)}% vs active #{Float.round(active_metrics.recall * 100, 2)}%"
        )
        rollback_canary(model_type, canary)
        stats = Map.update!(state.stats, :canary_rollbacks, &(&1 + 1))
        %{state | stats: stats, canary_started_at: nil}

      # Canary outperforms: lower or equal FPR and similar TPR
      canary_metrics.fpr <= active_metrics.fpr and
        canary_metrics.recall >= active_metrics.recall * @canary_tpr_tolerance ->
        Logger.info(
          "[ModelManager] Promoting canary #{model_type} v#{canary.version} to active: " <>
          "FPR #{Float.round(canary_metrics.fpr * 100, 2)}% (was #{Float.round(active_metrics.fpr * 100, 2)}%), " <>
          "TPR #{Float.round(canary_metrics.recall * 100, 2)}%"
        )
        promote_canary_to_active(model_type, canary)
        stats = Map.update!(state.stats, :canary_promotions, &(&1 + 1))
        %{state | stats: stats, canary_started_at: nil}

      true ->
        # Canary performance is inconclusive; keep evaluating
        state
    end
  end

  defp rollback_canary(model_type, canary) do
    key = {model_type, canary.version}
    updated = %{canary | status: :retired, retired_at: DateTime.utc_now()}
    :ets.insert(@registry_table, {key, updated})
  end

  defp promote_canary_to_active(model_type, canary) do
    retire_active_models(model_type)

    key = {model_type, canary.version}
    updated = %{canary | status: :active, promoted_at: DateTime.utc_now()}
    :ets.insert(@registry_table, {key, updated})
  end

  # ── Private: model status helpers ─────────────────────────────────────

  defp find_models_by_status(model_type, status) do
    @registry_table
    |> :ets.tab2list()
    |> Enum.filter(fn {{type, _v}, record} ->
      type == model_type and record.status == status
    end)
    |> Enum.map(fn {_key, record} -> record end)
  end

  defp retire_active_models(model_type) do
    find_models_by_status(model_type, :active)
    |> Enum.each(fn model ->
      key = {model_type, model.version}
      updated = %{model | status: :retired, retired_at: DateTime.utc_now()}
      :ets.insert(@registry_table, {key, updated})
    end)
  end

  defp retire_canaries(model_type) do
    find_models_by_status(model_type, :canary)
    |> Enum.each(fn model ->
      key = {model_type, model.version}
      updated = %{model | status: :retired, retired_at: DateTime.utc_now()}
      :ets.insert(@registry_table, {key, updated})
    end)
  end

  # ── Private: snapshots ────────────────────────────────────────────────

  defp take_all_snapshots do
    now = DateTime.utc_now()

    @metrics_table
    |> :ets.tab2list()
    |> Enum.each(fn {{model_type, version}, metrics} ->
      snapshot_key = {model_type, version, DateTime.to_unix(now)}
      :ets.insert(@snapshots_table, {snapshot_key, Map.put(metrics, :snapshot_at, now)})
    end)

    Logger.debug("[ModelManager] Metric snapshots taken")
  end

  # ── Private: scheduling ───────────────────────────────────────────────

  defp schedule_metric_snapshot do
    Process.send_after(self(), :take_metric_snapshot, @metric_snapshot_interval_ms)
  end

  defp schedule_canary_check do
    Process.send_after(self(), :check_canary, @canary_check_interval_ms)
  end

  # ── Private: utility ──────────────────────────────────────────────────

  defp generate_prediction_id do
    :crypto.strong_rand_bytes(12) |> Base.encode16(case: :lower)
  end
end
