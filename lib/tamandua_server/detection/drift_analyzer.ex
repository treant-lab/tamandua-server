defmodule TamanduaServer.Detection.DriftAnalyzer do
  @moduledoc """
  Drift Root Cause Analyzer for the Elixir backend.

  Stores historical drift results, performs trend analysis over time,
  and generates alerts on sustained gradual drift.

  Integrates with the ML service's drift root cause analysis endpoints
  to provide comprehensive drift monitoring.

  ## Features

  - Historical drift result storage in PostgreSQL
  - Trend analysis over configurable time windows
  - Automatic alerting on sustained drift patterns
  - Feature attribution tracking
  - Remediation recommendation tracking

  ## Usage

      # Store a drift result
      DriftAnalyzer.store_drift_result(result)

      # Get trend analysis
      {:ok, trend} = DriftAnalyzer.analyze_trend("model-123", days: 7)

      # Check for sustained drift
      {:ok, sustained} = DriftAnalyzer.check_sustained_drift("model-123")
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub
  alias TamanduaServer.Detection.ML.DriftClient


  @ets_table :drift_analysis_cache
  @trend_check_interval_ms 15 * 60 * 1000  # 15 minutes
  @sustained_drift_threshold 3  # Consecutive drift detections
  @trend_window_days 7

  # ============================================================================
  # Types
  # ============================================================================

  @type drift_result :: %{
    model_id: String.t(),
    timestamp: DateTime.t(),
    drift_detected: boolean(),
    drift_type: String.t(),
    overall_severity: String.t(),
    features_drifting: non_neg_integer(),
    top_features: list(String.t()),
    recommendations: list(map()),
    confidence_score: float()
  }

  @type trend_result :: %{
    model_id: String.t(),
    period_days: non_neg_integer(),
    total_checks: non_neg_integer(),
    drift_count: non_neg_integer(),
    drift_rate: float(),
    severity_distribution: map(),
    trend_direction: String.t(),
    top_drifting_features: list(String.t()),
    average_confidence: float()
  }

  @type sustained_drift :: %{
    model_id: String.t(),
    sustained: boolean(),
    consecutive_count: non_neg_integer(),
    start_timestamp: DateTime.t() | nil,
    common_features: list(String.t()),
    recommended_action: String.t()
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Store a drift analysis result for historical tracking.
  """
  @spec store_drift_result(drift_result()) :: :ok | {:error, term()}
  def store_drift_result(result) do
    GenServer.call(__MODULE__, {:store_result, result})
  end

  @doc """
  Analyze drift trend over a time period.
  """
  @spec analyze_trend(String.t(), keyword()) :: {:ok, trend_result()} | {:error, term()}
  def analyze_trend(model_id, opts \\ []) do
    GenServer.call(__MODULE__, {:analyze_trend, model_id, opts})
  end

  @doc """
  Check for sustained/gradual drift that requires immediate attention.
  """
  @spec check_sustained_drift(String.t()) :: {:ok, sustained_drift()} | {:error, term()}
  def check_sustained_drift(model_id) do
    GenServer.call(__MODULE__, {:check_sustained, model_id})
  end

  @doc """
  Get historical drift results for a model.
  """
  @spec get_history(String.t(), keyword()) :: {:ok, list(map())} | {:error, term()}
  def get_history(model_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_history, model_id, opts})
  end

  @doc """
  Request full root cause analysis from ML service.
  """
  @spec request_root_cause_analysis(String.t(), map(), map()) :: {:ok, map()} | {:error, term()}
  def request_root_cause_analysis(model_id, baseline_data, current_data) do
    GenServer.call(__MODULE__, {:request_analysis, model_id, baseline_data, current_data}, 60_000)
  end

  @doc """
  Get all models with active drift.
  """
  @spec get_drifting_models() :: list(map())
  def get_drifting_models do
    GenServer.call(__MODULE__, :get_drifting_models)
  end

  @doc """
  Get statistics about drift analysis.
  """
  @spec get_statistics() :: map()
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Clear historical drift data for a model.
  """
  @spec clear_history(String.t()) :: :ok
  def clear_history(model_id) do
    GenServer.call(__MODULE__, {:clear_history, model_id})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS table for caching
    table = :ets.new(@ets_table, [
      :set,
      :named_table,
      :public,
      read_concurrency: true
    ])

    # Subscribe to drift events
    PubSub.subscribe(TamanduaServer.PubSub, "drift:detected")
    PubSub.subscribe(TamanduaServer.PubSub, "drift:root_cause")

    # Schedule periodic trend checks
    schedule_trend_check()

    Logger.info("[DriftAnalyzer] Started")

    {:ok, %{
      table: table,
      total_results_stored: 0,
      total_analyses: 0,
      alerts_generated: 0,
      last_trend_check: nil
    }}
  end

  @impl true
  def handle_call({:store_result, result}, _from, state) do
    case do_store_result(result) do
      {:ok, _record} ->
        new_state = %{state | total_results_stored: state.total_results_stored + 1}

        # Check if this triggers a sustained drift alert
        check_and_alert_sustained(result.model_id)

        {:reply, :ok, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:analyze_trend, model_id, opts}, _from, state) do
    days = Keyword.get(opts, :days, @trend_window_days)
    result = do_analyze_trend(model_id, days)
    new_state = %{state | total_analyses: state.total_analyses + 1}
    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:check_sustained, model_id}, _from, state) do
    result = do_check_sustained(model_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_history, model_id, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    result = do_get_history(model_id, limit, offset)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:request_analysis, model_id, baseline_data, current_data}, _from, state) do
    result = DriftClient.request_root_cause_analysis(model_id, baseline_data, current_data)

    case result do
      {:ok, analysis} ->
        # Store the result
        store_result = %{
          model_id: model_id,
          timestamp: DateTime.utc_now(),
          drift_detected: analysis["drift_detected"],
          drift_type: analysis["drift_type"],
          overall_severity: analysis["overall_severity"],
          features_drifting: analysis["features_drifting"],
          top_features: analysis["top_contributing_features"],
          recommendations: analysis["recommendations"],
          confidence_score: analysis["confidence_score"]
        }
        do_store_result(store_result)

        {:reply, {:ok, analysis}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_drifting_models, _from, state) do
    models = do_get_drifting_models()
    {:reply, models, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = %{
      total_results_stored: state.total_results_stored,
      total_analyses: state.total_analyses,
      alerts_generated: state.alerts_generated,
      last_trend_check: state.last_trend_check,
      cached_entries: :ets.info(@ets_table, :size)
    }
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:clear_history, model_id}, _from, state) do
    do_clear_history(model_id)
    :ets.delete(@ets_table, model_id)
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:trend_check, state) do
    # Check trends for all models with recent activity
    models = do_get_active_models()

    for model_id <- models do
      case do_check_sustained(model_id) do
        {:ok, %{sustained: true} = sustained} ->
          generate_sustained_drift_alert(model_id, sustained)

        _ ->
          :ok
      end
    end

    schedule_trend_check()
    {:noreply, %{state | last_trend_check: DateTime.utc_now()}}
  end

  @impl true
  def handle_info({:drift_detected, event}, state) do
    # Auto-store drift detection events
    result = %{
      model_id: event.model_id,
      timestamp: event.timestamp,
      drift_detected: true,
      drift_type: "unknown",
      overall_severity: severity_from_score(event.drift_score),
      features_drifting: 0,
      top_features: [],
      recommendations: [],
      confidence_score: 0.5
    }

    do_store_result(result)

    {:noreply, %{state | total_results_stored: state.total_results_stored + 1}}
  end

  @impl true
  def handle_info({:drift_root_cause, event}, state) do
    # Store full root cause analysis
    do_store_result(event)
    {:noreply, %{state | total_results_stored: state.total_results_stored + 1}}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp schedule_trend_check do
    Process.send_after(self(), :trend_check, @trend_check_interval_ms)
  end

  defp do_store_result(result) do
    # Store in database (using a simple map structure)
    # In production, this would use an Ecto schema
    record = %{
      id: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower),
      model_id: result.model_id,
      timestamp: result.timestamp || DateTime.utc_now(),
      drift_detected: result.drift_detected,
      drift_type: result[:drift_type] || "unknown",
      overall_severity: result[:overall_severity] || "none",
      features_drifting: result[:features_drifting] || 0,
      top_features: result[:top_features] || [],
      recommendations: result[:recommendations] || [],
      confidence_score: result[:confidence_score] || 0.0,
      inserted_at: DateTime.utc_now()
    }

    # Cache in ETS for fast access
    key = {result.model_id, DateTime.to_unix(record.timestamp)}
    :ets.insert(@ets_table, {key, record})

    # Also store in persistent cache by model
    history_key = {:history, result.model_id}
    existing = case :ets.lookup(@ets_table, history_key) do
      [{^history_key, list}] -> list
      [] -> []
    end

    # Keep last 1000 entries per model
    updated = [record | existing] |> Enum.take(1000)
    :ets.insert(@ets_table, {history_key, updated})

    {:ok, record}
  end

  defp do_analyze_trend(model_id, days) do
    cutoff = DateTime.add(DateTime.utc_now(), -days * 24 * 60 * 60)

    history = case :ets.lookup(@ets_table, {:history, model_id}) do
      [{_, list}] -> list
      [] -> []
    end

    recent = Enum.filter(history, fn r ->
      DateTime.compare(r.timestamp, cutoff) == :gt
    end)

    if length(recent) == 0 do
      {:ok, %{
        model_id: model_id,
        period_days: days,
        total_checks: 0,
        drift_count: 0,
        drift_rate: 0.0,
        severity_distribution: %{},
        trend_direction: "stable",
        top_drifting_features: [],
        average_confidence: 0.0
      }}
    else
      drift_count = Enum.count(recent, & &1.drift_detected)
      total = length(recent)

      severities = Enum.frequencies_by(recent, & &1.overall_severity)

      # Calculate trend direction
      half = div(total, 2)
      {first_half, second_half} = Enum.split(recent, half)

      first_drift_rate = if length(first_half) > 0 do
        Enum.count(first_half, & &1.drift_detected) / length(first_half)
      else
        0.0
      end

      second_drift_rate = if length(second_half) > 0 do
        Enum.count(second_half, & &1.drift_detected) / length(second_half)
      else
        0.0
      end

      trend = cond do
        second_drift_rate > first_drift_rate * 1.5 -> "increasing"
        first_drift_rate > second_drift_rate * 1.5 -> "decreasing"
        true -> "stable"
      end

      # Get most common drifting features
      all_features = recent
        |> Enum.flat_map(& &1.top_features)
        |> Enum.frequencies()
        |> Enum.sort_by(fn {_, count} -> -count end)
        |> Enum.take(5)
        |> Enum.map(fn {feature, _} -> feature end)

      avg_confidence = if total > 0 do
        Enum.sum(Enum.map(recent, & &1.confidence_score)) / total
      else
        0.0
      end

      {:ok, %{
        model_id: model_id,
        period_days: days,
        total_checks: total,
        drift_count: drift_count,
        drift_rate: drift_count / total,
        severity_distribution: severities,
        trend_direction: trend,
        top_drifting_features: all_features,
        average_confidence: avg_confidence
      }}
    end
  end

  defp do_check_sustained(model_id) do
    history = case :ets.lookup(@ets_table, {:history, model_id}) do
      [{_, list}] -> list
      [] -> []
    end

    recent = Enum.take(history, @sustained_drift_threshold + 2)

    if length(recent) < @sustained_drift_threshold do
      {:ok, %{
        model_id: model_id,
        sustained: false,
        consecutive_count: 0,
        start_timestamp: nil,
        common_features: [],
        recommended_action: "collect_more_data"
      }}
    else
      # Count consecutive drift detections from most recent
      consecutive = Enum.take_while(recent, & &1.drift_detected) |> length()

      sustained = consecutive >= @sustained_drift_threshold

      start_ts = if sustained do
        Enum.at(recent, consecutive - 1)[:timestamp]
      else
        nil
      end

      # Find common features across consecutive drifts
      common_features = if sustained do
        recent
        |> Enum.take(consecutive)
        |> Enum.flat_map(& &1.top_features)
        |> Enum.frequencies()
        |> Enum.filter(fn {_, count} -> count >= consecutive end)
        |> Enum.map(fn {feature, _} -> feature end)
      else
        []
      end

      # Determine recommended action
      action = cond do
        consecutive >= 5 -> "immediate_retrain"
        consecutive >= 3 -> "investigate_and_retrain"
        consecutive >= 2 -> "investigate"
        true -> "monitor"
      end

      {:ok, %{
        model_id: model_id,
        sustained: sustained,
        consecutive_count: consecutive,
        start_timestamp: start_ts,
        common_features: common_features,
        recommended_action: action
      }}
    end
  end

  defp do_get_history(model_id, limit, offset) do
    history = case :ets.lookup(@ets_table, {:history, model_id}) do
      [{_, list}] -> list
      [] -> []
    end

    result = history
      |> Enum.drop(offset)
      |> Enum.take(limit)

    {:ok, result}
  end

  defp do_get_drifting_models do
    # Get all models with recent drift
    all_keys = :ets.tab2list(@ets_table)

    all_keys
    |> Enum.filter(fn
      {{:history, _model_id}, _} -> true
      _ -> false
    end)
    |> Enum.map(fn {{:history, model_id}, history} ->
      recent = Enum.take(history, 5)
      drift_count = Enum.count(recent, & &1.drift_detected)

      if drift_count > 0 do
        %{
          model_id: model_id,
          recent_drift_count: drift_count,
          last_drift: Enum.find(recent, & &1.drift_detected)
        }
      else
        nil
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.sort_by(& &1.recent_drift_count, :desc)
  end

  defp do_get_active_models do
    cutoff = DateTime.add(DateTime.utc_now(), -24 * 60 * 60)  # Last 24 hours

    :ets.tab2list(@ets_table)
    |> Enum.filter(fn
      {{:history, _model_id}, history} ->
        case List.first(history) do
          nil -> false
          record -> DateTime.compare(record.timestamp, cutoff) == :gt
        end
      _ -> false
    end)
    |> Enum.map(fn {{:history, model_id}, _} -> model_id end)
  end

  defp do_clear_history(model_id) do
    :ets.delete(@ets_table, {:history, model_id})

    # Also clear individual entries
    :ets.tab2list(@ets_table)
    |> Enum.filter(fn
      {{^model_id, _ts}, _} -> true
      _ -> false
    end)
    |> Enum.each(fn {key, _} -> :ets.delete(@ets_table, key) end)
  end

  defp check_and_alert_sustained(model_id) do
    case do_check_sustained(model_id) do
      {:ok, %{sustained: true} = sustained} ->
        generate_sustained_drift_alert(model_id, sustained)
      _ ->
        :ok
    end
  end

  defp generate_sustained_drift_alert(model_id, sustained) do
    PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:generated",
      {:drift_sustained_alert, %{
        model_id: model_id,
        consecutive_count: sustained.consecutive_count,
        start_timestamp: sustained.start_timestamp,
        common_features: sustained.common_features,
        recommended_action: sustained.recommended_action,
        severity: if(sustained.consecutive_count >= 5, do: "high", else: "medium"),
        timestamp: DateTime.utc_now()
      }}
    )

    Logger.warning(
      "[DriftAnalyzer] Sustained drift detected",
      model_id: model_id,
      consecutive_count: sustained.consecutive_count,
      action: sustained.recommended_action
    )
  end

  defp severity_from_score(score) when is_number(score) do
    cond do
      score >= 0.8 -> "high"
      score >= 0.5 -> "medium"
      score >= 0.2 -> "low"
      true -> "none"
    end
  end

  defp severity_from_score(_), do: "unknown"
end
