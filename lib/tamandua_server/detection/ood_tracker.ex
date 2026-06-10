defmodule TamanduaServer.Detection.OODTracker do
  @moduledoc """
  GenServer for tracking Out-of-Distribution (OOD) rates per model.

  Monitors OOD detection results from the ML service and provides:
  - Per-model OOD rate tracking with rolling windows
  - Alert generation for sustained high OOD rates
  - Historical OOD statistics for dashboards
  - Integration with inference events for automatic tracking

  OOD detection indicates when model predictions may be unreliable because
  the input is far from the training distribution.

  Usage:
      # Record an OOD detection result
      OODTracker.record_detection("model-v1", %{
        is_ood: true,
        ood_score: 0.85,
        severity: "high",
        agent_id: "agent-123"
      })

      # Get OOD statistics for a model
      {:ok, stats} = OODTracker.get_model_stats("model-v1")
      stats.ood_rate  # => 0.15 (15% OOD rate)
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub
  alias TamanduaServer.Alerts

  @ets_table :ood_tracking
  @check_interval_ms 5 * 60 * 1000  # 5 minutes
  @window_size 100  # Rolling window for rate calculation
  @alert_threshold 0.2  # Alert if OOD rate > 20%
  @high_alert_threshold 0.4  # High alert if OOD rate > 40%
  @critical_alert_threshold 0.6  # Critical alert if OOD rate > 60%

  # ============================================================================
  # Types
  # ============================================================================

  @type ood_detection :: %{
          is_ood: boolean(),
          ood_score: float(),
          severity: String.t(),
          agent_id: String.t() | nil,
          method: String.t() | nil,
          timestamp: DateTime.t()
        }

  @type model_stats :: %{
          model_id: String.t(),
          total_detections: non_neg_integer(),
          ood_count: non_neg_integer(),
          ood_rate: float(),
          avg_ood_score: float(),
          recent_scores: list(),
          severity_distribution: map(),
          last_alert_at: DateTime.t() | nil,
          last_updated: DateTime.t()
        }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record an OOD detection result for a model.

  The detection map should contain:
  - is_ood: boolean indicating if the input was OOD
  - ood_score: float between 0.0 and 1.0
  - severity: "none" | "low" | "medium" | "high" | "critical"
  - agent_id: optional agent identifier
  - method: optional detection method used
  """
  @spec record_detection(String.t(), map()) :: :ok
  def record_detection(model_id, detection) do
    GenServer.cast(__MODULE__, {:record_detection, model_id, detection})
  end

  @doc """
  Get OOD statistics for a specific model.
  """
  @spec get_model_stats(String.t()) :: {:ok, model_stats()} | {:error, :not_found}
  def get_model_stats(model_id) do
    GenServer.call(__MODULE__, {:get_model_stats, model_id})
  end

  @doc """
  Get OOD statistics for all tracked models.
  """
  @spec get_all_stats() :: list(model_stats())
  def get_all_stats do
    GenServer.call(__MODULE__, :get_all_stats)
  end

  @doc """
  Get list of models with high OOD rates (above alert threshold).
  """
  @spec get_high_ood_models() :: list({String.t(), float()})
  def get_high_ood_models do
    GenServer.call(__MODULE__, :get_high_ood_models)
  end

  @doc """
  Get aggregate OOD statistics across all models.
  """
  @spec get_aggregate_stats() :: map()
  def get_aggregate_stats do
    GenServer.call(__MODULE__, :get_aggregate_stats)
  end

  @doc """
  Reset statistics for a specific model.
  """
  @spec reset_model(String.t()) :: :ok
  def reset_model(model_id) do
    GenServer.cast(__MODULE__, {:reset_model, model_id})
  end

  @doc """
  Get active OOD alerts.
  """
  @spec get_active_alerts() :: list()
  def get_active_alerts do
    GenServer.call(__MODULE__, :get_active_alerts)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    table =
      :ets.new(@ets_table, [
        :set,
        :named_table,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])

    # Subscribe to inference events for automatic OOD tracking
    PubSub.subscribe(TamanduaServer.PubSub, "inference:ood")

    # Schedule periodic alert checks
    schedule_alert_check()

    Logger.info("[OODTracker] Started")

    {:ok,
     %{
       table: table,
       active_alerts: [],
       total_detections: 0,
       total_ood: 0
     }}
  end

  @impl true
  def handle_cast({:record_detection, model_id, detection}, state) do
    stats = get_or_create_stats(model_id)

    # Extract detection data
    is_ood = detection[:is_ood] || detection["is_ood"] || false
    ood_score = detection[:ood_score] || detection["ood_score"] || 0.0
    severity = detection[:severity] || detection["severity"] || "none"

    # Update rolling window of recent scores
    recent_scores = [ood_score | stats.recent_scores] |> Enum.take(@window_size)

    # Calculate new OOD rate from rolling window
    ood_in_window = Enum.count(recent_scores, fn s -> s > 0.5 end)
    ood_rate = ood_in_window / max(length(recent_scores), 1)

    # Update severity distribution
    severity_dist = Map.update(stats.severity_distribution, severity, 1, &(&1 + 1))

    # Calculate average OOD score
    total_score = stats.avg_ood_score * stats.total_detections + ood_score
    new_total = stats.total_detections + 1
    avg_score = total_score / new_total

    new_stats = %{
      stats
      | total_detections: new_total,
        ood_count: if(is_ood, do: stats.ood_count + 1, else: stats.ood_count),
        ood_rate: ood_rate,
        avg_ood_score: avg_score,
        recent_scores: recent_scores,
        severity_distribution: severity_dist,
        last_updated: DateTime.utc_now()
    }

    :ets.insert(@ets_table, {model_id, new_stats})

    # Update global counters
    new_state = %{
      state
      | total_detections: state.total_detections + 1,
        total_ood: if(is_ood, do: state.total_ood + 1, else: state.total_ood)
    }

    # Broadcast OOD event
    if is_ood do
      PubSub.broadcast(
        TamanduaServer.PubSub,
        "ood:detected",
        {:ood_detected,
         %{
           model_id: model_id,
           ood_score: ood_score,
           severity: severity,
           timestamp: DateTime.utc_now()
         }}
      )
    end

    # Emit telemetry
    :telemetry.execute(
      [:tamandua, :ood, :detection],
      %{score: ood_score, is_ood: if(is_ood, do: 1, else: 0)},
      %{model_id: model_id, severity: severity}
    )

    {:noreply, new_state}
  end

  @impl true
  def handle_cast({:reset_model, model_id}, state) do
    :ets.delete(@ets_table, model_id)
    Logger.info("[OODTracker] Reset stats for model #{model_id}")
    {:noreply, state}
  end

  @impl true
  def handle_call({:get_model_stats, model_id}, _from, state) do
    result =
      case :ets.lookup(@ets_table, model_id) do
        [{^model_id, stats}] -> {:ok, Map.put(stats, :model_id, model_id)}
        [] -> {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_all_stats, _from, state) do
    stats =
      :ets.tab2list(@ets_table)
      |> Enum.map(fn {model_id, stats} -> Map.put(stats, :model_id, model_id) end)
      |> Enum.sort_by(& &1.ood_rate, :desc)

    {:reply, stats, state}
  end

  @impl true
  def handle_call(:get_high_ood_models, _from, state) do
    high_ood =
      :ets.tab2list(@ets_table)
      |> Enum.filter(fn {_model_id, stats} -> stats.ood_rate > @alert_threshold end)
      |> Enum.map(fn {model_id, stats} -> {model_id, stats.ood_rate} end)
      |> Enum.sort_by(&elem(&1, 1), :desc)

    {:reply, high_ood, state}
  end

  @impl true
  def handle_call(:get_aggregate_stats, _from, state) do
    all_stats = :ets.tab2list(@ets_table)

    aggregate = %{
      models_tracked: length(all_stats),
      total_detections: state.total_detections,
      total_ood: state.total_ood,
      global_ood_rate: safe_divide(state.total_ood, state.total_detections),
      models_above_threshold: Enum.count(all_stats, fn {_, s} -> s.ood_rate > @alert_threshold end),
      models_critical: Enum.count(all_stats, fn {_, s} -> s.ood_rate > @critical_alert_threshold end),
      active_alerts: length(state.active_alerts)
    }

    {:reply, aggregate, state}
  end

  @impl true
  def handle_call(:get_active_alerts, _from, state) do
    {:reply, state.active_alerts, state}
  end

  @impl true
  def handle_info(:check_alerts, state) do
    new_alerts = check_and_generate_alerts(state.active_alerts)

    schedule_alert_check()

    {:noreply, %{state | active_alerts: new_alerts}}
  end

  @impl true
  def handle_info({:ood_result, model_id, result}, state) do
    # Handle OOD results from inference pipeline
    record_detection(model_id, result)
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp schedule_alert_check do
    Process.send_after(self(), :check_alerts, @check_interval_ms)
  end

  defp get_or_create_stats(model_id) do
    case :ets.lookup(@ets_table, model_id) do
      [{^model_id, stats}] ->
        stats

      [] ->
        %{
          total_detections: 0,
          ood_count: 0,
          ood_rate: 0.0,
          avg_ood_score: 0.0,
          recent_scores: [],
          severity_distribution: %{},
          last_alert_at: nil,
          last_updated: DateTime.utc_now()
        }
    end
  end

  defp check_and_generate_alerts(existing_alerts) do
    all_stats = :ets.tab2list(@ets_table)

    # Filter existing alerts that are still valid
    active_alerts =
      Enum.filter(existing_alerts, fn alert ->
        case :ets.lookup(@ets_table, alert.model_id) do
          [{_model_id, stats}] -> stats.ood_rate > @alert_threshold
          [] -> false
        end
      end)

    # Check for new alerts
    new_alerts =
      all_stats
      |> Enum.filter(fn {model_id, stats} ->
        stats.ood_rate > @alert_threshold and
          stats.total_detections >= 10 and
          not Enum.any?(active_alerts, &(&1.model_id == model_id))
      end)
      |> Enum.map(fn {model_id, stats} ->
        level = determine_alert_level(stats.ood_rate)
        alert = create_alert(model_id, stats, level)

        # Update last_alert_at
        updated_stats = %{stats | last_alert_at: DateTime.utc_now()}
        :ets.insert(@ets_table, {model_id, updated_stats})

        alert
      end)

    # Log new alerts
    Enum.each(new_alerts, fn alert ->
      Logger.warning(
        "[OODTracker] Alert generated for model #{alert.model_id}: " <>
          "OOD rate #{Float.round(alert.ood_rate * 100, 1)}% (#{alert.level})"
      )

      # Broadcast alert
      PubSub.broadcast(
        TamanduaServer.PubSub,
        "ood:alert",
        {:ood_alert, alert}
      )

      # Create system alert
      try do
        Alerts.create(%{
          type: "ood_high_rate",
          severity: alert_level_to_severity(alert.level),
          title: "High OOD Rate: #{alert.model_id}",
          description:
            "Model #{alert.model_id} has #{Float.round(alert.ood_rate * 100, 1)}% " <>
              "out-of-distribution rate over last #{alert.sample_count} inferences.",
          metadata: %{
            model_id: alert.model_id,
            ood_rate: alert.ood_rate,
            avg_ood_score: alert.avg_ood_score,
            sample_count: alert.sample_count
          }
        })
      rescue
        e ->
          Logger.error("[OODTracker] Failed to create alert: #{inspect(e)}")
      end
    end)

    active_alerts ++ new_alerts
  end

  defp determine_alert_level(ood_rate) when ood_rate >= @critical_alert_threshold, do: :critical
  defp determine_alert_level(ood_rate) when ood_rate >= @high_alert_threshold, do: :high
  defp determine_alert_level(_ood_rate), do: :warning

  defp alert_level_to_severity(:critical), do: "critical"
  defp alert_level_to_severity(:high), do: "high"
  defp alert_level_to_severity(_), do: "medium"

  defp create_alert(model_id, stats, level) do
    %{
      model_id: model_id,
      level: level,
      ood_rate: stats.ood_rate,
      avg_ood_score: stats.avg_ood_score,
      sample_count: stats.total_detections,
      severity_distribution: stats.severity_distribution,
      created_at: DateTime.utc_now()
    }
  end

  defp safe_divide(_numerator, 0), do: 0.0
  defp safe_divide(_numerator, 0.0), do: 0.0
  defp safe_divide(numerator, denominator), do: numerator / denominator
end
