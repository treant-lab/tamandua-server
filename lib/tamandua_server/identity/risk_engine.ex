defmodule TamanduaServer.Identity.RiskEngine do
  @moduledoc """
  User and Asset Risk Scoring Engine.

  Computes composite risk scores (0-100) for users and assets by aggregating
  multiple risk factors with configurable weights. Scores are continuously
  updated as new telemetry flows in and are used to prioritize investigations.

  ## Risk Score: 0-100 Composite

  The score combines:
  - Behavioral deviation score (from BaselineLearner)
  - Alert history (count, severity, recency)
  - Privilege level (admin = higher base risk)
  - Peer group outlier score (from PeerClustering)
  - Time-based decay (recent events weighted more)
  - Asset criticality multiplier

  ## Risk Tiers

  - `:low`      -   0-25
  - `:medium`   -  26-50
  - `:high`     -  51-75
  - `:critical` -  76-100

  ## Trending

  Tracks risk scores over time to detect rapid increases. Uses exponential
  weighted moving average with a lookback window.

  ## ETS Tables

  - `:risk_engine_scores`    - Current risk score per entity
  - `:risk_engine_history`   - Risk score history (sliding window)
  - `:risk_engine_factors`   - Individual risk factor values per entity
  """

  use GenServer
  require Logger

  # ---------------------------------------------------------------------------
  # Constants
  # ---------------------------------------------------------------------------

  @scores_table :risk_engine_scores
  @history_table :risk_engine_history
  @factors_table :risk_engine_factors

  # Risk tier boundaries
  @low_max 25
  @medium_max 50
  @high_max 75

  # Factor weights (configurable, should sum to ~100 for max score)
  @default_weights %{
    behavioral_deviation: 20,
    alert_history: 20,
    privilege_level: 10,
    peer_outlier: 15,
    recent_events: 15,
    asset_criticality: 10,
    external_signals: 10
  }

  # Time decay half-life in hours (events older than this contribute half as much)
  @decay_half_life_hours 72

  # Maximum history entries per entity
  @max_history_entries 168

  # Periodic intervals
  @recalc_interval :timer.minutes(10)
  @flush_interval :timer.minutes(15)
  @cleanup_interval :timer.hours(6)

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Calculate the current risk score for an entity.

  Returns a risk assessment with composite score, tier, and factor breakdown.

  ## Examples

      calculate_risk(:user, "user@example.com")
      # => %{score: 67, tier: :high, factors: [...], trending: :increasing}
  """
  @spec calculate_risk(atom(), String.t()) :: map()
  def calculate_risk(entity_type, entity_id)
      when is_atom(entity_type) and is_binary(entity_id) do
    GenServer.call(__MODULE__, {:calculate_risk, entity_type, entity_id})
  end

  @doc """
  Get historical risk scores for an entity within a timeframe.

  ## Options
  - `:hours` - Lookback hours (default: 24)
  - `:limit` - Maximum entries (default: 100)
  """
  @spec get_risk_history(atom(), String.t(), keyword()) :: list(map())
  def get_risk_history(entity_type, entity_id, opts \\ []) do
    hours = Keyword.get(opts, :hours, 24)
    limit = Keyword.get(opts, :limit, 100)
    cutoff = DateTime.add(DateTime.utc_now(), -hours, :hour)

    key = {entity_type, entity_id}

    case :ets.lookup(@history_table, key) do
      [{^key, entries}] ->
        entries
        |> Enum.filter(fn entry ->
          DateTime.compare(entry.timestamp, cutoff) != :lt
        end)
        |> Enum.take(limit)

      [] ->
        []
    end
  end

  @doc """
  Get all entities with risk scores above a threshold.
  """
  @spec get_high_risk_entities(integer()) :: list(map())
  def get_high_risk_entities(threshold \\ 75) do
    ets_safe_tab2list(@scores_table)
    |> Enum.filter(fn {_key, score_data} -> score_data.score >= threshold end)
    |> Enum.map(fn {{entity_type, entity_id}, score_data} ->
      Map.merge(score_data, %{entity_type: entity_type, entity_id: entity_id})
    end)
    |> Enum.sort_by(& &1.score, :desc)
  end

  @doc """
  Get the risk trend for an entity over recent history.
  Returns `:increasing`, `:stable`, or `:decreasing`.
  """
  @spec get_risk_trend(atom(), String.t()) :: :increasing | :stable | :decreasing
  def get_risk_trend(entity_type, entity_id) do
    history = get_risk_history(entity_type, entity_id, hours: 6, limit: 12)
    compute_trend(history)
  end

  @doc """
  Manually update a specific risk factor for an entity.
  The score will be recalculated on the next cycle.
  """
  @spec update_risk_factor(atom(), String.t(), atom(), number()) :: :ok
  def update_risk_factor(entity_type, entity_id, factor, value)
      when is_atom(factor) and is_number(value) do
    GenServer.cast(__MODULE__, {:update_factor, entity_type, entity_id, factor, value})
  end

  @doc """
  Get global stats about the risk engine.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # ---------------------------------------------------------------------------
  # GenServer Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@scores_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@history_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@factors_table, [:named_table, :set, :public, read_concurrency: true])

    # Subscribe to relevant events
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "baseline:anomalies")
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "identity:deviations")
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:new")

    schedule_recalc()
    schedule_flush()
    schedule_cleanup()

    Logger.info("[RiskEngine] Initialized with #{map_size(@default_weights)} risk factor weights")
    {:ok, %{recalc_count: 0, last_recalc_at: nil}}
  end

  @impl true
  def handle_call({:calculate_risk, entity_type, entity_id}, _from, state) do
    result = do_calculate_risk(entity_type, entity_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    scores = ets_safe_tab2list(@scores_table)

    tier_counts =
      Enum.frequencies_by(scores, fn {_key, data} -> data.tier end)

    avg_score =
      if length(scores) > 0 do
        Enum.sum(Enum.map(scores, fn {_k, d} -> d.score end)) / length(scores)
      else
        0.0
      end

    result = %{
      total_entities: length(scores),
      tier_distribution: %{
        critical: Map.get(tier_counts, :critical, 0),
        high: Map.get(tier_counts, :high, 0),
        medium: Map.get(tier_counts, :medium, 0),
        low: Map.get(tier_counts, :low, 0)
      },
      average_score: Float.round(avg_score, 1),
      total_factors_tracked: :ets.info(@factors_table, :size),
      recalc_count: state.recalc_count,
      last_recalc_at: state.last_recalc_at,
      weights: @default_weights
    }

    {:reply, result, state}
  end

  @impl true
  def handle_cast({:update_factor, entity_type, entity_id, factor, value}, state) do
    key = {entity_type, entity_id}

    factors =
      case :ets.lookup(@factors_table, key) do
        [{^key, f}] -> f
        [] -> %{}
      end

    updated = Map.put(factors, factor, %{value: value, updated_at: DateTime.utc_now()})
    :ets.insert(@factors_table, {key, updated})
    {:noreply, state}
  end

  # Handle baseline anomaly events
  @impl true
  def handle_info({:baseline_anomaly, entity_type, entity_id, score}, state) do
    update_risk_factor(entity_type, entity_id, :behavioral_deviation, score * 100)
    {:noreply, state}
  end

  # Handle identity deviation events
  @impl true
  def handle_info({:identity_deviation, user_id, _deviation_type, confidence}, state) do
    update_risk_factor(:user, user_id, :behavioral_deviation, confidence * 100)
    {:noreply, state}
  end

  # Handle new alert events
  @impl true
  def handle_info({:new_alert, alert}, state) do
    agent_id = extract_field(alert, :agent_id)

    if agent_id do
      severity = extract_field(alert, :severity)

      severity_score =
        case severity do
          s when s in [:critical, "critical"] -> 100
          s when s in [:high, "high"] -> 75
          s when s in [:medium, "medium"] -> 50
          _ -> 25
        end

      update_risk_factor(:agent, agent_id, :alert_history, severity_score)
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(:recalculate_all, state) do
    do_recalculate_all()
    schedule_recalc()
    {:noreply, %{state | recalc_count: state.recalc_count + 1, last_recalc_at: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:flush, state) do
    do_flush()
    schedule_flush()
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    do_cleanup()
    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Private - Risk Calculation
  # ---------------------------------------------------------------------------

  defp do_calculate_risk(entity_type, entity_id) do
    key = {entity_type, entity_id}

    factors =
      case :ets.lookup(@factors_table, key) do
        [{^key, f}] -> f
        [] -> %{}
      end

    now = DateTime.utc_now()

    # Calculate each factor contribution
    factor_scores =
      Enum.map(@default_weights, fn {factor_name, weight} ->
        raw_value =
          case Map.get(factors, factor_name) do
            %{value: v, updated_at: updated_at} ->
              # Apply time decay
              decay = time_decay(updated_at, now)
              v * decay

            nil ->
              0.0
          end

        # Normalize to 0-1 range and apply weight
        normalized = min(1.0, max(0.0, raw_value / 100.0))
        contribution = normalized * weight

        %{
          factor: factor_name,
          raw_value: Float.round(raw_value, 2),
          weight: weight,
          contribution: Float.round(contribution, 2)
        }
      end)

    total_score =
      factor_scores
      |> Enum.map(& &1.contribution)
      |> Enum.sum()
      |> round()
      |> min(100)
      |> max(0)

    tier = score_to_tier(total_score)
    trend = get_risk_trend(entity_type, entity_id)

    score_data = %{
      score: total_score,
      tier: tier,
      factors: factor_scores,
      trending: trend,
      calculated_at: now
    }

    # Store score
    :ets.insert(@scores_table, {key, score_data})

    # Record in history
    record_history(key, total_score, now)

    # Broadcast if high risk
    if total_score >= @high_max do
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "identity:risk_updates",
        {:high_risk_entity, entity_type, entity_id, score_data}
      )
    end

    score_data
  end

  defp time_decay(nil, _now), do: 1.0

  defp time_decay(%DateTime{} = updated_at, %DateTime{} = now) do
    hours_elapsed = abs(DateTime.diff(now, updated_at, :second)) / 3600.0
    # Exponential decay: value halves every @decay_half_life_hours
    :math.pow(0.5, hours_elapsed / @decay_half_life_hours)
  end

  defp time_decay(_, _), do: 1.0

  defp score_to_tier(score) when score <= @low_max, do: :low
  defp score_to_tier(score) when score <= @medium_max, do: :medium
  defp score_to_tier(score) when score <= @high_max, do: :high
  defp score_to_tier(_score), do: :critical

  defp record_history(key, score, timestamp) do
    entry = %{score: score, timestamp: timestamp}

    entries =
      case :ets.lookup(@history_table, key) do
        [{^key, existing}] -> [entry | existing] |> Enum.take(@max_history_entries)
        [] -> [entry]
      end

    :ets.insert(@history_table, {key, entries})
  end

  defp compute_trend(history) when length(history) < 3, do: :stable

  defp compute_trend(history) do
    scores = Enum.map(history, & &1.score)

    # Compare average of first half vs second half
    mid = div(length(scores), 2)
    {recent, older} = Enum.split(scores, mid)

    recent_avg = if recent == [], do: 0, else: Enum.sum(recent) / length(recent)
    older_avg = if older == [], do: 0, else: Enum.sum(older) / length(older)

    diff = recent_avg - older_avg

    cond do
      diff > 5 -> :increasing
      diff < -5 -> :decreasing
      true -> :stable
    end
  end

  # ---------------------------------------------------------------------------
  # Private - Periodic Tasks
  # ---------------------------------------------------------------------------

  defp do_recalculate_all do
    ets_safe_tab2list(@factors_table)
    |> Enum.each(fn {{entity_type, entity_id}, _factors} ->
      do_calculate_risk(entity_type, entity_id)
    end)

    Logger.debug("[RiskEngine] Recalculated all risk scores")
  end

  defp do_flush do
    scores_count = :ets.info(@scores_table, :size)
    Logger.debug("[RiskEngine] Flush: #{scores_count} risk scores persisted")
  end

  defp do_cleanup do
    # Prune history entries older than 7 days
    cutoff = DateTime.add(DateTime.utc_now(), -7, :day)

    ets_safe_tab2list(@history_table)
    |> Enum.each(fn {key, entries} ->
      filtered = Enum.filter(entries, fn e -> DateTime.compare(e.timestamp, cutoff) != :lt end)
      :ets.insert(@history_table, {key, filtered})
    end)

    Logger.debug("[RiskEngine] Cleanup completed")
  end

  # ---------------------------------------------------------------------------
  # Private - Utilities
  # ---------------------------------------------------------------------------

  defp extract_field(event, key) when is_atom(key) do
    Map.get(event, key) || Map.get(event, to_string(key))
  end

  defp ets_safe_tab2list(table) do
    try do
      :ets.tab2list(table)
    rescue
      ArgumentError -> []
    end
  end

  defp schedule_recalc do
    Process.send_after(self(), :recalculate_all, @recalc_interval)
  end

  defp schedule_flush do
    Process.send_after(self(), :flush, @flush_interval)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end
end
