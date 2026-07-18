defmodule TamanduaServer.Detection.MIADetector do
  @moduledoc """
  GenServer for Membership Inference Attack (MIA) detection.

  Tracks user sessions and detects patterns indicative of MIA attempts:
  - Sustained probing (>100 queries with MIA pattern)
  - Session-level risk aggregation
  - Coordinated multi-session attacks

  MIA attacks attempt to determine if specific data samples were used
  to train a model, representing a critical privacy threat.

  Usage:
      MIADetector.track_query("user-123", %{confidence: 0.95, predicted_class: 1, ...})
      {:ok, risk} = MIADetector.analyze_session("user-123")
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub

  @ets_table :mia_sessions
  @alert_threshold_queries 100
  @session_ttl_seconds 1800  # 30 minutes
  @garbage_collection_interval :timer.minutes(5)
  @probing_confidence_threshold 0.15  # Cliff threshold

  # ============================================================================
  # Types
  # ============================================================================

  @type query_record :: %{
          query_hash: String.t(),
          confidence: float(),
          predicted_class: non_neg_integer(),
          timestamp: DateTime.t()
        }

  @type session_state :: %{
          user_id: String.t(),
          queries: [query_record()],
          risk_score: float(),
          alert_triggered: boolean(),
          created_at: DateTime.t(),
          updated_at: DateTime.t(),
          attack_indicators: map()
        }

  @type risk_level :: :critical | :high | :medium | :low | :none

  @type risk_assessment :: %{
          is_attack: boolean(),
          attack_type: atom(),
          risk_level: risk_level(),
          membership_score: float(),
          confidence: float(),
          details: map(),
          recommendations: [String.t()]
        }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Track a query from a user session.

  Stores query metadata for MIA pattern detection.
  """
  @spec track_query(String.t(), map()) :: :ok
  def track_query(user_id, query_data) do
    GenServer.cast(__MODULE__, {:track_query, user_id, query_data})
  end

  @doc """
  Analyze a user session for MIA patterns.

  Returns a risk assessment with attack type, severity, and recommendations.
  """
  @spec analyze_session(String.t()) :: {:ok, risk_assessment()} | {:error, :session_not_found}
  def analyze_session(user_id) do
    GenServer.call(__MODULE__, {:analyze_session, user_id})
  end

  @doc """
  Get session statistics for a user.
  """
  @spec get_session_stats(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_session_stats(user_id) do
    GenServer.call(__MODULE__, {:get_session_stats, user_id})
  end

  @doc """
  Get all active sessions with their risk levels.
  """
  @spec list_sessions() :: [%{user_id: String.t(), query_count: integer(), risk_level: risk_level()}]
  def list_sessions do
    GenServer.call(__MODULE__, :list_sessions)
  end

  @doc """
  Check if a user has triggered an MIA alert.
  """
  @spec alert_triggered?(String.t()) :: boolean()
  def alert_triggered?(user_id) do
    GenServer.call(__MODULE__, {:alert_triggered, user_id})
  end

  @doc """
  Clear a user session.
  """
  @spec clear_session(String.t()) :: :ok
  def clear_session(user_id) do
    GenServer.cast(__MODULE__, {:clear_session, user_id})
  end

  @doc """
  Reset alert status for a user.
  """
  @spec reset_alert(String.t()) :: :ok
  def reset_alert(user_id) do
    GenServer.cast(__MODULE__, {:reset_alert, user_id})
  end

  @doc """
  Get overall MIA detection statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
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

    # Schedule garbage collection
    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)

    state = %{
      table: table,
      stats: %{
        total_queries_tracked: 0,
        alerts_triggered: 0,
        sessions_analyzed: 0,
        attacks_detected: 0,
        confidence_cliff_count: 0,
        statistical_probe_count: 0,
        shadow_model_count: 0
      }
    }

    Logger.info("[MIADetector] Started")
    {:ok, state}
  end

  @impl true
  def handle_cast({:track_query, user_id, query_data}, state) do
    now = DateTime.utc_now()

    query_record = %{
      query_hash: query_data[:query_hash] || query_data["query_hash"] || hash_query(query_data),
      confidence: query_data[:confidence] || query_data["confidence"],
      predicted_class: query_data[:predicted_class] || query_data["predicted_class"] || 0,
      timestamp: now
    }

    session = get_or_create_session(user_id)

    # Add query to session
    updated_queries = [query_record | session.queries]
    |> Enum.take(1000)  # Keep last 1000 queries

    updated_session = %{
      session
      | queries: updated_queries,
        updated_at: now
    }

    # Check for sustained probing alert
    updated_session =
      if length(updated_queries) >= @alert_threshold_queries and not session.alert_triggered do
        risk = analyze_session_internal(updated_session)

        if risk.is_attack do
          # Trigger alert
          broadcast_alert(user_id, risk)
          %{updated_session | alert_triggered: true, risk_score: risk.membership_score}
        else
          updated_session
        end
      else
        updated_session
      end

    :ets.insert(@ets_table, {user_id, updated_session})

    new_stats = Map.update!(state.stats, :total_queries_tracked, &(&1 + 1))
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:clear_session, user_id}, state) do
    :ets.delete(@ets_table, user_id)
    Logger.debug("[MIADetector] Cleared session for user #{user_id}")
    {:noreply, state}
  end

  @impl true
  def handle_cast({:reset_alert, user_id}, state) do
    case :ets.lookup(@ets_table, user_id) do
      [{^user_id, session}] ->
        updated_session = %{session | alert_triggered: false}
        :ets.insert(@ets_table, {user_id, updated_session})

      [] ->
        :ok
    end

    {:noreply, state}
  end

  @impl true
  def handle_call({:analyze_session, user_id}, _from, state) do
    result =
      case :ets.lookup(@ets_table, user_id) do
        [{^user_id, session}] ->
          risk = analyze_session_internal(session)

          # Update stats
          new_stats =
            state.stats
            |> Map.update!(:sessions_analyzed, &(&1 + 1))
            |> then(fn stats ->
              if risk.is_attack do
                stats
                |> Map.update!(:attacks_detected, &(&1 + 1))
                |> update_attack_type_count(risk.attack_type)
              else
                stats
              end
            end)

          {:ok, risk, new_stats}

        [] ->
          {:error, :session_not_found, state.stats}
      end

    case result do
      {:ok, risk, new_stats} ->
        {:reply, {:ok, risk}, %{state | stats: new_stats}}

      {:error, reason, _stats} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_session_stats, user_id}, _from, state) do
    result =
      case :ets.lookup(@ets_table, user_id) do
        [{^user_id, session}] ->
          confidences = Enum.map(session.queries, & &1.confidence)

          stats = %{
            user_id: user_id,
            query_count: length(session.queries),
            unique_queries: session.queries |> Enum.map(& &1.query_hash) |> Enum.uniq() |> length(),
            mean_confidence: safe_mean(confidences),
            std_confidence: safe_std(confidences),
            class_distribution: class_distribution(session.queries),
            alert_triggered: session.alert_triggered,
            risk_score: session.risk_score,
            created_at: session.created_at,
            updated_at: session.updated_at
          }

          {:ok, stats}

        [] ->
          {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call(:list_sessions, _from, state) do
    sessions =
      :ets.foldl(
        fn {user_id, session}, acc ->
          risk_level = calculate_risk_level(session)

          [
            %{
              user_id: user_id,
              query_count: length(session.queries),
              risk_level: risk_level,
              alert_triggered: session.alert_triggered
            }
            | acc
          ]
        end,
        [],
        @ets_table
      )

    {:reply, sessions, state}
  end

  @impl true
  def handle_call({:alert_triggered, user_id}, _from, state) do
    result =
      case :ets.lookup(@ets_table, user_id) do
        [{^user_id, session}] -> session.alert_triggered
        [] -> false
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_info(:garbage_collect, state) do
    now = DateTime.utc_now()
    cutoff = DateTime.add(now, -@session_ttl_seconds, :second)

    stale_keys =
      :ets.foldl(
        fn {user_id, session}, acc ->
          if DateTime.compare(session.updated_at, cutoff) == :lt do
            [user_id | acc]
          else
            acc
          end
        end,
        [],
        @ets_table
      )

    Enum.each(stale_keys, fn key -> :ets.delete(@ets_table, key) end)

    if length(stale_keys) > 0 do
      Logger.debug("[MIADetector] Garbage collected #{length(stale_keys)} stale sessions")
    end

    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp get_or_create_session(user_id) do
    case :ets.lookup(@ets_table, user_id) do
      [{^user_id, session}] ->
        session

      [] ->
        now = DateTime.utc_now()

        %{
          user_id: user_id,
          queries: [],
          risk_score: 0.0,
          alert_triggered: false,
          created_at: now,
          updated_at: now,
          attack_indicators: %{}
        }
    end
  end

  defp analyze_session_internal(session) do
    queries = session.queries

    if length(queries) < 5 do
      no_risk(:insufficient_data)
    else
      # Run all detection methods
      confidence_risk = detect_confidence_cliff(queries)
      statistical_risk = detect_statistical_probing(queries)
      variation_risk = detect_query_variations(queries)

      # Return highest risk
      risks = [confidence_risk, statistical_risk, variation_risk]
      detected = Enum.filter(risks, & &1.is_attack)

      if Enum.empty?(detected) do
        no_risk(:no_attack_detected)
      else
        Enum.max_by(detected, fn r -> risk_priority(r.risk_level) end)
      end
    end
  end

  defp detect_confidence_cliff(queries) do
    confidences = Enum.map(queries, & &1.confidence) |> Enum.sort()

    # Find cliff patterns
    cliffs =
      confidences
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.with_index()
      |> Enum.filter(fn {[a, b], _idx} ->
        abs(a - b) > @probing_confidence_threshold
      end)

    if length(cliffs) > 0 do
      max_drop = cliffs |> Enum.map(fn {[a, b], _} -> abs(a - b) end) |> Enum.max()
      membership_score = calculate_cliff_membership_score(cliffs, confidences)

      %{
        is_attack: true,
        attack_type: :confidence_cliff,
        risk_level: assess_risk_level(length(cliffs), max_drop),
        membership_score: membership_score,
        confidence: min(0.6 + length(cliffs) * 0.1, 0.95),
        details: %{
          cliff_count: length(cliffs),
          max_drop: max_drop,
          query_count: length(queries)
        },
        recommendations: [
          "Add noise to confidence scores",
          "Implement confidence rounding",
          "Monitor for continued probing"
        ]
      }
    else
      no_risk(:no_cliff_detected)
    end
  end

  defp detect_statistical_probing(queries) do
    if length(queries) < 20 do
      no_risk(:insufficient_queries)
    else
      confidences = Enum.map(queries, & &1.confidence)

      # Check for uniform distribution (systematic sampling)
      histogram = build_histogram(confidences, 10)
      uniformity = calculate_uniformity(histogram)

      if uniformity > 0.85 do
        membership_score = calculate_membership_score(confidences)

        %{
          is_attack: true,
          attack_type: :statistical_probe,
          risk_level: :high,
          membership_score: membership_score,
          confidence: uniformity,
          details: %{
            uniformity: uniformity,
            histogram: histogram,
            query_count: length(queries)
          },
          recommendations: [
            "Implement rate limiting",
            "Add response jitter",
            "Use differential privacy"
          ]
        }
      else
        no_risk(:no_uniform_sampling)
      end
    end
  end

  defp detect_query_variations(queries) do
    if length(queries) < 5 do
      no_risk(:insufficient_queries)
    else
      # Group by hash prefix
      groups =
        queries
        |> Enum.group_by(fn q -> String.slice(q.query_hash, 0, 8) end)
        |> Enum.filter(fn {_prefix, qs} -> length(qs) >= 5 end)

      if length(groups) > 0 do
        {_prefix, largest_group} = Enum.max_by(groups, fn {_, qs} -> length(qs) end)
        confidences = Enum.map(largest_group, & &1.confidence)
        variance = safe_variance(confidences)

        membership_score = calculate_membership_score(confidences)

        risk_level =
          if variance > 0.1 do
            :high
          else
            :medium
          end

        %{
          is_attack: true,
          attack_type: :query_variation,
          risk_level: risk_level,
          membership_score: membership_score,
          confidence: min(length(largest_group) / 10, 0.95),
          details: %{
            variation_groups: length(groups),
            largest_group_size: length(largest_group),
            confidence_variance: variance
          },
          recommendations: [
            "Implement query deduplication",
            "Add input perturbation detection",
            "Rate limit similar queries"
          ]
        }
      else
        no_risk(:no_variation_pattern)
      end
    end
  end

  defp calculate_cliff_membership_score(cliffs, _confidences) do
    if Enum.empty?(cliffs) do
      0.0
    else
      # Cliffs near 0.5 are more suspicious
      proximities =
        Enum.map(cliffs, fn {[a, b], _} ->
          mid = (a + b) / 2
          1.0 - abs(mid - 0.5) * 2
        end)

      drops = Enum.map(cliffs, fn {[a, b], _} -> abs(a - b) end)

      weighted =
        Enum.zip(drops, proximities)
        |> Enum.map(fn {d, p} -> d * p end)

      score = Enum.sum(weighted) / length(weighted)
      min(max(score, 0.0), 1.0)
    end
  end

  defp calculate_membership_score(confidences) do
    if Enum.empty?(confidences) do
      0.0
    else
      mean_conf = safe_mean(confidences)
      max_conf = Enum.max(confidences)
      std_conf = safe_std(confidences)

      mean_score = mean_conf
      variance_score = max(0, 1 - std_conf * 2)
      high_conf_score = :math.pow(max_conf, 2)

      score = 0.4 * mean_score + 0.3 * variance_score + 0.3 * high_conf_score
      min(max(score, 0.0), 1.0)
    end
  end

  defp assess_risk_level(cliff_count, max_drop) do
    cond do
      cliff_count >= 5 and max_drop > 0.3 -> :critical
      cliff_count >= 3 or max_drop > 0.25 -> :high
      cliff_count >= 2 or max_drop > 0.2 -> :medium
      true -> :low
    end
  end

  defp calculate_risk_level(session) do
    query_count = length(session.queries)

    cond do
      session.risk_score > 0.8 -> :critical
      session.risk_score > 0.6 -> :high
      session.risk_score > 0.4 -> :medium
      query_count > @alert_threshold_queries -> :low
      true -> :none
    end
  end

  defp risk_priority(:critical), do: 4
  defp risk_priority(:high), do: 3
  defp risk_priority(:medium), do: 2
  defp risk_priority(:low), do: 1
  defp risk_priority(:none), do: 0

  defp no_risk(reason) do
    %{
      is_attack: false,
      attack_type: :none,
      risk_level: :none,
      membership_score: 0.0,
      confidence: 0.0,
      details: %{reason: reason},
      recommendations: []
    }
  end

  defp build_histogram(values, bins) do
    if Enum.empty?(values) do
      List.duplicate(0, bins)
    else
      bin_width = 1.0 / bins

      Enum.reduce(values, List.duplicate(0, bins), fn val, hist ->
        bin_idx = min(trunc(val / bin_width), bins - 1)
        List.update_at(hist, bin_idx, &(&1 + 1))
      end)
    end
  end

  defp calculate_uniformity(histogram) do
    total = Enum.sum(histogram)

    if total == 0 do
      0.0
    else
      normalized = Enum.map(histogram, fn count -> count / total end)
      expected = 1.0 / length(histogram)
      std = :math.sqrt(Enum.sum(Enum.map(normalized, fn p -> :math.pow(p - expected, 2) end)) / length(normalized))
      1.0 - std
    end
  end

  defp safe_mean([]), do: 0.0
  defp safe_mean(values), do: Enum.sum(values) / length(values)

  defp safe_std([]), do: 0.0
  defp safe_std([_]), do: 0.0

  defp safe_std(values) do
    mean = safe_mean(values)
    variance = Enum.sum(Enum.map(values, fn v -> :math.pow(v - mean, 2) end)) / length(values)
    :math.sqrt(variance)
  end

  defp safe_variance([]), do: 0.0
  defp safe_variance([_]), do: 0.0

  defp safe_variance(values) do
    mean = safe_mean(values)
    Enum.sum(Enum.map(values, fn v -> :math.pow(v - mean, 2) end)) / length(values)
  end

  defp class_distribution(queries) do
    queries
    |> Enum.group_by(& &1.predicted_class)
    |> Enum.map(fn {class, qs} -> {class, length(qs)} end)
    |> Map.new()
  end

  defp hash_query(query_data) do
    data =
      query_data
      |> Enum.sort()
      |> :erlang.term_to_binary()

    :crypto.hash(:sha256, data) |> Base.encode16(case: :lower)
  end

  defp broadcast_alert(user_id, risk) do
    Logger.warning("[MIADetector] Alert triggered for user #{user_id}",
      attack_type: risk.attack_type,
      risk_level: risk.risk_level,
      membership_score: risk.membership_score
    )

    PubSub.broadcast(
      TamanduaServer.PubSub,
      "mia:alerts",
      {:mia_alert, user_id, risk}
    )
  end

  defp update_attack_type_count(stats, :confidence_cliff) do
    Map.update!(stats, :confidence_cliff_count, &(&1 + 1))
  end

  defp update_attack_type_count(stats, :statistical_probe) do
    Map.update!(stats, :statistical_probe_count, &(&1 + 1))
  end

  defp update_attack_type_count(stats, :shadow_model) do
    Map.update!(stats, :shadow_model_count, &(&1 + 1))
  end

  defp update_attack_type_count(stats, _), do: stats
end
