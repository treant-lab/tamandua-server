defmodule TamanduaServer.Detection.BaselineLearner do
  @moduledoc """
  Persistent Behavioral Baseline Learning Engine.

  Learns normal behavioral patterns per entity (agent, user, asset) and detects
  anomalies via z-score analysis. Continuously ingests telemetry from PubSub and
  maintains rolling statistical models.

  ## Baseline Types

  - `:process_execution`      - Process names, parent-child pairs, command lines
  - `:network_connection`     - Destinations, ports, protocols, byte volumes
  - `:file_access`            - File paths, extensions, operation types
  - `:authentication`         - Login times, success/fail ratios, locations
  - `:dns_query`              - Queried domains, record types, frequencies
  - `:registry_modification`  - Registry paths, value types, operations

  ## Learning Modes

  - `:learning` - First 7 days (configurable). All observations recorded, no alerts.
  - `:active`   - Detecting anomalies against the established baseline.
  - `:frozen`   - Baseline locked, no further updates.

  ## Storage Architecture

  Two ETS tables provide fast, lock-free reads on the hot path:

  * `:baseline_learner_stats`   - Statistical profiles keyed by
    `{entity_type, entity_id, feature_name}` with running mean, variance,
    count, min, max (Welford's online algorithm).

  * `:baseline_learner_config`  - Per-entity learning mode and metadata
    keyed by `{entity_type, entity_id}` with value containing mode, timestamps,
    and event counts.

  * `:baseline_learner_histograms` - Time-of-day (24 bins) and day-of-week
    (7 bins) frequency histograms per entity.

  * `:baseline_learner_categoricals` - Frequency distributions for categorical
    features (process names, destinations, etc.) per entity.

  The GenServer serializes writes and runs periodic flushes to PostgreSQL.

  ## Anomaly Detection

  Z-score analysis flags deviations > 3 standard deviations from the baseline
  mean. Rolling updates use an exponential moving average (EMA) so the baseline
  slowly adapts to legitimate behavioral drift.

  ## PubSub

  Subscribes to `"telemetry:events"` for continuous learning.
  Publishes anomalies to `"baseline:anomalies"`.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Persistence

  # ---------------------------------------------------------------------------
  # Constants
  # ---------------------------------------------------------------------------

  @stats_table :baseline_learner_stats
  @config_table :baseline_learner_config
  @histograms_table :baseline_learner_histograms
  @categoricals_table :baseline_learner_categoricals

  @baseline_types ~w(process_execution network_connection file_access authentication dns_query registry_modification)a

  @default_learning_days 7
  @z_score_threshold 3.0
  @ema_alpha 0.05
  @min_observations_for_anomaly 30

  # Periodic timers
  @flush_interval :timer.minutes(5)
  @dets_flush_interval :timer.seconds(60)
  @cleanup_interval :timer.hours(6)
  @mode_check_interval :timer.minutes(5)

  # Maximum categorical entries per feature to prevent unbounded growth
  @max_categorical_entries 500

  # DETS persistence version -- bump when record format changes to auto-reset
  @persistence_version 1

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Update the baseline for an entity with a new feature vector.

  The feature vector is a map of `%{feature_name => value}` where values
  can be numeric (for statistical tracking) or binary/atom (for categorical
  frequency tracking).

  ## Examples

      update_baseline(:process_execution, "agent-123", %{
        "process_count" => 42,
        "process_name" => "explorer.exe",
        "parent_name" => "userinit.exe"
      })
  """
  @spec update_baseline(atom(), String.t(), map()) :: :ok | {:error, :frozen}
  def update_baseline(entity_type, entity_id, feature_vector)
      when is_atom(entity_type) and is_binary(entity_id) and is_map(feature_vector) do
    GenServer.cast(__MODULE__, {:update_baseline, entity_type, entity_id, feature_vector})
  end

  @doc """
  Check whether an observation is anomalous against the learned baseline.

  Returns `{:normal | :anomalous, score, details}` where:
  - `score` is 0.0 (perfectly normal) to 1.0 (extremely anomalous)
  - `details` is a list of individual feature deviations

  ## Examples

      check_anomaly(:network_connection, "agent-123", %{
        "bytes_out" => 50_000_000,
        "dest_port" => 443
      })
      # => {:anomalous, 0.82, [%{feature: "bytes_out", z_score: 4.2, ...}]}
  """
  @spec check_anomaly(atom(), String.t(), map()) ::
          {:normal | :anomalous, float(), list(map())}
  def check_anomaly(entity_type, entity_id, feature_vector)
      when is_atom(entity_type) and is_binary(entity_id) and is_map(feature_vector) do
    mode = get_learning_status(entity_type, entity_id)

    if mode == :learning do
      {:normal, 0.0, [%{note: "Entity still in learning mode"}]}
    else
      do_check_anomaly(entity_type, entity_id, feature_vector)
    end
  end

  @doc """
  Retrieve the full baseline for an entity.

  Returns a map with statistical profiles, histograms, and categorical
  distributions, or `nil` if no baseline exists.
  """
  @spec get_baseline(atom(), String.t()) :: map() | nil
  def get_baseline(entity_type, entity_id) do
    config = lookup_config(entity_type, entity_id)

    if config do
      stats = lookup_all_stats(entity_type, entity_id)
      histograms = lookup_histograms(entity_type, entity_id)
      categoricals = lookup_categoricals(entity_type, entity_id)

      %{
        entity_type: entity_type,
        entity_id: entity_id,
        mode: config.mode,
        learning_started_at: config.started_at,
        events_processed: config.event_count,
        learning_days: config.learning_days,
        statistics: stats,
        histograms: histograms,
        categoricals: categoricals
      }
    else
      nil
    end
  end

  @doc """
  Get the current learning status for an entity.
  Returns `:learning`, `:active`, `:frozen`, or `:unknown`.
  """
  @spec get_learning_status(atom(), String.t()) :: :learning | :active | :frozen | :unknown
  def get_learning_status(entity_type, entity_id) do
    case lookup_config(entity_type, entity_id) do
      nil -> :unknown
      config -> config.mode
    end
  end

  @doc """
  Flush all in-memory baselines to PostgreSQL.
  Called periodically by the GenServer and can be invoked manually.
  """
  @spec flush_to_db() :: :ok
  def flush_to_db do
    GenServer.cast(__MODULE__, :flush_to_db)
  end

  @doc """
  Reset the baseline for a specific entity, clearing all learned data.
  """
  @spec reset_baseline(atom(), String.t()) :: :ok
  def reset_baseline(entity_type, entity_id) do
    GenServer.cast(__MODULE__, {:reset_baseline, entity_type, entity_id})
  end

  @doc """
  Set the learning mode for an entity. Valid modes: `:learning`, `:active`, `:frozen`.
  """
  @spec set_mode(atom(), String.t(), :learning | :active | :frozen) :: :ok
  def set_mode(entity_type, entity_id, mode) when mode in [:learning, :active, :frozen] do
    GenServer.cast(__MODULE__, {:set_mode, entity_type, entity_id, mode})
  end

  @doc """
  Get global statistics about the baseline learner.
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
    # Initialize DETS-backed ETS tables. On startup, previous baselines are
    # loaded from DETS so learning does not start from zero after a restart.
    dets_opts = [version: @persistence_version]

    {:ok, dets_stats} =
      Persistence.init_persistent_ets(@stats_table, "baseline_stats", dets_opts)

    {:ok, dets_config} =
      Persistence.init_persistent_ets(@config_table, "baseline_config", dets_opts)

    {:ok, dets_histograms} =
      Persistence.init_persistent_ets(@histograms_table, "baseline_histograms", dets_opts)

    {:ok, dets_categoricals} =
      Persistence.init_persistent_ets(@categoricals_table, "baseline_categoricals", dets_opts)

    # Subscribe to telemetry events
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "telemetry:events")

    # Schedule periodic tasks
    schedule_flush()
    schedule_dets_flush()
    schedule_cleanup()
    schedule_mode_check()

    restored_entities = :ets.info(@config_table, :size)
    restored_features = :ets.info(@stats_table, :size)

    Logger.info(
      "[BaselineLearner] Initialized with #{length(@baseline_types)} baseline types, " <>
        "restored #{restored_entities} entities and #{restored_features} feature stats from DETS"
    )

    {:ok,
     %{
       flush_count: 0,
       last_flush_at: nil,
       events_since_flush: 0,
       dets_refs: %{
         stats: dets_stats,
         config: dets_config,
         histograms: dets_histograms,
         categoricals: dets_categoricals
       }
     }}
  end

  @impl true
  def handle_cast({:update_baseline, entity_type, entity_id, feature_vector}, state) do
    config = ensure_config(entity_type, entity_id)

    if config.mode == :frozen do
      {:noreply, state}
    else
      do_update_baseline(entity_type, entity_id, feature_vector, config)
      {:noreply, %{state | events_since_flush: state.events_since_flush + 1}}
    end
  end

  @impl true
  def handle_cast(:flush_to_db, state) do
    do_flush_to_db()
    {:noreply, %{state | flush_count: state.flush_count + 1, last_flush_at: DateTime.utc_now(), events_since_flush: 0}}
  end

  @impl true
  def handle_cast({:reset_baseline, entity_type, entity_id}, state) do
    do_reset_baseline(entity_type, entity_id)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:set_mode, entity_type, entity_id, mode}, state) do
    config = ensure_config(entity_type, entity_id)
    updated = %{config | mode: mode}
    # Write-through: mode changes are significant and must survive restarts
    Persistence.write_through(
      @config_table,
      state.dets_refs.config,
      {entity_type, entity_id},
      updated
    )
    Logger.info("[BaselineLearner] Set mode for #{entity_type}/#{entity_id} to #{mode}")
    {:noreply, state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    config_entries = ets_safe_tab2list(@config_table)

    learning_count =
      Enum.count(config_entries, fn {_key, config} -> config.mode == :learning end)

    active_count =
      Enum.count(config_entries, fn {_key, config} -> config.mode == :active end)

    frozen_count =
      Enum.count(config_entries, fn {_key, config} -> config.mode == :frozen end)

    total_features = :ets.info(@stats_table, :size)
    total_histograms = :ets.info(@histograms_table, :size)
    total_categoricals = :ets.info(@categoricals_table, :size)

    total_events =
      Enum.reduce(config_entries, 0, fn {_key, config}, acc -> acc + config.event_count end)

    result = %{
      total_entities: length(config_entries),
      learning: learning_count,
      active: active_count,
      frozen: frozen_count,
      total_features_tracked: total_features,
      total_histograms: total_histograms,
      total_categoricals: total_categoricals,
      total_events_processed: total_events,
      flush_count: state.flush_count,
      last_flush_at: state.last_flush_at,
      events_since_flush: state.events_since_flush,
      baseline_types: @baseline_types
    }

    {:reply, result, state}
  end

  # Handle PubSub telemetry events
  @impl true
  def handle_info({:telemetry_event, event}, state) do
    process_telemetry_event(event)
    {:noreply, state}
  end

  @impl true
  def handle_info(:flush, state) do
    do_flush_to_db()
    schedule_flush()

    {:noreply,
     %{
       state
       | flush_count: state.flush_count + 1,
         last_flush_at: DateTime.utc_now(),
         events_since_flush: 0
     }}
  end

  @impl true
  def handle_info(:dets_flush, state) do
    # Periodic batch flush of all ETS tables to DETS for persistence
    Persistence.flush(@stats_table, state.dets_refs.stats)
    Persistence.flush(@config_table, state.dets_refs.config)
    Persistence.flush(@histograms_table, state.dets_refs.histograms)
    Persistence.flush(@categoricals_table, state.dets_refs.categoricals)

    schedule_dets_flush()

    Logger.debug("[BaselineLearner] DETS flush completed")
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    do_cleanup()
    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(:check_modes, state) do
    check_learning_completions()
    schedule_mode_check()
    {:noreply, state}
  end

  # Catch-all for unknown messages (PubSub broadcasts we don't handle)
  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    # Final flush to DETS before shutdown
    if dets_refs = state[:dets_refs] do
      Logger.info("[BaselineLearner] Shutting down, flushing state to DETS")
      Persistence.flush(@stats_table, dets_refs.stats)
      Persistence.flush(@config_table, dets_refs.config)
      Persistence.flush(@histograms_table, dets_refs.histograms)
      Persistence.flush(@categoricals_table, dets_refs.categoricals)

      Persistence.close(dets_refs.stats)
      Persistence.close(dets_refs.config)
      Persistence.close(dets_refs.histograms)
      Persistence.close(dets_refs.categoricals)
    end

    :ok
  end

  # ---------------------------------------------------------------------------
  # Private - Update Logic
  # ---------------------------------------------------------------------------

  defp do_update_baseline(entity_type, entity_id, feature_vector, config) do
    now = DateTime.utc_now()

    # Update event count
    updated_config = %{config | event_count: config.event_count + 1}
    :ets.insert(@config_table, {{entity_type, entity_id}, updated_config})

    # Process each feature
    Enum.each(feature_vector, fn {feature_name, value} ->
      feature_key = {entity_type, entity_id, feature_name}

      cond do
        is_number(value) ->
          update_numeric_stats(feature_key, value, config.mode)

        is_binary(value) or is_atom(value) ->
          update_categorical(feature_key, to_string(value))

        true ->
          :skip
      end
    end)

    # Update time-of-day and day-of-week histograms
    update_temporal_histograms(entity_type, entity_id, now)
  end

  defp update_numeric_stats(feature_key, value, mode) do
    case :ets.lookup(@stats_table, feature_key) do
      [{^feature_key, stats}] ->
        updated =
          if mode == :learning do
            # Pure Welford's online algorithm during learning
            welford_update(stats, value)
          else
            # EMA-blended update during active mode for drift adaptation
            ema_update(stats, value)
          end

        :ets.insert(@stats_table, {feature_key, updated})

      [] ->
        # First observation
        initial = %{
          count: 1,
          mean: value * 1.0,
          m2: 0.0,
          min: value,
          max: value,
          last_value: value,
          last_updated: System.system_time(:second)
        }

        :ets.insert(@stats_table, {feature_key, initial})
    end
  end

  defp welford_update(stats, value) do
    count = stats.count + 1
    delta = value - stats.mean
    new_mean = stats.mean + delta / count
    delta2 = value - new_mean
    new_m2 = stats.m2 + delta * delta2

    %{
      stats
      | count: count,
        mean: new_mean,
        m2: new_m2,
        min: min(stats.min, value),
        max: max(stats.max, value),
        last_value: value,
        last_updated: System.system_time(:second)
    }
  end

  defp ema_update(stats, value) do
    count = stats.count + 1
    # Exponential moving average for mean
    new_mean = stats.mean * (1 - @ema_alpha) + value * @ema_alpha
    # Update M2 with Welford step (still useful for variance estimation)
    delta = value - stats.mean
    delta2 = value - new_mean
    new_m2 = stats.m2 + delta * delta2

    %{
      stats
      | count: count,
        mean: new_mean,
        m2: new_m2,
        min: min(stats.min, value),
        max: max(stats.max, value),
        last_value: value,
        last_updated: System.system_time(:second)
    }
  end

  defp update_categorical(feature_key, value) do
    hist_key = {:cat, feature_key}

    case :ets.lookup(@categoricals_table, hist_key) do
      [{^hist_key, freq_map}] ->
        current_count = Map.get(freq_map, value, 0)

        updated =
          if map_size(freq_map) >= @max_categorical_entries and current_count == 0 do
            # Evict least frequent entry to make room
            {min_key, _} = Enum.min_by(freq_map, fn {_k, v} -> v end)
            freq_map |> Map.delete(min_key) |> Map.put(value, 1)
          else
            Map.put(freq_map, value, current_count + 1)
          end

        :ets.insert(@categoricals_table, {hist_key, updated})

      [] ->
        :ets.insert(@categoricals_table, {hist_key, %{value => 1}})
    end
  end

  defp update_temporal_histograms(entity_type, entity_id, %DateTime{} = now) do
    hour = now.hour
    day_of_week = Date.day_of_week(DateTime.to_date(now))
    hist_key = {:temporal, entity_type, entity_id}

    case :ets.lookup(@histograms_table, hist_key) do
      [{^hist_key, histograms}] ->
        # Update hour-of-day histogram (24 bins)
        hour_hist = histograms.hour_of_day
        updated_hour = Map.update(hour_hist, hour, 1, &(&1 + 1))

        # Update day-of-week histogram (7 bins)
        dow_hist = histograms.day_of_week
        updated_dow = Map.update(dow_hist, day_of_week, 1, &(&1 + 1))

        updated = %{histograms | hour_of_day: updated_hour, day_of_week: updated_dow}
        :ets.insert(@histograms_table, {hist_key, updated})

      [] ->
        initial = %{
          hour_of_day: %{hour => 1},
          day_of_week: %{day_of_week => 1}
        }

        :ets.insert(@histograms_table, {hist_key, initial})
    end
  end

  # ---------------------------------------------------------------------------
  # Private - Anomaly Detection
  # ---------------------------------------------------------------------------

  defp do_check_anomaly(entity_type, entity_id, feature_vector) do
    deviations =
      Enum.reduce(feature_vector, [], fn {feature_name, value}, acc ->
        feature_key = {entity_type, entity_id, feature_name}

        deviation =
          cond do
            is_number(value) ->
              check_numeric_anomaly(feature_key, value)

            is_binary(value) or is_atom(value) ->
              check_categorical_anomaly(feature_key, to_string(value))

            true ->
              nil
          end

        if deviation, do: [deviation | acc], else: acc
      end)

    # Add temporal anomaly check
    temporal_deviation = check_temporal_anomaly(entity_type, entity_id)
    all_deviations = if temporal_deviation, do: [temporal_deviation | deviations], else: deviations

    if all_deviations == [] do
      {:normal, 0.0, []}
    else
      # Composite score: average of individual anomaly scores
      anomaly_scores = Enum.map(all_deviations, & &1.anomaly_score)
      max_score = Enum.max(anomaly_scores)
      avg_score = Enum.sum(anomaly_scores) / length(anomaly_scores)
      # Use weighted combination favoring max anomaly
      composite = max_score * 0.7 + avg_score * 0.3

      status = if composite > 0.5, do: :anomalous, else: :normal
      {status, Float.round(composite, 4), all_deviations}
    end
  end

  defp check_numeric_anomaly(feature_key, value) do
    case :ets.lookup(@stats_table, feature_key) do
      [{^feature_key, stats}] when stats.count >= @min_observations_for_anomaly ->
        stddev = compute_stddev(stats)

        if stddev > 0.0 do
          z_score = abs(value - stats.mean) / stddev

          if z_score > @z_score_threshold do
            anomaly_score = min(1.0, z_score / (@z_score_threshold * 2))

            %{
              feature: elem(feature_key, 2),
              type: :numeric_deviation,
              z_score: Float.round(z_score, 2),
              value: value,
              baseline_mean: Float.round(stats.mean, 2),
              baseline_stddev: Float.round(stddev, 2),
              baseline_min: stats.min,
              baseline_max: stats.max,
              observations: stats.count,
              anomaly_score: anomaly_score
            }
          else
            nil
          end
        else
          # Zero stddev means all values were the same
          if value != stats.mean do
            %{
              feature: elem(feature_key, 2),
              type: :novel_value,
              value: value,
              baseline_mean: stats.mean,
              observations: stats.count,
              anomaly_score: 0.6
            }
          else
            nil
          end
        end

      _ ->
        nil
    end
  end

  defp check_categorical_anomaly(feature_key, value) do
    hist_key = {:cat, feature_key}

    case :ets.lookup(@categoricals_table, hist_key) do
      [{^hist_key, freq_map}] when map_size(freq_map) > 0 ->
        total = Enum.sum(Map.values(freq_map))

        if total >= @min_observations_for_anomaly do
          count = Map.get(freq_map, value, 0)
          frequency = count / total

          if count == 0 do
            # Never-before-seen categorical value
            %{
              feature: elem(feature_key, 2),
              type: :novel_category,
              value: value,
              known_values: map_size(freq_map),
              total_observations: total,
              anomaly_score: 0.7
            }
          else
            # Very rare value (below 1% frequency)
            if frequency < 0.01 do
              %{
                feature: elem(feature_key, 2),
                type: :rare_category,
                value: value,
                frequency: Float.round(frequency, 6),
                count: count,
                total_observations: total,
                anomaly_score: 0.4
              }
            else
              nil
            end
          end
        else
          nil
        end

      _ ->
        nil
    end
  end

  defp check_temporal_anomaly(entity_type, entity_id) do
    hist_key = {:temporal, entity_type, entity_id}
    now = DateTime.utc_now()
    current_hour = now.hour

    case :ets.lookup(@histograms_table, hist_key) do
      [{^hist_key, histograms}] ->
        hour_hist = histograms.hour_of_day
        total = Enum.sum(Map.values(hour_hist))

        if total >= @min_observations_for_anomaly do
          hour_count = Map.get(hour_hist, current_hour, 0)
          hour_frequency = hour_count / total
          expected_frequency = 1.0 / 24.0

          # Flag if this hour has < 10% of expected activity
          if hour_frequency < expected_frequency * 0.1 and hour_count < 3 do
            %{
              feature: "time_of_day",
              type: :unusual_time,
              current_hour: current_hour,
              hour_frequency: Float.round(hour_frequency, 4),
              expected_frequency: Float.round(expected_frequency, 4),
              total_observations: total,
              anomaly_score: 0.5
            }
          else
            nil
          end
        else
          nil
        end

      _ ->
        nil
    end
  end

  # ---------------------------------------------------------------------------
  # Private - Config Management
  # ---------------------------------------------------------------------------

  defp ensure_config(entity_type, entity_id) do
    case lookup_config(entity_type, entity_id) do
      nil ->
        config = %{
          mode: :learning,
          started_at: DateTime.utc_now(),
          learning_days: @default_learning_days,
          event_count: 0
        }

        :ets.insert(@config_table, {{entity_type, entity_id}, config})
        config

      config ->
        config
    end
  end

  defp lookup_config(entity_type, entity_id) do
    case :ets.lookup(@config_table, {entity_type, entity_id}) do
      [{_key, config}] -> config
      [] -> nil
    end
  end

  defp lookup_all_stats(entity_type, entity_id) do
    # Pattern match on ETS to find all features for this entity
    pattern = {{entity_type, entity_id, :_}, :_}

    :ets.match_object(@stats_table, pattern)
    |> Enum.map(fn {{_et, _eid, feature_name}, stats} ->
      stddev = compute_stddev(stats)

      %{
        feature: feature_name,
        count: stats.count,
        mean: Float.round(stats.mean, 4),
        stddev: Float.round(stddev, 4),
        min: stats.min,
        max: stats.max,
        last_value: stats.last_value
      }
    end)
  end

  defp lookup_histograms(entity_type, entity_id) do
    hist_key = {:temporal, entity_type, entity_id}

    case :ets.lookup(@histograms_table, hist_key) do
      [{^hist_key, histograms}] -> histograms
      [] -> %{hour_of_day: %{}, day_of_week: %{}}
    end
  end

  defp lookup_categoricals(entity_type, entity_id) do
    # Scan for all categorical features for this entity
    # Keys are {:cat, {entity_type, entity_id, feature_name}}
    ets_safe_tab2list(@categoricals_table)
    |> Enum.filter(fn
      {{:cat, {^entity_type, ^entity_id, _feature}}, _} -> true
      _ -> false
    end)
    |> Enum.map(fn {{:cat, {_et, _eid, feature_name}}, freq_map} ->
      total = Enum.sum(Map.values(freq_map))
      top_values = freq_map |> Enum.sort_by(fn {_k, v} -> v end, :desc) |> Enum.take(20)

      %{
        feature: feature_name,
        unique_values: map_size(freq_map),
        total_observations: total,
        top_values: Enum.map(top_values, fn {k, v} -> %{value: k, count: v} end)
      }
    end)
  end

  # ---------------------------------------------------------------------------
  # Private - Telemetry Event Processing
  # ---------------------------------------------------------------------------

  defp process_telemetry_event(event) do
    agent_id = extract_field(event, :agent_id)
    event_type = extract_field(event, :event_type)

    if agent_id do
      baseline_type = classify_event_type(event_type)

      if baseline_type do
        feature_vector = extract_features(baseline_type, event)

        if map_size(feature_vector) > 0 do
          update_baseline(baseline_type, agent_id, feature_vector)

          # Also update user-level baseline if user info is available
          user_id = extract_field(event, :user) || extract_field(event, :user_name)

          if user_id do
            update_baseline(baseline_type, "user:#{user_id}", feature_vector)
          end
        end
      end
    end
  end

  defp classify_event_type(event_type) when is_binary(event_type) do
    cond do
      event_type in ~w(process_create process_start process_execution) -> :process_execution
      event_type in ~w(network_connect network_connection tcp_connect udp_connect) -> :network_connection
      event_type in ~w(file_create file_write file_delete file_rename file_access) -> :file_access
      event_type in ~w(logon_success logon_failure authentication login) -> :authentication
      event_type in ~w(dns_query dns_response dns_lookup) -> :dns_query
      event_type in ~w(registry_create registry_set registry_delete registry_modification) -> :registry_modification
      true -> nil
    end
  end

  defp classify_event_type(_), do: nil

  defp extract_features(:process_execution, event) do
    features = %{}

    features =
      case extract_field(event, :process_name) do
        nil -> features
        v -> Map.put(features, "process_name", v)
      end

    features =
      case extract_field(event, :parent_process_name) do
        nil -> features
        v -> Map.put(features, "parent_process_name", v)
      end

    features =
      case extract_field(event, :command_line) do
        nil -> features
        v -> Map.put(features, "command_line_length", String.length(v))
      end

    features
  end

  defp extract_features(:network_connection, event) do
    features = %{}

    features =
      case extract_field(event, :dest_ip) || extract_field(event, :destination_ip) do
        nil -> features
        v -> Map.put(features, "dest_ip", v)
      end

    features =
      case extract_field(event, :dest_port) || extract_field(event, :destination_port) do
        nil -> features
        v when is_number(v) -> Map.put(features, "dest_port", v)
        v when is_binary(v) -> Map.put(features, "dest_port", parse_number(v, 0))
        _ -> features
      end

    features =
      case extract_field(event, :bytes_sent) || extract_field(event, :bytes_out) do
        nil -> features
        v when is_number(v) -> Map.put(features, "bytes_sent", v)
        _ -> features
      end

    features
  end

  defp extract_features(:file_access, event) do
    features = %{}

    features =
      case extract_field(event, :file_path) || extract_field(event, :path) do
        nil ->
          features

        v ->
          ext = Path.extname(v)
          features = Map.put(features, "file_extension", ext)
          Map.put(features, "file_path_depth", length(String.split(v, ["\\", "/"])))
      end

    features =
      case extract_field(event, :operation) do
        nil -> features
        v -> Map.put(features, "operation", v)
      end

    features
  end

  defp extract_features(:authentication, event) do
    features = %{}

    features =
      case extract_field(event, :status) || extract_field(event, :event_type) do
        nil -> features
        v -> Map.put(features, "auth_status", v)
      end

    features =
      case extract_field(event, :source_ip) || extract_field(event, :ip_address) do
        nil -> features
        v -> Map.put(features, "source_ip", v)
      end

    features
  end

  defp extract_features(:dns_query, event) do
    features = %{}

    features =
      case extract_field(event, :domain) || extract_field(event, :query_name) do
        nil -> features
        v -> Map.put(features, "query_domain", v)
      end

    features =
      case extract_field(event, :record_type) || extract_field(event, :query_type) do
        nil -> features
        v -> Map.put(features, "record_type", v)
      end

    features
  end

  defp extract_features(:registry_modification, event) do
    features = %{}

    features =
      case extract_field(event, :registry_path) || extract_field(event, :key_path) do
        nil -> features
        v -> Map.put(features, "registry_path", v)
      end

    features =
      case extract_field(event, :operation) do
        nil -> features
        v -> Map.put(features, "registry_operation", v)
      end

    features
  end

  defp extract_features(_type, _event), do: %{}

  # ---------------------------------------------------------------------------
  # Private - Periodic Tasks
  # ---------------------------------------------------------------------------

  defp do_flush_to_db do
    # In production this would persist to PostgreSQL. For now we log stats.
    config_count = :ets.info(@config_table, :size)
    stats_count = :ets.info(@stats_table, :size)

    Logger.debug(
      "[BaselineLearner] Flushed to DB: #{config_count} entities, #{stats_count} feature stats"
    )
  end

  defp do_cleanup do
    # Remove stale entries (not updated in 30 days)
    cutoff = System.system_time(:second) - 30 * 24 * 3600

    ets_safe_tab2list(@stats_table)
    |> Enum.each(fn {key, stats} ->
      if stats.last_updated < cutoff do
        :ets.delete(@stats_table, key)
      end
    end)

    Logger.debug("[BaselineLearner] Cleanup completed")
  end

  defp check_learning_completions do
    now = DateTime.utc_now()

    ets_safe_tab2list(@config_table)
    |> Enum.each(fn {{entity_type, entity_id}, config} ->
      if config.mode == :learning do
        days_elapsed = DateTime.diff(now, config.started_at, :second) / 86_400

        if days_elapsed >= config.learning_days do
          updated = %{config | mode: :active}
          :ets.insert(@config_table, {{entity_type, entity_id}, updated})

          Logger.info(
            "[BaselineLearner] #{entity_type}/#{entity_id} transitioned to active mode after #{config.learning_days} days"
          )

          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "baseline:status",
            {:baseline_active, entity_type, entity_id}
          )
        end
      end
    end)
  end

  defp do_reset_baseline(entity_type, entity_id) do
    # Delete config
    :ets.delete(@config_table, {entity_type, entity_id})

    # Delete all stats for this entity
    pattern = {{entity_type, entity_id, :_}, :_}

    :ets.match_object(@stats_table, pattern)
    |> Enum.each(fn {key, _} -> :ets.delete(@stats_table, key) end)

    # Delete histograms
    :ets.delete(@histograms_table, {:temporal, entity_type, entity_id})

    # Delete categoricals
    ets_safe_tab2list(@categoricals_table)
    |> Enum.each(fn
      {{:cat, {^entity_type, ^entity_id, _}}, _} = entry ->
        :ets.delete(@categoricals_table, elem(entry, 0))

      _ ->
        :ok
    end)

    Logger.info("[BaselineLearner] Reset baseline for #{entity_type}/#{entity_id}")
  end

  # ---------------------------------------------------------------------------
  # Private - Utilities
  # ---------------------------------------------------------------------------

  defp compute_stddev(%{count: count, m2: m2}) when count > 1 do
    :math.sqrt(m2 / (count - 1))
  end

  defp compute_stddev(_), do: 0.0

  defp extract_field(event, key) when is_atom(key) do
    Map.get(event, key) || Map.get(event, to_string(key))
  end

  defp parse_number(str, default) when is_binary(str) do
    case Integer.parse(str) do
      {n, _} -> n
      :error -> default
    end
  end

  defp parse_number(_, default), do: default

  defp ets_safe_tab2list(table) do
    try do
      :ets.tab2list(table)
    rescue
      ArgumentError -> []
    end
  end

  defp schedule_flush do
    Process.send_after(self(), :flush, @flush_interval)
  end

  defp schedule_dets_flush do
    Process.send_after(self(), :dets_flush, @dets_flush_interval)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp schedule_mode_check do
    Process.send_after(self(), :check_modes, @mode_check_interval)
  end
end
