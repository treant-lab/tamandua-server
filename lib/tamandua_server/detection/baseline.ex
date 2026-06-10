defmodule TamanduaServer.Detection.Baseline do
  @moduledoc """
  Baseline Learning Engine for false-positive reduction.

  Learns normal behavioral patterns per agent and organization:
  - Process execution patterns (name, parent, command line)
  - Network connection patterns (destination, port, protocol)
  - File access patterns (path patterns, operations)
  - Schedule patterns (time-of-day activity)

  ## Architecture

  Two ETS tables provide fast, lock-free reads on the hot path:

  * `:baseline_profiles`  -- per-agent frequency maps keyed by
    `{agent_id, feature_key}` with value `{count, last_seen_unix}`.
    Feature keys are computed from event attributes (process name,
    network destination, file path pattern, etc.).

  * `:baseline_config`    -- per-agent learning-mode flags and metadata
    keyed by `agent_id` with value `{status_atom, started_at_unix,
    learning_days, total_events}`.

  The GenServer owns both tables and is responsible for:
  1. Periodic persistence of ETS data to the `baselines` and
     `baseline_learning_status` PostgreSQL tables (every 5 minutes).
  2. Periodic cleanup of stale baselines (agents not seen in 30 days).
  3. Checking and auto-completing expired learning periods.

  ## Scoring

  `get_baseline_score/2` uses z-score analysis against the recorded
  frequency distribution.  If an event's feature has been observed
  many times and is well within the normal frequency range, a high
  score (0.5-0.8) is returned to reduce the detection engine's threat
  score.  Novel or anomalous events receive a low score (0.0-0.1).

  ## Usage

      # Engine calls on every event:
      if Baseline.learning_mode?(agent_id) do
        Baseline.record_event(agent_id, event)
      else
        score = Baseline.get_baseline_score(agent_id, event)
      end
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Detection.BaselinePatterns
  alias TamanduaServer.Detection.Baseline.{Pattern, LearningStatus}
  alias TamanduaServer.Detection.Config, as: DetectionConfig
  alias TamanduaServer.Agents.OrgLookup

  # ---------------------------------------------------------------------------
  # Constants
  # ---------------------------------------------------------------------------

  @learning_period_days 7

  # Confidence reduction factors for pattern-based baseline matches
  @high_confidence_reduction 0.5
  @medium_confidence_reduction 0.25
  @low_confidence_reduction 0.1

  # ETS table names
  @profiles_table :baseline_profiles
  @config_table :baseline_config

  # Timers
  @persist_interval :timer.minutes(5)
  @cleanup_interval :timer.hours(6)
  @learning_check_interval :timer.minutes(5)

  # Stale baseline threshold (30 days in seconds)
  @stale_threshold_seconds 30 * 24 * 60 * 60

  # Minimum observations before z-score is meaningful
  @min_observations 10

  # Z-score thresholds for scoring
  @z_very_common 0.5    # within half a std-dev -> very normal
  @z_common 1.5         # within 1.5 std-devs -> normal
  @z_somewhat_common 2.5 # within 2.5 std-devs -> somewhat normal

  # ===========================================================================
  # Client API
  # ===========================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if an agent is currently in learning mode.

  Uses the ETS config table for a fast, lock-free lookup.  Falls back
  to the GenServer for a database-backed check when the ETS entry is
  missing.
  """
  @spec learning_mode?(String.t()) :: boolean()
  def learning_mode?(agent_id) do
    case ets_learning_status(agent_id) do
      {:ok, :learning} -> true
      {:ok, _other} -> false
      :miss -> GenServer.call(__MODULE__, {:learning_mode?, agent_id})
    end
  rescue
    # GenServer not started yet or crashed
    _ -> false
  end

  @doc """
  Start the learning period for an agent.

  Options:
  - `:learning_days` -- number of days (default #{@learning_period_days})
  - `:organization_id` -- org id (auto-resolved if omitted)
  """
  @spec start_learning(String.t(), keyword()) :: {:ok, LearningStatus.t()} | {:error, term()}
  def start_learning(agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:start_learning, agent_id, opts})
  end

  @doc """
  Stop (pause) the learning period for an agent without marking it as
  completed.  Learning can be resumed later with `start_learning/2`.
  """
  @spec stop_learning(String.t()) :: {:ok, LearningStatus.t()} | {:error, term()}
  def stop_learning(agent_id) do
    GenServer.call(__MODULE__, {:stop_learning, agent_id})
  end

  @doc """
  Force-complete the learning period for an agent.

  After this call the agent's baseline is active and will be used
  for scoring.
  """
  @spec end_learning(String.t()) :: {:ok, LearningStatus.t()} | {:error, term()}
  def end_learning(agent_id) do
    GenServer.call(__MODULE__, {:end_learning, agent_id})
  end

  @doc """
  Record an event pattern during learning mode.

  This is a fire-and-forget cast so it never blocks the caller.
  Events are recorded both in ETS (for fast scoring) and forwarded
  to `BaselinePatterns` for database persistence.
  """
  @spec record_event(String.t(), map()) :: :ok
  def record_event(agent_id, event) do
    GenServer.cast(__MODULE__, {:record_event, agent_id, event})
  end

  @doc """
  Calculate how anomalous an event is relative to the agent's baseline.

  Returns a float 0.0-1.0 representing how much to REDUCE the threat
  score:
  - 0.5-0.8 : event matches known baseline patterns closely (normal)
  - 0.0-0.1 : event is novel/anomalous (no reduction)

  Uses z-score calculation against recorded frequency distributions
  in ETS for sub-millisecond latency.
  """
  @spec get_baseline_score(String.t(), map()) :: float()
  def get_baseline_score(agent_id, event) do
    # Hot path: attempt ETS-based z-score first
    case ets_zscore_baseline(agent_id, event) do
      {:ok, score} -> score
      :unavailable -> GenServer.call(__MODULE__, {:get_baseline_score, agent_id, event})
    end
  rescue
    _ -> 0.0
  end

  @doc """
  Adjust detection confidence based on baseline.
  Returns the detection map with potentially reduced threat_score.
  """
  @spec adjust_confidence(map(), String.t(), map()) :: map()
  def adjust_confidence(detection, agent_id, event) do
    GenServer.call(__MODULE__, {:adjust_confidence, detection, agent_id, event})
  end

  @doc """
  Get the baseline profile for an agent.

  Returns a map with feature frequency data pulled from ETS.
  """
  @spec get_profile(String.t()) :: map()
  def get_profile(agent_id) do
    GenServer.call(__MODULE__, {:get_profile, agent_id})
  end

  @doc """
  Get baseline stats for an agent.
  """
  @spec get_stats(String.t()) :: map()
  def get_stats(agent_id) do
    GenServer.call(__MODULE__, {:get_stats, agent_id})
  end

  @doc """
  Get the learning status for an agent.
  """
  @spec get_learning_status(String.t()) :: LearningStatus.t() | nil
  def get_learning_status(agent_id) do
    GenServer.call(__MODULE__, {:get_learning_status, agent_id})
  end

  @doc """
  Get all database-persisted patterns for an agent.
  """
  @spec get_patterns(String.t(), keyword()) :: [Pattern.t()]
  def get_patterns(agent_id, opts \\ []) do
    BaselinePatterns.list_patterns(agent_id, opts)
  end

  @doc """
  Clear the entire baseline for an agent (ETS + database).
  The agent can start fresh with `start_learning/2` afterwards.
  """
  @spec reset_baseline(String.t()) :: :ok | {:error, term()}
  def reset_baseline(agent_id) do
    GenServer.call(__MODULE__, {:reset_baseline, agent_id})
  end

  @doc """
  Record a false positive signal from analyst feedback.

  Strengthens the baseline for the given event features by boosting
  the occurrence count of the matching feature keys. This makes the
  pattern appear more "normal," reducing future threat scores.
  """
  @spec record_false_positive(String.t(), map()) :: :ok
  def record_false_positive(agent_id, event_features) do
    GenServer.cast(__MODULE__, {:record_false_positive, agent_id, event_features})
  end

  @doc """
  Record a true positive signal from analyst feedback.

  Weakens the baseline for the given event features by reducing
  the confidence weight of matching patterns. This prevents the
  baseline from suppressing genuinely malicious activity that
  was previously considered normal.
  """
  @spec record_true_positive(String.t(), map()) :: :ok
  def record_true_positive(agent_id, event_features) do
    GenServer.cast(__MODULE__, {:record_true_positive, agent_id, event_features})
  end

  # ===========================================================================
  # GenServer Implementation
  # ===========================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables owned by this process
    :ets.new(@profiles_table, [
      :named_table,
      :set,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    :ets.new(@config_table, [
      :named_table,
      :set,
      :public,
      read_concurrency: true
    ])

    # Warm the config cache from the database
    warm_config_cache()

    # Schedule periodic tasks
    schedule_persist()
    schedule_cleanup()
    schedule_learning_check()

    Logger.info("Baseline Learning Engine started (persist=#{@persist_interval}ms, cleanup=#{@cleanup_interval}ms)")
    {:ok, %{persist_dirty: false}}
  end

  # --- handle_call -----------------------------------------------------------

  @impl true
  def handle_call({:learning_mode?, agent_id}, _from, state) do
    {:reply, is_learning?(agent_id), state}
  end

  @impl true
  def handle_call({:start_learning, agent_id, opts}, _from, state) do
    result = do_start_learning(agent_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:stop_learning, agent_id}, _from, state) do
    result = do_stop_learning(agent_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:end_learning, agent_id}, _from, state) do
    result = do_end_learning(agent_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_baseline_score, agent_id, event}, _from, state) do
    score = calculate_baseline_score(agent_id, event)
    {:reply, score, state}
  end

  @impl true
  def handle_call({:adjust_confidence, detection, agent_id, event}, _from, state) do
    adjusted = do_adjust_confidence(detection, agent_id, event)
    {:reply, adjusted, state}
  end

  @impl true
  def handle_call({:get_profile, agent_id}, _from, state) do
    profile = build_agent_profile(agent_id)
    {:reply, profile, state}
  end

  @impl true
  def handle_call({:get_stats, agent_id}, _from, state) do
    stats = do_get_stats(agent_id)
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:get_learning_status, agent_id}, _from, state) do
    status = get_or_load_status(agent_id)
    {:reply, status, state}
  end

  @impl true
  def handle_call({:reset_baseline, agent_id}, _from, state) do
    result = do_reset_baseline(agent_id)
    {:reply, result, state}
  end

  # --- handle_cast -----------------------------------------------------------

  @impl true
  def handle_cast({:record_event, agent_id, event}, state) do
    if is_learning?(agent_id) do
      do_record_event(agent_id, event)
    end
    {:noreply, %{state | persist_dirty: true}}
  end

  @impl true
  def handle_cast({:auto_complete_learning, agent_id}, state) do
    Logger.info("Auto-completing expired learning period for agent #{agent_id}")
    do_end_learning(agent_id)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_false_positive, agent_id, event_features}, state) do
    do_record_false_positive(agent_id, event_features)
    {:noreply, %{state | persist_dirty: true}}
  end

  @impl true
  def handle_cast({:record_true_positive, agent_id, event_features}, state) do
    do_record_true_positive(agent_id, event_features)
    {:noreply, %{state | persist_dirty: true}}
  end

  # --- handle_info (periodic tasks) ------------------------------------------

  @impl true
  def handle_info(:persist_profiles, state) do
    if state.persist_dirty do
      persist_ets_to_database()
    end
    schedule_persist()
    {:noreply, %{state | persist_dirty: false}}
  end

  @impl true
  def handle_info(:cleanup_stale, state) do
    cleanup_stale_baselines()
    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(:check_learning_periods, state) do
    check_and_complete_learning_periods()
    schedule_learning_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.debug("Baseline: unexpected message #{inspect(msg)}")
    {:noreply, state}
  end

  # ===========================================================================
  # ETS Fast-Path Helpers (called outside GenServer context)
  # ===========================================================================

  # Look up the learning status from the config ETS table.
  # Returns {:ok, status_atom} or :miss.
  defp ets_learning_status(agent_id) do
    case :ets.lookup(@config_table, agent_id) do
      [{^agent_id, status_atom, started_at_unix, learning_days, _total}] ->
        if status_atom == :learning do
          # Check expiry
          now_unix = System.system_time(:second)
          expiry = started_at_unix + learning_days * 86_400
          if now_unix > expiry do
            {:ok, :expired}
          else
            {:ok, :learning}
          end
        else
          {:ok, status_atom}
        end

      [] ->
        :miss
    end
  rescue
    ArgumentError -> :miss
  end

  # Compute a z-score-based baseline score directly from ETS.
  # Returns {:ok, float} or :unavailable.
  defp ets_zscore_baseline(agent_id, event) do
    # Only score if the agent has completed learning
    case ets_learning_status(agent_id) do
      {:ok, :completed} ->
        features = extract_event_features(event)
        if features == [] do
          {:ok, 0.0}
        else
          scores = Enum.map(features, fn feature_key ->
            compute_feature_zscore(agent_id, feature_key)
          end)
          # Average the feature scores, weighting process features higher
          avg = Enum.sum(scores) / max(length(scores), 1)
          {:ok, Float.round(min(max(avg, 0.0), 0.8), 3)}
        end

      _ ->
        :unavailable
    end
  rescue
    _ -> :unavailable
  end

  # Compute a single feature's baseline score using z-score against the
  # frequency distribution of all features for the agent of the same type.
  defp compute_feature_zscore(agent_id, feature_key) do
    # Look up this specific feature
    case :ets.lookup(@profiles_table, {agent_id, feature_key}) do
      [{{^agent_id, ^feature_key}, count, _last_seen}] ->
        # Gather all feature counts for the same agent and feature type
        feature_type = feature_type_from_key(feature_key)
        all_counts = gather_feature_counts(agent_id, feature_type)

        if length(all_counts) < @min_observations do
          # Not enough data for z-score; fall back to simple frequency heuristic
          simple_frequency_score(count, all_counts)
        else
          zscore_to_baseline_score(count, all_counts)
        end

      [] ->
        # Feature never observed -> novel -> low score
        0.0
    end
  end

  # Convert a z-score into a baseline reduction score.
  # Low absolute z-score = very normal = high baseline score.
  defp zscore_to_baseline_score(count, all_counts) do
    n = length(all_counts)
    mean = Enum.sum(all_counts) / n
    variance = Enum.reduce(all_counts, 0.0, fn c, acc ->
      acc + (c - mean) * (c - mean)
    end) / n
    stddev = :math.sqrt(max(variance, 0.001))

    z = abs((count - mean) / stddev)

    cond do
      z <= @z_very_common  -> 0.8   # well within normal range
      z <= @z_common       -> 0.6   # within normal range
      z <= @z_somewhat_common -> 0.3 # edge of normal
      true                 -> 0.05  # anomalous
    end
  end

  # Fallback when we have fewer than @min_observations data points.
  defp simple_frequency_score(count, all_counts) do
    max_count = if all_counts == [], do: 1, else: Enum.max(all_counts)
    ratio = count / max(max_count, 1)

    cond do
      ratio >= 0.5  -> 0.6
      ratio >= 0.1  -> 0.3
      count >= 3    -> 0.2
      count >= 1    -> 0.1
      true          -> 0.0
    end
  end

  # Gather all feature counts for an agent filtered by feature type prefix.
  defp gather_feature_counts(agent_id, feature_type) do
    prefix = "#{feature_type}:"

    # Use ets:select with a match spec for efficient scanning.
    # Pattern: {{agent_id, feature_key}, count, _last_seen}
    match_spec = [
      {
        {{:"$1", :"$2"}, :"$3", :_},
        [
          {:andalso,
            {:==, :"$1", agent_id},
            {:==, {:binary_part, :"$2", 0, byte_size(prefix)}, prefix}}
        ],
        [:"$3"]
      }
    ]

    try do
      :ets.select(@profiles_table, match_spec)
    rescue
      _ -> []
    end
  end

  # Extract the feature type prefix from a feature key.
  defp feature_type_from_key(key) when is_binary(key) do
    case String.split(key, ":", parts: 2) do
      [type, _rest] -> type
      _ -> "unknown"
    end
  end

  # ===========================================================================
  # Event Feature Extraction
  # ===========================================================================

  # Extract feature keys from an event for ETS storage and scoring.
  # Each feature key is a string like "process:svchost.exe" or
  # "network:443:tcp" that identifies a behavioral pattern.
  defp extract_event_features(event) do
    event_type = to_string(event[:event_type] || event["event_type"] || "")
    payload = event[:payload] || event["payload"] || %{}

    case event_type do
      type when type in ["process_create", "process_start"] ->
        extract_process_features(payload)

      type when type in ["network_connect", "network_listen"] ->
        extract_network_features(payload)

      type when type in ["file_create", "file_modify", "file_open",
                          "file_read", "file_write"] ->
        extract_file_features(payload)

      type when type in ["dns_query"] ->
        extract_dns_features(payload)

      _ ->
        []
    end
  end

  defp extract_process_features(payload) do
    name = get_field(payload, :name)
    parent = get_field(payload, :parent_name)

    features = []
    features = if name, do: ["process:#{String.downcase(name)}" | features], else: features
    features = if name && parent do
      ["process_chain:#{String.downcase(parent)}->#{String.downcase(name)}" | features]
    else
      features
    end
    features
  end

  defp extract_network_features(payload) do
    port = get_field(payload, :remote_port)
    protocol = get_field(payload, :protocol)
    dest = get_field(payload, :remote_ip)
    process_name = get_field(payload, :process_name)

    features = []
    features = if port, do: ["network_port:#{port}" | features], else: features
    features = if dest && port do
      ["network_dest:#{dest}:#{port}" | features]
    else
      features
    end
    features = if process_name && port do
      ["network_proc:#{String.downcase(to_string(process_name))}:#{port}" | features]
    else
      features
    end
    features
  end

  defp extract_file_features(payload) do
    path = get_field(payload, :path)

    if path do
      normalized = normalize_path(path)
      dir = Path.dirname(normalized)

      features = ["file_path:#{normalized}"]
      features = if dir != ".", do: ["file_dir:#{dir}" | features], else: features
      features
    else
      []
    end
  end

  defp extract_dns_features(payload) do
    query = get_field(payload, :query) || get_field(payload, :domain)

    if query do
      domain = String.downcase(to_string(query))
      # Extract parent domain (e.g. "sub.example.com" -> "example.com")
      parts = String.split(domain, ".")
      parent = if length(parts) >= 2 do
        parts |> Enum.take(-2) |> Enum.join(".")
      else
        domain
      end

      ["dns:#{domain}", "dns_parent:#{parent}"]
    else
      []
    end
  end

  # Normalize a file path for pattern storage (strip user-specific and
  # temporal components).
  defp normalize_path(path) when is_binary(path) do
    path
    |> String.downcase()
    |> String.replace(~r/\\users\\[^\\]+/i, "\\users\\<user>")
    |> String.replace(~r/\/home\/[^\/]+/i, "/home/<user>")
    |> String.replace(~r/\d{4}[-_]\d{2}[-_]\d{2}/, "<date>")
    |> String.replace(~r/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i, "<uuid>")
    |> String.replace(~r/\d{6,}/, "<num>")
    |> String.slice(0, 200)
  end

  defp normalize_path(path), do: to_string(path) |> normalize_path()

  defp get_field(map, key) when is_atom(key) do
    Map.get(map, key) || Map.get(map, Atom.to_string(key))
  end

  # ===========================================================================
  # Internal: Learning Mode
  # ===========================================================================

  defp is_learning?(agent_id) do
    case ets_learning_status(agent_id) do
      {:ok, :learning} ->
        true

      {:ok, :expired} ->
        # Auto-complete in the background (don't block caller)
        GenServer.cast(__MODULE__, {:auto_complete_learning, agent_id})
        false

      {:ok, _} ->
        false

      :miss ->
        # Fall back to database
        case get_or_load_status(agent_id) do
          %LearningStatus{status: "learning"} = status ->
            if LearningStatus.learning_expired?(status) do
              do_end_learning(agent_id)
              false
            else
              true
            end

          _ ->
            false
        end
    end
  end

  defp get_or_load_status(agent_id) do
    # Check ETS config table first
    case :ets.lookup(@config_table, agent_id) do
      [{^agent_id, _status, _started, _days, _total}] ->
        # ETS has the flag, but we need the full struct for the caller.
        # Load from DB (cached by Ecto query cache).
        load_status_from_db(agent_id)

      [] ->
        load_status_from_db(agent_id)
    end
  rescue
    ArgumentError -> load_status_from_db(agent_id)
  end

  defp load_status_from_db(agent_id) do
    status = Repo.one(from s in LearningStatus, where: s.agent_id == ^agent_id)

    if status do
      # Populate ETS config cache
      status_atom = String.to_atom(status.status)
      started_unix = if status.started_at, do: DateTime.to_unix(status.started_at), else: 0
      :ets.insert(@config_table, {
        agent_id,
        status_atom,
        started_unix,
        status.learning_days,
        status.events_processed
      })
    end

    status
  rescue
    e ->
      Logger.warning("Baseline: failed to load status for #{agent_id}: #{inspect(e)}")
      nil
  end

  # ===========================================================================
  # Internal: Start / Stop / End / Reset Learning
  # ===========================================================================

  defp do_start_learning(agent_id, opts) do
    learning_days = Keyword.get(opts, :learning_days, @learning_period_days)
    org_id = Keyword.get(opts, :organization_id) || OrgLookup.get_org_id(agent_id)
    now = DateTime.utc_now()

    existing = Repo.one(from s in LearningStatus, where: s.agent_id == ^agent_id)

    result = if existing do
      existing
      |> LearningStatus.changeset(%{
        started_at: now,
        completed_at: nil,
        learning_days: learning_days,
        status: "learning",
        events_processed: 0,
        patterns_learned: 0
      })
      |> Repo.update()
    else
      %LearningStatus{}
      |> LearningStatus.changeset(%{
        agent_id: agent_id,
        organization_id: org_id,
        started_at: now,
        learning_days: learning_days,
        status: "learning",
        events_processed: 0,
        patterns_learned: 0
      })
      |> Repo.insert()
    end

    case result do
      {:ok, status} ->
        update_config_cache(agent_id, status)
        Logger.info("Started baseline learning for agent #{agent_id} (#{learning_days} days)")
        {:ok, status}

      {:error, _} = error ->
        error
    end
  end

  defp do_stop_learning(agent_id) do
    case Repo.one(from s in LearningStatus, where: s.agent_id == ^agent_id) do
      nil ->
        {:error, :not_found}

      status ->
        result =
          status
          |> LearningStatus.changeset(%{status: "paused"})
          |> Repo.update()

        case result do
          {:ok, updated} ->
            update_config_cache(agent_id, updated)
            Logger.info("Paused baseline learning for agent #{agent_id}")
            {:ok, updated}

          error ->
            error
        end
    end
  rescue
    e ->
      Logger.error("Baseline: stop_learning failed for #{agent_id}: #{inspect(e)}")
      {:error, e}
  end

  defp do_end_learning(agent_id) do
    now = DateTime.utc_now()

    case Repo.one(from s in LearningStatus, where: s.agent_id == ^agent_id) do
      nil ->
        {:error, :not_found}

      status ->
        pattern_count = Repo.aggregate(
          from(p in Pattern, where: p.agent_id == ^agent_id),
          :count,
          :id
        )

        result =
          status
          |> LearningStatus.changeset(%{
            completed_at: now,
            status: "completed",
            patterns_learned: pattern_count
          })
          |> Repo.update()

        case result do
          {:ok, updated} ->
            update_config_cache(agent_id, updated)
            Logger.info("Completed baseline learning for agent #{agent_id}: #{pattern_count} patterns")
            {:ok, updated}

          error ->
            error
        end
    end
  rescue
    e ->
      Logger.error("Baseline: end_learning failed for #{agent_id}: #{inspect(e)}")
      {:error, e}
  end

  defp do_reset_baseline(agent_id) do
    # 1. Delete ETS profile entries for this agent
    delete_agent_profiles(agent_id)

    # 2. Delete ETS config entry
    :ets.delete(@config_table, agent_id)

    # 3. Delete database patterns
    Repo.delete_all(from p in Pattern, where: p.agent_id == ^agent_id)

    # 4. Delete learning status
    Repo.delete_all(from s in LearningStatus, where: s.agent_id == ^agent_id)

    Logger.info("Reset baseline for agent #{agent_id}")
    :ok
  rescue
    e ->
      Logger.error("Baseline: reset failed for #{agent_id}: #{inspect(e)}")
      {:error, e}
  end

  defp delete_agent_profiles(agent_id) do
    # ETS select_delete with a match spec: delete all entries where the
    # first element of the key tuple matches agent_id.
    match_spec = [
      {{{:"$1", :_}, :_, :_}, [{:==, :"$1", agent_id}], [true]}
    ]
    :ets.select_delete(@profiles_table, match_spec)
  rescue
    _ -> :ok
  end

  defp update_config_cache(agent_id, %LearningStatus{} = status) do
    status_atom = String.to_atom(status.status)
    started_unix = if status.started_at, do: DateTime.to_unix(status.started_at), else: 0
    :ets.insert(@config_table, {
      agent_id,
      status_atom,
      started_unix,
      status.learning_days,
      status.events_processed
    })
  end

  # ===========================================================================
  # Internal: Record Event
  # ===========================================================================

  defp do_record_event(agent_id, event) do
    now_unix = System.system_time(:second)

    # 1. Record features in ETS for fast z-score scoring
    features = extract_event_features(event)
    Enum.each(features, fn feature_key ->
      ets_key = {agent_id, feature_key}
      case :ets.lookup(@profiles_table, ets_key) do
        [{^ets_key, count, _last_seen}] ->
          :ets.insert(@profiles_table, {ets_key, count + 1, now_unix})

        [] ->
          :ets.insert(@profiles_table, {ets_key, 1, now_unix})
      end
    end)

    # 2. Record in BaselinePatterns for database persistence
    event_type = to_string(event[:event_type] || event["event_type"] || "")
    payload = event[:payload] || event["payload"] || %{}

    case event_type do
      type when type in ["process_create", "process_start"] ->
        BaselinePatterns.record_process(agent_id, payload)
        increment_events_processed(agent_id)

      type when type in ["network_connect", "network_listen"] ->
        BaselinePatterns.record_network(agent_id, payload)
        increment_events_processed(agent_id)

      type when type in ["file_create", "file_modify", "file_open",
                          "file_read", "file_write"] ->
        BaselinePatterns.record_file_access(agent_id, payload)
        increment_events_processed(agent_id)

      _ ->
        BaselinePatterns.record_schedule(agent_id, event)
        :ok
    end

    # 3. Update ETS config event counter
    case :ets.lookup(@config_table, agent_id) do
      [{^agent_id, status, started, days, total}] ->
        :ets.insert(@config_table, {agent_id, status, started, days, total + 1})
      [] ->
        :ok
    end
  rescue
    e ->
      Logger.warning("Baseline: failed to record event for #{agent_id}: #{inspect(e)}")
  end

  # ===========================================================================
  # Internal: Analyst Feedback (FP / TP)
  # ===========================================================================

  # Strengthen baseline for a false positive: boost ETS counts by a large
  # increment so this pattern is treated as highly normal.
  defp do_record_false_positive(agent_id, event_features) do
    now_unix = System.system_time(:second)
    features = extract_event_features(event_features)

    # FP boost: add a large count to make the pattern look very normal.
    # This is equivalent to the pattern having been observed many times
    # during baseline learning.
    fp_boost = 50

    Enum.each(features, fn feature_key ->
      ets_key = {agent_id, feature_key}
      case :ets.lookup(@profiles_table, ets_key) do
        [{^ets_key, count, _last_seen}] ->
          :ets.insert(@profiles_table, {ets_key, count + fp_boost, now_unix})

        [] ->
          :ets.insert(@profiles_table, {ets_key, fp_boost, now_unix})
      end
    end)

    # Also reduce confidence weight for matching DB patterns
    if features != [] do
      reduce_pattern_confidence(agent_id, features, :boost)
    end

    Logger.info("Baseline: recorded FP feedback for agent #{agent_id} (#{length(features)} features boosted)")
  rescue
    e ->
      Logger.warning("Baseline: failed to record FP for #{agent_id}: #{inspect(e)}")
  end

  # Weaken baseline for a true positive: reduce ETS counts so this pattern
  # is NOT treated as normal by the baseline scoring.
  defp do_record_true_positive(agent_id, event_features) do
    now_unix = System.system_time(:second)
    features = extract_event_features(event_features)

    # TP penalty: halve the count to make the pattern less normal.
    # If the count was boosted by a previous FP verdict, this corrects it.
    Enum.each(features, fn feature_key ->
      ets_key = {agent_id, feature_key}
      case :ets.lookup(@profiles_table, ets_key) do
        [{^ets_key, count, _last_seen}] when count > 1 ->
          new_count = max(div(count, 2), 1)
          :ets.insert(@profiles_table, {ets_key, new_count, now_unix})

        _ ->
          # Feature not in baseline or count is 1 -- nothing to weaken
          :ok
      end
    end)

    # Also increase confidence weight for matching DB patterns so the
    # detection is not suppressed
    if features != [] do
      reduce_pattern_confidence(agent_id, features, :weaken)
    end

    Logger.info("Baseline: recorded TP feedback for agent #{agent_id} (#{length(features)} features weakened)")
  rescue
    e ->
      Logger.warning("Baseline: failed to record TP for #{agent_id}: #{inspect(e)}")
  end

  # Adjust DB pattern confidence weights based on analyst feedback.
  # :boost increases confidence_weight (pattern is more normal)
  # :weaken decreases confidence_weight (pattern is less normal)
  defp reduce_pattern_confidence(agent_id, features, direction) do
    Enum.each(features, fn feature_key ->
      feature_type = feature_type_from_key(feature_key)
      baseline_type = map_feature_type_to_baseline(feature_type)
      pattern_hash = Pattern.pattern_hash(%{"feature_key" => feature_key, "count" => 0})

      existing = Repo.one(from p in Pattern,
        where: p.agent_id == ^agent_id,
        where: p.baseline_type == ^baseline_type,
        where: fragment("md5(pattern::text) = ?", ^pattern_hash)
      )

      if existing do
        new_weight = case direction do
          :boost -> min(existing.confidence_weight + 0.5, 3.0)
          :weaken -> max(existing.confidence_weight - 0.5, 0.1)
        end

        existing
        |> Pattern.changeset(%{confidence_weight: new_weight})
        |> Repo.update()
      end
    end)
  rescue
    e ->
      Logger.warning("Baseline: failed to adjust pattern confidence: #{inspect(e)}")
  end

  defp increment_events_processed(agent_id) do
    Repo.update_all(
      from(s in LearningStatus,
        where: s.agent_id == ^agent_id,
        where: s.status == "learning"
      ),
      inc: [events_processed: 1]
    )
  rescue
    _ -> :ok
  end

  # ===========================================================================
  # Internal: Baseline Scoring (GenServer fallback)
  # ===========================================================================

  defp calculate_baseline_score(agent_id, event) do
    event_type = to_string(event[:event_type] || event["event_type"] || "")
    payload = event[:payload] || event["payload"] || %{}

    status = get_or_load_status(agent_id)

    if status && status.status == "completed" do
      # Try z-score from ETS first
      features = extract_event_features(event)

      ets_score = if features != [] do
        scores = Enum.map(features, fn fk -> compute_feature_zscore(agent_id, fk) end)
        Enum.sum(scores) / max(length(scores), 1)
      else
        nil
      end

      # Fall back to pattern-based scoring if ETS has no data
      pattern_score = case event_type do
        type when type in ["process_create", "process_start"] ->
          case BaselinePatterns.match_process(agent_id, payload) do
            {:match, score} -> score
            :no_match -> 0.0
          end

        type when type in ["network_connect", "network_listen"] ->
          case BaselinePatterns.match_network(agent_id, payload) do
            {:match, score} -> score
            :no_match -> 0.0
          end

        type when type in ["file_create", "file_modify", "file_open",
                            "file_read", "file_write"] ->
          case BaselinePatterns.match_file_access(agent_id, payload) do
            {:match, score} -> score
            :no_match -> 0.0
          end

        _ ->
          0.0
      end

      # Use the higher of the two scores (ETS z-score or pattern match)
      final = cond do
        ets_score && ets_score > 0 && pattern_score > 0 ->
          max(ets_score, pattern_score)
        ets_score && ets_score > 0 ->
          ets_score
        true ->
          pattern_score
      end

      Float.round(min(max(final, 0.0), 0.8), 3)
    else
      0.0
    end
  end

  # ===========================================================================
  # Internal: Confidence Adjustment
  # ===========================================================================

  defp do_adjust_confidence(detection, agent_id, event) do
    if is_learning?(agent_id) do
      detection
    else
      baseline_score = calculate_baseline_score(agent_id, event)
      current_score = detection[:threat_score] || detection["threat_score"] || 0.0

      if baseline_score > 0.0 do
        reduction = cond do
          baseline_score >= 0.8 -> @high_confidence_reduction
          baseline_score >= 0.5 -> @medium_confidence_reduction
          baseline_score >= 0.2 -> @low_confidence_reduction
          true -> 0.0
        end

        adjusted_score = current_score * (1.0 - reduction)

        detection
        |> Map.put(:threat_score, adjusted_score)
        |> Map.put(:baseline_adjusted, true)
        |> Map.put(:baseline_score, baseline_score)
        |> Map.put(:original_threat_score, current_score)
      else
        detection
      end
    end
  end

  # ===========================================================================
  # Internal: Profile Builder
  # ===========================================================================

  defp build_agent_profile(agent_id) do
    # Scan all ETS entries for this agent
    match_spec = [
      {{{:"$1", :"$2"}, :"$3", :"$4"}, [{:==, :"$1", agent_id}], [{{:"$2", :"$3", :"$4"}}]}
    ]

    entries = try do
      :ets.select(@profiles_table, match_spec)
    rescue
      _ -> []
    end

    # Group by feature type
    grouped = Enum.group_by(entries, fn {key, _count, _ts} ->
      feature_type_from_key(key)
    end)

    feature_counts = Map.new(grouped, fn {type, items} ->
      sorted = items
      |> Enum.sort_by(fn {_k, count, _ts} -> count end, :desc)
      |> Enum.take(50)
      |> Enum.map(fn {key, count, last_seen} ->
        %{feature: key, count: count, last_seen_unix: last_seen}
      end)

      {type, sorted}
    end)

    total_features = length(entries)
    total_observations = Enum.reduce(entries, 0, fn {_k, c, _ts}, acc -> acc + c end)

    status = get_or_load_status(agent_id)

    %{
      agent_id: agent_id,
      learning_status: status && status.status,
      total_features: total_features,
      total_observations: total_observations,
      features_by_type: feature_counts
    }
  end

  # ===========================================================================
  # Internal: Stats
  # ===========================================================================

  defp do_get_stats(agent_id) do
    status = get_or_load_status(agent_id)

    pattern_stats = try do
      BaselinePatterns.get_pattern_stats(agent_id)
    rescue
      _ -> []
    end

    total_patterns = Enum.reduce(pattern_stats, 0, fn s, acc -> acc + s.pattern_count end)

    # ETS profile stats
    profile = build_agent_profile(agent_id)

    common_count = try do
      length(BaselinePatterns.get_common_patterns(agent_id))
    rescue
      _ -> 0
    end

    rare_count = try do
      length(BaselinePatterns.get_rare_patterns(agent_id))
    rescue
      _ -> 0
    end

    %{
      agent_id: agent_id,
      learning_status: status && status.status,
      learning_started_at: status && status.started_at,
      learning_completed_at: status && status.completed_at,
      learning_days: status && status.learning_days,
      events_processed: status && status.events_processed || 0,
      patterns_learned: total_patterns,
      pattern_breakdown: pattern_stats,
      common_patterns: common_count,
      rare_patterns: rare_count,
      ets_features: profile.total_features,
      ets_observations: profile.total_observations
    }
  end

  # ===========================================================================
  # Periodic Tasks
  # ===========================================================================

  defp schedule_persist do
    interval = DetectionConfig.baseline_persist_interval()
    Process.send_after(self(), :persist_profiles, interval || @persist_interval)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup_stale, @cleanup_interval)
  end

  defp schedule_learning_check do
    Process.send_after(self(), :check_learning_periods, @learning_check_interval)
  end

  # Persist ETS profile data to the baselines table.
  defp persist_ets_to_database do
    Logger.debug("Baseline: persisting ETS profiles to database")

    entries = try do
      :ets.tab2list(@profiles_table)
    rescue
      _ -> []
    end

    # Group by agent_id
    by_agent = Enum.group_by(entries, fn {{agent_id, _feature}, _count, _ts} -> agent_id end)

    persisted_count = Enum.reduce(by_agent, 0, fn {agent_id, agent_entries}, acc ->
      count = persist_agent_profiles(agent_id, agent_entries)
      acc + count
    end)

    if persisted_count > 0 do
      Logger.info("Baseline: persisted #{persisted_count} profile entries to database")
    end
  rescue
    e ->
      Logger.error("Baseline: persistence failed: #{inspect(e)}")
  end

  defp persist_agent_profiles(agent_id, entries) do
    now = DateTime.utc_now()
    org_id = OrgLookup.get_org_id(agent_id)

    Enum.reduce(entries, 0, fn {{_aid, feature_key}, count, last_seen_unix}, acc ->
      feature_type = feature_type_from_key(feature_key)
      baseline_type = map_feature_type_to_baseline(feature_type)

      last_seen_dt = case DateTime.from_unix(last_seen_unix) do
        {:ok, dt} -> dt
        _ -> now
      end

      pattern_map = %{"feature_key" => feature_key, "count" => count}
      pattern_hash = Pattern.pattern_hash(pattern_map)

      # Upsert: update count and last_seen if exists, otherwise insert
      existing = Repo.one(from p in Pattern,
        where: p.agent_id == ^agent_id,
        where: p.baseline_type == ^baseline_type,
        where: fragment("md5(pattern::text) = ?", ^pattern_hash)
      )

      result = case existing do
        nil ->
          %Pattern{}
          |> Pattern.changeset(%{
            agent_id: agent_id,
            organization_id: org_id,
            baseline_type: baseline_type,
            pattern: pattern_map,
            occurrence_count: count,
            first_seen: last_seen_dt,
            last_seen: last_seen_dt,
            confidence_weight: 1.0
          })
          |> Repo.insert()

        %Pattern{} = p ->
          new_count = max(p.occurrence_count, count)
          p
          |> Pattern.changeset(%{
            occurrence_count: new_count,
            last_seen: last_seen_dt,
            confidence_weight: min(p.confidence_weight + 0.01, 2.0)
          })
          |> Repo.update()
      end

      case result do
        {:ok, _} -> acc + 1
        {:error, _} -> acc
      end
    end)
  rescue
    e ->
      Logger.warning("Baseline: persist for agent #{agent_id} failed: #{inspect(e)}")
      0
  end

  defp map_feature_type_to_baseline(feature_type) do
    case feature_type do
      t when t in ["process", "process_chain"] -> "process"
      t when t in ["network_port", "network_dest", "network_proc"] -> "network"
      t when t in ["file_path", "file_dir"] -> "file"
      t when t in ["dns", "dns_parent"] -> "network"
      _ -> "schedule"
    end
  end

  # Clean up baselines for agents not seen in 30 days.
  defp cleanup_stale_baselines do
    Logger.debug("Baseline: cleaning up stale baselines")

    cutoff_unix = System.system_time(:second) - @stale_threshold_seconds

    # Scan ETS for entries with last_seen before cutoff
    match_spec = [
      {{{:"$1", :"$2"}, :"$3", :"$4"},
        [{:<, :"$4", cutoff_unix}],
        [{{:"$1", :"$2"}}]}
    ]

    stale_keys = try do
      :ets.select(@profiles_table, match_spec)
    rescue
      _ -> []
    end

    if length(stale_keys) > 0 do
      stale_agents = stale_keys
      |> Enum.map(fn {agent_id, _feature} -> agent_id end)
      |> Enum.uniq()

      # Only delete if ALL features for an agent are stale
      Enum.each(stale_agents, fn agent_id ->
        agent_match = [
          {{{:"$1", :_}, :_, :"$2"},
            [{:andalso, {:==, :"$1", agent_id}, {:>=, :"$2", cutoff_unix}}],
            [true]}
        ]

        has_recent = try do
          :ets.select_count(@profiles_table, agent_match) > 0
        rescue
          _ -> true
        end

        unless has_recent do
          Logger.info("Baseline: cleaning up stale baseline for agent #{agent_id}")
          delete_agent_profiles(agent_id)
          :ets.delete(@config_table, agent_id)

          # Also clean DB records older than 30 days
          cutoff_dt = DateTime.add(DateTime.utc_now(), -@stale_threshold_seconds, :second)
          Repo.delete_all(
            from(p in Pattern,
              where: p.agent_id == ^agent_id,
              where: p.last_seen < ^cutoff_dt
            )
          )
        end
      end)

      Logger.info("Baseline: stale cleanup evaluated #{length(stale_agents)} agents")
    end
  rescue
    e ->
      Logger.error("Baseline: stale cleanup failed: #{inspect(e)}")
  end

  # Check for learning periods that have expired and auto-complete them.
  defp check_and_complete_learning_periods do
    expired = Repo.all(from s in LearningStatus,
      where: s.status == "learning"
    )
    |> Enum.filter(fn status ->
      LearningStatus.learning_expired?(status)
    end)

    Enum.each(expired, fn status ->
      Logger.info("Auto-completing baseline learning for agent #{status.agent_id}")
      do_end_learning(status.agent_id)
    end)

    if length(expired) > 0 do
      Logger.info("Baseline: auto-completed #{length(expired)} learning periods")
    end
  rescue
    e ->
      Logger.error("Baseline: learning period check failed: #{inspect(e)}")
  end

  # Warm the ETS config cache from the database on startup.
  defp warm_config_cache do
    statuses = Repo.all(from s in LearningStatus,
      where: s.status in ["learning", "completed"]
    )

    Enum.each(statuses, fn status ->
      update_config_cache(status.agent_id, status)
    end)

    Logger.info("Baseline: warmed config cache with #{length(statuses)} agents")
  rescue
    e ->
      Logger.warning("Baseline: config cache warm failed: #{inspect(e)}")
  end
end
