defmodule TamanduaServer.ThreatIntel.IOCScoring do
  @moduledoc """
  IOC Scoring Engine for threat intelligence quality assessment.

  Implements a comprehensive scoring system that considers:
  - Age-based decay: IOCs lose relevance over time
  - Source reputation: Trusted sources contribute higher scores
  - Sighting count: Multiple independent sightings increase confidence
  - False positive feedback: Analyst feedback adjusts scores
  - MISP event metadata: Threat level, analysis status, TLP

  ## Score Components

  The final IOC score (0-100) is calculated from:
  1. **Base Score** (0-100): Initial score from source reputation
  2. **Age Decay** (0-1 multiplier): Exponential decay based on IOC age
  3. **Sighting Boost** (+0-30): Additional points for multiple sightings
  4. **FP Penalty** (-0-50): Reduction based on false positive reports
  5. **Correlation Boost** (+0-20): Bonus for IOCs linked to known campaigns/actors

  ## Configuration

  Configure scoring parameters in config:

      config :tamandua_server, TamanduaServer.ThreatIntel.IOCScoring,
        half_life_days: 90,
        min_score_threshold: 20,
        max_sighting_boost: 30,
        fp_weight: 10

  ## Usage

      # Calculate score for a single IOC
      score = IOCScoring.calculate_score(ioc)

      # Batch score IOCs
      scored_iocs = IOCScoring.batch_score(iocs)

      # Record a sighting
      IOCScoring.record_sighting(ioc_id, source: "detection", type: :sighting)

      # Record false positive feedback
      IOCScoring.record_false_positive(ioc_id, analyst_id, reason: "Internal IP")
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Detection.IOC
  alias TamanduaServer.ThreatIntel.MISPInstance

  import Ecto.Query

  @ets_scores :ioc_scores_cache
  @ets_sightings :ioc_sightings_cache

  # Default configuration
  @default_half_life_days 90
  @default_min_score_threshold 20
  @default_max_sighting_boost 30
  @default_fp_weight 10
  @default_correlation_boost 20

  # Source reputation scores (0-100)
  @source_reputation %{
    # Premium commercial feeds
    "crowdstrike" => 95,
    "mandiant" => 95,
    "recorded_future" => 90,
    "flashpoint" => 90,

    # MISP instances (adjusted by trust_level)
    "misp" => 80,

    # Open source feeds
    "alienvault_otx" => 75,
    "abuse.ch" => 80,
    "malware_bazaar" => 85,
    "urlhaus" => 80,
    "threatfox" => 80,
    "feodo_tracker" => 85,

    # Community feeds
    "openphish" => 70,
    "phishtank" => 70,
    "spamhaus" => 85,
    "tor_exit_nodes" => 60,

    # Internal/manual
    "manual" => 50,
    "internal" => 60,
    "detection" => 70,

    # Unknown sources
    "unknown" => 30
  }

  # IOC type weights (some IOC types are inherently more reliable)
  @type_weights %{
    "hash_sha256" => 1.0,
    "hash_sha1" => 0.95,
    "hash_md5" => 0.90,
    "domain" => 0.85,
    "ip" => 0.80,
    "url" => 0.85,
    "email" => 0.75,
    "filename" => 0.60
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Calculate the score for a single IOC.

  Returns a map with score breakdown:
  - score: Final score (0-100)
  - base_score: Source reputation score
  - age_factor: Age decay multiplier
  - sighting_boost: Points from sightings
  - fp_penalty: Deduction from false positives
  - correlation_boost: Bonus from campaign/actor links
  """
  @spec calculate_score(map() | IOC.t()) :: map()
  def calculate_score(ioc) do
    GenServer.call(__MODULE__, {:calculate_score, ioc})
  end

  @doc """
  Batch calculate scores for multiple IOCs.
  """
  @spec batch_score([map() | IOC.t()]) :: [map()]
  def batch_score(iocs) when is_list(iocs) do
    GenServer.call(__MODULE__, {:batch_score, iocs}, 60_000)
  end

  @doc """
  Record a sighting for an IOC.

  Sighting types:
  - :sighting (0) - IOC was observed
  - :false_positive (1) - IOC was a false positive
  - :expiration (2) - IOC should be expired
  """
  @spec record_sighting(String.t(), keyword()) :: :ok | {:error, term()}
  def record_sighting(ioc_id, opts \\ []) do
    GenServer.call(__MODULE__, {:record_sighting, ioc_id, opts})
  end

  @doc """
  Record false positive feedback for an IOC.
  """
  @spec record_false_positive(String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def record_false_positive(ioc_id, analyst_id, opts \\ []) do
    GenServer.call(__MODULE__, {:record_false_positive, ioc_id, analyst_id, opts})
  end

  @doc """
  Get sighting statistics for an IOC.
  """
  @spec get_sighting_stats(String.t()) :: map()
  def get_sighting_stats(ioc_id) do
    GenServer.call(__MODULE__, {:get_sighting_stats, ioc_id})
  end

  @doc """
  Recalculate and update scores for all IOCs.
  """
  @spec recalculate_all() :: {:ok, integer()}
  def recalculate_all do
    GenServer.call(__MODULE__, :recalculate_all, 300_000)
  end

  @doc """
  Get source reputation configuration.
  """
  @spec get_source_reputation() :: map()
  def get_source_reputation do
    @source_reputation
  end

  @doc """
  Update source reputation for a custom source.
  """
  @spec update_source_reputation(String.t(), integer()) :: :ok
  def update_source_reputation(source, score) when score >= 0 and score <= 100 do
    GenServer.call(__MODULE__, {:update_source_reputation, source, score})
  end

  @doc """
  Get scoring configuration.
  """
  @spec get_config() :: map()
  def get_config do
    GenServer.call(__MODULE__, :get_config)
  end

  @doc """
  Get IOCs above a minimum score threshold.
  """
  @spec get_high_confidence_iocs(keyword()) :: [map()]
  def get_high_confidence_iocs(opts \\ []) do
    GenServer.call(__MODULE__, {:get_high_confidence_iocs, opts})
  end

  @doc """
  Get scoring statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    # Create ETS tables for caching
    :ets.new(@ets_scores, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_sightings, [:named_table, :set, :public, read_concurrency: true])

    state = %{
      half_life_days: Keyword.get(opts, :half_life_days, @default_half_life_days),
      min_score_threshold: Keyword.get(opts, :min_score_threshold, @default_min_score_threshold),
      max_sighting_boost: Keyword.get(opts, :max_sighting_boost, @default_max_sighting_boost),
      fp_weight: Keyword.get(opts, :fp_weight, @default_fp_weight),
      correlation_boost: Keyword.get(opts, :correlation_boost, @default_correlation_boost),
      custom_source_reputation: %{},
      stats: %{
        iocs_scored: 0,
        sightings_recorded: 0,
        fps_recorded: 0,
        last_recalculation: nil
      }
    }

    # Schedule periodic score recalculation
    schedule_recalculation()

    Logger.info("[IOCScoring] Initialized with half_life=#{state.half_life_days} days")
    {:ok, state}
  end

  @impl true
  def handle_call({:calculate_score, ioc}, _from, state) do
    score_data = do_calculate_score(ioc, state)
    {:reply, score_data, update_stats(state, :iocs_scored)}
  end

  @impl true
  def handle_call({:batch_score, iocs}, _from, state) do
    scored = Enum.map(iocs, fn ioc ->
      {ioc, do_calculate_score(ioc, state)}
    end)

    new_state = %{state | stats: %{state.stats | iocs_scored: state.stats.iocs_scored + length(iocs)}}
    {:reply, scored, new_state}
  end

  @impl true
  def handle_call({:record_sighting, ioc_id, opts}, _from, state) do
    result = do_record_sighting(ioc_id, opts)
    {:reply, result, update_stats(state, :sightings_recorded)}
  end

  @impl true
  def handle_call({:record_false_positive, ioc_id, analyst_id, opts}, _from, state) do
    result = do_record_false_positive(ioc_id, analyst_id, opts)
    {:reply, result, update_stats(state, :fps_recorded)}
  end

  @impl true
  def handle_call({:get_sighting_stats, ioc_id}, _from, state) do
    stats = do_get_sighting_stats(ioc_id)
    {:reply, stats, state}
  end

  @impl true
  def handle_call(:recalculate_all, _from, state) do
    count = do_recalculate_all(state)
    new_state = %{state | stats: %{state.stats | last_recalculation: DateTime.utc_now()}}
    {:reply, {:ok, count}, new_state}
  end

  @impl true
  def handle_call({:update_source_reputation, source, score}, _from, state) do
    new_reputation = Map.put(state.custom_source_reputation, source, score)
    {:reply, :ok, %{state | custom_source_reputation: new_reputation}}
  end

  @impl true
  def handle_call(:get_config, _from, state) do
    config = %{
      half_life_days: state.half_life_days,
      min_score_threshold: state.min_score_threshold,
      max_sighting_boost: state.max_sighting_boost,
      fp_weight: state.fp_weight,
      correlation_boost: state.correlation_boost,
      source_reputation: Map.merge(@source_reputation, state.custom_source_reputation),
      type_weights: @type_weights
    }
    {:reply, config, state}
  end

  @impl true
  def handle_call({:get_high_confidence_iocs, opts}, _from, state) do
    iocs = do_get_high_confidence_iocs(opts, state)
    {:reply, iocs, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_info(:recalculate_scores, state) do
    Logger.info("[IOCScoring] Starting periodic score recalculation")
    count = do_recalculate_all(state)
    Logger.info("[IOCScoring] Recalculated scores for #{count} IOCs")

    schedule_recalculation()
    new_state = %{state | stats: %{state.stats | last_recalculation: DateTime.utc_now()}}
    {:noreply, new_state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions - Score Calculation
  # ============================================================================

  defp do_calculate_score(ioc, state) do
    # Get IOC attributes
    source = get_source(ioc)
    ioc_type = get_type(ioc)
    created_at = get_created_at(ioc)
    metadata = get_metadata(ioc)
    ioc_id = get_id(ioc)

    # 1. Base score from source reputation
    base_score = get_source_score(source, state, metadata)

    # 2. Apply type weight
    type_weight = Map.get(@type_weights, ioc_type, 0.7)
    weighted_base = base_score * type_weight

    # 3. Calculate age decay
    age_factor = calculate_age_decay(created_at, state.half_life_days)

    # 4. Get sighting boost
    sighting_stats = do_get_sighting_stats(ioc_id)
    sighting_boost = calculate_sighting_boost(sighting_stats, state.max_sighting_boost)

    # 5. Calculate false positive penalty
    fp_penalty = calculate_fp_penalty(sighting_stats, state.fp_weight)

    # 6. Correlation boost (campaign/actor linkage)
    correlation_boost = calculate_correlation_boost(metadata, state.correlation_boost)

    # 7. MISP metadata boost
    misp_boost = calculate_misp_boost(metadata)

    # Calculate final score
    decayed_score = weighted_base * age_factor
    final_score = decayed_score + sighting_boost + correlation_boost + misp_boost - fp_penalty
    final_score = max(0, min(100, final_score))

    %{
      score: round(final_score),
      base_score: round(weighted_base),
      age_factor: Float.round(age_factor, 3),
      sighting_boost: round(sighting_boost),
      fp_penalty: round(fp_penalty),
      correlation_boost: round(correlation_boost),
      misp_boost: round(misp_boost),
      sighting_count: sighting_stats.sightings,
      fp_count: sighting_stats.false_positives,
      age_days: calculate_age_days(created_at),
      source: source,
      type: ioc_type
    }
  end

  defp get_source_score(source, state, metadata) do
    # Check custom reputation first
    custom = Map.get(state.custom_source_reputation, source)
    if custom, do: custom, else: get_default_source_score(source, metadata)
  end

  defp get_default_source_score(source, metadata) do
    base_score = Map.get(@source_reputation, source, @source_reputation["unknown"])

    # If it's a MISP source, adjust by trust level
    if String.starts_with?(source || "", "misp:") do
      trust_level = get_in(metadata, ["trust_level"]) || get_in(metadata, [:trust_level]) || 50
      # Scale base score by trust level (0-100)
      base_score * (trust_level / 100)
    else
      base_score
    end
  end

  defp calculate_age_decay(nil, _half_life), do: 1.0
  defp calculate_age_decay(created_at, half_life_days) do
    age_days = calculate_age_days(created_at)

    # Exponential decay: score = initial * 0.5^(age/half_life)
    # This gives us 50% score at half_life days, 25% at 2x half_life, etc.
    :math.pow(0.5, age_days / half_life_days)
  end

  defp calculate_age_days(nil), do: 0
  defp calculate_age_days(%DateTime{} = dt) do
    DateTime.diff(DateTime.utc_now(), dt, :day)
  end
  defp calculate_age_days(%NaiveDateTime{} = dt) do
    NaiveDateTime.diff(NaiveDateTime.utc_now(), dt, :day)
  end
  defp calculate_age_days(_), do: 0

  defp calculate_sighting_boost(sighting_stats, max_boost) do
    sightings = sighting_stats.sightings
    unique_sources = sighting_stats.unique_sources

    # Diminishing returns: each additional sighting adds less
    # Multiple unique sources add extra boost
    sighting_value = :math.log(sightings + 1) * 5
    source_bonus = unique_sources * 3

    min(sighting_value + source_bonus, max_boost)
  end

  defp calculate_fp_penalty(sighting_stats, fp_weight) do
    fps = sighting_stats.false_positives
    # Each FP report adds penalty, with increasing weight for confirmed FPs
    fps * fp_weight
  end

  defp calculate_correlation_boost(metadata, max_boost) do
    boost = 0

    # Boost for threat actor attribution
    boost = if metadata["threat_actor_id"] || metadata["threat_actor_name"], do: boost + 10, else: boost

    # Boost for campaign linkage
    boost = if metadata["campaign_id"] || metadata["campaign_name"], do: boost + 5, else: boost

    # Boost for MITRE ATT&CK linkage
    ttps = metadata["mitre_ttps"] || []
    boost = boost + min(length(ttps) * 2, 5)

    min(boost, max_boost)
  end

  defp calculate_misp_boost(metadata) do
    boost = 0

    # MISP threat level (1=high, 2=medium, 3=low, 4=undefined)
    threat_level = metadata["threat_level_id"] || metadata["misp_threat_level"]
    boost = case threat_level do
      1 -> boost + 10
      2 -> boost + 5
      3 -> boost + 2
      _ -> boost
    end

    # MISP analysis status (0=initial, 1=ongoing, 2=completed)
    analysis = metadata["analysis"] || metadata["misp_analysis"]
    boost = case analysis do
      2 -> boost + 5  # Completed analysis
      1 -> boost + 2  # Ongoing
      _ -> boost
    end

    # to_ids flag
    boost = if metadata["to_ids"] == true, do: boost + 5, else: boost

    min(boost, 20)
  end

  # ============================================================================
  # Private Functions - Sightings
  # ============================================================================

  defp do_record_sighting(ioc_id, opts) do
    source = Keyword.get(opts, :source, "internal")
    sighting_type = Keyword.get(opts, :type, :sighting)
    timestamp = Keyword.get(opts, :timestamp, DateTime.utc_now())

    # Get current sightings from ETS
    current = case :ets.lookup(@ets_sightings, ioc_id) do
      [{^ioc_id, data}] -> data
      [] -> %{sightings: [], false_positives: [], expirations: []}
    end

    sighting = %{
      source: source,
      timestamp: timestamp,
      type: sighting_type
    }

    updated = case sighting_type do
      :sighting -> %{current | sightings: [sighting | current.sightings]}
      :false_positive -> %{current | false_positives: [sighting | current.false_positives]}
      :expiration -> %{current | expirations: [sighting | current.expirations]}
    end

    :ets.insert(@ets_sightings, {ioc_id, updated})

    # Also update IOC score in database
    update_ioc_score(ioc_id)

    :ok
  end

  defp do_record_false_positive(ioc_id, analyst_id, opts) do
    reason = Keyword.get(opts, :reason, "Analyst reported")
    confidence = Keyword.get(opts, :confidence, 1.0)

    do_record_sighting(ioc_id, [
      type: :false_positive,
      source: "analyst:#{analyst_id}",
      metadata: %{reason: reason, confidence: confidence}
    ])
  end

  defp do_get_sighting_stats(nil), do: %{sightings: 0, false_positives: 0, expirations: 0, unique_sources: 0}
  defp do_get_sighting_stats(ioc_id) do
    case :ets.lookup(@ets_sightings, ioc_id) do
      [{^ioc_id, data}] ->
        unique_sources =
          data.sightings
          |> Enum.map(& &1.source)
          |> Enum.uniq()
          |> length()

        %{
          sightings: length(data.sightings),
          false_positives: length(data.false_positives),
          expirations: length(data.expirations),
          unique_sources: unique_sources,
          last_sighting: List.first(data.sightings),
          last_fp: List.first(data.false_positives)
        }

      [] ->
        %{sightings: 0, false_positives: 0, expirations: 0, unique_sources: 0}
    end
  end

  defp update_ioc_score(ioc_id) do
    # Queue score update (don't block sighting recording)
    Task.start(fn ->
      try do
        case Repo.get(IOC, ioc_id) do
          nil -> :ok
          ioc ->
            score_data = do_calculate_score(ioc, get_default_state())

            # Update the IOC's score in metadata
            new_metadata = Map.merge(ioc.metadata || %{}, %{
              "score" => score_data.score,
              "score_updated_at" => DateTime.to_iso8601(DateTime.utc_now())
            })

            ioc
            |> IOC.changeset(%{metadata: new_metadata})
            |> Repo.update()
        end
      rescue
        _ -> :ok
      end
    end)
  end

  defp get_default_state do
    %{
      half_life_days: @default_half_life_days,
      max_sighting_boost: @default_max_sighting_boost,
      fp_weight: @default_fp_weight,
      correlation_boost: @default_correlation_boost,
      custom_source_reputation: %{}
    }
  end

  # ============================================================================
  # Private Functions - Batch Operations
  # ============================================================================

  defp do_recalculate_all(state) do
    # Get all IOCs
    iocs = from(i in IOC, select: i) |> Repo.all()

    # Calculate and update scores
    Enum.each(iocs, fn ioc ->
      score_data = do_calculate_score(ioc, state)

      new_metadata = Map.merge(ioc.metadata || %{}, %{
        "score" => score_data.score,
        "score_breakdown" => %{
          "base" => score_data.base_score,
          "age_factor" => score_data.age_factor,
          "sighting_boost" => score_data.sighting_boost,
          "fp_penalty" => score_data.fp_penalty,
          "correlation_boost" => score_data.correlation_boost
        },
        "score_updated_at" => DateTime.to_iso8601(DateTime.utc_now())
      })

      ioc
      |> IOC.changeset(%{metadata: new_metadata})
      |> Repo.update()
    end)

    length(iocs)
  rescue
    e ->
      Logger.error("[IOCScoring] Recalculation failed: #{inspect(e)}")
      0
  end

  defp do_get_high_confidence_iocs(opts, state) do
    min_score = Keyword.get(opts, :min_score, state.min_score_threshold)
    limit = Keyword.get(opts, :limit, 100)
    type_filter = Keyword.get(opts, :type)

    query = from(i in IOC,
      where: fragment("(?->>'score')::int >= ?", i.metadata, ^min_score),
      order_by: [desc: fragment("(?->>'score')::int", i.metadata)],
      limit: ^limit
    )

    query = if type_filter do
      where(query, [i], i.type == ^type_filter)
    else
      query
    end

    query
    |> Repo.all()
    |> Enum.map(fn ioc ->
      %{
        id: ioc.id,
        type: ioc.type,
        value: ioc.value,
        source: ioc.source,
        score: get_in(ioc.metadata, ["score"]) || 0,
        created_at: ioc.inserted_at
      }
    end)
  rescue
    _ -> []
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp get_source(%IOC{} = ioc), do: ioc.source || "unknown"
  defp get_source(%{source: source}), do: source || "unknown"
  defp get_source(%{"source" => source}), do: source || "unknown"
  defp get_source(_), do: "unknown"

  defp get_type(%IOC{} = ioc), do: ioc.type || "unknown"
  defp get_type(%{type: type}), do: type || "unknown"
  defp get_type(%{"type" => type}), do: type || "unknown"
  defp get_type(_), do: "unknown"

  defp get_created_at(%IOC{} = ioc), do: ioc.inserted_at
  defp get_created_at(%{inserted_at: dt}), do: dt
  defp get_created_at(%{created_at: dt}), do: dt
  defp get_created_at(%{"inserted_at" => dt}), do: parse_datetime(dt)
  defp get_created_at(%{"created_at" => dt}), do: parse_datetime(dt)
  defp get_created_at(_), do: nil

  defp get_metadata(%IOC{} = ioc), do: ioc.metadata || %{}
  defp get_metadata(%{metadata: m}), do: m || %{}
  defp get_metadata(%{"metadata" => m}), do: m || %{}
  defp get_metadata(_), do: %{}

  defp get_id(%IOC{} = ioc), do: ioc.id
  defp get_id(%{id: id}), do: id
  defp get_id(%{"id" => id}), do: id
  defp get_id(_), do: nil

  defp parse_datetime(nil), do: nil
  defp parse_datetime(%DateTime{} = dt), do: dt
  defp parse_datetime(%NaiveDateTime{} = dt), do: dt
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp parse_datetime(_), do: nil

  defp schedule_recalculation do
    # Recalculate scores every 6 hours
    Process.send_after(self(), :recalculate_scores, :timer.hours(6))
  end

  defp update_stats(state, key) do
    count = Map.get(state.stats, key, 0)
    %{state | stats: Map.put(state.stats, key, count + 1)}
  end
end
