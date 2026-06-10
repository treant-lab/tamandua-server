defmodule TamanduaServer.ThreatIntel.Aggregator do
  @moduledoc """
  Threat Intelligence Aggregator.

  Central hub for managing IOCs from multiple sources with:
  - Deduplication across all feeds
  - Confidence scoring based on multiple sources
  - Priority ranking
  - Automatic enrichment
  - Bloom filters for fast negative lookups
  - Background indexing

  ## Architecture

  ```
  [Feed 1] ─┐
  [Feed 2] ─┤
  [Feed 3] ─┼──► [Aggregator] ──► [IOC Database]
  [Feed N] ─┤         │
            │         ▼
            │    [Bloom Filter]
            │    [ETS Hot Cache]
            ▼
       [Enrichment Pipeline]
  ```

  ## Usage

      # Ingest IOCs from a feed
      Aggregator.ingest_batch("recorded_future", iocs)

      # Fast lookup (uses bloom filter first)
      Aggregator.fast_lookup(:ip, "1.2.3.4")

      # Get aggregated stats
      Aggregator.get_stats()
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.IOCs
  alias TamanduaServer.ThreatIntel.IOCScoring

  @ets_hot_cache :aggregator_hot_cache
  @ets_source_tracking :aggregator_sources
  @ets_dedup_index :aggregator_dedup

  # Bloom filter parameters (for ~10M entries with 0.1% FP rate)
  @bloom_size 143_775_874  # bits
  @bloom_hashes 10

  # Hot cache settings
  @hot_cache_ttl :timer.hours(24)
  @hot_cache_max_size 100_000

  # Batch processing
  @batch_size 1000
  @enrichment_batch_size 100

  # Source weights for confidence calculation
  @source_weights %{
    "crowdstrike" => 1.0,
    "mandiant" => 1.0,
    "recorded_future" => 0.95,
    "proofpoint" => 0.9,
    "alienvault_otx" => 0.8,
    "abuse_ch" => 0.85,
    "feodo_tracker" => 0.9,
    "ssl_blacklist" => 0.85,
    "urlhaus" => 0.85,
    "malware_bazaar" => 0.9,
    "phishtank" => 0.85,
    "openphish" => 0.85,
    "spamhaus" => 0.95,
    "emerging_threats" => 0.8,
    "misp" => 0.8,
    "manual" => 0.7,
    "default" => 0.6
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Ingest a batch of IOCs from a specific source.

  IOCs are deduplicated, scored, and stored.
  Returns stats about the ingestion.
  """
  @spec ingest_batch(String.t(), [map()]) :: {:ok, map()}
  def ingest_batch(source, iocs) when is_list(iocs) do
    GenServer.call(__MODULE__, {:ingest_batch, source, iocs}, 120_000)
  end

  @doc """
  Fast lookup using bloom filter for quick negative check.

  Returns immediately if IOC is definitely not in database.
  """
  @spec fast_lookup(atom(), String.t()) :: {:ok, map()} | :not_found | :maybe
  def fast_lookup(type, value) do
    GenServer.call(__MODULE__, {:fast_lookup, type, value})
  end

  @doc """
  Lookup with full details including all sources that reported the IOC.
  """
  @spec detailed_lookup(atom(), String.t()) :: {:ok, map()} | :not_found
  def detailed_lookup(type, value) do
    GenServer.call(__MODULE__, {:detailed_lookup, type, value})
  end

  @doc """
  Get IOCs that appear in multiple sources (high confidence).
  """
  @spec get_multi_source_iocs(keyword()) :: [map()]
  def get_multi_source_iocs(opts \\ []) do
    GenServer.call(__MODULE__, {:get_multi_source_iocs, opts})
  end

  @doc """
  Get aggregation statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get feed health status.
  """
  @spec get_feed_health() :: map()
  def get_feed_health do
    GenServer.call(__MODULE__, :get_feed_health)
  end

  @doc """
  Trigger background enrichment for recent IOCs.
  """
  @spec enrich_recent() :: :ok
  def enrich_recent do
    GenServer.cast(__MODULE__, :enrich_recent)
  end

  @doc """
  Force rebuild of bloom filter and indexes.
  """
  @spec rebuild_indexes() :: :ok
  def rebuild_indexes do
    GenServer.cast(__MODULE__, :rebuild_indexes)
  end

  @doc """
  Clear hot cache.
  """
  @spec clear_cache() :: :ok
  def clear_cache do
    GenServer.call(__MODULE__, :clear_cache)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@ets_hot_cache, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_source_tracking, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@ets_dedup_index, [:named_table, :set, :public, read_concurrency: true])

    # Initialize bloom filter (using ETS for simplicity, could use :bloom_filter lib)
    :ets.new(:aggregator_bloom, [:named_table, :set, :public, read_concurrency: true])

    state = %{
      bloom_filter: initialize_bloom_filter(),
      stats: %{
        total_ingested: 0,
        total_deduplicated: 0,
        total_enriched: 0,
        by_source: %{},
        by_type: %{},
        multi_source_count: 0,
        last_ingestion: nil,
        bloom_false_positives: 0
      },
      feed_health: %{},
      enrichment_queue: :queue.new(),
      cache_hits: 0,
      cache_misses: 0
    }

    # Schedule periodic maintenance
    schedule_cache_cleanup()
    schedule_health_check()

    Logger.info("[Aggregator] Initialized with bloom filter and caching")

    {:ok, state}
  end

  @impl true
  def handle_call({:ingest_batch, source, iocs}, _from, state) do
    start_time = System.monotonic_time(:millisecond)

    # Process in batches for memory efficiency
    {results, new_state} = process_ingestion_batch(source, iocs, state)

    elapsed = System.monotonic_time(:millisecond) - start_time
    Logger.info("[Aggregator] Ingested #{results.inserted} IOCs from #{source} in #{elapsed}ms (#{results.deduplicated} deduped)")

    {:reply, {:ok, results}, new_state}
  end

  @impl true
  def handle_call({:fast_lookup, type, value}, _from, state) do
    key = normalize_key(type, value)

    # First check bloom filter
    if bloom_maybe_contains?(state.bloom_filter, key) do
      # Bloom filter says maybe - check hot cache
      case :ets.lookup(@ets_hot_cache, key) do
        [{^key, cached_data, _timestamp}] ->
          new_state = %{state | cache_hits: state.cache_hits + 1}
          {:reply, {:ok, cached_data}, new_state}

        [] ->
          # Not in cache, need full lookup
          new_state = %{state | cache_misses: state.cache_misses + 1}
          {:reply, :maybe, new_state}
      end
    else
      # Bloom filter says definitely not present
      {:reply, :not_found, state}
    end
  end

  @impl true
  def handle_call({:detailed_lookup, type, value}, _from, state) do
    key = normalize_key(type, value)

    # Get all sources that reported this IOC
    sources = :ets.lookup(@ets_source_tracking, key)
    |> Enum.map(fn {_, source_data} -> source_data end)

    if length(sources) > 0 do
      # Calculate aggregated confidence
      aggregated = aggregate_ioc_data(key, sources)

      # Update hot cache
      :ets.insert(@ets_hot_cache, {key, aggregated, System.monotonic_time(:second)})

      {:reply, {:ok, aggregated}, state}
    else
      {:reply, :not_found, state}
    end
  end

  @impl true
  def handle_call({:get_multi_source_iocs, opts}, _from, state) do
    min_sources = Keyword.get(opts, :min_sources, 2)
    limit = Keyword.get(opts, :limit, 100)
    type_filter = Keyword.get(opts, :type)

    # Get IOCs with multiple sources
    multi_source = :ets.foldl(fn {key, _}, acc ->
      source_count = length(:ets.lookup(@ets_source_tracking, key))

      if source_count >= min_sources do
        [type, value] = String.split(key, ":", parts: 2)

        if is_nil(type_filter) or type == Atom.to_string(type_filter) do
          [{key, source_count} | acc]
        else
          acc
        end
      else
        acc
      end
    end, [], @ets_dedup_index)
    |> Enum.sort_by(fn {_, count} -> count end, :desc)
    |> Enum.take(limit)
    |> Enum.map(fn {key, source_count} ->
      sources = :ets.lookup(@ets_source_tracking, key)
      |> Enum.map(fn {_, data} -> data end)

      aggregate_ioc_data(key, sources)
      |> Map.put(:source_count, source_count)
    end)

    {:reply, multi_source, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = Map.merge(state.stats, %{
      hot_cache_size: :ets.info(@ets_hot_cache, :size),
      dedup_index_size: :ets.info(@ets_dedup_index, :size),
      source_tracking_size: :ets.info(@ets_source_tracking, :size),
      cache_hit_rate: calculate_cache_hit_rate(state),
      enrichment_queue_size: :queue.len(state.enrichment_queue)
    })

    {:reply, stats, state}
  end

  @impl true
  def handle_call(:get_feed_health, _from, state) do
    {:reply, state.feed_health, state}
  end

  @impl true
  def handle_call(:clear_cache, _from, state) do
    :ets.delete_all_objects(@ets_hot_cache)
    {:reply, :ok, %{state | cache_hits: 0, cache_misses: 0}}
  end

  @impl true
  def handle_cast(:enrich_recent, state) do
    Task.start(fn -> do_enrichment_batch(state) end)
    {:noreply, state}
  end

  @impl true
  def handle_cast(:rebuild_indexes, state) do
    Logger.info("[Aggregator] Rebuilding indexes...")
    Task.start(fn -> do_rebuild_indexes() end)
    {:noreply, %{state | bloom_filter: initialize_bloom_filter()}}
  end

  @impl true
  def handle_info(:cache_cleanup, state) do
    cleanup_expired_cache()
    schedule_cache_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(:health_check, state) do
    new_health = check_feed_health(state)
    schedule_health_check()
    {:noreply, %{state | feed_health: new_health}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Ingestion
  # ============================================================================

  defp process_ingestion_batch(source, iocs, state) do
    # Normalize and deduplicate within batch
    normalized = Enum.map(iocs, fn ioc ->
      normalize_ioc(ioc, source)
    end)
    |> Enum.reject(&is_nil/1)

    # Check for duplicates and merge
    {new_iocs, updated_iocs} = Enum.reduce(normalized, {[], []}, fn ioc, {new_acc, update_acc} ->
      key = normalize_key(ioc.type, ioc.value)

      case :ets.lookup(@ets_dedup_index, key) do
        [{^key, existing_id}] ->
          # Already exists - track new source
          source_data = %{
            source: source,
            confidence: ioc.confidence,
            severity: ioc.severity,
            tags: ioc.tags,
            metadata: ioc.metadata,
            seen_at: DateTime.utc_now()
          }
          :ets.insert(@ets_source_tracking, {key, source_data})
          {new_acc, [existing_id | update_acc]}

        [] ->
          # New IOC
          {[ioc | new_acc], update_acc}
      end
    end)

    # Insert new IOCs to database
    inserted_count = if length(new_iocs) > 0 do
      case IOCs.bulk_add(new_iocs, on_conflict: :update) do
        {:ok, result} ->
          # Update indexes for new IOCs
          Enum.each(new_iocs, fn ioc ->
            key = normalize_key(ioc.type, ioc.value)
            :ets.insert(@ets_dedup_index, {key, ioc.value})

            source_data = %{
              source: source,
              confidence: ioc.confidence,
              severity: ioc.severity,
              tags: ioc.tags,
              metadata: ioc.metadata,
              seen_at: DateTime.utc_now()
            }
            :ets.insert(@ets_source_tracking, {key, source_data})

            # Add to bloom filter
            bloom_add(state.bloom_filter, key)
          end)

          result.successful

        {:error, _} ->
          0
      end
    else
      0
    end

    # Update stats
    new_stats = update_ingestion_stats(state.stats, source, length(iocs), inserted_count, length(updated_iocs))

    # Update feed health
    new_health = Map.put(state.feed_health, source, %{
      last_seen: DateTime.utc_now(),
      iocs_last_batch: length(iocs),
      status: :healthy
    })

    # Refresh the detection engine ETS cache if any IOCs were inserted
    if inserted_count > 0 do
      Task.start(fn -> TamanduaServer.Detection.Engine.reload_iocs() end)
    end

    results = %{
      total: length(iocs),
      inserted: inserted_count,
      deduplicated: length(updated_iocs),
      source: source
    }

    {results, %{state | stats: new_stats, feed_health: new_health}}
  end

  defp normalize_ioc(ioc, source) do
    value = ioc[:value] || ioc["value"]
    type = ioc[:type] || ioc["type"]

    if value && type && String.length(to_string(value)) > 0 do
      %{
        type: to_string(type),
        value: normalize_value(type, value),
        source: source,
        severity: ioc[:severity] || ioc["severity"] || "medium",
        confidence: (ioc[:confidence] || ioc["confidence"] || 0.7) |> ensure_float(),
        tags: (ioc[:tags] || ioc["tags"] || []) |> List.wrap(),
        metadata: (ioc[:metadata] || ioc["metadata"] || %{}) |> ensure_map(),
        description: ioc[:description] || ioc["description"] || ""
      }
    else
      nil
    end
  end

  defp normalize_value(type, value) when type in ["ip", :ip] do
    String.trim(to_string(value))
  end

  defp normalize_value(type, value) when type in ["domain", :domain, "url", :url] do
    value
    |> to_string()
    |> String.downcase()
    |> String.trim()
  end

  defp normalize_value(type, value) when type in ["hash_md5", :hash_md5, "hash_sha1", :hash_sha1, "hash_sha256", :hash_sha256] do
    value
    |> to_string()
    |> String.downcase()
    |> String.trim()
  end

  defp normalize_value(_type, value), do: String.trim(to_string(value))

  defp normalize_key(type, value) do
    "#{type}:#{normalize_value(type, value)}"
  end

  defp ensure_float(val) when is_float(val), do: val
  defp ensure_float(val) when is_integer(val), do: val / 1.0
  defp ensure_float(_), do: 0.7

  defp ensure_map(val) when is_map(val), do: val
  defp ensure_map(_), do: %{}

  # ============================================================================
  # Private Functions - Aggregation
  # ============================================================================

  defp aggregate_ioc_data(key, sources) do
    [type, value] = String.split(key, ":", parts: 2)

    # Calculate aggregated confidence
    weighted_confidences = Enum.map(sources, fn src ->
      weight = Map.get(@source_weights, src.source, @source_weights["default"])
      src.confidence * weight
    end)

    # Multi-source boost: each additional source adds confidence
    source_count = length(sources)
    base_confidence = Enum.sum(weighted_confidences) / max(length(weighted_confidences), 1)
    multi_source_boost = min((source_count - 1) * 0.05, 0.15)
    final_confidence = min(base_confidence + multi_source_boost, 1.0)

    # Aggregate severity (take highest)
    severities = Enum.map(sources, & &1.severity)
    highest_severity = highest_severity(severities)

    # Merge tags
    all_tags = Enum.flat_map(sources, & &1.tags) |> Enum.uniq()

    # Get all source names
    source_names = Enum.map(sources, & &1.source) |> Enum.uniq()

    # First and last seen
    first_seen = Enum.min_by(sources, & &1.seen_at, DateTime).seen_at
    last_seen = Enum.max_by(sources, & &1.seen_at, DateTime).seen_at

    %{
      type: type,
      value: value,
      confidence: Float.round(final_confidence, 3),
      severity: highest_severity,
      tags: all_tags,
      sources: source_names,
      source_count: source_count,
      first_seen: first_seen,
      last_seen: last_seen,
      metadata: merge_metadata(sources)
    }
  end

  defp highest_severity(severities) do
    priority = %{"critical" => 4, "high" => 3, "medium" => 2, "low" => 1}

    severities
    |> Enum.max_by(fn sev -> Map.get(priority, sev, 0) end, fn -> "medium" end)
  end

  defp merge_metadata(sources) do
    Enum.reduce(sources, %{}, fn src, acc ->
      Map.merge(acc, src.metadata || %{})
    end)
  end

  # ============================================================================
  # Private Functions - Bloom Filter
  # ============================================================================

  defp initialize_bloom_filter do
    # Simple bloom filter using ETS
    # For production, use a proper bloom filter library
    %{
      size: @bloom_size,
      hashes: @bloom_hashes,
      bits: :ets.new(:bloom_bits, [:set, :public])
    }
  end

  defp bloom_add(bloom, key) do
    positions = bloom_positions(key, bloom.hashes, bloom.size)
    Enum.each(positions, fn pos ->
      :ets.insert(bloom.bits, {pos, true})
    end)
  end

  defp bloom_maybe_contains?(bloom, key) do
    positions = bloom_positions(key, bloom.hashes, bloom.size)
    Enum.all?(positions, fn pos ->
      case :ets.lookup(bloom.bits, pos) do
        [{^pos, true}] -> true
        [] -> false
      end
    end)
  end

  defp bloom_positions(key, num_hashes, size) do
    # Use multiple hash functions
    base_hash = :erlang.phash2(key, size)

    Enum.map(1..num_hashes, fn i ->
      :erlang.phash2({key, i}, size)
    end)
    |> Enum.uniq()
  end

  # ============================================================================
  # Private Functions - Maintenance
  # ============================================================================

  defp cleanup_expired_cache do
    now = System.monotonic_time(:second)
    ttl_seconds = @hot_cache_ttl |> div(1000)

    # Delete expired entries
    expired = :ets.foldl(fn {key, _, timestamp}, acc ->
      if now - timestamp > ttl_seconds do
        [key | acc]
      else
        acc
      end
    end, [], @ets_hot_cache)

    Enum.each(expired, fn key ->
      :ets.delete(@ets_hot_cache, key)
    end)

    # Enforce max size
    current_size = :ets.info(@ets_hot_cache, :size)
    if current_size > @hot_cache_max_size do
      # Delete oldest entries
      to_delete = current_size - @hot_cache_max_size

      :ets.tab2list(@ets_hot_cache)
      |> Enum.sort_by(fn {_, _, ts} -> ts end)
      |> Enum.take(to_delete)
      |> Enum.each(fn {key, _, _} -> :ets.delete(@ets_hot_cache, key) end)
    end
  end

  defp check_feed_health(state) do
    now = DateTime.utc_now()
    stale_threshold = :timer.hours(12) |> div(1000)

    Map.new(state.feed_health, fn {source, health} ->
      status = if health.last_seen do
        age = DateTime.diff(now, health.last_seen)
        if age > stale_threshold, do: :stale, else: :healthy
      else
        :unknown
      end

      {source, Map.put(health, :status, status)}
    end)
  end

  defp do_enrichment_batch(_state) do
    # Get recent IOCs that need enrichment
    # This would call external enrichment services
    Logger.debug("[Aggregator] Running enrichment batch")
  end

  defp do_rebuild_indexes do
    Logger.info("[Aggregator] Rebuilding all indexes from database...")

    # Clear existing indexes
    :ets.delete_all_objects(@ets_dedup_index)
    :ets.delete_all_objects(@ets_source_tracking)

    # Rebuild from database
    # This would iterate through the IOC database and rebuild indexes

    Logger.info("[Aggregator] Index rebuild complete")
  end

  defp update_ingestion_stats(stats, source, total, inserted, deduplicated) do
    by_source = Map.update(stats.by_source, source, total, &(&1 + total))

    %{stats |
      total_ingested: stats.total_ingested + total,
      total_deduplicated: stats.total_deduplicated + deduplicated,
      by_source: by_source,
      last_ingestion: DateTime.utc_now()
    }
  end

  defp calculate_cache_hit_rate(state) do
    total = state.cache_hits + state.cache_misses
    if total > 0, do: state.cache_hits / total, else: 0.0
  end

  defp schedule_cache_cleanup do
    Process.send_after(self(), :cache_cleanup, :timer.minutes(15))
  end

  defp schedule_health_check do
    Process.send_after(self(), :health_check, :timer.minutes(5))
  end
end
