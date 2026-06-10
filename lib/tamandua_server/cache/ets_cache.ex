defmodule TamanduaServer.Cache.ETSCache do
  @moduledoc """
  High-performance in-memory ETS cache for frequently accessed lookups.

  Optimized for read-heavy workloads with concurrent access patterns.
  Used for detection rules (YARA, Sigma), IOCs, and configuration data.

  ## Features

  - Multiple ETS tables per cache type
  - TTL support via background cleanup
  - Cache warming on startup
  - Atomic read/write operations
  - Ordered set for range queries
  - Built-in statistics tracking

  ## Cache Types

  - `:yara_rules` - YARA detection rules (1 hour TTL)
  - `:sigma_rules` - Sigma detection rules (1 hour TTL)
  - `:iocs` - Indicators of Compromise (1 day TTL)
  - `:detection_config` - Detection engine configuration (1 hour TTL)
  - `:threat_intel` - Threat intelligence data (6 hours TTL)

  ## Examples

      # Get/put in specific cache
      ETSCache.get(:yara_rules, "rule_123")
      ETSCache.put(:yara_rules, "rule_123", rule_data)

      # Get all entries
      ETSCache.all(:sigma_rules)

      # Cache warming
      ETSCache.warm(:iocs, fn -> ThreatIntel.list_active_iocs() end)
  """

  use GenServer
  require Logger

  @cleanup_interval :timer.minutes(5)
  @default_ttl :timer.hours(1)

  # Cache type configurations
  @cache_configs %{
    yara_rules: %{ttl: :timer.hours(1), table_type: :set},
    sigma_rules: %{ttl: :timer.hours(1), table_type: :set},
    iocs: %{ttl: :timer.hours(24), table_type: :set},
    detection_config: %{ttl: :timer.hours(1), table_type: :set},
    threat_intel: %{ttl: :timer.hours(6), table_type: :set},
    ml_predictions: %{ttl: :timer.minutes(15), table_type: :set},
    agent_metadata: %{ttl: :timer.minutes(5), table_type: :set},
    user_sessions: %{ttl: :timer.hours(24), table_type: :set}
  }

  # Statistics table
  @stats_table :ets_cache_stats

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Gets a value from ETS cache.
  Returns `{:ok, value}` if found and not expired, `:miss` otherwise.
  """
  def get(cache_type, key) do
    table = table_name(cache_type)

    case :ets.lookup(table, key) do
      [{^key, value, expires_at}] ->
        if System.monotonic_time(:millisecond) < expires_at do
          increment_stat(cache_type, :hits)
          {:ok, value}
        else
          :ets.delete(table, key)
          increment_stat(cache_type, :misses)
          :miss
        end

      [] ->
        increment_stat(cache_type, :misses)
        :miss
    end
  rescue
    ArgumentError ->
      Logger.warning("[ETSCache] Table #{cache_type} not initialized")
      :miss
  end

  @doc """
  Puts a value into ETS cache with optional TTL override.
  """
  def put(cache_type, key, value, opts \\ []) do
    table = table_name(cache_type)
    config = Map.get(@cache_configs, cache_type, %{ttl: @default_ttl})
    ttl = Keyword.get(opts, :ttl, config.ttl)

    expires_at = System.monotonic_time(:millisecond) + ttl
    :ets.insert(table, {key, value, expires_at})
    :ok
  rescue
    ArgumentError ->
      Logger.error("[ETSCache] Failed to put in table #{cache_type}")
      {:error, :table_not_found}
  end

  @doc """
  Deletes a key from the cache.
  """
  def delete(cache_type, key) do
    table = table_name(cache_type)
    :ets.delete(table, key)
    :ok
  rescue
    ArgumentError ->
      {:error, :table_not_found}
  end

  @doc """
  Clears all entries from a cache type.
  """
  def clear(cache_type) do
    table = table_name(cache_type)
    :ets.delete_all_objects(table)
    :ok
  rescue
    ArgumentError ->
      {:error, :table_not_found}
  end

  @doc """
  Returns all entries in a cache (useful for warming).
  """
  def all(cache_type) do
    table = table_name(cache_type)
    now = System.monotonic_time(:millisecond)

    table
    |> :ets.tab2list()
    |> Enum.filter(fn {_key, _value, expires_at} -> expires_at > now end)
    |> Enum.map(fn {key, value, _expires_at} -> {key, value} end)
  rescue
    ArgumentError ->
      []
  end

  @doc """
  Returns the number of entries in a cache.
  """
  def size(cache_type) do
    table = table_name(cache_type)
    :ets.info(table, :size)
  rescue
    ArgumentError ->
      0
  end

  @doc """
  Cache-aside pattern with ETS.
  """
  def fetch(cache_type, key, fetch_fn) when is_function(fetch_fn) do
    case get(cache_type, key) do
      {:ok, value} ->
        {:ok, value}

      :miss ->
        case fetch_fn.() do
          {:ok, value} ->
            put(cache_type, key, value)
            {:ok, value}

          {:error, _} = error ->
            error

          value ->
            put(cache_type, key, value)
            {:ok, value}
        end
    end
  end

  @doc """
  Warms a cache by bulk-loading data.

  ## Examples

      ETSCache.warm(:yara_rules, fn ->
        Detection.list_yara_rules()
        |> Enum.map(&{&1.id, &1})
      end)
  """
  def warm(cache_type, fetch_fn) when is_function(fetch_fn) do
    Logger.info("[ETSCache] Warming cache: #{cache_type}")

    case fetch_fn.() do
      entries when is_list(entries) ->
        Enum.each(entries, fn {key, value} ->
          put(cache_type, key, value)
        end)

        Logger.info("[ETSCache] Warmed #{length(entries)} entries in #{cache_type}")
        {:ok, length(entries)}

      {:error, reason} ->
        Logger.error("[ETSCache] Failed to warm #{cache_type}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Returns statistics for a cache type.
  """
  def stats(cache_type) do
    hits = get_stat(cache_type, :hits)
    misses = get_stat(cache_type, :misses)
    total = hits + misses
    hit_rate = if total > 0, do: Float.round(hits / total * 100, 2), else: 0.0

    %{
      cache_type: cache_type,
      size: size(cache_type),
      hits: hits,
      misses: misses,
      total_requests: total,
      hit_rate_percent: hit_rate,
      ttl_ms: Map.get(@cache_configs, cache_type, %{ttl: @default_ttl}).ttl
    }
  end

  @doc """
  Returns statistics for all cache types.
  """
  def stats_all do
    @cache_configs
    |> Map.keys()
    |> Enum.map(&stats/1)
  end

  @doc """
  Checks if a cache type exists.
  """
  def exists?(cache_type) do
    table = table_name(cache_type)

    case :ets.info(table) do
      :undefined -> false
      _ -> true
    end
  end

  @doc """
  Returns all configured cache types.
  """
  def cache_types do
    Map.keys(@cache_configs)
  end

  # GenServer Callbacks

  @impl true
  def init(_opts) do
    # Create ETS table for each cache type
    Enum.each(@cache_configs, fn {cache_type, config} ->
      table = table_name(cache_type)
      table_type = Map.get(config, :table_type, :set)

      :ets.new(table, [
        table_type,
        :public,
        :named_table,
        read_concurrency: true,
        write_concurrency: true
      ])

      Logger.debug("[ETSCache] Created table: #{table} (type: #{table_type})")
    end)

    # Create statistics table
    :ets.new(@stats_table, [
      :set,
      :public,
      :named_table,
      read_concurrency: true,
      write_concurrency: true
    ])

    schedule_cleanup()

    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    expired_count = cleanup_expired()

    if expired_count > 0 do
      Logger.debug("[ETSCache] Cleaned up #{expired_count} expired entries")
    end

    schedule_cleanup()
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Private Functions

  defp table_name(cache_type) do
    String.to_atom("ets_cache_#{cache_type}")
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp cleanup_expired do
    now = System.monotonic_time(:millisecond)

    @cache_configs
    |> Map.keys()
    |> Enum.map(fn cache_type ->
      table = table_name(cache_type)

      :ets.select_delete(table, [
        {{:_, :_, :"$1"}, [{:<, :"$1", now}], [true]}
      ])
    end)
    |> Enum.sum()
  end

  defp increment_stat(cache_type, stat) do
    key = {cache_type, stat}

    try do
      :ets.update_counter(@stats_table, key, {2, 1})
    rescue
      ArgumentError ->
        :ets.insert(@stats_table, {key, 1})
    end
  end

  defp get_stat(cache_type, stat) do
    key = {cache_type, stat}

    case :ets.lookup(@stats_table, key) do
      [{^key, count}] -> count
      [] -> 0
    end
  end
end
