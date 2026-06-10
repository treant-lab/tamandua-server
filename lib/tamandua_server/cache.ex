defmodule TamanduaServer.Cache do
  @moduledoc """
  A simple caching interface using ETS with TTL-based expiration.

  Supports namespaced caches and tracks hit/miss statistics.

  ## Examples

      # Simple usage
      TamanduaServer.Cache.put("my_key", "my_value")
      TamanduaServer.Cache.get("my_key")
      #=> {:ok, "my_value"}

      # With TTL (in seconds)
      TamanduaServer.Cache.put("temp_key", "temp_value", 60)

      # Namespaced caches
      TamanduaServer.Cache.put(:ml_predictions, "hash123", %{score: 0.95})
      TamanduaServer.Cache.get(:ml_predictions, "hash123")

      # Get or fetch pattern
      TamanduaServer.Cache.get_or_fetch("user:1", 300, fn ->
        {:ok, Repo.get(User, 1)}
      end)
  """

  use GenServer

  @table :tamandua_cache
  @stats_table :tamandua_cache_stats
  @cleanup_interval :timer.seconds(60)
  @default_ttl 300

  # Client API

  @doc """
  Gets a value from the cache.
  Returns `{:ok, value}` if found and not expired, `:miss` otherwise.
  """
  def get(key), do: get(:default, key)

  def get(namespace, key) do
    cache_key = {namespace, key}

    case :ets.lookup(@table, cache_key) do
      [{^cache_key, value, expires_at}] ->
        if System.monotonic_time(:second) < expires_at do
          increment_stat(namespace, :hits)
          {:ok, value}
        else
          :ets.delete(@table, cache_key)
          increment_stat(namespace, :misses)
          :miss
        end

      [] ->
        increment_stat(namespace, :misses)
        :miss
    end
  end

  @doc """
  Puts a value in the cache with an optional TTL in seconds.
  Default TTL is #{@default_ttl} seconds.
  """
  def put(key, value, ttl_seconds \\ @default_ttl)

  def put(key, value, ttl_seconds) when is_integer(ttl_seconds) do
    put(:default, key, value, ttl_seconds)
  end

  def put(namespace, key, value) when is_atom(namespace) do
    put(namespace, key, value, @default_ttl)
  end

  def put(namespace, key, value, ttl_seconds) do
    cache_key = {namespace, key}
    expires_at = System.monotonic_time(:second) + ttl_seconds
    :ets.insert(@table, {cache_key, value, expires_at})
    :ok
  end

  @doc """
  Deletes a key from the cache.
  """
  def delete(key), do: delete(:default, key)

  def delete(namespace, key) do
    cache_key = {namespace, key}
    :ets.delete(@table, cache_key)
    :ok
  end

  @doc """
  Clears all entries from the cache.
  """
  def clear do
    :ets.delete_all_objects(@table)
    :ets.delete_all_objects(@stats_table)
    :ok
  end

  @doc """
  Clears all entries from a specific namespace.
  """
  def clear(namespace) do
    :ets.match_delete(@table, {{namespace, :_}, :_, :_})
    :ets.delete(@stats_table, {namespace, :hits})
    :ets.delete(@stats_table, {namespace, :misses})
    :ok
  end

  @doc """
  Gets a value from cache, or fetches it using the provided function if not present.

  The fetch function should return `{:ok, value}`, `{:error, reason}`, or a raw value.
  """
  def get_or_fetch(key, ttl_seconds \\ @default_ttl, fetch_fn)

  def get_or_fetch(key, ttl_seconds, fetch_fn) when is_function(fetch_fn) do
    get_or_fetch(:default, key, ttl_seconds, fetch_fn)
  end

  def get_or_fetch(namespace, key, fetch_fn) when is_atom(namespace) and is_function(fetch_fn) do
    get_or_fetch(namespace, key, @default_ttl, fetch_fn)
  end

  def get_or_fetch(namespace, key, ttl_seconds, fetch_fn) do
    case get(namespace, key) do
      {:ok, value} ->
        {:ok, value}

      :miss ->
        case fetch_fn.() do
          {:ok, value} ->
            put(namespace, key, value, ttl_seconds)
            {:ok, value}

          {:error, _} = error ->
            error

          value ->
            put(namespace, key, value, ttl_seconds)
            {:ok, value}
        end
    end
  end

  @doc """
  Returns statistics for the cache.
  """
  def stats, do: stats(:default)

  def stats(namespace) do
    hits = get_stat(namespace, :hits)
    misses = get_stat(namespace, :misses)
    total = hits + misses
    hit_rate = if total > 0, do: Float.round(hits / total * 100, 2), else: 0.0

    %{
      namespace: namespace,
      hits: hits,
      misses: misses,
      total_requests: total,
      hit_rate_percent: hit_rate
    }
  end

  @doc """
  Returns the total number of entries in the cache.
  """
  def size do
    :ets.info(@table, :size)
  end

  @doc """
  Returns true if the cache ETS table is initialized.
  """
  def initialized? do
    case :ets.info(@table) do
      :undefined -> false
      _ -> true
    end
  end

  @doc """
  Returns the number of entries in a specific namespace.
  """
  def size(namespace) do
    :ets.select_count(@table, [
      {{{namespace, :_}, :_, :_}, [], [true]}
    ])
  end

  # GenServer Implementation

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    :ets.new(@table, [
      :set,
      :public,
      :named_table,
      read_concurrency: true,
      write_concurrency: true
    ])

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
      require Logger
      Logger.debug("Cache cleanup removed #{expired_count} expired entries")
    end

    schedule_cleanup()
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Private Functions

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp cleanup_expired do
    now = System.monotonic_time(:second)

    :ets.select_delete(@table, [
      {{:_, :_, :"$1"}, [{:<, :"$1", now}], [true]}
    ])
  end

  defp increment_stat(namespace, stat) do
    key = {namespace, stat}

    try do
      :ets.update_counter(@stats_table, key, {2, 1})
    rescue
      ArgumentError ->
        :ets.insert(@stats_table, {key, 1})
    end
  end

  defp get_stat(namespace, stat) do
    key = {namespace, stat}

    case :ets.lookup(@stats_table, key) do
      [{^key, count}] -> count
      [] -> 0
    end
  end
end
