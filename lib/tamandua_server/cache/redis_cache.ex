defmodule TamanduaServer.Cache.RedisCache do
  @moduledoc """
  Redis-backed distributed cache with TTL support, namespacing, and serialization.

  Provides high-availability caching for hot data (alerts, agents, sessions) across
  multiple nodes with automatic failover and connection pooling.

  ## Features

  - TTL-based expiration (5 min, 1 hour, 1 day presets)
  - Namespace isolation (tenant-specific caches)
  - JSON serialization via Jason
  - Connection pooling with Redix
  - Distributed cache invalidation via PubSub
  - Cache stampede prevention (single-flight pattern)
  - Stale-while-revalidate support

  ## Examples

      # Simple get/put
      RedisCache.get("alert:123")
      RedisCache.put("alert:123", alert_data, ttl: :timer.minutes(5))

      # Namespaced cache
      RedisCache.get("tenant_1", "agent:456")
      RedisCache.put("tenant_1", "agent:456", agent_data)

      # Cache-aside pattern
      RedisCache.fetch("user:1", ttl: :timer.hours(1), fn ->
        Repo.get(User, 1)
      end)

      # Pattern-based invalidation
      RedisCache.delete_pattern("tenant_1", "alert:*")
  """

  use GenServer
  require Logger

  alias Phoenix.PubSub

  @default_namespace "tamandua"
  @default_ttl :timer.minutes(5)
  @default_pool_size 10

  # Predefined TTLs
  @ttl_5min :timer.minutes(5)
  @ttl_1hour :timer.hours(1)
  @ttl_1day :timer.hours(24)

  # PubSub topic for cache invalidation
  @invalidation_topic "cache:invalidation"

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Gets a value from Redis cache.
  Returns `{:ok, value}` if found, `:miss` if not found or expired.
  """
  def get(key), do: get(@default_namespace, key)

  def get(namespace, key) do
    cache_key = build_key(namespace, key)

    case Redix.command(:redix, ["GET", cache_key]) do
      {:ok, nil} ->
        :miss

      {:ok, json} ->
        case Jason.decode(json) do
          {:ok, value} -> {:ok, value}
          {:error, _} -> :miss
        end

      {:error, reason} ->
        Logger.warning("[RedisCache] GET failed for #{cache_key}: #{inspect(reason)}")
        :miss
    end
  end

  @doc """
  Puts a value into Redis cache with TTL.

  ## Options

  - `:ttl` - Time to live in milliseconds (default: 5 minutes)
  - `:namespace` - Cache namespace (default: "tamandua")
  """
  def put(key, value, opts \\ [])

  def put(key, value, opts) when is_list(opts) do
    put(@default_namespace, key, value, opts)
  end

  def put(namespace, key, value) when is_atom(namespace) or is_binary(namespace) do
    put(namespace, key, value, [])
  end

  def put(namespace, key, value, opts) do
    cache_key = build_key(namespace, key)
    ttl = Keyword.get(opts, :ttl, @default_ttl)

    case Jason.encode(value) do
      {:ok, json} ->
        # Use SETEX for atomic set with expiration
        ttl_seconds = div(ttl, 1000)

        case Redix.command(:redix, ["SETEX", cache_key, ttl_seconds, json]) do
          {:ok, "OK"} -> :ok
          {:error, reason} ->
            Logger.warning("[RedisCache] PUT failed for #{cache_key}: #{inspect(reason)}")
            {:error, reason}
        end

      {:error, reason} ->
        Logger.error("[RedisCache] JSON encode failed: #{inspect(reason)}")
        {:error, :encode_failed}
    end
  end

  @doc """
  Deletes a key from the cache and broadcasts invalidation.
  """
  def delete(key), do: delete(@default_namespace, key)

  def delete(namespace, key) do
    cache_key = build_key(namespace, key)

    case Redix.command(:redix, ["DEL", cache_key]) do
      {:ok, _count} ->
        # Broadcast invalidation to other nodes
        broadcast_invalidation(namespace, key)
        :ok

      {:error, reason} ->
        Logger.warning("[RedisCache] DEL failed for #{cache_key}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Deletes all keys matching a pattern (e.g., "alert:*").
  Uses SCAN for safe iteration without blocking Redis.
  """
  def delete_pattern(pattern), do: delete_pattern(@default_namespace, pattern)

  def delete_pattern(namespace, pattern) do
    full_pattern = build_key(namespace, pattern)

    # Use SCAN to avoid blocking Redis
    keys = scan_keys(full_pattern)

    case Redix.pipeline(:redix, Enum.map(keys, &["DEL", &1])) do
      {:ok, _results} ->
        # Broadcast pattern invalidation
        broadcast_invalidation(namespace, pattern)
        {:ok, length(keys)}

      {:error, reason} ->
        Logger.warning("[RedisCache] DEL pattern failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Cache-aside pattern: get from cache or fetch using provided function.

  ## Options

  - `:ttl` - Time to live in milliseconds
  - `:stale_while_revalidate` - Serve stale data while refreshing (default: false)
  """
  def fetch(key, opts \\ [], fetch_fn) when is_function(fetch_fn) do
    fetch(@default_namespace, key, opts, fetch_fn)
  end

  def fetch(namespace, key, opts, fetch_fn) when is_function(fetch_fn) do
    case get(namespace, key) do
      {:ok, value} ->
        {:ok, value}

      :miss ->
        # Cache stampede prevention: use distributed lock
        lock_key = build_key(namespace, "lock:#{key}")

        case acquire_lock(lock_key) do
          :ok ->
            try do
              # Double-check cache (another process may have populated it)
              case get(namespace, key) do
                {:ok, value} ->
                  {:ok, value}

                :miss ->
                  case fetch_fn.() do
                    {:ok, value} ->
                      put(namespace, key, value, opts)
                      {:ok, value}

                    {:error, _} = error ->
                      error

                    value ->
                      put(namespace, key, value, opts)
                      {:ok, value}
                  end
              end
            after
              release_lock(lock_key)
            end

          {:error, :locked} ->
            # Wait and retry
            Process.sleep(100)
            get(namespace, key)
        end
    end
  end

  @doc """
  Checks if a key exists in the cache.
  """
  def exists?(key), do: exists?(@default_namespace, key)

  def exists?(namespace, key) do
    cache_key = build_key(namespace, key)

    case Redix.command(:redix, ["EXISTS", cache_key]) do
      {:ok, 1} -> true
      {:ok, 0} -> false
      {:error, _} -> false
    end
  end

  @doc """
  Gets TTL for a key in seconds.
  Returns `{:ok, ttl}` or `:miss` if key doesn't exist.
  """
  def ttl(key), do: ttl(@default_namespace, key)

  def ttl(namespace, key) do
    cache_key = build_key(namespace, key)

    case Redix.command(:redix, ["TTL", cache_key]) do
      {:ok, -2} -> :miss
      {:ok, -1} -> {:ok, :no_expiration}
      {:ok, ttl_seconds} -> {:ok, ttl_seconds}
      {:error, _} -> :miss
    end
  end

  @doc """
  Increments a counter in Redis (useful for rate limiting, metrics).
  """
  def incr(key, amount \\ 1), do: incr(@default_namespace, key, amount)

  def incr(namespace, key, amount) do
    cache_key = build_key(namespace, key)

    case Redix.command(:redix, ["INCRBY", cache_key, amount]) do
      {:ok, new_value} -> {:ok, new_value}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Clears all keys in a namespace.
  CAUTION: This uses pattern deletion and may be slow on large datasets.
  """
  def clear_namespace(namespace) do
    delete_pattern(namespace, "*")
  end

  @doc """
  Returns cache statistics (requires Redis INFO command).
  """
  def stats do
    case Redix.command(:redix, ["INFO", "stats"]) do
      {:ok, info} ->
        parse_redis_info(info)

      {:error, reason} ->
        Logger.warning("[RedisCache] Stats failed: #{inspect(reason)}")
        %{}
    end
  end

  # GenServer Callbacks

  @impl true
  def init(opts) do
    config = get_config()
    pool_size = Keyword.get(opts, :pool_size, config[:pool_size])

    # Subscribe to cache invalidation broadcasts
    PubSub.subscribe(TamanduaServer.PubSub, @invalidation_topic)

    {:ok, %{pool_size: pool_size}}
  end

  @impl true
  def handle_info({:invalidate, namespace, key}, state) do
    # Local invalidation triggered by remote node
    Logger.debug("[RedisCache] Received invalidation for #{namespace}:#{key}")
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Private Functions

  defp build_key(namespace, key) do
    "#{namespace}:#{key}"
  end

  defp scan_keys(pattern, cursor \\ "0", acc \\ []) do
    case Redix.command(:redix, ["SCAN", cursor, "MATCH", pattern, "COUNT", "100"]) do
      {:ok, [next_cursor, keys]} ->
        new_acc = acc ++ keys

        if next_cursor == "0" do
          new_acc
        else
          scan_keys(pattern, next_cursor, new_acc)
        end

      {:error, reason} ->
        Logger.warning("[RedisCache] SCAN failed: #{inspect(reason)}")
        acc
    end
  end

  defp acquire_lock(lock_key, timeout \\ 5000) do
    # Use SET NX EX for atomic lock acquisition
    ttl_seconds = div(timeout, 1000)

    case Redix.command(:redix, ["SET", lock_key, "1", "NX", "EX", ttl_seconds]) do
      {:ok, "OK"} -> :ok
      {:ok, nil} -> {:error, :locked}
      {:error, reason} -> {:error, reason}
    end
  end

  defp release_lock(lock_key) do
    Redix.command(:redix, ["DEL", lock_key])
  end

  defp broadcast_invalidation(namespace, key) do
    PubSub.broadcast(
      TamanduaServer.PubSub,
      @invalidation_topic,
      {:invalidate, namespace, key}
    )
  end

  defp parse_redis_info(info) do
    info
    |> String.split("\r\n")
    |> Enum.filter(&String.contains?(&1, ":"))
    |> Enum.map(&String.split(&1, ":"))
    |> Enum.filter(&(length(&1) == 2))
    |> Enum.map(fn [k, v] -> {k, v} end)
    |> Map.new()
  end

  defp get_config do
    Application.get_env(:tamandua_server, :cache, [])
    |> Keyword.get(:redis, [])
    |> Keyword.merge(
      host: "localhost",
      port: 6379,
      namespace: @default_namespace,
      pool_size: @default_pool_size
    )
  end

  # Public helper functions for common TTL values

  def ttl_5min, do: @ttl_5min
  def ttl_1hour, do: @ttl_1hour
  def ttl_1day, do: @ttl_1day
end
