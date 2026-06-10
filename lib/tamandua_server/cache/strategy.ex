defmodule TamanduaServer.Cache.Strategy do
  @moduledoc """
  Caching strategies for different resource types.

  Defines TTL, cache type (Redis vs ETS), and invalidation rules
  for each resource in the Tamandua EDR system.

  ## Usage

      # Get cache strategy for a resource
      strategy = Strategy.for_resource(:alert)

      # Cache a resource using its strategy
      Strategy.cache(:alert, alert_id, alert_data)

      # Fetch with strategy
      Strategy.fetch(:alert, alert_id, fn -> Repo.get(Alert, alert_id) end)
  """

  alias TamanduaServer.Cache.{RedisCache, ETSCache, Invalidator}

  @doc """
  Returns the caching strategy for a given resource type.
  """
  def for_resource(resource_type) do
    case resource_type do
      # Hot data - Redis with short TTL
      :alert ->
        %{
          cache: :redis,
          ttl: RedisCache.ttl_5min(),
          namespace: "tamandua",
          invalidate_on: [:update, :delete, :status_change]
        }

      :agent ->
        %{
          cache: :redis,
          ttl: :timer.minutes(1),
          namespace: "tamandua",
          invalidate_on: [:update, :delete, :status_change, :disconnect]
        }

      # Detection rules - ETS with longer TTL
      :yara_rule ->
        %{
          cache: :ets,
          cache_type: :yara_rules,
          ttl: RedisCache.ttl_1hour(),
          invalidate_on: [:update, :delete, :reload]
        }

      :sigma_rule ->
        %{
          cache: :ets,
          cache_type: :sigma_rules,
          ttl: RedisCache.ttl_1hour(),
          invalidate_on: [:update, :delete, :reload]
        }

      # Threat intel - ETS with daily refresh
      :ioc ->
        %{
          cache: :ets,
          cache_type: :iocs,
          ttl: RedisCache.ttl_1day(),
          invalidate_on: [:update, :delete, :sync]
        }

      :threat_intel ->
        %{
          cache: :ets,
          cache_type: :threat_intel,
          ttl: :timer.hours(6),
          invalidate_on: [:sync, :enrichment_update]
        }

      # User sessions - Redis with session TTL
      :user_session ->
        %{
          cache: :redis,
          ttl: :timer.hours(24),
          namespace: "sessions",
          invalidate_on: [:logout, :timeout, :revoke]
        }

      # API responses - HTTP cache with ETag
      :api_response ->
        %{
          cache: :http,
          ttl: :timer.minutes(1),
          etag: true,
          vary: ["Accept", "Authorization"]
        }

      # Dashboard aggregations - Redis with medium TTL
      :dashboard_stats ->
        %{
          cache: :redis,
          ttl: :timer.minutes(5),
          namespace: "dashboards",
          invalidate_on: [:alert_change, :agent_change]
        }

      # Default strategy
      _ ->
        %{
          cache: :redis,
          ttl: RedisCache.ttl_5min(),
          namespace: "tamandua"
        }
    end
  end

  @doc """
  Caches data using the appropriate strategy for the resource type.
  """
  def cache(resource_type, key, value, opts \\ []) do
    strategy = for_resource(resource_type)
    ttl = Keyword.get(opts, :ttl, strategy.ttl)

    case strategy.cache do
      :redis ->
        namespace = Map.get(strategy, :namespace, "tamandua")
        cache_key = build_key(resource_type, key)
        RedisCache.put(namespace, cache_key, value, ttl: ttl)

      :ets ->
        cache_type = Map.get(strategy, :cache_type, resource_type)
        ETSCache.put(cache_type, key, value, ttl: ttl)

      _ ->
        {:error, :unsupported_cache_type}
    end
  end

  @doc """
  Fetches data using cache-aside pattern with appropriate strategy.
  """
  def fetch(resource_type, key, fetch_fn, opts \\ []) do
    strategy = for_resource(resource_type)
    ttl = Keyword.get(opts, :ttl, strategy.ttl)

    case strategy.cache do
      :redis ->
        namespace = Map.get(strategy, :namespace, "tamandua")
        cache_key = build_key(resource_type, key)
        RedisCache.fetch(namespace, cache_key, [ttl: ttl], fetch_fn)

      :ets ->
        cache_type = Map.get(strategy, :cache_type, resource_type)
        ETSCache.fetch(cache_type, key, fetch_fn)

      _ ->
        fetch_fn.()
    end
  end

  @doc """
  Gets data from cache using appropriate strategy.
  """
  def get(resource_type, key) do
    strategy = for_resource(resource_type)

    case strategy.cache do
      :redis ->
        namespace = Map.get(strategy, :namespace, "tamandua")
        cache_key = build_key(resource_type, key)
        RedisCache.get(namespace, cache_key)

      :ets ->
        cache_type = Map.get(strategy, :cache_type, resource_type)
        ETSCache.get(cache_type, key)

      _ ->
        :miss
    end
  end

  @doc """
  Invalidates a resource using its strategy.
  """
  def invalidate(resource_type, key) do
    Invalidator.invalidate(resource_type, key)
  end

  @doc """
  Checks if invalidation should occur for a given event.
  """
  def should_invalidate?(resource_type, event) do
    strategy = for_resource(resource_type)
    invalidate_on = Map.get(strategy, :invalidate_on, [])

    event in invalidate_on
  end

  @doc """
  Returns recommended cache configuration for deployment.
  """
  def deployment_config do
    %{
      redis: %{
        pool_size: 10,
        timeout: 5000,
        max_memory: "2gb",
        maxmemory_policy: "allkeys-lru"
      },
      ets: %{
        total_memory_limit: "1gb",
        cleanup_interval: :timer.minutes(5)
      },
      http: %{
        enable_etag: true,
        enable_last_modified: true,
        default_ttl: 60
      }
    }
  end

  # Private Functions

  defp build_key(resource_type, key) do
    "#{resource_type}:#{key}"
  end
end
