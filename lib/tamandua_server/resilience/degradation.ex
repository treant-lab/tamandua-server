defmodule TamanduaServer.Resilience.Degradation do
  @moduledoc """
  Graceful degradation strategies for handling service failures.

  Provides fallback mechanisms when primary services are unavailable,
  typically used in conjunction with circuit breakers.

  ## Patterns

  1. **Simple Fallback** - Return alternative value when primary fails
  2. **Cached Fallback** - Serve stale data from cache
  3. **Stale-While-Revalidate** - Return cache immediately, refresh async

  ## Usage

      # Simple fallback
      Degradation.with_fallback(
        :ml_service,
        fn -> MLClient.scan(file) end,
        fn -> {:ok, %{risk_score: 0.5, source: :fallback}} end
      )

      # Cached fallback
      Degradation.with_fallback(
        :threat_intel,
        fn -> ThreatIntel.lookup(ip) end,
        Degradation.cached_fallback("threat_intel:\#{ip}", 300)
      )
  """

  alias TamanduaServer.Resilience.Fuse
  require Logger

  @doc """
  Execute primary function with circuit breaker, falling back on failure.

  ## Parameters

  - `fuse_name` - Name of the circuit breaker to use
  - `primary_fn` - Function to execute (should return `{:ok, result}` or `{:error, reason}`)
  - `fallback_fn` - Function to call if primary fails or circuit is blown

  ## Example

      with_fallback(
        :external_api,
        fn -> ExternalAPI.fetch_data() end,
        fn -> {:ok, cached_data} end
      )
  """
  def with_fallback(fuse_name, primary_fn, fallback_fn) do
    case Fuse.run(fuse_name, primary_fn) do
      {:ok, result} ->
        {:ok, result}

      {:error, :blown} ->
        log_degradation(fuse_name, :circuit_blown)
        fallback_fn.()

      {:error, reason} ->
        log_degradation(fuse_name, reason)
        fallback_fn.()
    end
  end

  @doc """
  Create a cached fallback function.

  Returns a function that reads from cache when called.
  Typically used with `with_fallback/3`.

  ## Parameters

  - `cache_key` - Key to lookup in cache
  - `ttl_seconds` - Maximum age of cached data to accept (optional, defaults to any age)

  ## Example

      fallback_fn = cached_fallback("api_data:users", 300)
      with_fallback(:api, fn -> fetch_users() end, fallback_fn)
  """
  def cached_fallback(cache_key, _ttl_seconds \\ :infinity) do
    fn ->
      # In a real implementation, this would check Nebulex cache
      # For now, return error if cache miss
      case lookup_cache(cache_key) do
        {:ok, value} ->
          Logger.info("Serving from cache (degraded): #{cache_key}")
          {:ok, value}

        :miss ->
          {:error, :no_fallback}
      end
    end
  end

  @doc """
  Stale-while-revalidate pattern.

  Returns cached data immediately, then refreshes cache asynchronously.

  ## Parameters

  - `cache_key` - Key for cache storage
  - `primary_fn` - Function to fetch fresh data
  - `ttl_seconds` - Cache TTL in seconds

  ## Example

      stale_while_revalidate(
        "threat_feeds:abusech",
        fn -> ThreatFeeds.fetch_abusech() end,
        3600
      )
  """
  def stale_while_revalidate(cache_key, primary_fn, ttl_seconds) do
    case lookup_cache(cache_key) do
      {:ok, cached_value} ->
        # Return cached immediately
        Logger.debug("Serving stale data while revalidating: #{cache_key}")

        # Spawn async refresh
        Task.start(fn ->
          case primary_fn.() do
            {:ok, fresh_value} ->
              write_cache(cache_key, fresh_value, ttl_seconds)
              Logger.debug("Cache revalidated: #{cache_key}")

            {:error, reason} ->
              Logger.warning("Failed to revalidate cache #{cache_key}: #{inspect(reason)}")
          end
        end)

        {:ok, cached_value}

      :miss ->
        # No cache, fetch synchronously
        case primary_fn.() do
          {:ok, value} ->
            write_cache(cache_key, value, ttl_seconds)
            {:ok, value}

          error ->
            error
        end
    end
  end

  # Helpers

  defp log_degradation(fuse_name, reason) do
    Logger.warning("Degraded mode activated for #{fuse_name}: #{inspect(reason)}")

    :telemetry.execute(
      [:tamandua, :degradation, :activated],
      %{count: 1},
      %{fuse_name: fuse_name, reason: reason}
    )
  end

  defp lookup_cache(_key) do
    # Placeholder - would integrate with TamanduaServer.Cache (Nebulex)
    # For now, return miss
    :miss
  end

  defp write_cache(_key, _value, _ttl) do
    # Placeholder - would integrate with TamanduaServer.Cache (Nebulex)
    :ok
  end
end
