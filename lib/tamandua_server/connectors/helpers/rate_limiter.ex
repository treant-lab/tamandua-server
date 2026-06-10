defmodule TamanduaServer.Connectors.Helpers.RateLimiter do
  @moduledoc """
  Built-in rate limiting for connectors.

  Uses token bucket algorithm with ETS-based state.
  Supports per-connector and per-endpoint rate limits.
  """

  use GenServer
  require Logger

  @table :connector_rate_limits

  defmodule Bucket do
    @moduledoc false
    defstruct [:capacity, :tokens, :refill_rate, :last_refill]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if request is allowed under rate limit.

  ## Example:
      case RateLimiter.check_rate("misp:api", limit: 100, window: 60) do
        :ok -> # proceed
        {:error, :rate_limited} -> # wait
      end
  """
  def check_rate(key, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    window = Keyword.get(opts, :window, 60)

    GenServer.call(__MODULE__, {:check_rate, key, limit, window})
  end

  @doc """
  Reset rate limit for a key.
  """
  def reset(key) do
    GenServer.call(__MODULE__, {:reset, key})
  end

  @doc """
  Get current rate limit status for a key.
  """
  def status(key) do
    GenServer.call(__MODULE__, {:status, key})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    Logger.info("[Connectors.RateLimiter] Started rate limiter")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:check_rate, key, limit, window}, _from, state) do
    now = System.system_time(:second)

    bucket = case :ets.lookup(@table, key) do
      [{^key, b}] -> b
      [] -> init_bucket(limit, window)
    end

    # Refill tokens based on elapsed time
    elapsed = now - bucket.last_refill
    refill = min(elapsed * bucket.refill_rate, bucket.capacity - bucket.tokens)
    new_tokens = bucket.tokens + refill

    result = if new_tokens >= 1 do
      # Consume 1 token
      updated_bucket = %{bucket |
        tokens: new_tokens - 1,
        last_refill: now
      }
      :ets.insert(@table, {key, updated_bucket})
      :ok
    else
      # Rate limited
      :ets.insert(@table, {key, %{bucket | last_refill: now, tokens: new_tokens}})
      wait_time = trunc((1 - new_tokens) / bucket.refill_rate)
      {:error, {:rate_limited, wait_time}}
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:reset, key}, _from, state) do
    :ets.delete(@table, key)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:status, key}, _from, state) do
    result = case :ets.lookup(@table, key) do
      [{^key, bucket}] ->
        {:ok, %{
          tokens: bucket.tokens,
          capacity: bucket.capacity,
          refill_rate: bucket.refill_rate
        }}
      [] ->
        {:error, :not_found}
    end

    {:reply, result, state}
  end

  defp init_bucket(capacity, window) do
    %Bucket{
      capacity: capacity,
      tokens: capacity,
      refill_rate: capacity / window,
      last_refill: System.system_time(:second)
    }
  end
end
