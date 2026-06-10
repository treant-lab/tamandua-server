defmodule TamanduaServerWeb.Plugs.AdaptiveRateLimiter do
  @moduledoc """
  Adaptive rate limiter using a token bucket algorithm with per-endpoint
  cost weighting, user-tier buckets, and automatic backoff for repeat offenders.

  ## Token Bucket Algorithm

  Each client gets a bucket of tokens that refills at a steady rate.
  Every request consumes tokens proportional to the endpoint's cost.
  When the bucket is empty, requests are rejected with HTTP 429.

  ## Features

  - **Per-endpoint cost**: Heavy operations (scan, hunt, response) cost more tokens
  - **Tier-based buckets**: Admin, Analyst, Agent, and Anonymous tiers
  - **Adaptive backoff**: Repeat offenders get halved refill rates for 10 minutes
  - **Burst allowance**: Up to 2x bucket capacity on first request after full refill
  - **Whitelist**: Internal IPs and health check endpoints bypass limiting
  - **Metrics**: Emits `:telemetry` events for monitoring
  - **Standard headers**: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After

  ## ETS Table

  Uses `:rate_limit_buckets` with rows:
      {key, tokens, last_refill, violations, backoff_until}

  ## Usage

      plug TamanduaServerWeb.Plugs.AdaptiveRateLimiter
  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  # ---------------------------------------------------------------------------
  # ETS table name
  # ---------------------------------------------------------------------------
  @ets_table :rate_limit_buckets

  # ---------------------------------------------------------------------------
  # Per-endpoint token costs (method + path pattern)
  # Higher cost = heavier operation
  # ---------------------------------------------------------------------------
  @endpoint_costs %{
    # Heavy operations
    {"POST", "/api/v1/response/scan"} => 10,
    {"POST", "/api/v1/response/kill"} => 10,
    {"POST", "/api/v1/response/quarantine"} => 10,
    {"POST", "/api/v1/response/collect"} => 10,
    {"POST", "/api/v1/hunting/query"} => 5,
    {"POST", "/api/v1/hunting/search"} => 5,
    {"POST", "/api/v1/hunting/tql"} => 5,
    {"POST", "/api/v1/response/execute"} => 5,
    {"POST", "/api/v1/ai/query"} => 5,
    {"POST", "/api/v1/ai/chat"} => 5,
    {"POST", "/api/v1/ml/predict"} => 5,
    {"POST", "/api/v1/ml/predict/batch"} => 8,
    {"POST", "/api/v1/samples/analyze"} => 8,
    {"POST", "/api/v1/samples/batch"} => 10,
    {"POST", "/api/v1/forensics"} => 8,
    {"POST", "/api/v1/reports/generate"} => 5,
    {"POST", "/api/v1/reports/generate-advanced"} => 8,

    # Normal read operations
    {"GET", "/api/v1/alerts"} => 1,
    {"GET", "/api/v1/events"} => 1,
    {"GET", "/api/v1/agents"} => 1,
    {"GET", "/api/v1/stats/overview"} => 1,

    # Agent telemetry (high volume, low cost)
    {"POST", "/api/v1/agents/telemetry"} => 0.5,
    {"POST", "/api/v1/xdr/ingest"} => 0.5,
    {"POST", "/api/v1/xdr/ingest/batch"} => 1
  }

  # ---------------------------------------------------------------------------
  # Bucket configuration per tier
  # {max_tokens, refill_rate_per_second}
  # ---------------------------------------------------------------------------
  @tier_config %{
    admin:     {500,  10.0},
    analyst:   {200,   5.0},
    agent:     {1000, 20.0},
    anonymous: {30,    1.0}
  }

  # ---------------------------------------------------------------------------
  # Adaptive backoff configuration
  # ---------------------------------------------------------------------------

  # Number of violations in the tracking window before backoff kicks in
  @violation_threshold 3

  # Time window in seconds for counting violations
  @violation_window_sec 300  # 5 minutes

  # Duration of the backoff penalty in seconds
  @backoff_duration_sec 600  # 10 minutes

  # Factor to reduce refill rate during backoff
  @backoff_refill_factor 0.5

  # Burst multiplier -- allow up to this factor of max_tokens after a full refill
  @burst_multiplier 2.0

  # ---------------------------------------------------------------------------
  # Plug callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    ensure_table()

    if whitelisted?(conn) do
      conn
    else
      enforce(conn)
    end
  end

  # ---------------------------------------------------------------------------
  # Core enforcement
  # ---------------------------------------------------------------------------

  defp enforce(conn) do
    now = System.system_time(:millisecond)
    tier = resolve_tier(conn)
    key = bucket_key(conn, tier)
    cost = endpoint_cost(conn)
    {max_tokens, base_refill} = Map.fetch!(@tier_config, tier)
    burst_cap = trunc(max_tokens * @burst_multiplier)

    # Fetch or initialise the bucket
    {tokens, last_refill, violations, backoff_until} = get_bucket(key, burst_cap, now)

    # Determine effective refill rate (halved during backoff)
    effective_refill =
      if now < backoff_until do
        base_refill * @backoff_refill_factor
      else
        base_refill
      end

    # Refill tokens based on elapsed time
    elapsed_sec = (now - last_refill) / 1000.0
    refilled = tokens + elapsed_sec * effective_refill
    current_tokens = min(refilled, burst_cap / 1.0)

    if current_tokens >= cost do
      # Allow the request
      new_tokens = current_tokens - cost
      put_bucket(key, new_tokens, now, violations, backoff_until)

      remaining = trunc(new_tokens)
      reset_sec = if effective_refill > 0 do
        trunc(Float.ceil((max_tokens - new_tokens) / effective_refill))
      else
        60
      end
      reset_at = System.system_time(:second) + reset_sec

      emit_telemetry(:allowed, conn, tier, remaining)

      conn
      |> put_rate_limit_headers(max_tokens, remaining, reset_at)
    else
      # Deny the request -- record violation
      {new_violations, new_backoff} =
        record_violation(violations, backoff_until, now)

      put_bucket(key, current_tokens, now, new_violations, new_backoff)

      retry_after =
        if effective_refill > 0 do
          trunc(Float.ceil((cost - current_tokens) / effective_refill))
        else
          60
        end

      reset_at = System.system_time(:second) + retry_after

      emit_telemetry(:denied, conn, tier, 0)

      Logger.warning(
        "[AdaptiveRateLimiter] Rate limited: key=#{key} tier=#{tier} " <>
          "tokens=#{Float.round(current_tokens, 2)} cost=#{cost} violations=#{new_violations}"
      )

      conn
      |> put_rate_limit_headers(max_tokens, 0, reset_at)
      |> put_resp_header("retry-after", to_string(retry_after))
      |> put_resp_content_type("application/json")
      |> send_resp(429, Jason.encode!(%{
        error: "Rate limit exceeded",
        retry_after: retry_after
      }))
      |> halt()
    end
  end

  # ---------------------------------------------------------------------------
  # Tier resolution
  # ---------------------------------------------------------------------------

  defp resolve_tier(conn) do
    user = conn.assigns[:current_user]
    agent = conn.assigns[:current_agent]

    cond do
      not is_nil(agent) ->
        :agent

      not is_nil(user) ->
        role = to_string(user.role) |> String.downcase()
        case role do
          "admin" -> :admin
          "superadmin" -> :admin
          "analyst" -> :analyst
          "soc_analyst" -> :analyst
          _ -> :analyst
        end

      true ->
        :anonymous
    end
  end

  # ---------------------------------------------------------------------------
  # Bucket key generation
  # ---------------------------------------------------------------------------

  defp bucket_key(conn, tier) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()

    identifier =
      case tier do
        :agent ->
          agent = conn.assigns[:current_agent]
          if agent, do: "agent:#{agent.id}", else: "ip:#{ip}"

        :admin ->
          user = conn.assigns[:current_user]
          "user:#{user.id}"

        :analyst ->
          user = conn.assigns[:current_user]
          "user:#{user.id}"

        :anonymous ->
          "ip:#{ip}"
      end

    "rl:#{identifier}"
  end

  # ---------------------------------------------------------------------------
  # Per-endpoint cost lookup
  # ---------------------------------------------------------------------------

  defp endpoint_cost(conn) do
    method = conn.method
    path = Enum.join(["" | conn.path_info], "/")

    # Try exact match first
    case Map.get(@endpoint_costs, {method, path}) do
      nil ->
        # Try prefix match for parameterised routes
        find_prefix_cost(method, path)

      cost ->
        cost
    end
  end

  defp find_prefix_cost(method, path) do
    @endpoint_costs
    |> Enum.find_value(fn {{m, pattern}, cost} ->
      if m == method && String.starts_with?(path, pattern) do
        cost
      else
        nil
      end
    end)
    |> case do
      nil -> default_cost(method)
      cost -> cost
    end
  end

  # Fallback costs by HTTP method
  defp default_cost("GET"), do: 1
  defp default_cost("HEAD"), do: 1
  defp default_cost("OPTIONS"), do: 0.5
  defp default_cost("POST"), do: 2
  defp default_cost("PUT"), do: 2
  defp default_cost("PATCH"), do: 2
  defp default_cost("DELETE"), do: 3
  defp default_cost(_), do: 1

  # ---------------------------------------------------------------------------
  # Violation tracking / adaptive backoff
  # ---------------------------------------------------------------------------

  defp record_violation(violations, backoff_until, now) do
    new_violations = violations + 1

    new_backoff =
      if new_violations >= @violation_threshold and now >= backoff_until do
        # Activate backoff for @backoff_duration_sec
        now + @backoff_duration_sec * 1000
      else
        backoff_until
      end

    {new_violations, new_backoff}
  end

  # ---------------------------------------------------------------------------
  # ETS bucket operations
  # ---------------------------------------------------------------------------

  @doc false
  def ensure_table do
    case :ets.whereis(@ets_table) do
      :undefined ->
        try do
          :ets.new(@ets_table, [
            :set,
            :public,
            :named_table,
            {:write_concurrency, true},
            {:read_concurrency, true}
          ])
        rescue
          ArgumentError -> :ok
        end

      _ ->
        :ok
    end
  end

  defp get_bucket(key, burst_cap, now) do
    case :ets.lookup(@ets_table, key) do
      [] ->
        # New bucket: start at burst capacity
        {burst_cap / 1.0, now, 0, 0}

      [{^key, tokens, last_refill, violations, backoff_until}] ->
        # Expire old violations if outside the window
        violations =
          if now - last_refill > @violation_window_sec * 1000 do
            0
          else
            violations
          end

        {tokens, last_refill, violations, backoff_until}
    end
  end

  defp put_bucket(key, tokens, last_refill, violations, backoff_until) do
    :ets.insert(@ets_table, {key, tokens, last_refill, violations, backoff_until})
  end

  # ---------------------------------------------------------------------------
  # Whitelist checks
  # ---------------------------------------------------------------------------

  defp whitelisted?(conn) do
    health_check?(conn) || private_ip?(conn.remote_ip)
  end

  defp health_check?(conn) do
    path = Enum.join(["" | conn.path_info], "/")
    String.starts_with?(path, "/health")
  end

  defp private_ip?({127, _, _, _}), do: true
  defp private_ip?({10, _, _, _}), do: true
  defp private_ip?({172, b, _, _}) when b >= 16 and b <= 31, do: true
  defp private_ip?({192, 168, _, _}), do: true
  # IPv6 loopback ::1
  defp private_ip?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  # IPv4-mapped IPv6 loopback ::ffff:127.0.0.1
  defp private_ip?({0, 0, 0, 0, 0, 65535, 32512, 1}), do: true
  defp private_ip?(_), do: false

  # ---------------------------------------------------------------------------
  # Response headers
  # ---------------------------------------------------------------------------

  defp put_rate_limit_headers(conn, limit, remaining, reset_at) do
    conn
    |> put_resp_header("x-ratelimit-limit", to_string(limit))
    |> put_resp_header("x-ratelimit-remaining", to_string(max(0, remaining)))
    |> put_resp_header("x-ratelimit-reset", to_string(reset_at))
  end

  # ---------------------------------------------------------------------------
  # Telemetry events
  # ---------------------------------------------------------------------------

  defp emit_telemetry(outcome, conn, tier, remaining) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()
    path = Enum.join(["" | conn.path_info], "/")

    :telemetry.execute(
      [:tamandua, :rate_limiter, outcome],
      %{remaining: remaining},
      %{
        tier: tier,
        ip: ip,
        method: conn.method,
        path: path
      }
    )
  end

  # ---------------------------------------------------------------------------
  # Periodic cleanup (called from Application supervisor)
  # ---------------------------------------------------------------------------

  @doc """
  Removes expired bucket entries from the ETS table.
  Intended to be called periodically (e.g. every 5 minutes).
  """
  def cleanup do
    now = System.system_time(:millisecond)
    # Remove entries not touched for 30 minutes
    max_idle_ms = 30 * 60 * 1000

    case :ets.whereis(@ets_table) do
      :undefined ->
        :ok

      _ ->
        :ets.foldl(
          fn {_key, _tokens, last_refill, _violations, _backoff} = entry, acc ->
            if now - last_refill > max_idle_ms do
              :ets.delete(@ets_table, elem(entry, 0))
            end

            acc
          end,
          :ok,
          @ets_table
        )
    end
  end
end
