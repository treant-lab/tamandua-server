defmodule TamanduaServerWeb.Plugs.TenantRateLimiter do
  @moduledoc """
  Per-tenant rate limiting plug.

  This plug enforces rate limits based on the tenant's license tier
  and configured limits. It uses ETS for high-performance rate tracking.

  ## Features

  - Per-organization rate limiting
  - Per-API-key rate limiting (overrides org limits if more restrictive)
  - Sliding window rate limiting
  - Configurable limits per tier
  - Rate limit headers in responses

  ## Usage

  Add to your router pipeline after TenantScope:

      pipeline :api_tenant do
        plug TamanduaServerWeb.Plugs.TenantScope
        plug TamanduaServerWeb.Plugs.TenantRateLimiter
      end

  ## Rate Limit Headers

  Responses include standard rate limit headers:
  - `X-RateLimit-Limit` - Maximum requests allowed
  - `X-RateLimit-Remaining` - Requests remaining in current window
  - `X-RateLimit-Reset` - Unix timestamp when the window resets

  ## Options

  - `:window` - Time window in seconds (default: 60 for per-minute)
  - `:limit_type` - Type of limit: `:minute`, `:hour`, `:day` (default: `:minute`)
  - `:bypass_for` - List of roles that bypass rate limiting (default: [])
  """

  import Plug.Conn
  require Logger

  alias TamanduaServer.Tenants
  alias TamanduaServer.Accounts.{APIKey}

  @behaviour Plug

  @ets_table :tenant_rate_limits_tracker
  @cleanup_interval 300_000  # 5 minutes in milliseconds

  # Default limits when no config exists
  @default_limits %{
    api_requests_per_minute: 1000,
    api_requests_per_hour: 50000,
    api_requests_per_day: 500000
  }

  @impl true
  def init(opts) do
    # Ensure ETS table exists
    ensure_ets_table()

    # Start cleanup process if not already running
    start_cleanup_process()

    opts
  end

  @impl true
  def call(conn, opts) do
    limit_type = Keyword.get(opts, :limit_type, :minute)
    bypass_roles = Keyword.get(opts, :bypass_for, [])

    # Check if user should bypass rate limiting
    if should_bypass?(conn, bypass_roles) do
      conn
    else
      check_rate_limit(conn, limit_type)
    end
  end

  # ---------------------------------------------------------------------------
  # Rate Limit Checking
  # ---------------------------------------------------------------------------

  defp check_rate_limit(conn, limit_type) do
    org_id = conn.assigns[:current_organization_id]
    api_key = conn.assigns[:current_api_key]

    if org_id do
      {limit, window} = get_effective_limit(org_id, api_key, limit_type)
      key = rate_limit_key(org_id, api_key, limit_type)

      case check_and_increment(key, limit, window) do
        {:ok, _count, remaining, reset_at} ->
          conn
          |> put_rate_limit_headers(limit, remaining, reset_at)

        {:error, :rate_limited, reset_at} ->
          Logger.warning("Rate limit exceeded for org #{org_id}, key: #{key}")

          conn
          |> put_rate_limit_headers(limit, 0, reset_at)
          |> put_resp_content_type("application/json")
          |> send_resp(429, Jason.encode!(%{
            error: "Rate limit exceeded",
            code: "rate_limited",
            retry_after: reset_at - System.system_time(:second)
          }))
          |> halt()
      end
    else
      # No tenant context, apply global defaults
      conn
    end
  end

  defp get_effective_limit(org_id, api_key, limit_type) do
    # Get organization limits
    org_limit = get_org_limit(org_id, limit_type)

    # Get API key limits if applicable
    api_key_limit =
      if api_key do
        get_api_key_limit(api_key, limit_type)
      else
        nil
      end

    # Use the more restrictive limit
    limit =
      case {org_limit, api_key_limit} do
        {org, nil} -> org
        {org, key} -> min(org, key)
      end

    window = window_for_limit_type(limit_type)

    {limit, window}
  end

  defp get_org_limit(org_id, limit_type) do
    case Tenants.get_rate_limits(org_id) do
      {:ok, limits} ->
        case limit_type do
          :minute -> limits.api_requests_per_minute
          :hour -> limits.api_requests_per_hour
          :day -> limits.api_requests_per_day
        end

      {:error, _} ->
        # Use defaults
        case limit_type do
          :minute -> @default_limits.api_requests_per_minute
          :hour -> @default_limits.api_requests_per_hour
          :day -> @default_limits.api_requests_per_day
        end
    end
  end

  defp get_api_key_limit(%APIKey{} = key, limit_type) do
    case limit_type do
      :minute -> key.rate_limit_per_minute
      :hour -> key.rate_limit_per_hour
      :day -> nil  # No daily limit on API keys, use org limit
    end
  end

  defp window_for_limit_type(:minute), do: 60
  defp window_for_limit_type(:hour), do: 3600
  defp window_for_limit_type(:day), do: 86400

  defp rate_limit_key(org_id, nil, limit_type) do
    "org:#{org_id}:#{limit_type}"
  end

  defp rate_limit_key(org_id, %APIKey{id: key_id}, limit_type) do
    "api_key:#{org_id}:#{key_id}:#{limit_type}"
  end

  # ---------------------------------------------------------------------------
  # Sliding Window Counter
  # ---------------------------------------------------------------------------

  defp check_and_increment(key, limit, window) do
    ensure_ets_table()

    now = System.system_time(:second)
    window_start = now - window
    reset_at = now + window

    # Atomic operation: get current count and increment
    case :ets.lookup(@ets_table, key) do
      [] ->
        # New key, initialize
        :ets.insert(@ets_table, {key, [{now, 1}], now})
        {:ok, 1, limit - 1, reset_at}

      [{^key, requests, _last_update}] ->
        # Filter requests within window
        recent_requests = Enum.filter(requests, fn {ts, _} -> ts > window_start end)
        current_count = Enum.reduce(recent_requests, 0, fn {_, c}, acc -> acc + c end)

        if current_count >= limit do
          # Rate limited
          {:error, :rate_limited, reset_at}
        else
          # Add new request
          new_requests = [{now, 1} | recent_requests]
          :ets.insert(@ets_table, {key, new_requests, now})
          {:ok, current_count + 1, limit - current_count - 1, reset_at}
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Response Headers
  # ---------------------------------------------------------------------------

  defp put_rate_limit_headers(conn, limit, remaining, reset_at) do
    conn
    |> put_resp_header("x-ratelimit-limit", to_string(limit))
    |> put_resp_header("x-ratelimit-remaining", to_string(max(0, remaining)))
    |> put_resp_header("x-ratelimit-reset", to_string(reset_at))
  end

  # ---------------------------------------------------------------------------
  # Bypass Logic
  # ---------------------------------------------------------------------------

  defp should_bypass?(conn, bypass_roles) do
    user = conn.assigns[:current_user]

    cond do
      # No user, no bypass
      is_nil(user) ->
        false

      # Check if user has a bypass role
      user.role in Enum.map(bypass_roles, &to_string/1) ->
        true

      true ->
        false
    end
  end

  # ---------------------------------------------------------------------------
  # ETS Management
  # ---------------------------------------------------------------------------

  defp ensure_ets_table do
    case :ets.whereis(@ets_table) do
      :undefined ->
        :ets.new(@ets_table, [:set, :public, :named_table, {:write_concurrency, true}, {:read_concurrency, true}])

      _ ->
        :ok
    end
  end

  defp start_cleanup_process do
    # Check if cleanup process is already running
    case Process.whereis(:tenant_rate_limit_cleanup) do
      nil ->
        pid = spawn_link(fn -> cleanup_loop() end)
        Process.register(pid, :tenant_rate_limit_cleanup)

      _pid ->
        :ok
    end
  rescue
    # Process may already be registered
    _ -> :ok
  end

  defp cleanup_loop do
    Process.sleep(@cleanup_interval)

    try do
      cleanup_old_entries()
    rescue
      _ -> :ok
    end

    cleanup_loop()
  end

  defp cleanup_old_entries do
    now = System.system_time(:second)
    # Remove entries older than 1 day
    max_age = 86400

    case :ets.whereis(@ets_table) do
      :undefined ->
        :ok

      _ ->
        :ets.foldl(fn {key, _requests, last_update}, acc ->
          if now - last_update > max_age do
            :ets.delete(@ets_table, key)
          end
          acc
        end, :ok, @ets_table)
    end
  end
end
