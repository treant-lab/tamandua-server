defmodule TamanduaServerWeb.Plugs.RateLimiter do
  @moduledoc """
  Rate limiting plug for API endpoints.
  """

  import Plug.Conn

  @default_limit 100
  @default_window_ms 60_000

  def init(opts), do: opts

  def call(conn, opts) do
    TamanduaServerWeb.Plugs.RateLimiterStore.ensure_table()
    limit = Keyword.get(opts, :limit, @default_limit)
    window_ms = Keyword.get(opts, :window_ms, @default_window_ms)

    key = rate_limit_key(conn)

    case check_rate(key, limit, window_ms) do
      {:allow, count} ->
        conn
        |> put_resp_header("x-ratelimit-limit", to_string(limit))
        |> put_resp_header("x-ratelimit-remaining", to_string(limit - count))

      {:deny, _count} ->
        conn
        |> put_resp_header("x-ratelimit-limit", to_string(limit))
        |> put_resp_header("x-ratelimit-remaining", "0")
        |> put_resp_header("retry-after", to_string(div(window_ms, 1000)))
        |> send_resp(429, Jason.encode!(%{error: "Rate limit exceeded"}))
        |> halt()
    end
  end

  defp rate_limit_key(conn) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()
    "rate_limit:#{ip}"
  end

  defp check_rate(key, limit, window_ms) do
    # Simple in-memory rate limiting using ETS
    # In production, use Redis or Hammer library
    now = System.system_time(:millisecond)
    window_start = now - window_ms

    try do
      case :ets.lookup(:rate_limiter, key) do
        [] ->
          :ets.insert(:rate_limiter, {key, [{now, 1}]})
          {:allow, 1}

        [{^key, requests}] ->
          # Filter requests within window
          valid_requests = Enum.filter(requests, fn {ts, _} -> ts > window_start end)
          count = length(valid_requests) + 1

          if count <= limit do
            :ets.insert(:rate_limiter, {key, [{now, count} | valid_requests]})
            {:allow, count}
          else
            {:deny, count}
          end
      end
    rescue
      ArgumentError ->
        TamanduaServerWeb.Plugs.RateLimiterStore.ensure_table()
        check_rate(key, limit, window_ms)
    end
  end
end
