defmodule TamanduaServerWeb.Plugs.RateLimiterTest do
  use ExUnit.Case, async: false
  use Plug.Test

  alias TamanduaServerWeb.Plugs.RateLimiter
  alias TamanduaServerWeb.Plugs.RateLimiterStore

  setup do
    if Process.whereis(RateLimiterStore) == nil do
      start_supervised!(RateLimiterStore)
    end

    RateLimiterStore.ensure_table()
    :ets.delete_all_objects(:rate_limiter)

    :ok
  end

  test "rate limiter table survives request process exit" do
    parent = self()

    spawn(fn ->
      conn =
        :get
        |> conn("/api/v1/health")
        |> Map.put(:remote_ip, {127, 0, 0, 1})
        |> RateLimiter.call(limit: 2, window_ms: 60_000)

      send(parent, {:limited, get_resp_header(conn, "x-ratelimit-remaining")})
    end)

    assert_receive {:limited, ["1"]}
    assert :ets.whereis(:rate_limiter) != :undefined

    conn =
      :get
      |> conn("/api/v1/health")
      |> Map.put(:remote_ip, {127, 0, 0, 1})
      |> RateLimiter.call(limit: 2, window_ms: 60_000)

    assert get_resp_header(conn, "x-ratelimit-remaining") == ["0"]
  end
end
