defmodule TamanduaServerWeb.Plugs.CircuitBreakerTest do
  use ExUnit.Case, async: false
  use Plug.Test

  alias TamanduaServerWeb.Plugs.CircuitBreaker
  alias TamanduaServer.Resilience.Fuse

  @moduletag :unit

  setup do
    fuse_name = :test_circuit_breaker_plug
    Fuse.install(fuse_name)
    on_exit(fn -> :fuse.remove(fuse_name) end)
    {:ok, fuse_name: fuse_name}
  end

  describe "init/1" do
    test "accepts fuse_name and fallback_status options" do
      opts = CircuitBreaker.init(fuse_name: :my_fuse, fallback_status: 503)
      assert opts[:fuse_name] == :my_fuse
      assert opts[:fallback_status] == 503
    end

    test "defaults fallback_status to 503" do
      opts = CircuitBreaker.init(fuse_name: :my_fuse)
      assert opts[:fallback_status] == 503
    end
  end

  describe "call/2 - fuse ok" do
    test "passes through when fuse is healthy", %{fuse_name: fuse_name} do
      conn =
        conn(:get, "/api/v1/alerts")
        |> CircuitBreaker.call(CircuitBreaker.init(fuse_name: fuse_name))

      refute conn.halted
      assert conn.status == nil
    end
  end

  describe "call/2 - fuse blown" do
    test "returns 503 when fuse is blown", %{fuse_name: fuse_name} do
      # Trip the fuse
      Fuse.melt(fuse_name)

      conn =
        conn(:get, "/api/v1/alerts")
        |> CircuitBreaker.call(CircuitBreaker.init(fuse_name: fuse_name))

      assert conn.halted
      assert conn.status == 503
      assert conn.resp_body =~ "Service Unavailable"
    end

    test "includes Retry-After header when blown", %{fuse_name: fuse_name} do
      Fuse.melt(fuse_name)

      conn =
        conn(:get, "/api/v1/alerts")
        |> CircuitBreaker.call(CircuitBreaker.init(fuse_name: fuse_name))

      retry_after = get_resp_header(conn, "retry-after")
      assert length(retry_after) > 0
    end

    test "returns JSON error response", %{fuse_name: fuse_name} do
      Fuse.melt(fuse_name)

      conn =
        conn(:get, "/api/v1/alerts")
        |> CircuitBreaker.call(CircuitBreaker.init(fuse_name: fuse_name))

      assert conn.resp_body
      {:ok, body} = Jason.decode(conn.resp_body)
      assert body["error"]
    end
  end
end
