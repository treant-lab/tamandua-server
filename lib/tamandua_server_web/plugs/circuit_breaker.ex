defmodule TamanduaServerWeb.Plugs.CircuitBreaker do
  @moduledoc """
  Plug for protecting routes with a circuit breaker.

  Returns 503 Service Unavailable when the specified fuse is blown,
  preventing cascading failures to downstream services.

  ## Configuration

      plug CircuitBreaker, fuse_name: :ml_service, fallback_status: 503

  ## Usage in Router

      pipeline :ml_protected do
        plug :api
        plug CircuitBreaker, fuse_name: :ml_service
      end

      scope "/api/v1/ml", TamanduaServerWeb.API.V1 do
        pipe_through :ml_protected
        post "/scan", MLController, :scan
      end
  """

  import Plug.Conn
  require Logger

  alias TamanduaServer.Resilience.Fuse

  @behaviour Plug

  @impl Plug
  def init(opts) do
    [
      fuse_name: Keyword.fetch!(opts, :fuse_name),
      fallback_status: Keyword.get(opts, :fallback_status, 503)
    ]
  end

  @impl Plug
  def call(conn, opts) do
    fuse_name = opts[:fuse_name]
    fallback_status = opts[:fallback_status]

    case Fuse.status(fuse_name) do
      :ok ->
        conn

      :blown ->
        handle_blown_fuse(conn, fuse_name, fallback_status)
    end
  end

  defp handle_blown_fuse(conn, fuse_name, status_code) do
    Logger.warning("Circuit breaker #{fuse_name} is blown, returning #{status_code}")

    # Calculate retry-after based on fuse reset time
    # For now, use a fixed 30 seconds (matches default fuse config)
    retry_after = 30

    conn
    |> put_resp_content_type("application/json")
    |> put_resp_header("retry-after", Integer.to_string(retry_after))
    |> send_resp(status_code, Jason.encode!(%{
      error: "Service Unavailable",
      message: "The requested service is temporarily unavailable. Please retry after #{retry_after} seconds.",
      circuit_breaker: fuse_name,
      retry_after: retry_after
    }))
    |> halt()
  end
end
