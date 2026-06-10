defmodule TamanduaServer.Metrics.Plug do
  @moduledoc """
  Plug for exposing Prometheus metrics endpoint

  Add to router.ex:

      scope "/", TamanduaServerWeb do
        pipe_through :api
        forward "/metrics", TamanduaServer.Metrics.Plug
      end
  """

  use Plug.Router

  plug(:match)
  plug(:dispatch)

  get "/" do
    metrics = Prometheus.Format.Text.format()

    conn
    |> put_resp_content_type("text/plain; version=0.0.4")
    |> send_resp(200, metrics)
  end

  match _ do
    send_resp(conn, 404, "Not Found")
  end
end
