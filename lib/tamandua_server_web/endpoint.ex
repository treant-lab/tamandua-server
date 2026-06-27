defmodule TamanduaServerWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :tamandua_server

  # The session will be stored in the cookie and signed,
  # this means its contents can be read but not tampered with.
  @session_options [
    store: :cookie,
    key: "_tamandua_server_key",
    signing_salt: "tamandua_salt",
    same_site: "Lax"
  ]

  socket("/live", Phoenix.LiveView.Socket,
    websocket: [connect_info: [session: @session_options]],
    longpoll: false
  )

  # Agent WebSocket endpoint with mTLS support
  socket("/socket/agent", TamanduaServerWeb.AgentSocket,
    websocket: [
      connect_info: [:peer_data, :x_headers],
      timeout: 300_000,
      compress: true,
      # The Rust agent speaks Phoenix's V1 object-frame protocol. Some
      # installed builds still advertise vsn=2.0.0, so keep this endpoint
      # tolerant while those agents roll forward.
      serializer: [
        {Phoenix.Socket.V1.JSONSerializer, "~> 1.0.0"},
        {Phoenix.Socket.V1.JSONSerializer, "~> 2.0.0"}
      ]
    ],
    longpoll: false
  )

  # Dashboard WebSocket for real-time updates
  socket("/socket/dashboard", TamanduaServerWeb.DashboardSocket,
    websocket: [
      connect_info: [session: @session_options],
      timeout: 60_000
    ],
    longpoll: false
  )

  # Streaming WebSocket for external consumers
  socket("/socket/stream", TamanduaServerWeb.StreamSocket,
    websocket: [
      connect_info: [session: @session_options],
      timeout: 120_000,
      compress: true
    ],
    longpoll: false
  )

  # GraphQL WebSocket for subscriptions
  socket("/api/graphql/websocket", TamanduaServerWeb.GraphQL.UserSocket,
    websocket: [
      connect_info: [session: @session_options],
      timeout: 60_000
    ],
    longpoll: false
  )

  # Serve at "/" the static files from "priv/static" directory.
  plug(Plug.Static,
    at: "/",
    from: :tamandua_server,
    gzip: false,
    only: TamanduaServerWeb.static_paths()
  )

  # Code reloading can be explicitly enabled under the
  # :code_reloader configuration of your endpoint.
  if code_reloading? do
    socket("/phoenix/live_reload/socket", Phoenix.LiveReloader.Socket)
    plug(Phoenix.LiveReloader)
    plug(Phoenix.CodeReloader)
    plug(Phoenix.Ecto.CheckRepoStatus, otp_app: :tamandua_server)
  end

  plug(Phoenix.LiveDashboard.RequestLogger,
    param_key: "request_logger",
    cookie_key: "request_logger"
  )

  plug(Plug.RequestId)
  plug(Plug.Telemetry, event_prefix: [:phoenix, :endpoint])

  plug(Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library(),
    body_reader: {TamanduaServerWeb.CacheBodyReader, :read_body, []}
  )

  plug(Plug.MethodOverride)
  plug(Plug.Head)
  plug(Plug.Session, @session_options)

  # CORS for API access
  plug(CORSPlug,
    origin: &TamanduaServerWeb.Endpoint.cors_origins/0,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    headers: [
      "Authorization",
      "Content-Type",
      "Accept",
      "X-API-Key",
      "X-Request-ID",
      "X-Tamandua-Payload-SHA256",
      "X-Tamandua-Signature-Algorithm",
      "X-Tamandua-Signature",
      "X-Tamandua-Signing-Key-ID"
    ]
  )

  plug(TamanduaServerWeb.Router)

  @doc """
  Returns CORS origins configuration.

  In production with session authentication enabled, wildcard "*" origins are
  a security risk (credentials can leak to any origin). This function logs a
  warning if wildcard is used in production and validates the configuration.
  """
  def cors_origins do
    origins = Application.get_env(:tamandua_server, :cors_origins)
    env = Application.get_env(:tamandua_server, :env, :dev)

    case origins do
      "*" ->
        if env == :prod do
          require Logger

          Logger.warning(
            "[Security] CORS origin '*' is insecure in production with session-based auth. " <>
              "Set CORS_ORIGINS to a comma-separated list of allowed origins."
          )
        end

        "*"

      origins when is_binary(origins) and origins != "" ->
        # Parse comma-separated origins from env var
        String.split(origins, ",", trim: true) |> Enum.map(&String.trim/1)

      origins when is_list(origins) ->
        origins

      _ ->
        ["http://localhost:4000", "http://localhost:3000"]
    end
  end
end

defmodule TamanduaServerWeb.CacheBodyReader do
  @moduledoc """
  Custom body reader that caches the raw body for webhook signature verification.
  """

  def read_body(conn, opts) do
    {:ok, body, conn} = Plug.Conn.read_body(conn, opts)
    conn = update_in(conn.assigns[:raw_body], &[body | &1 || []])
    {:ok, body, conn}
  end
end
