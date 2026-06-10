import Config

lab_light? = System.get_env("TAMANDUA_LAB_LIGHT", "false") == "true"

# Configure your database
config :tamandua_server, TamanduaServer.Repo,
  username: System.get_env("POSTGRES_USER") || "tamandua",
  password: System.get_env("POSTGRES_PASSWORD") || "tamandua_dev_password",
  hostname: System.get_env("POSTGRES_HOST") || "localhost",
  port: String.to_integer(System.get_env("POSTGRES_PORT") || "5432"),
  database: System.get_env("POSTGRES_DB") || "tamandua_dev",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

# For development, we disable any cache and enable
# temporary file watchers for phoenix and templates.
config :tamandua_server, TamanduaServerWeb.Endpoint,
  # Binding to all interfaces for Docker compatibility
  http: [ip: {0, 0, 0, 0}, port: 4000],
  check_origin: false,
  code_reloader: !lab_light?,
  debug_errors: true,
  secret_key_base: "dev_secret_key_base_this_is_only_for_development_not_production_64bytes",
  watchers:
    if(lab_light?,
      do: [],
      else: [
        esbuild: {Esbuild, :install_and_run, [:default, ~w(--sourcemap=inline --watch)]},
        tailwind: {Tailwind, :install_and_run, [:default, ~w(--watch)]}
      ]
    )

# Watch static and templates for browser reloading.
unless lab_light? do
  config :tamandua_server, TamanduaServerWeb.Endpoint,
    live_reload: [
      patterns: [
        ~r"priv/static/.*(js|css|png|jpeg|jpg|gif|svg)$",
        ~r"priv/gettext/.*(po)$",
        ~r"lib/tamandua_server_web/(controllers|live|components)/.*(ex|heex)$"
      ]
    ]
end

# Enable dev routes for dashboard and mailbox
config :tamandua_server, dev_routes: !lab_light?

# Enable Vite dev server for React hot reloading
config :tamandua_server, dev_assets: false

# Do not include metadata nor timestamps in development logs
config :logger, :console, format: "[$level] $message\n"

# Set a higher stacktrace during development. Avoid configuring such
# in production as building large stacktraces may be expensive.
config :phoenix, :stacktrace_depth, 20

# Initialize plugs at runtime for faster development compilation
config :phoenix, :plug_init_mode, :runtime

# Disable swoosh api client as it is only required for production adapters.
config :swoosh, :api_client, false

# Guardian secret for development ONLY
# DO NOT use this in production - generate a proper secret
config :tamandua_server, TamanduaServer.Guardian,
  secret_key: "dev_secret_key_for_development_only_DO_NOT_USE_IN_PRODUCTION_8675309"

# Agent secret for development ONLY
# In production, set TAMANDUA_AGENT_SECRET environment variable
config :tamandua_server,
  agent_secret: "dev_agent_secret_for_development_only_DO_NOT_USE_IN_PRODUCTION",
  env: :dev,
  require_mtls: false,
  ml_service_url: System.get_env("ML_SERVICE_URL", "http://localhost:8000")

# Threat Intelligence API Keys (set via environment variables)
# In development, these can be left as nil for local testing
config :tamandua_server, :threat_intel,
  virustotal_api_key: System.get_env("VT_API_KEY"),
  alienvault_api_key: System.get_env("OTX_API_KEY"),
  shodan_api_key: System.get_env("SHODAN_API_KEY"),
  abuseipdb_api_key: System.get_env("ABUSEIPDB_API_KEY")

# ClickHouse — high-volume telemetry storage
# Uses the HTTP interface (port 8123). Run `docker compose up clickhouse` to start.
# Set CLICKHOUSE_ENABLED=false to disable dual-write if ClickHouse is not running locally.
config :tamandua_server, TamanduaServer.Telemetry.ClickHouse,
  enabled: System.get_env("CLICKHOUSE_ENABLED", "true") == "true",
  url: System.get_env("CLICKHOUSE_URL") || "http://localhost:8123",
  database: System.get_env("CLICKHOUSE_DATABASE") || "tamandua",
  username: System.get_env("CLICKHOUSE_USERNAME") || "default",
  password: System.get_env("CLICKHOUSE_PASSWORD") || "",
  batch_size: 1000,
  flush_interval_ms: 5_000,
  retry_count: 3,
  max_consecutive_failures: 5,
  circuit_open_duration_ms: 60_000,
  query_timeout: 30_000

# Disable Oban in tests
config :tamandua_server, Oban, testing: :inline

# Cache configuration for development
config :tamandua_server, :cache,
  redis: [
    host: System.get_env("REDIS_HOST") || "localhost",
    port: String.to_integer(System.get_env("REDIS_PORT") || "6379"),
    namespace: "tamandua_dev",
    pool_size: 10,
    timeout: 5000
  ],
  ets: [
    default_ttl: :timer.hours(1),
    cleanup_interval: :timer.minutes(5)
  ],
  http: [
    enable_etag: true,
    enable_last_modified: true,
    default_ttl: 60
  ],
  warming: [
    enabled: true,
    warm_on_startup: true,
    periodic_interval: :timer.hours(12)
  ]
