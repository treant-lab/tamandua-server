import Config

# Note: do not include sensitive configuration here.
# All secrets should be in runtime.exs and loaded from environment.

# For production, don't forget to configure the url host
# to something meaningful, Phoenix uses this information
# when generating URLs.

# Do not print debug messages in production
config :logger, level: :info

# Runtime production configuration, including reading
# of environment variables, is done on config/runtime.exs.

config :tamandua_server, TamanduaServerWeb.Endpoint,
  cache_static_manifest: "priv/static/cache_manifest.json",
  check_origin: true

# Production environment flag
config :tamandua_server,
  env: :prod,
  require_mtls: true
