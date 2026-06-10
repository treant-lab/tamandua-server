import Config

# We don't run a server during test. If one is required,
# you can enable the server option below.
# NOTE: For E2E tests with Wallaby, we need the server running
config :tamandua_server, TamanduaServerWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "test_secret_key_base_for_test_environment_only",
  server: true  # Enable for E2E tests

# In test we don't send emails.
config :tamandua_server, TamanduaServer.Mailer,
  adapter: Swoosh.Adapters.Local

# Disable swoosh api client as it is only required for production adapters.
config :swoosh, :api_client, false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Configure Ecto for tests
config :tamandua_server, TamanduaServer.Repo,
  database: "tamandua_test",
  pool_size: 10,
  ownership_timeout: 15_000,
  start_owner: true

# Configure Oban for tests
config :tamandua_server, Oban,
  repo: TamanduaServer.Repo,
  queues: false # Disable queues during tests

# Configure Wallaby for E2E tests
config :wallaby,
  otp_app: :tamandua_server,
  driver: Wallaby.Chrome,
  screenshot_on_failure: true,
  screenshot_dir: "tmp/screenshots",
  js_errors: false,
  max_wait_time: 5_000,
  hackney_options: [timeout: :infinity, recv_timeout: :infinity]

# SQL Sandbox for concurrent tests
config :tamandua_server, :sql_sandbox, true
