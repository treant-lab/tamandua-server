# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
import Config

# Ecto Repos
config :tamandua_server,
  ecto_repos: [TamanduaServer.Repo]

# OCSP agent-certificate revocation checking.
# Disabled by default so dev/test (no live OCSP responder) are unaffected.
# When enabled, the agent socket performs an OCSP check after CN match and
# starts the TamanduaServer.PKI.OCSP checker (with its ETS status cache).
config :tamandua_server, :ocsp_enabled, false

config :tamandua_server, TamanduaServer.PKI.OCSP,
  # responder_url: "http://ocsp.tamandua.local", # AIA fallback (optional)
  cache_ttl_seconds: 300,
  request_timeout_ms: 5_000,
  soft_fail: true

# Configures the endpoint
config :tamandua_server, TamanduaServerWeb.Endpoint,
  url: [host: "localhost"],
  render_errors: [
    formats: [html: TamanduaServerWeb.ErrorHTML, json: TamanduaServerWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: TamanduaServer.PubSub,
  live_view: [signing_salt: "tamandua_lv_salt"]

# Configures the mailer
config :tamandua_server, TamanduaServer.Mailer, adapter: Swoosh.Adapters.Local

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.17.11",
  default: [
    args:
      ~w(js/app.js --bundle --target=es2017 --outdir=../priv/static/assets --external:/fonts/* --external:/images/*),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => Path.expand("../deps", __DIR__)}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "3.3.2",
  default: [
    args: ~w(
      --config=tailwind.config.js
      --input=css/app.css
      --output=../priv/static/assets/app.css
    ),
    cd: Path.expand("../assets", __DIR__)
  ]

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id, :agent_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Configure Inertia.js
config :inertia,
  endpoint: TamanduaServerWeb.Endpoint,
  static_paths: ["/assets"],
  default_version: "1",
  camelize_props: false

# Guardian configuration
# IMPORTANT: In production, GUARDIAN_SECRET_KEY must be set via environment variable
# Generate with: mix guardian.gen.secret
# Note: Actual secret is configured in dev.exs/prod.exs/runtime.exs
#
# Pin the signing/verification algorithm to a single symmetric algorithm.
# This is explicit defense against JWT algorithm-confusion / "alg: none"
# attacks: the verifier will reject any token whose header advertises a
# different algorithm, regardless of Guardian's library defaults.
config :tamandua_server, TamanduaServer.Guardian,
  issuer: "tamandua_server",
  allowed_algos: ["HS512"]

# Oban configuration
config :tamandua_server, Oban,
  repo: TamanduaServer.Repo,
  plugins: [
    {Oban.Plugins.Pruner, max_age: 60 * 60 * 24 * 7},
    {Oban.Plugins.Cron, crontab: [
      {"0 * * * *", TamanduaServer.Workers.CleanupWorker},
      # Daily recording retention cleanup at 3:00 AM UTC
      {"0 3 * * *", TamanduaServer.Workers.RecordingRetentionWorker},
      # Daily event archival and sampling at 4:00 AM UTC (staggered 1 hour after recordings)
      {"0 4 * * *", TamanduaServer.Workers.ArchiveEventsWorker},
      # Threat intel feed sync every 4 hours (at minute 15 to stagger with other jobs)
      {"15 */4 * * *", TamanduaServer.Workers.ThreatIntelSyncWorker},
      # Check for expired network isolations every 5 minutes
      {"*/5 * * * *", TamanduaServer.Jobs.IsolationExpiryJob},
      # Clean up expired and old agent commands every 30 minutes
      {"*/30 * * * *", TamanduaServer.Workers.CleanupCommandsWorker}
    ]}
  ],
  queues: [
    default: 10,
    alerts: 5,
    ml: 3,
    ml_training: 1,
    reports: 2,
    threat_intel: 2,
    graph_enrichment: 5,
    isolation: 3,
    archival: 2,
    notifications: 10,
    remediation: 5,
    blockchain: 3
  ]

# Live Response Session Recording configuration
# Recordings are gzip-compressed and optionally AES-256-GCM encrypted.
# Set TAMANDUA_RECORDING_KEY env var (32+ chars) to enable encryption.
config :tamandua_server, TamanduaServer.LiveResponse.SessionRecording,
  recording_dir: "priv/live_response_recordings",
  encryption_key: System.get_env("TAMANDUA_RECORDING_KEY"),
  retention_days: 90

# Nebulex cache configuration
config :tamandua_server, TamanduaServer.Cache,
  gc_interval: :timer.hours(1),
  max_size: 100_000,
  allocated_memory: 100_000_000,
  gc_cleanup_min_timeout: :timer.seconds(10),
  gc_cleanup_max_timeout: :timer.minutes(10)

# Hammer rate limiting configuration
config :hammer,
  backend: {Hammer.Backend.ETS,
            [expiry_ms: 60_000 * 60 * 4,
             cleanup_interval_ms: 60_000 * 10]}

# Cloud provider configuration (credentials from environment)
# AWS: Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY env vars
config :tamandua_server, TamanduaServer.Cloud.AWS,
  access_key_id: System.get_env("AWS_ACCESS_KEY_ID"),
  secret_access_key: System.get_env("AWS_SECRET_ACCESS_KEY"),
  regions: ["us-east-1", "us-west-2", "eu-west-1"]

# S3-compatible storage for model artifacts and tenant data
# Supports AWS S3, MinIO, Wasabi, Cloudflare R2, and other S3-compatible services
config :ex_aws,
  access_key_id: [{:system, "AWS_ACCESS_KEY_ID"}, :instance_role],
  secret_access_key: [{:system, "AWS_SECRET_ACCESS_KEY"}, :instance_role],
  region: {:system, "AWS_REGION", "us-east-1"}

config :tamandua_server, TamanduaServer.Storage.S3Client,
  bucket: System.get_env("S3_BUCKET", "tamandua-artifacts"),
  host: System.get_env("S3_HOST"),
  scheme: System.get_env("S3_SCHEME", "https://"),
  port: System.get_env("S3_PORT", "443")

# Azure: Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET env vars
config :tamandua_server, TamanduaServer.Cloud.Azure,
  tenant_id: System.get_env("AZURE_TENANT_ID"),
  client_id: System.get_env("AZURE_CLIENT_ID"),
  client_secret: System.get_env("AZURE_CLIENT_SECRET")

# GCP: Set GCP_SERVICE_ACCOUNT_KEY_PATH to path of service account JSON key file
config :tamandua_server, TamanduaServer.Cloud.GCP,
  service_account_key_path: System.get_env("GCP_SERVICE_ACCOUNT_KEY_PATH")

# Trivy vulnerability scanner configuration
# Supports CLI mode (calls trivy binary) or server mode (Trivy server API)
config :tamandua_server, :trivy,
  enabled: true,
  mode: :cli,                                    # :cli or :server
  server_url: "http://localhost:4954",           # Only used in server mode
  timeout: 120_000,                              # Scan timeout in ms
  severity: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",  # Severity levels to include
  ignore_unfixed: false                          # Only show vulns with fixes

# Threat Intelligence Feed Synchronization
# Free feeds (no API key required) are enabled by default.
# Premium feeds (OTX, MISP, VirusTotal, Shodan) require API keys via env vars.
config :tamandua_server, TamanduaServer.Detection.ThreatIntelFeeds,
  enabled: true,
  sync_interval_hours: 4,
  initial_sync_delay_seconds: 30,
  feeds: %{
    # --- Free feeds (no API key) ---
    abusech_feodo: %{enabled: true, description: "Abuse.ch Feodo Tracker - Banking trojan C2 IPs"},
    abusech_urlhaus: %{enabled: true, description: "Abuse.ch URLhaus - Malware distribution URLs"},
    abusech_threatfox: %{enabled: true, description: "Abuse.ch ThreatFox - IOC sharing"},
    abusech_malware_bazaar: %{enabled: true, description: "Abuse.ch Malware Bazaar - Malware sample hashes"},
    abusech_ssl_blacklist: %{enabled: true, description: "Abuse.ch SSL Blacklist - Malicious SSL certs"},
    emergingthreats: %{enabled: true, description: "EmergingThreats - Compromised IPs"},
    tor_exit_nodes: %{enabled: true, description: "Tor exit node list (anomaly detection, not blocking)"},
    phishtank: %{enabled: true, description: "PhishTank - Verified phishing URLs"},
    openphish: %{enabled: true, description: "OpenPhish - Phishing URLs"},
    spamhaus_drop: %{enabled: true, description: "Spamhaus DROP - Do Not Route Or Peer"},
    firehol_level1: %{enabled: true, description: "FireHOL Level 1 - Aggregated IP blocklist"},
    c2_intel_feeds: %{enabled: true, description: "C2 Intel Feeds - C2 domains"},
    # --- Premium feeds (require API key via env var) ---
    # Set OTX_API_KEY environment variable to enable AlienVault OTX
    otx: %{enabled: false, description: "AlienVault OTX (set OTX_API_KEY env var)"},
    # Set MISP_URL and MISP_API_KEY environment variables to enable MISP
    misp: %{enabled: false, description: "MISP (set MISP_URL and MISP_API_KEY env vars)"}
  }

# ClickHouse telemetry storage (high-volume events)
# Enabled by default in dev (override with CLICKHOUSE_ENABLED=false env var).
# Disabled in test (see runtime.exs). Production reads from CLICKHOUSE_ENABLED env var.
# ClickHouse handles raw telemetry events at scale while PostgreSQL remains
# the source of truth for relational data (users, agents, alerts, configs).
config :tamandua_server, TamanduaServer.Telemetry.ClickHouse,
  enabled: true,
  url: "http://localhost:8123",
  database: "tamandua",
  username: "default",
  password: "",
  pool_size: 10,
  batch_size: 1000,
  flush_interval_ms: 5000,
  retry_count: 3,
  max_consecutive_failures: 5,
  circuit_open_duration_ms: 60_000,
  query_timeout: 30_000

# PostgreSQL Event Archival and Retention
# Controls how events are archived and sampled to prevent unbounded growth.
# Works in conjunction with TimescaleDB retention policies.
config :tamandua_server, TamanduaServer.Telemetry,
  # Archive events older than 30 days to events_archive table
  event_retention_days: 30,
  # Compress TimescaleDB chunks older than 7 days
  event_compression_days: 7,
  # Enable intelligent sampling for medium-age events
  event_sampling_enabled: true,
  # Keep 10% of low-value events in the 7-30 day window
  event_sampling_rate: 0.1,
  # Enable archival worker (set to false to disable)
  archive_enabled: true,
  # Process this many events per batch during archival
  archive_batch_size: 5000

# Stripe billing configuration
# In production, STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET env vars are required
config :stripity_stripe,
  api_key: System.get_env("STRIPE_SECRET_KEY"),
  webhook_signing_secret: System.get_env("STRIPE_WEBHOOK_SECRET")

config :tamandua_server, TamanduaServer.Billing,
  # Price IDs for each tier
  prices: %{
    pro_monthly: System.get_env("STRIPE_PRICE_PRO_MONTHLY"),
    pro_annual: System.get_env("STRIPE_PRICE_PRO_ANNUAL"),
    enterprise_annual: System.get_env("STRIPE_PRICE_ENTERPRISE"),
    # Metered prices for usage-based billing
    api_calls: System.get_env("STRIPE_PRICE_API_CALLS"),
    model_scans: System.get_env("STRIPE_PRICE_MODEL_SCANS")
  },
  # Usage thresholds (included in base price)
  included_usage: %{
    pro: %{api_calls: 100_000, scans: 1_000},
    enterprise: %{api_calls: 1_000_000, scans: 10_000}
  }

# NL Hunter configuration (Natural Language Threat Hunting)
# LLM translation is enabled by default if an API key is present
config :tamandua_server, TamanduaServer.Hunting.NLHunter,
  llm_enabled: true  # Set to false to force pattern-based translation only

# LLM Client configuration (GPT/Claude for NL processing)
# Uses OPENAI_API_KEY or ANTHROPIC_API_KEY environment variables
config :tamandua_server, TamanduaServer.AI.LLMClient,
  provider: :openai,                # :openai or :anthropic
  model: "gpt-4o-mini",             # Default model for translations
  timeout: 60_000,                  # Request timeout in ms
  max_retries: 3                    # Retry count for rate limits

# Response safety enforcement
# When false (default), the response-safety guard is REPORT-ONLY: it logs a
# would-block warning for protected targets but still runs the action.
# Set to true to ENFORCE (block) responses on protected targets.
config :tamandua_server, :response_safety_enforce, false

# Disaster Recovery FailoverManager
# When false (default), the DR FailoverManager is NOT started, avoiding
# health-check probes against DR peers (Redis/PostgreSQL replicas) that are
# absent in dev/test. Set to true in multi-site deployments to enable
# automatic failover orchestration.
config :tamandua_server, :dr_failover_enabled, false

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
