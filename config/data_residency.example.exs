import Config

# ===========================================================================
# Multi-Tenancy Data Residency Configuration
# ===========================================================================
#
# This file configures regional database connections, S3 buckets, Redis,
# and RabbitMQ instances for multi-tenant data residency compliance.
#
# Copy this file to config/data_residency.exs and configure for your environment.
# Then add to config/runtime.exs:
#   import_config "data_residency.exs"
#

# ===========================================================================
# Regional Database Configuration
# ===========================================================================

# European Union (GDPR Compliance)
config :tamandua_server, TamanduaServer.Repo.EU,
  url: System.get_env("DATABASE_URL_EU") || "postgresql://localhost:5432/tamandua_eu",
  pool_size: String.to_integer(System.get_env("EU_DB_POOL_SIZE") || "10"),
  queue_target: 5000,
  queue_interval: 1000,
  ssl: System.get_env("EU_DB_SSL", "true") == "true",
  # Enable statement logging for audit compliance
  log: :info,
  # Increase timeout for large queries
  timeout: 30_000,
  # Connection parameters
  parameters: [
    # Set timezone to UTC
    timezone: "UTC",
    # Enable application_name for connection tracking
    application_name: "tamandua_eu"
  ]

# United States (CCPA Compliance)
config :tamandua_server, TamanduaServer.Repo.US,
  url: System.get_env("DATABASE_URL_US") || "postgresql://localhost:5432/tamandua_us",
  pool_size: String.to_integer(System.get_env("US_DB_POOL_SIZE") || "10"),
  queue_target: 5000,
  queue_interval: 1000,
  ssl: System.get_env("US_DB_SSL", "true") == "true",
  log: :info,
  timeout: 30_000,
  parameters: [
    timezone: "UTC",
    application_name: "tamandua_us"
  ]

# Asia-Pacific
config :tamandua_server, TamanduaServer.Repo.APAC,
  url: System.get_env("DATABASE_URL_APAC") || "postgresql://localhost:5432/tamandua_apac",
  pool_size: String.to_integer(System.get_env("APAC_DB_POOL_SIZE") || "10"),
  queue_target: 5000,
  queue_interval: 1000,
  ssl: System.get_env("APAC_DB_SSL", "true") == "true",
  log: :info,
  timeout: 30_000,
  parameters: [
    timezone: "UTC",
    application_name: "tamandua_apac"
  ]

# Canada
config :tamandua_server, TamanduaServer.Repo.CA,
  url: System.get_env("DATABASE_URL_CA") || "postgresql://localhost:5432/tamandua_ca",
  pool_size: String.to_integer(System.get_env("CA_DB_POOL_SIZE") || "10"),
  queue_target: 5000,
  queue_interval: 1000,
  ssl: System.get_env("CA_DB_SSL", "true") == "true",
  log: :info,
  timeout: 30_000

# United Kingdom (Post-Brexit)
config :tamandua_server, TamanduaServer.Repo.UK,
  url: System.get_env("DATABASE_URL_UK") || "postgresql://localhost:5432/tamandua_uk",
  pool_size: String.to_integer(System.get_env("UK_DB_POOL_SIZE") || "10"),
  queue_target: 5000,
  queue_interval: 1000,
  ssl: System.get_env("UK_DB_SSL", "true") == "true",
  log: :info,
  timeout: 30_000

# Australia
config :tamandua_server, TamanduaServer.Repo.AU,
  url: System.get_env("DATABASE_URL_AU") || "postgresql://localhost:5432/tamandua_au",
  pool_size: String.to_integer(System.get_env("AU_DB_POOL_SIZE") || "10"),
  queue_target: 5000,
  queue_interval: 1000,
  ssl: System.get_env("AU_DB_SSL", "true") == "true",
  log: :info,
  timeout: 30_000

# Japan
config :tamandua_server, TamanduaServer.Repo.JP,
  url: System.get_env("DATABASE_URL_JP") || "postgresql://localhost:5432/tamandua_jp",
  pool_size: String.to_integer(System.get_env("JP_DB_POOL_SIZE") || "10"),
  queue_target: 5000,
  queue_interval: 1000,
  ssl: System.get_env("JP_DB_SSL", "true") == "true",
  log: :info,
  timeout: 30_000

# India
config :tamandua_server, TamanduaServer.Repo.IN,
  url: System.get_env("DATABASE_URL_IN") || "postgresql://localhost:5432/tamandua_in",
  pool_size: String.to_integer(System.get_env("IN_DB_POOL_SIZE") || "10"),
  queue_target: 5000,
  queue_interval: 1000,
  ssl: System.get_env("IN_DB_SSL", "true") == "true",
  log: :info,
  timeout: 30_000

# ===========================================================================
# Regional S3 Configuration
# ===========================================================================

config :tamandua_server, :s3_regional,
  eu: %{
    bucket: System.get_env("S3_BUCKET_EU") || "tamandua-eu-telemetry",
    region: "eu-central-1",
    endpoint: System.get_env("S3_ENDPOINT_EU"),
    access_key_id: System.get_env("AWS_ACCESS_KEY_ID_EU"),
    secret_access_key: System.get_env("AWS_SECRET_ACCESS_KEY_EU"),
    kms_key_id: System.get_env("KMS_KEY_ID_EU")
  },
  us: %{
    bucket: System.get_env("S3_BUCKET_US") || "tamandua-us-telemetry",
    region: "us-east-1",
    endpoint: System.get_env("S3_ENDPOINT_US"),
    access_key_id: System.get_env("AWS_ACCESS_KEY_ID_US"),
    secret_access_key: System.get_env("AWS_SECRET_ACCESS_KEY_US"),
    kms_key_id: System.get_env("KMS_KEY_ID_US")
  },
  apac: %{
    bucket: System.get_env("S3_BUCKET_APAC") || "tamandua-apac-telemetry",
    region: "ap-southeast-1",
    endpoint: System.get_env("S3_ENDPOINT_APAC"),
    access_key_id: System.get_env("AWS_ACCESS_KEY_ID_APAC"),
    secret_access_key: System.get_env("AWS_SECRET_ACCESS_KEY_APAC"),
    kms_key_id: System.get_env("KMS_KEY_ID_APAC")
  }

# ===========================================================================
# Regional Redis Configuration
# ===========================================================================

config :tamandua_server, :redis_regional,
  eu: System.get_env("REDIS_URL_EU") || "redis://eu-redis:6379",
  us: System.get_env("REDIS_URL_US") || "redis://us-redis:6379",
  apac: System.get_env("REDIS_URL_APAC") || "redis://apac-redis:6379",
  ca: System.get_env("REDIS_URL_CA") || "redis://ca-redis:6379",
  uk: System.get_env("REDIS_URL_UK") || "redis://uk-redis:6379",
  au: System.get_env("REDIS_URL_AU") || "redis://au-redis:6379",
  jp: System.get_env("REDIS_URL_JP") || "redis://jp-redis:6379",
  in: System.get_env("REDIS_URL_IN") || "redis://in-redis:6379"

# ===========================================================================
# Regional RabbitMQ Configuration
# ===========================================================================

config :tamandua_server, :rabbitmq_regional,
  eu: System.get_env("RABBITMQ_URL_EU") || "amqp://eu-rabbitmq:5672",
  us: System.get_env("RABBITMQ_URL_US") || "amqp://us-rabbitmq:5672",
  apac: System.get_env("RABBITMQ_URL_APAC") || "amqp://apac-rabbitmq:5672",
  ca: System.get_env("RABBITMQ_URL_CA") || "amqp://ca-rabbitmq:5672",
  uk: System.get_env("RABBITMQ_URL_UK") || "amqp://uk-rabbitmq:5672",
  au: System.get_env("RABBITMQ_URL_AU") || "amqp://au-rabbitmq:5672",
  jp: System.get_env("RABBITMQ_URL_JP") || "amqp://jp-rabbitmq:5672",
  in: System.get_env("RABBITMQ_URL_IN") || "amqp://in-rabbitmq:5672"

# ===========================================================================
# Data Residency Settings
# ===========================================================================

config :tamandua_server, :data_residency,
  # Enable data residency enforcement
  enabled: System.get_env("DATA_RESIDENCY_ENABLED", "true") == "true",
  # Default region for new tenants
  default_region: String.to_atom(System.get_env("DEFAULT_REGION") || "us"),
  # Enable cross-region replication
  replication_enabled: System.get_env("REPLICATION_ENABLED", "false") == "true",
  # Replication lag alert threshold (milliseconds)
  replication_lag_warning_ms: 5_000,
  replication_lag_critical_ms: 30_000,
  # Health check interval
  health_check_interval_ms: 60_000

# ===========================================================================
# Compliance Settings
# ===========================================================================

config :tamandua_server, :compliance,
  # Enable automatic compliance validation
  auto_validate: System.get_env("COMPLIANCE_AUTO_VALIDATE", "true") == "true",
  # Compliance validation interval (hours)
  validation_interval_hours: String.to_integer(System.get_env("COMPLIANCE_VALIDATION_INTERVAL") || "24"),
  # Alert on compliance violations
  alert_on_violations: System.get_env("COMPLIANCE_ALERT_VIOLATIONS", "true") == "true",
  # GDPR breach notification hours
  gdpr_breach_notification_hours: 72,
  # HIPAA breach notification days
  hipaa_breach_notification_days: 60
