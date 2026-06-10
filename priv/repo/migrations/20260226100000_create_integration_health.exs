defmodule TamanduaServer.Repo.Migrations.CreateIntegrationHealth do
  use Ecto.Migration

  def change do
    # Integration health metrics table
    create_if_not_exists table(:integration_health_metrics, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :integration_id, references(:integrations, on_delete: :delete_all, type: :binary_id), null: false

      # Connection status
      add :status, :string, null: false  # connected, disconnected, degraded
      add :last_connected_at, :utc_datetime
      add :last_disconnected_at, :utc_datetime

      # API rate limits
      add :rate_limit_total, :integer
      add :rate_limit_used, :integer
      add :rate_limit_remaining, :integer
      add :rate_limit_reset_at, :utc_datetime

      # Error rates (per minute)
      add :errors_per_minute, :float, default: 0.0
      add :errors_5xx_count, :integer, default: 0
      add :errors_4xx_count, :integer, default: 0
      add :total_errors, :integer, default: 0
      add :total_requests, :integer, default: 0

      # Latency metrics (milliseconds)
      add :latency_avg, :float
      add :latency_p50, :float
      add :latency_p95, :float
      add :latency_p99, :float

      # Sync status
      add :last_sync_at, :utc_datetime
      add :sync_lag_seconds, :integer, default: 0
      add :pending_items, :integer, default: 0
      add :synced_items, :integer, default: 0

      # Credential status
      add :credential_expires_at, :utc_datetime
      add :credential_status, :string  # valid, expiring_soon, expired

      # Health check results
      add :last_health_check_at, :utc_datetime
      add :last_health_check_success, :boolean
      add :health_check_failures, :integer, default: 0

      # Additional metadata
      add :error_message, :text
      add :metadata, :map, default: %{}

      timestamps()
    end

    create_if_not_exists index(:integration_health_metrics, [:integration_id])
    create_if_not_exists index(:integration_health_metrics, [:status])
    create_if_not_exists index(:integration_health_metrics, [:last_health_check_at])

    # Integration uptime tracking
    create_if_not_exists table(:integration_uptime, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :integration_id, references(:integrations, on_delete: :delete_all, type: :binary_id), null: false

      # Date (for daily aggregation)
      add :date, :date, null: false

      # Uptime metrics (seconds)
      add :uptime_seconds, :integer, default: 0
      add :downtime_seconds, :integer, default: 0
      add :total_seconds, :integer, default: 86400  # 24 hours

      # Incident counts
      add :incident_count, :integer, default: 0
      add :mttr_seconds, :integer  # Mean Time To Recovery

      # SLA compliance
      add :sla_target, :float, default: 99.9  # 99.9%
      add :sla_actual, :float
      add :sla_compliant, :boolean

      timestamps()
    end

    create_if_not_exists unique_index(:integration_uptime, [:integration_id, :date])
    create_if_not_exists index(:integration_uptime, [:integration_id])
    create_if_not_exists index(:integration_uptime, [:date])

    # Integration incidents (downtime events)
    create_if_not_exists table(:integration_incidents, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :integration_id, references(:integrations, on_delete: :delete_all, type: :binary_id), null: false

      # Incident details
      add :incident_type, :string, null: false  # connection_failure, high_error_rate, rate_limit, credential_expiry, sync_lag
      add :severity, :string, null: false  # critical, high, medium, low
      add :status, :string, default: "open"  # open, acknowledged, resolved

      # Timestamps
      add :started_at, :utc_datetime, null: false
      add :resolved_at, :utc_datetime
      add :acknowledged_at, :utc_datetime

      # Resolution
      add :resolution_time_seconds, :integer
      add :resolution_notes, :text

      # Details
      add :error_message, :text
      add :metadata, :map, default: %{}

      # Alert status
      add :alert_sent, :boolean, default: false
      add :alert_sent_at, :utc_datetime

      timestamps()
    end

    create_if_not_exists index(:integration_incidents, [:integration_id])
    create_if_not_exists index(:integration_incidents, [:status])
    create_if_not_exists index(:integration_incidents, [:severity])
    create_if_not_exists index(:integration_incidents, [:started_at])

    # Integration health alerts configuration
    create_if_not_exists table(:integration_health_alerts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :integration_id, references(:integrations, on_delete: :delete_all, type: :binary_id), null: false

      # Alert type and thresholds
      add :alert_type, :string, null: false  # connection_failure, high_error_rate, rate_limit, credential_expiry, sync_lag
      add :enabled, :boolean, default: true

      # Thresholds
      add :error_rate_threshold, :float, default: 5.0  # 5%
      add :rate_limit_threshold, :float, default: 80.0  # 80%
      add :credential_expiry_days, :integer, default: 7  # 7 days
      add :sync_lag_hours, :integer, default: 1  # 1 hour

      # Notification settings
      add :notification_channels, {:array, :string}, default: []  # ["email", "slack", "pagerduty"]
      add :notification_interval_minutes, :integer, default: 60  # Re-alert every 60 minutes

      # Last notification
      add :last_notification_at, :utc_datetime

      timestamps()
    end

    create_if_not_exists index(:integration_health_alerts, [:integration_id])
    create_if_not_exists index(:integration_health_alerts, [:alert_type])
    create_if_not_exists index(:integration_health_alerts, [:enabled])

    # Integration health check history (for synthetic transactions)
    create_if_not_exists table(:integration_health_checks, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :integration_id, references(:integrations, on_delete: :delete_all, type: :binary_id), null: false

      # Check details
      add :check_type, :string, null: false  # connectivity, authentication, synthetic_transaction
      add :success, :boolean, null: false
      add :duration_ms, :integer
      add :status_code, :integer
      add :error_message, :text
      add :response_body, :text

      # Metadata
      add :metadata, :map, default: %{}

      add :checked_at, :utc_datetime, null: false
    end

    create_if_not_exists index(:integration_health_checks, [:integration_id])
    create_if_not_exists index(:integration_health_checks, [:checked_at])
    create_if_not_exists index(:integration_health_checks, [:success])

    # Partition by time if needed (keep last 90 days)
  end
end
