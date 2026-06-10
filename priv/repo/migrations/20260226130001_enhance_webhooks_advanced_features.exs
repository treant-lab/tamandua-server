defmodule TamanduaServer.Repo.Migrations.EnhanceWebhooksAdvancedFeatures do
  use Ecto.Migration

  def change do
    alter table(:webhooks) do
      # HTTP Configuration
      add :http_method, :string, default: "POST", null: false
      add :payload_format, :string, default: "json", null: false
      add :content_type, :string, default: "application/json"

      # Template System
      add :template, :text
      add :use_template, :boolean, default: false, null: false

      # OAuth 2.0 Authentication
      add :oauth_client_id, :string
      add :oauth_client_secret, :string
      add :oauth_token_url, :string
      add :oauth_scope, :string
      add :oauth_token_cache, :map
      add :oauth_token_expires_at, :utc_datetime

      # mTLS Authentication
      add :mtls_enabled, :boolean, default: false, null: false
      add :mtls_client_cert, :text
      add :mtls_client_key, :text
      add :mtls_ca_cert, :text

      # Priority & Delivery Options
      add :priority, :string, default: "normal", null: false
      add :async_mode, :boolean, default: true, null: false

      # Health Monitoring
      add :health_status, :string, default: "healthy", null: false
      add :consecutive_failures, :integer, default: 0, null: false
      add :circuit_breaker_open_until, :utc_datetime
      add :last_health_check_at, :utc_datetime

      # Rate Limiting
      add :rate_limit_per_minute, :integer
      add :rate_limit_per_hour, :integer

      # Metadata
      add :tags, {:array, :string}, default: []
      add :metadata, :map, default: %{}
    end

    create index(:webhooks, [:health_status])
    create index(:webhooks, [:priority])
    create index(:webhooks, [:http_method])

    # Dead Letter Queue table
    create table(:webhook_dead_letter_queue, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :webhook_id, references(:webhooks, type: :binary_id, on_delete: :delete_all),
        null: false

      add :delivery_log_id, references(:webhook_deliveries, type: :binary_id, on_delete: :nilify_all)
      add :event_type, :string, null: false
      add :event_id, :binary_id
      add :payload, :map, null: false
      add :error_reason, :text, null: false
      add :failure_count, :integer, default: 1, null: false
      add :retry_attempted_at, :utc_datetime
      add :resolved_at, :utc_datetime
      add :resolved_by, :binary_id  # User ID
      add :resolution_notes, :text

      timestamps()
    end

    create index(:webhook_dead_letter_queue, [:webhook_id])
    create index(:webhook_dead_letter_queue, [:event_type])
    create index(:webhook_dead_letter_queue, [:resolved_at])

    # Webhook Health Metrics table
    create table(:webhook_health_metrics, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :webhook_id, references(:webhooks, type: :binary_id, on_delete: :delete_all),
        null: false

      add :timestamp, :utc_datetime, null: false
      add :success_count, :integer, default: 0, null: false
      add :failure_count, :integer, default: 0, null: false
      add :avg_response_time_ms, :float
      add :p95_response_time_ms, :float
      add :p99_response_time_ms, :float
      add :error_rate_percent, :float
      add :status_codes, :map, default: %{}

      timestamps(updated_at: false)
    end

    create index(:webhook_health_metrics, [:webhook_id, :timestamp])
    create index(:webhook_health_metrics, [:timestamp])

    # Webhook Rate Limit Tracking
    create table(:webhook_rate_limits, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :webhook_id, references(:webhooks, type: :binary_id, on_delete: :delete_all),
        null: false

      add :window_start, :utc_datetime, null: false
      add :window_end, :utc_datetime, null: false
      add :request_count, :integer, default: 0, null: false

      timestamps(updated_at: false)
    end

    create unique_index(:webhook_rate_limits, [:webhook_id, :window_start])
    create index(:webhook_rate_limits, [:window_end])
  end
end
