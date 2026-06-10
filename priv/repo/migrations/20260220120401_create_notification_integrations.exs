defmodule TamanduaServer.Repo.Migrations.CreateNotificationIntegrations do
  use Ecto.Migration

  def change do
    # Notification integrations table
    create table(:notification_integrations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Integration metadata
      add :name, :string, null: false
      add :provider, :string, null: false  # slack, teams, email, pagerduty, opsgenie, discord, telegram
      add :enabled, :boolean, default: true, null: false

      # Provider-specific configuration (encrypted)
      add :config, :map, null: false
      # Example configs:
      # Slack: %{webhook_url: "...", oauth_token: "...", channel: "#alerts"}
      # Teams: %{webhook_url: "..."}
      # Email: %{smtp_host: "...", smtp_port: 587, username: "...", password: "...", from: "..."}
      # PagerDuty: %{integration_key: "...", api_key: "..."}
      # OpsGenie: %{api_key: "...", region: "us"}
      # Discord: %{webhook_url: "..."}
      # Telegram: %{bot_token: "...", chat_id: "..."}

      # Template configuration
      add :template_title, :text  # Liquid/Mustache template for title
      add :template_body, :text   # Liquid/Mustache template for body

      # Routing rules
      add :routing_rules, :map, default: %{}
      # Example: %{
      #   severity: ["critical", "high"],
      #   alert_types: ["malware", "ransomware"],
      #   mitre_techniques: ["T1059.001"],
      #   tags: ["production"]
      # }

      # Throttling configuration
      add :throttle_enabled, :boolean, default: false
      add :throttle_max_per_hour, :integer, default: 60

      # Health tracking
      add :last_success_at, :utc_datetime_usec
      add :last_failure_at, :utc_datetime_usec
      add :failure_count, :integer, default: 0
      add :total_sent, :integer, default: 0
      add :total_failed, :integer, default: 0

      timestamps(type: :utc_datetime_usec)
    end

    create index(:notification_integrations, [:organization_id])
    create index(:notification_integrations, [:provider])
    create index(:notification_integrations, [:enabled])
    create unique_index(:notification_integrations, [:organization_id, :name])

    # Notification delivery logs table
    create table(:notification_delivery_logs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :integration_id, references(:notification_integrations, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all)

      # Delivery details
      add :status, :string, null: false  # sent, failed, retry, throttled
      add :provider, :string, null: false
      add :recipient, :string  # channel, email, phone, etc.

      # Request/Response
      add :rendered_title, :text
      add :rendered_body, :text
      add :error_message, :text
      add :response_code, :integer
      add :response_body, :text

      # Metadata
      add :delivered_at, :utc_datetime_usec
      add :retry_count, :integer, default: 0
      add :next_retry_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create index(:notification_delivery_logs, [:integration_id])
    create index(:notification_delivery_logs, [:organization_id])
    create index(:notification_delivery_logs, [:alert_id])
    create index(:notification_delivery_logs, [:status])
    create index(:notification_delivery_logs, [:inserted_at])
    create index(:notification_delivery_logs, [:next_retry_at], where: "status = 'retry'")
  end
end
