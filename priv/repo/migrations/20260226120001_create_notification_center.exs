defmodule TamanduaServer.Repo.Migrations.CreateNotificationCenter do
  use Ecto.Migration

  def change do
    # Notification types enum
    execute(
      """
      CREATE TYPE notification_type AS ENUM (
        'alert_new',
        'alert_status_change',
        'alert_assigned',
        'alert_unassigned',
        'alert_escalated',
        'comment_mention',
        'comment_reply',
        'agent_offline',
        'agent_reconnected',
        'integration_failure',
        'integration_recovered',
        'policy_violation',
        'system_event',
        'sla_breach',
        'sla_warning'
      )
      """,
      "DROP TYPE notification_type"
    )

    # Notification channels enum
    execute(
      """
      CREATE TYPE notification_channel AS ENUM (
        'in_app',
        'email',
        'sms',
        'slack',
        'teams',
        'pagerduty',
        'webhook'
      )
      """,
      "DROP TYPE notification_channel"
    )

    # Notifications table
    create table(:notifications, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false

      add :type, :notification_type, null: false
      add :title, :string, null: false
      add :body, :text
      add :priority, :string, default: "normal", null: false  # low, normal, high, critical

      # Metadata
      add :metadata, :jsonb, default: "{}"
      add :related_resource_type, :string  # "alert", "agent", "integration", etc.
      add :related_resource_id, :binary_id

      # State
      add :read_at, :utc_datetime
      add :acknowledged_at, :utc_datetime
      add :archived_at, :utc_datetime
      add :expires_at, :utc_datetime

      # Grouping
      add :group_key, :string  # For grouping similar notifications
      add :group_count, :integer, default: 1  # How many notifications grouped

      timestamps(type: :utc_datetime)
    end

    create index(:notifications, [:organization_id, :user_id])
    create index(:notifications, [:user_id, :read_at])
    create index(:notifications, [:type])
    create index(:notifications, [:related_resource_type, :related_resource_id])
    create index(:notifications, [:group_key])
    create index(:notifications, [:inserted_at])
    create index(:notifications, [:expires_at])

    # User notification preferences table
    create table(:user_notification_preferences, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Global preferences
      add :enabled, :boolean, default: true, null: false
      add :frequency, :string, default: "immediate", null: false  # immediate, digest_15min, digest_hourly, digest_daily

      # Quiet hours (DND)
      add :quiet_hours_enabled, :boolean, default: false
      add :quiet_hours_start, :time  # e.g., 22:00:00
      add :quiet_hours_end, :time    # e.g., 08:00:00
      add :quiet_hours_timezone, :string, default: "UTC"

      # Severity threshold
      add :min_severity, :string, default: "low"  # low, medium, high, critical

      # Per-type channel preferences (JSONB)
      # Structure: %{"alert_new" => ["in_app", "email"], "comment_mention" => ["in_app"], ...}
      add :channel_preferences, :jsonb, default: "{}"

      # Override for critical alerts (always notify)
      add :critical_override, :boolean, default: true

      timestamps(type: :utc_datetime)
    end

    create unique_index(:user_notification_preferences, [:user_id, :organization_id])

    # Escalation policies table
    create table(:escalation_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :name, :string, null: false
      add :description, :text
      add :enabled, :boolean, default: true, null: false

      # Escalation chain (array of user IDs)
      # Structure: [{"user_id": "...", "delay_minutes": 15}, ...]
      add :escalation_chain, :jsonb, null: false

      # Conditions for triggering escalation
      add :trigger_conditions, :jsonb, default: "{}"

      # On-call schedule (optional)
      add :schedule_enabled, :boolean, default: false
      add :schedule, :jsonb  # Calendar/rotation schedule

      timestamps(type: :utc_datetime)
    end

    create index(:escalation_policies, [:organization_id])
    create index(:escalation_policies, [:enabled])

    # Escalation instances (active escalations)
    create table(:escalation_instances, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :escalation_policy_id, references(:escalation_policies, type: :binary_id, on_delete: :delete_all), null: false

      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false

      add :current_level, :integer, default: 0, null: false
      add :max_level, :integer, null: false

      add :started_at, :utc_datetime, null: false
      add :completed_at, :utc_datetime
      add :acknowledged_at, :utc_datetime
      add :acknowledged_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      add :state, :string, default: "pending", null: false  # pending, in_progress, acknowledged, completed, cancelled

      timestamps(type: :utc_datetime)
    end

    create index(:escalation_instances, [:organization_id, :state])
    create index(:escalation_instances, [:alert_id])
    create index(:escalation_instances, [:escalation_policy_id])

    # Notification delivery log (tracks multi-channel delivery)
    create table(:notification_deliveries, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :notification_id, references(:notifications, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :channel, :notification_channel, null: false
      add :status, :string, null: false  # pending, sent, failed, throttled

      add :sent_at, :utc_datetime
      add :failed_at, :utc_datetime
      add :error_message, :text

      add :provider_response, :jsonb
      add :retry_count, :integer, default: 0

      timestamps(type: :utc_datetime)
    end

    create index(:notification_deliveries, [:notification_id])
    create index(:notification_deliveries, [:channel, :status])
    create index(:notification_deliveries, [:organization_id])

    # Notification templates table
    create table(:notification_templates, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      add :type, :notification_type, null: false
      add :channel, :notification_channel, null: false

      add :name, :string, null: false
      add :description, :text

      add :subject_template, :text  # For email/SMS
      add :body_template, :text, null: false

      add :is_default, :boolean, default: false

      timestamps(type: :utc_datetime)
    end

    create index(:notification_templates, [:organization_id, :type, :channel])
    create index(:notification_templates, [:type, :channel, :is_default])

    # Webhook notification configs
    create table(:notification_webhooks, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :name, :string, null: false
      add :url, :string, null: false
      add :method, :string, default: "POST", null: false

      add :headers, :jsonb, default: "{}"
      add :auth_type, :string  # none, basic, bearer, api_key
      add :auth_config, :jsonb, default: "{}"

      add :notification_types, {:array, :string}, default: []
      add :enabled, :boolean, default: true

      timestamps(type: :utc_datetime)
    end

    create index(:notification_webhooks, [:organization_id])
    create index(:notification_webhooks, [:enabled])
  end
end
