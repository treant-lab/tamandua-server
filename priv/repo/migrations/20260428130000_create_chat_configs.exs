defmodule TamanduaServer.Repo.Migrations.CreateChatConfigs do
  @moduledoc """
  Creates chat configuration tables for Slack and Teams integrations.

  Each organization can have multiple workspace/team configurations with:
  - Encrypted bot tokens and credentials
  - Channel routing for alerts and escalations
  - Notification rules and digest schedules
  - Conversation references for proactive messaging
  """

  use Ecto.Migration

  def change do
    # Slack workspace configurations
    create table(:slack_workspace_configs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :team_id, :string, null: false  # Slack workspace team_id
      add :team_name, :string
      add :bot_token, :binary  # Encrypted
      add :signing_secret, :binary  # Encrypted
      add :alert_channel, :string  # Channel ID for regular alerts
      add :escalation_channel, :string  # Channel ID for critical/high alerts
      add :min_severity, :string, default: "high"
      add :enabled, :boolean, default: true
      add :notification_rules, :map, default: %{}
      add :digest_schedule, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:slack_workspace_configs, [:team_id])
    create index(:slack_workspace_configs, [:organization_id])
    create index(:slack_workspace_configs, [:enabled])

    # Teams configurations
    create table(:teams_configs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :team_id, :string, null: false  # MS Teams team_id
      add :team_name, :string
      add :tenant_id, :string  # Azure AD tenant
      add :app_id, :string
      add :app_password, :binary  # Encrypted
      add :alert_channel_id, :string
      add :escalation_channel_id, :string
      add :webhook_url, :string  # Incoming webhook URL
      add :min_severity, :string, default: "high"
      add :enabled, :boolean, default: true
      add :notification_rules, :map, default: %{}
      add :digest_schedule, :map, default: %{}
      add :conversation_reference, :map  # For proactive messaging

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:teams_configs, [:team_id])
    create index(:teams_configs, [:organization_id])
    create index(:teams_configs, [:enabled])
  end
end
