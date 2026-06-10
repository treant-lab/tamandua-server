defmodule TamanduaServer.Repo.Migrations.CreateTicketingConfigs do
  @moduledoc """
  Migration to create the ticketing_configs table for Jira and ServiceNow integrations.

  This table stores per-organization ticketing configurations with encrypted credentials.
  """

  use Ecto.Migration

  def change do
    create table(:ticketing_configs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :type, :string, null: false  # "jira" or "servicenow"
      add :enabled, :boolean, default: false
      add :config, :binary  # Encrypted config blob (JSON serialized then encrypted)
      add :min_severity, :string, default: "high"  # Only create tickets for this severity and above
      add :auto_create, :boolean, default: true
      add :dedupe_enabled, :boolean, default: true
      add :dedupe_window_hours, :integer, default: 24
      add :last_sync_at, :utc_datetime_usec
      add :health_status, :string, default: "unknown"

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:ticketing_configs, [:organization_id, :type])
    create index(:ticketing_configs, [:organization_id])
    create index(:ticketing_configs, [:enabled])
  end
end
