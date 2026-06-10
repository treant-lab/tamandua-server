defmodule TamanduaServer.Repo.Migrations.CreateIntegrations do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:integrations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :type, :string, null: false
      add :name, :string, null: false
      add :description, :text
      add :config, :map, default: %{}
      add :encrypted_config, :binary
      add :enabled, :boolean, default: true, null: false
      add :last_sync_at, :utc_datetime
      add :last_error, :text
      add :stats, :map, default: %{}

      add :organization_id, references(:organizations, on_delete: :delete_all, type: :binary_id)

      timestamps()
    end

    create_if_not_exists index(:integrations, [:type])
    create_if_not_exists index(:integrations, [:organization_id])
    create_if_not_exists index(:integrations, [:enabled])
    create_if_not_exists unique_index(:integrations, [:type, :name, :organization_id], name: :integrations_type_name_org_unique)

    # Routing rules table
    create_if_not_exists table(:routing_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :conditions, {:array, :map}, default: []
      add :destinations, {:array, :string}, default: []
      add :transform, :map
      add :enabled, :boolean, default: true, null: false
      add :priority, :integer, default: 50, null: false

      add :organization_id, references(:organizations, on_delete: :delete_all, type: :binary_id)

      timestamps()
    end

    create_if_not_exists index(:routing_rules, [:organization_id])
    create_if_not_exists index(:routing_rules, [:enabled])
    create_if_not_exists index(:routing_rules, [:priority])

    # Integration logs table for activity tracking
    create_if_not_exists table(:integration_logs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :integration_id, references(:integrations, on_delete: :delete_all, type: :binary_id), null: false
      add :level, :string, null: false  # info, warning, error
      add :message, :text, null: false
      add :metadata, :map, default: %{}

      add :inserted_at, :utc_datetime, null: false
    end

    create_if_not_exists index(:integration_logs, [:integration_id])
    create_if_not_exists index(:integration_logs, [:level])
    create_if_not_exists index(:integration_logs, [:inserted_at])

    # Keep logs for 30 days by default - partition by time if needed
  end
end
