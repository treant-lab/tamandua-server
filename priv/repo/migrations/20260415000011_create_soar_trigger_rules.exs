defmodule TamanduaServer.Repo.Migrations.CreateSoarTriggerRules do
  use Ecto.Migration

  def change do
    create table(:soar_trigger_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :enabled, :boolean, default: true, null: false
      add :priority, :integer, default: 50, null: false

      # Match criteria (JSON)
      add :match_criteria, :map, default: %{}

      # Action configuration
      add :soar_platform, :string, null: false  # "xsoar", "tines", "both"
      add :playbook_name, :string, null: false
      add :webhook_url, :string  # For Tines webhooks
      add :params, :map, default: %{}

      # Tenant scoping
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:soar_trigger_rules, [:enabled])
    create index(:soar_trigger_rules, [:organization_id])
    create index(:soar_trigger_rules, [:soar_platform])
    create unique_index(:soar_trigger_rules, [:name, :organization_id], name: :soar_trigger_rules_name_org_unique)
  end
end
