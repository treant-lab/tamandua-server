defmodule TamanduaServer.Repo.Migrations.CreateRemediationPolicies do
  use Ecto.Migration

  def change do
    create table(:remediation_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :is_enabled, :boolean, default: true, null: false
      add :is_default, :boolean, default: false, null: false
      add :priority, :integer, default: 100, null: false  # Lower = higher priority

      # Risk threshold configuration
      add :auto_threshold, :float  # Auto-execute below this score (e.g., 0.3)
      add :manual_threshold, :float  # Require approval above this score (e.g., 0.7)

      # Action configuration
      add :action_type, :string, null: false  # quarantine, block, notify, escalate
      add :action_config, :map, default: %{}  # Action-specific settings

      # Conditions (all must match for policy to apply)
      add :conditions, :map, default: %{}  # {severity: [...], mitre_tactics: [...], agent_groups: [...]}

      # Scope
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :agent_group_ids, {:array, :binary_id}, default: []  # Apply to specific groups

      timestamps(type: :utc_datetime_usec)
    end

    create index(:remediation_policies, [:organization_id])
    create index(:remediation_policies, [:is_enabled])
    create index(:remediation_policies, [:priority])
    create unique_index(:remediation_policies, [:name, :organization_id])
  end
end
