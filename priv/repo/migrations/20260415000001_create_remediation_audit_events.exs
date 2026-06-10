defmodule TamanduaServer.Repo.Migrations.CreateRemediationAuditEvents do
  use Ecto.Migration

  def change do
    create table(:remediation_audit_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :workflow_id, references(:remediation_workflows, type: :binary_id, on_delete: :nilify_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      # Event details
      add :event_type, :string, null: false
      add :previous_state, :string
      add :new_state, :string

      # Actor information
      add :actor_id, :binary_id
      add :actor_type, :string, null: false
      add :actor_email, :string

      # Additional context
      add :details, :map, default: %{}
      add :ip_address, :string
      add :user_agent, :string

      # Immutable - only inserted_at, no updated_at
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:remediation_audit_events, [:workflow_id])
    create index(:remediation_audit_events, [:organization_id, :inserted_at])
    create index(:remediation_audit_events, [:event_type])
    create index(:remediation_audit_events, [:actor_id])

    # Add escalation fields to workflows if not present
    alter table(:remediation_workflows) do
      add_if_not_exists :escalation_level, :integer, default: 0
      add_if_not_exists :escalation_timeout_minutes, :integer, default: 60
      add_if_not_exists :last_escalated_at, :utc_datetime_usec
    end

    # Add escalation timeout to policies
    alter table(:remediation_policies) do
      add_if_not_exists :escalation_timeout_minutes, :integer, default: 60
    end
  end
end
