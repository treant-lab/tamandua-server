defmodule TamanduaServer.Repo.Migrations.CreateAiApprovalExecutions do
  use Ecto.Migration

  def up do
    create table(:ai_approval_executions, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:investigation_id, :string, null: false)
      add(:recommendation_id, :string, null: false)

      add(
        :approver_id,
        references(:users, type: :binary_id, on_delete: :nothing),
        null: false
      )

      add(:idempotency_key, :string, null: false)
      add(:status, :string, null: false, default: "pending")
      add(:action_type, :string, null: false)
      add(:target, :jsonb, null: false, default: fragment("'{}'::jsonb"))
      add(:result, :jsonb)
      add(:error, :jsonb)
      add(:started_at, :utc_datetime_usec)
      add(:completed_at, :utc_datetime_usec)

      timestamps(type: :utc_datetime_usec)
    end

    create(
      unique_index(
        :ai_approval_executions,
        [:organization_id, :investigation_id, :recommendation_id],
        name: :ai_approval_executions_org_investigation_recommendation_idx
      )
    )

    create(
      unique_index(:ai_approval_executions, [:organization_id, :idempotency_key],
        name: :ai_approval_executions_org_idempotency_idx
      )
    )

    create(index(:ai_approval_executions, [:organization_id, :status, :inserted_at]))
    create(index(:ai_approval_executions, [:organization_id, :approver_id, :inserted_at]))

    create(
      constraint(:ai_approval_executions, :ai_approval_executions_status_check,
        check: "status IN ('pending', 'running', 'succeeded', 'failed')"
      )
    )

    execute("ALTER TABLE ai_approval_executions ENABLE ROW LEVEL SECURITY")
    execute("ALTER TABLE ai_approval_executions FORCE ROW LEVEL SECURITY")

    execute("""
    CREATE POLICY ai_approval_executions_organization_isolation ON ai_approval_executions
    FOR ALL TO PUBLIC
    USING (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
    WITH CHECK (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
    """)
  end

  def down do
    execute(
      "DROP POLICY IF EXISTS ai_approval_executions_organization_isolation ON ai_approval_executions"
    )

    execute("ALTER TABLE ai_approval_executions NO FORCE ROW LEVEL SECURITY")
    execute("ALTER TABLE ai_approval_executions DISABLE ROW LEVEL SECURITY")
    drop(table(:ai_approval_executions))
  end
end
