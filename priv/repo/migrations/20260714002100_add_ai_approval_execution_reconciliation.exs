defmodule TamanduaServer.Repo.Migrations.AddAiApprovalExecutionReconciliation do
  use Ecto.Migration

  def up do
    alter table(:ai_approval_executions) do
      add(:lease_expires_at, :utc_datetime_usec)

      add(
        :reconciled_by_id,
        references(:users, type: :binary_id, on_delete: :nothing)
      )

      add(:reconciled_at, :utc_datetime_usec)
      add(:reconciliation_evidence_ref, :string)
    end

    drop(constraint(:ai_approval_executions, :ai_approval_executions_status_check))

    create(
      constraint(:ai_approval_executions, :ai_approval_executions_status_check,
        check:
          "status IN ('pending', 'running', 'succeeded', 'failed', 'reconciliation_required')"
      )
    )

    create(index(:ai_approval_executions, [:organization_id, :status, :lease_expires_at]))
  end

  def down do
    drop(index(:ai_approval_executions, [:organization_id, :status, :lease_expires_at]))
    drop(constraint(:ai_approval_executions, :ai_approval_executions_status_check))

    create(
      constraint(:ai_approval_executions, :ai_approval_executions_status_check,
        check: "status IN ('pending', 'running', 'succeeded', 'failed')"
      )
    )

    alter table(:ai_approval_executions) do
      remove(:reconciliation_evidence_ref)
      remove(:reconciled_at)
      remove(:reconciled_by_id)
      remove(:lease_expires_at)
    end
  end
end
