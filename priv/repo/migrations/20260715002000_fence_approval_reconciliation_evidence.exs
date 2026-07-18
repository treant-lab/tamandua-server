defmodule TamanduaServer.Repo.Migrations.FenceApprovalReconciliationEvidence do
  use Ecto.Migration

  def up do
    create(
      unique_index(:ai_approval_executions, [:reconciliation_evidence_ref],
        where: "reconciliation_evidence_ref IS NOT NULL",
        name: :ai_approval_executions_reconciliation_evidence_ref_idx
      )
    )
  end

  def down do
    drop(
      index(:ai_approval_executions, [:reconciliation_evidence_ref],
        name: :ai_approval_executions_reconciliation_evidence_ref_idx
      )
    )
  end
end
