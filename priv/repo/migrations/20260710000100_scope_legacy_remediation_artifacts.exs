defmodule TamanduaServer.Repo.Migrations.ScopeLegacyRemediationArtifacts do
  use Ecto.Migration

  @tables [
    "remediation_audit_log",
    "remediation_approval_history",
    "remediation_metrics"
  ]

  def up do
    alter table(:remediation_audit_log) do
      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all)
    end

    alter table(:remediation_approval_history) do
      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all)
    end

    alter table(:remediation_metrics) do
      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all)
    end

    create index(:remediation_audit_log, [:organization_id])
    create index(:remediation_audit_log, [:organization_id, :execution_id])
    create index(:remediation_approval_history, [:organization_id])
    create index(:remediation_approval_history, [:organization_id, :execution_id])
    create index(:remediation_metrics, [:organization_id])
    create index(:remediation_metrics, [:organization_id, :metric_date])
    create index(:remediation_executions, [:organization_id, :playbook_id])

    execute """
    WITH candidates AS (
      SELECT
        audit.id,
        execution.organization_id AS execution_org,
        playbook.organization_id AS playbook_org
      FROM remediation_audit_log AS audit
      LEFT JOIN remediation_executions AS execution ON execution.id = audit.execution_id
      LEFT JOIN remediation_playbooks AS playbook ON playbook.id = audit.playbook_id
      WHERE audit.organization_id IS NULL
    )
    UPDATE remediation_audit_log AS audit
    SET organization_id = COALESCE(candidate.execution_org, candidate.playbook_org)
    FROM candidates AS candidate
    WHERE audit.id = candidate.id
      AND (
        candidate.execution_org IS NULL
        OR candidate.playbook_org IS NULL
        OR candidate.execution_org = candidate.playbook_org
      )
    """

    execute """
    UPDATE remediation_approval_history AS history
    SET organization_id = execution.organization_id
    FROM remediation_executions AS execution
    WHERE history.organization_id IS NULL
      AND history.execution_id = execution.id
      AND execution.organization_id IS NOT NULL
    """

    execute """
    WITH candidates AS (
      SELECT
        metric.id,
        execution.organization_id AS execution_org,
        playbook.organization_id AS playbook_org
      FROM remediation_metrics AS metric
      LEFT JOIN remediation_executions AS execution ON execution.id = metric.execution_id
      LEFT JOIN remediation_playbooks AS playbook ON playbook.id = metric.playbook_id
      WHERE metric.organization_id IS NULL
    )
    UPDATE remediation_metrics AS metric
    SET organization_id = COALESCE(candidate.execution_org, candidate.playbook_org)
    FROM candidates AS candidate
    WHERE metric.id = candidate.id
      AND (
        candidate.execution_org IS NULL
        OR candidate.playbook_org IS NULL
        OR candidate.execution_org = candidate.playbook_org
      )
    """

    for table <- @tables do
      execute("ALTER TABLE #{table} ENABLE ROW LEVEL SECURITY")
      execute("ALTER TABLE #{table} FORCE ROW LEVEL SECURITY")

      execute("""
      CREATE POLICY #{table}_organization_isolation ON #{table}
      FOR ALL TO PUBLIC
      USING (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
      WITH CHECK (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
      """)
    end
  end

  def down do
    for table <- Enum.reverse(@tables) do
      execute("DROP POLICY IF EXISTS #{table}_organization_isolation ON #{table}")
      execute("ALTER TABLE #{table} NO FORCE ROW LEVEL SECURITY")
      execute("ALTER TABLE #{table} DISABLE ROW LEVEL SECURITY")
    end

    drop index(:remediation_executions, [:organization_id, :playbook_id])
    drop index(:remediation_metrics, [:organization_id, :metric_date])
    drop index(:remediation_metrics, [:organization_id])
    drop index(:remediation_approval_history, [:organization_id, :execution_id])
    drop index(:remediation_approval_history, [:organization_id])
    drop index(:remediation_audit_log, [:organization_id, :execution_id])
    drop index(:remediation_audit_log, [:organization_id])

    alter table(:remediation_metrics) do
      remove :organization_id
    end

    alter table(:remediation_approval_history) do
      remove :organization_id
    end

    alter table(:remediation_audit_log) do
      remove :organization_id
    end
  end
end
