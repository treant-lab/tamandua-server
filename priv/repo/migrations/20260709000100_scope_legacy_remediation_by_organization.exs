defmodule TamanduaServer.Repo.Migrations.ScopeLegacyRemediationByOrganization do
  use Ecto.Migration

  def up do
    alter table(:remediation_playbooks) do
      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all)
    end

    alter table(:remediation_executions) do
      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all)

      add :approval_timeout_minutes, :integer, default: 30
    end

    create index(:remediation_playbooks, [:organization_id])
    create index(:remediation_playbooks, [:organization_id, :enabled])
    create index(:remediation_executions, [:organization_id])
    create index(:remediation_executions, [:organization_id, :status])

    execute """
    UPDATE remediation_playbooks AS p
    SET organization_id = u.organization_id
    FROM users AS u
    WHERE p.organization_id IS NULL
      AND p.created_by = u.id
      AND u.organization_id IS NOT NULL
    """

    execute """
    WITH candidates AS (
      SELECT
        e.id,
        p.organization_id AS playbook_org,
        a.organization_id AS agent_org,
        al.organization_id AS alert_org,
        u.organization_id AS user_org
      FROM remediation_executions AS e
      LEFT JOIN remediation_playbooks AS p ON p.id = e.playbook_id
      LEFT JOIN agents AS a ON a.id = e.agent_id
      LEFT JOIN alerts AS al ON al.id = e.alert_id
      LEFT JOIN users AS u ON u.id = e.triggered_by
      WHERE e.organization_id IS NULL
    )
    UPDATE remediation_executions AS e
    SET organization_id = COALESCE(c.playbook_org, c.agent_org, c.alert_org, c.user_org)
    FROM candidates AS c
    WHERE e.id = c.id
      AND (c.playbook_org IS NULL OR c.agent_org IS NULL OR c.playbook_org = c.agent_org)
      AND (c.playbook_org IS NULL OR c.alert_org IS NULL OR c.playbook_org = c.alert_org)
      AND (c.playbook_org IS NULL OR c.user_org IS NULL OR c.playbook_org = c.user_org)
      AND (c.agent_org IS NULL OR c.alert_org IS NULL OR c.agent_org = c.alert_org)
      AND (c.agent_org IS NULL OR c.user_org IS NULL OR c.agent_org = c.user_org)
      AND (c.alert_org IS NULL OR c.user_org IS NULL OR c.alert_org = c.user_org)
    """

    for table <- ["remediation_playbooks", "remediation_executions"] do
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
    for table <- ["remediation_executions", "remediation_playbooks"] do
      execute("DROP POLICY IF EXISTS #{table}_organization_isolation ON #{table}")
      execute("ALTER TABLE #{table} NO FORCE ROW LEVEL SECURITY")
      execute("ALTER TABLE #{table} DISABLE ROW LEVEL SECURITY")
    end

    drop index(:remediation_executions, [:organization_id, :status])
    drop index(:remediation_executions, [:organization_id])
    drop index(:remediation_playbooks, [:organization_id, :enabled])
    drop index(:remediation_playbooks, [:organization_id])

    alter table(:remediation_executions) do
      remove :approval_timeout_minutes
      remove :organization_id
    end

    alter table(:remediation_playbooks) do
      remove :organization_id
    end
  end
end
