defmodule TamanduaServer.Repo.Migrations.CreateAiAgenticInvestigationSnapshots do
  use Ecto.Migration

  def up do
    create table(:ai_agentic_investigation_snapshots, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:investigation_id, :string, null: false)
      add(:alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false)
      add(:state, :string, null: false)
      add(:terminal, :boolean, null: false, default: false)
      add(:snapshot_version, :integer, null: false, default: 1)
      add(:snapshot, :jsonb, null: false)
      add(:snapshot_sha256, :string, null: false)

      timestamps(type: :utc_datetime_usec)
    end

    create(
      unique_index(
        :ai_agentic_investigation_snapshots,
        [:organization_id, :investigation_id],
        name: :ai_agentic_investigation_snapshots_org_investigation_idx
      )
    )

    create(
      index(
        :ai_agentic_investigation_snapshots,
        [:organization_id, :terminal, :updated_at]
      )
    )

    create(
      constraint(
        :ai_agentic_investigation_snapshots,
        :ai_agentic_investigation_snapshots_version_check,
        check: "snapshot_version = 1"
      )
    )

    create(
      constraint(
        :ai_agentic_investigation_snapshots,
        :ai_agentic_investigation_snapshots_hash_check,
        check: "snapshot_sha256 ~ '^[a-f0-9]{64}$'"
      )
    )

    execute("ALTER TABLE ai_agentic_investigation_snapshots ENABLE ROW LEVEL SECURITY")
    execute("ALTER TABLE ai_agentic_investigation_snapshots FORCE ROW LEVEL SECURITY")

    execute("""
    CREATE POLICY ai_agentic_investigation_snapshots_organization_isolation
    ON ai_agentic_investigation_snapshots
    FOR ALL TO PUBLIC
    USING (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
    WITH CHECK (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
    """)
  end

  def down do
    execute("""
    DROP POLICY IF EXISTS ai_agentic_investigation_snapshots_organization_isolation
    ON ai_agentic_investigation_snapshots
    """)

    execute("ALTER TABLE ai_agentic_investigation_snapshots NO FORCE ROW LEVEL SECURITY")
    execute("ALTER TABLE ai_agentic_investigation_snapshots DISABLE ROW LEVEL SECURITY")
    drop(table(:ai_agentic_investigation_snapshots))
  end
end
