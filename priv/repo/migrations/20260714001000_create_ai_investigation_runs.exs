defmodule TamanduaServer.Repo.Migrations.CreateAiInvestigationRuns do
  use Ecto.Migration

  def up do
    create table(:ai_investigation_runs, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false)
      add(:idempotency_key, :string, null: false)
      add(:mode, :string, null: false, default: "shadow")
      add(:status, :string, null: false, default: "queued")
      add(:source, :string, null: false, default: "explicit")
      add(:policy_version, :string, null: false, default: "shadow-v1")
      add(:summary, :jsonb, null: false, default: fragment("'{}'::jsonb"))
      add(:error_code, :string)
      add(:started_at, :utc_datetime_usec)
      add(:completed_at, :utc_datetime_usec)

      timestamps(type: :utc_datetime_usec)
    end

    create(
      unique_index(:ai_investigation_runs, [:organization_id, :idempotency_key],
        name: :ai_investigation_runs_org_idempotency_idx
      )
    )

    create(index(:ai_investigation_runs, [:organization_id, :alert_id]))
    create(index(:ai_investigation_runs, [:organization_id, :status, :inserted_at]))

    create(
      constraint(:ai_investigation_runs, :ai_investigation_runs_mode_check,
        check: "mode IN ('shadow', 'recommendation')"
      )
    )

    create(
      constraint(:ai_investigation_runs, :ai_investigation_runs_status_check,
        check: "status IN ('queued', 'running', 'observed', 'abstained', 'failed')"
      )
    )

    create table(:ai_investigation_evidence, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :run_id,
        references(:ai_investigation_runs, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:kind, :string, null: false)
      add(:source, :string, null: false)
      add(:source_ref, :string, null: false)
      add(:dedupe_key, :string, null: false)
      add(:payload, :jsonb, null: false, default: fragment("'{}'::jsonb"))
      add(:observed_at, :utc_datetime_usec, null: false)

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create(
      unique_index(:ai_investigation_evidence, [:organization_id, :run_id, :dedupe_key],
        name: :ai_investigation_evidence_org_run_dedupe_idx
      )
    )

    create(index(:ai_investigation_evidence, [:organization_id, :run_id, :observed_at]))

    for table <- ["ai_investigation_runs", "ai_investigation_evidence"] do
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
    for table <- ["ai_investigation_evidence", "ai_investigation_runs"] do
      execute("DROP POLICY IF EXISTS #{table}_organization_isolation ON #{table}")
      execute("ALTER TABLE #{table} NO FORCE ROW LEVEL SECURITY")
      execute("ALTER TABLE #{table} DISABLE ROW LEVEL SECURITY")
    end

    drop(table(:ai_investigation_evidence))
    drop(table(:ai_investigation_runs))
  end
end
