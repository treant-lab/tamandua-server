defmodule TamanduaServer.Repo.Migrations.CreateScreenCaptureEvidenceSessions do
  use Ecto.Migration

  def up do
    create table(:screen_capture_evidence_sessions, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false)
      add(:status, :string, null: false, default: "scheduled")
      add(:reason, :string, null: false)
      add(:capture_request, :map, null: false)
      add(:frame_count, :integer, null: false)
      add(:interval_seconds, :integer, null: false)
      add(:next_frame_index, :integer, null: false, default: 0)
      add(:requested_by_id, :binary_id)
      add(:requested_by_email, :string)
      add(:started_at, :utc_datetime_usec)
      add(:completed_at, :utc_datetime_usec)
      add(:cancelled_at, :utc_datetime_usec)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:failure_reason, :string)
      timestamps(type: :utc_datetime_usec)
    end

    create(index(:screen_capture_evidence_sessions, [:organization_id, :agent_id, :inserted_at]))
    create(index(:screen_capture_evidence_sessions, [:organization_id, :status, :expires_at]))

    create(
      constraint(:screen_capture_evidence_sessions, :evidence_session_status_check,
        check:
          "status IN ('scheduled','running','completed','partial','cancelled','failed','expired')"
      )
    )

    create(
      constraint(:screen_capture_evidence_sessions, :evidence_session_bounds_check,
        check:
          "frame_count BETWEEN 2 AND 10 AND interval_seconds BETWEEN 5 AND 60 AND next_frame_index BETWEEN 0 AND frame_count"
      )
    )

    execute("ALTER TABLE screen_capture_evidence_sessions ENABLE ROW LEVEL SECURITY")
    execute("ALTER TABLE screen_capture_evidence_sessions FORCE ROW LEVEL SECURITY")

    execute("""
    CREATE POLICY screen_capture_evidence_sessions_organization_isolation
    ON screen_capture_evidence_sessions FOR ALL TO PUBLIC
    USING (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
    WITH CHECK (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
    """)

    alter table(:screen_capture_artifacts) do
      add(
        :evidence_session_id,
        references(:screen_capture_evidence_sessions, type: :binary_id, on_delete: :nilify_all)
      )

      add(:frame_index, :integer)
    end

    create(
      unique_index(:screen_capture_artifacts, [:evidence_session_id, :frame_index],
        where: "evidence_session_id IS NOT NULL"
      )
    )

    create(
      constraint(:screen_capture_artifacts, :screen_capture_artifact_frame_index_check,
        check: "frame_index IS NULL OR frame_index >= 0"
      )
    )
  end

  def down do
    alter table(:screen_capture_artifacts) do
      remove(:frame_index)
      remove(:evidence_session_id)
    end

    execute(
      "DROP POLICY IF EXISTS screen_capture_evidence_sessions_organization_isolation ON screen_capture_evidence_sessions"
    )

    drop(table(:screen_capture_evidence_sessions))
  end
end
