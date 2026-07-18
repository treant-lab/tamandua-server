defmodule TamanduaServer.Repo.Migrations.AddEvidenceSessionV2 do
  use Ecto.Migration

  def up do
    drop(constraint(:screen_capture_evidence_sessions, :evidence_session_status_check))
    drop(constraint(:screen_capture_evidence_sessions, :evidence_session_bounds_check))

    alter table(:screen_capture_evidence_sessions) do
      add(:alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all))

      add(
        :investigation_id,
        references(:investigations, type: :binary_id, on_delete: :nilify_all)
      )

      add(:case_id, references(:case_investigations, type: :binary_id, on_delete: :nilify_all))
      add(:mobile_command_id, references(:mdm_commands, type: :binary_id, on_delete: :nilify_all))
      add(:approval_status, :string, null: false, default: "not_required")
      add(:approval_expires_at, :utc_datetime_usec)
      add(:approved_by_id, references(:users, type: :binary_id, on_delete: :nilify_all))
      add(:approved_at, :utc_datetime_usec)
    end

    create(index(:screen_capture_evidence_sessions, [:organization_id, :alert_id]))
    create(index(:screen_capture_evidence_sessions, [:organization_id, :investigation_id]))
    create(index(:screen_capture_evidence_sessions, [:organization_id, :case_id]))

    create(
      constraint(:screen_capture_evidence_sessions, :evidence_session_status_check,
        check:
          "status IN ('pending_approval','scheduled','running','completed','partial','cancelled','failed','expired')"
      )
    )

    create(
      constraint(:screen_capture_evidence_sessions, :evidence_session_bounds_check,
        check:
          "frame_count BETWEEN 2 AND 30 AND interval_seconds BETWEEN 5 AND 60 AND next_frame_index BETWEEN 0 AND frame_count AND ((frame_count - 1) * interval_seconds) <= 1800"
      )
    )

    create(
      constraint(:screen_capture_evidence_sessions, :evidence_session_approval_status_check,
        check: "approval_status IN ('not_required','pending','approved','expired')"
      )
    )

    create(
      constraint(:screen_capture_evidence_sessions, :evidence_session_approval_coherence_check,
        check:
          "(approval_status = 'not_required' AND status <> 'pending_approval' AND approved_by_id IS NULL AND approved_at IS NULL) OR (approval_status = 'pending' AND status = 'pending_approval' AND approval_expires_at IS NOT NULL AND approved_by_id IS NULL AND approved_at IS NULL) OR (approval_status = 'approved' AND status <> 'pending_approval' AND approved_by_id IS NOT NULL AND approved_at IS NOT NULL) OR (approval_status = 'expired' AND status IN ('expired','cancelled'))"
      )
    )

    create table(:evidence_session_exports, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :evidence_session_id,
        references(:screen_capture_evidence_sessions, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:requested_by_id, references(:users, type: :binary_id, on_delete: :nilify_all))
      add(:sha256, :string, null: false)
      add(:size, :bigint, null: false)
      add(:content, :binary, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      timestamps(type: :utc_datetime_usec)
    end

    create(index(:evidence_session_exports, [:organization_id, :evidence_session_id]))
    create(index(:evidence_session_exports, [:organization_id, :expires_at]))
    tenant_rls(:evidence_session_exports)

    create table(:evidence_session_diffs, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :evidence_session_id,
        references(:screen_capture_evidence_sessions, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :left_artifact_id,
        references(:screen_capture_artifacts, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :right_artifact_id,
        references(:screen_capture_artifacts, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:metrics, :map, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      timestamps(type: :utc_datetime_usec)
    end

    create(index(:evidence_session_diffs, [:organization_id, :evidence_session_id, :expires_at]))
    tenant_rls(:evidence_session_diffs)
  end

  def down do
    drop(table(:evidence_session_diffs))
    drop(table(:evidence_session_exports))

    drop(
      constraint(:screen_capture_evidence_sessions, :evidence_session_approval_coherence_check)
    )

    drop(constraint(:screen_capture_evidence_sessions, :evidence_session_approval_status_check))
    drop(constraint(:screen_capture_evidence_sessions, :evidence_session_bounds_check))
    drop(constraint(:screen_capture_evidence_sessions, :evidence_session_status_check))

    alter table(:screen_capture_evidence_sessions) do
      remove(:approved_at)
      remove(:approved_by_id)
      remove(:approval_expires_at)
      remove(:approval_status)
      remove(:case_id)
      remove(:mobile_command_id)
      remove(:investigation_id)
      remove(:alert_id)
    end

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
  end

  defp tenant_rls(table) do
    name = "#{table}_organization_isolation"
    execute("ALTER TABLE #{table} ENABLE ROW LEVEL SECURITY")
    execute("ALTER TABLE #{table} FORCE ROW LEVEL SECURITY")

    execute(
      "CREATE POLICY #{name} ON #{table} FOR ALL TO PUBLIC USING (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id()) WITH CHECK (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())"
    )
  end
end
