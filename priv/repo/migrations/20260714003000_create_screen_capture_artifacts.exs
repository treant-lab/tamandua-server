defmodule TamanduaServer.Repo.Migrations.CreateScreenCaptureArtifacts do
  use Ecto.Migration

  def up do
    create table(:screen_capture_artifacts, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false)

      add(
        :command_id,
        references(:agent_commands, type: :binary_id, on_delete: :nilify_all)
      )

      add(:status, :string, null: false, default: "pending")
      add(:mime, :string)
      add(:size, :bigint)
      add(:sha256, :string)
      add(:display, :string, null: false, default: "all")
      add(:captured_at, :utc_datetime_usec)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:uploaded_at, :utc_datetime_usec)
      add(:upload_token_hash, :binary)
      add(:upload_token_used_at, :utc_datetime_usec)
      add(:failure_reason, :string)
      add(:content, :binary)

      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:screen_capture_artifacts, [:command_id]))
    create(index(:screen_capture_artifacts, [:organization_id, :agent_id, :inserted_at]))
    create(index(:screen_capture_artifacts, [:organization_id, :status, :expires_at]))

    create(
      constraint(:screen_capture_artifacts, :screen_capture_artifacts_status_check,
        check: "status IN ('pending', 'ready', 'expired', 'failed')"
      )
    )

    create(
      constraint(:screen_capture_artifacts, :screen_capture_artifacts_mime_check,
        check: "mime IS NULL OR mime = 'image/png'"
      )
    )

    create(
      constraint(:screen_capture_artifacts, :screen_capture_artifacts_size_check,
        check: "size IS NULL OR (size > 0 AND size <= 8388608)"
      )
    )

    create(
      constraint(:screen_capture_artifacts, :screen_capture_artifacts_content_size_check,
        check:
          "content IS NULL OR (octet_length(content) <= 8388608 AND size = octet_length(content))"
      )
    )

    execute("ALTER TABLE screen_capture_artifacts ENABLE ROW LEVEL SECURITY")
    execute("ALTER TABLE screen_capture_artifacts FORCE ROW LEVEL SECURITY")

    execute("""
    CREATE POLICY screen_capture_artifacts_organization_isolation
    ON screen_capture_artifacts
    FOR ALL TO PUBLIC
    USING (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
    WITH CHECK (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
    """)
  end

  def down do
    execute(
      "DROP POLICY IF EXISTS screen_capture_artifacts_organization_isolation ON screen_capture_artifacts"
    )

    execute("ALTER TABLE screen_capture_artifacts NO FORCE ROW LEVEL SECURITY")
    execute("ALTER TABLE screen_capture_artifacts DISABLE ROW LEVEL SECURITY")
    drop(table(:screen_capture_artifacts))
  end
end
