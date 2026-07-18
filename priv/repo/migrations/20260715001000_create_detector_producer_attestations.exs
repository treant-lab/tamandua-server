defmodule TamanduaServer.Repo.Migrations.CreateDetectorProducerAttestations do
  use Ecto.Migration

  def up do
    create table(:detector_producer_attestations, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:attested_by_id, references(:users, type: :binary_id, on_delete: :nilify_all))
      add(:producer_id, :string, null: false)
      add(:detector_id, :string, null: false)
      add(:detector_type, :string, null: false)
      add(:detector_version, :string, null: false)
      add(:source, :string, null: false)
      add(:revision, :string, null: false)
      add(:artifact_sha256, :string, null: false)
      add(:input_schema_sha256, :string, null: false)
      add(:allowed_evidence_classes, {:array, :string}, null: false, default: [])
      add(:allowed_claim_scopes, {:array, :string}, null: false, default: [])
      add(:attestation_sha256, :string, null: false)
      add(:status, :string, null: false, default: "active")
      add(:attested_at, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec)
      add(:revoked_at, :utc_datetime_usec)

      timestamps(type: :utc_datetime_usec)
    end

    create(
      unique_index(:detector_producer_attestations, [:organization_id, :attestation_sha256],
        name: :detector_producer_attestations_org_hash_idx
      )
    )

    create(
      index(:detector_producer_attestations, [:organization_id, :producer_id, :status],
        name: :detector_producer_attestations_org_producer_idx
      )
    )

    create(
      constraint(:detector_producer_attestations, :detector_producer_attestations_status_check,
        check: "status IN ('active', 'revoked')"
      )
    )

    execute("ALTER TABLE detector_producer_attestations ENABLE ROW LEVEL SECURITY")
    execute("ALTER TABLE detector_producer_attestations FORCE ROW LEVEL SECURITY")

    execute("""
    CREATE POLICY detector_producer_attestations_organization_isolation
    ON detector_producer_attestations
    FOR ALL TO PUBLIC
    USING (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
    WITH CHECK (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
    """)
  end

  def down do
    execute("DROP POLICY IF EXISTS detector_producer_attestations_organization_isolation ON detector_producer_attestations")
    execute("ALTER TABLE detector_producer_attestations NO FORCE ROW LEVEL SECURITY")
    execute("ALTER TABLE detector_producer_attestations DISABLE ROW LEVEL SECURITY")
    drop(table(:detector_producer_attestations))
  end
end
