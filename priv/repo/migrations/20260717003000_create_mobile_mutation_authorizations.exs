defmodule TamanduaServer.Repo.Migrations.CreateMobileMutationAuthorizations do
  use Ecto.Migration

  def change do
    create table(:mobile_mutation_authorizations, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :identity_key_id,
        references(:mobile_device_identity_keys, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:actor_id, :string, null: false)
      add(:installation_id, :string, null: false)
      add(:platform, :string, null: false)
      add(:device_key_id, :string, null: false)
      add(:key_scope_id, :string, null: false)
      add(:request_id, :string, null: false)
      add(:challenge_digest, :binary, null: false)
      add(:nonce_digest, :binary, null: false)
      add(:operation, :string, null: false)
      add(:http_method, :string, null: false)
      add(:route_id, :string, null: false)
      add(:resource_id, :string, null: false)
      add(:body_sha256, :binary, null: false)
      add(:algorithm, :string, null: false)
      add(:issued_at, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:consumed_at, :utc_datetime_usec)
      add(:result_resource_id, :string)
      add(:result_outcome, :string)

      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:mobile_mutation_authorizations, [:organization_id, :request_id]))

    create(unique_index(:mobile_mutation_authorizations, [:organization_id, :challenge_digest]))

    create(unique_index(:mobile_mutation_authorizations, [:organization_id, :nonce_digest]))

    create(
      index(:mobile_mutation_authorizations, [
        :organization_id,
        :installation_id,
        :consumed_at
      ])
    )

    create(index(:mobile_mutation_authorizations, [:identity_key_id]))
    create(index(:mobile_mutation_authorizations, [:expires_at]))

    create(
      constraint(:mobile_mutation_authorizations, :mobile_mutation_result_consistency,
        check:
          "(result_resource_id IS NULL AND result_outcome IS NULL) OR " <>
            "(consumed_at IS NOT NULL AND result_resource_id IS NOT NULL AND " <>
            "result_resource_id <> '' AND " <>
            "result_outcome IN ('created', 'updated'))"
      )
    )

    execute(
      "ALTER TABLE mobile_mutation_authorizations ENABLE ROW LEVEL SECURITY",
      "ALTER TABLE mobile_mutation_authorizations DISABLE ROW LEVEL SECURITY"
    )

    execute(
      "ALTER TABLE mobile_mutation_authorizations FORCE ROW LEVEL SECURITY",
      "ALTER TABLE mobile_mutation_authorizations NO FORCE ROW LEVEL SECURITY"
    )

    execute(
      """
      CREATE POLICY mobile_mutation_authorizations_tenant_isolation
        ON mobile_mutation_authorizations
        FOR ALL TO PUBLIC
        USING (organization_id = current_organization_id())
        WITH CHECK (organization_id = current_organization_id())
      """,
      "DROP POLICY IF EXISTS mobile_mutation_authorizations_tenant_isolation ON mobile_mutation_authorizations"
    )
  end
end
