defmodule TamanduaServer.Repo.Migrations.CreatePKITables do
  use Ecto.Migration

  def change do
    # CA certificates storage
    create_if_not_exists table(:pki_certificates, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :type, :string, null: false  # "root_ca" or "intermediate_ca"
      add :certificate_pem, :text, null: false
      add :encrypted_key, :binary, null: false
      add :metadata, :map

      timestamps()
    end

    create_if_not_exists unique_index(:pki_certificates, [:type])

    # CA certificates archive (for rotation history)
    create_if_not_exists table(:pki_certificates_archive, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :type, :string, null: false
      add :certificate_pem, :text, null: false
      add :archived_at, :utc_datetime, null: false

      timestamps()
    end

    # Agent certificates
    create_if_not_exists table(:agent_certificates, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :agent_id, references(:agents, type: :uuid, on_delete: :delete_all), null: false
      add :certificate_pem, :text, null: false
      add :serial_number, :string, null: false
      add :not_after, :utc_datetime, null: false
      add :status, :string, default: "active", null: false  # "active", "revoked", "expired"
      add :metadata, :map

      timestamps()
    end

    # Add missing columns to agent_certificates if table exists
    execute """
    DO $$
    BEGIN
      ALTER TABLE agent_certificates ADD COLUMN IF NOT EXISTS not_after TIMESTAMP WITHOUT TIME ZONE;
      ALTER TABLE agent_certificates ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'active';
      ALTER TABLE agent_certificates ADD COLUMN IF NOT EXISTS serial_number VARCHAR;
      ALTER TABLE agent_certificates ADD COLUMN IF NOT EXISTS certificate_pem TEXT;
      ALTER TABLE agent_certificates ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';
    EXCEPTION
      WHEN undefined_table THEN NULL;
    END $$;
    """, ""

    execute "CREATE UNIQUE INDEX IF NOT EXISTS agent_certificates_agent_id_index ON agent_certificates(agent_id)", ""
    execute "CREATE UNIQUE INDEX IF NOT EXISTS agent_certificates_serial_number_index ON agent_certificates(serial_number)", ""
    execute "CREATE INDEX IF NOT EXISTS agent_certificates_not_after_index ON agent_certificates(not_after)", ""
    execute "CREATE INDEX IF NOT EXISTS agent_certificates_status_index ON agent_certificates(status)", ""

    # Agent certificates archive (for renewal history)
    create_if_not_exists table(:agent_certificates_archive, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :agent_id, :uuid, null: false
      add :certificate_pem, :text, null: false
      add :serial_number, :string, null: false
      add :archived_at, :utc_datetime, null: false

      timestamps()
    end

    create_if_not_exists index(:agent_certificates_archive, [:agent_id])
    create_if_not_exists index(:agent_certificates_archive, [:archived_at])

    # Certificate revocations
    create_if_not_exists table(:certificate_revocations, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :serial_number, :string, null: false
      add :reason, :string, null: false
      add :revoked_at, :utc_datetime, null: false
      add :status, :string, default: "revoked", null: false  # "revoked", "removed"
      add :metadata, :map

      timestamps()
    end

    create_if_not_exists unique_index(:certificate_revocations, [:serial_number])
    create_if_not_exists index(:certificate_revocations, [:revoked_at])
    create_if_not_exists index(:certificate_revocations, [:status])

    # Certificate Revocation Lists (CRL)
    create_if_not_exists table(:certificate_revocation_lists, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :crl_number, :bigint, null: false
      add :crl_der, :binary, null: false
      add :generated_at, :utc_datetime, null: false

      timestamps()
    end

    create_if_not_exists unique_index(:certificate_revocation_lists, [:crl_number])
    create_if_not_exists index(:certificate_revocation_lists, [:generated_at])
  end
end
