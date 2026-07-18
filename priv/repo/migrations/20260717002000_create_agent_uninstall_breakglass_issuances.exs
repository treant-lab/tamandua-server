defmodule TamanduaServer.Repo.Migrations.CreateAgentUninstallBreakglassIssuances do
  use Ecto.Migration

  # Ordering dependency: 20260717001000_create_agent_uninstall_intents.exs
  # creates users(id, organization_id), required by the composite issuer FK.

  def up do
    create table(:agent_uninstall_breakglass_issuances, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:intent_id, :binary_id, null: false)
      add(:organization_id, :binary_id, null: false)
      add(:agent_id, :binary_id, null: false)
      add(:issued_by_user_id, :binary_id, null: false)
      add(:platform, :string, null: false)
      add(:consumer, :string, null: false)
      add(:reason, :string, null: false)
      add(:key_id, :string, null: false)
      add(:issued_at, :utc_datetime_usec, null: false)
      add(:not_before, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:nonce_sha256, :binary, null: false)
      add(:payload_sha256, :binary, null: false)
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    execute("""
    ALTER TABLE agent_uninstall_breakglass_issuances
      ADD CONSTRAINT agent_uninstall_breakglass_issuances_organization_fkey
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT,
      ADD CONSTRAINT agent_uninstall_breakglass_issuances_agent_tenant_fkey
        FOREIGN KEY (agent_id, organization_id)
        REFERENCES agents(id, organization_id) ON DELETE RESTRICT,
      ADD CONSTRAINT agent_uninstall_breakglass_issuances_issuer_tenant_fkey
        FOREIGN KEY (issued_by_user_id, organization_id)
        REFERENCES users(id, organization_id) ON DELETE RESTRICT
    """)

    create(
      unique_index(:agent_uninstall_breakglass_issuances, [:organization_id, :intent_id],
        name: :agent_uninstall_breakglass_issuances_org_intent_uidx
      )
    )

    create(
      unique_index(
        :agent_uninstall_breakglass_issuances,
        [:organization_id, :nonce_sha256],
        name: :agent_uninstall_breakglass_issuances_org_nonce_uidx
      )
    )

    create(
      unique_index(
        :agent_uninstall_breakglass_issuances,
        [:organization_id, :payload_sha256],
        name: :agent_uninstall_breakglass_issuances_org_payload_uidx
      )
    )

    create(index(:agent_uninstall_breakglass_issuances, [:organization_id, :agent_id, :issued_at]))
    create(index(:agent_uninstall_breakglass_issuances, [:expires_at]))

    execute("""
    ALTER TABLE agent_uninstall_breakglass_issuances
      ADD CONSTRAINT agent_uninstall_breakglass_issuances_platform_check
        CHECK (platform IN ('windows', 'linux', 'macos')),
      ADD CONSTRAINT agent_uninstall_breakglass_issuances_consumer_check
        CHECK (consumer IN ('native_cli', 'windows_msi')),
      ADD CONSTRAINT agent_uninstall_breakglass_issuances_consumer_platform_check
        CHECK (consumer <> 'windows_msi' OR platform = 'windows'),
      ADD CONSTRAINT agent_uninstall_breakglass_issuances_reason_check
        CHECK (
          octet_length(reason) BETWEEN 8 AND 512 AND
          reason = btrim(reason) AND
          reason !~ '[[:cntrl:]]'
        ),
      ADD CONSTRAINT agent_uninstall_breakglass_issuances_key_id_check
        CHECK (
          octet_length(key_id) BETWEEN 1 AND 64 AND
          key_id ~ '^[a-z0-9][a-z0-9._-]*$'
        ),
      ADD CONSTRAINT agent_uninstall_breakglass_issuances_time_check
        CHECK (
          date_trunc('second', issued_at) = issued_at AND
          date_trunc('second', not_before) = not_before AND
          date_trunc('second', expires_at) = expires_at AND
          issued_at <= not_before AND
          not_before < expires_at AND
          expires_at >= issued_at + interval '1 second' AND
          expires_at <= issued_at + interval '24 hours'
        ),
      ADD CONSTRAINT agent_uninstall_breakglass_issuances_digest_check
        CHECK (octet_length(nonce_sha256) = 32 AND octet_length(payload_sha256) = 32)
    """)

    execute("ALTER TABLE agent_uninstall_breakglass_issuances ENABLE ROW LEVEL SECURITY")
    execute("ALTER TABLE agent_uninstall_breakglass_issuances FORCE ROW LEVEL SECURITY")

    execute("""
    CREATE POLICY agent_uninstall_breakglass_issuances_tenant_select
      ON agent_uninstall_breakglass_issuances
      FOR SELECT
      USING (
        organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
      )
    """)

    execute("""
    CREATE POLICY agent_uninstall_breakglass_issuances_tenant_insert
      ON agent_uninstall_breakglass_issuances
      FOR INSERT
      WITH CHECK (
        organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
      )
    """)

    execute("""
    CREATE FUNCTION reject_agent_uninstall_breakglass_issuance_mutation()
    RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
    AS $$
    BEGIN
      RAISE EXCEPTION 'agent_uninstall_breakglass_issuances is append-only'
        USING ERRCODE = '55000';
    END;
    $$
    """)

    execute("""
    CREATE TRIGGER agent_uninstall_breakglass_issuances_append_only
      BEFORE UPDATE OR DELETE ON agent_uninstall_breakglass_issuances
      FOR EACH ROW EXECUTE FUNCTION reject_agent_uninstall_breakglass_issuance_mutation()
    """)

    execute("""
    CREATE TRIGGER agent_uninstall_breakglass_issuances_no_truncate
      BEFORE TRUNCATE ON agent_uninstall_breakglass_issuances
      FOR EACH STATEMENT EXECUTE FUNCTION reject_agent_uninstall_breakglass_issuance_mutation()
    """)

    execute(
      "REVOKE UPDATE, DELETE, TRUNCATE ON agent_uninstall_breakglass_issuances FROM PUBLIC"
    )
  end

  def down do
    execute("""
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM agent_uninstall_breakglass_issuances LIMIT 1) THEN
        RAISE EXCEPTION 'refusing destructive rollback: uninstall breakglass issuances exist';
      END IF;
    END;
    $$
    """)

    execute("""
    DROP TRIGGER IF EXISTS agent_uninstall_breakglass_issuances_no_truncate
      ON agent_uninstall_breakglass_issuances
    """)

    execute("""
    DROP TRIGGER IF EXISTS agent_uninstall_breakglass_issuances_append_only
      ON agent_uninstall_breakglass_issuances
    """)

    execute("DROP FUNCTION IF EXISTS reject_agent_uninstall_breakglass_issuance_mutation()")
    drop(table(:agent_uninstall_breakglass_issuances))
  end
end
