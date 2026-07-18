defmodule TamanduaServer.Repo.Migrations.CreateAgentUninstallIntents do
  use Ecto.Migration

  def up do
    create(
      unique_index(:users, [:id, :organization_id], name: :users_id_organization_uidx)
    )

    create table(:agent_uninstall_intents, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:organization_id, :binary_id, null: false)
      add(:agent_id, :binary_id, null: false)
      add(:issued_by_user_id, :binary_id, null: false)
      add(:action, :string, null: false, default: "agent_uninstall")
      add(:reason, :string, null: false)
      add(:idempotency_key_sha256, :binary)
      add(:nonce_sha256, :binary)
      add(:verifier_version, :string)
      add(:platform, :string)
      add(:consumer, :string)
      add(:token_generation, :integer)
      add(:state, :string, null: false, default: "pending")
      add(:issued_at, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:consumed_at, :utc_datetime_usec)
      add(:superseded_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    execute("""
    ALTER TABLE agent_uninstall_intents
      ADD CONSTRAINT agent_uninstall_intents_organization_fkey
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
      ADD CONSTRAINT agent_uninstall_intents_agent_tenant_fkey
        FOREIGN KEY (agent_id, organization_id)
        REFERENCES agents(id, organization_id) ON DELETE CASCADE,
      ADD CONSTRAINT agent_uninstall_intents_issuer_tenant_fkey
        FOREIGN KEY (issued_by_user_id, organization_id)
        REFERENCES users(id, organization_id) ON DELETE RESTRICT
    """)

    create(
      unique_index(:agent_uninstall_intents, [:organization_id, :agent_id, :action],
        where: "state = 'pending'",
        name: :agent_uninstall_intents_one_pending_uidx
      )
    )

    create(
      unique_index(
        :agent_uninstall_intents,
        [:organization_id, :agent_id, :action, :idempotency_key_sha256],
        where: "idempotency_key_sha256 IS NOT NULL",
        name: :agent_uninstall_intents_idempotency_uidx
      )
    )

    create(
      unique_index(:agent_uninstall_intents, [:organization_id, :nonce_sha256],
        where: "nonce_sha256 IS NOT NULL",
        name: :agent_uninstall_intents_nonce_uidx
      )
    )

    create(index(:agent_uninstall_intents, [:organization_id, :agent_id, :issued_at]))
    create(index(:agent_uninstall_intents, [:expires_at]))

    execute("""
    ALTER TABLE agent_uninstall_intents
      ADD CONSTRAINT agent_uninstall_intents_action_check
        CHECK (action = 'agent_uninstall'),
      ADD CONSTRAINT agent_uninstall_intents_reason_check
        CHECK (reason IN ('operator_requested', 'device_retirement', 'incident_response', 'agent_replacement')),
      ADD CONSTRAINT agent_uninstall_intents_ttl_check
        CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'),
      ADD CONSTRAINT agent_uninstall_intents_digest_sizes_check
        CHECK (
          (idempotency_key_sha256 IS NULL OR octet_length(idempotency_key_sha256) = 32) AND
          (nonce_sha256 IS NULL OR octet_length(nonce_sha256) = 32)
        ),
      ADD CONSTRAINT agent_uninstall_intents_state_check
        CHECK (
          (state = 'pending' AND nonce_sha256 IS NULL AND verifier_version IS NULL AND
            platform IS NULL AND consumer IS NULL AND token_generation IS NULL AND
            consumed_at IS NULL AND superseded_at IS NULL)
          OR
          (state = 'superseded' AND nonce_sha256 IS NULL AND verifier_version IS NULL AND
            platform IS NULL AND consumer IS NULL AND token_generation IS NULL AND
            consumed_at IS NULL AND superseded_at IS NOT NULL AND
            superseded_at >= issued_at)
          OR
          (state = 'consumed' AND nonce_sha256 IS NOT NULL AND
            verifier_version = 'uninstall_intent_v1' AND
            platform IN ('windows', 'linux', 'macos') AND
            consumer IN ('native_cli', 'windows_msi') AND
            token_generation > 0 AND consumed_at IS NOT NULL AND
            consumed_at >= issued_at AND consumed_at <= expires_at AND
            superseded_at IS NULL)
        )
    """)

    execute("ALTER TABLE agent_uninstall_intents ENABLE ROW LEVEL SECURITY")
    execute("ALTER TABLE agent_uninstall_intents FORCE ROW LEVEL SECURITY")

    execute("""
    CREATE POLICY agent_uninstall_intents_tenant_isolation
      ON agent_uninstall_intents
      FOR ALL
      USING (
        organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
      )
      WITH CHECK (
        organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
      )
    """)

    execute("""
    CREATE FUNCTION enforce_agent_uninstall_intent_transition()
    RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
    AS $$
    BEGIN
      IF NEW.id IS DISTINCT FROM OLD.id OR
         NEW.organization_id IS DISTINCT FROM OLD.organization_id OR
         NEW.agent_id IS DISTINCT FROM OLD.agent_id OR
         NEW.issued_by_user_id IS DISTINCT FROM OLD.issued_by_user_id OR
         NEW.action IS DISTINCT FROM OLD.action OR
         NEW.reason IS DISTINCT FROM OLD.reason OR
         NEW.idempotency_key_sha256 IS DISTINCT FROM OLD.idempotency_key_sha256 OR
         NEW.issued_at IS DISTINCT FROM OLD.issued_at OR
         NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
         NEW.inserted_at IS DISTINCT FROM OLD.inserted_at THEN
        RAISE EXCEPTION 'immutable agent uninstall intent material changed'
          USING ERRCODE = '23514';
      END IF;

      IF NOT (
        (OLD.state = 'pending' AND NEW.state IN ('consumed', 'superseded')) OR
        (OLD.state IN ('consumed', 'superseded') AND NEW.state = OLD.state AND
          to_jsonb(NEW) - 'updated_at' = to_jsonb(OLD) - 'updated_at')
      ) THEN
        RAISE EXCEPTION 'forbidden agent uninstall intent state transition'
          USING ERRCODE = '23514';
      END IF;

      RETURN NEW;
    END;
    $$
    """)

    execute("""
    CREATE TRIGGER agent_uninstall_intents_transition_guard
      BEFORE UPDATE ON agent_uninstall_intents
      FOR EACH ROW EXECUTE FUNCTION enforce_agent_uninstall_intent_transition()
    """)
  end

  def down do
    drop(table(:agent_uninstall_intents))
    execute("DROP FUNCTION enforce_agent_uninstall_intent_transition()")
    drop(index(:users, [:id, :organization_id], name: :users_id_organization_uidx))
  end
end
