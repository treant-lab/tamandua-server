defmodule TamanduaServer.Repo.Migrations.CreateEnrollmentCSRIntents do
  use Ecto.Migration

  def up do
    create(
      unique_index(:installation_tokens, [:id, :organization_id],
        name: :installation_tokens_id_organization_uidx
      )
    )

    create table(:enrollment_csr_intents, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:organization_id, :binary_id, null: false)
      add(:installation_token_id, :binary_id, null: false)
      add(:state, :string, null: false)

      add(:fingerprint_key_version, :smallint, null: false)
      add(:idempotency_key_hash, :binary, null: false)
      add(:request_fingerprint, :binary, null: false)
      add(:csr_der, :binary, null: false)
      add(:csr_sha256, :binary, null: false)
      add(:public_key_spki_der, :binary, null: false)
      add(:public_key_sha256, :binary, null: false)
      add(:agent_info_canonical, :binary, null: false)

      add(:reserved_agent_id, :binary_id, null: false)
      add(:signer_request_id, :binary_id)
      add(:committed_agent_id, :binary_id)
      add(:capacity_slot, :integer, null: false)
      add(:fencing_token, :bigint, null: false)
      add(:lease_owner_hash, :binary)
      add(:lease_expires_at, :utc_datetime_usec)
      add(:attempt_count, :smallint, null: false, default: 0)

      add(:signer_receipt_hash, :binary)
      add(:certificate_sha256, :binary)
      add(:certificate_response, :binary)
      add(:recovery_code, :string)
      add(:last_error_code, :string)

      add(:reserved_at, :utc_datetime_usec, null: false)
      add(:signing_started_at, :utc_datetime_usec)
      add(:committed_at, :utc_datetime_usec)
      add(:failed_at, :utc_datetime_usec)
      add(:reconciliation_required_at, :utc_datetime_usec)
      add(:redacted_at, :utc_datetime_usec)
      add(:expires_at, :utc_datetime_usec, null: false)

      timestamps(type: :utc_datetime_usec)
    end

    execute("""
    ALTER TABLE enrollment_csr_intents
      ADD CONSTRAINT enrollment_csr_intents_organization_fkey
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
      ADD CONSTRAINT enrollment_csr_intents_installation_token_tenant_fkey
        FOREIGN KEY (installation_token_id, organization_id)
        REFERENCES installation_tokens(id, organization_id) ON DELETE RESTRICT
    """)

    create(
      unique_index(:enrollment_csr_intents, [:organization_id, :idempotency_key_hash],
        name: :enrollment_csr_intents_org_idempotency_uidx
      )
    )

    create(
      unique_index(:enrollment_csr_intents, [:signer_request_id],
        where: "signer_request_id IS NOT NULL",
        name: :enrollment_csr_intents_signer_request_uidx
      )
    )

    create(
      unique_index(:enrollment_csr_intents, [:organization_id, :capacity_slot],
        where: "state IN ('reserved', 'signing', 'reconciliation_required')",
        name: :enrollment_csr_intents_active_capacity_uidx
      )
    )

    create(index(:enrollment_csr_intents, [:organization_id, :state, :expires_at]))
    create(index(:enrollment_csr_intents, [:organization_id, :reserved_agent_id]))

    execute("""
    ALTER TABLE enrollment_csr_intents
      ADD CONSTRAINT enrollment_csr_intents_state_check
        CHECK (state IN ('reserved', 'signing', 'committed', 'failed', 'reconciliation_required')),
      ADD CONSTRAINT enrollment_csr_intents_key_version_check
        CHECK (fingerprint_key_version BETWEEN 1 AND 32767),
      ADD CONSTRAINT enrollment_csr_intents_hash_sizes_check
        CHECK (
          octet_length(idempotency_key_hash) = 32 AND
          octet_length(request_fingerprint) = 32 AND
          octet_length(csr_sha256) = 32 AND
          octet_length(public_key_sha256) = 32 AND
          (lease_owner_hash IS NULL OR octet_length(lease_owner_hash) = 32) AND
          (signer_receipt_hash IS NULL OR octet_length(signer_receipt_hash) = 32) AND
          (certificate_sha256 IS NULL OR octet_length(certificate_sha256) = 32)
        ),
      ADD CONSTRAINT enrollment_csr_intents_payload_sizes_check
        CHECK (
          octet_length(csr_der) BETWEEN 1 AND 32768 AND
          octet_length(public_key_spki_der) BETWEEN 1 AND 2048 AND
          octet_length(agent_info_canonical) BETWEEN 2 AND 16384 AND
          (certificate_response IS NULL OR octet_length(certificate_response) BETWEEN 1 AND 131072)
        ),
      ADD CONSTRAINT enrollment_csr_intents_capacity_fence_attempt_check
        CHECK (capacity_slot >= 0 AND fencing_token > 0 AND attempt_count BETWEEN 0 AND 10),
      ADD CONSTRAINT enrollment_csr_intents_time_order_check
        CHECK (expires_at > reserved_at),
      ADD CONSTRAINT enrollment_csr_intents_code_sizes_check
        CHECK (
          (recovery_code IS NULL OR char_length(recovery_code) BETWEEN 1 AND 64) AND
          (last_error_code IS NULL OR char_length(last_error_code) BETWEEN 1 AND 64)
        ),
      ADD CONSTRAINT enrollment_csr_intents_lease_pair_check
        CHECK ((lease_owner_hash IS NULL) = (lease_expires_at IS NULL)),
      ADD CONSTRAINT enrollment_csr_intents_redaction_check
        CHECK (
          redacted_at IS NULL OR (
            csr_der = decode('00', 'hex') AND
            public_key_spki_der = decode('00', 'hex') AND
            agent_info_canonical = convert_to('{}', 'UTF8') AND
            (
              (state = 'committed' AND certificate_response = decode('00', 'hex')) OR
              (state = 'failed' AND certificate_response IS NULL)
            )
          )
        ),
      ADD CONSTRAINT enrollment_csr_intents_state_fields_check
        CHECK (
          (state = 'reserved' AND signer_request_id IS NULL AND committed_agent_id IS NULL AND
            lease_owner_hash IS NULL AND attempt_count = 0 AND signing_started_at IS NULL AND
            committed_at IS NULL AND failed_at IS NULL AND reconciliation_required_at IS NULL AND
            signer_receipt_hash IS NULL AND certificate_sha256 IS NULL AND certificate_response IS NULL AND
            recovery_code IS NULL AND last_error_code IS NULL AND redacted_at IS NULL)
          OR
          (state = 'signing' AND signer_request_id IS NOT NULL AND committed_agent_id IS NULL AND
            lease_owner_hash IS NOT NULL AND attempt_count BETWEEN 1 AND 10 AND signing_started_at IS NOT NULL AND
            signing_started_at >= reserved_at AND lease_expires_at > signing_started_at AND
            lease_expires_at <= expires_at AND
            committed_at IS NULL AND failed_at IS NULL AND reconciliation_required_at IS NULL AND
            signer_receipt_hash IS NULL AND certificate_sha256 IS NULL AND certificate_response IS NULL AND
            recovery_code IS NULL AND last_error_code IS NULL AND redacted_at IS NULL)
          OR
          (state = 'committed' AND signer_request_id IS NOT NULL AND committed_agent_id = reserved_agent_id AND
            lease_owner_hash IS NULL AND attempt_count BETWEEN 1 AND 10 AND signing_started_at IS NOT NULL AND
            committed_at IS NOT NULL AND committed_at >= signing_started_at AND failed_at IS NULL AND
            reconciliation_required_at IS NULL AND
            signer_receipt_hash IS NOT NULL AND certificate_sha256 IS NOT NULL AND certificate_response IS NOT NULL AND
            recovery_code IS NULL AND last_error_code IS NULL AND
            (redacted_at IS NULL OR redacted_at >= committed_at))
          OR
          (state = 'failed' AND committed_agent_id IS NULL AND lease_owner_hash IS NULL AND
            committed_at IS NULL AND failed_at IS NOT NULL AND failed_at >= reserved_at AND
            (signing_started_at IS NULL OR failed_at >= signing_started_at) AND
            reconciliation_required_at IS NULL AND
            signer_receipt_hash IS NULL AND certificate_sha256 IS NULL AND certificate_response IS NULL AND
            recovery_code IS NULL AND last_error_code IS NOT NULL AND
            (redacted_at IS NULL OR redacted_at >= failed_at))
          OR
          (state = 'reconciliation_required' AND signer_request_id IS NOT NULL AND committed_agent_id IS NULL AND
            lease_owner_hash IS NULL AND attempt_count BETWEEN 1 AND 10 AND signing_started_at IS NOT NULL AND
            committed_at IS NULL AND failed_at IS NULL AND reconciliation_required_at IS NOT NULL AND
            reconciliation_required_at >= signing_started_at AND certificate_response IS NULL AND
            recovery_code IS NOT NULL AND last_error_code IS NULL AND redacted_at IS NULL)
        )
    """)

    execute("ALTER TABLE enrollment_csr_intents ENABLE ROW LEVEL SECURITY")
    execute("ALTER TABLE enrollment_csr_intents FORCE ROW LEVEL SECURITY")

    execute("""
    CREATE FUNCTION enforce_enrollment_csr_intent_transition()
    RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
    AS $$
    BEGIN
      IF NEW.id IS DISTINCT FROM OLD.id OR
         NEW.organization_id IS DISTINCT FROM OLD.organization_id OR
         NEW.installation_token_id IS DISTINCT FROM OLD.installation_token_id OR
         NEW.fingerprint_key_version IS DISTINCT FROM OLD.fingerprint_key_version OR
         NEW.idempotency_key_hash IS DISTINCT FROM OLD.idempotency_key_hash OR
         NEW.request_fingerprint IS DISTINCT FROM OLD.request_fingerprint OR
         NEW.csr_sha256 IS DISTINCT FROM OLD.csr_sha256 OR
         NEW.public_key_sha256 IS DISTINCT FROM OLD.public_key_sha256 OR
         NEW.reserved_agent_id IS DISTINCT FROM OLD.reserved_agent_id OR
         NEW.capacity_slot IS DISTINCT FROM OLD.capacity_slot OR
         NEW.reserved_at IS DISTINCT FROM OLD.reserved_at OR
         NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
         NEW.inserted_at IS DISTINCT FROM OLD.inserted_at THEN
        RAISE EXCEPTION 'immutable enrollment CSR intent material changed'
          USING ERRCODE = '23514';
      END IF;

      IF (NEW.csr_der IS DISTINCT FROM OLD.csr_der OR
          NEW.public_key_spki_der IS DISTINCT FROM OLD.public_key_spki_der OR
          NEW.agent_info_canonical IS DISTINCT FROM OLD.agent_info_canonical) AND
         NOT (OLD.state IN ('committed', 'failed') AND NEW.state = OLD.state AND
           OLD.redacted_at IS NULL AND NEW.redacted_at IS NOT NULL) THEN
        RAISE EXCEPTION 'enrollment CSR intent payload changed outside terminal redaction'
          USING ERRCODE = '23514';
      END IF;

      IF (OLD.signer_request_id IS NOT NULL AND
          NEW.signer_request_id IS DISTINCT FROM OLD.signer_request_id) OR
         (OLD.signing_started_at IS NOT NULL AND
          NEW.signing_started_at IS DISTINCT FROM OLD.signing_started_at) OR
         NEW.attempt_count < OLD.attempt_count OR
         (NEW.lease_owner_hash IS DISTINCT FROM OLD.lease_owner_hash AND
          OLD.lease_owner_hash IS NOT NULL AND NEW.lease_owner_hash IS NOT NULL AND
          NEW.fencing_token <= OLD.fencing_token) THEN
        RAISE EXCEPTION 'enrollment CSR intent signer lineage regressed'
          USING ERRCODE = '23514';
      END IF;

      IF NOT (
        (OLD.state = 'reserved' AND NEW.state IN ('signing', 'failed')) OR
        (OLD.state = 'signing' AND NEW.state IN ('signing', 'committed', 'failed', 'reconciliation_required')) OR
        (OLD.state = 'reconciliation_required' AND NEW.state = 'committed') OR
        (OLD.state IN ('committed', 'failed') AND NEW.state = OLD.state AND
          OLD.redacted_at IS NULL AND NEW.redacted_at IS NOT NULL AND
          (to_jsonb(NEW) - ARRAY['csr_der', 'public_key_spki_der', 'agent_info_canonical',
            'certificate_response', 'redacted_at', 'updated_at']) =
          (to_jsonb(OLD) - ARRAY['csr_der', 'public_key_spki_der', 'agent_info_canonical',
            'certificate_response', 'redacted_at', 'updated_at']))
      ) THEN
        RAISE EXCEPTION 'forbidden enrollment CSR intent state transition'
          USING ERRCODE = '23514';
      END IF;

      IF NEW.fencing_token < OLD.fencing_token OR
         (OLD.state = 'reserved' AND NEW.state = 'signing' AND
           NEW.fencing_token <= OLD.fencing_token) OR
         (OLD.state = 'reconciliation_required' AND NEW.state = 'committed' AND
           NEW.fencing_token <= OLD.fencing_token) THEN
        RAISE EXCEPTION 'stale enrollment CSR intent fencing token'
          USING ERRCODE = '23514';
      END IF;

      RETURN NEW;
    END;
    $$
    """)

    execute("""
    CREATE TRIGGER enrollment_csr_intents_transition_guard
      BEFORE UPDATE ON enrollment_csr_intents
      FOR EACH ROW EXECUTE FUNCTION enforce_enrollment_csr_intent_transition()
    """)

    execute("""
    CREATE POLICY enrollment_csr_intents_tenant_isolation
      ON enrollment_csr_intents
      FOR ALL
      USING (
        organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
      )
      WITH CHECK (
        organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
      )
    """)
  end

  def down do
    drop(table(:enrollment_csr_intents))
    execute("DROP FUNCTION enforce_enrollment_csr_intent_transition()")

    drop(
      index(:installation_tokens, [:id, :organization_id],
        name: :installation_tokens_id_organization_uidx
      )
    )
  end
end
