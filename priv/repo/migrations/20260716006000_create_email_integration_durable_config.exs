defmodule TamanduaServer.Repo.Migrations.CreateEmailIntegrationDurableConfig do
  use Ecto.Migration

  def up do
    create table(:email_integration_config_heads, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:provider, :string, null: false)
      add(:committed_revision, :bigint, null: false, default: 0)
      add(:pending_revision, :bigint)
      add(:pending_operation_id, :binary_id)
      add(:pending_owner_id, :string)
      add(:pending_expires_at, :utc_datetime_usec)
      add(:applied_revision, :bigint, null: false, default: 0)
      add(:apply_status, :string, null: false, default: "never_applied")
      add(:last_apply_error_code, :string)
      add(:last_applied_at, :utc_datetime_usec)

      timestamps(type: :utc_datetime_usec)
    end

    create(
      unique_index(:email_integration_config_heads, [:organization_id, :provider],
        name: :email_integration_config_heads_org_provider_idx
      )
    )

    create(
      unique_index(:email_integration_config_heads, [:id, :organization_id, :provider],
        name: :email_integration_config_heads_identity_scope_idx
      )
    )

    create(
      unique_index(
        :email_integration_config_heads,
        [:organization_id, :provider, :pending_operation_id],
        where: "pending_operation_id IS NOT NULL",
        name: :email_integration_config_heads_pending_operation_idx
      )
    )

    create(index(:email_integration_config_heads, [:pending_expires_at]))
    create(index(:email_integration_config_heads, [:apply_status, :updated_at]))

    create(
      constraint(:email_integration_config_heads, :email_config_heads_provider_check,
        check: "provider IN ('microsoft365', 'google_workspace')"
      )
    )

    create(
      constraint(:email_integration_config_heads, :email_config_heads_revisions_check,
        check:
          "committed_revision >= 0 AND applied_revision >= 0 AND applied_revision <= committed_revision"
      )
    )

    create(
      constraint(:email_integration_config_heads, :email_config_heads_pending_complete_check,
        check: """
        (pending_revision IS NULL AND pending_operation_id IS NULL AND
         pending_owner_id IS NULL AND pending_expires_at IS NULL) OR
        (pending_revision > committed_revision AND pending_operation_id IS NOT NULL AND
         pending_owner_id IS NOT NULL AND pending_expires_at IS NOT NULL)
        """
      )
    )

    create(
      constraint(:email_integration_config_heads, :email_config_heads_apply_status_check,
        check: "apply_status IN ('never_applied', 'pending', 'applied', 'degraded')"
      )
    )

    create table(:email_integration_config_versions, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :head_id,
        :binary_id,
        null: false
      )

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:provider, :string, null: false)
      add(:revision, :bigint, null: false)
      add(:base_revision, :bigint, null: false)
      add(:status, :string, null: false, default: "pending")
      add(:public_config, :map, null: false, default: %{})
      add(:secret_ciphertext, :text, null: false)
      add(:vault_key_name, :string, null: false)
      add(:vault_ciphertext_version, :integer, null: false)
      add(:secret_schema_version, :integer, null: false, default: 2)
      add(:operation_id, :binary_id, null: false)
      add(:created_by, :string, null: false)
      add(:lease_expires_at, :utc_datetime_usec, null: false)
      add(:request_fingerprint, :binary, null: false)
      add(:request_fingerprint_key_version, :integer, null: false)
      add(:ciphertext_sha256, :binary, null: false)
      add(:committed_at, :utc_datetime_usec)
      add(:aborted_at, :utc_datetime_usec)
      add(:abort_reason_code, :string)

      timestamps(type: :utc_datetime_usec)
    end

    create(
      unique_index(
        :email_integration_config_versions,
        [:organization_id, :provider, :revision],
        name: :email_integration_config_versions_org_provider_revision_idx
      )
    )

    create(
      unique_index(
        :email_integration_config_versions,
        [:organization_id, :provider, :operation_id],
        name: :email_integration_config_versions_operation_idx
      )
    )

    create(index(:email_integration_config_versions, [:head_id, :status, :revision]))

    execute("""
    ALTER TABLE email_integration_config_versions
    ADD CONSTRAINT email_config_versions_head_scope_fkey
    FOREIGN KEY (head_id, organization_id, provider)
    REFERENCES email_integration_config_heads (id, organization_id, provider)
    ON DELETE RESTRICT
    """)

    execute("""
    CREATE UNIQUE INDEX email_integration_config_versions_one_pending_idx
    ON email_integration_config_versions (organization_id, provider)
    WHERE status = 'pending'
    """)

    execute("""
    CREATE UNIQUE INDEX email_integration_config_versions_one_committed_idx
    ON email_integration_config_versions (organization_id, provider)
    WHERE status = 'committed'
    """)

    create(
      constraint(:email_integration_config_versions, :email_config_versions_provider_check,
        check: "provider IN ('microsoft365', 'google_workspace')"
      )
    )

    create(
      constraint(:email_integration_config_versions, :email_config_versions_revision_check,
        check: "base_revision >= 0 AND revision > base_revision"
      )
    )

    create(
      constraint(:email_integration_config_versions, :email_config_versions_idempotency_check,
        check: """
        octet_length(request_fingerprint) = 32 AND
        request_fingerprint_key_version > 0 AND
        octet_length(ciphertext_sha256) = 32 AND
        lease_expires_at > inserted_at
        """
      )
    )

    create(
      constraint(:email_integration_config_versions, :email_config_versions_status_check,
        check: "status IN ('pending', 'committed', 'superseded', 'aborted')"
      )
    )

    create(
      constraint(:email_integration_config_versions, :email_config_versions_public_object_check,
        check:
          "jsonb_typeof(public_config) = 'object' AND octet_length(public_config::text) <= 16384"
      )
    )

    create(
      constraint(
        :email_integration_config_versions,
        :email_config_versions_public_no_secrets_check,
        check: """
        public_config::text !~*
        '\"(client[-_]?secret|access[-_]?token|service[-_]?account[-_]?key|private[-_]?key|private[-_]?key[-_]?id|refresh[-_]?token|password|token)\"[[:space:]]*:'
        """
      )
    )

    create(
      constraint(
        :email_integration_config_versions,
        :email_config_versions_public_contract_check,
        check: """
        (provider = 'microsoft365' AND
         public_config ?& ARRAY['tenant_id', 'client_id', 'poll_interval_ms', 'enabled'] AND
         (public_config - ARRAY['tenant_id', 'client_id', 'poll_interval_ms', 'enabled']) = '{}'::jsonb AND
         jsonb_typeof(public_config->'tenant_id') = 'string' AND
         octet_length(public_config->>'tenant_id') BETWEEN 1 AND 512 AND
         btrim(public_config->>'tenant_id') <> '' AND
         btrim(public_config->>'tenant_id') = public_config->>'tenant_id' AND
         jsonb_typeof(public_config->'client_id') = 'string' AND
         octet_length(public_config->>'client_id') BETWEEN 1 AND 512 AND
         btrim(public_config->>'client_id') <> '' AND
         btrim(public_config->>'client_id') = public_config->>'client_id' AND
         jsonb_typeof(public_config->'poll_interval_ms') = 'number' AND
         CASE WHEN public_config->>'poll_interval_ms' ~ '^[0-9]+$'
              THEN (public_config->>'poll_interval_ms')::bigint BETWEEN 10000 AND 86400000
              ELSE FALSE END AND
         jsonb_typeof(public_config->'enabled') = 'boolean') OR
        (provider = 'google_workspace' AND
         public_config ?& ARRAY['admin_email', 'poll_interval_ms', 'enabled'] AND
         (public_config - ARRAY['admin_email', 'poll_interval_ms', 'enabled']) = '{}'::jsonb AND
         jsonb_typeof(public_config->'admin_email') = 'string' AND
         octet_length(public_config->>'admin_email') BETWEEN 3 AND 320 AND
         public_config->>'admin_email' ~ '^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$' AND
         jsonb_typeof(public_config->'poll_interval_ms') = 'number' AND
         CASE WHEN public_config->>'poll_interval_ms' ~ '^[0-9]+$'
              THEN (public_config->>'poll_interval_ms')::bigint BETWEEN 10000 AND 86400000
              ELSE FALSE END AND
         jsonb_typeof(public_config->'enabled') = 'boolean')
        """
      )
    )

    create(
      constraint(
        :email_integration_config_versions,
        :email_config_versions_vault_ciphertext_check,
        check:
          "secret_ciphertext LIKE 'vault:v%:%' AND octet_length(secret_ciphertext) <= 2097152 AND vault_ciphertext_version > 0 AND secret_schema_version = 2"
      )
    )

    create(
      constraint(:email_integration_config_versions, :email_config_versions_lifecycle_check,
        check: """
        (status = 'pending' AND committed_at IS NULL AND aborted_at IS NULL AND
         abort_reason_code IS NULL) OR
        (status = 'committed' AND committed_at IS NOT NULL AND aborted_at IS NULL AND
         abort_reason_code IS NULL) OR
        (status = 'superseded' AND committed_at IS NOT NULL AND aborted_at IS NULL AND
         abort_reason_code IS NULL) OR
        (status = 'aborted' AND committed_at IS NULL AND aborted_at IS NOT NULL AND
         abort_reason_code ~ '^[a-z0-9_:-]{1,100}$')
        """
      )
    )

    execute("""
    CREATE FUNCTION prevent_email_config_version_content_mutation() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
    AS $$
    DECLARE
      transition_at timestamp with time zone;
    BEGIN
      IF TG_OP = 'INSERT' THEN
        IF NEW.status IS DISTINCT FROM 'pending' OR
           NEW.committed_at IS NOT NULL OR
           NEW.aborted_at IS NOT NULL OR
           NEW.abort_reason_code IS NOT NULL THEN
          RAISE EXCEPTION 'email integration config versions must be inserted pending';
        END IF;

        transition_at := pg_catalog.clock_timestamp();
        NEW.inserted_at := transition_at;
        NEW.updated_at := transition_at;
        RETURN NEW;
      END IF;

      IF NEW.id IS DISTINCT FROM OLD.id OR
         NEW.head_id IS DISTINCT FROM OLD.head_id OR
         NEW.organization_id IS DISTINCT FROM OLD.organization_id OR
         NEW.provider IS DISTINCT FROM OLD.provider OR
         NEW.revision IS DISTINCT FROM OLD.revision OR
         NEW.base_revision IS DISTINCT FROM OLD.base_revision OR
         NEW.public_config IS DISTINCT FROM OLD.public_config OR
         NEW.secret_ciphertext IS DISTINCT FROM OLD.secret_ciphertext OR
         NEW.vault_key_name IS DISTINCT FROM OLD.vault_key_name OR
         NEW.vault_ciphertext_version IS DISTINCT FROM OLD.vault_ciphertext_version OR
         NEW.secret_schema_version IS DISTINCT FROM OLD.secret_schema_version OR
         NEW.operation_id IS DISTINCT FROM OLD.operation_id OR
         NEW.created_by IS DISTINCT FROM OLD.created_by OR
         NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at OR
         NEW.request_fingerprint IS DISTINCT FROM OLD.request_fingerprint OR
         NEW.request_fingerprint_key_version IS DISTINCT FROM OLD.request_fingerprint_key_version OR
         NEW.ciphertext_sha256 IS DISTINCT FROM OLD.ciphertext_sha256 OR
         NEW.inserted_at IS DISTINCT FROM OLD.inserted_at THEN
        RAISE EXCEPTION 'email integration config version content is immutable';
      END IF;

      IF OLD.status = 'pending' AND NEW.status = 'committed' THEN
        transition_at := pg_catalog.clock_timestamp();
        NEW.committed_at := transition_at;
        NEW.aborted_at := NULL;
        NEW.abort_reason_code := NULL;
        NEW.updated_at := transition_at;

        IF NEW.committed_at < OLD.inserted_at THEN
          RAISE EXCEPTION 'committed timestamp precedes insertion';
        END IF;
      ELSIF OLD.status = 'pending' AND NEW.status = 'aborted' THEN
        IF NEW.abort_reason_code IS NULL OR
           NEW.abort_reason_code !~ '^[a-z0-9_:-]{1,100}$' THEN
          RAISE EXCEPTION 'invalid email integration config abort reason';
        END IF;

        transition_at := pg_catalog.clock_timestamp();
        NEW.committed_at := NULL;
        NEW.aborted_at := transition_at;
        NEW.updated_at := transition_at;

        IF NEW.aborted_at < OLD.inserted_at THEN
          RAISE EXCEPTION 'aborted timestamp precedes insertion';
        END IF;
      ELSIF OLD.status = 'committed' AND NEW.status = 'superseded' THEN
        transition_at := pg_catalog.clock_timestamp();
        NEW.committed_at := OLD.committed_at;
        NEW.aborted_at := NULL;
        NEW.abort_reason_code := NULL;
        NEW.updated_at := transition_at;
      ELSE
        RAISE EXCEPTION 'invalid email integration config version lifecycle transition';
      END IF;

      RETURN NEW;
    END;
    $$
    """)

    execute("REVOKE ALL ON FUNCTION prevent_email_config_version_content_mutation() FROM PUBLIC")

    execute("""
    CREATE TRIGGER email_config_version_content_immutable
    BEFORE INSERT OR UPDATE ON email_integration_config_versions
    FOR EACH ROW EXECUTE FUNCTION prevent_email_config_version_content_mutation()
    """)

    execute("""
    CREATE FUNCTION prevent_email_config_version_destruction() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
    AS $$
    BEGIN
      RAISE EXCEPTION 'email integration config versions cannot be deleted or truncated';
    END;
    $$
    """)

    execute("REVOKE ALL ON FUNCTION prevent_email_config_version_destruction() FROM PUBLIC")

    execute("""
    CREATE TRIGGER email_config_version_delete_denied
    BEFORE DELETE ON email_integration_config_versions
    FOR EACH ROW EXECUTE FUNCTION prevent_email_config_version_destruction()
    """)

    execute("""
    CREATE TRIGGER email_config_version_truncate_denied
    BEFORE TRUNCATE ON email_integration_config_versions
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_email_config_version_destruction()
    """)

    execute("REVOKE DELETE, TRUNCATE ON email_integration_config_versions FROM PUBLIC")

    execute("""
    CREATE FUNCTION enforce_email_config_pending_consistency() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
    AS $$
    DECLARE
      pending_head public.email_integration_config_heads%ROWTYPE;
      current_version_status text;
    BEGIN
      IF TG_TABLE_NAME = 'email_integration_config_heads' THEN
        SELECT * INTO pending_head
        FROM public.email_integration_config_heads
        WHERE id = NEW.id;
      ELSE
        SELECT status INTO current_version_status
        FROM public.email_integration_config_versions
        WHERE id = NEW.id;

        SELECT * INTO pending_head
        FROM public.email_integration_config_heads
        WHERE organization_id = NEW.organization_id
          AND provider = NEW.provider;

        IF current_version_status = 'pending' AND
           (pending_head.id IS NULL OR
            pending_head.pending_operation_id IS DISTINCT FROM NEW.operation_id) THEN
          RAISE EXCEPTION 'pending email integration ledger version has no matching head';
        END IF;
      END IF;

      IF TG_TABLE_NAME = 'email_integration_config_heads' AND
         pending_head.pending_operation_id IS NULL AND EXISTS (
        SELECT 1 FROM public.email_integration_config_versions version
        WHERE version.organization_id = pending_head.organization_id
          AND version.provider = pending_head.provider
          AND version.status = 'pending'
      ) THEN
        RAISE EXCEPTION 'pending email integration ledger version has no matching head';
      END IF;

      IF pending_head.pending_operation_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM public.email_integration_config_versions version
        WHERE version.organization_id = pending_head.organization_id
          AND version.provider = pending_head.provider
          AND version.operation_id = pending_head.pending_operation_id
          AND version.revision = pending_head.pending_revision
          AND version.created_by = pending_head.pending_owner_id
          AND version.lease_expires_at = pending_head.pending_expires_at
          AND version.status = 'pending'
      ) THEN
        RAISE EXCEPTION 'email integration pending head is inconsistent with ledger';
      END IF;

      IF pending_head.id IS NOT NULL AND pending_head.committed_revision = 0 AND EXISTS (
        SELECT 1 FROM public.email_integration_config_versions version
        WHERE version.organization_id = pending_head.organization_id
          AND version.provider = pending_head.provider
          AND version.status = 'committed'
      ) THEN
        RAISE EXCEPTION 'committed email integration ledger version has no matching head';
      END IF;

      IF pending_head.id IS NOT NULL AND pending_head.committed_revision > 0 AND NOT EXISTS (
        SELECT 1 FROM public.email_integration_config_versions version
        WHERE version.head_id = pending_head.id
          AND version.organization_id = pending_head.organization_id
          AND version.provider = pending_head.provider
          AND version.revision = pending_head.committed_revision
          AND version.status = 'committed'
      ) THEN
        RAISE EXCEPTION 'email integration committed head is inconsistent with ledger';
      END IF;

      IF TG_TABLE_NAME = 'email_integration_config_versions' AND
         current_version_status = 'committed' AND
         (pending_head.id IS NULL OR
          pending_head.committed_revision IS DISTINCT FROM NEW.revision) THEN
        RAISE EXCEPTION 'committed email integration ledger version has no matching head';
      END IF;

      IF TG_TABLE_NAME = 'email_integration_config_versions' AND
         current_version_status = 'superseded' AND
         pending_head.id IS NOT NULL AND
         pending_head.committed_revision = NEW.revision THEN
        RAISE EXCEPTION 'superseded email integration ledger version remains referenced';
      END IF;

      RETURN NULL;
    END;
    $$
    """)

    execute("REVOKE ALL ON FUNCTION enforce_email_config_pending_consistency() FROM PUBLIC")

    execute("""
    CREATE CONSTRAINT TRIGGER email_config_head_pending_consistency
    AFTER INSERT OR UPDATE ON email_integration_config_heads
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION enforce_email_config_pending_consistency()
    """)

    execute("""
    CREATE CONSTRAINT TRIGGER email_config_version_pending_consistency
    AFTER INSERT OR UPDATE ON email_integration_config_versions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION enforce_email_config_pending_consistency()
    """)

    execute("""
    CREATE FUNCTION notify_email_runtime_config_head() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
    AS $$
    BEGIN
      PERFORM pg_catalog.pg_notify('tamandua_email_runtime_config', 'changed');
      RETURN NULL;
    END;
    $$
    """)

    execute("REVOKE ALL ON FUNCTION notify_email_runtime_config_head() FROM PUBLIC")

    execute("""
    CREATE TRIGGER email_runtime_config_head_notify
    AFTER UPDATE OF committed_revision, applied_revision, apply_status
    ON email_integration_config_heads
    FOR EACH ROW
    WHEN (OLD.committed_revision IS DISTINCT FROM NEW.committed_revision OR
          OLD.applied_revision IS DISTINCT FROM NEW.applied_revision OR
          OLD.apply_status IS DISTINCT FROM NEW.apply_status)
    EXECUTE FUNCTION notify_email_runtime_config_head()
    """)

    for table <- ["email_integration_config_heads", "email_integration_config_versions"] do
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
    for table <- ["email_integration_config_versions", "email_integration_config_heads"] do
      execute("DROP POLICY IF EXISTS #{table}_organization_isolation ON #{table}")
      execute("ALTER TABLE #{table} NO FORCE ROW LEVEL SECURITY")
      execute("ALTER TABLE #{table} DISABLE ROW LEVEL SECURITY")
    end

    execute(
      "DROP TRIGGER IF EXISTS email_runtime_config_head_notify ON email_integration_config_heads"
    )

    execute("DROP FUNCTION IF EXISTS notify_email_runtime_config_head()")

    execute(
      "DROP TRIGGER IF EXISTS email_config_version_content_immutable ON email_integration_config_versions"
    )

    execute(
      "DROP TRIGGER IF EXISTS email_config_version_pending_consistency ON email_integration_config_versions"
    )

    execute(
      "DROP TRIGGER IF EXISTS email_config_head_pending_consistency ON email_integration_config_heads"
    )

    execute(
      "DROP TRIGGER IF EXISTS email_config_version_delete_denied ON email_integration_config_versions"
    )

    execute(
      "DROP TRIGGER IF EXISTS email_config_version_truncate_denied ON email_integration_config_versions"
    )

    execute("DROP FUNCTION IF EXISTS prevent_email_config_version_destruction()")
    execute("DROP FUNCTION IF EXISTS enforce_email_config_pending_consistency()")
    execute("DROP FUNCTION IF EXISTS prevent_email_config_version_content_mutation()")
    drop(table(:email_integration_config_versions))
    drop(table(:email_integration_config_heads))
  end
end
