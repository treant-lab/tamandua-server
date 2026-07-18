defmodule TamanduaServer.Repo.Migrations.CreatePersistentUserSessions do
  use Ecto.Migration

  def up do
    alter table(:users) do
      add(:auth_epoch, :bigint, null: false, default: 0)
    end

    execute("""
    CREATE FUNCTION tamandua_bump_user_auth_epoch()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      IF NEW.password_hash IS DISTINCT FROM OLD.password_hash
         OR NEW.mfa_secret IS DISTINCT FROM OLD.mfa_secret
         OR NEW.mfa_enabled IS DISTINCT FROM OLD.mfa_enabled
         OR NEW.is_active IS DISTINCT FROM OLD.is_active
         OR NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
        NEW.auth_epoch := OLD.auth_epoch + 1;
      ELSE
        NEW.auth_epoch := OLD.auth_epoch;
      END IF;
      RETURN NEW;
    END;
    $$
    """)

    execute("""
    CREATE TRIGGER users_auth_epoch_monotonic
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION tamandua_bump_user_auth_epoch()
    """)

    create(unique_index(:users, [:id, :organization_id], name: :users_id_organization_id_unique))

    create table(:persistent_user_sessions, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:user_id, :binary_id, null: false)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:token_digest, :binary, null: false)
      add(:binding_digest, :binary, null: false)
      add(:auth_epoch, :bigint, null: false)
      add(:auth_method, :string, null: false)
      add(:authenticated_at, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:revoked_at, :utc_datetime_usec)
      add(:last_seen_at, :utc_datetime_usec, null: false)
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create(unique_index(:persistent_user_sessions, [:token_digest]))
    create(index(:persistent_user_sessions, [:organization_id, :user_id]))
    create(index(:persistent_user_sessions, [:expires_at], where: "revoked_at IS NULL"))

    create(
      constraint(:persistent_user_sessions, :persistent_session_token_digest_size,
        check: "octet_length(token_digest) = 32"
      )
    )

    create(
      constraint(:persistent_user_sessions, :persistent_session_binding_digest_size,
        check: "octet_length(binding_digest) = 32"
      )
    )

    create(
      constraint(:persistent_user_sessions, :persistent_session_distinct_digests,
        check: "token_digest <> binding_digest"
      )
    )

    create(
      constraint(:persistent_user_sessions, :persistent_session_auth_epoch_nonnegative,
        check: "auth_epoch >= 0"
      )
    )

    create(
      constraint(:persistent_user_sessions, :persistent_session_auth_method,
        check: "auth_method IN ('password', 'wallet', 'mfa')"
      )
    )

    create(
      constraint(:persistent_user_sessions, :persistent_session_chronology,
        check:
          "authenticated_at <= last_seen_at AND last_seen_at < expires_at AND " <>
            "expires_at <= authenticated_at + interval '7 days' AND " <>
            "(revoked_at IS NULL OR authenticated_at <= revoked_at)"
      )
    )

    execute("""
    ALTER TABLE persistent_user_sessions
    ADD CONSTRAINT persistent_user_sessions_user_tenant_fkey
    FOREIGN KEY (user_id, organization_id)
    REFERENCES users(id, organization_id)
    ON DELETE CASCADE
    """)
  end

  def down do
    execute("""
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM persistent_user_sessions LIMIT 1) THEN
        RAISE EXCEPTION 'refusing to drop non-empty persistent_user_sessions';
      END IF;
    END;
    $$
    """)

    drop(table(:persistent_user_sessions))
    drop(index(:users, [:id, :organization_id], name: :users_id_organization_id_unique))

    execute("DROP TRIGGER users_auth_epoch_monotonic ON users")
    execute("DROP FUNCTION tamandua_bump_user_auth_epoch()")

    alter table(:users) do
      remove(:auth_epoch)
    end
  end
end
