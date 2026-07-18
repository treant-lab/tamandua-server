defmodule TamanduaServer.Repo.Migrations.CreatePlatformOperatorAuthority do
  use Ecto.Migration

  @capabilities "'organizations_metadata_read', 'global_threat_intel_manage', 'misp_global_read', 'misp_global_manage'"

  def up do
    create table(:platform_operator_grants, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:user_id, references(:users, type: :binary_id, on_delete: :restrict), null: false)

      add(:granted_by_user_id, references(:users, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:capabilities, {:array, :string}, null: false)
      add(:reason, :text, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:revoked_at, :utc_datetime_usec)

      add(:revoked_by_user_id, references(:users, type: :binary_id, on_delete: :restrict))
      add(:revoke_reason, :text)

      timestamps(type: :utc_datetime_usec)
    end

    create(
      constraint(:platform_operator_grants, :platform_operator_grants_no_self_grant_check,
        check: "user_id <> granted_by_user_id"
      )
    )

    create(
      constraint(:platform_operator_grants, :platform_operator_grants_capabilities_check,
        check:
          "cardinality(capabilities) > 0 AND capabilities <@ ARRAY[#{@capabilities}]::varchar[]"
      )
    )

    create(
      constraint(:platform_operator_grants, :platform_operator_grants_revocation_check,
        check:
          "(revoked_at IS NULL AND revoked_by_user_id IS NULL AND revoke_reason IS NULL) OR " <>
            "(revoked_at IS NOT NULL AND revoked_by_user_id IS NOT NULL AND revoke_reason IS NOT NULL)"
      )
    )

    create(
      index(:platform_operator_grants, [:user_id, :expires_at],
        name: :platform_operator_grants_active_lookup_idx,
        where: "revoked_at IS NULL"
      )
    )

    create table(:platform_operator_elevation_proofs, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:user_id, references(:users, type: :binary_id, on_delete: :restrict), null: false)

      add(
        :grant_id,
        references(:platform_operator_grants, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:proof_hash, :binary, null: false)
      add(:session_binding_hash, :binary, null: false)
      add(:mfa_timestep_hash, :binary, null: false)
      add(:audience, :string, null: false)
      add(:purpose, :string, null: false)
      add(:issued_at, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:consumed_at, :utc_datetime_usec)
      add(:consumed_operation_id, :string)
      add(:revoked_at, :utc_datetime_usec)

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create(unique_index(:platform_operator_elevation_proofs, [:proof_hash]))

    create(
      unique_index(
        :platform_operator_elevation_proofs,
        [:user_id, :session_binding_hash, :audience, :mfa_timestep_hash],
        name: :platform_operator_elevation_proofs_mfa_step_uidx
      )
    )

    create(index(:platform_operator_elevation_proofs, [:user_id, :expires_at]))

    create(
      unique_index(:platform_operator_elevation_proofs, [:consumed_operation_id],
        where: "consumed_operation_id IS NOT NULL"
      )
    )

    create(
      constraint(
        :platform_operator_elevation_proofs,
        :platform_operator_elevation_consumption_check,
        check:
          "(consumed_at IS NULL AND consumed_operation_id IS NULL) OR " <>
            "(consumed_at IS NOT NULL AND consumed_operation_id IS NOT NULL)"
      )
    )

    create(
      constraint(
        :platform_operator_elevation_proofs,
        :platform_operator_elevation_audience_check,
        check: "audience IN (#{@capabilities})"
      )
    )

    create(
      constraint(
        :platform_operator_elevation_proofs,
        :platform_operator_elevation_purpose_check,
        check: "purpose = 'platform_operation'"
      )
    )

    create(
      constraint(
        :platform_operator_elevation_proofs,
        :platform_operator_elevation_hash_lengths_check,
        check:
          "octet_length(proof_hash) = 32 AND octet_length(session_binding_hash) = 32 AND " <>
            "octet_length(mfa_timestep_hash) = 32"
      )
    )

    create(
      constraint(
        :platform_operator_elevation_proofs,
        :platform_operator_elevation_expiry_check,
        check: "expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'"
      )
    )

    create table(:platform_operator_events, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:event_type, :string, null: false)
      add(:actor_user_id, references(:users, type: :binary_id, on_delete: :restrict))
      add(:subject_user_id, references(:users, type: :binary_id, on_delete: :restrict))

      add(
        :grant_id,
        references(:platform_operator_grants, type: :binary_id, on_delete: :restrict)
      )

      add(
        :elevation_proof_id,
        references(:platform_operator_elevation_proofs, type: :binary_id, on_delete: :restrict)
      )

      add(:capability, :string)
      add(:outcome, :string, null: false)
      add(:reason, :text, null: false)
      add(:operation_id, :string)
      add(:request_id, :string)
      add(:target, :string)
      add(:metadata, :map, null: false, default: %{})
      add(:occurred_at, :utc_datetime_usec, null: false)

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create(index(:platform_operator_events, [:actor_user_id, :occurred_at]))
    create(index(:platform_operator_events, [:subject_user_id, :occurred_at]))
    create(index(:platform_operator_events, [:event_type, :occurred_at]))
    create(index(:platform_operator_events, [:operation_id]))

    create(
      unique_index(:platform_operator_events, [:operation_id],
        name: :platform_operator_events_ceremony_operation_uidx,
        where: "event_type IN ('grant_created', 'grant_revoked') AND operation_id IS NOT NULL"
      )
    )

    create(
      unique_index(:platform_operator_events, [:operation_id],
        name: :platform_operator_events_external_intent_operation_uidx,
        where: "event_type = 'authorization_intent'"
      )
    )

    create(
      unique_index(:platform_operator_events, [:operation_id],
        name: :platform_operator_events_external_terminal_operation_uidx,
        where: "event_type IN ('operation_succeeded', 'operation_failed')"
      )
    )

    create(
      constraint(:platform_operator_events, :platform_operator_events_type_check,
        check:
          "event_type IN ('grant_requested', 'grant_approved', 'grant_created', 'grant_revoked', " <>
            "'elevation_issued', 'authorization_intent', 'authorization_allowed', " <>
            "'authorization_denied', 'operation_succeeded', 'operation_failed')"
      )
    )

    create(
      constraint(:platform_operator_events, :platform_operator_events_outcome_check,
        check: "outcome IN ('pending', 'success', 'failed', 'denied')"
      )
    )

    create(
      constraint(:platform_operator_events, :platform_operator_events_capability_check,
        check: "capability IS NULL OR capability IN (#{@capabilities})"
      )
    )

    create table(:platform_operator_external_receipts, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:operation_id, :string, null: false)
      add(:token_hash, :binary, null: false)
      add(:worker_identity_hash, :binary, null: false)

      add(
        :intent_event_id,
        references(:platform_operator_events, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:issued_at, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:terminal_at, :utc_datetime_usec)
      add(:terminal_outcome, :string)
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create(unique_index(:platform_operator_external_receipts, [:operation_id]))
    create(unique_index(:platform_operator_external_receipts, [:intent_event_id]))

    create(
      constraint(:platform_operator_external_receipts, :platform_operator_receipt_hash_check,
        check: "octet_length(token_hash) = 32 AND octet_length(worker_identity_hash) = 32"
      )
    )

    create(
      constraint(:platform_operator_external_receipts, :platform_operator_receipt_expiry_check,
        check: "expires_at > issued_at AND expires_at <= issued_at + interval '1 hour'"
      )
    )

    create(
      constraint(:platform_operator_external_receipts, :platform_operator_receipt_terminal_check,
        check:
          "(terminal_at IS NULL AND terminal_outcome IS NULL) OR " <>
            "(terminal_at IS NOT NULL AND terminal_outcome IN ('succeeded', 'failed'))"
      )
    )

    execute("""
    CREATE FUNCTION reject_platform_operator_event_mutation()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      RAISE EXCEPTION 'platform_operator_events is append-only';
    END;
    $$
    """)

    execute("""
    CREATE TRIGGER platform_operator_events_append_only
    BEFORE UPDATE OR DELETE ON platform_operator_events
    FOR EACH ROW EXECUTE FUNCTION reject_platform_operator_event_mutation()
    """)

    execute("""
    CREATE TRIGGER platform_operator_events_no_truncate
    BEFORE TRUNCATE ON platform_operator_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_platform_operator_event_mutation()
    """)

    runtime_role = runtime_role!()

    if runtime_role do
      # This is defense in depth only. Production preflight must also prove the
      # runtime role is not owner/superuser and receives no inherited write ACL.
      quoted_role = quote_identifier(runtime_role)

      execute(
        "REVOKE ALL PRIVILEGES ON platform_operator_events, platform_operator_grants, " <>
          "platform_operator_elevation_proofs, platform_operator_external_receipts " <>
          "FROM #{quoted_role}"
      )

      execute("GRANT SELECT, INSERT ON platform_operator_events TO #{quoted_role}")

      execute(
        "GRANT SELECT, INSERT, UPDATE ON platform_operator_grants, " <>
          "platform_operator_elevation_proofs, platform_operator_external_receipts " <>
          "TO #{quoted_role}"
      )
    end
  end

  def down do
    execute("""
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM platform_operator_events LIMIT 1)
         OR EXISTS (SELECT 1 FROM platform_operator_elevation_proofs LIMIT 1)
         OR EXISTS (SELECT 1 FROM platform_operator_grants LIMIT 1) THEN
        RAISE EXCEPTION 'refusing destructive rollback: platform operator authority contains rows';
      END IF;
    END;
    $$
    """)

    execute(
      "DROP TRIGGER IF EXISTS platform_operator_events_no_truncate ON platform_operator_events"
    )

    execute(
      "DROP TRIGGER IF EXISTS platform_operator_events_append_only ON platform_operator_events"
    )

    execute("DROP FUNCTION IF EXISTS reject_platform_operator_event_mutation()")
    drop(table(:platform_operator_external_receipts))
    drop(table(:platform_operator_events))
    drop(table(:platform_operator_elevation_proofs))
    drop(table(:platform_operator_grants))
  end

  defp runtime_role! do
    case System.get_env("TAMANDUA_DB_RUNTIME_ROLE") do
      nil ->
        nil

      "" ->
        nil

      role ->
        if Regex.match?(~r/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/, role),
          do: role,
          else: raise("TAMANDUA_DB_RUNTIME_ROLE is not a safe PostgreSQL identifier")
    end
  end

  defp quote_identifier(role), do: ~s("#{role}")
end
