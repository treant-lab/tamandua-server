defmodule TamanduaServer.Repo.Migrations.CreateMobileDeviceIdentityRecovery do
  use Ecto.Migration

  def change do
    create table(:mobile_device_identity_recovery_intents, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :requested_by_id,
        references(:users, type: :binary_id, on_delete: :nilify_all)
      )

      add(:installation_id, :string, null: false)
      add(:purpose, :string, null: false)
      add(:state, :string, null: false, default: "pending")
      add(:old_device_key_id, :string, null: false)
      add(:candidate_device_key_id, :string, null: false)
      add(:reason, :string, null: false)
      add(:token_digest, :binary, null: false)
      add(:step_up_required, :boolean, null: false, default: false)
      add(:authorization_state, :string, null: false)
      add(:authorization_provenance, :map, null: false, default: %{})
      add(:resolution, :string)
      add(:issued_at, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:token_consumed_at, :utc_datetime_usec)
      add(:last_checked_at, :utc_datetime_usec)
      add(:consumed_at, :utc_datetime_usec)
      add(:denied_at, :utc_datetime_usec)
      add(:expired_at, :utc_datetime_usec)

      timestamps(type: :utc_datetime_usec)
    end

    create(
      unique_index(:mobile_device_identity_recovery_intents, [
        :organization_id,
        :token_digest
      ])
    )

    create(
      index(:mobile_device_identity_recovery_intents, [
        :organization_id,
        :installation_id,
        :state
      ])
    )

    create(
      unique_index(
        :mobile_device_identity_recovery_intents,
        [:organization_id, :installation_id],
        name: :mobile_recovery_one_pending_installation_index,
        where: "state = 'pending'"
      )
    )

    create(
      unique_index(
        :mobile_device_identity_recovery_intents,
        [:organization_id, :candidate_device_key_id],
        name: :mobile_recovery_one_pending_candidate_index,
        where: "state = 'pending'"
      )
    )

    create(index(:mobile_device_identity_recovery_intents, [:expires_at]))
    create(index(:mobile_device_identity_recovery_intents, [:requested_by_id]))

    create(
      constraint(:mobile_device_identity_recovery_intents, :recovery_intent_valid_purpose,
        check: "purpose IN ('reconcile_rotation', 'rebind')"
      )
    )

    create(
      constraint(:mobile_device_identity_recovery_intents, :recovery_intent_valid_state,
        check: "state IN ('pending', 'consumed', 'denied', 'expired')"
      )
    )

    create(
      constraint(
        :mobile_device_identity_recovery_intents,
        :recovery_intent_valid_authorization_state,
        check: "authorization_state IN ('not_required', 'pending_authorization')"
      )
    )

    create(
      constraint(:mobile_device_identity_recovery_intents, :recovery_intent_server_policy,
        check:
          "(purpose = 'rebind' AND step_up_required = TRUE AND authorization_state = 'pending_authorization') OR " <>
            "(purpose = 'reconcile_rotation' AND step_up_required = FALSE AND authorization_state = 'not_required')"
      )
    )

    create(
      constraint(:mobile_device_identity_recovery_intents, :recovery_intent_distinct_keys,
        check: "candidate_device_key_id <> old_device_key_id"
      )
    )

    create(
      constraint(:mobile_device_identity_recovery_intents, :recovery_intent_key_id_format,
        check:
          "old_device_key_id ~ '^tmdk_v1_[A-Za-z0-9_-]{43}$' AND " <>
            "candidate_device_key_id ~ '^tmdk_v1_[A-Za-z0-9_-]{43}$'"
      )
    )

    create(
      constraint(:mobile_device_identity_recovery_intents, :recovery_intent_token_digest_size,
        check: "octet_length(token_digest) = 32"
      )
    )

    create(
      constraint(:mobile_device_identity_recovery_intents, :recovery_intent_valid_ttl,
        check: "expires_at > issued_at"
      )
    )

    create(
      constraint(:mobile_device_identity_recovery_intents, :recovery_intent_audit_state,
        check:
          "(state = 'pending' AND resolution IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL) OR " <>
            "(state = 'consumed' AND resolution IN ('previous_key_confirmed', 'replacement_key_confirmed') AND token_consumed_at IS NOT NULL AND consumed_at IS NOT NULL) OR " <>
            "(state = 'denied' AND resolution = 'active_key_unknown' AND token_consumed_at IS NOT NULL AND denied_at IS NOT NULL) OR " <>
            "(state = 'expired' AND resolution IS NULL AND expired_at IS NOT NULL)"
      )
    )
  end
end
