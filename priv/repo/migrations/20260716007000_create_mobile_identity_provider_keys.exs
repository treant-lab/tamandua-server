defmodule TamanduaServer.Repo.Migrations.CreateMobileIdentityProviderKeys do
  use Ecto.Migration

  def change do
    create table(:mobile_device_identity_provider_keys, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :identity_key_id,
        references(:mobile_device_identity_keys, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:provider, :string, null: false)
      add(:profile_id, :string, null: false)
      add(:environment, :string, null: false)
      add(:team_id, :string, null: false)
      add(:bundle_id, :string, null: false)
      add(:installation_id, :string, null: false)
      add(:credential_id, :binary, null: false)
      add(:public_key_spki, :binary, null: false)
      add(:receipt_sha256, :binary, null: false)
      add(:sign_count, :bigint, null: false)
      add(:last_asserted_at, :utc_datetime_usec, null: false)

      timestamps(type: :utc_datetime_usec)
    end

    create(
      unique_index(:mobile_device_identity_provider_keys, [:identity_key_id],
        name: :mobile_identity_provider_keys_identity_idx
      )
    )

    create(
      unique_index(
        :mobile_device_identity_provider_keys,
        [:provider, :environment, :credential_id],
        name: :mobile_identity_provider_keys_global_credential_idx
      )
    )

    create(
      index(:mobile_device_identity_provider_keys, [:organization_id, :installation_id],
        name: :mobile_identity_provider_keys_installation_idx
      )
    )

    create(
      constraint(:mobile_device_identity_provider_keys, :mobile_identity_provider_check,
        check: "provider = 'apple_app_attest'"
      )
    )

    create(
      constraint(
        :mobile_device_identity_provider_keys,
        :mobile_identity_provider_environment_check,
        check: "environment IN ('development', 'production')"
      )
    )

    create(
      constraint(
        :mobile_device_identity_provider_keys,
        :mobile_identity_provider_sign_count_check,
        check: "sign_count > 0"
      )
    )

    create table(:mobile_device_identity_apple_contexts, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :assertion_challenge_id,
        references(:mobile_device_identity_challenges, type: :binary_id, on_delete: :restrict)
      )

      add(:installation_id, :string, null: false)
      add(:profile_id, :string, null: false)
      add(:environment, :string, null: false)
      add(:team_id, :string, null: false)
      add(:bundle_id, :string, null: false)
      add(:state, :string, null: false, default: "attest_pending")
      add(:attestation_challenge_digest, :binary, null: false)
      add(:receipt_id, :binary_id)
      add(:credential_id, :binary)
      add(:public_key_spki, :binary)
      add(:receipt_sha256, :binary)
      add(:validation_category, :integer)
      add(:bundle_version, :string)
      add(:metadata, :map, null: false, default: %{})
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:consumed_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(
      unique_index(:mobile_device_identity_apple_contexts, [:receipt_id],
        name: :mobile_identity_apple_contexts_receipt_idx
      )
    )

    create(
      unique_index(:mobile_device_identity_apple_contexts, [:assertion_challenge_id],
        name: :mobile_identity_apple_contexts_assertion_challenge_idx
      )
    )

    create(
      index(:mobile_device_identity_apple_contexts, [:organization_id, :installation_id, :state],
        name: :mobile_identity_apple_contexts_installation_idx
      )
    )

    create(
      index(:mobile_device_identity_apple_contexts, [:expires_at],
        name: :mobile_identity_apple_contexts_expiry_idx
      )
    )

    create(
      constraint(
        :mobile_device_identity_apple_contexts,
        :mobile_identity_apple_context_state_check,
        check: "state IN ('attest_pending', 'assert_pending', 'consumed')"
      )
    )
  end
end
