defmodule TamanduaServer.Repo.Migrations.CreateMobileDeviceIdentityProtocol do
  use Ecto.Migration

  def change do
    create table(:mobile_device_identity_challenges, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:installation_id, :string, null: false)
      add(:platform, :string, null: false)
      add(:purpose, :string, null: false)
      add(:key_scope_id, :string, null: false)
      add(:challenge_digest, :binary, null: false)
      add(:state, :string, null: false, default: "pending")
      add(:issued_at, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:consumed_at, :utc_datetime_usec)

      timestamps(type: :utc_datetime_usec)
    end

    create(
      unique_index(:mobile_device_identity_challenges, [
        :organization_id,
        :challenge_digest
      ])
    )

    create(
      index(:mobile_device_identity_challenges, [
        :organization_id,
        :installation_id,
        :state
      ])
    )

    create(index(:mobile_device_identity_challenges, [:expires_at]))

    create table(:mobile_device_identity_keys, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :mobile_device_id,
        references(:mobile_devices, type: :binary_id, on_delete: :nilify_all)
      )

      add(
        :proof_challenge_id,
        references(:mobile_device_identity_challenges,
          type: :binary_id,
          on_delete: :restrict
        ),
        null: false
      )

      add(
        :rotated_from_id,
        references(:mobile_device_identity_keys, type: :binary_id, on_delete: :nilify_all)
      )

      add(:installation_id, :string, null: false)
      add(:platform, :string, null: false)
      add(:key_scope_id, :string, null: false)
      add(:device_key_id, :string, null: false)
      add(:public_key_spki, :binary, null: false)
      add(:algorithm, :string, null: false)
      add(:proof_state, :string, null: false)
      add(:attestation_state, :string, null: false)
      add(:lifecycle_state, :string, null: false)
      add(:activated_at, :utc_datetime_usec, null: false)
      add(:last_proof_at, :utc_datetime_usec, null: false)
      add(:revoked_at, :utc_datetime_usec)
      add(:rotated_at, :utc_datetime_usec)
      add(:metadata, :map, null: false, default: %{})

      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:mobile_device_identity_keys, [:organization_id, :device_key_id]))

    create(
      unique_index(:mobile_device_identity_keys, [:organization_id, :installation_id],
        where: "lifecycle_state = 'active'",
        name: :mobile_device_identity_keys_one_active_installation_index
      )
    )

    create(index(:mobile_device_identity_keys, [:organization_id, :installation_id]))
    create(index(:mobile_device_identity_keys, [:rotated_from_id]))
    create(index(:mobile_device_identity_keys, [:proof_challenge_id]))
  end
end
