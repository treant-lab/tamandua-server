defmodule TamanduaServer.Repo.Migrations.CreateMobileSignedPostureV1 do
  use Ecto.Migration

  def change do
    create table(:mobile_signed_posture_requests, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :identity_key_id,
        references(:mobile_device_identity_keys, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:requested_by_id, references(:users, type: :binary_id, on_delete: :nilify_all))
      add(:installation_id, :string, null: false)
      add(:device_key_id, :string, null: false)
      add(:key_scope_id, :string, null: false)
      add(:request_id_digest, :binary, null: false)
      add(:challenge_id_digest, :binary, null: false)
      add(:nonce_digest, :binary, null: false)
      add(:state, :string, null: false, default: "pending")
      add(:auth_method, :string, null: false)
      add(:issued_at, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:consumed_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:mobile_signed_posture_requests, [:organization_id, :request_id_digest]))

    create(
      unique_index(:mobile_signed_posture_requests, [:organization_id, :challenge_id_digest])
    )

    create(unique_index(:mobile_signed_posture_requests, [:organization_id, :nonce_digest]))
    create(index(:mobile_signed_posture_requests, [:organization_id, :installation_id, :state]))
    create(index(:mobile_signed_posture_requests, [:expires_at]))

    create(
      constraint(:mobile_signed_posture_requests, :signed_posture_request_digest_sizes,
        check:
          "octet_length(request_id_digest) = 32 AND octet_length(challenge_id_digest) = 32 AND octet_length(nonce_digest) = 32"
      )
    )

    create(
      constraint(:mobile_signed_posture_requests, :signed_posture_request_distinct_bindings,
        check:
          "request_id_digest <> challenge_id_digest AND request_id_digest <> nonce_digest AND challenge_id_digest <> nonce_digest"
      )
    )

    create(
      constraint(:mobile_signed_posture_requests, :signed_posture_request_key_formats,
        check:
          "device_key_id ~ '^tmdk_v1_[A-Za-z0-9_-]{43}$' AND key_scope_id ~ '^tmdks_v1_[A-Za-z0-9_-]{43}$'"
      )
    )

    create(
      constraint(:mobile_signed_posture_requests, :signed_posture_request_ttl,
        check: "expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'"
      )
    )

    create(
      constraint(:mobile_signed_posture_requests, :signed_posture_request_state,
        check:
          "(state = 'pending' AND consumed_at IS NULL) OR (state = 'consumed' AND consumed_at IS NOT NULL)"
      )
    )

    create table(:mobile_signed_posture_receipts, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :request_id,
        references(:mobile_signed_posture_requests, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(
        :identity_key_id,
        references(:mobile_device_identity_keys, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:installation_id, :string, null: false)
      add(:device_key_id, :string, null: false)
      add(:key_scope_id, :string, null: false)
      add(:posture, :map, null: false)
      add(:posture_sha256, :string, null: false)
      add(:signed_payload_sha256, :string, null: false)
      add(:signature_sha256, :binary, null: false)
      add(:observed_at, :utc_datetime_usec, null: false)
      add(:verified_at, :utc_datetime_usec, null: false)
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create(unique_index(:mobile_signed_posture_receipts, [:request_id]))

    create(
      index(:mobile_signed_posture_receipts, [:organization_id, :installation_id, :verified_at])
    )

    create(
      constraint(:mobile_signed_posture_receipts, :signed_posture_receipt_signature_digest,
        check: "octet_length(signature_sha256) = 32"
      )
    )

    create(
      constraint(:mobile_signed_posture_receipts, :signed_posture_receipt_key_formats,
        check:
          "device_key_id ~ '^tmdk_v1_[A-Za-z0-9_-]{43}$' AND key_scope_id ~ '^tmdks_v1_[A-Za-z0-9_-]{43}$'"
      )
    )

    create(
      constraint(:mobile_signed_posture_receipts, :signed_posture_receipt_hash_formats,
        check:
          "posture_sha256 ~ '^[A-Za-z0-9_-]{43}$' AND signed_payload_sha256 ~ '^[A-Za-z0-9_-]{43}$'"
      )
    )

    create table(:mobile_signed_posture_projections, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :receipt_id,
        references(:mobile_signed_posture_receipts, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(
        :identity_key_id,
        references(:mobile_device_identity_keys, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:installation_id, :string, null: false)
      add(:device_key_id, :string, null: false)
      add(:key_scope_id, :string, null: false)
      add(:posture, :map, null: false)
      add(:posture_sha256, :string, null: false)
      add(:observed_at, :utc_datetime_usec, null: false)
      add(:verified_at, :utc_datetime_usec, null: false)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:mobile_signed_posture_projections, [:organization_id, :installation_id]))
    create(index(:mobile_signed_posture_projections, [:organization_id, :verified_at]))

    create(
      constraint(:mobile_signed_posture_projections, :signed_posture_projection_key_formats,
        check:
          "device_key_id ~ '^tmdk_v1_[A-Za-z0-9_-]{43}$' AND key_scope_id ~ '^tmdks_v1_[A-Za-z0-9_-]{43}$'"
      )
    )

    create(
      constraint(:mobile_signed_posture_projections, :signed_posture_projection_hash_format,
        check: "posture_sha256 ~ '^[A-Za-z0-9_-]{43}$'"
      )
    )
  end
end
