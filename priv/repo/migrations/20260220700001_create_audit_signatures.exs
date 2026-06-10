defmodule TamanduaServer.Repo.Migrations.CreateAuditSignatures do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:audit_signatures, primary_key: false) do
      add :id, :binary_id, primary_key: true

      # Organization scoping
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      # Sealing metadata
      add :seal_number, :bigint, null: false
      add :start_sequence, :bigint, null: false
      add :end_sequence, :bigint, null: false
      add :entry_count, :integer, null: false

      # Merkle tree root
      add :merkle_root, :string, null: false

      # Digital signature (Ed25519)
      add :signature, :binary, null: false
      add :public_key, :binary, null: false

      # Timestamp
      add :sealed_at, :utc_datetime_usec, null: false

      # Verification metadata
      add :verified_at, :utc_datetime_usec
      add :verification_status, :string, default: "pending"
      add :verification_details, :map, default: %{}

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    # Indexes for efficient querying
    create_if_not_exists index(:audit_signatures, [:organization_id])
    create_if_not_exists index(:audit_signatures, [:seal_number])
    create_if_not_exists index(:audit_signatures, [:organization_id, :seal_number])
    create_if_not_exists index(:audit_signatures, [:sealed_at])
    create_if_not_exists index(:audit_signatures, [:verification_status])

    # Unique constraint on sequence ranges per organization
    create_if_not_exists unique_index(:audit_signatures, [:organization_id, :start_sequence])
    create_if_not_exists unique_index(:audit_signatures, [:organization_id, :end_sequence])

    # Add Merkle proof field to audit_logs
    alter table(:audit_logs) do
      add_if_not_exists :merkle_proof, :map
      add_if_not_exists :seal_id, references(:audit_signatures, type: :binary_id, on_delete: :nilify_all)
    end

    create_if_not_exists index(:audit_logs, [:seal_id])
  end
end
