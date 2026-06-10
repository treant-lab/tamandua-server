defmodule TamanduaServer.Repo.Migrations.EnhanceAuditLogs do
  use Ecto.Migration

  def change do
    # Add tamper-proof hash chain fields to audit_logs
    alter table(:audit_logs) do
      add_if_not_exists :severity, :string, default: "info"
      add_if_not_exists :sequence_number, :bigint
      add_if_not_exists :entry_hash, :string
      add_if_not_exists :previous_hash, :string
    end

    # Create index for hash chain verification
    create_if_not_exists index(:audit_logs, [:organization_id, :sequence_number])
    create_if_not_exists index(:audit_logs, [:severity])

    # Create audit retention policies table
    create_if_not_exists table(:audit_retention_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Retention periods
      add :hot_retention_days, :integer, default: 90
      add :warm_retention_days, :integer, default: 365
      add :cold_retention_years, :integer, default: 7

      # Archival settings
      add :auto_archive, :boolean, default: true
      add :compress_archives, :boolean, default: true
      add :archive_storage_path, :string

      # Compliance requirements
      add :compliance_framework, :string
      add :legal_hold, :boolean, default: false
      add :legal_hold_until, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists unique_index(:audit_retention_policies, [:organization_id])

    # Create audit archives table
    create_if_not_exists table(:audit_archives, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :date_from, :utc_datetime_usec, null: false
      add :date_to, :utc_datetime_usec, null: false
      add :entry_count, :integer, null: false
      add :compressed_data, :binary
      add :checksum, :string, null: false
      add :storage_tier, :string, default: "warm"

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:audit_archives, [:organization_id])
    create_if_not_exists index(:audit_archives, [:date_from, :date_to])
    create_if_not_exists index(:audit_archives, [:storage_tier])
  end
end
