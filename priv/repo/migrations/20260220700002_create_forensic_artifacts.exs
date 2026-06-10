defmodule TamanduaServer.Repo.Migrations.CreateForensicArtifacts do
  use Ecto.Migration

  def change do
    create table(:forensic_artifacts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :case_id, :string
      add :artifact_type, :string, null: false
      add :artifact_subtype, :string

      # Collection parameters
      add :parameters, :map, default: %{}

      # Status tracking
      add :status, :string, null: false, default: "pending"
      add :progress_percent, :integer, default: 0
      add :progress_bytes, :bigint, default: 0
      add :total_bytes, :bigint
      add :eta_seconds, :integer
      add :transfer_speed_mbps, :float

      # Error tracking
      add :error_message, :text
      add :error_details, :map

      # Collection metadata
      add :collection_started_at, :utc_datetime
      add :collection_completed_at, :utc_datetime
      add :collection_duration_ms, :bigint

      # File information
      add :file_path, :text
      add :file_size, :bigint
      add :sha256_hash, :string
      add :compression_type, :string
      add :encrypted, :boolean, default: false
      add :encryption_key_id, :string

      # Chain of custody
      add :collector_name, :string, null: false
      add :collector_email, :string
      add :collection_method, :string, default: "automated"
      add :custody_chain, {:array, :map}, default: []
      add :evidence_seal_hash, :string
      add :evidence_integrity_verified, :boolean, default: false

      # Upload tracking
      add :upload_destination, :string
      add :s3_bucket, :string
      add :s3_key, :string
      add :s3_url, :text
      add :upload_started_at, :utc_datetime
      add :upload_completed_at, :utc_datetime
      add :download_url, :text
      add :download_expires_at, :utc_datetime

      # Metadata
      add :tags, {:array, :string}, default: []
      add :notes, :text
      add :metadata, :map, default: %{}

      # Audit
      add :requested_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :approved_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create index(:forensic_artifacts, [:agent_id])
    create index(:forensic_artifacts, [:organization_id])
    create index(:forensic_artifacts, [:case_id])
    create index(:forensic_artifacts, [:artifact_type])
    create index(:forensic_artifacts, [:status])
    create index(:forensic_artifacts, [:requested_by_id])
    create index(:forensic_artifacts, [:sha256_hash])
    create index(:forensic_artifacts, [:inserted_at])

    # Composite indexes for common queries
    create index(:forensic_artifacts, [:organization_id, :status])
    create index(:forensic_artifacts, [:agent_id, :status])
    create index(:forensic_artifacts, [:organization_id, :artifact_type])
  end
end
