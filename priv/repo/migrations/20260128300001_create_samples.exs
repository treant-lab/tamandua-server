defmodule TamanduaServer.Repo.Migrations.CreateSamples do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:samples, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :sha256, :string, null: false
      add :sha1, :string
      add :md5, :string
      add :file_size, :integer
      add :file_type, :string
      add :file_name, :string
      add :source_agent_id, :binary_id
      add :source_path, :string

      # ML analysis results
      add :ml_score, :float
      add :ml_verdict, :string  # "malicious", "suspicious", "clean", "unknown"
      add :ml_family, :string   # malware family if detected
      add :ml_confidence, :float
      add :ml_analyzed_at, :utc_datetime_usec

      # Metadata
      add :is_signed, :boolean
      add :signer, :string
      add :entropy, :float
      add :first_seen, :utc_datetime_usec
      add :last_seen, :utc_datetime_usec
      add :submission_count, :integer, default: 1

      # Storage
      add :stored_path, :string
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    # Unique index on sha256 for deduplication
    create_if_not_exists unique_index(:samples, [:sha256])
    create_if_not_exists index(:samples, [:sha1])
    create_if_not_exists index(:samples, [:md5])
    create_if_not_exists index(:samples, [:source_agent_id])
    create_if_not_exists index(:samples, [:ml_verdict])
    create_if_not_exists index(:samples, [:ml_family])
    create_if_not_exists index(:samples, [:file_type])
    create_if_not_exists index(:samples, [:inserted_at])
    create_if_not_exists index(:samples, [:first_seen])

    # Composite index for finding unanalyzed samples
    create_if_not_exists index(:samples, [:ml_verdict, :inserted_at])
    create_if_not_exists index(:samples, [:organization_id])
  end
end
