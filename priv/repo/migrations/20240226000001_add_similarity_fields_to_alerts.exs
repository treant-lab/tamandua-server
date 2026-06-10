defmodule TamanduaServer.Repo.Migrations.AddSimilarityFieldsToAlerts do
  use Ecto.Migration

  def change do
    alter table(:alerts) do
      # Similarity cluster ID (for grouping similar alerts)
      add :similarity_cluster_id, :integer

      # Whether this alert is a cluster leader (representative)
      add :is_cluster_leader, :boolean, default: false

      # Embedding vector (stored as JSONB for flexibility)
      # In production, consider using pgvector extension for efficient similarity search
      add :embedding, :map

      # Duplicate detection fields
      add :is_duplicate, :boolean, default: false
      add :duplicate_type, :string  # "exact" or "near"
      add :duplicate_of_alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all)

      # Alert hash for duplicate detection
      add :alert_hash, :string

      # Timestamps for similarity processing
      add :similarity_computed_at, :utc_datetime_usec
      add :last_similarity_check_at, :utc_datetime_usec
    end

    # Indexes for efficient queries
    create index(:alerts, [:similarity_cluster_id])
    create index(:alerts, [:is_cluster_leader])
    create index(:alerts, [:is_duplicate])
    create index(:alerts, [:duplicate_of_alert_id])
    create index(:alerts, [:alert_hash])
    create index(:alerts, [:similarity_computed_at])
  end
end
