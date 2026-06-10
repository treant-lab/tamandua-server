defmodule TamanduaServer.Repo.Migrations.CreateModelProvenance do
  use Ecto.Migration

  def change do
    create table(:model_provenance, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :model_id, :string, null: false
      add :registry, :string, null: false
      add :sha256, :string
      add :version, :string
      add :downloaded_at, :utc_datetime_usec, null: false
      add :scanned_at, :utc_datetime_usec
      add :scan_result, :map
      add :risk_score, :float
      add :findings_count, :integer, default: 0
      add :status, :string, default: "pending", null: false
      add :metadata, :map, default: "{}"
      add :organization_id, references(:organizations, on_delete: :delete_all, type: :binary_id)

      timestamps(type: :utc_datetime_usec)
    end

    # Unique constraint: model_id + registry + sha256
    # Allows tracking different versions (sha256) of the same model
    create unique_index(:model_provenance, [:model_id, :registry, :sha256],
             name: :model_provenance_model_id_registry_sha256_index
           )

    # Index on registry for filtering by source
    create index(:model_provenance, [:registry])

    # Index on status for querying pending/scanning/malicious models
    create index(:model_provenance, [:status])

    # Index on risk_score for finding high-risk models
    create index(:model_provenance, [:risk_score])

    # Index on organization_id for multi-tenant queries
    create index(:model_provenance, [:organization_id])

    # Composite index for common query: registry + status
    create index(:model_provenance, [:registry, :status])

    # Index on downloaded_at for time-based queries
    create index(:model_provenance, [:downloaded_at])
  end
end
