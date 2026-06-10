defmodule TamanduaServer.Repo.Migrations.CreateKnownGoodHashes do
  @moduledoc """
  Creates the known_good_hashes table for storing verified model file hashes.

  Known-good hashes allow the system to skip expensive deep scans for models
  that have been pre-verified by administrators. When a model's SHA-256 hash
  matches an entry in this table, the scanner returns "verified" immediately
  without invoking the full analysis pipeline.
  """
  use Ecto.Migration

  def change do
    create table(:known_good_hashes, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :sha256, :string, null: false, size: 64
      add :name, :string
      add :source, :string, null: false  # 'custom', 'import', 'verified_scan'
      add :model_type, :string  # 'pickle', 'gguf', 'safetensors', 'onnx'
      add :notes, :text
      add :created_by, :string
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    # Primary lookup index: unique per sha256+organization (allows same hash in different orgs)
    create unique_index(:known_good_hashes, [:sha256, :organization_id],
      name: :known_good_hashes_sha256_organization_id_index
    )

    # Index for tenant queries
    create index(:known_good_hashes, [:organization_id])

    # Index for filtering by source type
    create index(:known_good_hashes, [:source])

    # Index for filtering by model type
    create index(:known_good_hashes, [:model_type])
  end
end
