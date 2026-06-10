defmodule TamanduaServer.Repo.Migrations.AddMetadataAndUniqueIndexToIocs do
  use Ecto.Migration

  def change do
    alter table(:iocs) do
      add :metadata, :map, default: %{}, null: false
    end

    # Create a two-column unique index on (type, value) to support ON CONFLICT
    # upserts in bulk_add/2 and feed sync operations. The original migration
    # only created a three-column index on (type, value, organization_id),
    # which PostgreSQL cannot match when organization_id is NULL.
    create_if_not_exists unique_index(:iocs, [:type, :value], name: :iocs_type_value_unique_index)
  end
end
