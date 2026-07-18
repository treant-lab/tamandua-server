defmodule TamanduaServer.Repo.Migrations.EnrichSoftwareInventoryMetadata do
  use Ecto.Migration

  def change do
    alter table(:software_inventory) do
      add_if_not_exists :publisher, :string
      add_if_not_exists :package_manager, :string
      add_if_not_exists :license, :string
      add_if_not_exists :metadata, :map, default: %{}
      add_if_not_exists :installed, :boolean, default: true, null: false
      add_if_not_exists :removed_at, :utc_datetime
    end

    create_if_not_exists index(:software_inventory, [:agent_id, :installed])
    create_if_not_exists index(:software_inventory, [:package_manager])
  end
end
