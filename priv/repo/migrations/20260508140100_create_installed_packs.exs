defmodule TamanduaServer.Repo.Migrations.CreateInstalledPacks do
  use Ecto.Migration

  def change do
    create table(:installed_packs, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :pack_id, :string, null: false
      add :pack_version, :string, null: false
      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all), null: false
      add :installed_by_id, references(:users, type: :uuid, on_delete: :nilify_all)
      add :enabled, :boolean, default: true
      add :config, :map, default: %{}

      timestamps()
    end

    # Each pack can only be installed once per organization
    create unique_index(:installed_packs, [:pack_id, :organization_id])

    # For listing installed packs by org
    create index(:installed_packs, [:organization_id])

    # For filtering by enabled status
    create index(:installed_packs, [:organization_id, :enabled])
  end
end
