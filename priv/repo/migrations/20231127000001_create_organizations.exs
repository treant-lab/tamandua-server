defmodule TamanduaServer.Repo.Migrations.CreateOrganizations do
  use Ecto.Migration

  def change do
    create table(:organizations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :slug, :string, null: false
      add :settings, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:organizations, [:slug])
  end
end
