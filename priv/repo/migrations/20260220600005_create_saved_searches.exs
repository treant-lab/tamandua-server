defmodule TamanduaServer.Repo.Migrations.CreateSavedSearches do
  use Ecto.Migration

  def change do
    create table(:saved_searches, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :filter_json, :map, null: false
      add :is_shared, :boolean, default: false, null: false
      add :is_template, :boolean, default: false, null: false
      add :is_starred, :boolean, default: false, null: false
      add :category, :string
      add :version, :integer, default: 1, null: false
      add :parent_id, references(:saved_searches, type: :binary_id, on_delete: :nilify_all)
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :usage_count, :integer, default: 0, null: false
      add :last_used_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create index(:saved_searches, [:user_id])
    create index(:saved_searches, [:organization_id])
    create index(:saved_searches, [:organization_id, :is_shared])
    create index(:saved_searches, [:organization_id, :is_template])
    create index(:saved_searches, [:parent_id])
    create index(:saved_searches, [:category])
  end
end
