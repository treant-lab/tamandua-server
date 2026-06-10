defmodule TamanduaServer.Repo.Migrations.CreateSavedFilters do
  use Ecto.Migration

  def change do
    create table(:saved_filters, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false

      # Basic fields
      add :name, :string, null: false
      add :description, :text
      add :filter_json, :map, null: false
      add :category, :string
      add :scope, :string, null: false, default: "alerts"

      # Sharing and visibility
      add :is_public, :boolean, default: false
      add :is_template, :boolean, default: false
      add :is_pinned, :boolean, default: false
      add :shared_with_team, :boolean, default: false

      # Usage tracking
      add :usage_count, :integer, default: 0
      add :last_used_at, :utc_datetime_usec

      # Versioning
      add :version, :integer, default: 1
      add :parent_id, references(:saved_filters, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:saved_filters, [:user_id])
    create index(:saved_filters, [:organization_id])
    create index(:saved_filters, [:scope])
    create index(:saved_filters, [:category])
    create index(:saved_filters, [:is_public])
    create index(:saved_filters, [:is_template])
    create index(:saved_filters, [:is_pinned])
    create index(:saved_filters, [:parent_id])
    create index(:saved_filters, [:last_used_at])
    create index(:saved_filters, [:usage_count])

    # Composite indexes for common queries
    create index(:saved_filters, [:user_id, :scope, :is_pinned])
    create index(:saved_filters, [:organization_id, :is_public, :scope])
  end
end
