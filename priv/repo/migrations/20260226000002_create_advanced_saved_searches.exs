defmodule TamanduaServer.Repo.Migrations.CreateAdvancedSavedSearches do
  use Ecto.Migration

  def change do
    create table(:saved_audit_searches, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :name, :string, null: false
      add :description, :string

      # Search filters as JSON
      add :filters, :map, null: false

      # Sharing
      add :is_public, :boolean, default: false
      add :shared_with_users, {:array, :binary_id}, default: []

      # Statistics
      add :use_count, :integer, default: 0
      add :last_used_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create index(:saved_audit_searches, [:user_id])
    create index(:saved_audit_searches, [:organization_id])
    create index(:saved_audit_searches, [:is_public])
  end
end
