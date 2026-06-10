defmodule TamanduaServer.Repo.Migrations.CreateRbacTables do
  use Ecto.Migration

  def change do
    # Roles table
    create_if_not_exists table(:roles, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :slug, :string, null: false
      add :description, :text
      add :builtin, :boolean, default: false, null: false
      add :priority, :integer, default: 0, null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists unique_index(:roles, [:organization_id, :slug])
    create_if_not_exists index(:roles, [:builtin])
    create_if_not_exists index(:roles, [:priority])

    # Permissions table (for custom permissions storage)
    create_if_not_exists table(:permissions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :slug, :string, null: false
      add :description, :text
      add :category, :string

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists unique_index(:permissions, [:slug])
    create_if_not_exists index(:permissions, [:category])

    # Role-Permission join table
    create_if_not_exists table(:role_permissions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :role_id, references(:roles, type: :binary_id, on_delete: :delete_all), null: false
      add :permission_id, references(:permissions, type: :binary_id, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists unique_index(:role_permissions, [:role_id, :permission_id])
    create_if_not_exists index(:role_permissions, [:permission_id])

    # User-Role join table with scope support
    create_if_not_exists table(:user_roles, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :role_id, references(:roles, type: :binary_id, on_delete: :delete_all), null: false

      # Scope for resource-level permissions
      add :scope_type, :string
      add :scope_id, :binary_id

      # Grant tracking
      add :granted_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :granted_at, :utc_datetime_usec
      add :expires_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists unique_index(:user_roles, [:user_id, :role_id, :scope_type, :scope_id],
      name: :user_roles_unique_assignment
    )
    create_if_not_exists index(:user_roles, [:role_id])
    create_if_not_exists index(:user_roles, [:scope_type, :scope_id])
    create_if_not_exists index(:user_roles, [:expires_at])
  end
end
