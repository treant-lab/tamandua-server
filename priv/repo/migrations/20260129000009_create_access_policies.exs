defmodule TamanduaServer.Repo.Migrations.CreateAccessPolicies do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:access_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :name, :string, null: false
      add :description, :text
      add :permission, :string, null: false  # "*" for all, or specific permission slug
      add :conditions, :map, default: %{}
      add :effect, :string, null: false, default: "allow"  # "allow" or "deny"
      add :priority, :integer, null: false, default: 50
      add :is_active, :boolean, null: false, default: true
      add :applies_to_roles, {:array, :string}, default: []

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists unique_index(:access_policies, [:organization_id, :name])
    create_if_not_exists index(:access_policies, [:organization_id])
    create_if_not_exists index(:access_policies, [:permission])
    create_if_not_exists index(:access_policies, [:priority])
    create_if_not_exists index(:access_policies, [:is_active])

    # Add api_only field to roles if not exists
    alter table(:roles) do
      add_if_not_exists :api_only, :boolean, default: false
    end
  end
end
