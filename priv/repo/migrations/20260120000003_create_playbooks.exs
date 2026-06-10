defmodule TamanduaServer.Repo.Migrations.CreatePlaybooks do
  use Ecto.Migration

  def change do
    # For Response Playbooks
    create_if_not_exists table(:playbooks, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :trigger_type, :string
      add :trigger_conditions, :map
      add :steps, {:array, :map}
      add :enabled, :boolean, default: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists index(:playbooks, [:name])
    create_if_not_exists index(:playbooks, [:trigger_type])
    create_if_not_exists index(:playbooks, [:enabled])
    create_if_not_exists index(:playbooks, [:organization_id])
  end
end
