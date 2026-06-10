defmodule TamanduaServer.Repo.Migrations.CreateAgenticAgents do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:agentic_agents, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :org_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :definition, :map, null: false, default: %{}
      add :enabled, :boolean, null: false, default: true
      add :version, :integer, null: false, default: 1

      timestamps()
    end

    create_if_not_exists index(:agentic_agents, [:org_id])
    create_if_not_exists index(:agentic_agents, [:enabled])
    create_if_not_exists index(:agentic_agents, [:name])
  end
end
