defmodule TamanduaServer.Repo.Migrations.CreateAiAgentsInventory do
  use Ecto.Migration

  def change do
    # For AI Agent Posture
    create_if_not_exists table(:ai_agents, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string
      add :vendor, :string
      add :agent_type, :string
      add :endpoint_url, :string
      add :permissions, :map
      add :risk_score, :float
      add :approved, :boolean, default: false
      add :owner, :string
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists index(:ai_agents, [:name])
    create_if_not_exists index(:ai_agents, [:vendor])
    create_if_not_exists index(:ai_agents, [:agent_type])
    create_if_not_exists index(:ai_agents, [:approved])
    create_if_not_exists index(:ai_agents, [:organization_id])
  end
end
