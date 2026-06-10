defmodule TamanduaServer.Repo.Migrations.CreateHuntSessions do
  use Ecto.Migration

  def change do
    # For NL Hunting sessions
    create_if_not_exists table(:hunt_sessions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :query, :text
      add :parsed_query, :map
      add :findings, {:array, :map}
      add :hypotheses, {:array, :map}
      add :status, :string
      add :created_by, :string
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists index(:hunt_sessions, [:status])
    create_if_not_exists index(:hunt_sessions, [:created_by])
    create_if_not_exists index(:hunt_sessions, [:organization_id])
  end
end
