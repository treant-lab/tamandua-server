defmodule TamanduaServer.Repo.Migrations.CreateInvestigations do
  use Ecto.Migration

  def change do
    # For AgenticAnalyst investigations
    create_if_not_exists table(:investigations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, :string
      add :status, :string
      add :priority, :string
      add :hypotheses, :map
      add :evidence, :map
      add :recommendations, :map
      add :triage_result, :map
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists index(:investigations, [:alert_id])
    create_if_not_exists index(:investigations, [:status])
    create_if_not_exists index(:investigations, [:organization_id])
  end
end
