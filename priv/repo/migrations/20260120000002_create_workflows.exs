defmodule TamanduaServer.Repo.Migrations.CreateWorkflows do
  use Ecto.Migration

  def change do
    # For Hyperautomation workflows
    create_if_not_exists table(:workflows, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string
      add :description, :text
      add :trigger_type, :string
      add :trigger_config, :map
      add :steps, {:array, :map}
      add :enabled, :boolean, default: true
      add :created_by, :string
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists table(:workflow_executions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :workflow_id, references(:workflows, type: :binary_id, on_delete: :delete_all)
      add :status, :string
      add :context, :map
      add :result, :map
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime

      timestamps()
    end

    create_if_not_exists index(:workflows, [:name])
    create_if_not_exists index(:workflows, [:trigger_type])
    create_if_not_exists index(:workflows, [:enabled])
    create_if_not_exists index(:workflow_executions, [:workflow_id])
    create_if_not_exists index(:workflow_executions, [:status])
    create_if_not_exists index(:workflows, [:organization_id])
  end
end
