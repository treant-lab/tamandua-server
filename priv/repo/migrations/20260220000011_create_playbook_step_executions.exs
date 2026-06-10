defmodule TamanduaServer.Repo.Migrations.CreatePlaybookStepExecutions do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:playbook_step_executions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :execution_id, references(:playbook_executions, type: :binary_id, on_delete: :delete_all), null: false
      add :step_index, :integer, null: false
      add :step_name, :string
      add :action_type, :string, null: false
      add :status, :string, null: false  # pending, running, completed, failed, skipped, retrying
      add :params, :map, default: %{}
      add :result, :jsonb
      add :error_message, :text
      add :retry_count, :integer, default: 0
      add :max_retries, :integer, default: 0
      add :timeout_seconds, :integer
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime
      add :duration_ms, :integer

      timestamps(type: :utc_datetime)
    end

    create_if_not_exists index(:playbook_step_executions, [:execution_id])
    create_if_not_exists index(:playbook_step_executions, [:status])
    create_if_not_exists index(:playbook_step_executions, [:execution_id, :step_index])
    create_if_not_exists index(:playbook_step_executions, [:started_at])

    # Add index for finding failed steps that can be retried
    create_if_not_exists index(:playbook_step_executions, [:status, :retry_count])
  end
end
