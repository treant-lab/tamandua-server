defmodule TamanduaServer.Repo.Migrations.CreateHuntingWorkflows do
  use Ecto.Migration

  def change do
    # Workflow definitions (templates)
    create_if_not_exists table(:hunting_workflows, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :category, :string  # lateral_movement, credential_theft, etc.
      add :steps, {:array, :map}, default: []  # Step definitions
      add :metadata, :map, default: %{}  # MITRE mapping, tags, etc.
      add :version, :integer, default: 1
      add :is_custom, :boolean, default: false
      add :is_template, :boolean, default: true
      add :visibility, :string, default: "global"  # global, organization, private
      add :created_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :parent_workflow_id, references(:hunting_workflows, type: :binary_id, on_delete: :nilify_all)

      timestamps()
    end

    create_if_not_exists index(:hunting_workflows, [:category])
    create_if_not_exists index(:hunting_workflows, [:is_template])
    create_if_not_exists index(:hunting_workflows, [:visibility])
    create_if_not_exists index(:hunting_workflows, [:organization_id])
    create_if_not_exists index(:hunting_workflows, [:created_by])
    create_if_not_exists index(:hunting_workflows, [:parent_workflow_id])

    # Workflow executions (instances)
    create_if_not_exists table(:workflow_executions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :workflow_id, references(:hunting_workflows, type: :binary_id, on_delete: :delete_all), null: false
      add :status, :string, default: "pending"  # pending, in_progress, paused, completed, failed
      add :current_step_index, :integer, default: 0
      add :step_states, {:array, :map}, default: []  # State for each step
      add :findings, {:array, :map}, default: []  # Collected evidence
      add :annotations, {:array, :map}, default: []  # Analyst notes per step
      add :hypothesis_status, :map, default: %{}  # confirmed, refuted, unclear
      add :progress_percentage, :integer, default: 0
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime
      add :error_message, :text
      add :final_report, :map  # Generated report
      add :executed_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists index(:workflow_executions, [:workflow_id])
    create_if_not_exists index(:workflow_executions, [:status])
    create_if_not_exists index(:workflow_executions, [:executed_by])
    create_if_not_exists index(:workflow_executions, [:organization_id])
    create_if_not_exists index(:workflow_executions, [:started_at])
    create_if_not_exists index(:workflow_executions, [:completed_at])

    # Workflow step results
    create_if_not_exists table(:workflow_step_results, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :execution_id, references(:workflow_executions, type: :binary_id, on_delete: :delete_all), null: false
      add :step_index, :integer, null: false
      add :step_type, :string  # query, decision, manual_review, collect_evidence, notify
      add :query, :text
      add :results, {:array, :map}, default: []
      add :result_count, :integer, default: 0
      add :decision, :string  # For decision steps
      add :annotations, :text
      add :status, :string  # pending, running, completed, skipped, failed
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime
      add :duration_ms, :integer

      timestamps()
    end

    create_if_not_exists index(:workflow_step_results, [:execution_id])
    create_if_not_exists index(:workflow_step_results, [:execution_id, :step_index])
    create_if_not_exists index(:workflow_step_results, [:status])

    # Workflow findings
    create_if_not_exists table(:workflow_findings, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :execution_id, references(:workflow_executions, type: :binary_id, on_delete: :delete_all), null: false
      add :step_index, :integer
      add :finding_type, :string  # ioc, suspicious_activity, evidence, etc.
      add :severity, :string  # low, medium, high, critical
      add :title, :string
      add :description, :text
      add :data, :map
      add :linked_alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all)
      add :exported_to_misp, :boolean, default: false
      add :exported_at, :utc_datetime

      timestamps()
    end

    create_if_not_exists index(:workflow_findings, [:execution_id])
    create_if_not_exists index(:workflow_findings, [:finding_type])
    create_if_not_exists index(:workflow_findings, [:severity])
    create_if_not_exists index(:workflow_findings, [:linked_alert_id])
  end
end
