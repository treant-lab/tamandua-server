defmodule TamanduaServer.Repo.Migrations.CreateRemediationTables do
  use Ecto.Migration

  def change do
    # Remediation Playbooks Table
    create table(:remediation_playbooks, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :category, :string
      add :trigger_type, :string, default: "manual"
      add :trigger_conditions, :map, default: %{}
      add :steps, {:array, :map}, default: []
      add :enabled, :boolean, default: true
      add :require_approval, :boolean, default: false
      add :approval_tier, :string, default: "analyst"
      add :approval_timeout_minutes, :integer, default: 30
      add :auto_rollback_on_failure, :boolean, default: false
      add :tags, {:array, :string}, default: []
      add :severity_threshold, :string
      add :risk_level, :string, default: "medium"
      add :execution_count, :integer, default: 0
      add :success_count, :integer, default: 0
      add :failure_count, :integer, default: 0
      add :last_executed_at, :utc_datetime
      add :created_by, :binary_id
      add :version, :integer, default: 1
      add :is_template, :boolean, default: false

      timestamps()
    end

    create index(:remediation_playbooks, [:enabled])
    create index(:remediation_playbooks, [:category])
    create index(:remediation_playbooks, [:trigger_type])
    create index(:remediation_playbooks, [:risk_level])
    create index(:remediation_playbooks, [:is_template])
    create index(:remediation_playbooks, [:created_by])

    # Remediation Executions Table
    create table(:remediation_executions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :playbook_id, references(:remediation_playbooks, type: :binary_id, on_delete: :nilify_all)
      add :playbook_name, :string
      add :playbook_version, :integer
      add :trigger_event, :map, default: %{}
      add :status, :string, default: "pending"
      add :execution_mode, :string, default: "live"
      add :steps_completed, :integer, default: 0
      add :steps_total, :integer, default: 0
      add :current_step_index, :integer, default: 0
      add :error_message, :text
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime
      add :execution_context, :map, default: %{}
      add :execution_results, {:array, :map}, default: []

      # Approval workflow fields
      add :require_approval, :boolean, default: false
      add :approval_tier, :string
      add :approval_status, :string
      add :approved_by, :binary_id
      add :approved_at, :utc_datetime
      add :approval_comments, :text

      # Rollback fields
      add :rollback_available, :boolean, default: false
      add :rollback_data, :map, default: %{}
      add :rolled_back, :boolean, default: false
      add :rolled_back_at, :utc_datetime
      add :rolled_back_by, :binary_id

      # Metadata
      add :triggered_by, :binary_id
      add :agent_id, :binary_id
      add :alert_id, :binary_id
      add :impact_assessment, :map

      timestamps()
    end

    create index(:remediation_executions, [:playbook_id])
    create index(:remediation_executions, [:status])
    create index(:remediation_executions, [:execution_mode])
    create index(:remediation_executions, [:approval_status])
    create index(:remediation_executions, [:triggered_by])
    create index(:remediation_executions, [:agent_id])
    create index(:remediation_executions, [:alert_id])
    create index(:remediation_executions, [:started_at])
    create index(:remediation_executions, [:completed_at])

    # Remediation Audit Log Table
    create table(:remediation_audit_log, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :execution_id, references(:remediation_executions, type: :binary_id, on_delete: :delete_all)
      add :playbook_id, :binary_id
      add :action_type, :string, null: false
      add :action_name, :string
      add :step_index, :integer
      add :status, :string, null: false
      add :action_params, :map, default: %{}
      add :action_result, :map
      add :error_message, :text
      add :duration_ms, :integer
      add :retry_count, :integer, default: 0
      add :dry_run, :boolean, default: false
      add :executed_by, :binary_id
      add :executed_at, :utc_datetime

      # Before/After state (for rollback)
      add :before_state, :map
      add :after_state, :map

      timestamps()
    end

    create index(:remediation_audit_log, [:execution_id])
    create index(:remediation_audit_log, [:playbook_id])
    create index(:remediation_audit_log, [:action_type])
    create index(:remediation_audit_log, [:status])
    create index(:remediation_audit_log, [:executed_at])
    create index(:remediation_audit_log, [:dry_run])

    # Remediation Approval History Table
    create table(:remediation_approval_history, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :execution_id, references(:remediation_executions, type: :binary_id, on_delete: :delete_all)
      add :action, :string, null: false
      add :approver_id, :binary_id
      add :from_user_id, :binary_id
      add :to_user_id, :binary_id
      add :comments, :text
      add :reason, :text
      add :timestamp, :utc_datetime, null: false

      timestamps()
    end

    create index(:remediation_approval_history, [:execution_id])
    create index(:remediation_approval_history, [:approver_id])
    create index(:remediation_approval_history, [:action])
    create index(:remediation_approval_history, [:timestamp])

    # Remediation Metrics Table (for reporting)
    create table(:remediation_metrics, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :playbook_id, :binary_id
      add :execution_id, :binary_id
      add :metric_date, :date, null: false
      add :total_executions, :integer, default: 0
      add :successful_executions, :integer, default: 0
      add :failed_executions, :integer, default: 0
      add :cancelled_executions, :integer, default: 0
      add :avg_duration_ms, :integer
      add :min_duration_ms, :integer
      add :max_duration_ms, :integer
      add :total_actions_executed, :integer, default: 0
      add :total_rollbacks, :integer, default: 0
      add :approval_rate, :float, default: 0.0
      add :avg_approval_time_ms, :integer

      timestamps()
    end

    create index(:remediation_metrics, [:playbook_id])
    create index(:remediation_metrics, [:metric_date])
    create unique_index(:remediation_metrics, [:playbook_id, :metric_date])
  end
end
