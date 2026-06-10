defmodule TamanduaServer.Repo.Migrations.AddWorkflowAndAssignmentToAlerts do
  use Ecto.Migration

  def change do
    # Add workflow and assignment tracking columns
    alter table(:alerts) do
      add :workflow_state, :string, default: "new", null: false
      add :previous_state, :string
      add :state_changed_at, :utc_datetime_usec
      add :state_changed_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      # Assignment tracking
      add :assigned_at, :utc_datetime_usec
      add :assigned_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :assignment_notes, :text

      # SLA tracking
      add :acknowledged_at, :utc_datetime_usec
      add :acknowledged_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :sla_acknowledge_deadline, :utc_datetime_usec
      add :sla_resolve_deadline, :utc_datetime_usec
      add :sla_acknowledge_breached, :boolean, default: false
      add :sla_resolve_breached, :boolean, default: false

      # Escalation tracking
      add :escalation_level, :integer, default: 0
      add :escalated_at, :utc_datetime_usec
      add :escalated_to_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :escalation_reason, :text
    end

    # Create workflow state transition audit table
    create table(:alert_state_transitions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false
      add :from_state, :string, null: false
      add :to_state, :string, null: false
      add :transition_reason, :text
      add :transition_notes, :text
      add :transitioned_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    # Create assignment history table
    create table(:alert_assignments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false
      add :assigned_to_id, references(:users, type: :binary_id, on_delete: :nilify_all), null: false
      add :assigned_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :assignment_type, :string, default: "manual" # manual, auto_round_robin, auto_least_busy, auto_expertise
      add :handoff_notes, :text
      add :unassigned_at, :utc_datetime_usec
      add :unassigned_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :unassignment_reason, :text

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    # Create SLA configuration table
    create table(:sla_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :enabled, :boolean, default: true

      # Severity-based thresholds (in minutes)
      add :critical_acknowledge_minutes, :integer, default: 15
      add :critical_resolve_minutes, :integer, default: 240 # 4 hours
      add :high_acknowledge_minutes, :integer, default: 60
      add :high_resolve_minutes, :integer, default: 480 # 8 hours
      add :medium_acknowledge_minutes, :integer, default: 240
      add :medium_resolve_minutes, :integer, default: 1440 # 24 hours
      add :low_acknowledge_minutes, :integer, default: 480
      add :low_resolve_minutes, :integer, default: 2880 # 48 hours

      # Business hours configuration
      add :business_hours_only, :boolean, default: false
      add :business_hours_start, :time
      add :business_hours_end, :time
      add :business_days, {:array, :integer}, default: [1, 2, 3, 4, 5] # Mon-Fri
      add :timezone, :string, default: "UTC"

      # Priority/weight
      add :priority, :integer, default: 0

      timestamps(type: :utc_datetime_usec)
    end

    # Create analyst workload tracking table
    create table(:analyst_workload, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :assigned_count, :integer, default: 0
      add :critical_count, :integer, default: 0
      add :high_count, :integer, default: 0
      add :medium_count, :integer, default: 0
      add :low_count, :integer, default: 0
      add :total_workload_score, :float, default: 0.0 # Weighted score
      add :last_assignment_at, :utc_datetime_usec
      add :is_available, :boolean, default: true
      add :max_capacity, :integer, default: 50

      timestamps(type: :utc_datetime_usec)
    end

    # Create auto-assignment configuration table
    create table(:auto_assignment_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :enabled, :boolean, default: true

      # Assignment strategy
      add :strategy, :string, default: "round_robin" # round_robin, least_busy, expertise, random

      # Matching conditions (same as escalation rules)
      add :severity_filter, {:array, :string}, default: []
      add :mitre_techniques, {:array, :string}, default: []
      add :mitre_tactics, {:array, :string}, default: []
      add :source_filter, {:array, :string}, default: []

      # Assignment pool (user IDs)
      add :analyst_pool, {:array, :binary_id}, default: []

      # Expertise mapping (for expertise-based assignment)
      add :expertise_map, :map, default: %{} # %{"T1059" => [user_id1, user_id2]}

      # Priority
      add :priority, :integer, default: 0

      timestamps(type: :utc_datetime_usec)
    end

    # Create indexes for efficient querying
    create index(:alerts, [:workflow_state])
    create index(:alerts, [:assigned_at])
    create index(:alerts, [:acknowledged_at])
    create index(:alerts, [:escalation_level])
    create index(:alerts, [:sla_acknowledge_deadline])
    create index(:alerts, [:sla_resolve_deadline])
    create index(:alerts, [:sla_acknowledge_breached])
    create index(:alerts, [:sla_resolve_breached])
    create index(:alerts, [:state_changed_by_id])
    create index(:alerts, [:assigned_by_id])
    create index(:alerts, [:acknowledged_by_id])
    create index(:alerts, [:escalated_to_id])

    create index(:alert_state_transitions, [:alert_id])
    create index(:alert_state_transitions, [:from_state])
    create index(:alert_state_transitions, [:to_state])
    create index(:alert_state_transitions, [:transitioned_by_id])
    create index(:alert_state_transitions, [:inserted_at])

    create index(:alert_assignments, [:alert_id])
    create index(:alert_assignments, [:assigned_to_id])
    create index(:alert_assignments, [:assigned_by_id])
    create index(:alert_assignments, [:assignment_type])
    create index(:alert_assignments, [:inserted_at])

    create index(:sla_policies, [:organization_id])
    create index(:sla_policies, [:enabled])
    create index(:sla_policies, [:priority])

    create index(:analyst_workload, [:user_id])
    create index(:analyst_workload, [:organization_id])
    create index(:analyst_workload, [:is_available])
    create unique_index(:analyst_workload, [:user_id, :organization_id])

    create index(:auto_assignment_rules, [:organization_id])
    create index(:auto_assignment_rules, [:enabled])
    create index(:auto_assignment_rules, [:strategy])
    create index(:auto_assignment_rules, [:priority])

    # Add composite indexes for common queries
    create index(:alerts, [:organization_id, :workflow_state, :assigned_to_id])
    create index(:alerts, [:organization_id, :sla_acknowledge_breached])
    create index(:alerts, [:organization_id, :sla_resolve_breached])
  end
end
