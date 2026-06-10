defmodule TamanduaServer.Repo.Migrations.CreateAgentPolicies do
  use Ecto.Migration

  def change do
    # Policy templates and configurations
    create table(:agent_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :version, :integer, null: false, default: 1
      add :status, :string, null: false, default: "draft"

      # Policy scope: "organization", "group", "agent"
      add :scope, :string, null: false, default: "organization"

      # Policy type: "template", "custom"
      add :policy_type, :string, null: false, default: "custom"

      # Template name if this is a template-based policy
      add :template_name, :string

      # Inheritance: policy this one inherits from
      add :parent_policy_id, references(:agent_policies, type: :binary_id, on_delete: :nilify_all)

      # Policy content in YAML format
      add :config, :map, null: false, default: %{}

      # Parsed policy structure
      # {
      #   "collectors": {
      #     "process": {"enabled": true, "interval_ms": 5000},
      #     "file": {"enabled": true, "interval_ms": 10000},
      #     "network": {"enabled": true, "interval_ms": 5000},
      #     ...
      #   },
      #   "resource_limits": {
      #     "max_cpu_percent": 10,
      #     "max_memory_mb": 500,
      #     "max_disk_mb": 1000
      #   },
      #   "detection": {
      #     "yara_enabled": true,
      #     "sigma_enabled": true,
      #     "ml_enabled": true,
      #     "custom_rules": []
      #   },
      #   "response": {
      #     "allowed_actions": ["isolate", "kill_process", "quarantine"],
      #     "auto_response_enabled": false,
      #     "max_actions_per_hour": 10
      #   },
      #   "network": {
      #     "allowed_domains": [],
      #     "blocked_domains": [],
      #     "proxy_enabled": false
      #   }
      # }
      add :policy_data, :map, null: false, default: %{}

      # Compliance tags
      add :compliance_tags, {:array, :string}, default: []

      # Metadata
      add :tags, {:array, :string}, default: []
      add :metadata, :map, default: %{}

      # Ownership
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :created_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :updated_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create index(:agent_policies, [:organization_id])
    create index(:agent_policies, [:scope])
    create index(:agent_policies, [:status])
    create index(:agent_policies, [:policy_type])
    create index(:agent_policies, [:parent_policy_id])
    create unique_index(:agent_policies, [:organization_id, :name, :version],
      name: :agent_policies_org_name_version_index)

    # Policy assignments to groups
    create table(:agent_policy_group_assignments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :policy_id, references(:agent_policies, type: :binary_id, on_delete: :delete_all), null: false
      add :group_id, references(:agent_groups, type: :binary_id, on_delete: :delete_all), null: false

      # Override specific policy settings at group level
      add :overrides, :map, default: %{}

      # Priority (higher = takes precedence)
      add :priority, :integer, default: 0

      add :assigned_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :assigned_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:agent_policy_group_assignments, [:policy_id])
    create index(:agent_policy_group_assignments, [:group_id])
    create unique_index(:agent_policy_group_assignments, [:policy_id, :group_id])

    # Policy assignments to individual agents (overrides)
    create table(:agent_policy_assignments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :policy_id, references(:agent_policies, type: :binary_id, on_delete: :delete_all), null: false
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false

      # Override specific policy settings at agent level
      add :overrides, :map, default: %{}

      # Priority (higher = takes precedence)
      add :priority, :integer, default: 100

      add :assigned_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :assigned_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:agent_policy_assignments, [:policy_id])
    create index(:agent_policy_assignments, [:agent_id])
    create unique_index(:agent_policy_assignments, [:policy_id, :agent_id])

    # Policy deployments
    create table(:agent_policy_deployments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :policy_id, references(:agent_policies, type: :binary_id, on_delete: :delete_all), null: false

      # Deployment strategy: "immediate", "scheduled", "phased"
      add :strategy, :string, null: false, default: "immediate"

      # Status: "pending", "in_progress", "completed", "failed", "rolled_back"
      add :status, :string, null: false, default: "pending"

      # For scheduled deployments
      add :scheduled_at, :utc_datetime

      # For phased rollouts
      add :rollout_phases, {:array, :map}, default: []
      # [
      #   %{percentage: 5, status: "completed", started_at: ~U[...], completed_at: ~U[...]},
      #   %{percentage: 25, status: "in_progress", started_at: ~U[...], completed_at: nil},
      #   %{percentage: 50, status: "pending", started_at: nil, completed_at: nil},
      #   %{percentage: 100, status: "pending", started_at: nil, completed_at: nil}
      # ]

      add :current_phase, :integer, default: 0
      add :current_phase_percentage, :integer, default: 0

      # Automatic rollback configuration
      add :auto_rollback_enabled, :boolean, default: true
      add :rollback_threshold_percent, :integer, default: 10
      add :rollback_reason, :text

      # Progress tracking
      add :total_agents, :integer, default: 0
      add :successful_agents, :integer, default: 0
      add :failed_agents, :integer, default: 0
      add :pending_agents, :integer, default: 0

      # Timestamps
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime
      add :failed_at, :utc_datetime
      add :rolled_back_at, :utc_datetime

      # Metadata
      add :error_summary, :map, default: %{}
      add :deployment_log, {:array, :map}, default: []

      # Ownership
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :deployed_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create index(:agent_policy_deployments, [:policy_id])
    create index(:agent_policy_deployments, [:organization_id])
    create index(:agent_policy_deployments, [:status])
    create index(:agent_policy_deployments, [:scheduled_at])

    # Deployment results per agent
    create table(:agent_policy_deployment_results, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :deployment_id, references(:agent_policy_deployments, type: :binary_id, on_delete: :delete_all), null: false
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false

      # Status: "pending", "in_progress", "success", "failed", "skipped"
      add :status, :string, null: false, default: "pending"

      # Phase this agent was deployed in
      add :phase_number, :integer

      # Error details if failed
      add :error_message, :text
      add :error_details, :map

      # Timestamps
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime
      add :failed_at, :utc_datetime

      # Previous policy for rollback
      add :previous_policy_snapshot, :map

      timestamps(type: :utc_datetime)
    end

    create index(:agent_policy_deployment_results, [:deployment_id])
    create index(:agent_policy_deployment_results, [:agent_id])
    create index(:agent_policy_deployment_results, [:status])
    create unique_index(:agent_policy_deployment_results, [:deployment_id, :agent_id])

    # Policy change history
    create table(:agent_policy_history, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :policy_id, references(:agent_policies, type: :binary_id, on_delete: :delete_all), null: false

      # Version tracking
      add :version, :integer, null: false
      add :previous_version, :integer

      # Change details
      add :change_type, :string, null: false
      # "created", "updated", "activated", "deactivated", "deployed", "rolled_back"

      add :changes, :map, default: %{}
      add :diff, :map, default: %{}

      # Metadata
      add :change_reason, :text
      add :changed_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create index(:agent_policy_history, [:policy_id])
    create index(:agent_policy_history, [:version])
    create index(:agent_policy_history, [:change_type])
  end
end
