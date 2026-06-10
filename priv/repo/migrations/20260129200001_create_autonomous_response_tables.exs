defmodule TamanduaServer.Repo.Migrations.CreateAutonomousResponseTables do
  use Ecto.Migration

  def change do
    # ==========================================================================
    # Asset Criticality Table
    # ==========================================================================
    create_if_not_exists table(:asset_criticality, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      # Criticality assessment
      add :level, :string  # critical, high, medium, low, minimal
      add :score, :integer  # 0-100
      add :role, :string  # domain_controller, database_server, workstation, etc.
      add :data_sensitivity, :string  # classified, pii, phi, pci, financial, public, internal
      add :compliance, :string  # hipaa, pci_dss, sox, gdpr, fisma, fedramp, none

      # Additional factors
      add :factors, {:array, :string}
      add :tags, {:array, :string}
      add :reason, :string  # Manual override reason

      # Auto-discovery metadata
      add :auto_discovered, :boolean, default: true
      add :discovery_source, :string  # hostname_pattern, process_detection, tag, manual
      add :last_discovery_at, :utc_datetime

      timestamps()
    end

    create_if_not_exists unique_index(:asset_criticality, [:agent_id])
    create_if_not_exists index(:asset_criticality, [:organization_id])
    create_if_not_exists index(:asset_criticality, [:level])
    create_if_not_exists index(:asset_criticality, [:role])

    # ==========================================================================
    # Autonomous Rules Table
    # ==========================================================================
    create_if_not_exists table(:autonomous_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      # Rule definition
      add :name, :string, null: false
      add :description, :text
      add :conditions, :map, null: false  # JSONB for complex conditions
      add :actions, {:array, :map}, null: false  # Array of action objects

      # Rule behavior
      add :priority, :integer, default: 50  # Higher = evaluated first
      add :enabled, :boolean, default: true
      add :auto_execute, :boolean, default: false
      add :mode, :string, default: "require_approval"  # auto_execute, require_approval, notify_only, disabled

      # Constraints and limits
      add :constraints, :map, default: %{}  # Rate limits, exclusions, etc.
      add :excluded_agents, {:array, :binary_id}, default: []
      add :excluded_asset_levels, {:array, :string}, default: []

      # Metadata
      add :tags, {:array, :string}
      add :created_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :updated_by, references(:users, type: :binary_id, on_delete: :nilify_all)

      # Statistics
      add :match_count, :integer, default: 0
      add :execution_count, :integer, default: 0
      add :last_match_at, :utc_datetime
      add :last_execution_at, :utc_datetime

      timestamps()
    end

    create_if_not_exists index(:autonomous_rules, [:organization_id])
    create_if_not_exists index(:autonomous_rules, [:enabled])
    create_if_not_exists index(:autonomous_rules, [:priority])
    create_if_not_exists index(:autonomous_rules, [:mode])

    # ==========================================================================
    # Autonomous Recommendations Table
    # ==========================================================================
    create_if_not_exists table(:autonomous_recommendations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      # Alert context
      add :severity, :string
      add :confidence_score, :float
      add :confidence_factors, {:array, :string}
      add :criticality_level, :string
      add :criticality_score, :integer

      # Recommendation details
      add :suggested_actions, {:array, :map}
      add :matching_rules, {:array, :binary_id}
      add :ml_confidence, :float
      add :auto_execute_eligible, :boolean, default: false
      add :justification, :text

      # Decision tracking
      add :status, :string, default: "pending"  # pending, approved, rejected, auto_executed, expired
      add :approved_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :rejection_reason, :text
      add :result, :map
      add :executed_at, :utc_datetime
      add :expires_at, :utc_datetime

      timestamps()
    end

    create_if_not_exists index(:autonomous_recommendations, [:alert_id])
    create_if_not_exists index(:autonomous_recommendations, [:agent_id])
    create_if_not_exists index(:autonomous_recommendations, [:organization_id])
    create_if_not_exists index(:autonomous_recommendations, [:status])
    create_if_not_exists index(:autonomous_recommendations, [:expires_at])

    # ==========================================================================
    # Autonomous Settings Table (per-org configuration)
    # ==========================================================================
    create_if_not_exists table(:autonomous_settings, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Core settings (stored as JSONB for flexibility)
      add :settings, :map, default: %{}

      # Individual toggles for quick reference
      add :autonomous_enabled, :boolean, default: true
      add :critical_asset_protection, :boolean, default: true
      add :emergency_disabled, :boolean, default: false
      add :emergency_disabled_reason, :text
      add :emergency_disabled_at, :utc_datetime
      add :emergency_disabled_by, references(:users, type: :binary_id, on_delete: :nilify_all)

      # Rate limiting
      add :max_actions_per_minute, :integer, default: 10
      add :max_actions_per_hour, :integer, default: 50
      add :min_confidence_for_auto, :integer, default: 90

      timestamps()
    end

    create_if_not_exists unique_index(:autonomous_settings, [:organization_id])

    # ==========================================================================
    # Analyst Decisions Table (for learning)
    # ==========================================================================
    create_if_not_exists table(:analyst_decisions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :recommendation_id, :binary_id
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all)
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      # Decision details
      add :decision, :string, null: false  # approved, rejected, modified
      add :suggested_actions, {:array, :map}
      add :selected_actions, {:array, :map}  # Actions actually taken (may differ from suggested)
      add :modifications, :map  # What the analyst changed
      add :result, :map

      # Alert context (captured for learning)
      add :alert_severity, :string
      add :confidence_score, :float
      add :criticality_level, :string
      add :mitre_techniques, {:array, :string}
      add :detection_source, :string

      # Time tracking
      add :decision_time_ms, :integer  # How long the analyst took to decide

      # Feedback
      add :feedback, :map  # Post-incident feedback
      add :effectiveness_rating, :integer  # 1-5 rating of how effective the response was

      timestamps()
    end

    create_if_not_exists index(:analyst_decisions, [:recommendation_id])
    create_if_not_exists index(:analyst_decisions, [:alert_id])
    create_if_not_exists index(:analyst_decisions, [:organization_id])
    create_if_not_exists index(:analyst_decisions, [:user_id])
    create_if_not_exists index(:analyst_decisions, [:decision])
    create_if_not_exists index(:analyst_decisions, [:alert_severity])

    # ==========================================================================
    # Learned Weights Table (ML model parameters)
    # ==========================================================================
    create_if_not_exists table(:learned_weights, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Model data
      add :weights, :map, null: false
      add :model_version, :string
      add :training_samples, :integer
      add :accuracy_metrics, :map

      # Metadata
      add :trained_by, :string  # "system" or user_id
      add :training_started_at, :utc_datetime
      add :training_completed_at, :utc_datetime

      timestamps()
    end

    create_if_not_exists unique_index(:learned_weights, [:organization_id])

    # ==========================================================================
    # Autonomous Audit Log Table
    # ==========================================================================
    create_if_not_exists table(:autonomous_audit_log, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      add :event_type, :string, null: false  # autonomous_action, approved_action, emergency_disable, etc.
      add :details, :map
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :ip_address, :string

      timestamps(updated_at: false)
    end

    create_if_not_exists index(:autonomous_audit_log, [:organization_id])
    create_if_not_exists index(:autonomous_audit_log, [:event_type])
    create_if_not_exists index(:autonomous_audit_log, [:inserted_at])
  end
end
