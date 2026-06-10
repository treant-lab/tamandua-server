defmodule TamanduaServer.Repo.Migrations.CreateConfigurationDriftTables do
  use Ecto.Migration

  def change do
    # Configuration baselines table - stores the expected configuration for agents
    create table(:agent_configuration_baselines, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Configuration categories
      add :collector_settings, :map, default: %{}
      add :response_permissions, :map, default: %{}
      add :network_settings, :map, default: %{}
      add :file_paths, :map, default: %{}
      add :resource_limits, :map, default: %{}
      add :enabled_features, :map, default: %{}
      add :rule_versions, :map, default: %{}

      # Metadata
      add :baseline_hash, :string
      add :baseline_version, :integer, default: 1
      add :is_active, :boolean, default: true
      add :created_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :approved_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :approved_at, :utc_datetime
      add :notes, :text

      timestamps(type: :utc_datetime)
    end

    create index(:agent_configuration_baselines, [:agent_id])
    create index(:agent_configuration_baselines, [:organization_id])
    create index(:agent_configuration_baselines, [:is_active])
    create index(:agent_configuration_baselines, [:baseline_hash])
    create unique_index(:agent_configuration_baselines, [:agent_id, :baseline_version])

    # Configuration drift detection results
    create table(:agent_configuration_drifts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :baseline_id, references(:agent_configuration_baselines, type: :binary_id, on_delete: :nilify_all)

      # Drift details
      add :drift_type, :string, null: false
      add :category, :string, null: false
      add :severity, :string, default: "medium"
      add :status, :string, default: "detected"

      # Change details
      add :field_path, :string
      add :expected_value, :map
      add :actual_value, :map
      add :drift_details, :map, default: %{}

      # Resolution
      add :remediation_action, :string
      add :remediation_status, :string
      add :remediation_attempted_at, :utc_datetime
      add :remediation_completed_at, :utc_datetime
      add :remediation_error, :text

      add :resolved_at, :utc_datetime
      add :resolved_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :resolution_notes, :text

      add :detected_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create index(:agent_configuration_drifts, [:agent_id])
    create index(:agent_configuration_drifts, [:organization_id])
    create index(:agent_configuration_drifts, [:baseline_id])
    create index(:agent_configuration_drifts, [:drift_type])
    create index(:agent_configuration_drifts, [:category])
    create index(:agent_configuration_drifts, [:severity])
    create index(:agent_configuration_drifts, [:status])
    create index(:agent_configuration_drifts, [:detected_at])
    create index(:agent_configuration_drifts, [:resolved_at])

    # Configuration scan history
    create table(:agent_configuration_scans, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :scan_type, :string, default: "scheduled"

      add :scanned_at, :utc_datetime, null: false
      add :duration_ms, :integer
      add :drifts_detected, :integer, default: 0
      add :drifts_critical, :integer, default: 0
      add :drifts_high, :integer, default: 0
      add :drifts_medium, :integer, default: 0
      add :drifts_low, :integer, default: 0

      add :scan_result, :string
      add :error_message, :text
      add :triggered_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create index(:agent_configuration_scans, [:agent_id])
    create index(:agent_configuration_scans, [:organization_id])
    create index(:agent_configuration_scans, [:scan_type])
    create index(:agent_configuration_scans, [:scanned_at])
    create index(:agent_configuration_scans, [:scan_result])

    # Compliance status tracking
    create table(:agent_compliance_status, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :is_compliant, :boolean, default: true
      add :drift_count, :integer, default: 0
      add :last_scan_at, :utc_datetime
      add :last_compliant_at, :utc_datetime
      add :non_compliant_since, :utc_datetime
      add :compliance_score, :float, default: 100.0

      add :critical_drifts, :integer, default: 0
      add :high_drifts, :integer, default: 0
      add :medium_drifts, :integer, default: 0
      add :low_drifts, :integer, default: 0

      timestamps(type: :utc_datetime)
    end

    # Unique index covers the agent_id index
    create unique_index(:agent_compliance_status, [:agent_id])
    create index(:agent_compliance_status, [:organization_id])
    create index(:agent_compliance_status, [:is_compliant])
    create index(:agent_compliance_status, [:compliance_score])
    create index(:agent_compliance_status, [:last_scan_at])
  end
end
