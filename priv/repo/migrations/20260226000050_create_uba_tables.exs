defmodule TamanduaServer.Repo.Migrations.CreateUbaTables do
  use Ecto.Migration

  def up do
    # User behaviors table - stores tracked user behavior events
    create table(:user_behaviors, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :behavior_type, :string, null: false
      add :timestamp, :utc_datetime_usec, null: false
      add :metadata, :map, default: %{}
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      add :value, :float  # Numeric value (e.g., bytes transferred, login duration)
      add :location, :string  # IP or geolocation
      add :device, :string  # Device identifier
      add :source, :string  # Source of behavior (e.g., "login", "file_access", "network")

      timestamps(type: :utc_datetime_usec)
    end

    create index(:user_behaviors, [:user_id])
    create index(:user_behaviors, [:behavior_type])
    create index(:user_behaviors, [:timestamp])
    create index(:user_behaviors, [:user_id, :behavior_type])
    create index(:user_behaviors, [:organization_id])

    # User baselines - statistical baselines per user per behavior
    create table(:user_baselines, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :behavior_type, :string, null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      # Statistical measures
      add :mean, :float
      add :stddev, :float
      add :median, :float
      add :p95, :float
      add :p99, :float
      add :min, :float
      add :max, :float
      add :count, :integer, default: 0

      # Time-based patterns
      add :hourly_pattern, :map, default: %{}  # Hour of day -> avg value
      add :daily_pattern, :map, default: %{}  # Day of week -> avg value
      add :common_locations, {:array, :string}, default: []
      add :common_devices, {:array, :string}, default: []

      # Learning status
      add :baseline_start, :utc_datetime_usec
      add :baseline_end, :utc_datetime_usec
      add :is_complete, :boolean, default: false
      add :last_updated, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:user_baselines, [:user_id, :behavior_type])
    create index(:user_baselines, [:user_id])
    create index(:user_baselines, [:is_complete])
    create index(:user_baselines, [:organization_id])

    # User anomalies - detected behavioral anomalies
    create table(:user_anomalies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :behavior_type, :string, null: false
      add :timestamp, :utc_datetime_usec, null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      add :anomaly_type, :string  # "statistical_outlier", "time_anomaly", "location_anomaly", etc.
      add :severity, :string  # "low", "medium", "high", "critical"
      add :score, :float  # Anomaly score (e.g., z-score, deviation)

      add :baseline_value, :float
      add :observed_value, :float
      add :deviation, :float

      add :metadata, :map, default: %{}
      add :is_acknowledged, :boolean, default: false
      add :acknowledged_by, references(:users, type: :binary_id)
      add :acknowledged_at, :utc_datetime_usec
      add :notes, :text

      timestamps(type: :utc_datetime_usec)
    end

    create index(:user_anomalies, [:user_id])
    create index(:user_anomalies, [:behavior_type])
    create index(:user_anomalies, [:timestamp])
    create index(:user_anomalies, [:severity])
    create index(:user_anomalies, [:is_acknowledged])
    create index(:user_anomalies, [:organization_id])

    # User risk scores - overall risk per user
    create table(:user_risk_scores, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      add :risk_score, :integer, default: 0  # 0-100
      add :risk_level, :string  # "low", "medium", "high", "critical"

      # Risk factors (points)
      add :off_hours_activity, :integer, default: 0
      add :new_location, :integer, default: 0
      add :excessive_data_access, :integer, default: 0
      add :privilege_escalation, :integer, default: 0
      add :failed_logins, :integer, default: 0
      add :anomalous_app_usage, :integer, default: 0
      add :peer_group_outlier, :integer, default: 0

      add :contributing_anomalies, {:array, :binary_id}, default: []
      add :last_calculated, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:user_risk_scores, [:user_id])
    create index(:user_risk_scores, [:risk_level])
    create index(:user_risk_scores, [:risk_score])
    create index(:user_risk_scores, [:organization_id])

    # Peer groups - group users for comparison
    create table(:peer_groups, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      add :criteria, :map, default: %{}  # Grouping criteria (role, department, location)
      add :user_ids, {:array, :binary_id}, default: []

      # Peer group baselines
      add :behavior_baselines, :map, default: %{}
      add :last_updated, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create index(:peer_groups, [:organization_id])
    create index(:peer_groups, [:name])

    # UBA alerts - high-priority behavioral alerts
    create table(:uba_alerts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      add :alert_type, :string, null: false  # "high_risk_user", "sudden_change", "impossible_travel", "privilege_escalation"
      add :severity, :string  # "low", "medium", "high", "critical"
      add :status, :string, default: "open"  # "open", "investigating", "closed"

      add :risk_score, :integer
      add :description, :text
      add :evidence, :map, default: %{}

      add :assigned_to, references(:users, type: :binary_id)
      add :resolved_at, :utc_datetime_usec
      add :resolution_notes, :text

      timestamps(type: :utc_datetime_usec)
    end

    create index(:uba_alerts, [:user_id])
    create index(:uba_alerts, [:alert_type])
    create index(:uba_alerts, [:severity])
    create index(:uba_alerts, [:status])
    create index(:uba_alerts, [:organization_id])

    # ML model states for UBA
    create table(:uba_ml_models, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :model_type, :string, null: false  # "isolation_forest", "lstm", "autoencoder"
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      add :model_path, :string
      add :version, :string
      add :accuracy, :float
      add :training_start, :utc_datetime_usec
      add :training_end, :utc_datetime_usec
      add :is_active, :boolean, default: false

      add :hyperparameters, :map, default: %{}
      add :metrics, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create index(:uba_ml_models, [:model_type])
    create index(:uba_ml_models, [:is_active])
    create index(:uba_ml_models, [:organization_id])
  end

  def down do
    drop table(:uba_ml_models)
    drop table(:uba_alerts)
    drop table(:peer_groups)
    drop table(:user_risk_scores)
    drop table(:user_anomalies)
    drop table(:user_baselines)
    drop table(:user_behaviors)
  end
end
