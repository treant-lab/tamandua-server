defmodule TamanduaServer.Repo.Migrations.CreateAgentHealthHistory do
  use Ecto.Migration

  def change do
    # Agent health score history for trend analysis
    create table(:agent_health_history, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false

      # Overall health score
      add :health_score, :integer, null: false
      add :category, :string, null: false # excellent, good, fair, poor

      # Score breakdown
      add :uptime_score, :integer
      add :cpu_score, :integer
      add :memory_score, :integer
      add :throughput_score, :integer
      add :error_rate_score, :integer
      add :coverage_score, :integer
      add :compliance_score, :integer

      # Issues snapshot (JSON array)
      add :issues, :map

      # Timestamp
      add :recorded_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create index(:agent_health_history, [:agent_id, :recorded_at])
    create index(:agent_health_history, [:agent_id, :category])
    create index(:agent_health_history, [:health_score])

    # Predictive maintenance records
    create table(:agent_health_predictions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false

      # Predictions
      add :current_score, :integer
      add :predicted_next_hour, :integer
      add :predicted_next_day, :integer
      add :trend, :string # improving, stable, degrading

      # Sudden drop detection
      add :sudden_drop_detected, :boolean, default: false
      add :sudden_drop_details, :map

      # Resource warnings
      add :resource_warnings, {:array, :map}

      # Maintenance recommendations
      add :recommendations, {:array, :map}

      # Confidence level
      add :confidence, :string # high, medium, low

      # Timestamp
      add :predicted_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create index(:agent_health_predictions, [:agent_id, :predicted_at])
    create index(:agent_health_predictions, [:sudden_drop_detected])
    create index(:agent_health_predictions, [:trend])

    # Health alert events (for rapid degradation)
    create table(:agent_health_alerts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false

      add :alert_type, :string, null: false # score_drop, resource_exhaustion, pattern_detected
      add :severity, :string, null: false # critical, warning, info
      add :message, :text, null: false
      add :details, :map

      # Resolution
      add :acknowledged, :boolean, default: false
      add :acknowledged_by, :string
      add :acknowledged_at, :utc_datetime
      add :resolved, :boolean, default: false
      add :resolved_at, :utc_datetime
      add :resolution_notes, :text

      add :triggered_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create index(:agent_health_alerts, [:agent_id, :triggered_at])
    create index(:agent_health_alerts, [:alert_type])
    create index(:agent_health_alerts, [:severity])
    create index(:agent_health_alerts, [:acknowledged])
    create index(:agent_health_alerts, [:resolved])

    # Fleet health summary (hourly aggregation)
    create table(:fleet_health_summary, primary_key: false) do
      add :id, :binary_id, primary_key: true

      # Time bucket
      add :hour_bucket, :utc_datetime, null: false

      # Category counts
      add :excellent_count, :integer, default: 0
      add :good_count, :integer, default: 0
      add :fair_count, :integer, default: 0
      add :poor_count, :integer, default: 0
      add :total_agents, :integer, default: 0

      # Average scores
      add :avg_health_score, :float
      add :avg_uptime_score, :float
      add :avg_cpu_score, :float
      add :avg_memory_score, :float
      add :avg_throughput_score, :float
      add :avg_error_rate_score, :float
      add :avg_coverage_score, :float
      add :avg_compliance_score, :float

      # Fleet-wide issues
      add :critical_issues_count, :integer, default: 0
      add :warning_issues_count, :integer, default: 0

      timestamps(type: :utc_datetime)
    end

    # Unique index covers the regular index
    create unique_index(:fleet_health_summary, [:hour_bucket])

    # Agent baselines for throughput scoring
    create_if_not_exists table(:agent_baselines, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false

      # Baseline metrics (calculated from historical data)
      add :baseline_events_per_sec, :float
      add :baseline_cpu_usage, :float
      add :baseline_memory_usage, :float
      add :baseline_disk_usage, :float

      # Statistical bounds
      add :events_per_sec_lower, :float
      add :events_per_sec_upper, :float
      add :cpu_usage_lower, :float
      add :cpu_usage_upper, :float
      add :memory_usage_lower, :float
      add :memory_usage_upper, :float

      # Calculation metadata
      add :calculated_at, :utc_datetime, null: false
      add :window_hours, :integer # Hours of data used for calculation
      add :data_points, :integer # Number of samples used

      timestamps(type: :utc_datetime)
    end

    # Add missing columns to existing table
    execute """
    DO $$
    BEGIN
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS calculated_at TIMESTAMP WITHOUT TIME ZONE;
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS baseline_events_per_sec FLOAT;
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS baseline_cpu_usage FLOAT;
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS baseline_memory_usage FLOAT;
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS baseline_disk_usage FLOAT;
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS events_per_sec_lower FLOAT;
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS events_per_sec_upper FLOAT;
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS cpu_usage_lower FLOAT;
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS cpu_usage_upper FLOAT;
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS memory_usage_lower FLOAT;
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS memory_usage_upper FLOAT;
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS window_hours INTEGER;
      ALTER TABLE agent_baselines ADD COLUMN IF NOT EXISTS data_points INTEGER;
    EXCEPTION
      WHEN undefined_table THEN NULL;
    END $$;
    """, ""

    execute "CREATE UNIQUE INDEX IF NOT EXISTS agent_baselines_agent_id_index ON agent_baselines(agent_id)", ""
    execute "CREATE INDEX IF NOT EXISTS agent_baselines_calculated_at_index ON agent_baselines(calculated_at)", ""
  end
end
