defmodule TamanduaServer.Repo.Migrations.CreateFpAnalysisTables do
  @moduledoc """
  Creates tables for False Positive Analysis and Tuning System.

  This migration establishes:
  - fp_reports: Analyst feedback on alerts (true positive / false positive)
  - rule_quality_metrics: Per-rule FP/TP statistics and quality scores
  - baseline_profiles: Environment-specific behavioral baselines
  - fp_patterns: Detected patterns of false positives for auto-tuning
  - tuning_recommendations: AI-generated tuning suggestions
  """

  use Ecto.Migration

  def change do
    # =========================================================================
    # FP Reports - Analyst feedback on alerts
    # =========================================================================
    create_if_not_exists table(:fp_reports, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :reported_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      # Classification
      add :classification, :string, null: false  # "true_positive", "false_positive", "benign", "suspicious"
      add :confidence, :float, default: 1.0  # Analyst confidence in classification (0.0-1.0)

      # Context and reasoning
      add :reason, :string  # Primary reason category
      add :reason_detail, :text  # Detailed explanation
      add :tags, {:array, :string}, default: []

      # Alert snapshot at time of report
      add :alert_snapshot, :map, default: %{}  # Copy of key alert fields

      # Detection source info
      add :detection_source, :string  # "yara", "sigma", "ml", "behavioral", "ioc"
      add :rule_id, :string  # ID/name of the triggering rule
      add :rule_name, :string

      # Environmental context
      add :agent_id, :binary_id
      add :hostname, :string
      add :os_type, :string  # "windows", "linux", "macos"
      add :asset_criticality, :string  # "critical", "high", "medium", "low"

      # Process/file context
      add :process_name, :string
      add :file_path, :string
      add :file_hash, :string
      add :command_line, :text

      # User context (from event)
      add :event_user, :string
      add :user_role, :string

      # Actions taken
      add :suppression_rule_created, :boolean, default: false
      add :suppression_rule_id, :binary_id
      add :baseline_updated, :boolean, default: false
      add :threshold_adjusted, :boolean, default: false

      # Review workflow
      add :reviewed, :boolean, default: false
      add :reviewed_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :reviewed_at, :utc_datetime_usec
      add :review_notes, :text

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:fp_reports, [:alert_id])
    create_if_not_exists index(:fp_reports, [:organization_id])
    create_if_not_exists index(:fp_reports, [:reported_by_id])
    create_if_not_exists index(:fp_reports, [:classification])
    create_if_not_exists index(:fp_reports, [:detection_source])
    create_if_not_exists index(:fp_reports, [:rule_id])
    create_if_not_exists index(:fp_reports, [:rule_name])
    create_if_not_exists index(:fp_reports, [:agent_id])
    create_if_not_exists index(:fp_reports, [:inserted_at])
    create_if_not_exists index(:fp_reports, [:organization_id, :detection_source])
    create_if_not_exists index(:fp_reports, [:organization_id, :classification])

    # =========================================================================
    # Rule Quality Metrics - Per-rule FP/TP statistics
    # =========================================================================
    create_if_not_exists table(:rule_quality_metrics, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      # Rule identification
      add :detection_source, :string, null: false  # "yara", "sigma", "ml", "behavioral", "ioc"
      add :rule_id, :string, null: false  # ID/name of the rule
      add :rule_name, :string
      add :rule_version, :string

      # Core metrics (rolling 30-day window by default)
      add :total_alerts, :integer, default: 0
      add :true_positives, :integer, default: 0
      add :false_positives, :integer, default: 0
      add :benign_count, :integer, default: 0
      add :suspicious_count, :integer, default: 0
      add :unclassified_count, :integer, default: 0

      # Calculated metrics
      add :precision, :float  # TP / (TP + FP)
      add :fp_rate, :float    # FP / Total
      add :quality_score, :float  # Composite quality score (0.0-1.0)

      # Trend data
      add :fp_rate_7d, :float  # FP rate last 7 days
      add :fp_rate_30d, :float  # FP rate last 30 days
      add :fp_rate_trend, :string  # "improving", "stable", "degrading"

      # Time-based patterns
      add :fp_by_hour, :map, default: %{}  # Hour -> FP count
      add :fp_by_day_of_week, :map, default: %{}  # Day -> FP count

      # Environment patterns
      add :fp_by_os, :map, default: %{}  # OS -> FP count
      add :fp_by_asset_criticality, :map, default: %{}

      # Common FP contexts
      add :top_fp_processes, {:array, :map}, default: []  # [{process: "...", count: N}, ...]
      add :top_fp_paths, {:array, :map}, default: []
      add :top_fp_users, {:array, :map}, default: []
      add :top_fp_agents, {:array, :map}, default: []

      # Suppression effectiveness
      add :suppressed_alerts, :integer, default: 0
      add :unsuppressed_fp_alerts, :integer, default: 0

      # Recommendation status
      add :tuning_recommendation, :string  # "tune_threshold", "add_exclusion", "disable", "none"
      add :recommended_action, :map, default: %{}  # Specific recommendation details
      add :last_recommendation_at, :utc_datetime_usec

      # Metadata
      add :last_alert_at, :utc_datetime_usec
      add :first_alert_at, :utc_datetime_usec
      add :metrics_window_start, :utc_datetime_usec
      add :metrics_window_end, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:rule_quality_metrics, [:organization_id])
    create_if_not_exists index(:rule_quality_metrics, [:detection_source])
    create_if_not_exists index(:rule_quality_metrics, [:rule_id])
    create_if_not_exists index(:rule_quality_metrics, [:quality_score])
    create_if_not_exists index(:rule_quality_metrics, [:fp_rate])
    create_if_not_exists unique_index(:rule_quality_metrics, [:organization_id, :detection_source, :rule_id])

    # =========================================================================
    # Baseline Profiles - Environment-specific behavioral baselines
    # =========================================================================
    create_if_not_exists table(:baseline_profiles, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      # Profile identification
      add :profile_type, :string, null: false  # "organization", "agent_group", "agent", "user", "asset_type"
      add :profile_key, :string, null: false   # The specific identifier (org_id, agent_id, user, etc.)
      add :profile_name, :string

      # Status
      add :status, :string, default: "learning"  # "learning", "active", "frozen", "stale"
      add :learning_started_at, :utc_datetime_usec
      add :learning_completed_at, :utc_datetime_usec
      add :learning_days, :integer, default: 7

      # Event statistics
      add :total_events_processed, :integer, default: 0
      add :events_per_day_avg, :float, default: 0.0
      add :events_per_hour_histogram, :map, default: %{}

      # Process baselines
      add :normal_processes, {:array, :string}, default: []  # Commonly seen process names
      add :process_frequencies, :map, default: %{}  # process -> frequency
      add :process_parent_pairs, {:array, :map}, default: []  # [{parent: "...", child: "..."}, ...]

      # Network baselines
      add :normal_destinations, {:array, :string}, default: []  # Commonly accessed IPs/domains
      add :normal_ports, {:array, :integer}, default: []
      add :network_volume_baseline, :map, default: %{}  # Stats on bytes in/out

      # File access baselines
      add :normal_file_paths, {:array, :string}, default: []
      add :normal_file_extensions, {:array, :string}, default: []

      # Authentication baselines
      add :normal_login_hours, {:array, :integer}, default: []  # 0-23
      add :normal_login_days, {:array, :integer}, default: []   # 1-7
      add :normal_auth_sources, {:array, :string}, default: []

      # Detection baselines (what rules normally fire)
      add :expected_rules, {:array, :string}, default: []  # Rules that commonly fire
      add :rule_frequencies, :map, default: %{}  # rule -> avg daily count

      # Anomaly thresholds (derived from baseline)
      add :thresholds, :map, default: %{}  # {metric: {mean, stddev, threshold}}

      # Metadata
      add :last_updated_at, :utc_datetime_usec
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:baseline_profiles, [:organization_id])
    create_if_not_exists index(:baseline_profiles, [:profile_type])
    create_if_not_exists index(:baseline_profiles, [:profile_key])
    create_if_not_exists index(:baseline_profiles, [:status])
    create_if_not_exists unique_index(:baseline_profiles, [:organization_id, :profile_type, :profile_key])

    # =========================================================================
    # FP Patterns - Detected patterns of false positives
    # =========================================================================
    create_if_not_exists table(:fp_patterns, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      # Pattern identification
      add :pattern_type, :string, null: false  # "process", "path", "time", "user", "rule", "agent", "combined"
      add :pattern_key, :string, null: false   # Unique identifier for the pattern

      # Pattern details
      add :pattern_data, :map, null: false, default: %{}  # The actual pattern definition
      add :description, :text

      # Detection source association
      add :detection_source, :string  # "yara", "sigma", "ml", "behavioral", or nil for cross-source
      add :associated_rules, {:array, :string}, default: []

      # Statistics
      add :fp_count, :integer, default: 0  # Number of FPs matching this pattern
      add :tp_count, :integer, default: 0  # Number of TPs matching this pattern (should be low)
      add :total_matches, :integer, default: 0
      add :fp_confidence, :float, default: 0.0  # Confidence this pattern indicates FP

      # Example alerts matching this pattern
      add :example_alert_ids, {:array, :binary_id}, default: []

      # Auto-tuning status
      add :suppression_created, :boolean, default: false
      add :suppression_rule_id, :binary_id
      add :auto_tuned_at, :utc_datetime_usec

      # Manual review
      add :reviewed, :boolean, default: false
      add :reviewed_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :reviewed_at, :utc_datetime_usec
      add :review_action, :string  # "approve_suppression", "reject", "modify", "pending"

      # Time window
      add :first_seen_at, :utc_datetime_usec
      add :last_seen_at, :utc_datetime_usec

      # Status
      add :status, :string, default: "detected"  # "detected", "confirmed", "rejected", "tuned"

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:fp_patterns, [:organization_id])
    create_if_not_exists index(:fp_patterns, [:pattern_type])
    create_if_not_exists index(:fp_patterns, [:detection_source])
    create_if_not_exists index(:fp_patterns, [:fp_confidence])
    create_if_not_exists index(:fp_patterns, [:status])
    create_if_not_exists unique_index(:fp_patterns, [:organization_id, :pattern_type, :pattern_key])

    # =========================================================================
    # Tuning Recommendations - AI-generated tuning suggestions
    # =========================================================================
    create_if_not_exists table(:tuning_recommendations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      # Recommendation type
      add :recommendation_type, :string, null: false  # "threshold_adjustment", "exclusion_rule", "disable_rule", "modify_rule", "baseline_update"

      # Target
      add :target_type, :string, null: false  # "rule", "detection_source", "agent", "environment"
      add :target_id, :string  # Rule ID, agent ID, etc.
      add :target_name, :string

      # Recommendation details
      add :title, :string, null: false
      add :description, :text
      add :rationale, :text  # Why this recommendation was generated
      add :impact_assessment, :text  # Expected impact of applying

      # Specific action
      add :action_data, :map, null: false, default: %{}  # Specific parameters for the recommendation
      # Example: %{type: "threshold", old_value: 0.7, new_value: 0.85}
      # Example: %{type: "exclusion", criteria: %{process_name: "...", path: "..."}}

      # Supporting data
      add :supporting_metrics, :map, default: %{}  # Metrics that support this recommendation
      add :related_fp_report_ids, {:array, :binary_id}, default: []
      add :related_pattern_ids, {:array, :binary_id}, default: []

      # Confidence and priority
      add :confidence, :float, default: 0.5  # 0.0-1.0
      add :priority, :string, default: "medium"  # "critical", "high", "medium", "low"
      add :estimated_fp_reduction, :float  # Estimated % reduction in FPs

      # Status
      add :status, :string, default: "pending"  # "pending", "approved", "rejected", "applied", "expired"
      add :expires_at, :utc_datetime_usec  # Recommendations can expire if not acted on

      # Application tracking
      add :applied_at, :utc_datetime_usec
      add :applied_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :applied_result, :map, default: %{}  # Result of applying the recommendation

      # Review
      add :reviewed_at, :utc_datetime_usec
      add :reviewed_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :review_notes, :text

      # Effectiveness tracking (post-application)
      add :effectiveness_measured, :boolean, default: false
      add :effectiveness_score, :float  # How well did this recommendation work?
      add :measured_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:tuning_recommendations, [:organization_id])
    create_if_not_exists index(:tuning_recommendations, [:recommendation_type])
    create_if_not_exists index(:tuning_recommendations, [:target_type])
    create_if_not_exists index(:tuning_recommendations, [:target_id])
    create_if_not_exists index(:tuning_recommendations, [:status])
    create_if_not_exists index(:tuning_recommendations, [:priority])
    create_if_not_exists index(:tuning_recommendations, [:confidence])
    create_if_not_exists index(:tuning_recommendations, [:inserted_at])

    # =========================================================================
    # Add FP-related columns to suppression rules if not exist
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alert_suppression_rules' AND column_name='fp_pattern_id') THEN
        ALTER TABLE alert_suppression_rules ADD COLUMN fp_pattern_id uuid;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alert_suppression_rules' AND column_name='auto_generated') THEN
        ALTER TABLE alert_suppression_rules ADD COLUMN auto_generated boolean DEFAULT false;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alert_suppression_rules' AND column_name='tuning_recommendation_id') THEN
        ALTER TABLE alert_suppression_rules ADD COLUMN tuning_recommendation_id uuid;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alert_suppression_rules' AND column_name='effectiveness_score') THEN
        ALTER TABLE alert_suppression_rules ADD COLUMN effectiveness_score float;
      END IF;
    END $$;
    """, ""
  end
end
