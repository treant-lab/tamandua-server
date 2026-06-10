defmodule TamanduaServer.Repo.Migrations.CreateSuppressionSystem do
  use Ecto.Migration

  def change do
    # This migration may conflict with earlier suppression table migrations
    # Wrap everything in exception handlers to be idempotent
    execute """
    DO $$
    BEGIN
      -- Only run if the table doesn't exist OR if it exists but is missing columns we need
      IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'alert_suppression_rules')
         OR NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'alert_suppression_rules' AND column_name = 'priority') THEN

        -- Add any missing columns to existing table
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'alert_suppression_rules') THEN
          ALTER TABLE alert_suppression_rules ADD COLUMN IF NOT EXISTS priority integer DEFAULT 0;
          ALTER TABLE alert_suppression_rules ADD COLUMN IF NOT EXISTS is_template boolean DEFAULT false;
          ALTER TABLE alert_suppression_rules ADD COLUMN IF NOT EXISTS template_name varchar;
          ALTER TABLE alert_suppression_rules ADD COLUMN IF NOT EXISTS template_description text;
        END IF;
      END IF;
    EXCEPTION
      WHEN OTHERS THEN NULL;
    END $$;
    """, ""

    # Create suppressed_alerts if not exists
    create_if_not_exists table(:suppressed_alerts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :title, :string, null: false
      add :description, :text
      add :severity, :string, null: false
      add :original_severity, :string
      add :mitre_tactics, {:array, :string}, default: []
      add :mitre_techniques, {:array, :string}, default: []
      add :threat_score, :float
      add :evidence, :map, default: %{}
      add :process_chain, {:array, :map}, default: []
      add :raw_event, :map
      add :detection_metadata, :map, default: %{}
      add :suppression_reason, :string, null: false
      add :suppression_type, :string, null: false
      add :suppressed_at, :utc_datetime_usec, null: false
      add :unsuppress_at, :utc_datetime_usec
      add :unsuppressed, :boolean, default: false, null: false
      add :unsuppressed_at, :utc_datetime_usec
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :suppression_rule_id, references(:alert_suppression_rules, type: :binary_id, on_delete: :nilify_all)
      add :suppressed_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :unsuppressed_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :unsuppressed_alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all)
      timestamps(type: :utc_datetime_usec)
    end

    # Create indexes safely
    execute "CREATE INDEX IF NOT EXISTS suppressed_alerts_org_idx ON suppressed_alerts(organization_id)", ""
    execute "CREATE INDEX IF NOT EXISTS suppressed_alerts_agent_idx ON suppressed_alerts(agent_id)", ""
    execute "CREATE INDEX IF NOT EXISTS suppressed_alerts_rule_idx ON suppressed_alerts(suppression_rule_id)", ""

    # Create suppression_analytics if not exists
    create_if_not_exists table(:suppression_analytics, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :period_start, :utc_datetime_usec, null: false
      add :period_end, :utc_datetime_usec, null: false
      add :period_type, :string, null: false
      add :total_alerts, :integer, default: 0
      add :suppressed_count, :integer, default: 0
      add :suppression_rate, :float, default: 0.0
      add :false_positive_reduction, :float, default: 0.0
      add :top_rules, :map, default: %{}
      add :suppressed_by_severity, :map, default: %{}
      add :suppressed_by_type, :map, default: %{}
      timestamps(type: :utc_datetime_usec)
    end

    # Create suppression_audit_log if not exists
    create_if_not_exists table(:suppression_audit_log, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :action, :string, null: false
      add :resource_type, :string, null: false
      add :resource_id, :binary_id
      add :changes, :map, default: %{}
      add :metadata, :map, default: %{}
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :occurred_at, :utc_datetime_usec, null: false
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end
  end
end
