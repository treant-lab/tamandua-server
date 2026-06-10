defmodule TamanduaServer.Repo.Migrations.AddAlertVerdicts do
  use Ecto.Migration

  def change do
    # Add verdict fields to alerts table
    # Use raw SQL with IF NOT EXISTS to avoid duplicate column errors
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='verdict') THEN
        ALTER TABLE alerts ADD COLUMN verdict varchar(255) DEFAULT 'unconfirmed';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='verdict_by_id') THEN
        ALTER TABLE alerts ADD COLUMN verdict_by_id uuid REFERENCES users(id) ON DELETE SET NULL;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='verdict_at') THEN
        ALTER TABLE alerts ADD COLUMN verdict_at timestamp;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='verdict_notes') THEN
        ALTER TABLE alerts ADD COLUMN verdict_notes text;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='suppression_rule_id') THEN
        ALTER TABLE alerts ADD COLUMN suppression_rule_id uuid;
      END IF;
    END $$;
    """, ""

    create_if_not_exists index(:alerts, [:verdict])
    create_if_not_exists index(:alerts, [:verdict_by_id])
    create_if_not_exists index(:alerts, [:verdict, :agent_id])

    # Create alert_suppression_rules table
    create_if_not_exists table(:alert_suppression_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :enabled, :boolean, default: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :created_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :source_alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all)

      # Matching criteria (all optional -- matched with AND logic)
      add :rule_name_pattern, :string
      add :agent_id, :binary_id
      add :process_name_pattern, :string
      add :parent_process_pattern, :string
      add :file_path_pattern, :string
      add :title_pattern, :string
      add :severity, :string
      add :mitre_techniques, {:array, :string}, default: []

      # Full criteria stored as JSON for complex matching
      add :criteria, :map, default: %{}

      # TTL and tracking
      add :expires_at, :utc_datetime_usec
      add :match_count, :integer, default: 0
      add :last_matched_at, :utc_datetime_usec
      add :max_matches, :integer  # nil = unlimited

      # Action: suppress, reduce_severity, tag
      add :action, :string, default: "suppress"
      add :reduce_to_severity, :string  # if action is reduce_severity

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:alert_suppression_rules, [:organization_id])
    create_if_not_exists index(:alert_suppression_rules, [:enabled])
    create_if_not_exists index(:alert_suppression_rules, [:agent_id])
    create_if_not_exists index(:alert_suppression_rules, [:expires_at])
    create_if_not_exists index(:alert_suppression_rules, [:rule_name_pattern])

    # Create verdict_feedback_log for audit trail of all verdict changes
    create_if_not_exists table(:verdict_feedback_log, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :previous_verdict, :string
      add :new_verdict, :string, null: false
      add :notes, :text
      add :suppression_rule_created, :boolean, default: false
      add :baseline_updated, :boolean, default: false
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:verdict_feedback_log, [:alert_id])
    create_if_not_exists index(:verdict_feedback_log, [:user_id])
    create_if_not_exists index(:verdict_feedback_log, [:new_verdict])
    create_if_not_exists index(:verdict_feedback_log, [:inserted_at])
  end
end
