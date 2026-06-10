defmodule TamanduaServer.Repo.Migrations.CreatePlaybookExecutions do
  use Ecto.Migration

  def change do
    # Add missing fields to playbooks table if not present (using raw SQL for proper IF NOT EXISTS)
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='require_approval') THEN
        ALTER TABLE playbooks ADD COLUMN require_approval boolean DEFAULT false;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='approval_timeout_minutes') THEN
        ALTER TABLE playbooks ADD COLUMN approval_timeout_minutes integer DEFAULT 30;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='tags') THEN
        ALTER TABLE playbooks ADD COLUMN tags varchar(255)[] DEFAULT '{}';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='severity_threshold') THEN
        ALTER TABLE playbooks ADD COLUMN severity_threshold varchar(255);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='execution_count') THEN
        ALTER TABLE playbooks ADD COLUMN execution_count integer DEFAULT 0;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='success_count') THEN
        ALTER TABLE playbooks ADD COLUMN success_count integer DEFAULT 0;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='last_executed_at') THEN
        ALTER TABLE playbooks ADD COLUMN last_executed_at timestamp;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='created_by') THEN
        ALTER TABLE playbooks ADD COLUMN created_by uuid REFERENCES users(id) ON DELETE SET NULL;
      END IF;
    END $$;
    """, ""

    # Create playbook_executions table for tracking execution history
    # Note: Use uuid type for foreign key to match playbooks.id (binary_id = uuid)
    create_if_not_exists table(:playbook_executions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :playbook_id, references(:playbooks, type: :uuid, on_delete: :delete_all), null: false
      add :trigger_event, :map
      add :status, :string, null: false  # pending_approval, running, completed, failed, cancelled
      add :steps_completed, {:array, :map}, default: []
      add :current_step, :integer, default: 0
      add :error_message, :text
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime
      add :approved_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :approved_at, :utc_datetime
      add :execution_context, :map, default: %{}
      add :dry_run, :boolean, default: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime)
    end

    create_if_not_exists index(:playbook_executions, [:playbook_id])
    create_if_not_exists index(:playbook_executions, [:status])
    create_if_not_exists index(:playbook_executions, [:started_at])
    create_if_not_exists index(:playbook_executions, [:approved_by])
    create_if_not_exists index(:playbook_executions, [:organization_id])
  end
end
