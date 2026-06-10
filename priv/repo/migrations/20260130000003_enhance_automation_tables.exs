defmodule TamanduaServer.Repo.Migrations.EnhanceAutomationTables do
  use Ecto.Migration

  def change do
    # ==========================================================================
    # Rename existing tables to match the Hyperautomation schema names
    # Use conditional SQL to avoid errors if already renamed
    # ==========================================================================
    execute(
      """
      DO $$
      BEGIN
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'workflows') THEN
          ALTER TABLE workflows RENAME TO automation_workflows;
        END IF;
      END $$;
      """,
      """
      DO $$
      BEGIN
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'automation_workflows') THEN
          ALTER TABLE automation_workflows RENAME TO workflows;
        END IF;
      END $$;
      """
    )

    execute(
      """
      DO $$
      BEGIN
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'workflow_executions') THEN
          ALTER TABLE workflow_executions RENAME TO automation_executions;
        END IF;
      END $$;
      """,
      """
      DO $$
      BEGIN
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'automation_executions') THEN
          ALTER TABLE automation_executions RENAME TO workflow_executions;
        END IF;
      END $$;
      """
    )

    # ==========================================================================
    # Add missing columns to automation_workflows
    # Use raw SQL with IF NOT EXISTS for columns that may already exist
    # (organization_id may have been added by AddMultitenancyOrganizationIds)
    # ==========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='version') THEN
        ALTER TABLE automation_workflows ADD COLUMN version integer DEFAULT 1;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='category') THEN
        ALTER TABLE automation_workflows ADD COLUMN category varchar(255);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='tags') THEN
        ALTER TABLE automation_workflows ADD COLUMN tags varchar(255)[] DEFAULT '{}';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='variables') THEN
        ALTER TABLE automation_workflows ADD COLUMN variables jsonb DEFAULT '{}'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='error_handlers') THEN
        ALTER TABLE automation_workflows ADD COLUMN error_handlers jsonb DEFAULT '[]'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='timeout_seconds') THEN
        ALTER TABLE automation_workflows ADD COLUMN timeout_seconds integer DEFAULT 3600;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='max_retries') THEN
        ALTER TABLE automation_workflows ADD COLUMN max_retries integer DEFAULT 3;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='retry_delay_seconds') THEN
        ALTER TABLE automation_workflows ADD COLUMN retry_delay_seconds integer DEFAULT 30;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='concurrency_limit') THEN
        ALTER TABLE automation_workflows ADD COLUMN concurrency_limit integer DEFAULT 10;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='require_approval') THEN
        ALTER TABLE automation_workflows ADD COLUMN require_approval boolean DEFAULT false;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='approval_roles') THEN
        ALTER TABLE automation_workflows ADD COLUMN approval_roles varchar(255)[] DEFAULT '{}';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='approval_timeout_minutes') THEN
        ALTER TABLE automation_workflows ADD COLUMN approval_timeout_minutes integer DEFAULT 60;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='ai_generated') THEN
        ALTER TABLE automation_workflows ADD COLUMN ai_generated boolean DEFAULT false;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='ai_suggestions') THEN
        ALTER TABLE automation_workflows ADD COLUMN ai_suggestions jsonb DEFAULT '[]'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='confidence_score') THEN
        ALTER TABLE automation_workflows ADD COLUMN confidence_score float;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='execution_count') THEN
        ALTER TABLE automation_workflows ADD COLUMN execution_count integer DEFAULT 0;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='success_count') THEN
        ALTER TABLE automation_workflows ADD COLUMN success_count integer DEFAULT 0;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='avg_duration_seconds') THEN
        ALTER TABLE automation_workflows ADD COLUMN avg_duration_seconds float;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='last_executed_at') THEN
        ALTER TABLE automation_workflows ADD COLUMN last_executed_at timestamp;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_workflows' AND column_name='organization_id') THEN
        ALTER TABLE automation_workflows ADD COLUMN organization_id uuid;
      END IF;
    END $$;
    """, ""

    # Update created_by column from :string to :binary_id by adding a new column
    # and dropping the old one (Ecto migrations cannot alter column types directly)
    # Use conditional SQL to handle cases where the column has already been converted
    execute(
      """
      DO $$
      BEGIN
        -- Only convert if created_by is still varchar type (not already uuid)
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'automation_workflows' AND column_name = 'created_by' AND data_type = 'character varying'
        ) THEN
          ALTER TABLE automation_workflows ADD COLUMN created_by_uuid uuid;
          ALTER TABLE automation_workflows DROP COLUMN created_by;
          ALTER TABLE automation_workflows RENAME COLUMN created_by_uuid TO created_by;
        ELSIF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'automation_workflows' AND column_name = 'created_by'
        ) THEN
          ALTER TABLE automation_workflows ADD COLUMN created_by uuid;
        END IF;
      END $$;
      """,
      "SELECT 1"
    )

    create_if_not_exists index(:automation_workflows, [:category])
    create_if_not_exists index(:automation_workflows, [:organization_id])
    create_if_not_exists index(:automation_workflows, [:ai_generated])

    execute(
      "CREATE UNIQUE INDEX IF NOT EXISTS automation_workflows_name_organization_id_index ON automation_workflows (name, organization_id)",
      "DROP INDEX IF EXISTS automation_workflows_name_organization_id_index"
    )

    # ==========================================================================
    # Add missing columns to automation_executions
    # Use raw SQL with IF NOT EXISTS to avoid duplicate column errors
    # ==========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='workflow_version') THEN
        ALTER TABLE automation_executions ADD COLUMN workflow_version integer;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='priority') THEN
        ALTER TABLE automation_executions ADD COLUMN priority integer DEFAULT 5;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='trigger_event') THEN
        ALTER TABLE automation_executions ADD COLUMN trigger_event jsonb DEFAULT '{}'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='input_variables') THEN
        ALTER TABLE automation_executions ADD COLUMN input_variables jsonb DEFAULT '{}'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='current_step_id') THEN
        ALTER TABLE automation_executions ADD COLUMN current_step_id varchar(255);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='completed_steps') THEN
        ALTER TABLE automation_executions ADD COLUMN completed_steps jsonb DEFAULT '[]'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='pending_steps') THEN
        ALTER TABLE automation_executions ADD COLUMN pending_steps varchar(255)[] DEFAULT '{}';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='step_results') THEN
        ALTER TABLE automation_executions ADD COLUMN step_results jsonb DEFAULT '{}'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='workflow_variables') THEN
        ALTER TABLE automation_executions ADD COLUMN workflow_variables jsonb DEFAULT '{}'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='error_message') THEN
        ALTER TABLE automation_executions ADD COLUMN error_message varchar(255);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='error_step_id') THEN
        ALTER TABLE automation_executions ADD COLUMN error_step_id varchar(255);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='retry_count') THEN
        ALTER TABLE automation_executions ADD COLUMN retry_count integer DEFAULT 0;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='last_error_at') THEN
        ALTER TABLE automation_executions ADD COLUMN last_error_at timestamp;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='approval_requested_at') THEN
        ALTER TABLE automation_executions ADD COLUMN approval_requested_at timestamp;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='approved_by') THEN
        ALTER TABLE automation_executions ADD COLUMN approved_by uuid;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='approved_at') THEN
        ALTER TABLE automation_executions ADD COLUMN approved_at timestamp;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='approval_notes') THEN
        ALTER TABLE automation_executions ADD COLUMN approval_notes varchar(255);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='duration_seconds') THEN
        ALTER TABLE automation_executions ADD COLUMN duration_seconds float;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='initiated_by') THEN
        ALTER TABLE automation_executions ADD COLUMN initiated_by uuid;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='correlation_id') THEN
        ALTER TABLE automation_executions ADD COLUMN correlation_id varchar(255);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='automation_executions' AND column_name='parent_execution_id') THEN
        ALTER TABLE automation_executions ADD COLUMN parent_execution_id uuid;
      END IF;
    END $$;
    """, ""

    # Update the workflow_id foreign key reference to point to renamed table
    # Drop old index and FK, re-create pointing to automation_workflows
    execute(
      "ALTER TABLE automation_executions DROP CONSTRAINT IF EXISTS workflow_executions_workflow_id_fkey",
      "SELECT 1"
    )

    execute(
      """
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.table_constraints
          WHERE constraint_name = 'automation_executions_workflow_id_fkey'
          AND table_name = 'automation_executions'
        ) THEN
          ALTER TABLE automation_executions ADD CONSTRAINT automation_executions_workflow_id_fkey
            FOREIGN KEY (workflow_id) REFERENCES automation_workflows(id) ON DELETE CASCADE;
        END IF;
      END $$;
      """,
      "SELECT 1"
    )

    # Change workflow_id to binary_id type to match the schema's @primary_key
    # The original migration used integer references; the schema expects binary_id
    # We need to convert both the PK of automation_workflows and the FK
    execute(
      """
      DO $$
      BEGIN
        -- Only convert if the column is still integer type
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'automation_workflows' AND column_name = 'id' AND data_type = 'bigint'
        ) THEN
          -- Drop constraints first
          ALTER TABLE automation_executions DROP CONSTRAINT IF EXISTS automation_executions_workflow_id_fkey;

          -- Convert automation_workflows PK to uuid
          ALTER TABLE automation_workflows DROP CONSTRAINT IF EXISTS workflows_pkey;
          ALTER TABLE automation_workflows ALTER COLUMN id DROP DEFAULT;
          ALTER TABLE automation_workflows ALTER COLUMN id SET DATA TYPE uuid USING gen_random_uuid();
          ALTER TABLE automation_workflows ADD PRIMARY KEY (id);

          -- Convert automation_executions PK to uuid
          ALTER TABLE automation_executions DROP CONSTRAINT IF EXISTS workflow_executions_pkey;
          ALTER TABLE automation_executions ALTER COLUMN id DROP DEFAULT;
          ALTER TABLE automation_executions ALTER COLUMN id SET DATA TYPE uuid USING gen_random_uuid();
          ALTER TABLE automation_executions ADD PRIMARY KEY (id);

          -- Convert workflow_id FK to uuid
          ALTER TABLE automation_executions ALTER COLUMN workflow_id SET DATA TYPE uuid USING gen_random_uuid();

          -- Re-add FK constraint
          ALTER TABLE automation_executions ADD CONSTRAINT automation_executions_workflow_id_fkey
            FOREIGN KEY (workflow_id) REFERENCES automation_workflows(id) ON DELETE CASCADE;
        END IF;
      END $$;
      """,
      "SELECT 1"
    )

    create_if_not_exists index(:automation_executions, [:priority])
    create_if_not_exists index(:automation_executions, [:correlation_id])
    create_if_not_exists index(:automation_executions, [:parent_execution_id])
    create_if_not_exists index(:automation_executions, [:started_at])

    # ==========================================================================
    # Create automation_audit_logs table
    # ==========================================================================
    create_if_not_exists table(:automation_audit_logs, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :execution_id, :binary_id
      add :workflow_id, :binary_id
      add :event_type, :string, null: false
      add :step_id, :string
      add :action_type, :string
      add :actor_id, :binary_id
      add :actor_type, :string
      add :target_type, :string
      add :target_id, :string
      add :details, :map, default: %{}
      add :outcome, :string, null: false
      add :duration_ms, :integer
      add :ip_address, :string
      add :user_agent, :string

      timestamps(updated_at: false)
    end

    create_if_not_exists index(:automation_audit_logs, [:execution_id])
    create_if_not_exists index(:automation_audit_logs, [:workflow_id])
    create_if_not_exists index(:automation_audit_logs, [:event_type])
    create_if_not_exists index(:automation_audit_logs, [:inserted_at])
  end
end
