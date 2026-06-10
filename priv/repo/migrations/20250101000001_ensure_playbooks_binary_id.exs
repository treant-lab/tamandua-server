defmodule TamanduaServer.Repo.Migrations.EnsurePlaybooksBinaryId do
  use Ecto.Migration

  @doc """
  Ensures the playbooks table uses binary_id for primary key.
  This migration handles the case where the table might have been created
  with bigint id before the project standardized on binary_id.
  """
  def up do
    # Check if playbooks table exists and has wrong id type
    # If so, we need to recreate it with the correct type
    execute """
    DO $$
    BEGIN
      -- Check if playbooks table exists with bigint id
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'playbooks'
        AND column_name = 'id'
        AND data_type = 'bigint'
      ) THEN
        -- Drop any foreign key constraints referencing playbooks
        ALTER TABLE IF EXISTS playbook_executions DROP CONSTRAINT IF EXISTS playbook_executions_playbook_id_fkey;

        -- Drop the old table and recreate
        DROP TABLE IF EXISTS playbooks CASCADE;

        -- Create table with binary_id
        CREATE TABLE playbooks (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          name varchar(255) NOT NULL,
          description text,
          trigger_type varchar(255),
          trigger_conditions jsonb,
          steps jsonb DEFAULT '[]'::jsonb,
          enabled boolean DEFAULT true,
          inserted_at timestamp(0) without time zone NOT NULL DEFAULT now(),
          updated_at timestamp(0) without time zone NOT NULL DEFAULT now()
        );

        CREATE INDEX IF NOT EXISTS playbooks_name_index ON playbooks(name);
        CREATE INDEX IF NOT EXISTS playbooks_trigger_type_index ON playbooks(trigger_type);
        CREATE INDEX IF NOT EXISTS playbooks_enabled_index ON playbooks(enabled);
      END IF;
    END $$;
    """
  end

  def down do
    # No rollback needed - this is a fix migration
    :ok
  end
end
