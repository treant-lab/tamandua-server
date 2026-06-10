defmodule TamanduaServer.Repo.Migrations.AddConsumedAgentToInstallationTokens do
  use Ecto.Migration

  def up do
    execute("ALTER TABLE installation_tokens ADD COLUMN IF NOT EXISTS consumed_at timestamp(6) without time zone")
    execute("ALTER TABLE installation_tokens ADD COLUMN IF NOT EXISTS consumed_agent_id uuid")

    execute("""
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'installation_tokens'::regclass
          AND conname = 'installation_tokens_consumed_agent_id_fkey'
      ) THEN
        ALTER TABLE installation_tokens
          ADD CONSTRAINT installation_tokens_consumed_agent_id_fkey
          FOREIGN KEY (consumed_agent_id)
          REFERENCES agents(id)
          ON DELETE SET NULL;
      END IF;
    END $$;
    """)

    create_if_not_exists index(:installation_tokens, [:consumed_agent_id])
  end

  def down do
    drop_if_exists index(:installation_tokens, [:consumed_agent_id])
    execute("ALTER TABLE installation_tokens DROP CONSTRAINT IF EXISTS installation_tokens_consumed_agent_id_fkey")
    execute("ALTER TABLE installation_tokens DROP COLUMN IF EXISTS consumed_agent_id")
    execute("ALTER TABLE installation_tokens DROP COLUMN IF EXISTS consumed_at")
  end
end
