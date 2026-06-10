defmodule TamanduaServer.Repo.Migrations.ReconcileAuditLogsSchema do
  use Ecto.Migration

  def change do
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS action_type VARCHAR", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_email VARCHAR", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS details JSONB DEFAULT '{}'::jsonb", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS changes JSONB DEFAULT '{}'::jsonb", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS category VARCHAR DEFAULT 'security'", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS severity VARCHAR DEFAULT 'info'", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS success BOOLEAN DEFAULT TRUE", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS error_message VARCHAR", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address VARCHAR", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_agent VARCHAR", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS request_id VARCHAR", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS suspicious BOOLEAN DEFAULT FALSE", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS suspicious_reason VARCHAR", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS sequence_number BIGINT", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS entry_hash VARCHAR", ""
    execute "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS previous_hash VARCHAR", ""

    execute """
    UPDATE audit_logs
    SET
      action_type = COALESCE(NULLIF(action_type, ''), category, 'security'),
      category = COALESCE(NULLIF(category, ''), 'security'),
      severity = COALESCE(NULLIF(severity, ''), 'info'),
      details = COALESCE(details, metadata, '{}'::jsonb),
      metadata = COALESCE(metadata, details, '{}'::jsonb),
      changes = COALESCE(changes, '{}'::jsonb),
      success = COALESCE(success, TRUE),
      suspicious = COALESCE(suspicious, FALSE),
      risk_score = COALESCE(risk_score, 0)
    """, ""

    execute """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'audit_logs'
          AND column_name = 'resource_id'
          AND data_type <> 'character varying'
      ) THEN
        ALTER TABLE audit_logs ALTER COLUMN resource_id TYPE VARCHAR USING resource_id::text;
      END IF;
    END $$;
    """, ""

    create_if_not_exists index(:audit_logs, [:organization_id])
    create_if_not_exists index(:audit_logs, [:action_type])
    create_if_not_exists index(:audit_logs, [:severity])
    create_if_not_exists index(:audit_logs, [:category])
    create_if_not_exists index(:audit_logs, [:resource_type])
    create_if_not_exists index(:audit_logs, [:resource_id])
    create_if_not_exists index(:audit_logs, [:inserted_at])
  end
end
