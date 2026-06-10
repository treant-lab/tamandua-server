defmodule TamanduaServer.Repo.Migrations.CreateAuditRetentionPolicies do
  use Ecto.Migration

  def change do
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_retention_policies') THEN
        CREATE TABLE audit_retention_policies (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          name VARCHAR NOT NULL,
          description VARCHAR,
          retention_days INTEGER NOT NULL,
          archive_after_days INTEGER,
          archive_enabled BOOLEAN DEFAULT FALSE,
          compression_enabled BOOLEAN DEFAULT TRUE,
          archive_type VARCHAR,
          archive_config JSONB DEFAULT '{}',
          legal_hold BOOLEAN DEFAULT FALSE,
          legal_hold_reason VARCHAR,
          legal_hold_until TIMESTAMP WITH TIME ZONE,
          applies_to_actions TEXT[] DEFAULT '{}',
          applies_to_categories TEXT[] DEFAULT '{}',
          is_active BOOLEAN DEFAULT TRUE,
          last_run_at TIMESTAMP WITH TIME ZONE,
          next_run_at TIMESTAMP WITH TIME ZONE,
          inserted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        );
      ELSE
        -- Add any missing columns
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS name VARCHAR;
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS description VARCHAR;
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS retention_days INTEGER;
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS archive_after_days INTEGER;
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS archive_enabled BOOLEAN DEFAULT FALSE;
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS compression_enabled BOOLEAN DEFAULT TRUE;
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS archive_type VARCHAR;
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS archive_config JSONB DEFAULT '{}';
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN DEFAULT FALSE;
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS legal_hold_reason VARCHAR;
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS legal_hold_until TIMESTAMP WITH TIME ZONE;
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS applies_to_actions TEXT[] DEFAULT '{}';
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS applies_to_categories TEXT[] DEFAULT '{}';
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS last_run_at TIMESTAMP WITH TIME ZONE;
        ALTER TABLE audit_retention_policies ADD COLUMN IF NOT EXISTS next_run_at TIMESTAMP WITH TIME ZONE;
      END IF;
    END $$;
    """, ""

    execute "CREATE UNIQUE INDEX IF NOT EXISTS audit_retention_policies_organization_id_name_index ON audit_retention_policies(organization_id, name)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_retention_policies_is_active_next_run_at_index ON audit_retention_policies(is_active, next_run_at)", ""
  end
end
