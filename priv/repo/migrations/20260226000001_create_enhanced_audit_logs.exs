defmodule TamanduaServer.Repo.Migrations.CreateEnhancedAuditLogs do
  use Ecto.Migration

  def change do
    # Only create table if it doesn't exist
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_logs') THEN
        CREATE TABLE audit_logs (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID REFERENCES users(id) ON DELETE SET NULL,
          organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          action VARCHAR NOT NULL,
          resource_type VARCHAR NOT NULL,
          resource_id UUID,
          metadata JSONB DEFAULT '{}',
          changes JSONB DEFAULT '{}',
          ip_address VARCHAR,
          user_agent VARCHAR,
          request_id VARCHAR,
          success BOOLEAN DEFAULT TRUE,
          error_message VARCHAR,
          severity VARCHAR DEFAULT 'info',
          category VARCHAR,
          suspicious BOOLEAN DEFAULT FALSE,
          suspicious_reason VARCHAR,
          risk_score INTEGER DEFAULT 0,
          search_vector TSVECTOR,
          inserted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        );
      ELSE
        -- Add any missing columns to existing table
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS suspicious BOOLEAN DEFAULT FALSE;
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS suspicious_reason VARCHAR;
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS search_vector TSVECTOR;
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS category VARCHAR;
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS severity VARCHAR DEFAULT 'info';
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS success BOOLEAN DEFAULT TRUE;
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS error_message VARCHAR;
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address VARCHAR;
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_agent VARCHAR;
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS request_id VARCHAR;
      END IF;
    END $$;
    """, ""

    # Create indexes safely
    execute "CREATE INDEX IF NOT EXISTS audit_logs_organization_id_idx ON audit_logs(organization_id)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_logs_user_id_idx ON audit_logs(user_id)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_logs_action_idx ON audit_logs(action)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_logs_resource_type_idx ON audit_logs(resource_type)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_logs_resource_id_idx ON audit_logs(resource_id)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_logs_inserted_at_idx ON audit_logs(inserted_at)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_logs_suspicious_idx ON audit_logs(suspicious)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_logs_category_idx ON audit_logs(category)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_logs_ip_address_idx ON audit_logs(ip_address)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_logs_success_idx ON audit_logs(success)", ""

    # Composite indexes
    execute "CREATE INDEX IF NOT EXISTS audit_logs_org_inserted_idx ON audit_logs(organization_id, inserted_at)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_logs_org_user_inserted_idx ON audit_logs(organization_id, user_id, inserted_at)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_logs_org_action_inserted_idx ON audit_logs(organization_id, action, inserted_at)", ""
    execute "CREATE INDEX IF NOT EXISTS audit_logs_org_suspicious_inserted_idx ON audit_logs(organization_id, suspicious, inserted_at)", ""

    # Full-text search index
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'audit_logs_search_vector_idx') THEN
        CREATE INDEX audit_logs_search_vector_idx ON audit_logs USING gin(search_vector);
      END IF;
    END $$;
    """, ""

    # Function to update search vector
    execute """
    CREATE OR REPLACE FUNCTION audit_logs_search_vector_update() RETURNS trigger AS $$
    BEGIN
      NEW.search_vector :=
        setweight(to_tsvector('english', COALESCE(NEW.action, '')), 'A') ||
        setweight(to_tsvector('english', COALESCE(NEW.resource_type, '')), 'B') ||
        setweight(to_tsvector('english', COALESCE(NEW.metadata::text, '')), 'C') ||
        setweight(to_tsvector('english', COALESCE(NEW.error_message, '')), 'D');
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """, ""

    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'audit_logs_search_vector_trigger') THEN
        CREATE TRIGGER audit_logs_search_vector_trigger
        BEFORE INSERT OR UPDATE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION audit_logs_search_vector_update();
      END IF;
    END $$;
    """, "DROP TRIGGER IF EXISTS audit_logs_search_vector_trigger ON audit_logs"
  end
end
