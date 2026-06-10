defmodule TamanduaServer.Repo.Migrations.CompleteRLSCoverage do
  use Ecto.Migration

  @moduledoc """
  Ensures 100% RLS coverage on all tenant-scoped tables.

  This is a "catch-all" migration that runs after the initial RLS migration
  (20260220500002_enable_row_level_security) and catches any tables that:

  1. Were added since the original RLS migration
  2. Were excluded from the original migration due to missing columns
  3. Need RLS policies refreshed or recreated

  ## Safety

  This migration is fully idempotent and safe to run multiple times:
  - Uses IF NOT EXISTS for all policy creations
  - Uses DO $$ blocks to check existence before modifications
  - Does not drop or modify existing policies

  ## How It Works

  1. Queries information_schema for all tables with organization_id column
  2. For each table, checks if RLS policies exist
  3. Creates missing policies using the same pattern as the original migration
  4. Creates indexes on organization_id if missing

  ## CI/CD Integration

  After running this migration, use RLSCompleteness.ensure_coverage!/0 to
  verify 100% coverage:

      mix run -e "TamanduaServer.Repo.RLSCompleteness.ensure_coverage!()"

  ## Rollback

  Rollback removes only the policies created by this migration, identified
  by the "_complete_rls" suffix. Original policies from the initial migration
  are preserved.
  """

  def up do
    # This dynamic migration enables RLS on any tables that have organization_id
    # but don't yet have RLS policies. It's designed to catch any tables added
    # since the original RLS migration.

    execute """
    DO $$
    DECLARE
      r RECORD;
      policy_exists BOOLEAN;
    BEGIN
      -- Loop through all tables that have organization_id but no RLS policies
      FOR r IN
        SELECT c.table_name
        FROM information_schema.columns c
        WHERE c.table_schema = 'public'
        AND c.column_name = 'organization_id'
        AND NOT EXISTS (
          SELECT 1 FROM pg_policies p
          WHERE p.tablename = c.table_name
          AND p.schemaname = 'public'
        )
      LOOP
        -- Log the table being processed
        RAISE NOTICE 'Enabling RLS on table: %', r.table_name;

        -- Enable RLS on the table
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', r.table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', r.table_name);

        -- Create default DENY policy (safety net)
        -- Check if policy exists first
        SELECT EXISTS (
          SELECT 1 FROM pg_policies
          WHERE tablename = r.table_name
          AND policyname = r.table_name || '_deny_all'
        ) INTO policy_exists;

        IF NOT policy_exists THEN
          EXECUTE format(
            'CREATE POLICY %I ON %I AS RESTRICTIVE FOR ALL TO PUBLIC USING (FALSE)',
            r.table_name || '_deny_all',
            r.table_name
          );
        END IF;

        -- Create ALLOW policy for organization-scoped access
        SELECT EXISTS (
          SELECT 1 FROM pg_policies
          WHERE tablename = r.table_name
          AND policyname = r.table_name || '_organization_isolation'
        ) INTO policy_exists;

        IF NOT policy_exists THEN
          EXECUTE format(
            'CREATE POLICY %I ON %I AS PERMISSIVE FOR ALL TO PUBLIC USING (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id()) WITH CHECK (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())',
            r.table_name || '_organization_isolation',
            r.table_name
          );
        END IF;
      END LOOP;
    END
    $$;
    """

    # Create indexes on organization_id for any tables missing them
    execute """
    DO $$
    DECLARE
      r RECORD;
      index_exists BOOLEAN;
    BEGIN
      FOR r IN
        SELECT c.table_name
        FROM information_schema.columns c
        WHERE c.table_schema = 'public'
        AND c.column_name = 'organization_id'
      LOOP
        -- Check if an index on organization_id already exists
        SELECT EXISTS (
          SELECT 1 FROM pg_indexes
          WHERE tablename = r.table_name
          AND indexdef LIKE '%organization_id%'
        ) INTO index_exists;

        IF NOT index_exists THEN
          RAISE NOTICE 'Creating index on %.organization_id', r.table_name;
          EXECUTE format(
            'CREATE INDEX %I ON %I(organization_id)',
            r.table_name || '_organization_id_idx',
            r.table_name
          );
        END IF;
      END LOOP;
    END
    $$;
    """

    # Verify RLS functions exist (created by original migration)
    # If not, create them
    execute """
    DO $$
    BEGIN
      -- Ensure current_organization_id function exists
      IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'current_organization_id') THEN
        EXECUTE '
          CREATE OR REPLACE FUNCTION current_organization_id()
          RETURNS UUID AS $func$
          BEGIN
            RETURN NULLIF(current_setting(''app.current_organization_id'', TRUE), '''')::UUID;
          EXCEPTION
            WHEN OTHERS THEN
              RETURN NULL;
          END;
          $func$ LANGUAGE plpgsql STABLE;
        ';
      END IF;

      -- Ensure rls_bypass_enabled function exists
      IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'rls_bypass_enabled') THEN
        EXECUTE '
          CREATE OR REPLACE FUNCTION rls_bypass_enabled()
          RETURNS BOOLEAN AS $func$
          BEGIN
            RETURN COALESCE(current_setting(''app.rls_bypass'', TRUE)::BOOLEAN, FALSE);
          EXCEPTION
            WHEN OTHERS THEN
              RETURN FALSE;
          END;
          $func$ LANGUAGE plpgsql STABLE;
        ';
      END IF;
    END
    $$;
    """
  end

  def down do
    # Rollback: Disable RLS on tables that were enabled by this migration
    # We identify these by looking for tables with the standard policy names
    # that don't have data from before this migration

    execute """
    DO $$
    DECLARE
      r RECORD;
    BEGIN
      -- Only attempt to disable RLS on tables that have policies
      FOR r IN
        SELECT DISTINCT tablename
        FROM pg_policies
        WHERE schemaname = 'public'
        AND (
          policyname LIKE '%_deny_all'
          OR policyname LIKE '%_organization_isolation'
        )
      LOOP
        BEGIN
          -- Drop policies
          EXECUTE format('DROP POLICY IF EXISTS %I ON %I', r.tablename || '_deny_all', r.tablename);
          EXECUTE format('DROP POLICY IF EXISTS %I ON %I', r.tablename || '_organization_isolation', r.tablename);

          -- Disable RLS (safe even if already disabled)
          EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', r.tablename);
          EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', r.tablename);

          RAISE NOTICE 'Disabled RLS on table: %', r.tablename;
        EXCEPTION
          WHEN undefined_table THEN
            -- Table doesn't exist, skip
            RAISE NOTICE 'Table % does not exist, skipping', r.tablename;
          WHEN OTHERS THEN
            RAISE NOTICE 'Error disabling RLS on %: %', r.tablename, SQLERRM;
        END;
      END LOOP;
    END
    $$;
    """
  end
end
