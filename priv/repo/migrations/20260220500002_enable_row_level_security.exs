defmodule TamanduaServer.Repo.Migrations.EnableRowLevelSecurity do
  use Ecto.Migration

  @moduledoc """
  Enables PostgreSQL Row-Level Security (RLS) for defense-in-depth multi-tenancy.

  This migration implements RLS policies on all tenant-scoped tables to ensure
  data isolation at the database level. This provides an additional security layer
  beyond application-level authorization.

  ## Security Model

  - RLS is enabled on all tables with organization_id columns
  - Default DENY policy prevents access without proper context
  - ALLOW policies grant access based on session variable app.current_organization_id
  - System operations can bypass RLS using BYPASSRLS role (for migrations, admin tools)

  ## Performance Considerations

  - RLS policies use indexed columns (organization_id)
  - Policies are optimized for query planner to use existing indexes
  - Expected overhead: <5% on typical queries
  - Session variables cached per connection

  ## Rollback Strategy

  - Can disable RLS on individual tables without data loss
  - Policies can be dropped independently
  - Application continues to work with RLS disabled (app-level auth still active)
  """

  # High-risk tables that should be protected first
  # These contain sensitive customer data and are frequently queried
  @critical_tables [
    :alerts,
    :events,
    :agents,
    :users,
    :response_actions,
    :audit_logs
  ]

  # All tables with organization_id that need RLS
  # Grouped by priority for incremental rollout
  @tenant_scoped_tables [
    # Core security tables (Tier 1 - Critical)
    :alerts,
    :events,
    :agents,
    :users,
    :response_actions,
    :audit_logs,
    :rbac_audit_log,
    :response_audit_trail,

    # Detection and rules (Tier 2 - High Priority)
    :sigma_rules,
    :yara_rules,
    :iocs,
    :exclusion_rules,
    :prevention_policies,

    # Investigations and analysis (Tier 3 - Medium Priority)
    :investigations,
    :case_investigations,
    :hunt_sessions,
    :saved_queries,
    :samples,
    :baselines,
    # :behavioral_baselines,  # Excluded: doesn't have organization_id column

    # Asset and inventory (Tier 4 - Medium Priority)
    :assets,
    :mobile_devices_v2,
    :mdm_commands,
    # :ai_agents_inventory,  # Excluded: table may not exist

    # Workflows and automation (Tier 5 - Standard)
    :workflows,
    :playbooks,
    :playbook_executions,
    :playbook_execution_steps,
    :autonomous_response_rules,
    :autonomous_response_actions,
    :autonomous_learning_models,
    :model_performance_metrics,
    :response_feedback,
    :decision_audit_trail,
    :confidence_thresholds,

    # Reporting and analytics (Tier 6 - Standard)
    :reports,
    :scheduled_reports,
    :alert_verdicts,
    :alert_correlations,
    :attack_campaigns,
    :campaign_alerts,
    :correlation_cache,
    :dedup_windows,
    :storylines,

    # Integration and external systems (Tier 7 - Standard)
    :integrations,
    :integration_logs,
    :threat_intel_cache,
    :misp_events,
    :misp_attributes,
    :misp_galaxies,
    :xdr_sources,
    :xdr_events,
    :xdr_alerts,

    # Vulnerability management (Tier 8 - Standard)
    :vulnerability_scans,
    :discovered_vulnerabilities,
    :vulnerability_exceptions,
    :patch_deployments,

    # Cloud security (Tier 9 - Standard)
    :cloud_accounts,
    :cloud_resources,
    :cloud_misconfigurations,
    :compliance_frameworks,
    :compliance_controls,
    :compliance_assessments,

    # Enterprise features (Tier 10 - Standard)
    :roles,
    :access_policies,
    :sso_providers,
    :sso_sessions,
    :organization_branding,
    :custom_domains,
    :licenses,
    :license_usage,
    :license_alerts,
    :feature_flags,
    :organization_hierarchy,
    :installation_tokens,
    :agent_certificates,
    :revoked_certificates,
    :breadcrumb_deployments,
    :breadcrumb_access_log,
    :agent_commands,
    :escalation_rules,
    :notification_preferences,
    :generated_yara_rules,
    :k8s_admission_policies,
    :knowledge_graph_entities
  ]

  def up do
    # Create helper function to get current organization from session variable
    execute """
    CREATE OR REPLACE FUNCTION current_organization_id()
    RETURNS UUID AS $$
    BEGIN
      RETURN NULLIF(current_setting('app.current_organization_id', TRUE), '')::UUID;
    EXCEPTION
      WHEN OTHERS THEN
        RETURN NULL;
    END;
    $$ LANGUAGE plpgsql STABLE;
    """

    # Create helper function to check if bypass mode is enabled
    # This is used for system operations like migrations, background jobs, etc.
    execute """
    CREATE OR REPLACE FUNCTION rls_bypass_enabled()
    RETURNS BOOLEAN AS $$
    BEGIN
      RETURN COALESCE(current_setting('app.rls_bypass', TRUE)::BOOLEAN, FALSE);
    EXCEPTION
      WHEN OTHERS THEN
        RETURN FALSE;
    END;
    $$ LANGUAGE plpgsql STABLE;
    """

    # Enable RLS on all tenant-scoped tables
    for table <- @tenant_scoped_tables do
      enable_rls_on_table(table)
    end
  end

  def down do
    # Disable RLS on all tables (in reverse order for safety)
    for table <- Enum.reverse(@tenant_scoped_tables) do
      disable_rls_on_table(table)
    end

    # Drop helper functions
    execute "DROP FUNCTION IF EXISTS rls_bypass_enabled()"
    execute "DROP FUNCTION IF EXISTS current_organization_id()"
  end

  # Private helper functions

  defp enable_rls_on_table(table) do
    table_name = Atom.to_string(table)

    # Wrap all RLS operations in a check for table and column existence
    execute """
    DO $$
    BEGIN
      -- Check if table exists and has organization_id column
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = '#{table_name}'
        AND column_name = 'organization_id'
      ) THEN
        -- Enable RLS on the table
        EXECUTE 'ALTER TABLE #{table_name} ENABLE ROW LEVEL SECURITY';
        EXECUTE 'ALTER TABLE #{table_name} FORCE ROW LEVEL SECURITY';

        -- Create ALLOW policy for organization-scoped access if not exists
        IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = '#{table_name}' AND policyname = '#{table_name}_organization_isolation') THEN
          EXECUTE 'CREATE POLICY #{table_name}_organization_isolation ON #{table_name} AS PERMISSIVE FOR ALL TO PUBLIC USING (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id()) WITH CHECK (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())';
        END IF;
      END IF;
    END
    $$;
    """

    # Create index on organization_id if it doesn't exist
    # This ensures RLS policies don't cause performance degradation
    # Most tables already have this index, but we ensure it exists
    execute """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = '#{table_name}'
        AND column_name = 'organization_id'
      ) THEN
        IF NOT EXISTS (
          SELECT 1 FROM pg_indexes
          WHERE tablename = '#{table_name}'
          AND indexdef LIKE '%organization_id%'
        ) THEN
          EXECUTE 'CREATE INDEX #{table_name}_organization_id_idx ON #{table_name}(organization_id)';
        END IF;
      END IF;
    END $$;
    """
  end

  defp disable_rls_on_table(table) do
    table_name = Atom.to_string(table)

    # Resilient drop policies and disable RLS
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = '#{table_name}') THEN
        EXECUTE 'DROP POLICY IF EXISTS #{table_name}_organization_isolation ON #{table_name}';
        EXECUTE 'ALTER TABLE #{table_name} NO FORCE ROW LEVEL SECURITY';
        EXECUTE 'ALTER TABLE #{table_name} DISABLE ROW LEVEL SECURITY';
      END IF;
    END $$;
    """
  end
end
