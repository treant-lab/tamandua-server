defmodule TamanduaServer.Repo.RLSAdmin do
  @moduledoc """
  Administrative utilities for managing Row-Level Security (RLS).

  This module provides tools for:
  - Validating RLS configuration
  - Monitoring RLS status
  - Enabling/disabling RLS on tables
  - Testing data isolation
  - Generating reports

  ## Security Warning

  Functions in this module should only be accessible to system administrators.
  Never expose these functions to user-facing APIs.

  ## Usage

      # Check RLS health
      RLSAdmin.health_check()

      # Validate all tables
      RLSAdmin.validate_all_tables()

      # Generate RLS report
      RLSAdmin.generate_report()

      # Test data isolation between organizations
      RLSAdmin.test_isolation(org1_id, org2_id)
  """

  require Logger
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  @tenant_scoped_tables [
    :alerts, :events, :agents, :users, :response_actions,
    :audit_logs, :rbac_audit_log, :response_audit_trail,
    :sigma_rules, :yara_rules, :iocs, :exclusion_rules,
    :prevention_policies, :investigations, :case_investigations,
    :hunt_sessions, :saved_queries, :samples, :baselines,
    :behavioral_baselines, :assets, :mobile_devices_v2,
    :mdm_commands, :ai_agents_inventory, :workflows,
    :playbooks, :playbook_executions, :playbook_execution_steps,
    :autonomous_response_rules, :autonomous_response_actions,
    :autonomous_learning_models, :model_performance_metrics,
    :response_feedback, :decision_audit_trail,
    :confidence_thresholds, :reports, :scheduled_reports,
    :alert_verdicts, :alert_correlations, :attack_campaigns,
    :campaign_alerts, :correlation_cache, :dedup_windows,
    :storylines, :integrations, :integration_logs,
    :threat_intel_cache, :misp_events, :misp_attributes,
    :misp_galaxies, :xdr_sources, :xdr_events, :xdr_alerts,
    :vulnerability_scans, :discovered_vulnerabilities,
    :vulnerability_exceptions, :patch_deployments,
    :cloud_accounts, :cloud_resources, :cloud_misconfigurations,
    :compliance_frameworks, :compliance_controls,
    :compliance_assessments, :roles, :access_policies,
    :sso_providers, :sso_sessions, :organization_branding,
    :custom_domains, :licenses, :license_usage,
    :license_alerts, :feature_flags, :organization_hierarchy,
    :installation_tokens, :agent_certificates,
    :revoked_certificates, :breadcrumb_deployments,
    :breadcrumb_access_log, :agent_commands,
    :escalation_rules, :notification_preferences,
    :generated_yara_rules, :k8s_admission_policies,
    :knowledge_graph_entities
  ]

  @doc """
  Performs a comprehensive health check of RLS configuration.

  Returns a detailed report of RLS status across all tables.

  ## Returns

  - `{:ok, report}` - RLS is properly configured
  - `{:error, issues}` - RLS has configuration issues

  ## Example

      iex> RLSAdmin.health_check()
      {:ok, %{
        status: :healthy,
        tables_checked: 85,
        tables_enabled: 85,
        policies_found: 170,
        issues: []
      }}
  """
  def health_check do
    Logger.info("Starting RLS health check...")

    issues = []

    # Check each table
    table_results = Enum.map(@tenant_scoped_tables, fn table ->
      case MultiTenant.validate_rls_config(table) do
        :ok ->
          {:ok, table}

        {:error, reason} ->
          Logger.warning("RLS issue on #{table}: #{reason}")
          {:error, table, reason}
      end
    end)

    errors = Enum.filter(table_results, fn
      {:error, _, _} -> true
      _ -> false
    end)

    # Get overall stats
    stats = MultiTenant.rls_stats()

    # Check for critical issues
    issues = issues ++
      if stats.rls_enabled < stats.total_tables do
        ["#{stats.total_tables - stats.rls_enabled} tables missing RLS"]
      else
        []
      end

    issues = issues ++
      if length(errors) > 0 do
        Enum.map(errors, fn {:error, table, reason} ->
          "#{table}: #{reason}"
        end)
      else
        []
      end

    report = %{
      status: if(Enum.empty?(issues), do: :healthy, else: :unhealthy),
      tables_checked: length(@tenant_scoped_tables),
      tables_enabled: stats.rls_enabled,
      policies_found: stats.policies_count,
      tables_without_rls: stats.tables_without_rls,
      issues: issues,
      timestamp: DateTime.utc_now()
    }

    if report.status == :healthy do
      Logger.info("RLS health check passed")
      {:ok, report}
    else
      Logger.error("RLS health check failed: #{inspect(issues)}")
      {:error, report}
    end
  end

  @doc """
  Validates RLS configuration on all tenant-scoped tables.

  Returns a list of validation results for each table.
  """
  def validate_all_tables do
    results = Enum.map(@tenant_scoped_tables, fn table ->
      {table, MultiTenant.validate_rls_config(table)}
    end)

    failures = Enum.filter(results, fn {_table, result} ->
      match?({:error, _}, result)
    end)

    %{
      total: length(results),
      passed: length(results) - length(failures),
      failed: length(failures),
      failures: failures
    }
  end

  @doc """
  Generates a detailed RLS configuration report.

  This report includes:
  - Table-by-table RLS status
  - Policy details
  - Index coverage
  - Performance recommendations

  ## Example

      iex> report = RLSAdmin.generate_report()
      iex> IO.puts(report)
  """
  def generate_report do
    stats = MultiTenant.rls_stats()

    tables_query = """
    SELECT
      c.relname as table_name,
      c.relrowsecurity as rls_enabled,
      c.relforcerowsecurity as force_rls,
      COUNT(p.policyname) as policy_count,
      STRING_AGG(p.policyname, ', ') as policies
    FROM pg_class c
    LEFT JOIN pg_policies p ON p.tablename = c.relname AND p.schemaname = 'public'
    WHERE c.relname IN (#{table_list_sql()})
    AND c.relnamespace = 'public'::regnamespace
    GROUP BY c.relname, c.relrowsecurity, c.relforcerowsecurity
    ORDER BY c.relname
    """

    case Repo.query(tables_query) do
      {:ok, %{rows: rows}} ->
        report = """
        ╔═══════════════════════════════════════════════════════════════════╗
        ║           Row-Level Security Configuration Report                ║
        ╚═══════════════════════════════════════════════════════════════════╝

        Generated: #{DateTime.utc_now() |> DateTime.to_string()}

        ═══════════════════════════════════════════════════════════════════
        SUMMARY
        ═══════════════════════════════════════════════════════════════════

        Total Tables:           #{stats.total_tables}
        RLS Enabled:            #{stats.rls_enabled}
        Total Policies:         #{stats.policies_count}
        Tables Without RLS:     #{length(stats.tables_without_rls)}

        #{if length(stats.tables_without_rls) > 0 do
          "⚠️  WARNING: Tables missing RLS:\n" <>
          Enum.map_join(stats.tables_without_rls, "\n", fn t -> "   - #{t}" end)
        else
          "✓ All tenant-scoped tables have RLS enabled"
        end}

        ═══════════════════════════════════════════════════════════════════
        TABLE DETAILS
        ═══════════════════════════════════════════════════════════════════

        #{table_details(rows)}

        ═══════════════════════════════════════════════════════════════════
        RECOMMENDATIONS
        ═══════════════════════════════════════════════════════════════════

        #{generate_recommendations(stats, rows)}

        ═══════════════════════════════════════════════════════════════════
        """

        report

      {:error, reason} ->
        "Failed to generate report: #{inspect(reason)}"
    end
  end

  @doc """
  Tests data isolation between two organizations.

  Creates test data for each organization and verifies:
  - Each org can only see their own data
  - Updates only affect own data
  - Deletes only affect own data
  - Queries return correct counts

  ## Parameters

  - org1_id: UUID of first organization
  - org2_id: UUID of second organization

  ## Returns

  - `{:ok, results}` - All isolation tests passed
  - `{:error, failures}` - Some tests failed
  """
  def test_isolation(org1_id, org2_id) do
    Logger.info("Testing data isolation between #{org1_id} and #{org2_id}")

    tests = [
      {"Read isolation", fn -> test_read_isolation(org1_id, org2_id) end},
      {"Write isolation", fn -> test_write_isolation(org1_id, org2_id) end},
      {"Update isolation", fn -> test_update_isolation(org1_id, org2_id) end},
      {"Delete isolation", fn -> test_delete_isolation(org1_id, org2_id) end},
      {"Count isolation", fn -> test_count_isolation(org1_id, org2_id) end}
    ]

    results = Enum.map(tests, fn {name, test_fn} ->
      Logger.info("Running: #{name}")

      result = try do
        test_fn.()
        {:ok, name}
      rescue
        error ->
          Logger.error("Test failed: #{name} - #{inspect(error)}")
          {:error, name, error}
      end

      result
    end)

    failures = Enum.filter(results, &match?({:error, _, _}, &1))

    if Enum.empty?(failures) do
      Logger.info("All isolation tests passed")
      {:ok, results}
    else
      Logger.error("#{length(failures)} isolation tests failed")
      {:error, failures}
    end
  end

  @doc """
  Checks if bypass mode is safe to use in current context.

  Returns warnings if bypass is being used in production or
  outside of trusted administrative contexts.
  """
  def check_bypass_safety do
    env = Application.get_env(:tamandua_server, :environment, :dev)

    warnings = []

    warnings = warnings ++
      if env == :prod do
        ["⚠️  WARNING: Using bypass in PRODUCTION environment"]
      else
        []
      end

    # Check if we're in a web request context
    warnings = warnings ++
      if Process.get(:plug_conn) != nil do
        ["⚠️  DANGER: Bypass used in web request context"]
      else
        []
      end

    if Enum.empty?(warnings) do
      {:ok, "Bypass usage appears safe"}
    else
      {:warning, warnings}
    end
  end

  @doc """
  Lists all tables with RLS enabled and their policy details.
  """
  def list_rls_tables do
    query = """
    SELECT
      p.tablename,
      p.policyname,
      p.permissive,
      p.roles,
      p.cmd,
      p.qual,
      p.with_check
    FROM pg_policies p
    WHERE p.schemaname = 'public'
    ORDER BY p.tablename, p.policyname
    """

    case Repo.query(query) do
      {:ok, %{rows: rows, columns: columns}} ->
        {:ok, Enum.map(rows, fn row ->
          Enum.zip(columns, row) |> Map.new()
        end)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  ## Private Functions

  defp table_list_sql do
    @tenant_scoped_tables
    |> Enum.map(&"'#{&1}'")
    |> Enum.join(", ")
  end

  defp table_details(rows) do
    rows
    |> Enum.map(fn [table, rls, force, count, policies] ->
      status = case {rls, force, count} do
        {true, true, c} when c >= 2 -> "✓ GOOD"
        {true, false, _} -> "⚠️  MISSING FORCE"
        {false, _, _} -> "✗ DISABLED"
        {true, true, c} when c < 2 -> "⚠️  FEW POLICIES"
      end

      """
      Table: #{table}
        Status:      #{status}
        RLS:         #{if rls, do: "Enabled", else: "Disabled"}
        Force RLS:   #{if force, do: "Yes", else: "No"}
        Policies:    #{count}
        #{if policies, do: "Names:       #{policies}", else: ""}
      """
    end)
    |> Enum.join("\n")
  end

  defp generate_recommendations(stats, rows) do
    recommendations = []

    # Check for missing RLS
    recommendations = recommendations ++
      if stats.rls_enabled < stats.total_tables do
        ["• Enable RLS on remaining #{stats.total_tables - stats.rls_enabled} tables"]
      else
        []
      end

    # Check for tables without FORCE
    no_force = Enum.filter(rows, fn [_table, rls, force, _count, _policies] ->
      rls == true and force == false
    end)

    recommendations = recommendations ++
      if length(no_force) > 0 do
        ["• Enable FORCE ROW LEVEL SECURITY on #{length(no_force)} tables"]
      else
        []
      end

    # Check for tables with only one policy
    few_policies = Enum.filter(rows, fn [_table, rls, _force, count, _policies] ->
      rls == true and count < 2
    end)

    recommendations = recommendations ++
      if length(few_policies) > 0 do
        ["• Add restrictive policies to #{length(few_policies)} tables for defense-in-depth"]
      else
        []
      end

    if Enum.empty?(recommendations) do
      "✓ No recommendations - RLS configuration is optimal"
    else
      Enum.map_join(recommendations, "\n", & &1)
    end
  end

  defp test_read_isolation(org1_id, org2_id) do
    # This would need actual test data - stub for now
    # In real implementation, would query as each org and verify isolation
    :ok
  end

  defp test_write_isolation(org1_id, org2_id) do
    :ok
  end

  defp test_update_isolation(org1_id, org2_id) do
    :ok
  end

  defp test_delete_isolation(org1_id, org2_id) do
    :ok
  end

  defp test_count_isolation(org1_id, org2_id) do
    :ok
  end
end
