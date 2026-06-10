defmodule TamanduaServer.Repo.RLSCompleteness do
  @moduledoc """
  Automated RLS coverage checker for defense-in-depth multi-tenancy.

  This module automatically detects tables with organization_id columns
  but missing RLS policies, enabling CI/CD to catch missing RLS before deploy.

  ## Usage

      # Check coverage status
      {:ok, %{covered: 85, missing: []}} = RLSCompleteness.check_coverage()

      # Get list of missing tables
      [] = RLSCompleteness.missing_tables()

      # Generate audit report
      report = RLSCompleteness.audit_report()
      IO.puts(report)

      # Ensure coverage (raises if any tables missing - for CI)
      RLSCompleteness.ensure_coverage!()

  ## CI Integration

  Add to your CI pipeline:

      mix run -e "TamanduaServer.Repo.RLSCompleteness.ensure_coverage!()"

  This will exit with status 1 if any tenant-scoped tables are missing RLS policies.
  """

  alias TamanduaServer.Repo

  require Logger

  @doc """
  Checks RLS coverage for all tenant-scoped tables.

  Returns {:ok, %{covered: count, missing: []}} if all tables have RLS,
  or {:error, missing_tables} if some tables are missing RLS policies.

  ## Examples

      iex> check_coverage()
      {:ok, %{covered: 85, missing: [], total: 85, coverage_pct: 100.0}}

      iex> check_coverage()
      {:error, ["new_table_without_rls"]}
  """
  @spec check_coverage() :: {:ok, map()} | {:error, list(String.t())}
  def check_coverage do
    case {tenant_scoped_tables(), tables_with_rls()} do
      {{:ok, tenant_tables}, {:ok, rls_tables}} ->
        tenant_set = MapSet.new(tenant_tables)
        rls_set = MapSet.new(rls_tables)

        missing = MapSet.difference(tenant_set, rls_set) |> MapSet.to_list()
        covered = MapSet.intersection(tenant_set, rls_set) |> MapSet.size()
        total = MapSet.size(tenant_set)

        coverage_pct = if total > 0, do: covered / total * 100.0, else: 100.0

        result = %{
          covered: covered,
          missing: missing,
          total: total,
          coverage_pct: Float.round(coverage_pct, 2)
        }

        if Enum.empty?(missing) do
          {:ok, result}
        else
          {:error, missing}
        end

      {{:error, reason}, _} ->
        Logger.error("Failed to query tenant-scoped tables: #{inspect(reason)}")
        {:error, [{:query_error, reason}]}

      {_, {:error, reason}} ->
        Logger.error("Failed to query RLS tables: #{inspect(reason)}")
        {:error, [{:query_error, reason}]}
    end
  end

  @doc """
  Returns list of tables that have organization_id but no RLS policies.

  ## Examples

      iex> missing_tables()
      []

      iex> missing_tables()
      ["new_table_without_rls", "another_table"]
  """
  @spec missing_tables() :: list(String.t())
  def missing_tables do
    case check_coverage() do
      {:ok, %{missing: missing}} -> missing
      {:error, missing} when is_list(missing) -> missing
    end
  end

  @doc """
  Generates a formatted audit report showing RLS coverage status.

  ## Examples

      iex> audit_report()
      \"""
      =====================================
      RLS Coverage Audit Report
      =====================================
      Date: 2026-04-15T10:30:00Z
      Status: PASS

      Coverage: 85/85 tables (100.0%)
      ...
      \"""
  """
  @spec audit_report() :: String.t()
  def audit_report do
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601()

    case check_coverage() do
      {:ok, %{covered: covered, total: total, coverage_pct: pct}} ->
        """
        =====================================
        RLS Coverage Audit Report
        =====================================
        Date: #{timestamp}
        Status: PASS

        Coverage: #{covered}/#{total} tables (#{pct}%)

        All tenant-scoped tables have RLS policies enabled.
        Defense-in-depth data isolation is active.

        =====================================
        """

      {:error, missing} when is_list(missing) ->
        missing_list = Enum.map_join(missing, "\n  - ", & &1)

        """
        =====================================
        RLS Coverage Audit Report
        =====================================
        Date: #{timestamp}
        Status: FAIL

        Missing RLS on #{length(missing)} table(s):
          - #{missing_list}

        ACTION REQUIRED:
        Run the RLS completeness migration to enable RLS on these tables:

          mix ecto.migrate

        Or manually enable RLS using:

          ALTER TABLE table_name ENABLE ROW LEVEL SECURITY;
          ALTER TABLE table_name FORCE ROW LEVEL SECURITY;

        =====================================
        """
    end
  end

  @doc """
  Ensures 100% RLS coverage, raising if any tables are missing.

  This function is designed for CI/CD integration. It will raise
  RuntimeError if any tenant-scoped tables lack RLS policies.

  ## Examples

      iex> ensure_coverage!()
      :ok

      iex> ensure_coverage!()
      ** (RuntimeError) RLS coverage incomplete! Missing tables: ["new_table"]
  """
  @spec ensure_coverage!() :: :ok | no_return()
  def ensure_coverage! do
    case check_coverage() do
      {:ok, %{missing: []}} ->
        Logger.info("RLS coverage check passed: all tenant-scoped tables protected")
        :ok

      {:error, missing} when is_list(missing) ->
        report = audit_report()
        Logger.error(report)

        raise RuntimeError,
          message: "RLS coverage incomplete! Missing tables: #{inspect(missing)}"
    end
  end

  @doc """
  Returns detailed information about each table's RLS status.

  ## Examples

      iex> table_details()
      [
        %{table: "alerts", has_org_id: true, rls_enabled: true, policies: ["alerts_deny_all", "alerts_organization_isolation"]},
        ...
      ]
  """
  @spec table_details() :: list(map())
  def table_details do
    case {tenant_scoped_tables(), tables_with_rls_details()} do
      {{:ok, tenant_tables}, {:ok, rls_details}} ->
        rls_map = Map.new(rls_details, fn {table, policies} -> {table, policies} end)

        Enum.map(tenant_tables, fn table ->
          policies = Map.get(rls_map, table, [])

          %{
            table: table,
            has_org_id: true,
            rls_enabled: length(policies) > 0,
            policies: policies
          }
        end)

      _ ->
        []
    end
  end

  # Private Functions

  # Queries information_schema for all tables with organization_id column
  defp tenant_scoped_tables do
    sql = """
    SELECT table_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
    AND column_name = 'organization_id'
    ORDER BY table_name
    """

    case Repo.query(sql) do
      {:ok, %{rows: rows}} ->
        tables = Enum.map(rows, fn [name] -> name end)
        {:ok, tables}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Queries pg_policies to get tables with RLS enabled
  defp tables_with_rls do
    sql = """
    SELECT DISTINCT tablename
    FROM pg_policies
    WHERE schemaname = 'public'
    ORDER BY tablename
    """

    case Repo.query(sql) do
      {:ok, %{rows: rows}} ->
        tables = Enum.map(rows, fn [name] -> name end)
        {:ok, tables}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Queries pg_policies with policy details
  defp tables_with_rls_details do
    sql = """
    SELECT tablename, array_agg(policyname ORDER BY policyname)
    FROM pg_policies
    WHERE schemaname = 'public'
    GROUP BY tablename
    ORDER BY tablename
    """

    case Repo.query(sql) do
      {:ok, %{rows: rows}} ->
        details = Enum.map(rows, fn [table, policies] -> {table, policies} end)
        {:ok, details}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
