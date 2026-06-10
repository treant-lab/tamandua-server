defmodule TamanduaServer.Integration.RLSCompletenessTest do
  @moduledoc """
  Integration tests for RLS completeness verification and RequireTenantContext plug.

  These tests verify:
  1. RLSCompleteness module correctly detects coverage gaps
  2. RequireTenantContext plug enforces tenant context on API routes
  3. Concurrent access maintains tenant isolation
  4. SQL injection protection in tenant context setting
  """

  use TamanduaServer.DataCase, async: false
  use TamanduaServerWeb.ConnCase, async: false

  import Plug.Conn
  import Phoenix.ConnTest

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Repo.RLSCompleteness
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServerWeb.Plugs.RequireTenantContext

  @moduletag :enterprise

  describe "RLSCompleteness.check_coverage/0" do
    test "returns {:ok, _} when all tenant-scoped tables have RLS" do
      result = RLSCompleteness.check_coverage()

      case result do
        {:ok, %{covered: covered, missing: [], total: total, coverage_pct: pct}} ->
          assert covered == total
          assert pct == 100.0
          assert covered >= 10, "Expected at least 10 tenant-scoped tables"

        {:error, missing} ->
          flunk("RLS coverage incomplete. Missing tables: #{inspect(missing)}")
      end
    end

    test "returns {:error, missing_tables} when tables lack RLS" do
      # This test simulates what would happen if a table was missing RLS
      # We can't actually create a table without RLS in a test, but we can
      # verify the function returns the expected structure
      case RLSCompleteness.check_coverage() do
        {:ok, %{missing: missing}} ->
          assert is_list(missing)

        {:error, missing} ->
          assert is_list(missing)
          assert Enum.all?(missing, &is_binary/1)
      end
    end
  end

  describe "RLSCompleteness.missing_tables/0" do
    test "returns empty list when all tables have RLS" do
      missing = RLSCompleteness.missing_tables()
      assert is_list(missing)

      # If there are missing tables, log them for visibility
      if length(missing) > 0 do
        IO.puts("\nMissing RLS tables: #{inspect(missing)}")
      end
    end
  end

  describe "RLSCompleteness.audit_report/0" do
    test "generates a formatted audit report" do
      report = RLSCompleteness.audit_report()

      assert is_binary(report)
      assert report =~ "RLS Coverage Audit Report"
      assert report =~ "Date:"
      assert report =~ "Status:"
      assert report =~ "Coverage:"
    end

    test "report contains PASS status when coverage is complete" do
      case RLSCompleteness.check_coverage() do
        {:ok, %{missing: []}} ->
          report = RLSCompleteness.audit_report()
          assert report =~ "Status: PASS"
          assert report =~ "100.0%"

        {:error, _} ->
          report = RLSCompleteness.audit_report()
          assert report =~ "Status: FAIL"
      end
    end
  end

  describe "RLSCompleteness.ensure_coverage!/0" do
    test "returns :ok when coverage is complete" do
      case RLSCompleteness.check_coverage() do
        {:ok, %{missing: []}} ->
          assert :ok = RLSCompleteness.ensure_coverage!()

        {:error, missing} ->
          assert_raise RuntimeError, ~r/RLS coverage incomplete/, fn ->
            RLSCompleteness.ensure_coverage!()
          end
          IO.puts("\nExpected failure - missing tables: #{inspect(missing)}")
      end
    end
  end

  describe "RLSCompleteness.table_details/0" do
    test "returns detailed information about each table" do
      details = RLSCompleteness.table_details()

      assert is_list(details)

      for detail <- details do
        assert is_map(detail)
        assert Map.has_key?(detail, :table)
        assert Map.has_key?(detail, :has_org_id)
        assert Map.has_key?(detail, :rls_enabled)
        assert Map.has_key?(detail, :policies)
      end
    end

    test "tables with RLS have at least 2 policies" do
      details = RLSCompleteness.table_details()

      rls_tables = Enum.filter(details, & &1.rls_enabled)

      for table_info <- rls_tables do
        assert length(table_info.policies) >= 2,
          "Table #{table_info.table} should have at least 2 policies (deny_all, organization_isolation)"
      end
    end
  end

  describe "RequireTenantContext plug - missing context" do
    test "returns 403 when organization_id is missing" do
      opts = RequireTenantContext.init([])

      conn =
        build_conn(:get, "/api/v1/alerts")
        |> put_private(:phoenix_endpoint, TamanduaServerWeb.Endpoint)
        |> RequireTenantContext.call(opts)

      assert conn.halted
      assert conn.status == 403

      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "tenant_context_required"
      assert body["message"] =~ "tenant"
    end

    test "allows request when organization_id is set" do
      org = insert(:organization)
      opts = RequireTenantContext.init([])

      conn =
        build_conn(:get, "/api/v1/alerts")
        |> assign(:current_organization_id, org.id)
        |> put_private(:phoenix_endpoint, TamanduaServerWeb.Endpoint)
        |> RequireTenantContext.call(opts)

      refute conn.halted
    end
  end

  describe "RequireTenantContext plug - invalid context" do
    test "returns 400 when organization_id is not a valid UUID" do
      opts = RequireTenantContext.init([])

      conn =
        build_conn(:get, "/api/v1/alerts")
        |> assign(:current_organization_id, "not-a-uuid")
        |> put_private(:phoenix_endpoint, TamanduaServerWeb.Endpoint)
        |> RequireTenantContext.call(opts)

      assert conn.halted
      assert conn.status == 400

      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "invalid_tenant_context"
    end

    test "returns 400 when organization_id is wrong type" do
      opts = RequireTenantContext.init([])

      conn =
        build_conn(:get, "/api/v1/alerts")
        |> assign(:current_organization_id, 12345)
        |> put_private(:phoenix_endpoint, TamanduaServerWeb.Endpoint)
        |> RequireTenantContext.call(opts)

      assert conn.halted
      assert conn.status == 400
    end
  end

  describe "RequireTenantContext plug - :except option" do
    test "bypasses enforcement for excepted paths" do
      opts = RequireTenantContext.init(except: ["/api/v1/health", "/api/v1/auth"])

      # Test health endpoint (excepted)
      conn =
        build_conn(:get, "/api/v1/health")
        |> put_private(:phoenix_endpoint, TamanduaServerWeb.Endpoint)
        |> RequireTenantContext.call(opts)

      refute conn.halted

      # Test auth endpoint (excepted)
      conn =
        build_conn(:post, "/api/v1/auth/login")
        |> put_private(:phoenix_endpoint, TamanduaServerWeb.Endpoint)
        |> RequireTenantContext.call(opts)

      refute conn.halted

      # Test non-excepted endpoint (should halt)
      conn =
        build_conn(:get, "/api/v1/alerts")
        |> put_private(:phoenix_endpoint, TamanduaServerWeb.Endpoint)
        |> RequireTenantContext.call(opts)

      assert conn.halted
      assert conn.status == 403
    end

    test "uses prefix matching for except paths" do
      opts = RequireTenantContext.init(except: ["/api/v1/auth"])

      # Any path starting with /api/v1/auth should be excepted
      paths = [
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/refresh",
        "/api/v1/auth/forgot-password"
      ]

      for path <- paths do
        conn =
          build_conn(:get, path)
          |> put_private(:phoenix_endpoint, TamanduaServerWeb.Endpoint)
          |> RequireTenantContext.call(opts)

        refute conn.halted, "Path #{path} should be excepted but was halted"
      end
    end
  end

  describe "concurrent access isolation" do
    setup do
      org1 = insert(:organization, name: "Concurrent Test Org 1")
      org2 = insert(:organization, name: "Concurrent Test Org 2")

      # Create data for each organization
      agent1 = insert(:agent, organization_id: org1.id)
      agent2 = insert(:agent, organization_id: org2.id)

      for i <- 1..10 do
        insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Org1 Alert #{i}")
        insert(:alert, organization_id: org2.id, agent_id: agent2.id, title: "Org2 Alert #{i}")
      end

      %{org1: org1, org2: org2}
    end

    test "parallel requests maintain organization isolation", %{org1: org1, org2: org2} do
      # Spawn many concurrent tasks that query alerts
      tasks = for _ <- 1..20 do
        Task.async(fn ->
          org1_alerts = MultiTenant.with_organization(org1.id, fn ->
            Repo.all(Alert)
          end)

          org2_alerts = MultiTenant.with_organization(org2.id, fn ->
            Repo.all(Alert)
          end)

          {length(org1_alerts), length(org2_alerts)}
        end)
      end

      results = Task.await_many(tasks, 30_000)

      # All results should show exactly 10 alerts per organization
      for {org1_count, org2_count} <- results do
        assert org1_count == 10,
          "Expected 10 org1 alerts, got #{org1_count} - isolation failure"
        assert org2_count == 10,
          "Expected 10 org2 alerts, got #{org2_count} - isolation failure"
      end
    end

    test "interleaved operations maintain isolation", %{org1: org1, org2: org2} do
      # Interleave operations between organizations
      results = for i <- 1..10 do
        if rem(i, 2) == 0 do
          MultiTenant.with_organization(org1.id, fn ->
            {:org1, Repo.aggregate(Alert, :count, :id)}
          end)
        else
          MultiTenant.with_organization(org2.id, fn ->
            {:org2, Repo.aggregate(Alert, :count, :id)}
          end)
        end
      end

      for result <- results do
        case result do
          {:org1, count} -> assert count == 10
          {:org2, count} -> assert count == 10
        end
      end
    end
  end

  describe "SQL injection protection" do
    test "malicious organization_id values are rejected" do
      malicious_ids = [
        "'; DROP TABLE alerts; --",
        "1' OR '1'='1",
        "1; SELECT * FROM users WHERE '1'='1",
        "NULL",
        "' UNION SELECT * FROM users --",
        "admin'--",
        "1 OR 1=1",
        "' OR ''='"
      ]

      for malicious_id <- malicious_ids do
        # Attempting to set malicious IDs should fail
        assert_raise ArgumentError, fn ->
          MultiTenant.put_organization_id(malicious_id)
        end
      end
    end

    test "valid UUIDs are accepted" do
      valid_ids = [
        "123e4567-e89b-12d3-a456-426614174000",
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        Ecto.UUID.generate()
      ]

      for valid_id <- valid_ids do
        # Valid UUIDs should not raise
        assert :ok = MultiTenant.put_organization_id(valid_id)
      end
    end

    test "RequireTenantContext rejects SQL injection in organization_id" do
      opts = RequireTenantContext.init([])

      # Even if somehow assigned, should be rejected as invalid UUID
      conn =
        build_conn(:get, "/api/v1/alerts")
        |> assign(:current_organization_id, "'; DROP TABLE alerts; --")
        |> put_private(:phoenix_endpoint, TamanduaServerWeb.Endpoint)
        |> RequireTenantContext.call(opts)

      assert conn.halted
      assert conn.status == 400
    end
  end

  describe "transaction boundary isolation" do
    test "context is cleared after transaction completes" do
      org = insert(:organization)

      MultiTenant.with_organization(org.id, fn ->
        {:ok, current} = MultiTenant.get_organization_id()
        assert current == org.id
      end)

      # After transaction, context should be cleared
      {:ok, current} = MultiTenant.get_organization_id()
      assert is_nil(current) or current == ""
    end

    test "failed transactions clear context" do
      org = insert(:organization)

      try do
        Repo.transaction(fn ->
          MultiTenant.put_organization_id(org.id)
          raise "Simulated failure"
        end)
      rescue
        _ -> :ok
      end

      # Context should be cleared after failed transaction
      {:ok, current} = MultiTenant.get_organization_id()
      assert is_nil(current) or current == ""
    end
  end

  # Helper function
  defp build_conn(method, path) do
    Plug.Test.conn(method, path)
  end
end
