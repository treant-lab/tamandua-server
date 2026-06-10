defmodule TamanduaServer.Integration.MultiTenantIsolationTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Remediation.Policy
  alias TamanduaServer.Remediation.Workflow

  @moduletag :enterprise

  describe "RLS coverage verification" do
    test "all tenant-scoped tables have RLS policies" do
      stats = MultiTenant.rls_stats()

      assert stats.tables_without_rls == [],
        "Tables missing RLS policies: #{inspect(stats.tables_without_rls)}"

      # Verify minimum expected tables
      assert stats.total_tables >= 10,
        "Expected at least 10 tenant-scoped tables, found #{stats.total_tables}"

      assert stats.rls_enabled == stats.total_tables,
        "Not all tables have RLS enabled: #{stats.rls_enabled}/#{stats.total_tables}"
    end

    test "validates RLS on core tables" do
      core_tables = [:alerts, :agents, :users, :remediation_policies, :remediation_workflows,
                     :detection_rules, :quarantine_entries, :audit_events]

      for table <- core_tables do
        assert :ok == MultiTenant.validate_rls_config(table),
          "RLS not properly configured on #{table}"
      end
    end
  end

  describe "cross-tenant query isolation" do
    setup do
      org1 = insert(:organization, name: "Enterprise A")
      org2 = insert(:organization, name: "Enterprise B")

      # Create data for org1
      agent1 = insert(:agent, organization_id: org1.id)
      user1 = insert(:user, organization_id: org1.id)
      alert1 = insert(:alert, organization_id: org1.id, agent_id: agent1.id)

      # Create data for org2
      agent2 = insert(:agent, organization_id: org2.id)
      user2 = insert(:user, organization_id: org2.id)
      alert2 = insert(:alert, organization_id: org2.id, agent_id: agent2.id)

      %{org1: org1, org2: org2, agent1: agent1, agent2: agent2,
        user1: user1, user2: user2, alert1: alert1, alert2: alert2}
    end

    test "organization cannot see other organization's alerts", ctx do
      org1_alerts = MultiTenant.with_organization(ctx.org1.id, fn ->
        Repo.all(Alert)
      end)

      assert length(org1_alerts) == 1
      assert hd(org1_alerts).id == ctx.alert1.id
      refute Enum.any?(org1_alerts, & &1.id == ctx.alert2.id)
    end

    test "organization cannot see other organization's agents", ctx do
      org1_agents = MultiTenant.with_organization(ctx.org1.id, fn ->
        Repo.all(Agent)
      end)

      assert length(org1_agents) == 1
      assert hd(org1_agents).id == ctx.agent1.id
    end

    test "organization cannot see other organization's users", ctx do
      org1_users = MultiTenant.with_organization(ctx.org1.id, fn ->
        Repo.all(User)
      end)

      assert length(org1_users) == 1
      assert hd(org1_users).id == ctx.user1.id
    end

    test "cannot fetch cross-tenant record by ID", ctx do
      result = MultiTenant.with_organization(ctx.org1.id, fn ->
        Repo.get(Alert, ctx.alert2.id)
      end)

      assert is_nil(result)
    end

    test "cannot update cross-tenant records", ctx do
      assert_raise Ecto.StaleEntryError, fn ->
        MultiTenant.with_organization(ctx.org1.id, fn ->
          ctx.alert2
          |> Ecto.Changeset.change(%{title: "Hacked!"})
          |> Repo.update!()
        end)
      end
    end

    test "cannot delete cross-tenant records", ctx do
      assert_raise Ecto.StaleEntryError, fn ->
        MultiTenant.with_organization(ctx.org1.id, fn ->
          Repo.delete!(ctx.alert2)
        end)
      end
    end
  end

  describe "bypass security" do
    test "bypass is audited via Logger.warning" do
      # Capture log output
      log = ExUnit.CaptureLog.capture_log(fn ->
        MultiTenant.with_bypass(fn ->
          Repo.all(Alert)
        end)
      end)

      assert log =~ "RLS bypass enabled"
    end

    test "bypass can see all organizations" do
      org1 = insert(:organization)
      org2 = insert(:organization)
      insert(:alert, organization_id: org1.id, agent_id: insert(:agent, organization_id: org1.id).id)
      insert(:alert, organization_id: org2.id, agent_id: insert(:agent, organization_id: org2.id).id)

      all_alerts = MultiTenant.with_bypass(fn ->
        Repo.all(Alert)
      end)

      assert length(all_alerts) >= 2
    end
  end

  describe "concurrent access isolation" do
    test "parallel requests maintain organization isolation" do
      org1 = insert(:organization, name: "Concurrent Org 1")
      org2 = insert(:organization, name: "Concurrent Org 2")

      for i <- 1..5 do
        insert(:alert, organization_id: org1.id, title: "Org1 Alert #{i}",
               agent_id: insert(:agent, organization_id: org1.id).id)
        insert(:alert, organization_id: org2.id, title: "Org2 Alert #{i}",
               agent_id: insert(:agent, organization_id: org2.id).id)
      end

      tasks = for _ <- 1..10 do
        Task.async(fn ->
          {org1_count, org2_count} = {
            MultiTenant.with_organization(org1.id, fn ->
              Repo.aggregate(Alert, :count, :id)
            end),
            MultiTenant.with_organization(org2.id, fn ->
              Repo.aggregate(Alert, :count, :id)
            end)
          }
          {org1_count, org2_count}
        end)
      end

      results = Task.await_many(tasks)

      for {org1_count, org2_count} <- results do
        assert org1_count == 5, "Org1 saw wrong count: #{org1_count}"
        assert org2_count == 5, "Org2 saw wrong count: #{org2_count}"
      end
    end
  end

  describe "SQL injection protection" do
    test "malicious organization_id is rejected" do
      malicious_ids = [
        "'; DROP TABLE alerts; --",
        "1' OR '1'='1",
        "1; SELECT * FROM users WHERE '1'='1"
      ]

      for malicious_id <- malicious_ids do
        assert_raise ArgumentError, fn ->
          MultiTenant.put_organization_id(malicious_id)
        end
      end
    end
  end

  describe "transaction behavior" do
    test "rollback clears organization context" do
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
      assert is_nil(current)
    end

    test "nested transactions maintain context" do
      org = insert(:organization)

      result = MultiTenant.with_organization(org.id, fn ->
        Repo.transaction(fn ->
          {:ok, current} = MultiTenant.get_organization_id()
          assert current == org.id
          "nested success"
        end)
      end)

      assert {:ok, "nested success"} = result
    end
  end

  describe "RLS performance" do
    setup do
      org1 = insert(:organization, name: "Perf Test Org 1")
      org2 = insert(:organization, name: "Perf Test Org 2")

      agent1 = insert(:agent, organization_id: org1.id)
      agent2 = insert(:agent, organization_id: org2.id)

      # Create 50 alerts for each organization
      for i <- 1..50 do
        insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Alert #{i}")
        insert(:alert, organization_id: org2.id, agent_id: agent2.id, title: "Alert #{i}")
      end

      %{org1: org1, org2: org2}
    end

    test "RLS overhead is less than 50% compared to bypass", %{org1: org1} do
      # Measure query time with RLS
      {rls_time, _result} = :timer.tc(fn ->
        MultiTenant.with_organization(org1.id, fn ->
          for _i <- 1..50 do
            Repo.all(Alert)
          end
        end)
      end)

      # Measure query time with bypass (no RLS)
      {bypass_time, _result} = :timer.tc(fn ->
        MultiTenant.with_bypass(fn ->
          for _i <- 1..50 do
            Repo.all(Alert)
          end
        end)
      end)

      # Calculate overhead percentage
      overhead_pct = ((rls_time - bypass_time) / bypass_time * 100)

      # Log results for visibility
      IO.puts("\nRLS Performance Test:")
      IO.puts("  RLS Time:    #{rls_time / 1000}ms")
      IO.puts("  Bypass Time: #{bypass_time / 1000}ms")
      IO.puts("  Overhead:    #{Float.round(overhead_pct, 2)}%")

      # Assert overhead is reasonable (<50%)
      assert overhead_pct < 50, "RLS overhead is too high: #{overhead_pct}%"
    end
  end
end
