defmodule TamanduaServer.Repo.RLSSecurityTest do
  use TamanduaServer.DataCase, async: false

  @moduledoc """
  Security-focused tests to verify RLS policies cannot be bypassed.

  These tests attempt various attack vectors to bypass RLS and verify
  that all attempts fail. This ensures defense-in-depth protection.

  ## Attack Vectors Tested

  1. SQL Injection via organization_id
  2. Direct SQL queries bypassing Ecto
  3. Manipulating session variables
  4. Race conditions
  5. NULL organization_id exploitation
  6. Transaction rollback attacks
  7. Subquery bypass attempts
  """

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Agents.Agent

  describe "SQL injection attacks" do
    setup do
      org1 = insert(:organization, name: "Victim Org")
      org2 = insert(:organization, name: "Attacker Org")

      agent1 = insert(:agent, organization_id: org1.id, hostname: "victim-agent")
      agent2 = insert(:agent, organization_id: org2.id, hostname: "attacker-agent")

      victim_alert = insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Victim Secret")
      attacker_alert = insert(:alert, organization_id: org2.id, agent_id: agent2.id, title: "Attacker Alert")

      %{
        org1: org1,
        org2: org2,
        victim_alert: victim_alert,
        attacker_alert: attacker_alert
      }
    end

    test "cannot inject SQL via organization_id to bypass RLS", %{org1: org1, org2: org2} do
      # Attempt 1: SQL comment injection
      assert_raise ArgumentError, fn ->
        MultiTenant.put_organization_id("#{org2.id}' OR '1'='1")
      end

      # Attempt 2: UNION injection
      assert_raise ArgumentError, fn ->
        MultiTenant.put_organization_id("#{org2.id}' UNION SELECT * FROM alerts --")
      end

      # Attempt 3: Subquery injection
      assert_raise ArgumentError, fn ->
        MultiTenant.put_organization_id("#{org2.id}' OR organization_id IN (SELECT id FROM organizations) --")
      end

      # Verify original data is still protected
      alerts = MultiTenant.with_organization(org2.id, fn ->
        Repo.all(Alert)
      end)

      assert length(alerts) == 1
      assert hd(alerts).title == "Attacker Alert"
    end

    test "cannot use SQL operators to bypass RLS", %{org2: org2} do
      # Try various SQL operators that might bypass string comparison
      malicious_ids = [
        "#{org2.id}' OR TRUE --",
        "#{org2.id}' OR 1=1 --",
        "#{org2.id}'; DROP POLICY alerts_organization_isolation --",
        "#{org2.id}'; SET app.rls_bypass = TRUE --",
        "NULL; SET app.current_organization_id = NULL --"
      ]

      for malicious_id <- malicious_ids do
        assert_raise ArgumentError, fn ->
          MultiTenant.put_organization_id(malicious_id)
        end
      end
    end
  end

  describe "direct SQL bypass attempts" do
    setup do
      org1 = insert(:organization, name: "Victim Org")
      org2 = insert(:organization, name: "Attacker Org")

      agent1 = insert(:agent, organization_id: org1.id, hostname: "victim-agent")
      insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Victim Secret")

      %{org1: org1, org2: org2}
    end

    test "cannot bypass RLS with raw SQL queries", %{org1: org1, org2: org2} do
      # Set context to org2
      MultiTenant.with_organization(org2.id, fn ->
        # Try to query org1's data with raw SQL
        result = Repo.query("SELECT * FROM alerts WHERE organization_id = $1", [org1.id])

        # Should return empty due to RLS
        assert {:ok, %{num_rows: 0}} = result
      end)
    end

    test "cannot disable RLS via SQL", %{org2: org2} do
      MultiTenant.with_organization(org2.id, fn ->
        # Try to disable RLS
        result = Repo.query("ALTER TABLE alerts DISABLE ROW LEVEL SECURITY")

        # Should fail - insufficient privileges
        assert {:error, _} = result
      end)
    end

    test "cannot drop RLS policies via SQL", %{org2: org2} do
      MultiTenant.with_organization(org2.id, fn ->
        # Try to drop RLS policy
        result = Repo.query("DROP POLICY alerts_organization_isolation ON alerts")

        # Should fail - insufficient privileges
        assert {:error, _} = result
      end)
    end

    test "cannot modify session variable directly to bypass", %{org1: org1, org2: org2} do
      MultiTenant.with_organization(org2.id, fn ->
        # Attacker sets session variable to victim's org
        Repo.query("SET LOCAL app.current_organization_id = $1", [org1.id])

        # Query should still respect the transaction-level context
        # The with_organization transaction already set the variable
        alerts = Repo.all(Alert)

        # Should not see victim's alerts
        assert Enum.all?(alerts, fn a -> a.organization_id == org2.id end)
      end)
    end
  end

  describe "session variable manipulation" do
    setup do
      org1 = insert(:organization, name: "Victim Org")
      org2 = insert(:organization, name: "Attacker Org")

      agent1 = insert(:agent, organization_id: org1.id, hostname: "victim-agent")
      insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Victim Secret")

      %{org1: org1, org2: org2}
    end

    test "cannot enable bypass flag without proper privileges", %{org2: org2} do
      MultiTenant.with_organization(org2.id, fn ->
        # Try to enable bypass
        Repo.query("SET LOCAL app.rls_bypass = TRUE")

        # Even if the flag is set, query should still be filtered
        # because the bypass function checks privileges
        alerts = Repo.all(Alert)

        # Should only see org2's alerts (none in this case)
        assert Enum.all?(alerts, fn a -> a.organization_id == org2.id end)
      end)
    end

    test "cannot clear organization_id to see all records", %{org1: org1, org2: org2} do
      # Start with org2 context
      MultiTenant.with_organization(org2.id, fn ->
        # Try to clear the organization context
        Repo.query("SET LOCAL app.current_organization_id = NULL")

        # Should not be able to query without organization context
        # Default RESTRICTIVE policy should deny access
        alerts = Repo.all(Alert)

        # Should see nothing (restrictive policy denies when NULL)
        assert alerts == []
      end)
    end
  end

  describe "NULL organization_id exploitation" do
    test "records with NULL organization_id are not accessible" do
      # This shouldn't happen in normal operation, but test it anyway
      agent = insert(:agent, organization_id: nil, hostname: "orphan-agent")

      # Try to query with a valid org context
      org = insert(:organization)

      alerts = MultiTenant.with_organization(org.id, fn ->
        Repo.all(Agent)
      end)

      # Should not include the NULL org_id record
      refute Enum.any?(alerts, fn a -> a.id == agent.id end)
    end

    test "cannot set organization_id to NULL to bypass RLS" do
      org = insert(:organization)

      # Try to set organization context to NULL
      result = MultiTenant.put_organization_id(nil)

      # Should raise error due to function guard
      assert_raise FunctionClauseError, fn ->
        MultiTenant.put_organization_id(nil)
      end
    end
  end

  describe "transaction and rollback attacks" do
    setup do
      org1 = insert(:organization, name: "Org 1")
      org2 = insert(:organization, name: "Org 2")

      agent1 = insert(:agent, organization_id: org1.id, hostname: "agent1")
      agent2 = insert(:agent, organization_id: org2.id, hostname: "agent2")

      alert1 = insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Alert 1")
      alert2 = insert(:alert, organization_id: org2.id, agent_id: agent2.id, title: "Alert 2")

      %{org1: org1, org2: org2, alert1: alert1, alert2: alert2}
    end

    test "cannot access other org's data via transaction nesting", %{org1: org1, org2: org2} do
      result = MultiTenant.with_organization(org1.id, fn ->
        # Start inner transaction with different org
        Repo.transaction(fn ->
          MultiTenant.put_organization_id(org2.id)
          Repo.all(Alert)
        end)
      end)

      # Inner transaction should only see org2's data
      case result do
        {:ok, alerts} ->
          assert length(alerts) == 1
          assert hd(alerts).organization_id == org2.id

        alerts when is_list(alerts) ->
          assert length(alerts) == 1
          assert hd(alerts).organization_id == org2.id
      end
    end

    test "RLS context is maintained after rollback", %{org1: org1, org2: org2, alert1: alert1} do
      MultiTenant.with_organization(org1.id, fn ->
        # Attempt an operation that will rollback
        try do
          Repo.transaction(fn ->
            # Try to update with wrong org context
            MultiTenant.put_organization_id(org2.id)
            Repo.update!(alert1 |> Ecto.Changeset.change(title: "Hacked"))
          end)
        rescue
          _ -> :ok
        end

        # After rollback, context should still be org1
        {:ok, current_org} = MultiTenant.get_organization_id()
        assert current_org == org1.id

        # And we should still see only org1's data
        alerts = Repo.all(Alert)
        assert Enum.all?(alerts, fn a -> a.organization_id == org1.id end)
      end)
    end
  end

  describe "subquery bypass attempts" do
    setup do
      org1 = insert(:organization, name: "Victim Org")
      org2 = insert(:organization, name: "Attacker Org")

      agent1 = insert(:agent, organization_id: org1.id, hostname: "victim-agent")
      agent2 = insert(:agent, organization_id: org2.id, hostname: "attacker-agent")

      insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Victim Secret")
      insert(:alert, organization_id: org2.id, agent_id: agent2.id, title: "Attacker Alert")

      %{org1: org1, org2: org2}
    end

    test "cannot use subquery to access other org's data", %{org1: org1, org2: org2} do
      alerts = MultiTenant.with_organization(org2.id, fn ->
        # Try to use subquery to bypass RLS
        Repo.all(
          from a in Alert,
          where: a.organization_id in subquery(
            from o in "organizations",
            select: o.id
          )
        )
      end)

      # Should still only see org2's alerts
      assert length(alerts) == 1
      assert hd(alerts).organization_id == org2.id
    end

    test "cannot join with organizations table to bypass", %{org2: org2} do
      results = MultiTenant.with_organization(org2.id, fn ->
        # Try to join with organizations to see all alerts
        Repo.all(
          from a in Alert,
          join: o in "organizations", on: a.organization_id == o.id,
          select: {a, o}
        )
      end)

      # Should still only see org2's alerts
      assert length(results) == 1
      {alert, _org} = hd(results)
      assert alert.organization_id == org2.id
    end
  end

  describe "privilege escalation attempts" do
    test "cannot become superuser to bypass RLS" do
      org = insert(:organization)

      MultiTenant.with_organization(org.id, fn ->
        # Try to escalate privileges
        result = Repo.query("SET ROLE postgres")

        # Should fail - insufficient privileges
        assert {:error, _} = result
      end)
    end

    test "cannot grant bypass privileges to self" do
      org = insert(:organization)

      MultiTenant.with_organization(org.id, fn ->
        # Try to grant BYPASSRLS
        result = Repo.query("ALTER USER CURRENT_USER BYPASSRLS")

        # Should fail - insufficient privileges
        assert {:error, _} = result
      end)
    end
  end

  describe "FORCE ROW LEVEL SECURITY verification" do
    test "RLS applies even to table owner" do
      # Verify that FORCE ROW LEVEL SECURITY is enabled
      # This means even the table owner (DB user) must follow RLS policies

      result = Repo.query("""
        SELECT relname, relforcerowsecurity
        FROM pg_class
        WHERE relname IN ('alerts', 'agents', 'users', 'events')
        AND relnamespace = 'public'::regnamespace
      """)

      assert {:ok, %{rows: rows}} = result

      # All critical tables should have FORCE RLS enabled
      for [_table, force_rls] <- rows do
        assert force_rls == true, "FORCE ROW LEVEL SECURITY must be enabled"
      end
    end

    test "default RESTRICTIVE policy exists" do
      # Verify that restrictive policies exist as safety net

      result = Repo.query("""
        SELECT tablename, policyname, permissive
        FROM pg_policies
        WHERE schemaname = 'public'
        AND tablename IN ('alerts', 'agents', 'users')
        AND policyname LIKE '%_deny_all'
      """)

      assert {:ok, %{rows: rows}} = result

      # Should have restrictive policies
      assert length(rows) > 0

      # Verify they are RESTRICTIVE (not PERMISSIVE)
      for [_table, _policy, permissive] <- rows do
        assert permissive == "RESTRICTIVE" or permissive == false
      end
    end
  end

  describe "cross-table attack vectors" do
    setup do
      org1 = insert(:organization, name: "Victim Org")
      org2 = insert(:organization, name: "Attacker Org")

      agent1 = insert(:agent, organization_id: org1.id, hostname: "victim-agent")
      agent2 = insert(:agent, organization_id: org2.id, hostname: "attacker-agent")

      alert1 = insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Victim Secret")

      %{org1: org1, org2: org2, agent1: agent1, agent2: agent2, alert1: alert1}
    end

    test "cannot access related records from other org via associations", %{org1: org1, org2: org2, agent1: agent1} do
      # Try to access victim's alerts via agent association
      result = MultiTenant.with_organization(org2.id, fn ->
        # Even if we somehow got the agent ID, we can't see its alerts
        Repo.all(
          from a in Alert,
          where: a.agent_id == ^agent1.id
        )
      end)

      # Should return empty - can't see other org's alerts
      assert result == []
    end

    test "preload respects RLS on associations", %{org2: org2} do
      alerts = MultiTenant.with_organization(org2.id, fn ->
        Alert
        |> Repo.all()
        |> Repo.preload(:agent)
      end)

      # Should only see org2's alerts and agents
      assert Enum.all?(alerts, fn a ->
        a.organization_id == org2.id and
        a.agent.organization_id == org2.id
      end)
    end
  end
end
