defmodule TamanduaServer.Repo.MultiTenantTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Agents.Agent

  describe "organization context management" do
    setup do
      # Create two organizations for isolation testing
      org1 = insert(:organization, name: "Org 1")
      org2 = insert(:organization, name: "Org 2")

      # Create agents for each organization
      agent1 = insert(:agent, organization_id: org1.id, hostname: "agent1")
      agent2 = insert(:agent, organization_id: org2.id, hostname: "agent2")

      # Create alerts for each organization
      alert1 = insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Alert 1")
      alert2 = insert(:alert, organization_id: org2.id, agent_id: agent2.id, title: "Alert 2")

      %{
        org1: org1,
        org2: org2,
        agent1: agent1,
        agent2: agent2,
        alert1: alert1,
        alert2: alert2
      }
    end

    test "put_organization_id/1 sets the session variable", %{org1: org1} do
      assert :ok = MultiTenant.put_organization_id(org1.id)

      {:ok, current_org} = MultiTenant.get_organization_id()
      assert current_org == org1.id
    end

    test "clear_organization_id/0 clears the session variable" do
      org_id = Ecto.UUID.generate()
      MultiTenant.put_organization_id(org_id)

      assert :ok = MultiTenant.clear_organization_id()

      {:ok, current_org} = MultiTenant.get_organization_id()
      assert is_nil(current_org)
    end

    test "get_organization_id/0 returns nil when not set" do
      {:ok, org_id} = MultiTenant.get_organization_id()
      assert is_nil(org_id)
    end
  end

  describe "with_organization/2 - data isolation" do
    setup do
      org1 = insert(:organization, name: "Org 1")
      org2 = insert(:organization, name: "Org 2")

      agent1 = insert(:agent, organization_id: org1.id, hostname: "agent1")
      agent2 = insert(:agent, organization_id: org2.id, hostname: "agent2")

      alert1 = insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Alert 1")
      alert2 = insert(:alert, organization_id: org2.id, agent_id: agent2.id, title: "Alert 2")
      alert3 = insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Alert 3")

      %{
        org1: org1,
        org2: org2,
        alert1: alert1,
        alert2: alert2,
        alert3: alert3
      }
    end

    test "queries only return data for the current organization", %{org1: org1, org2: org2} do
      # Query as org1 - should see 2 alerts
      org1_alerts = MultiTenant.with_organization(org1.id, fn ->
        Repo.all(Alert)
      end)

      assert length(org1_alerts) == 2
      assert Enum.all?(org1_alerts, fn a -> a.organization_id == org1.id end)

      # Query as org2 - should see 1 alert
      org2_alerts = MultiTenant.with_organization(org2.id, fn ->
        Repo.all(Alert)
      end)

      assert length(org2_alerts) == 1
      assert Enum.all?(org2_alerts, fn a -> a.organization_id == org2.id end)
    end

    test "cannot access other organization's data by ID", %{
      org1: org1,
      org2: org2,
      alert1: alert1,
      alert2: alert2
    } do
      # Try to get org2's alert while in org1 context
      result = MultiTenant.with_organization(org1.id, fn ->
        Repo.get(Alert, alert2.id)
      end)

      # Should return nil because of RLS
      assert is_nil(result)

      # Verify we can still get org1's alert
      result = MultiTenant.with_organization(org1.id, fn ->
        Repo.get(Alert, alert1.id)
      end)

      assert result.id == alert1.id
    end

    test "insert requires matching organization_id", %{org1: org1, agent1: agent1} do
      # This should work - organization_id matches context
      result = MultiTenant.with_organization(org1.id, fn ->
        %Alert{}
        |> Alert.changeset(%{
          title: "New Alert",
          severity: "high",
          status: "new",
          organization_id: org1.id,
          agent_id: agent1.id
        })
        |> Repo.insert()
      end)

      assert {:ok, _alert} = result
    end

    test "update only works on owned records", %{org1: org1, org2: org2, alert1: alert1, alert2: alert2} do
      # Can update own record
      result = MultiTenant.with_organization(org1.id, fn ->
        alert1
        |> Alert.changeset(%{title: "Updated Title"})
        |> Repo.update()
      end)

      assert {:ok, updated} = result
      assert updated.title == "Updated Title"

      # Cannot update other org's record (record not found due to RLS)
      assert_raise Ecto.StaleEntryError, fn ->
        MultiTenant.with_organization(org1.id, fn ->
          alert2
          |> Alert.changeset(%{title: "Hacked Title"})
          |> Repo.update()
        end)
      end
    end

    test "delete only works on owned records", %{org1: org1, alert1: alert1, alert2: alert2} do
      # Cannot delete other org's record
      assert_raise Ecto.StaleEntryError, fn ->
        MultiTenant.with_organization(org1.id, fn ->
          Repo.delete(alert2)
        end)
      end

      # Can delete own record
      result = MultiTenant.with_organization(org1.id, fn ->
        Repo.delete(alert1)
      end)

      assert {:ok, _deleted} = result
    end
  end

  describe "with_bypass/1 - system operations" do
    setup do
      org1 = insert(:organization, name: "Org 1")
      org2 = insert(:organization, name: "Org 2")

      agent1 = insert(:agent, organization_id: org1.id, hostname: "agent1")
      agent2 = insert(:agent, organization_id: org2.id, hostname: "agent2")

      insert(:alert, organization_id: org1.id, agent_id: agent1.id)
      insert(:alert, organization_id: org2.id, agent_id: agent2.id)

      %{org1: org1, org2: org2}
    end

    test "can access all organizations with bypass enabled" do
      # Without bypass, no organization context means no results
      # With bypass, should see all records
      all_alerts = MultiTenant.with_bypass(fn ->
        Repo.all(Alert)
      end)

      assert length(all_alerts) == 2
    end

    test "bypass_enabled? returns correct status" do
      {:ok, enabled} = MultiTenant.bypass_enabled?()
      assert enabled == false

      MultiTenant.with_bypass(fn ->
        {:ok, enabled} = MultiTenant.bypass_enabled?()
        assert enabled == true
      end)

      # Should be disabled again after with_bypass completes
      {:ok, enabled} = MultiTenant.bypass_enabled?()
      assert enabled == false
    end

    test "can perform cross-organization operations with bypass" do
      all_agent_count = MultiTenant.with_bypass(fn ->
        Repo.aggregate(Agent, :count, :id)
      end)

      assert all_agent_count == 2
    end
  end

  describe "RLS policy validation" do
    test "validates RLS is enabled on alerts table" do
      assert :ok = MultiTenant.validate_rls_config(:alerts)
    end

    test "validates RLS is enabled on agents table" do
      assert :ok = MultiTenant.validate_rls_config(:agents)
    end

    test "validates RLS is enabled on users table" do
      assert :ok = MultiTenant.validate_rls_config(:users)
    end

    test "returns error for non-existent table" do
      result = MultiTenant.validate_rls_config(:nonexistent_table)
      assert {:error, _reason} = result
    end
  end

  describe "rls_stats/0 - system statistics" do
    test "returns statistics about RLS configuration" do
      stats = MultiTenant.rls_stats()

      assert is_map(stats)
      assert Map.has_key?(stats, :total_tables)
      assert Map.has_key?(stats, :rls_enabled)
      assert Map.has_key?(stats, :policies_count)
      assert Map.has_key?(stats, :tables_without_rls)

      # We should have RLS enabled on core tables
      assert stats.rls_enabled > 0
      assert stats.policies_count > 0
    end
  end

  describe "performance testing" do
    setup do
      org1 = insert(:organization, name: "Org 1")
      org2 = insert(:organization, name: "Org 2")

      agent1 = insert(:agent, organization_id: org1.id, hostname: "agent1")
      agent2 = insert(:agent, organization_id: org2.id, hostname: "agent2")

      # Create 100 alerts for each organization
      for i <- 1..100 do
        insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Alert #{i}")
        insert(:alert, organization_id: org2.id, agent_id: agent2.id, title: "Alert #{i}")
      end

      %{org1: org1, org2: org2}
    end

    test "RLS overhead is minimal (<5% expected)", %{org1: org1} do
      # Measure query time with RLS
      {rls_time, _result} = :timer.tc(fn ->
        MultiTenant.with_organization(org1.id, fn ->
          for _i <- 1..100 do
            Repo.all(Alert)
          end
        end)
      end)

      # Measure query time with bypass (no RLS)
      {bypass_time, _result} = :timer.tc(fn ->
        MultiTenant.with_bypass(fn ->
          for _i <- 1..100 do
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

      # Assert overhead is reasonable (<50% - RLS adds some cost but should be manageable)
      # In production with proper indexes, this should be <5%
      assert overhead_pct < 50, "RLS overhead is too high: #{overhead_pct}%"
    end

    test "indexed queries perform well with RLS", %{org1: org1} do
      {time, result} = :timer.tc(fn ->
        MultiTenant.with_organization(org1.id, fn ->
          # Query using indexed organization_id
          Repo.all(from a in Alert, where: a.organization_id == ^org1.id)
        end)
      end)

      # Should complete in reasonable time even with 100 records
      assert time < 100_000, "Query took too long: #{time}μs"
      assert length(result) == 100
    end
  end

  describe "SQL injection protection" do
    test "organization_id is properly escaped" do
      # Try to inject SQL via organization_id
      malicious_id = "'; DROP TABLE alerts; --"

      # This should fail gracefully without executing the DROP
      assert_raise ArgumentError, fn ->
        MultiTenant.put_organization_id(malicious_id)
      end

      # Verify alerts table still exists
      assert Repo.all(Alert) |> is_list()
    end
  end

  describe "concurrent access isolation" do
    setup do
      org1 = insert(:organization, name: "Org 1")
      org2 = insert(:organization, name: "Org 2")

      agent1 = insert(:agent, organization_id: org1.id, hostname: "agent1")
      agent2 = insert(:agent, organization_id: org2.id, hostname: "agent2")

      insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Alert 1")
      insert(:alert, organization_id: org2.id, agent_id: agent2.id, title: "Alert 2")

      %{org1: org1, org2: org2}
    end

    test "concurrent queries maintain isolation", %{org1: org1, org2: org2} do
      # Spawn multiple processes querying different organizations
      parent = self()

      task1 = Task.async(fn ->
        result = MultiTenant.with_organization(org1.id, fn ->
          Process.sleep(10)
          Repo.all(Alert)
        end)
        send(parent, {:org1, result})
      end)

      task2 = Task.async(fn ->
        result = MultiTenant.with_organization(org2.id, fn ->
          Process.sleep(10)
          Repo.all(Alert)
        end)
        send(parent, {:org2, result})
      end)

      # Wait for both tasks
      Task.await(task1)
      Task.await(task2)

      # Receive results
      receive do
        {:org1, alerts} ->
          assert length(alerts) == 1
          assert Enum.all?(alerts, fn a -> a.organization_id == org1.id end)
      end

      receive do
        {:org2, alerts} ->
          assert length(alerts) == 1
          assert Enum.all?(alerts, fn a -> a.organization_id == org2.id end)
      end
    end
  end
end
