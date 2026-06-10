defmodule TamanduaServer.RLSTestHelpers do
  @moduledoc """
  Test helpers for working with Row-Level Security (RLS) in tests.

  This module provides utilities to:
  - Set up multi-tenant test data
  - Verify data isolation
  - Test RLS policies
  - Create test scenarios

  ## Usage

      use TamanduaServer.DataCase
      import TamanduaServer.RLSTestHelpers

      test "data isolation" do
        {org1, org2, data} = setup_two_orgs_with_data()

        # Test queries for org1
        assert_org_isolation(org1, data.org1_alerts)
      end
  """

  import Ecto.Query
  import ExUnit.Assertions

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  @doc """
  Creates two organizations with sample data for isolation testing.

  Returns:
  - org1: First organization
  - org2: Second organization
  - data: Map with test data for each organization

  ## Example

      {org1, org2, data} = setup_two_orgs_with_data()

      assert length(data.org1_alerts) == 3
      assert length(data.org2_alerts) == 2
  """
  def setup_two_orgs_with_data do
    org1 = insert(:organization, name: "Test Org 1")
    org2 = insert(:organization, name: "Test Org 2")

    # Create agents
    agent1 = insert(:agent, organization_id: org1.id, hostname: "agent-org1-1")
    agent2 = insert(:agent, organization_id: org1.id, hostname: "agent-org1-2")
    agent3 = insert(:agent, organization_id: org2.id, hostname: "agent-org2-1")

    # Create alerts
    org1_alerts = [
      insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Org1 Alert 1"),
      insert(:alert, organization_id: org1.id, agent_id: agent1.id, title: "Org1 Alert 2"),
      insert(:alert, organization_id: org1.id, agent_id: agent2.id, title: "Org1 Alert 3")
    ]

    org2_alerts = [
      insert(:alert, organization_id: org2.id, agent_id: agent3.id, title: "Org2 Alert 1"),
      insert(:alert, organization_id: org2.id, agent_id: agent3.id, title: "Org2 Alert 2")
    ]

    {org1, org2,
     %{
       org1: org1,
       org2: org2,
       org1_agents: [agent1, agent2],
       org2_agents: [agent3],
       org1_alerts: org1_alerts,
       org2_alerts: org2_alerts
     }}
  end

  @doc """
  Asserts that queries for an organization only return that org's data.

  ## Parameters

  - organization: The organization to test
  - expected_records: List of records that should be visible
  - schema: Schema module to query (default: Alert)

  ## Example

      assert_org_isolation(org1, expected_alerts, Alert)
  """
  def assert_org_isolation(organization, expected_records, schema \\ Alert) do
    actual_records =
      MultiTenant.with_organization(organization.id, fn ->
        Repo.all(schema)
      end)

    expected_ids = Enum.map(expected_records, & &1.id) |> Enum.sort()
    actual_ids = Enum.map(actual_records, & &1.id) |> Enum.sort()

    assert expected_ids == actual_ids,
           "Expected #{length(expected_records)} records, got #{length(actual_records)}"

    # Verify all records belong to organization
    assert Enum.all?(actual_records, fn record ->
             record.organization_id == organization.id
           end),
           "All records should belong to organization #{organization.id}"

    actual_records
  end

  @doc """
  Asserts that a record from another organization is not accessible.

  ## Example

      assert_cannot_access(org1, org2_alert)
  """
  def assert_cannot_access(organization, record) do
    result =
      MultiTenant.with_organization(organization.id, fn ->
        schema = record.__struct__
        Repo.get(schema, record.id)
      end)

    assert is_nil(result),
           "Should not be able to access record from another organization"
  end

  @doc """
  Asserts that a record from the same organization is accessible.

  ## Example

      assert_can_access(org1, org1_alert)
  """
  def assert_can_access(organization, record) do
    result =
      MultiTenant.with_organization(organization.id, fn ->
        schema = record.__struct__
        Repo.get(schema, record.id)
      end)

    refute is_nil(result),
           "Should be able to access record from same organization"

    assert result.id == record.id
    result
  end

  @doc """
  Asserts that insert only works with matching organization_id.

  ## Example

      # This should work
      assert_insert_allowed(org1, %{
        title: "New Alert",
        organization_id: org1.id,
        agent_id: agent1.id
      })

      # This should fail (wrong org_id)
      assert_insert_denied(org1, %{
        title: "New Alert",
        organization_id: org2.id,
        agent_id: agent1.id
      })
  """
  def assert_insert_allowed(organization, attrs, schema \\ Alert) do
    result =
      MultiTenant.with_organization(organization.id, fn ->
        struct(schema)
        |> schema.changeset(attrs)
        |> Repo.insert()
      end)

    assert {:ok, record} = result
    assert record.organization_id == organization.id
    record
  end

  def assert_insert_denied(organization, attrs, schema \\ Alert) do
    # Attempt to insert with wrong organization_id
    result =
      MultiTenant.with_organization(organization.id, fn ->
        struct(schema)
        |> schema.changeset(attrs)
        |> Repo.insert()
      end)

    # Should fail due to WITH CHECK policy
    assert {:error, _changeset} = result
  end

  @doc """
  Asserts that update only works on owned records.

  ## Example

      assert_update_allowed(org1, org1_alert, %{title: "Updated"})
      assert_update_denied(org1, org2_alert, %{title: "Hacked"})
  """
  def assert_update_allowed(organization, record, changes) do
    result =
      MultiTenant.with_organization(organization.id, fn ->
        record
        |> record.__struct__.changeset(changes)
        |> Repo.update()
      end)

    assert {:ok, updated} = result
    updated
  end

  def assert_update_denied(organization, record, changes) do
    # Should raise StaleEntryError because record not found (filtered by RLS)
    assert_raise Ecto.StaleEntryError, fn ->
      MultiTenant.with_organization(organization.id, fn ->
        record
        |> record.__struct__.changeset(changes)
        |> Repo.update()
      end)
    end
  end

  @doc """
  Asserts that delete only works on owned records.

  ## Example

      assert_delete_allowed(org1, org1_alert)
      assert_delete_denied(org1, org2_alert)
  """
  def assert_delete_allowed(organization, record) do
    result =
      MultiTenant.with_organization(organization.id, fn ->
        Repo.delete(record)
      end)

    assert {:ok, deleted} = result
    deleted
  end

  def assert_delete_denied(organization, record) do
    # Should raise StaleEntryError because record not found (filtered by RLS)
    assert_raise Ecto.StaleEntryError, fn ->
      MultiTenant.with_organization(organization.id, fn ->
        Repo.delete(record)
      end)
    end
  end

  @doc """
  Verifies that bypass mode allows access to all organizations.

  ## Example

      assert_bypass_sees_all(all_alerts)
  """
  def assert_bypass_sees_all(expected_records, schema \\ Alert) do
    actual_records =
      MultiTenant.with_bypass(fn ->
        Repo.all(schema)
      end)

    expected_ids = Enum.map(expected_records, & &1.id) |> Enum.sort()
    actual_ids = Enum.map(actual_records, & &1.id) |> Enum.sort()

    assert expected_ids == actual_ids,
           "Bypass should see all #{length(expected_records)} records"

    actual_records
  end

  @doc """
  Tests that concurrent queries maintain isolation.

  ## Example

      assert_concurrent_isolation(org1, org2, expected_org1_count, expected_org2_count)
  """
  def assert_concurrent_isolation(
        org1,
        org2,
        expected_org1_count,
        expected_org2_count,
        schema \\ Alert
      ) do
    parent = self()

    task1 =
      Task.async(fn ->
        count =
          MultiTenant.with_organization(org1.id, fn ->
            # Simulate concurrent execution
            Process.sleep(10)
            Repo.aggregate(schema, :count, :id)
          end)

        send(parent, {:org1, count})
      end)

    task2 =
      Task.async(fn ->
        count =
          MultiTenant.with_organization(org2.id, fn ->
            # Simulate concurrent execution
            Process.sleep(10)
            Repo.aggregate(schema, :count, :id)
          end)

        send(parent, {:org2, count})
      end)

    Task.await(task1)
    Task.await(task2)

    receive do
      {:org1, count} ->
        assert count == expected_org1_count,
               "Org1 should see #{expected_org1_count} records, got #{count}"
    end

    receive do
      {:org2, count} ->
        assert count == expected_org2_count,
               "Org2 should see #{expected_org2_count} records, got #{count}"
    end

    :ok
  end

  @doc """
  Measures RLS overhead for performance testing.

  Returns {rls_time_us, bypass_time_us, overhead_percent}

  ## Example

      {rls_time, bypass_time, overhead} = measure_rls_overhead(org, 100)
      assert overhead < 10.0, "RLS overhead should be <10%"
  """
  def measure_rls_overhead(organization, iterations \\ 100, schema \\ Alert) do
    # Measure with RLS
    {rls_time, _} =
      :timer.tc(fn ->
        for _i <- 1..iterations do
          MultiTenant.with_organization(organization.id, fn ->
            Repo.all(schema)
          end)
        end
      end)

    # Measure with bypass (no RLS)
    {bypass_time, _} =
      :timer.tc(fn ->
        for _i <- 1..iterations do
          MultiTenant.with_bypass(fn ->
            Repo.all(schema)
          end)
        end
      end)

    overhead = (rls_time - bypass_time) / bypass_time * 100

    {rls_time, bypass_time, overhead}
  end

  @doc """
  Creates a complete test scenario with multiple organizations and data.

  Returns a map with all test data organized by organization.

  ## Example

      scenario = create_test_scenario()
      assert length(scenario.org1.alerts) > 0
      assert length(scenario.org2.alerts) > 0
  """
  def create_test_scenario do
    # Create organizations
    org1 = insert(:organization, name: "Scenario Org 1")
    org2 = insert(:organization, name: "Scenario Org 2")
    org3 = insert(:organization, name: "Scenario Org 3")

    # Create users
    user1 = insert(:user, organization_id: org1.id, email: "user1@org1.com")
    user2 = insert(:user, organization_id: org2.id, email: "user2@org2.com")
    user3 = insert(:user, organization_id: org3.id, email: "user3@org3.com")

    # Create agents
    agent1_1 = insert(:agent, organization_id: org1.id, hostname: "agent1-1")
    agent1_2 = insert(:agent, organization_id: org1.id, hostname: "agent1-2")
    agent2_1 = insert(:agent, organization_id: org2.id, hostname: "agent2-1")
    agent3_1 = insert(:agent, organization_id: org3.id, hostname: "agent3-1")

    # Create alerts
    org1_alerts = [
      insert(:alert, organization_id: org1.id, agent_id: agent1_1.id, severity: "critical"),
      insert(:alert, organization_id: org1.id, agent_id: agent1_1.id, severity: "high"),
      insert(:alert, organization_id: org1.id, agent_id: agent1_2.id, severity: "medium")
    ]

    org2_alerts = [
      insert(:alert, organization_id: org2.id, agent_id: agent2_1.id, severity: "critical"),
      insert(:alert, organization_id: org2.id, agent_id: agent2_1.id, severity: "low")
    ]

    org3_alerts = [
      insert(:alert, organization_id: org3.id, agent_id: agent3_1.id, severity: "high")
    ]

    %{
      org1: %{
        organization: org1,
        users: [user1],
        agents: [agent1_1, agent1_2],
        alerts: org1_alerts
      },
      org2: %{
        organization: org2,
        users: [user2],
        agents: [agent2_1],
        alerts: org2_alerts
      },
      org3: %{
        organization: org3,
        users: [user3],
        agents: [agent3_1],
        alerts: org3_alerts
      }
    }
  end

  @doc """
  Verifies that RLS policies exist and are properly configured for a table.
  """
  def assert_rls_configured(table_name) when is_atom(table_name) do
    result = MultiTenant.validate_rls_config(table_name)

    assert :ok == result,
           "RLS should be properly configured on #{table_name}"
  end

  @doc """
  Asserts that preloading associations respects RLS.
  """
  def assert_preload_respects_rls(organization, record, association) do
    result =
      MultiTenant.with_organization(organization.id, fn ->
        record
        |> Repo.reload()
        |> Repo.preload(association)
      end)

    # Verify preloaded association also belongs to organization
    associated = Map.get(result, association)

    case associated do
      records when is_list(records) ->
        assert Enum.all?(records, fn r ->
                 r.organization_id == organization.id
               end),
               "All preloaded records should belong to organization"

      record when is_map(record) ->
        assert record.organization_id == organization.id,
               "Preloaded record should belong to organization"

      nil ->
        # Association is nil, that's fine
        :ok
    end

    result
  end

  # Private helper to get insert/1 from test case
  defp insert(factory, attrs \\ %{}) do
    # This assumes ExMachina or similar factory is available
    # Adjust based on your test setup
    apply(TamanduaServer.Factory, :insert, [factory, attrs])
  end
end
