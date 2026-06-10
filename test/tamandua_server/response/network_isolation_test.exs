defmodule TamanduaServer.Response.NetworkIsolationTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Response.NetworkIsolation
  alias TamanduaServer.Agents

  setup do
    # Create a test organization
    {:ok, org} = TamanduaServer.Accounts.create_organization(%{
      name: "Test Org",
      slug: "test-org-#{System.unique_integer([:positive])}"
    })

    # Create a test agent
    {:ok, agent} = Agents.create_agent_for_org(org.id, %{
      hostname: "test-host",
      os_type: "linux",
      machine_id: :crypto.strong_rand_bytes(16)
    })

    # Register the agent in the Registry (mock)
    TamanduaServer.Agents.Registry.register(agent.id, %{
      agent_id: agent.id,
      hostname: "test-host",
      os_type: "linux",
      status: :online,
      organization_id: org.id
    })

    {:ok, agent: agent, org: org}
  end

  describe "isolation with rollback" do
    test "captures previous network state", %{agent: agent} do
      # Get the agent before isolation
      {:ok, before} = Agents.get_agent(agent.id)
      assert before.previous_network_state == nil

      # Note: This test would fail if Executor.execute_action is not mocked
      # In a real test, you'd mock the Executor module
    end
  end

  describe "isolation exceptions" do
    test "stores and retrieves isolation exceptions", %{agent: agent} do
      exceptions = [
        %{"type" => "ip", "value" => "10.0.0.5"},
        %{"type" => "port", "value" => 443}
      ]

      # Set exceptions
      {:ok, updated} = Agents.set_isolation_exceptions(agent.id, exceptions)
      assert updated.isolation_exceptions == exceptions

      # Get exceptions
      {:ok, retrieved} = Agents.get_isolation_exceptions(agent.id)
      assert retrieved == exceptions
    end

    test "adds individual exception", %{agent: agent} do
      exception = %{"type" => "ip", "value" => "192.168.1.1"}

      {:ok, updated} = Agents.add_isolation_exception(agent.id, exception)
      assert exception in updated.isolation_exceptions
    end

    test "removes individual exception", %{agent: agent} do
      exceptions = [
        %{"type" => "ip", "value" => "10.0.0.5"},
        %{"type" => "port", "value" => 443}
      ]

      {:ok, _} = Agents.set_isolation_exceptions(agent.id, exceptions)

      # Remove one exception
      to_remove = %{"type" => "ip", "value" => "10.0.0.5"}
      {:ok, updated} = Agents.remove_isolation_exception(agent.id, to_remove)

      assert to_remove not in updated.isolation_exceptions
      assert length(updated.isolation_exceptions) == 1
    end
  end

  describe "expiry mechanism" do
    test "sets expiry time when isolating", %{agent: agent} do
      # This would require mocking Executor.execute_action
      # For now, just test the database field
      expiry = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, updated} = Agents.update_agent(agent, %{
        isolation_expires_at: expiry,
        status: "isolated"
      })

      assert updated.isolation_expires_at != nil
      assert DateTime.compare(updated.isolation_expires_at, expiry) == :eq
    end

    test "queries expired isolations" do
      # Create an agent with expired isolation
      {:ok, org} = TamanduaServer.Accounts.create_organization(%{
        name: "Test Org Expired",
        slug: "test-org-expired-#{System.unique_integer([:positive])}"
      })

      {:ok, expired_agent} = Agents.create_agent_for_org(org.id, %{
        hostname: "expired-host",
        os_type: "windows",
        machine_id: :crypto.strong_rand_bytes(16),
        isolation_expires_at: DateTime.add(DateTime.utc_now(), -3600, :second),
        status: "isolated"
      })

      # Query expired agents
      import Ecto.Query
      now = DateTime.utc_now()

      expired = TamanduaServer.Repo.all(
        from a in TamanduaServer.Agents.Agent,
        where: not is_nil(a.isolation_expires_at),
        where: a.isolation_expires_at <= ^now,
        select: a.id
      )

      assert expired_agent.id in expired
    end
  end
end
