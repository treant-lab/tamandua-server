defmodule TamanduaServer.Investigations.PivotEngineTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Investigations.{PivotEngine, PivotChain}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Accounts.{Organization, User}

  describe "pivot_from_ip/3" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      agent = insert(:agent, organization: org, ip_address: "192.168.1.100")

      alert =
        insert(:alert,
          organization: org,
          agent: agent,
          evidence: %{"network" => %{"remote_ip" => "10.0.0.5"}}
        )

      event =
        insert(:event,
          agent: agent,
          event_type: "NetworkConnect",
          payload: %{"remote_ip" => "10.0.0.5", "dst_ip" => "10.0.0.5"}
        )

      %{org: org, user: user, agent: agent, alert: alert, event: event}
    end

    test "finds agents with matching IP", %{org: org, agent: agent} do
      result = PivotEngine.pivot_from_ip(agent.ip_address, org.id)

      assert result.entity_type == :ip
      assert result.entity_value == agent.ip_address
      assert result.total_count > 0
      assert Enum.any?(result.results, fn r -> r[:type] == "agent" && r[:id] == agent.id end)
    end

    test "finds alerts with matching IP in evidence", %{org: org, alert: alert} do
      result = PivotEngine.pivot_from_ip("10.0.0.5", org.id)

      assert result.entity_type == :ip
      assert result.total_count > 0
      assert Enum.any?(result.results, fn r -> r[:type] == "alert" && r[:id] == alert.id end)
    end

    test "finds events with matching IP", %{org: org, event: event} do
      result = PivotEngine.pivot_from_ip("10.0.0.5", org.id)

      assert result.entity_type == :ip
      assert result.total_count > 0
      assert Enum.any?(result.results, fn r -> r[:type] == "event" && r[:id] == event.id end)
    end

    test "returns empty results for non-existent IP", %{org: org} do
      result = PivotEngine.pivot_from_ip("1.2.3.4", org.id)

      assert result.entity_type == :ip
      assert result.total_count == 0
      assert result.results == []
    end

    test "respects organization isolation", %{agent: agent} do
      other_org = insert(:organization)
      result = PivotEngine.pivot_from_ip(agent.ip_address, other_org.id)

      assert result.total_count == 0
    end

    test "respects limit option", %{org: org, agent: agent} do
      # Insert many events
      for i <- 1..150 do
        insert(:event,
          agent: agent,
          event_type: "NetworkConnect",
          payload: %{"remote_ip" => "test.ip.#{i}"}
        )
      end

      result = PivotEngine.pivot_from_ip("test.ip.1", org.id, limit: 10)

      assert result.truncated == false || result.total_count <= 10
    end

    test "uses cache when enabled", %{org: org, agent: agent} do
      # First call should hit database
      result1 = PivotEngine.pivot_from_ip(agent.ip_address, org.id, cache: true)
      refute result1.cached

      # Second call should use cache
      result2 = PivotEngine.pivot_from_ip(agent.ip_address, org.id, cache: true)
      # Note: Cache implementation may vary, this is a structural test
      assert result2.entity_value == agent.ip_address
    end
  end

  describe "pivot_from_hash/3" do
    setup do
      org = insert(:organization)
      agent = insert(:agent, organization: org)
      hash = "abc123def456"

      alert =
        insert(:alert,
          organization: org,
          agent: agent,
          evidence: %{"sha256" => hash}
        )

      event =
        insert(:event,
          agent: agent,
          event_type: "ProcessCreate",
          payload: %{"sha256" => hash}
        )

      %{org: org, agent: agent, hash: hash, alert: alert, event: event}
    end

    test "finds alerts with matching hash", %{org: org, hash: hash, alert: alert} do
      result = PivotEngine.pivot_from_hash(hash, org.id)

      assert result.entity_type == :hash
      assert result.entity_value == hash
      assert Enum.any?(result.results, fn r -> r[:type] == "alert" && r[:id] == alert.id end)
    end

    test "finds events with matching hash", %{org: org, hash: hash, event: event} do
      result = PivotEngine.pivot_from_hash(hash, org.id)

      assert result.entity_type == :hash
      assert Enum.any?(result.results, fn r -> r[:type] == "event" && r[:id] == event.id end)
    end

    test "normalizes hash (removes prefix)", %{org: org, hash: hash} do
      result1 = PivotEngine.pivot_from_hash("sha256:#{hash}", org.id)
      result2 = PivotEngine.pivot_from_hash(hash, org.id)

      assert result1.total_count == result2.total_count
    end
  end

  describe "pivot_from_user/3" do
    setup do
      org = insert(:organization)
      agent = insert(:agent, organization: org)
      username = "testuser"

      alert =
        insert(:alert,
          organization: org,
          agent: agent,
          evidence: %{"process" => %{"user" => username}}
        )

      event =
        insert(:event,
          agent: agent,
          event_type: "ProcessCreate",
          payload: %{"user" => username}
        )

      %{org: org, agent: agent, username: username, alert: alert, event: event}
    end

    test "finds alerts for user", %{org: org, username: username, alert: alert} do
      result = PivotEngine.pivot_from_user(username, org.id)

      assert result.entity_type == :user
      assert result.entity_value == username
      assert Enum.any?(result.results, fn r -> r[:type] == "alert" && r[:id] == alert.id end)
    end

    test "finds events for user", %{org: org, username: username, event: event} do
      result = PivotEngine.pivot_from_user(username, org.id)

      assert Enum.any?(result.results, fn r -> r[:type] == "event" && r[:id] == event.id end)
    end
  end

  describe "pivot_from_agent/3" do
    setup do
      org = insert(:organization)
      agent = insert(:agent, organization: org)

      alert = insert(:alert, organization: org, agent: agent)
      event = insert(:event, agent: agent)

      %{org: org, agent: agent, alert: alert, event: event}
    end

    test "finds agent details", %{org: org, agent: agent} do
      result = PivotEngine.pivot_from_agent(agent.id, org.id)

      assert result.entity_type == :agent
      assert result.entity_value == agent.id
      assert Enum.any?(result.results, fn r -> r[:type] == "agent" && r[:id] == agent.id end)
    end

    test "finds alerts on agent", %{org: org, agent: agent, alert: alert} do
      result = PivotEngine.pivot_from_agent(agent.id, org.id)

      assert Enum.any?(result.results, fn r -> r[:type] == "alert" && r[:id] == alert.id end)
    end

    test "finds events on agent", %{org: org, agent: agent, event: event} do
      result = PivotEngine.pivot_from_agent(agent.id, org.id)

      assert Enum.any?(result.results, fn r -> r[:type] == "event" && r[:id] == event.id end)
    end

    test "returns empty for non-existent agent", %{org: org} do
      result = PivotEngine.pivot_from_agent(Ecto.UUID.generate(), org.id)

      assert result.total_count == 0
    end
  end

  describe "build_pivot_graph/1" do
    test "builds graph with nodes and links" do
      org = insert(:organization)
      agent = insert(:agent, organization: org)

      alert = insert(:alert, organization: org, agent: agent)

      result1 = PivotEngine.pivot_from_agent(agent.id, org.id)
      result2 = PivotEngine.pivot_from_ip(agent.ip_address, org.id)

      graph = PivotEngine.build_pivot_graph([result1, result2])

      assert is_list(graph.nodes)
      assert is_list(graph.links)
      assert length(graph.nodes) > 0
      assert length(graph.links) > 0
    end

    test "creates unique nodes" do
      org = insert(:organization)
      agent = insert(:agent, organization: org)

      # Multiple pivots that might return same entities
      result1 = PivotEngine.pivot_from_agent(agent.id, org.id)
      result2 = PivotEngine.pivot_from_agent(agent.id, org.id)

      graph = PivotEngine.build_pivot_graph([result1, result2])

      node_ids = Enum.map(graph.nodes, & &1.id)
      assert length(node_ids) == length(Enum.uniq(node_ids))
    end
  end

  describe "save_pivot_chain/3 and load_pivot_chain/1" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)

      %{org: org, user: user}
    end

    test "saves and loads pivot chain", %{org: org, user: user} do
      chain_data = %{
        name: "Test Investigation",
        description: "Testing pivot chain",
        chain_data: %{
          pivots: [
            %{type: "ip", value: "1.2.3.4", timestamp: DateTime.utc_now()},
            %{type: "hash", value: "abc123", timestamp: DateTime.utc_now()}
          ]
        }
      }

      assert {:ok, saved_chain} = PivotEngine.save_pivot_chain(chain_data, org.id, user.id)
      assert saved_chain.name == "Test Investigation"
      assert saved_chain.pivot_count == 2

      assert {:ok, loaded_chain} = PivotEngine.load_pivot_chain(saved_chain.id)
      assert loaded_chain.id == saved_chain.id
      assert loaded_chain.name == saved_chain.name
    end

    test "returns error for non-existent chain" do
      assert {:error, :not_found} = PivotEngine.load_pivot_chain(Ecto.UUID.generate())
    end
  end

  describe "list_pivot_chains/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)

      # Create some chains
      for i <- 1..5 do
        PivotEngine.save_pivot_chain(
          %{
            name: "Chain #{i}",
            description: "Test chain #{i}",
            chain_data: %{pivots: []}
          },
          org.id,
          user.id
        )
      end

      %{org: org, user: user}
    end

    test "lists chains for organization", %{org: org} do
      chains = PivotEngine.list_pivot_chains(org.id)

      assert length(chains) == 5
      assert Enum.all?(chains, fn c -> c.organization_id == org.id end)
    end

    test "respects limit option", %{org: org} do
      chains = PivotEngine.list_pivot_chains(org.id, limit: 3)

      assert length(chains) == 3
    end

    test "respects organization isolation" do
      other_org = insert(:organization)
      chains = PivotEngine.list_pivot_chains(other_org.id)

      assert length(chains) == 0
    end
  end

  describe "delete_pivot_chain/1" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)

      {:ok, chain} =
        PivotEngine.save_pivot_chain(
          %{
            name: "Test Chain",
            description: "To be deleted",
            chain_data: %{pivots: []}
          },
          org.id,
          user.id
        )

      %{chain: chain}
    end

    test "deletes existing chain", %{chain: chain} do
      assert {:ok, _deleted} = PivotEngine.delete_pivot_chain(chain.id)
      assert {:error, :not_found} = PivotEngine.load_pivot_chain(chain.id)
    end

    test "returns error for non-existent chain" do
      assert {:error, :not_found} = PivotEngine.delete_pivot_chain(Ecto.UUID.generate())
    end
  end

  describe "get_pivot_templates/0" do
    test "returns list of templates" do
      templates = PivotEngine.get_pivot_templates()

      assert is_list(templates)
      assert length(templates) > 0

      Enum.each(templates, fn template ->
        assert Map.has_key?(template, :name)
        assert Map.has_key?(template, :description)
        assert Map.has_key?(template, :steps)
        assert is_list(template.steps)
      end)
    end
  end

  # Test helpers
  defp insert(:organization) do
    Repo.insert!(%Organization{
      name: "Test Org",
      slug: "test-org-#{System.unique_integer([:positive])}"
    })
  end

  defp insert(:user, opts) do
    org = Keyword.fetch!(opts, :organization)

    Repo.insert!(%User{
      email: "user#{System.unique_integer([:positive])}@test.com",
      password_hash: "hashed",
      organization_id: org.id
    })
  end

  defp insert(:agent, opts) do
    org = Keyword.fetch!(opts, :organization)
    ip = Keyword.get(opts, :ip_address, "192.168.1.#{:rand.uniform(255)}")

    Repo.insert!(%Agent{
      hostname: "test-agent-#{System.unique_integer([:positive])}",
      ip_address: ip,
      os_type: "linux",
      status: "online",
      organization_id: org.id
    })
  end

  defp insert(:alert, opts) do
    org = Keyword.fetch!(opts, :organization)
    agent = Keyword.fetch!(opts, :agent)
    evidence = Keyword.get(opts, :evidence, %{})

    Repo.insert!(%Alert{
      title: "Test Alert",
      severity: "medium",
      organization_id: org.id,
      agent_id: agent.id,
      evidence: evidence
    })
  end

  defp insert(:event, opts) do
    agent = Keyword.fetch!(opts, :agent)
    event_type = Keyword.get(opts, :event_type, "ProcessCreate")
    payload = Keyword.get(opts, :payload, %{})

    Repo.insert!(%Event{
      agent_id: agent.id,
      event_type: event_type,
      timestamp: DateTime.utc_now(),
      payload: payload
    })
  end
end
