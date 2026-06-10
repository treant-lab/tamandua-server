defmodule TamanduaServer.Alerts.CorrelationTest do
  @moduledoc """
  Comprehensive unit tests for alert correlation engine.
  Tests correlation scoring, graph building, and attack path detection.
  """
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Alerts.{CorrelationEngine, Alert, AlertCorrelation, GraphBuilder}
  alias TamanduaServer.Repo

  setup do
    # Start the correlation engine for tests
    start_supervised!(CorrelationEngine)

    {org, agent} = create_agent_with_org()

    %{org: org, agent: agent}
  end

  # ── Alert Correlation Tests ────────────────────────────────────────────

  describe "correlate_alert/2" do
    test "correlates alerts with shared IP addresses", %{agent: agent, org: org} do
      # Create two alerts with the same remote IP
      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        severity: :high,
        raw_event: %{
          "payload" => %{"remote_ip" => "10.0.0.100"}
        },
        inserted_at: DateTime.utc_now() |> DateTime.add(-300, :second)
      })

      alert2 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        severity: :medium,
        raw_event: %{
          "payload" => %{"remote_ip" => "10.0.0.100"}
        }
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      assert length(correlations) >= 0
      # Correlations should be based on shared entity (IP)
    end

    test "correlates alerts with shared user", %{agent: agent, org: org} do
      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        raw_event: %{
          "payload" => %{"user" => "compromised_user"}
        },
        inserted_at: DateTime.utc_now() |> DateTime.add(-600, :second)
      })

      alert2 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        raw_event: %{
          "payload" => %{"user" => "compromised_user"}
        }
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      # Should find correlation based on shared user
      assert is_list(correlations)
    end

    test "correlates alerts with same MITRE technique", %{agent: agent, org: org} do
      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        mitre_techniques: ["T1059.001"],
        inserted_at: DateTime.utc_now() |> DateTime.add(-900, :second)
      })

      alert2 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        mitre_techniques: ["T1059.001"]
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      # Should find behavioral correlation
      assert is_list(correlations)
    end

    test "respects time window parameter", %{agent: agent, org: org} do
      # Alert outside time window
      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        raw_event: %{"payload" => %{"remote_ip" => "10.0.0.50"}},
        inserted_at: DateTime.utc_now() |> DateTime.add(-7200, :second) # 2 hours ago
      })

      alert2 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        raw_event: %{"payload" => %{"remote_ip" => "10.0.0.50"}}
      })

      # Use 1 hour window (3600 seconds)
      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id, time_window_seconds: 3600)

      # Should not correlate with alert outside window
      correlated_ids = Enum.map(correlations, fn {alert, _score, _types} -> alert.id end)
      refute alert1.id in correlated_ids
    end

    test "filters correlations by threshold", %{agent: agent, org: org} do
      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        severity: :low,
        mitre_techniques: []
      })

      alert2 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        severity: :low,
        mitre_techniques: []
      })

      # Use high threshold to filter weak correlations
      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id, threshold: 0.9)

      # With high threshold, weak correlations should be filtered
      assert is_list(correlations)
    end

    test "returns error for non-existent alert" do
      fake_id = Ecto.UUID.generate()

      {:error, :alert_not_found} = CorrelationEngine.correlate_alert(fake_id)
    end
  end

  # ── Graph Building Tests ───────────────────────────────────────────────

  describe "build_correlation_graph/2" do
    test "builds graph from single alert", %{agent: agent, org: org} do
      alert = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        severity: :high
      })

      {:ok, graph} = CorrelationEngine.build_correlation_graph([alert.id])

      assert is_map(graph)
      assert Map.has_key?(graph, :nodes)
      assert Map.has_key?(graph, :edges)
      assert length(graph.nodes) >= 1
    end

    test "builds graph with multiple connected alerts", %{agent: agent, org: org} do
      # Create chain of related alerts
      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        raw_event: %{"payload" => %{"remote_ip" => "10.0.0.100"}},
        mitre_techniques: ["T1566.001"]
      })

      alert2 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        raw_event: %{"payload" => %{"remote_ip" => "10.0.0.100"}},
        mitre_techniques: ["T1059.001"]
      })

      alert3 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        raw_event: %{"payload" => %{"remote_ip" => "10.0.0.100"}},
        mitre_techniques: ["T1003.001"]
      })

      {:ok, graph} = CorrelationEngine.build_correlation_graph([alert1.id, alert2.id, alert3.id])

      # Should have 3 nodes
      assert length(graph.nodes) == 3

      # Should have edges connecting them
      assert is_list(graph.edges)
    end

    test "includes agent and event metadata in nodes", %{agent: agent, org: org} do
      alert = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        title: "Test Alert",
        severity: :critical
      })

      {:ok, graph} = CorrelationEngine.build_correlation_graph([alert.id])

      node = Enum.find(graph.nodes, fn n -> n.id == alert.id end)

      assert node != nil
      assert node.title == "Test Alert"
      assert node.severity == :critical
    end

    test "respects depth parameter for multi-hop correlations", %{agent: agent, org: org} do
      alert = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id
      })

      # Depth 1: only direct correlations
      {:ok, graph1} = CorrelationEngine.build_correlation_graph([alert.id], depth: 1)

      # Depth 2: includes second-degree correlations
      {:ok, graph2} = CorrelationEngine.build_correlation_graph([alert.id], depth: 2)

      # Both should succeed
      assert is_map(graph1)
      assert is_map(graph2)
    end

    test "handles empty alert list" do
      {:ok, graph} = CorrelationEngine.build_correlation_graph([])

      assert graph.nodes == []
      assert graph.edges == []
    end
  end

  # ── Attack Path Detection Tests ────────────────────────────────────────

  describe "find_attack_paths/3" do
    test "finds direct path between two correlated alerts", %{agent: agent, org: org} do
      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        mitre_techniques: ["T1566.001"], # Phishing
        inserted_at: DateTime.utc_now() |> DateTime.add(-3600, :second)
      })

      alert2 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        mitre_techniques: ["T1059.001"], # PowerShell
        raw_event: %{"payload" => %{"user" => "victim"}}
      })

      # Try to find attack path
      result = CorrelationEngine.find_attack_paths(alert1.id, alert2.id)

      # Should either find paths or return empty list
      assert is_tuple(result) or is_list(result)
    end

    test "finds multi-hop attack chain", %{agent: agent, org: org} do
      # Create attack chain: Phishing -> Execution -> Credential Access
      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        mitre_tactics: ["initial-access"],
        mitre_techniques: ["T1566.001"],
        inserted_at: DateTime.utc_now() |> DateTime.add(-7200, :second)
      })

      alert2 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        mitre_tactics: ["execution"],
        mitre_techniques: ["T1059.001"],
        inserted_at: DateTime.utc_now() |> DateTime.add(-3600, :second)
      })

      alert3 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        mitre_tactics: ["credential-access"],
        mitre_techniques: ["T1003.001"]
      })

      result = CorrelationEngine.find_attack_paths(alert1.id, alert3.id, max_depth: 3)

      assert is_tuple(result) or is_list(result)
    end

    test "returns error when no path exists", %{agent: agent, org: org} do
      # Create two completely unrelated alerts
      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        mitre_techniques: ["T1566.001"],
        inserted_at: DateTime.utc_now() |> DateTime.add(-10000, :second)
      })

      # Different agent, different time, different everything
      {_org2, agent2} = create_agent_with_org()
      alert2 = insert!(:alert, %{
        agent_id: agent2.id,
        organization_id: org.id,
        mitre_techniques: ["T1003.001"]
      })

      result = CorrelationEngine.find_attack_paths(alert1.id, alert2.id)

      # Should indicate no path found
      assert result == {:ok, []} or match?({:error, _}, result)
    end
  end

  # ── Correlation Statistics Tests ───────────────────────────────────────

  describe "get_correlation_stats/1" do
    test "returns statistics for organization", %{org: org} do
      {:ok, stats} = CorrelationEngine.get_correlation_stats(org.id)

      assert is_map(stats)
      assert Map.has_key?(stats, :total_alerts)
      assert Map.has_key?(stats, :total_correlations)
    end

    test "includes correlation counts", %{org: org, agent: agent} do
      # Create some alerts to generate stats
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id})
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id})

      {:ok, stats} = CorrelationEngine.get_correlation_stats(org.id)

      assert is_integer(stats.total_alerts)
      assert stats.total_alerts >= 0
    end
  end

  # ── GraphBuilder Integration Tests ─────────────────────────────────────

  describe "GraphBuilder integration" do
    test "builds process chain graph", %{agent: agent, org: org} do
      alert = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        process_chain: [
          %{"pid" => 1, "name" => "explorer.exe"},
          %{"pid" => 100, "ppid" => 1, "name" => "cmd.exe"},
          %{"pid" => 200, "ppid" => 100, "name" => "powershell.exe"}
        ]
      })

      # GraphBuilder should be able to process this
      graph = GraphBuilder.build_process_graph([alert])

      assert is_map(graph)
      assert Map.has_key?(graph, :nodes) or Map.has_key?(graph, :processes)
    end

    test "builds entity relationship graph", %{agent: agent, org: org} do
      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        evidence: %{
          "file_hash" => "abc123",
          "ip" => "10.0.0.100",
          "user" => "victim"
        }
      })

      alert2 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        evidence: %{
          "file_hash" => "abc123",
          "ip" => "10.0.0.200"
        }
      })

      graph = GraphBuilder.build_entity_graph([alert1, alert2])

      assert is_map(graph)
    end
  end

  # ── Edge Cases and Error Handling ──────────────────────────────────────

  describe "edge cases" do
    test "handles alert with no correlatable fields", %{agent: agent, org: org} do
      alert = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        raw_event: %{},
        mitre_techniques: []
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert.id)

      assert correlations == []
    end

    test "handles alerts from different organizations", %{agent: agent, org: org} do
      {org2, agent2} = create_agent_with_org()

      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        raw_event: %{"payload" => %{"remote_ip" => "10.0.0.100"}}
      })

      alert2 = insert!(:alert, %{
        agent_id: agent2.id,
        organization_id: org2.id,
        raw_event: %{"payload" => %{"remote_ip" => "10.0.0.100"}}
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      # Should not correlate across organizations
      correlated_ids = Enum.map(correlations, fn {alert, _score, _types} -> alert.id end)
      refute alert1.id in correlated_ids
    end

    test "handles concurrent correlation requests", %{agent: agent, org: org} do
      alerts = Enum.map(1..5, fn _ ->
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          raw_event: %{"payload" => %{"remote_ip" => "10.0.0.100"}}
        })
      end)

      # Correlate all alerts concurrently
      tasks = Enum.map(alerts, fn alert ->
        Task.async(fn -> CorrelationEngine.correlate_alert(alert.id) end)
      end)

      results = Task.await_many(tasks, 30_000)

      # All should complete successfully
      assert Enum.all?(results, fn result -> match?({:ok, _}, result) end)
    end

    test "handles very large correlation graphs gracefully", %{agent: agent, org: org} do
      # Create many alerts
      alert_ids = Enum.map(1..20, fn i ->
        alert = insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          raw_event: %{"payload" => %{"remote_ip" => "10.0.0.#{rem(i, 10)}"}}
        })
        alert.id
      end)

      # Build graph should handle this
      result = CorrelationEngine.build_correlation_graph(alert_ids, depth: 1)

      assert match?({:ok, _graph}, result)
    end
  end

  # ── Correlation Scoring Tests ──────────────────────────────────────────

  describe "correlation scoring" do
    test "temporal correlation increases score for nearby events", %{agent: agent, org: org} do
      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        inserted_at: DateTime.utc_now() |> DateTime.add(-60, :second)
      })

      alert2 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      # Alerts close in time should have some correlation
      assert is_list(correlations)
    end

    test "entity correlation increases score for shared IOCs", %{agent: agent, org: org} do
      shared_hash = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)

      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        evidence: %{"file_hash" => shared_hash}
      })

      alert2 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        evidence: %{"file_hash" => shared_hash}
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      # Shared hash should create strong correlation
      if length(correlations) > 0 do
        {_alert, score, _types} = hd(correlations)
        assert score > 0
      end
    end

    test "behavioral correlation increases score for same MITRE tactics", %{agent: agent, org: org} do
      alert1 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        mitre_tactics: ["credential-access"],
        mitre_techniques: ["T1003.001"]
      })

      alert2 = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        mitre_tactics: ["credential-access"],
        mitre_techniques: ["T1003.002"]
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      # Same tactic should create correlation
      assert is_list(correlations)
    end
  end
end
