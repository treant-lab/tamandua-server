defmodule TamanduaServer.Alerts.CorrelationEngineTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Alerts.{Alert, CorrelationEngine, AlertCorrelation}
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Agents.Agent

  setup do
    # Create organization
    {:ok, org} = %Organization{}
    |> Organization.changeset(%{name: "Test Org", api_key: "test-key"})
    |> Repo.insert()

    # Create agent
    {:ok, agent} = %Agent{}
    |> Agent.changeset(%{
      hostname: "test-host",
      ip_address: "192.168.1.100",
      os_type: "linux",
      organization_id: org.id
    })
    |> Repo.insert()

    # Start correlation engine
    {:ok, _pid} = start_supervised(CorrelationEngine)

    {:ok, %{organization: org, agent: agent}}
  end

  describe "correlate_alert/2" do
    test "correlates alerts with shared IOCs", %{organization: org, agent: agent} do
      sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

      # Create first alert with IOC
      {:ok, alert1} = create_alert(org, agent, %{
        title: "Malware detected",
        evidence: %{
          "file_hashes" => %{
            "sha256" => sha256
          }
        }
      })

      # Wait a bit
      Process.sleep(100)

      # Create second alert with same IOC
      {:ok, alert2} = create_alert(org, agent, %{
        title: "Suspicious file access",
        evidence: %{
          "file_hashes" => %{
            "sha256" => sha256
          }
        }
      })

      # Correlate alert2
      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      assert length(correlations) > 0

      # Should find alert1
      assert Enum.any?(correlations, fn {alert, score, types} ->
        alert.id == alert1.id and score > 0.5 and "ioc" in types
      end)
    end

    test "does not correlate alerts with shared MITRE techniques alone", %{organization: org, agent: agent} do
      {:ok, alert1} = create_alert(org, agent, %{
        title: "Credential dumping",
        mitre_techniques: ["T1003"]
      })

      Process.sleep(100)

      {:ok, alert2} = create_alert(org, agent, %{
        title: "LSASS access",
        mitre_techniques: ["T1003", "T1055"]
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      refute_correlated_with(correlations, alert1)
    end

    test "does not correlate alerts by temporal proximity alone", %{organization: org, agent: agent} do
      {:ok, alert1} = create_alert(org, agent, %{title: "Alert 1"})
      {:ok, alert2} = create_alert(org, agent, %{title: "Alert 2"})

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      refute_correlated_with(correlations, alert1)
    end

    test "does not correlate alerts by common process name alone", %{organization: org, agent: agent} do
      {:ok, alert1} = create_alert(org, agent, %{
        title: "Browser network anomaly",
        evidence: %{
          "process" => %{
            "name" => "chrome.exe",
            "pid" => 10_001,
            "user" => "alice"
          }
        }
      })

      {:ok, alert2} = create_alert(org, agent, %{
        title: "Browser child process anomaly",
        evidence: %{
          "process" => %{
            "name" => "chrome.exe",
            "pid" => 20_002,
            "user" => "bob"
          }
        }
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      refute_correlated_with(correlations, alert1)
    end

    test "does not correlate alerts by equal severity alone", %{organization: org, agent: agent} do
      {:ok, alert1} = create_alert(org, agent, %{
        title: "Medium severity alert 1",
        severity: "high"
      })

      {:ok, alert2} = create_alert(org, agent, %{
        title: "Medium severity alert 2",
        severity: "high"
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      refute_correlated_with(correlations, alert1)
    end

    test "does not correlate alerts by generic MITRE technique without strong entity evidence", %{organization: org, agent: agent} do
      {:ok, alert1} = create_alert(org, agent, %{
        title: "Generic command execution",
        mitre_techniques: ["T1059"],
        mitre_tactics: ["execution"]
      })

      {:ok, alert2} = create_alert(org, agent, %{
        title: "Unrelated command execution",
        mitre_techniques: ["T1059"],
        mitre_tactics: ["execution"]
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      refute_correlated_with(correlations, alert1)
    end

    test "does not correlate unrelated alerts", %{organization: org, agent: agent} do
      # Create alert in the past
      past_time = DateTime.add(DateTime.utc_now(), -7200, :second)  # 2 hours ago

      {:ok, alert1} = %Alert{}
      |> Alert.changeset(%{
        title: "Old alert",
        severity: "low",
        organization_id: org.id,
        agent_id: agent.id,
        inserted_at: past_time,
        updated_at: past_time
      })
      |> Repo.insert()

      # Create new alert with different characteristics
      {:ok, alert2} = create_alert(org, agent, %{
        title: "New alert",
        severity: "critical",
        mitre_techniques: ["T1059"]
      })

      {:ok, correlations} = CorrelationEngine.correlate_alert(alert2.id)

      # Should not find old unrelated alert
      refute Enum.any?(correlations, fn {alert, _score, _types} ->
        alert.id == alert1.id
      end)
    end
  end

  describe "build_correlation_graph/2" do
    test "builds graph with nodes and edges", %{organization: org, agent: agent} do
      # Create correlated alerts
      {:ok, alert1} = create_alert(org, agent, %{
        title: "Alert 1",
        evidence: %{"file_hashes" => %{"sha256" => "abc123"}}
      })

      {:ok, alert2} = create_alert(org, agent, %{
        title: "Alert 2",
        evidence: %{"file_hashes" => %{"sha256" => "abc123"}}
      })

      # Correlate them
      {:ok, _} = CorrelationEngine.correlate_alert(alert2.id)

      # Build graph
      {:ok, graph} = CorrelationEngine.build_correlation_graph([alert1.id, alert2.id])

      assert is_map(graph)
      assert is_list(graph.nodes)
      assert is_list(graph.links)

      # Should have alert nodes
      assert length(graph.nodes) > 0

      # Should have correlation metadata
      assert is_map(graph.correlation_metadata)
      assert graph.correlation_metadata.total_alerts >= 2
    end

    test "expands graph to include related alerts", %{organization: org, agent: agent} do
      # Create chain of correlated alerts
      {:ok, alert1} = create_alert(org, agent, %{
        title: "Alert 1",
        evidence: %{"network" => %{"remote_ip" => "1.2.3.4"}}
      })

      {:ok, alert2} = create_alert(org, agent, %{
        title: "Alert 2",
        evidence: %{"network" => %{"remote_ip" => "1.2.3.4"}}
      })

      {:ok, alert3} = create_alert(org, agent, %{
        title: "Alert 3",
        evidence: %{"network" => %{"remote_ip" => "1.2.3.4"}}
      })

      # Correlate them
      {:ok, _} = CorrelationEngine.correlate_alert(alert2.id)
      {:ok, _} = CorrelationEngine.correlate_alert(alert3.id)

      # Build graph from alert1 with depth 2
      {:ok, graph} = CorrelationEngine.build_correlation_graph([alert1.id], depth: 2)

      # Should include all three alerts (expanded)
      alert_nodes = Enum.filter(graph.nodes, fn node -> node.type == "alert" end)
      alert_ids = Enum.map(alert_nodes, & &1.alert_id)

      assert alert1.id in alert_ids
      assert alert2.id in alert_ids or alert3.id in alert_ids
    end
  end

  describe "find_attack_paths/3" do
    test "finds direct path between correlated alerts", %{organization: org, agent: agent} do
      # Create path: alert1 -> alert2 -> alert3
      {:ok, alert1} = create_alert(org, agent, %{title: "Initial access"})
      {:ok, alert2} = create_alert(org, agent, %{title: "Lateral movement"})
      {:ok, alert3} = create_alert(org, agent, %{title: "Exfiltration"})

      # Create correlations
      create_correlation(alert1, alert2, 0.8, ["temporal"])
      create_correlation(alert2, alert3, 0.9, ["technique"])

      # Find path
      {:ok, paths} = CorrelationEngine.find_attack_paths(alert1.id, alert3.id, max_depth: 3)

      assert length(paths) > 0

      {path, score, ttps} = List.first(paths)
      assert alert1.id in path
      assert alert3.id in path
      assert score > 0.0
      assert is_map(ttps)
    end

    test "returns empty list when no path exists", %{organization: org, agent: agent} do
      # Create two unrelated alerts
      {:ok, alert1} = create_alert(org, agent, %{title: "Alert 1"})
      {:ok, alert2} = create_alert(org, agent, %{title: "Alert 2"})

      {:ok, paths} = CorrelationEngine.find_attack_paths(alert1.id, alert2.id, max_depth: 3)

      assert paths == []
    end
  end

  describe "get_correlation_stats/1" do
    test "returns correlation statistics", %{organization: org, agent: agent} do
      # Create and correlate some alerts
      {:ok, alert1} = create_alert(org, agent, %{title: "Alert 1"})
      {:ok, alert2} = create_alert(org, agent, %{title: "Alert 2"})

      create_correlation(alert1, alert2, 0.8, ["temporal"])

      {:ok, stats} = CorrelationEngine.get_correlation_stats(org.id)

      assert is_map(stats)
      assert stats.total_correlations >= 1
      assert is_float(stats.average_confidence)
      assert is_map(stats.correlation_types)
      assert is_list(stats.most_correlated_alerts)
    end
  end

  # Helper functions

  defp create_alert(org, agent, attrs) do
    default_attrs = %{
      title: "Test Alert",
      severity: "medium",
      organization_id: org.id,
      agent_id: agent.id
    }

    %Alert{}
    |> Alert.changeset(Map.merge(default_attrs, attrs))
    |> Repo.insert()
  end

  defp create_correlation(alert1, alert2, confidence, types) do
    %AlertCorrelation{}
    |> AlertCorrelation.changeset(%{
      alert_id: alert1.id,
      related_alert_id: alert2.id,
      correlation_type: List.first(types),
      confidence: confidence,
      similarity_score: confidence,
      metadata: %{"correlation_types" => types},
      organization_id: alert1.organization_id
    })
    |> Repo.insert()
  end

  defp refute_correlated_with(correlations, unexpected_alert) do
    refute Enum.any?(correlations, fn {alert, _score, _types} ->
      alert.id == unexpected_alert.id
    end)
  end
end
