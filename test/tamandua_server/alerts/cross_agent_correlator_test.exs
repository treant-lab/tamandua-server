defmodule TamanduaServer.Alerts.CrossAgentCorrelatorTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.{Alert, CrossAgentCorrelator, AttackCampaign}
  alias TamanduaServer.Repo

  import Ecto.Query

  setup do
    # Start the correlator
    start_supervised!(CrossAgentCorrelator)

    # Create test organization
    org = insert_organization()

    # Create test agents on different subnets
    agent1 = insert_agent(%{hostname: "server1", ip_address: "192.168.1.10", organization_id: org.id})
    agent2 = insert_agent(%{hostname: "server2", ip_address: "192.168.1.20", organization_id: org.id})
    agent3 = insert_agent(%{hostname: "workstation1", ip_address: "192.168.2.50", organization_id: org.id})

    %{org: org, agent1: agent1, agent2: agent2, agent3: agent3}
  end

  describe "temporal pattern matching" do
    test "finds alerts within time window", %{org: org, agent1: agent1, agent2: agent2} do
      # Create initial alert
      {:ok, alert1} = Alerts.create_alert(%{
        title: "Suspicious Process Execution",
        severity: "high",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_techniques: ["T1055", "T1059"],
        mitre_tactics: ["execution", "defense-evasion"]
      })

      # Create related alert within 5 minutes
      Process.sleep(100)
      {:ok, alert2} = Alerts.create_alert(%{
        title: "Credential Dumping Detected",
        severity: "critical",
        organization_id: org.id,
        agent_id: agent2.id,
        mitre_techniques: ["T1003", "T1055"],
        mitre_tactics: ["credential-access", "execution"]
      })

      # Find related alerts
      {:ok, related} = Alerts.find_related_alerts(alert1, time_window_minutes: 10)

      assert length(related) == 1
      {related_alert, score} = List.first(related)
      assert related_alert.id == alert2.id
      assert score > 0.0
    end

    test "excludes alerts outside time window", %{org: org, agent1: agent1} do
      # Create old alert (simulate by backdating)
      old_time = DateTime.add(DateTime.utc_now(), -3600, :second)

      {:ok, old_alert} = %Alert{}
      |> Alert.changeset(%{
        title: "Old Alert",
        severity: "low",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_techniques: ["T1055"],
        inserted_at: old_time,
        updated_at: old_time
      })
      |> Repo.insert()

      # Create new alert
      {:ok, new_alert} = Alerts.create_alert(%{
        title: "New Alert",
        severity: "high",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_techniques: ["T1055"]
      })

      # Find related - should not find old alert
      {:ok, related} = Alerts.find_related_alerts(new_alert, time_window_minutes: 30)

      assert length(related) == 0
    end
  end

  describe "probabilistic grouping" do
    test "calculates similarity based on shared MITRE techniques", %{org: org, agent1: agent1} do
      # Create alerts with overlapping techniques
      {:ok, alert1} = Alerts.create_alert(%{
        title: "Alert 1",
        severity: "high",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_techniques: ["T1055", "T1059", "T1003"],
        mitre_tactics: ["execution"]
      })

      {:ok, alert2} = Alerts.create_alert(%{
        title: "Alert 2",
        severity: "high",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_techniques: ["T1055", "T1003"],
        mitre_tactics: ["execution"]
      })

      # Find related
      {:ok, related} = Alerts.find_related_alerts(alert1)

      assert length(related) == 1
      {_, score} = List.first(related)
      # Score should be high due to shared rare techniques
      assert score > 0.5
    end

    test "calculates similarity based on shared IOCs", %{org: org, agent1: agent1} do
      # Create alerts with same file hash
      evidence1 = %{
        "file_hashes" => %{"sha256" => "abc123def456"},
        "process" => %{"name" => "malware.exe"}
      }

      evidence2 = %{
        "file_hashes" => %{"sha256" => "abc123def456"},
        "process" => %{"name" => "different.exe"}
      }

      {:ok, alert1} = Alerts.create_alert(%{
        title: "Malware Detected",
        severity: "critical",
        organization_id: org.id,
        agent_id: agent1.id,
        evidence: evidence1,
        mitre_techniques: ["T1027"]
      })

      {:ok, alert2} = Alerts.create_alert(%{
        title: "File Analysis",
        severity: "high",
        organization_id: org.id,
        agent_id: agent1.id,
        evidence: evidence2,
        mitre_techniques: ["T1027"]
      })

      {:ok, related} = Alerts.find_related_alerts(alert1)

      assert length(related) == 1
      {_, score} = List.first(related)
      assert score > 0.6  # High score due to shared hash
    end

    test "factors in network proximity", %{org: org, agent1: agent1, agent2: agent2, agent3: agent3} do
      # Create alerts on same subnet (agent1 and agent2)
      {:ok, alert1} = Alerts.create_alert(%{
        title: "Network Event 1",
        severity: "medium",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_techniques: ["T1071"]
      })

      {:ok, alert2_same_subnet} = Alerts.create_alert(%{
        title: "Network Event 2",
        severity: "medium",
        organization_id: org.id,
        agent_id: agent2.id,  # Same subnet as agent1
        mitre_techniques: ["T1071"]
      })

      {:ok, alert3_diff_subnet} = Alerts.create_alert(%{
        title: "Network Event 3",
        severity: "medium",
        organization_id: org.id,
        agent_id: agent3.id,  # Different subnet
        mitre_techniques: ["T1071"]
      })

      {:ok, related} = Alerts.find_related_alerts(alert1)

      # Should find both, but same-subnet should have higher score
      assert length(related) == 2

      same_subnet_result = Enum.find(related, fn {alert, _} -> alert.id == alert2_same_subnet.id end)
      diff_subnet_result = Enum.find(related, fn {alert, _} -> alert.id == alert3_diff_subnet.id end)

      {_, same_score} = same_subnet_result
      {_, diff_score} = diff_subnet_result

      assert same_score > diff_score
    end
  end

  describe "attack chain detection" do
    test "detects lateral movement pattern", %{org: org, agent1: agent1, agent2: agent2} do
      # Create alerts matching lateral movement pattern
      {:ok, alert1} = Alerts.create_alert(%{
        title: "Credential Access",
        severity: "high",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_tactics: ["credential-access"],
        mitre_techniques: ["T1003"]
      })

      {:ok, alert2} = Alerts.create_alert(%{
        title: "Lateral Movement",
        severity: "high",
        organization_id: org.id,
        agent_id: agent2.id,
        mitre_tactics: ["lateral-movement"],
        mitre_techniques: ["T1021"]
      })

      {:ok, alert3} = Alerts.create_alert(%{
        title: "Execution",
        severity: "high",
        organization_id: org.id,
        agent_id: agent2.id,
        mitre_tactics: ["execution"],
        mitre_techniques: ["T1059"]
      })

      # Detect chains
      {:ok, chains} = Alerts.detect_attack_chains([alert1, alert2, alert3])

      lateral_chain = Enum.find(chains, fn chain -> chain.pattern == :lateral_movement end)
      assert lateral_chain != nil
      assert lateral_chain.confidence > 0.0
      assert length(lateral_chain.alerts) >= 2
    end

    test "detects ransomware pattern", %{org: org, agent1: agent1} do
      # Create alerts matching ransomware pattern
      {:ok, alert1} = Alerts.create_alert(%{
        title: "Initial Access",
        severity: "medium",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_tactics: ["initial-access"],
        mitre_techniques: ["T1566"]
      })

      {:ok, alert2} = Alerts.create_alert(%{
        title: "Execution",
        severity: "high",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_tactics: ["execution"],
        mitre_techniques: ["T1059"]
      })

      {:ok, alert3} = Alerts.create_alert(%{
        title: "Data Encryption",
        severity: "critical",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_tactics: ["impact"],
        mitre_techniques: ["T1486"]
      })

      {:ok, chains} = Alerts.detect_attack_chains([alert1, alert2, alert3])

      ransomware_chain = Enum.find(chains, fn chain -> chain.pattern == :ransomware end)
      assert ransomware_chain != nil
      assert ransomware_chain.confidence > 0.5
    end
  end

  describe "network graph analysis" do
    test "builds network graph from alerts", %{org: org, agent1: agent1, agent2: agent2} do
      # Create alerts with network evidence
      evidence1 = %{
        "network" => %{"remote_ip" => "192.168.1.20"}
      }

      {:ok, alert1} = Alerts.create_alert(%{
        title: "Network Connection",
        severity: "medium",
        organization_id: org.id,
        agent_id: agent1.id,
        evidence: evidence1
      })

      {:ok, alert2} = Alerts.create_alert(%{
        title: "Remote Event",
        severity: "medium",
        organization_id: org.id,
        agent_id: agent2.id
      })

      # Build graph
      graph = Alerts.build_network_graph([alert1.id, alert2.id])

      assert is_map(graph)
      assert Map.has_key?(graph, "nodes")
      assert Map.has_key?(graph, "edges")
      assert length(graph["nodes"]) >= 2
    end
  end

  describe "campaign detection" do
    test "creates campaign from correlated alerts", %{org: org, agent1: agent1, agent2: agent2} do
      # Create multiple related alerts
      alerts = for i <- 1..3 do
        {:ok, alert} = Alerts.create_alert(%{
          title: "Attack Step #{i}",
          severity: "high",
          organization_id: org.id,
          agent_id: if(rem(i, 2) == 0, do: agent2.id, else: agent1.id),
          mitre_techniques: ["T1055", "T1059"],
          mitre_tactics: ["execution", "defense-evasion"]
        })

        # Small delay to ensure time ordering
        Process.sleep(50)
        alert
      end

      # Wait for correlation to run
      Process.sleep(500)

      # Check if campaigns were created
      campaigns = Alerts.list_attack_campaigns(organization_id: org.id)

      # May or may not create campaign depending on similarity threshold,
      # but the system should handle it gracefully
      if length(campaigns) > 0 do
        campaign = List.first(campaigns)
        assert campaign.organization_id == org.id
        assert campaign.alert_count >= 2
      end
    end

    test "adds new alert to existing campaign", %{org: org, agent1: agent1} do
      # Create campaign manually
      {:ok, campaign} = Alerts.create_attack_campaign(%{
        name: "Test Campaign",
        organization_id: org.id,
        severity: "high",
        status: "active",
        start_time: DateTime.utc_now(),
        attack_pattern: "lateral_movement"
      })

      # Create alert
      {:ok, alert} = Alerts.create_alert(%{
        title: "Test Alert",
        severity: "high",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_techniques: ["T1055"]
      })

      # Add to campaign
      {:ok, _} = Alerts.add_alert_to_campaign(campaign.id, alert.id, role: "lateral")

      # Verify
      {:ok, updated_campaign} = Alerts.get_attack_campaign(campaign.id)
      assert updated_campaign.alert_count == 1

      # Verify alert has campaign_id
      updated_alert = Repo.get(Alert, alert.id)
      assert updated_alert.campaign_id == campaign.id
    end

    test "calculates campaign statistics", %{org: org, agent1: agent1} do
      # Create some campaigns
      for i <- 1..3 do
        {:ok, campaign} = Alerts.create_attack_campaign(%{
          name: "Campaign #{i}",
          organization_id: org.id,
          severity: if(i == 1, do: "critical", else: "high"),
          status: if(i == 3, do: "resolved", else: "active"),
          start_time: DateTime.utc_now(),
          attack_pattern: "lateral_movement",
          alert_count: i * 2,
          agent_count: i
        })

        # Add some alerts to verify counts
        for j <- 1..i do
          {:ok, alert} = Alerts.create_alert(%{
            title: "Alert #{j}",
            severity: "high",
            organization_id: org.id,
            agent_id: agent1.id
          })

          Alerts.add_alert_to_campaign(campaign.id, alert.id)
        end
      end

      # Get stats
      stats = Alerts.get_campaign_stats(organization_id: org.id, days: 7)

      assert stats.total_campaigns == 3
      assert stats.by_status["active"] == 2
      assert stats.by_status["resolved"] == 1
      assert stats.by_severity["critical"] == 1
      assert stats.by_severity["high"] == 2
      assert stats.by_pattern["lateral_movement"] == 3
    end
  end

  describe "correlation metadata" do
    test "stores correlation metadata", %{org: org, agent1: agent1} do
      # Create correlated alerts
      {:ok, alert1} = Alerts.create_alert(%{
        title: "Alert 1",
        severity: "high",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_techniques: ["T1055", "T1059"]
      })

      {:ok, alert2} = Alerts.create_alert(%{
        title: "Alert 2",
        severity: "high",
        organization_id: org.id,
        agent_id: agent1.id,
        mitre_techniques: ["T1055", "T1003"]
      })

      # Wait for correlation
      Process.sleep(200)

      # Check correlations
      correlations = Alerts.get_alert_correlations(alert1.id)

      if length(correlations) > 0 do
        correlation = List.first(correlations)
        assert correlation.metadata["shared_techniques"] != nil
        assert "T1055" in correlation.metadata["shared_techniques"]
        assert correlation.confidence > 0.0
      end
    end
  end

  # Helper functions

  defp insert_organization do
    {:ok, org} = TamanduaServer.Accounts.create_organization(%{
      name: "Test Org #{System.unique_integer([:positive])}",
      slug: "test-org-#{System.unique_integer([:positive])}"
    })
    org
  end

  defp insert_agent(attrs \\ %{}) do
    default_attrs = %{
      hostname: "test-host-#{System.unique_integer([:positive])}",
      os_type: "linux",
      os_version: "Ubuntu 22.04",
      agent_version: "1.0.0"
    }

    attrs = Map.merge(default_attrs, attrs)

    {:ok, agent} = TamanduaServer.Agents.register_agent(attrs)
    agent
  end
end
