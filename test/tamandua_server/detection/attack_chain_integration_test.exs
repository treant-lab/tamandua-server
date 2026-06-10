defmodule TamanduaServer.Detection.AttackChainIntegrationTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Detection.{AttackChainDetector, ChainLibrary}
  alias TamanduaServer.{Repo, Alerts}

  setup do
    # Start the detector
    start_supervised!(AttackChainDetector)

    # Create test organization and agent
    org = insert(:organization)
    agent = insert(:agent, organization: org)

    # Install built-in chains
    {:ok, _result} = ChainLibrary.install_builtin_chains(org.id)
    AttackChainDetector.reload_chains()

    {:ok, %{org: org, agent: agent}}
  end

  describe "credential stuffing chain" do
    test "detects full credential stuffing attack", %{agent: agent} do
      # Step 1: Multiple brute force attempts (T1110)
      event1 = build_brute_force_event(agent.id, "alice", "10.0.0.5")
      event2 = build_brute_force_event(agent.id, "alice", "10.0.0.5")
      event3 = build_brute_force_event(agent.id, "alice", "10.0.0.5")

      {:ok, []} = AttackChainDetector.process_event(event1)
      {:ok, []} = AttackChainDetector.process_event(event2)
      {:ok, []} = AttackChainDetector.process_event(event3)

      # Verify chain is progressing
      active = AttackChainDetector.get_active_chains(agent.id)
      assert length(active) > 0

      chain = Enum.find(active, &(&1.chain_name =~ "Credential Stuffing"))
      assert chain
      assert chain.current_step == 1

      # Step 2: Successful login (T1078)
      event4 = build_valid_account_event(agent.id, "alice", "10.0.0.5")
      {:ok, completed} = AttackChainDetector.process_event(event4)

      # Should complete the chain
      assert length(completed) == 1
      alert = hd(completed)

      assert alert.title =~ "Credential Stuffing"
      assert alert.severity == "critical"
      assert "T1110" in alert.mitre_techniques
      assert "T1078" in alert.mitre_techniques
      assert alert.description =~ "alice"
      assert alert.description =~ "10.0.0.5"

      # Verify alert was created in database
      db_alert = Repo.get(Alerts.Alert, alert.id)
      assert db_alert
      assert db_alert.detection_metadata["chain_name"] == "Credential Stuffing to Account Takeover"
    end
  end

  describe "ransomware kill chain" do
    test "detects full ransomware deployment", %{agent: agent} do
      # Step 1: Discovery (T1083, T1082)
      event1 = build_discovery_event(agent.id, "T1083")
      event2 = build_discovery_event(agent.id, "T1082")

      {:ok, []} = AttackChainDetector.process_event(event1)
      {:ok, []} = AttackChainDetector.process_event(event2)

      # Step 2: Defense inhibition (T1562, T1490)
      event3 = build_defense_evasion_event(agent.id, "T1490")
      {:ok, []} = AttackChainDetector.process_event(event3)

      # Step 3: Encryption (T1486)
      event4 = build_ransomware_event(agent.id)
      {:ok, completed} = AttackChainDetector.process_event(event4)

      # Should complete the chain
      assert length(completed) == 1
      alert = hd(completed)

      assert alert.title =~ "Ransomware"
      assert alert.severity == "critical"
      assert "T1486" in alert.mitre_techniques
      assert alert.description =~ "RANSOMWARE"
    end
  end

  describe "lateral movement chain" do
    test "detects reconnaissance to lateral movement", %{agent: agent} do
      user = "admin"

      # Step 1: Network discovery (T1046, T1018)
      event1 = build_network_discovery_event(agent.id, "T1046", user)
      event2 = build_network_discovery_event(agent.id, "T1018", user)

      {:ok, []} = AttackChainDetector.process_event(event1)
      {:ok, []} = AttackChainDetector.process_event(event2)

      # Step 2: Account discovery (T1087)
      event3 = build_account_discovery_event(agent.id, user)
      {:ok, []} = AttackChainDetector.process_event(event3)

      # Step 3: Lateral movement (T1021)
      event4 = build_lateral_movement_event(agent.id, user)
      {:ok, completed} = AttackChainDetector.process_event(event4)

      # Should complete the chain
      assert length(completed) == 1
      alert = hd(completed)

      assert alert.title =~ "Lateral Movement"
      assert alert.severity == "high"
      assert alert.description =~ user
    end
  end

  describe "chain conditions" do
    test "same_user condition prevents chain completion", %{agent: agent} do
      # Step 1 with user1
      event1 = build_brute_force_event(agent.id, "user1", "10.0.0.5")
      event2 = build_brute_force_event(agent.id, "user1", "10.0.0.5")
      event3 = build_brute_force_event(agent.id, "user1", "10.0.0.5")

      {:ok, []} = AttackChainDetector.process_event(event1)
      {:ok, []} = AttackChainDetector.process_event(event2)
      {:ok, []} = AttackChainDetector.process_event(event3)

      # Step 2 with different user should fail
      event4 = build_valid_account_event(agent.id, "user2", "10.0.0.5")
      {:ok, completed} = AttackChainDetector.process_event(event4)

      assert completed == []
    end

    test "same_agent condition ensures events on same endpoint", %{org: org} do
      agent1 = insert(:agent, organization: org)
      agent2 = insert(:agent, organization: org)

      # Step 1 on agent1
      event1 = build_discovery_event(agent1.id, "T1083")
      event2 = build_discovery_event(agent1.id, "T1082")

      {:ok, []} = AttackChainDetector.process_event(event1)
      {:ok, []} = AttackChainDetector.process_event(event2)

      # Step 2 on different agent should not advance the chain for agent1
      event3 = build_defense_evasion_event(agent2.id, "T1490")
      {:ok, []} = AttackChainDetector.process_event(event3)

      # Verify agent1 chain is still at step 1
      active = AttackChainDetector.get_active_chains(agent1.id)
      ransomware_chain = Enum.find(active, &(&1.chain_name =~ "Ransomware"))

      if ransomware_chain do
        assert ransomware_chain.current_step == 1
      end
    end
  end

  describe "partial chain tracking" do
    test "tracks partial chains that don't complete", %{agent: agent} do
      # Start a chain but don't complete it
      event1 = build_brute_force_event(agent.id, "alice", "10.0.0.5")
      event2 = build_brute_force_event(agent.id, "alice", "10.0.0.5")
      event3 = build_brute_force_event(agent.id, "alice", "10.0.0.5")

      {:ok, []} = AttackChainDetector.process_event(event1)
      {:ok, []} = AttackChainDetector.process_event(event2)
      {:ok, []} = AttackChainDetector.process_event(event3)

      # Verify active chain exists
      active = AttackChainDetector.get_active_chains(agent.id)
      assert length(active) > 0

      chain = Enum.find(active, &(&1.chain_name =~ "Credential Stuffing"))
      assert chain
      assert chain.current_step == 1
      assert chain.matched_events == 3
    end
  end

  describe "detector statistics" do
    test "tracks statistics across chain detections", %{agent: agent} do
      initial_stats = AttackChainDetector.get_stats()

      # Trigger a chain
      Enum.each(1..3, fn _ ->
        event = build_brute_force_event(agent.id, "alice", "10.0.0.5")
        AttackChainDetector.process_event(event)
      end)

      event = build_valid_account_event(agent.id, "alice", "10.0.0.5")
      {:ok, _completed} = AttackChainDetector.process_event(event)

      new_stats = AttackChainDetector.get_stats()

      assert new_stats.events_processed > initial_stats.events_processed
      assert new_stats.chains_triggered > initial_stats.chains_triggered
    end
  end

  # Helper functions to build test events

  defp build_brute_force_event(agent_id, user, source_ip) do
    %{
      agent_id: agent_id,
      event_id: Ecto.UUID.generate(),
      mitre_techniques: ["T1110"],
      user: user,
      source_ip: source_ip,
      timestamp: DateTime.utc_now(),
      event_type: "authentication_failure"
    }
  end

  defp build_valid_account_event(agent_id, user, source_ip) do
    %{
      agent_id: agent_id,
      event_id: Ecto.UUID.generate(),
      mitre_techniques: ["T1078"],
      user: user,
      source_ip: source_ip,
      timestamp: DateTime.utc_now(),
      event_type: "authentication_success"
    }
  end

  defp build_discovery_event(agent_id, technique) do
    %{
      agent_id: agent_id,
      event_id: Ecto.UUID.generate(),
      mitre_techniques: [technique],
      user: "SYSTEM",
      timestamp: DateTime.utc_now(),
      event_type: "discovery"
    }
  end

  defp build_defense_evasion_event(agent_id, technique) do
    %{
      agent_id: agent_id,
      event_id: Ecto.UUID.generate(),
      mitre_techniques: [technique],
      user: "SYSTEM",
      timestamp: DateTime.utc_now(),
      event_type: "defense_evasion",
      process_name: "vssadmin.exe"
    }
  end

  defp build_ransomware_event(agent_id) do
    %{
      agent_id: agent_id,
      event_id: Ecto.UUID.generate(),
      mitre_techniques: ["T1486"],
      user: "SYSTEM",
      timestamp: DateTime.utc_now(),
      event_type: "file_encryption",
      process_name: "ransomware.exe"
    }
  end

  defp build_network_discovery_event(agent_id, technique, user) do
    %{
      agent_id: agent_id,
      event_id: Ecto.UUID.generate(),
      mitre_techniques: [technique],
      user: user,
      timestamp: DateTime.utc_now(),
      event_type: "network_discovery"
    }
  end

  defp build_account_discovery_event(agent_id, user) do
    %{
      agent_id: agent_id,
      event_id: Ecto.UUID.generate(),
      mitre_techniques: ["T1087"],
      user: user,
      timestamp: DateTime.utc_now(),
      event_type: "account_discovery"
    }
  end

  defp build_lateral_movement_event(agent_id, user) do
    %{
      agent_id: agent_id,
      event_id: Ecto.UUID.generate(),
      mitre_techniques: ["T1021"],
      user: user,
      timestamp: DateTime.utc_now(),
      event_type: "remote_service",
      dest_ip: "10.0.0.10"
    }
  end
end
