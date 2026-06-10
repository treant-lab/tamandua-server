defmodule TamanduaServer.Detection.AttackChainDetectorTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Detection.{AttackChain, AttackChainDetector, ChainLibrary}
  alias TamanduaServer.{Repo, Alerts}

  setup do
    # Start the detector
    start_supervised!(AttackChainDetector)

    # Create test organization
    org = insert(:organization)

    # Create test agent
    agent = insert(:agent, organization: org)

    # Create simple test chain
    {:ok, chain} =
      %AttackChain{}
      |> AttackChain.changeset(%{
        name: "Test Chain",
        description: "Test attack chain",
        severity: "high",
        organization_id: org.id,
        enabled: true,
        definition: %{
          "steps" => [
            %{
              "name" => "Step 1",
              "techniques" => ["T1110"],
              "threshold" => 2,
              "timeframe" => 300
            },
            %{
              "name" => "Step 2",
              "techniques" => ["T1078"],
              "threshold" => 1,
              "timeframe" => 600,
              "conditions" => %{"same_user" => true}
            }
          ],
          "narrative_template" => "Test chain completed for user {user}"
        }
      })
      |> Repo.insert()

    # Reload chains
    AttackChainDetector.reload_chains()

    {:ok, %{org: org, agent: agent, chain: chain}}
  end

  describe "process_event/1" do
    test "advances chain on matching technique", %{agent: agent, chain: _chain} do
      event1 = build_event(agent.id, ["T1110"], "testuser", "192.168.1.100")
      event2 = build_event(agent.id, ["T1110"], "testuser", "192.168.1.100")

      {:ok, completed1} = AttackChainDetector.process_event(event1)
      assert completed1 == []

      {:ok, completed2} = AttackChainDetector.process_event(event2)
      assert completed2 == []

      # Check active chains
      active = AttackChainDetector.get_active_chains(agent.id)
      assert length(active) == 1
      assert hd(active).current_step == 1
    end

    test "completes chain when all steps match", %{agent: agent, chain: _chain} do
      # Step 1: Two T1110 events (threshold: 2)
      event1 = build_event(agent.id, ["T1110"], "testuser", "192.168.1.100")
      event2 = build_event(agent.id, ["T1110"], "testuser", "192.168.1.100")

      {:ok, []} = AttackChainDetector.process_event(event1)
      {:ok, []} = AttackChainDetector.process_event(event2)

      # Step 2: One T1078 event (threshold: 1)
      event3 = build_event(agent.id, ["T1078"], "testuser", "192.168.1.100")
      {:ok, completed} = AttackChainDetector.process_event(event3)

      assert length(completed) == 1
      alert = hd(completed)
      assert alert.title =~ "Test Chain"
      assert alert.severity == "high"
    end

    test "does not advance chain if condition fails", %{agent: agent, chain: _chain} do
      # Step 1: Two T1110 events
      event1 = build_event(agent.id, ["T1110"], "user1", "192.168.1.100")
      event2 = build_event(agent.id, ["T1110"], "user1", "192.168.1.100")

      {:ok, []} = AttackChainDetector.process_event(event1)
      {:ok, []} = AttackChainDetector.process_event(event2)

      # Step 2: T1078 with different user (should fail same_user condition)
      event3 = build_event(agent.id, ["T1078"], "user2", "192.168.1.100")
      {:ok, completed} = AttackChainDetector.process_event(event3)

      assert completed == []

      # Chain should still be at step 1
      active = AttackChainDetector.get_active_chains(agent.id)
      assert length(active) == 1
      assert hd(active).current_step == 1
    end

    test "ignores events without techniques", %{agent: agent} do
      event = %{agent_id: agent.id, event_id: Ecto.UUID.generate()}
      {:ok, completed} = AttackChainDetector.process_event(event)
      assert completed == []
    end

    test "ignores events without agent_id" do
      event = %{mitre_techniques: ["T1110"], event_id: Ecto.UUID.generate()}
      {:ok, completed} = AttackChainDetector.process_event(event)
      assert completed == []
    end
  end

  describe "condition checking" do
    test "same_source_ip condition", %{agent: agent, org: org} do
      {:ok, chain} =
        %AttackChain{}
        |> AttackChain.changeset(%{
          name: "IP Condition Test",
          organization_id: org.id,
          definition: %{
            "steps" => [
              %{"name" => "S1", "techniques" => ["T1110"], "threshold" => 1, "timeframe" => 300},
              %{
                "name" => "S2",
                "techniques" => ["T1078"],
                "threshold" => 1,
                "timeframe" => 600,
                "conditions" => %{"same_source_ip" => true}
              }
            ]
          }
        })
        |> Repo.insert()

      AttackChainDetector.reload_chains()

      # Step 1 from IP 1
      {:ok, []} = AttackChainDetector.process_event(build_event(agent.id, ["T1110"], "user", "1.1.1.1"))

      # Step 2 from different IP should fail
      {:ok, []} = AttackChainDetector.process_event(build_event(agent.id, ["T1078"], "user", "2.2.2.2"))

      active = AttackChainDetector.get_active_chains(agent.id)
      matching_chain = Enum.find(active, &(&1.chain_id == chain.id))
      assert matching_chain.current_step == 1

      # Step 2 from same IP should succeed
      {:ok, completed} = AttackChainDetector.process_event(build_event(agent.id, ["T1078"], "user", "1.1.1.1"))
      assert length(completed) == 1
    end

    test "same_process condition", %{agent: agent, org: org} do
      {:ok, chain} =
        %AttackChain{}
        |> AttackChain.changeset(%{
          name: "Process Condition Test",
          organization_id: org.id,
          definition: %{
            "steps" => [
              %{"name" => "S1", "techniques" => ["T1105"], "threshold" => 1, "timeframe" => 300},
              %{
                "name" => "S2",
                "techniques" => ["T1059"],
                "threshold" => 1,
                "timeframe" => 600,
                "conditions" => %{"same_process" => true}
              }
            ]
          }
        })
        |> Repo.insert()

      AttackChainDetector.reload_chains()

      # Step 1 with PID 1234
      event1 = build_event(agent.id, ["T1105"], "user", "1.1.1.1") |> Map.put(:pid, 1234)
      {:ok, []} = AttackChainDetector.process_event(event1)

      # Step 2 with different PID should fail
      event2 = build_event(agent.id, ["T1059"], "user", "1.1.1.1") |> Map.put(:pid, 5678)
      {:ok, []} = AttackChainDetector.process_event(event2)

      # Step 2 with same PID should succeed
      event3 = build_event(agent.id, ["T1059"], "user", "1.1.1.1") |> Map.put(:pid, 1234)
      {:ok, completed} = AttackChainDetector.process_event(event3)
      assert length(completed) == 1
    end
  end

  describe "get_stats/1" do
    test "returns detector statistics" do
      stats = AttackChainDetector.get_stats()

      assert is_integer(stats.events_processed)
      assert is_integer(stats.chains_triggered)
      assert is_integer(stats.chains_loaded)
      assert is_integer(stats.active_chains)
    end
  end

  describe "get_active_chains/1" do
    test "returns active chains for agent", %{agent: agent} do
      event = build_event(agent.id, ["T1110"], "user", "1.1.1.1")
      {:ok, _} = AttackChainDetector.process_event(event)

      active = AttackChainDetector.get_active_chains(agent.id)
      assert length(active) > 0

      chain = hd(active)
      assert chain.current_step >= 0
      assert is_integer(chain.matched_events)
    end

    test "returns empty list for agent with no active chains", %{org: org} do
      other_agent = insert(:agent, organization: org)
      active = AttackChainDetector.get_active_chains(other_agent.id)
      assert active == []
    end
  end

  describe "reload_chains/0" do
    test "reloads chains from database", %{org: org} do
      initial_stats = AttackChainDetector.get_stats()

      # Add new chain
      %AttackChain{}
      |> AttackChain.changeset(%{
        name: "New Chain",
        organization_id: org.id,
        definition: %{
          "steps" => [
            %{"name" => "S1", "techniques" => ["T1234"], "threshold" => 1, "timeframe" => 300}
          ]
        }
      })
      |> Repo.insert!()

      # Reload
      :ok = AttackChainDetector.reload_chains()

      new_stats = AttackChainDetector.get_stats()
      assert new_stats.chains_loaded > initial_stats.chains_loaded
    end
  end

  describe "test mode" do
    test "does not create alerts in test mode", %{agent: agent, org: org} do
      {:ok, _chain} =
        %AttackChain{}
        |> AttackChain.changeset(%{
          name: "Test Mode Chain",
          organization_id: org.id,
          test_mode: true,
          definition: %{
            "steps" => [
              %{"name" => "S1", "techniques" => ["T1110"], "threshold" => 1, "timeframe" => 300}
            ]
          }
        })
        |> Repo.insert()

      AttackChainDetector.reload_chains()

      event = build_event(agent.id, ["T1110"], "user", "1.1.1.1")
      {:ok, completed} = AttackChainDetector.process_event(event)

      # Should return alert data but not persist
      assert length(completed) == 1
      alert_data = hd(completed)
      assert alert_data.detection_metadata.test_mode == true

      # Verify no alert in database
      alerts = Repo.all(Alerts.Alert)
      assert alerts == []
    end
  end

  describe "narrative generation" do
    test "generates narrative with context", %{agent: agent, org: org} do
      {:ok, chain} =
        %AttackChain{}
        |> AttackChain.changeset(%{
          name: "Narrative Test",
          organization_id: org.id,
          definition: %{
            "steps" => [
              %{"name" => "S1", "techniques" => ["T1110"], "threshold" => 1, "timeframe" => 300}
            ],
            "narrative_template" => "User {user} from {source_ip} triggered chain"
          }
        })
        |> Repo.insert()

      AttackChainDetector.reload_chains()

      event = build_event(agent.id, ["T1110"], "alice", "10.0.0.5")
      {:ok, completed} = AttackChainDetector.process_event(event)

      assert length(completed) == 1
      alert = hd(completed)
      assert alert.description =~ "alice"
      assert alert.description =~ "10.0.0.5"
    end
  end

  # Helper functions

  defp build_event(agent_id, techniques, user, source_ip) do
    %{
      agent_id: agent_id,
      event_id: Ecto.UUID.generate(),
      mitre_techniques: techniques,
      user: user,
      source_ip: source_ip,
      timestamp: DateTime.utc_now()
    }
  end
end
