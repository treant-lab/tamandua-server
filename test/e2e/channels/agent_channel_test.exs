defmodule TamanduaServerWeb.E2E.AgentChannelTest do
  use TamanduaServerWeb.ChannelCase
  alias TamanduaServer.Agents
  alias TamanduaServerWeb.AgentSocket
  alias TamanduaServerWeb.AgentChannel

  describe "agent WebSocket connection" do
    test "agent can connect with valid token" do
      agent = insert(:agent)
      token = Agents.generate_token(agent)

      {:ok, socket} = connect(AgentSocket, %{"token" => token})
      {:ok, _, socket} = subscribe_and_join(socket, AgentChannel, "agent:#{agent.id}")

      assert socket.assigns.agent_id == agent.id
      assert socket.assigns.authenticated == true
    end

    test "agent connection fails with invalid token" do
      agent = insert(:agent)

      assert {:error, %{reason: "unauthorized"}} =
        connect(AgentSocket, %{"token" => "invalid-token"})
    end

    test "agent connection fails with expired token" do
      agent = insert(:agent)

      # Generate expired token (issued in the past beyond expiration)
      expired_token = Agents.generate_token(agent, expires_in: -3600)

      assert {:error, %{reason: "unauthorized"}} =
        connect(AgentSocket, %{"token" => expired_token})
    end

    test "agent cannot join another agent's channel" do
      agent1 = insert(:agent)
      agent2 = insert(:agent)
      token = Agents.generate_token(agent1)

      {:ok, socket} = connect(AgentSocket, %{"token" => token})

      # Try to join agent2's channel
      assert {:error, %{reason: "forbidden"}} =
        subscribe_and_join(socket, AgentChannel, "agent:#{agent2.id}")
    end

    test "agent status updates to online on connect" do
      agent = insert(:agent, status: :offline)
      token = Agents.generate_token(agent)

      {:ok, socket} = connect(AgentSocket, %{"token" => token})
      {:ok, _, _socket} = subscribe_and_join(socket, AgentChannel, "agent:#{agent.id}")

      # Wait for async status update
      :timer.sleep(100)

      updated_agent = Agents.get_agent!(agent.id)
      assert updated_agent.status == :online
      assert updated_agent.last_seen != nil
    end

    test "agent status updates to offline on disconnect" do
      agent = insert(:agent, status: :online)
      {:ok, socket} = setup_agent_socket(agent)

      # Disconnect
      leave(socket)

      :timer.sleep(100)

      updated_agent = Agents.get_agent!(agent.id)
      assert updated_agent.status == :offline
    end

    test "agent connection broadcasts presence" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Subscribe to agent status updates
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agents:status")

      # Simulate heartbeat
      push(socket, "heartbeat", %{})

      assert_broadcast "presence_state", %{}
    end
  end

  describe "telemetry events" do
    test "agent can send telemetry events" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Send telemetry
      ref = push(socket, "telemetry", %{
        events: [
          %{
            type: "process_create",
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
            data: %{
              pid: 1234,
              name: "chrome.exe",
              path: "C:\\Program Files\\Chrome\\chrome.exe",
              command_line: "chrome.exe --new-window"
            }
          }
        ]
      })

      assert_reply ref, :ok, %{count: 1}
    end

    test "multiple telemetry events in batch" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      events = for i <- 1..100 do
        %{
          type: "process_create",
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
          data: %{
            pid: 1000 + i,
            name: "process-#{i}.exe"
          }
        }
      end

      ref = push(socket, "telemetry", %{events: events})

      assert_reply ref, :ok, %{count: 100}
    end

    test "telemetry event validation" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Send invalid event (missing required fields)
      ref = push(socket, "telemetry", %{
        events: [
          %{
            type: "process_create"
            # Missing timestamp and data
          }
        ]
      })

      assert_reply ref, :error, %{reason: "invalid_event"}
    end

    test "telemetry events are stored in database" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      push(socket, "telemetry", %{
        events: [
          %{
            type: "file_create",
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
            data: %{
              path: "C:\\Windows\\Temp\\malware.exe",
              size: 1024,
              hash: "abc123"
            }
          }
        ]
      })

      :timer.sleep(200)

      # Verify stored in DB
      events = TamanduaServer.Telemetry.list_events_for_agent(agent.id)
      assert length(events) == 1
      assert hd(events).event_type == "file_create"
    end

    test "telemetry triggers detection engine" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Subscribe to alert notifications
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:new")

      # Send suspicious event
      push(socket, "telemetry", %{
        events: [
          %{
            type: "process_create",
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
            data: %{
              pid: 1234,
              name: "powershell.exe",
              command_line: "powershell.exe -EncodedCommand ABCD123...",
              parent_name: "WINWORD.EXE"
            }
          }
        ]
      })

      # Should trigger detection
      assert_receive {:new_alert, _alert}, 1000
    end

    test "rate limiting on telemetry uploads" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Send many events rapidly
      for i <- 1..1000 do
        push(socket, "telemetry", %{
          events: [
            %{
              type: "network_connection",
              timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
              data: %{connection_id: i}
            }
          ]
        })
      end

      # Should eventually get rate limited
      ref = push(socket, "telemetry", %{
        events: [
          %{
            type: "test",
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
            data: %{}
          }
        ]
      })

      assert_reply ref, :error, %{reason: "rate_limited"}
    end
  end

  describe "command execution" do
    test "agent receives kill_process command" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Send command from server
      TamanduaServer.Response.execute_command(agent.id, :kill_process, %{pid: 1234})

      # Agent should receive command
      assert_push "command", %{
        type: "kill_process",
        payload: %{pid: 1234}
      }
    end

    test "agent receives quarantine_file command" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      TamanduaServer.Response.execute_command(agent.id, :quarantine_file, %{
        path: "C:\\Windows\\Temp\\malware.exe"
      })

      assert_push "command", %{
        type: "quarantine_file",
        payload: %{path: "C:\\Windows\\Temp\\malware.exe"}
      }
    end

    test "agent receives isolate_network command" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      TamanduaServer.Response.execute_command(agent.id, :isolate_network, %{})

      assert_push "command", %{type: "isolate_network"}
    end

    test "agent acknowledges command execution" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Create command
      command = insert(:command, agent: agent, type: "kill_process", status: "pending")

      # Agent acknowledges
      ref = push(socket, "command_ack", %{
        command_id: command.id,
        status: "success",
        output: "Process 1234 terminated"
      })

      assert_reply ref, :ok, %{}

      # Verify command status updated
      updated_command = TamanduaServer.Response.get_command!(command.id)
      assert updated_command.status == "success"
      assert updated_command.output == "Process 1234 terminated"
    end

    test "agent reports command failure" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      command = insert(:command, agent: agent, type: "kill_process")

      ref = push(socket, "command_ack", %{
        command_id: command.id,
        status: "failed",
        error: "Access denied"
      })

      assert_reply ref, :ok, %{}

      updated_command = TamanduaServer.Response.get_command!(command.id)
      assert updated_command.status == "failed"
      assert updated_command.error == "Access denied"
    end

    test "command timeout handling" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Create command with short timeout
      command = insert(:command,
        agent: agent,
        type: "shell_execute",
        timeout_seconds: 1
      )

      # Don't send acknowledgment
      # Wait for timeout
      :timer.sleep(1500)

      updated_command = TamanduaServer.Response.get_command!(command.id)
      assert updated_command.status == "timeout"
    end
  end

  describe "configuration updates" do
    test "agent receives config update" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Update agent config
      Agents.update_config(agent, %{
        poll_interval: 30,
        upload_batch_size: 500
      })

      # Agent should receive update
      assert_push "config_update", %{
        poll_interval: 30,
        upload_batch_size: 500
      }
    end

    test "agent receives YARA rule update" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Update YARA rules
      rule_content = """
      rule TestRule {
        strings:
          $s1 = "malware"
        condition:
          $s1
      }
      """

      TamanduaServer.Detection.update_yara_rules(rule_content)

      assert_push "yara_update", %{rules: ^rule_content}
    end

    test "agent receives Sigma rule update" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Update Sigma rules
      sigma_rules = [
        %{
          id: "rule-1",
          title: "Suspicious PowerShell",
          detection: %{
            selection: %{
              "process.name" => "powershell.exe"
            }
          }
        }
      ]

      TamanduaServer.Detection.update_sigma_rules(sigma_rules)

      assert_push "sigma_update", %{rules: rules}
      assert length(rules) == 1
    end

    test "agent acknowledges config update" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      ref = push(socket, "config_ack", %{
        version: "1.2.0",
        applied_at: DateTime.utc_now() |> DateTime.to_iso8601()
      })

      assert_reply ref, :ok, %{}
    end
  end

  describe "heartbeat" do
    test "agent sends heartbeat" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      ref = push(socket, "heartbeat", %{
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
        cpu: 45.5,
        memory: 60.2,
        disk: 75.0
      })

      assert_reply ref, :ok, %{}
    end

    test "heartbeat updates last_seen timestamp" do
      agent = insert(:agent, last_seen: ~U[2024-01-01 10:00:00Z])
      {:ok, socket} = setup_agent_socket(agent)

      push(socket, "heartbeat", %{
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
      })

      :timer.sleep(100)

      updated_agent = Agents.get_agent!(agent.id)
      assert DateTime.compare(updated_agent.last_seen, ~U[2024-01-01 10:00:00Z]) == :gt
    end

    test "heartbeat updates system metrics" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      push(socket, "heartbeat", %{
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
        cpu: 85.0,
        memory: 90.0,
        disk: 95.0
      })

      :timer.sleep(100)

      metrics = Agents.get_latest_metrics(agent.id)
      assert metrics.cpu == 85.0
      assert metrics.memory == 90.0
      assert metrics.disk == 95.0
    end

    test "missed heartbeat triggers alert" do
      agent = insert(:agent, last_seen: DateTime.add(DateTime.utc_now(), -600, :second))

      # Subscribe to alerts
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:new")

      # Trigger heartbeat check
      TamanduaServer.Agents.check_agent_health(agent)

      assert_receive {:new_alert, alert}, 1000
      assert alert.title =~ "Agent Offline"
      assert alert.agent_id == agent.id
    end
  end

  describe "file scanning" do
    test "server requests file scan" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Request scan
      TamanduaServer.Response.execute_command(agent.id, :scan_file, %{
        path: "C:\\Users\\test\\Downloads\\file.exe"
      })

      assert_push "command", %{
        type: "scan_file",
        payload: %{path: "C:\\Users\\test\\Downloads\\file.exe"}
      }
    end

    test "agent reports scan results" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      ref = push(socket, "scan_result", %{
        path: "C:\\Windows\\Temp\\suspicious.exe",
        hash: "abc123def456",
        malicious: true,
        detections: ["Trojan.Generic", "Backdoor.Win32"]
      })

      assert_reply ref, :ok, %{}

      # Should trigger alert
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:new")
      assert_receive {:new_alert, alert}, 1000
      assert alert.severity == :critical
    end
  end

  describe "connection resilience" do
    test "agent can reconnect after disconnect" do
      agent = insert(:agent)
      token = Agents.generate_token(agent)

      # First connection
      {:ok, socket1} = connect(AgentSocket, %{"token" => token})
      {:ok, _, socket1} = subscribe_and_join(socket1, AgentChannel, "agent:#{agent.id}")

      # Disconnect
      leave(socket1)

      # Reconnect
      {:ok, socket2} = connect(AgentSocket, %{"token" => token})
      {:ok, _, socket2} = subscribe_and_join(socket2, AgentChannel, "agent:#{agent.id}")

      assert socket2.assigns.agent_id == agent.id
    end

    test "buffered commands delivered after reconnect" do
      agent = insert(:agent)
      {:ok, socket} = setup_agent_socket(agent)

      # Disconnect
      leave(socket)

      # Queue commands while offline
      TamanduaServer.Response.execute_command(agent.id, :kill_process, %{pid: 1234})
      TamanduaServer.Response.execute_command(agent.id, :kill_process, %{pid: 5678})

      # Reconnect
      token = Agents.generate_token(agent)
      {:ok, new_socket} = connect(AgentSocket, %{"token" => token})
      {:ok, _, _new_socket} = subscribe_and_join(new_socket, AgentChannel, "agent:#{agent.id}")

      # Should receive buffered commands
      assert_push "command", %{payload: %{pid: 1234}}
      assert_push "command", %{payload: %{pid: 5678}}
    end
  end

  # Helper functions

  defp setup_agent_socket(agent) do
    token = Agents.generate_token(agent)
    {:ok, socket} = connect(AgentSocket, %{"token" => token})
    {:ok, _, socket} = subscribe_and_join(socket, AgentChannel, "agent:#{agent.id}")
    {:ok, socket}
  end
end
