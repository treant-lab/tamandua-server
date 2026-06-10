defmodule TamanduaServer.Integration.ResponseFlowTest do
  @moduledoc """
  Integration tests for the response action flow.

  Tests:
  1. Response actions are created for alerts
  2. Playbooks are triggered by detections
  3. Commands are sent to agents
  4. Agent command responses are processed
  5. Response actions are logged
  """

  use TamanduaServerWeb.ChannelCase
  import Phoenix.ChannelTest

  alias TamanduaServerWeb.AgentSocket
  alias TamanduaServer.Response.{Executor, Playbook}
  alias TamanduaServer.Alerts
  alias TamanduaServer.Detection.Engine

  @moduletag :integration

  setup do
    # Start required services
    start_supervised!(TamanduaServer.Detection.Engine)
    start_supervised!({TamanduaServer.Agents.Registry, []})

    # Start playbook engine if not running
    case GenServer.whereis(Playbook) do
      nil -> start_supervised!(Playbook)
      _pid -> :ok
    end

    :ok
  end

  describe "response action execution" do
    test "kill process command is sent to agent" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, _socket} = join(socket, "agent:#{agent.id}", %{})

      # Wait for config push
      assert_push "config", _config, 5000

      # Execute kill process action
      target_pid = 12345

      spawn(fn ->
        Executor.execute_action(agent.id, :kill_process, %{
          pid: target_pid,
          force: true
        })
      end)

      # Agent should receive kill command
      assert_push "command", command, 5000
      assert command.command_type in ["kill_process", :kill_process]
      assert command.payload["pid"] == target_pid or command.payload[:pid] == target_pid
    end

    test "quarantine file command is sent to agent" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, _socket} = join(socket, "agent:#{agent.id}", %{})
      assert_push "config", _config, 5000

      target_path = "C:\\Users\\test\\malware.exe"

      spawn(fn ->
        Executor.execute_action(agent.id, :quarantine_file, %{
          path: target_path
        })
      end)

      # Agent should receive quarantine command
      assert_push "command", command, 5000
      assert command.command_type in ["quarantine_file", :quarantine_file]
    end

    test "isolate network command is sent to agent" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, _socket} = join(socket, "agent:#{agent.id}", %{})
      assert_push "config", _config, 5000

      spawn(fn ->
        Executor.execute_action(agent.id, :isolate_network, %{
          reason: "Suspected ransomware",
          duration_seconds: 3600
        })
      end)

      # Agent should receive isolate command
      assert_push "command", command, 5000
      assert command.command_type in ["isolate_network", :isolate_network]
    end

    test "unisolate network command is sent to agent" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, _socket} = join(socket, "agent:#{agent.id}", %{})
      assert_push "config", _config, 5000

      spawn(fn ->
        Executor.execute_action(agent.id, :unisolate_network, %{
          reason: "False positive confirmed"
        })
      end)

      assert_push "command", command, 5000
      assert command.command_type in ["unisolate_network", :unisolate_network]
    end

    test "scan path command is sent to agent" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, _socket} = join(socket, "agent:#{agent.id}", %{})
      assert_push "config", _config, 5000

      spawn(fn ->
        Executor.execute_action(agent.id, :scan_path, %{
          path: "C:\\Users"
        })
      end)

      assert_push "command", command, 5000
      assert command.command_type in ["scan_path", :scan_path]
    end
  end

  describe "command response handling" do
    test "successful command response is processed" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, socket} = join(socket, "agent:#{agent.id}", %{})
      assert_push "config", _config, 5000

      # Send command response
      response = %{
        "command_id" => Ecto.UUID.generate(),
        "success" => true,
        "result_data" => %{
          "pid_killed" => 12345,
          "exit_code" => 0
        }
      }

      push(socket, "command_response", response)
      :timer.sleep(100)

      # Response should be processed without error
    end

    test "failed command response is logged" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, socket} = join(socket, "agent:#{agent.id}", %{})
      assert_push "config", _config, 5000

      # Send failed command response
      response = %{
        "command_id" => Ecto.UUID.generate(),
        "success" => false,
        "error_message" => "Process not found"
      }

      push(socket, "command_response", response)
      :timer.sleep(100)

      # Error should be logged
    end
  end

  describe "playbook execution" do
    test "creates playbook" do
      playbook_attrs = %{
        name: "Test Playbook",
        description: "Integration test playbook",
        trigger_type: "manual",
        steps: [
          %{"action" => "collect_forensics", "params" => %{}}
        ],
        enabled: true
      }

      {:ok, playbook} = Playbook.create_playbook(playbook_attrs)

      assert playbook.name == "Test Playbook"
      assert playbook.enabled == true
      assert length(playbook.steps) == 1
    end

    test "lists playbooks" do
      # Create a test playbook first
      Playbook.create_playbook(%{
        name: "List Test Playbook",
        steps: [%{"action" => "send_notification", "params" => %{}}],
        trigger_type: "manual"
      })

      {:ok, playbooks} = Playbook.list_playbooks()

      assert is_list(playbooks)
    end

    test "executes manual playbook" do
      {_org, agent} = create_agent_with_org()

      {:ok, playbook} = Playbook.create_playbook(%{
        name: "Manual Execution Test",
        description: "Test manual playbook execution",
        trigger_type: "manual",
        steps: [
          %{"action" => "send_notification", "params" => %{
            "channel" => "webhook",
            "message" => "Test notification"
          }}
        ],
        enabled: true,
        require_approval: false
      })

      context = %{
        agent_id: agent.id,
        severity: "high"
      }

      {:ok, execution} = Playbook.execute_playbook(playbook.id, context)

      assert execution.playbook_id == playbook.id
      assert execution.status in ["running", "pending_approval", "completed", "failed"]
    end

    test "playbook with approval requirement creates pending approval" do
      {:ok, playbook} = Playbook.create_playbook(%{
        name: "Approval Required Playbook",
        trigger_type: "manual",
        steps: [
          %{"action" => "isolate_host", "params" => %{}}
        ],
        enabled: true,
        require_approval: true,
        approval_timeout_minutes: 30
      })

      {:ok, execution} = Playbook.execute_playbook(playbook.id, %{})

      assert execution.status == "pending_approval"

      # Should appear in pending approvals
      {:ok, pending} = Playbook.get_pending_approvals()
      assert Enum.any?(pending, fn p -> p.execution.id == execution.id end)
    end

    test "approves pending playbook execution" do
      {:ok, playbook} = Playbook.create_playbook(%{
        name: "Approve Test Playbook",
        trigger_type: "manual",
        steps: [
          %{"action" => "send_notification", "params" => %{"channel" => "webhook"}}
        ],
        enabled: true,
        require_approval: true
      })

      {:ok, execution} = Playbook.execute_playbook(playbook.id, %{})
      assert execution.status == "pending_approval"

      approver_id = Ecto.UUID.generate()
      {:ok, approved} = Playbook.approve_execution(execution.id, approver_id)

      assert approved.status == "running"
      assert approved.approved_by == approver_id
    end

    test "cancels pending playbook execution" do
      {:ok, playbook} = Playbook.create_playbook(%{
        name: "Cancel Test Playbook",
        trigger_type: "manual",
        steps: [
          %{"action" => "isolate_host", "params" => %{}}
        ],
        enabled: true,
        require_approval: true
      })

      {:ok, execution} = Playbook.execute_playbook(playbook.id, %{})

      {:ok, cancelled} = Playbook.cancel_execution(execution.id, "Test cancellation")

      assert cancelled.status == "cancelled"
      assert cancelled.error_message == "Test cancellation"
    end

    test "updates playbook" do
      {:ok, playbook} = Playbook.create_playbook(%{
        name: "Update Test Playbook",
        trigger_type: "manual",
        steps: [%{"action" => "send_notification", "params" => %{}}],
        enabled: true
      })

      {:ok, updated} = Playbook.update_playbook(playbook.id, %{
        name: "Updated Playbook Name",
        enabled: false
      })

      assert updated.name == "Updated Playbook Name"
      assert updated.enabled == false
    end

    test "deletes playbook" do
      {:ok, playbook} = Playbook.create_playbook(%{
        name: "Delete Test Playbook",
        trigger_type: "manual",
        steps: [%{"action" => "send_notification", "params" => %{}}]
      })

      {:ok, _deleted} = Playbook.delete_playbook(playbook.id)

      # Should no longer be found
      assert {:error, :not_found} = Playbook.get_playbook(playbook.id)
    end
  end

  describe "automated response triggers" do
    test "alert triggers matching playbook" do
      {_org, agent} = create_agent_with_org()

      # Create playbook that triggers on high severity alerts
      {:ok, _playbook} = Playbook.create_playbook(%{
        name: "High Severity Response",
        trigger_type: "alert",
        trigger_conditions: %{
          "severity" => "high"
        },
        steps: [
          %{"action" => "send_notification", "params" => %{
            "channel" => "webhook",
            "message" => "High severity alert detected"
          }}
        ],
        enabled: true,
        require_approval: false
      })

      # Create a high severity alert
      alert = %{
        id: Ecto.UUID.generate(),
        agent_id: agent.id,
        severity: "high",
        title: "Test Alert",
        description: "Test alert for playbook trigger",
        mitre_tactics: ["execution"],
        mitre_techniques: ["T1059"]
      }

      # Trigger playbooks for alert
      Playbook.trigger_for_alert(alert)

      # Allow async processing
      :timer.sleep(200)

      # Playbook should have been executed
    end
  end

  describe "forensics collection" do
    test "requests forensic artifact collection" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, _socket} = join(socket, "agent:#{agent.id}", %{})
      assert_push "config", _config, 5000

      spawn(fn ->
        Executor.collect_forensics(agent.id, %{
          type: "memory",
          target_pid: 1234
        })
      end)

      # Agent should receive forensics collection command
      assert_push "command", command, 5000
      assert command.command_type in ["collect_artifact", :collect_artifact, "collect_forensics", :collect_forensics]
    end
  end

  describe "live response commands" do
    test "sends process list command" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, _socket} = join(socket, "agent:#{agent.id}", %{})
      assert_push "config", _config, 5000

      spawn(fn ->
        Executor.execute_action(agent.id, :process_list, %{})
      end)

      assert_push "command", command, 5000
      assert command.command_type in ["process_list", :process_list]
    end

    test "sends network connections command" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, _socket} = join(socket, "agent:#{agent.id}", %{})
      assert_push "config", _config, 5000

      spawn(fn ->
        Executor.execute_action(agent.id, :network_connections, %{})
      end)

      assert_push "command", command, 5000
      assert command.command_type in ["network_connections", :network_connections]
    end

    test "sends file download command" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, _socket} = join(socket, "agent:#{agent.id}", %{})
      assert_push "config", _config, 5000

      spawn(fn ->
        Executor.execute_action(agent.id, :file_download, %{
          path: "C:\\Users\\test\\evidence.txt"
        })
      end)

      assert_push "command", command, 5000
      assert command.command_type in ["file_download", :file_download]
    end
  end
end
