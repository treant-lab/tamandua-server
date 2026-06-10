defmodule TamanduaServer.Agents.CommandManagerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Agents.{CommandManager, AgentCommand}
  alias TamanduaServer.Repo

  describe "queue_command/4" do
    test "creates a pending command for an online agent" do
      # Setup: Register a mock agent
      agent_id = "test-agent-#{:rand.uniform(10000)}"
      TamanduaServer.Agents.Registry.register(agent_id, %{
        hostname: "test-host",
        os_type: "linux",
        worker_pid: self()
      })

      # Queue a command
      {:ok, command} =
        CommandManager.queue_command(agent_id, :kill_process, %{pid: 1234}, priority: 5)

      assert command.agent_id == agent_id
      assert command.command_type == "kill_process"
      assert command.command_params == %{pid: 1234}
      assert command.status == "pending"
      assert command.priority == 5
      assert command.expires_at != nil

      # Verify command is in database
      assert Repo.get(AgentCommand, command.id) != nil
    end

    test "accepts canonical network response action commands and payload keys" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"

      TamanduaServer.Agents.Registry.register(agent_id, %{
        hostname: "test-host",
        os_type: "linux",
        worker_pid: self()
      })

      cases = [
        {:block_ip, %{ip: "203.0.113.10", direction: "both", reason: "network_insight"}},
        {:unblock_ip, %{ip: "203.0.113.10"}},
        {:block_domain, %{domain: "example.test", reason: "network_insight"}},
        {:unblock_domain, %{domain: "example.test"}},
        {:isolate_network, %{allowed_ips: ["10.0.0.5"], server_ip: "10.0.0.1"}},
        {:unisolate_network, %{reason: "restore"}}
      ]

      for {command_type, params} <- cases do
        assert {:ok, command} = CommandManager.queue_command(agent_id, command_type, params)
        assert command.command_type == to_string(command_type)
        assert command.command_params == params
      end
    end

    test "returns error for nonexistent agent" do
      result = CommandManager.queue_command("nonexistent-agent", :kill_process, %{})
      assert result == {:error, :agent_not_found}
    end

    test "sets default priority and timeout" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"
      TamanduaServer.Agents.Registry.register(agent_id, %{
        hostname: "test-host",
        os_type: "windows",
        worker_pid: self()
      })

      {:ok, command} = CommandManager.queue_command(agent_id, :quarantine_file, %{path: "C:\\bad.exe"})

      assert command.priority == 0
      assert command.expires_at != nil

      # Should expire in approximately 1 hour (3600 seconds)
      diff = DateTime.diff(command.expires_at, DateTime.utc_now(), :second)
      assert diff >= 3590 and diff <= 3610
    end
  end

  describe "get_command/1" do
    test "retrieves a command by ID" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"
      TamanduaServer.Agents.Registry.register(agent_id, %{worker_pid: self()})

      {:ok, created} = CommandManager.queue_command(agent_id, :isolate_network, %{})

      {:ok, retrieved} = CommandManager.get_command(created.id)
      assert retrieved.id == created.id
      assert retrieved.command_type == "isolate_network"
    end

    test "returns error for nonexistent command" do
      result = CommandManager.get_command(Ecto.UUID.generate())
      assert result == {:error, :not_found}
    end
  end

  describe "pending_commands/1" do
    test "returns pending commands ordered by priority and age" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"
      TamanduaServer.Agents.Registry.register(agent_id, %{worker_pid: self()})

      # Create commands with different priorities
      {:ok, cmd1} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 1}, priority: 0)
      {:ok, cmd2} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 2}, priority: 10)
      {:ok, cmd3} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 3}, priority: 5)

      # Mark one as sent
      Repo.update!(AgentCommand.mark_sent(cmd1))

      pending = CommandManager.pending_commands(agent_id)

      # Should only return pending commands, ordered by priority (desc)
      assert length(pending) == 2
      assert hd(pending).id == cmd2.id  # Priority 10 first
      assert List.last(pending).id == cmd3.id  # Priority 5 second
    end
  end

  describe "cancel_command/1" do
    test "cancels a pending command" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"
      TamanduaServer.Agents.Registry.register(agent_id, %{worker_pid: self()})

      {:ok, command} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 9999})

      assert :ok = CommandManager.cancel_command(command.id)

      # Verify command is marked as failed
      {:ok, updated} = CommandManager.get_command(command.id)
      assert updated.status == "failed"
      assert updated.error == "Cancelled by user"
    end

    test "returns error when cancelling already-sent command" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"
      TamanduaServer.Agents.Registry.register(agent_id, %{worker_pid: self()})

      {:ok, command} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 9999})

      # Mark as sent
      Repo.update!(AgentCommand.mark_sent(command))

      result = CommandManager.cancel_command(command.id)
      assert result == {:error, :already_sent}
    end
  end

  describe "command_stats/1" do
    test "returns statistics for an agent's commands" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"
      TamanduaServer.Agents.Registry.register(agent_id, %{worker_pid: self()})

      # Create various commands
      {:ok, cmd1} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 1})
      {:ok, cmd2} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 2})
      {:ok, cmd3} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 3})

      # Mark one as sent, one as completed
      Repo.update!(AgentCommand.mark_sent(cmd1))
      Repo.update!(AgentCommand.mark_completed(cmd2))

      stats = CommandManager.command_stats(agent_id)

      assert stats.total == 3
      assert stats.by_status["pending"] == 1
      assert stats.by_status["sent"] == 1
      assert stats.by_status["completed"] == 1
    end
  end

  describe "retry_command/1" do
    test "creates a new command with same parameters" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"
      TamanduaServer.Agents.Registry.register(agent_id, %{worker_pid: self()})

      {:ok, original} =
        CommandManager.queue_command(agent_id, :quarantine_file, %{path: "/tmp/malware"}, priority: 8)

      # Mark as failed
      Repo.update!(AgentCommand.mark_failed(original, "Timeout"))

      # Retry
      {:ok, retried} = CommandManager.retry_command(original.id)

      assert retried.id != original.id
      assert retried.agent_id == original.agent_id
      assert retried.command_type == original.command_type
      assert retried.command_params == original.command_params
      assert retried.priority == original.priority
      assert retried.status == "pending"
    end
  end
end
