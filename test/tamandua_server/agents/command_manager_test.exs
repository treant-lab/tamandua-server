defmodule TamanduaServer.Agents.CommandManagerTest do
  use TamanduaServer.DataCase, async: true

  @organization_id "11111111-1111-4111-8111-111111111111"

  alias TamanduaServer.Agents.{CommandManager, AgentCommand}
  alias TamanduaServer.Repo

  describe "queue_command/4" do
    test "creates a pending command for an online agent" do
      # Setup: Register a mock agent
      agent_id = "test-agent-#{:rand.uniform(10000)}"

      TamanduaServer.Agents.Registry.register(agent_id, %{
        hostname: "test-host",
        os_type: "linux",
        organization_id: @organization_id,
        worker_pid: self()
      })

      on_exit(fn -> TamanduaServer.Agents.Registry.unregister(agent_id) end)

      # Queue a command
      {:ok, command} =
        CommandManager.queue_command(agent_id, :kill_process, %{pid: 1234}, priority: 5)

      assert command.agent_id == agent_id
      assert command.command_type == "kill_process"
      assert command.command_params == %{"pid" => 1234}
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
        organization_id: @organization_id,
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
        assert command.command_params == stringify_keys(params)
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
        organization_id: @organization_id,
        worker_pid: self()
      })

      {:ok, command} =
        CommandManager.queue_command(agent_id, :quarantine_file, %{path: "C:\\bad.exe"})

      assert command.priority == 0
      assert command.expires_at != nil

      # Should expire in approximately 1 hour (3600 seconds)
      diff = DateTime.diff(command.expires_at, DateTime.utc_now(), :second)
      assert diff >= 3590 and diff <= 3610
    end

    test "returns the existing command for a repeated idempotency key" do
      agent_id = "test-agent-#{System.unique_integer([:positive])}"
      key = "decision-test-#{System.unique_integer([:positive])}"

      TamanduaServer.Agents.Registry.register(agent_id, %{
        hostname: "test-host",
        os_type: "linux",
        organization_id: @organization_id,
        worker_pid: self()
      })

      on_exit(fn -> TamanduaServer.Agents.Registry.unregister(agent_id) end)

      assert {:ok, first} =
               CommandManager.queue_command(
                 agent_id,
                 :kill_process,
                 %{pid: 1234},
                 idempotency_key: key
               )

      assert {:ok, replay} =
               CommandManager.queue_command(
                 agent_id,
                 :kill_process,
                 %{pid: 1234},
                 idempotency_key: key
               )

      assert replay.id == first.id
      assert replay.idempotency_key == key

      assert Repo.aggregate(
               from(c in AgentCommand,
                 where: c.agent_id == ^agent_id and c.idempotency_key == ^key
               ),
               :count,
               :id
             ) == 1
    end
  end

  describe "queue_fleet_osquery/3" do
    test "queues osquery command only for live agents that reported the capability" do
      org_id = @organization_id
      capable_agent = "test-agent-#{:rand.uniform(10000)}"
      remote_query_agent = "test-agent-#{:rand.uniform(10000)}"
      unsupported_agent = "test-agent-#{:rand.uniform(10000)}"

      TamanduaServer.Agents.Registry.register(capable_agent, %{
        hostname: "capable-host",
        os_type: "linux",
        organization_id: org_id,
        worker_pid: self(),
        capabilities: ["live_response", "osquery_query"]
      })

      TamanduaServer.Agents.Registry.register(remote_query_agent, %{
        hostname: "remote-query-host",
        os_type: "windows",
        organization_id: org_id,
        worker_pid: self(),
        capabilities: ["remote_query"]
      })

      TamanduaServer.Agents.Registry.register(unsupported_agent, %{
        hostname: "unsupported-host",
        os_type: "linux",
        organization_id: org_id,
        worker_pid: self(),
        capabilities: ["live_response"]
      })

      result =
        CommandManager.queue_fleet_osquery(
          org_id,
          "select pid, name from processes limit 5;",
          max_rows: 5,
          max_output_bytes: 8192,
          priority: 2,
          timeout: 120
        )

      assert result.total_targets == 3
      assert Enum.map(result.queued, & &1.agent_id) == [capable_agent, remote_query_agent]
      assert Enum.map(result.queued, & &1.command_type) == ["osquery_query", "osquery_query"]
      assert Enum.all?(result.queued, &(&1.command_params["max_rows"] == 5))

      assert result.skipped == [
               %{agent_id: unsupported_agent, reason: :missing_osquery_capability}
             ]
    end

    test "honors explicit agent allowlist for fleet osquery" do
      org_id = @organization_id
      agent_a = "test-agent-#{:rand.uniform(10000)}"
      agent_b = "test-agent-#{:rand.uniform(10000)}"

      for agent_id <- [agent_a, agent_b] do
        TamanduaServer.Agents.Registry.register(agent_id, %{
          hostname: agent_id,
          os_type: "linux",
          organization_id: org_id,
          worker_pid: self(),
          capabilities: ["osquery_query"]
        })
      end

      result =
        CommandManager.queue_fleet_osquery(
          org_id,
          "select * from os_version;",
          agent_ids: [agent_b]
        )

      assert result.total_targets == 1
      assert Enum.map(result.queued, & &1.agent_id) == [agent_b]
      assert result.skipped == []
    end
  end

  describe "get_command/1" do
    test "retrieves a command by ID" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"

      TamanduaServer.Agents.Registry.register(agent_id, %{
        organization_id: @organization_id,
        worker_pid: self()
      })

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
    test "returns deliverable (pending + sent) commands ordered by priority and age" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"

      TamanduaServer.Agents.Registry.register(agent_id, %{
        organization_id: @organization_id,
        worker_pid: self()
      })

      # Create commands with different priorities
      {:ok, cmd1} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 1}, priority: 0)
      {:ok, cmd2} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 2}, priority: 10)
      {:ok, cmd3} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 3}, priority: 5)
      {:ok, cmd4} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 4}, priority: 1)

      # Mark one as sent (may never have reached the agent), one as completed
      Repo.update!(AgentCommand.mark_sent(cmd1))
      Repo.update!(AgentCommand.mark_completed(cmd4))

      pending = CommandManager.pending_commands(agent_id)

      # "sent" commands are included for redelivery on reconnect; terminal
      # statuses are excluded. Ordered by priority (desc).
      assert Enum.map(pending, & &1.id) == [cmd2.id, cmd3.id, cmd1.id]
    end
  end

  describe "cancel_command/1" do
    test "cancels a pending command" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"

      TamanduaServer.Agents.Registry.register(agent_id, %{
        organization_id: @organization_id,
        worker_pid: self()
      })

      {:ok, command} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 9999})

      assert :ok = CommandManager.cancel_command(command.id)

      # Verify command is marked as failed
      {:ok, updated} = CommandManager.get_command(command.id)
      assert updated.status == "failed"
      assert updated.error == "Cancelled by user"
    end

    test "returns error when cancelling already-sent command" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"

      TamanduaServer.Agents.Registry.register(agent_id, %{
        organization_id: @organization_id,
        worker_pid: self()
      })

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

      TamanduaServer.Agents.Registry.register(agent_id, %{
        organization_id: @organization_id,
        worker_pid: self()
      })

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
      assert is_number(stats.avg_completion_seconds)
    end
  end

  describe "retry_command/1" do
    test "creates a new command with same parameters" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"

      TamanduaServer.Agents.Registry.register(agent_id, %{
        organization_id: @organization_id,
        worker_pid: self()
      })

      {:ok, original} =
        CommandManager.queue_command(agent_id, :quarantine_file, %{path: "/tmp/malware"},
          priority: 8
        )

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

    test "rejects screen capture retries that would reuse one-time credentials" do
      agent_id = "test-agent-#{:rand.uniform(10000)}"

      {:ok, original} =
        AgentCommand.insert_new(%{
          agent_id: agent_id,
          command_type: "screen_capture",
          command_params: %{
            "artifact_id" => Ecto.UUID.generate(),
            "upload" => %{"credential_status" => "consumed_or_expired"}
          }
        })

      assert {:error, :non_retryable_command} = CommandManager.retry_command(original.id)
      assert Repo.aggregate(AgentCommand, :count) == 1
    end
  end

  defp stringify_keys(value) when is_map(value) do
    Map.new(value, fn {key, nested_value} -> {to_string(key), stringify_keys(nested_value)} end)
  end

  defp stringify_keys(value) when is_list(value), do: Enum.map(value, &stringify_keys/1)
  defp stringify_keys(value), do: value
end
