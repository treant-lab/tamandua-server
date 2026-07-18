defmodule TamanduaServer.Response.ProcessManagerTest do
  @moduledoc """
  Tests for the asynchronous (queue-based) ProcessManager contract.

  Every ProcessManager function queues a persisted `AgentCommand` via
  `CommandManager.queue_command/4` and returns
  `{:ok, %{command_id: id, status: :queued}}` immediately; the agent's
  result arrives later on the AgentCommand row. These tests assert:

  1. the return shape,
  2. the persisted command row (type + params as the agent wire contract
     expects them: string keys, exact field names from
     apps/tamandua_agent/src/live_response/process_manager.rs), and
  3. that the agent worker is notified (`:send_pending_commands` is sent to
     the registered `worker_pid`, which is the test process here).
  """

  # async: false because Agents.Registry is a shared named ETS table.
  use TamanduaServer.DataCase, async: false

  @organization_id "44444444-4444-4444-8444-444444444444"

  alias TamanduaServer.Agents.{AgentCommand, Registry}
  alias TamanduaServer.Response.ProcessManager

  setup do
    agent_id = "pm-agent-" <> Integer.to_string(System.unique_integer([:positive]))

    :ok =
      Registry.register(agent_id, %{
        hostname: "pm-test-host",
        os_type: "linux",
        organization_id: @organization_id,
        worker_pid: self()
      })

    on_exit(fn -> Registry.unregister(agent_id) end)

    {:ok, agent_id: agent_id}
  end

  defp assert_queued(
         {:ok, %{command_id: command_id, status: :queued}},
         expected_type,
         expected_params
       ) do
    command = Repo.get!(AgentCommand, command_id)
    assert command.command_type == expected_type
    assert command.command_params == expected_params
    assert command.status == "pending"
    # The registered worker (the test process) is nudged to push the command.
    assert_receive :send_pending_commands
    command
  end

  describe "get_process_tree/2" do
    test "queues a process_tree_list command with defaults", %{agent_id: agent_id} do
      result = ProcessManager.get_process_tree(agent_id)

      assert_queued(result, "process_tree_list", %{
        "include_security_checks" => true,
        "filter_elevated" => false
      })
    end

    test "honors include_security_checks and filter_elevated options", %{agent_id: agent_id} do
      result =
        ProcessManager.get_process_tree(agent_id,
          include_security_checks: false,
          filter_elevated: true
        )

      assert_queued(result, "process_tree_list", %{
        "include_security_checks" => false,
        "filter_elevated" => true
      })
    end

    test "returns error for unknown agent" do
      assert {:error, "Agent not found or offline"} =
               ProcessManager.get_process_tree("non-existent")
    end
  end

  describe "kill_process/3" do
    test "queues a process_kill command", %{agent_id: agent_id} do
      result = ProcessManager.kill_process(agent_id, 1234)

      assert_queued(result, "process_kill", %{"pid" => 1234, "force" => false})
    end

    test "supports force option", %{agent_id: agent_id} do
      result = ProcessManager.kill_process(agent_id, 1234, force: true)

      assert_queued(result, "process_kill", %{"pid" => 1234, "force" => true})
    end

    test "returns error for unknown agent" do
      assert {:error, "Agent not found or offline"} =
               ProcessManager.kill_process("non-existent", 1234)
    end
  end

  describe "suspend_process/2" do
    test "queues a process_suspend command", %{agent_id: agent_id} do
      result = ProcessManager.suspend_process(agent_id, 1234)

      assert_queued(result, "process_suspend", %{"pid" => 1234})
    end

    test "returns error for unknown agent" do
      assert {:error, "Agent not found or offline"} =
               ProcessManager.suspend_process("non-existent", 1234)
    end
  end

  describe "resume_process/2" do
    test "queues a process_resume command", %{agent_id: agent_id} do
      result = ProcessManager.resume_process(agent_id, 1234)

      assert_queued(result, "process_resume", %{"pid" => 1234})
    end

    test "returns error for unknown agent" do
      assert {:error, "Agent not found or offline"} =
               ProcessManager.resume_process("non-existent", 1234)
    end
  end

  describe "set_process_priority/3" do
    test "queues a process_set_priority command for each valid level", %{agent_id: agent_id} do
      for priority <- [
            "realtime",
            "high",
            "above_normal",
            "normal",
            "below_normal",
            "idle",
            "low"
          ] do
        result = ProcessManager.set_process_priority(agent_id, 1234, priority)

        assert_queued(result, "process_set_priority", %{"pid" => 1234, "priority" => priority})
      end
    end

    test "rejects invalid priority without queueing", %{agent_id: agent_id} do
      assert {:error, "Invalid priority: invalid"} =
               ProcessManager.set_process_priority(agent_id, 1234, "invalid")

      refute_receive :send_pending_commands, 50
    end

    test "returns error for unknown agent" do
      assert {:error, "Agent not found or offline"} =
               ProcessManager.set_process_priority("non-existent", 1234, "normal")
    end
  end

  describe "list_handles/3" do
    test "queues a process_list_handles command without type filter", %{agent_id: agent_id} do
      result = ProcessManager.list_handles(agent_id, 1234)

      assert_queued(result, "process_list_handles", %{"pid" => 1234, "type" => nil})
    end

    test "queues a type filter when given", %{agent_id: agent_id} do
      result = ProcessManager.list_handles(agent_id, 1234, type: "file")

      assert_queued(result, "process_list_handles", %{"pid" => 1234, "type" => "file"})
    end

    test "returns error for unknown agent" do
      assert {:error, "Agent not found or offline"} =
               ProcessManager.list_handles("non-existent", 1234)
    end
  end

  describe "create_process_dump/3" do
    test "queues a process_create_dump command without strings by default", %{agent_id: agent_id} do
      result = ProcessManager.create_process_dump(agent_id, 1234)

      assert_queued(result, "process_create_dump", %{"pid" => 1234, "include_strings" => false})
    end

    test "queues include_strings when requested", %{agent_id: agent_id} do
      result = ProcessManager.create_process_dump(agent_id, 1234, include_strings: true)

      assert_queued(result, "process_create_dump", %{"pid" => 1234, "include_strings" => true})
    end

    test "returns error for unknown agent" do
      assert {:error, "Agent not found or offline"} =
               ProcessManager.create_process_dump("non-existent", 1234)
    end
  end

  describe "kill_processes/3" do
    test "queues one process_kill command per pid", %{agent_id: agent_id} do
      pids = [1234, 5678, 9012]

      assert {:ok, %{succeeded: succeeded, failed: []}} =
               ProcessManager.kill_processes(agent_id, pids)

      assert Enum.map(succeeded, & &1.pid) == pids

      for %{pid: pid, result: %{command_id: command_id, status: :queued}} <- succeeded do
        command = Repo.get!(AgentCommand, command_id)
        assert command.command_type == "process_kill"
        assert command.command_params == %{"pid" => pid, "force" => false}
      end
    end

    test "supports force option", %{agent_id: agent_id} do
      assert {:ok, %{succeeded: succeeded, failed: []}} =
               ProcessManager.kill_processes(agent_id, [42], force: true)

      assert [%{pid: 42, result: %{command_id: command_id}}] = succeeded
      assert Repo.get!(AgentCommand, command_id).command_params == %{"pid" => 42, "force" => true}
    end

    test "reports per-pid failure for unknown agent" do
      assert {:ok, %{succeeded: [], failed: failed}} =
               ProcessManager.kill_processes("non-existent", [1, 2])

      assert Enum.map(failed, & &1.pid) == [1, 2]
      assert Enum.all?(failed, &(&1.reason == "Agent not found or offline"))
    end
  end
end
