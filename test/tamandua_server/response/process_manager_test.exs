defmodule TamanduaServer.Response.ProcessManagerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Response.ProcessManager
  alias TamanduaServer.{Agents, Response}

  describe "get_process_tree/2" do
    test "returns process tree with valid agent" do
      agent = create_test_agent()

      # Mock the command execution
      # In a real test, you'd mock the AgentRegistry and command sending

      assert {:ok, _tree_data} = ProcessManager.get_process_tree(agent.agent_id)
    end

    test "returns error for offline agent" do
      agent = create_test_agent(status: :offline)

      assert {:error, "Agent is offline"} = ProcessManager.get_process_tree(agent.agent_id)
    end

    test "returns error for non-existent agent" do
      assert {:error, _reason} = ProcessManager.get_process_tree("non-existent")
    end

    test "accepts security checks option" do
      agent = create_test_agent()

      assert {:ok, _tree_data} =
               ProcessManager.get_process_tree(agent.agent_id,
                 include_security_checks: true
               )
    end

    test "accepts filter elevated option" do
      agent = create_test_agent()

      assert {:ok, _tree_data} =
               ProcessManager.get_process_tree(agent.agent_id, filter_elevated: true)
    end
  end

  describe "kill_process/3" do
    test "sends kill command with valid PID" do
      agent = create_test_agent()
      pid = 1234

      assert {:ok, _result} = ProcessManager.kill_process(agent.agent_id, pid)
    end

    test "supports force option" do
      agent = create_test_agent()
      pid = 1234

      assert {:ok, _result} = ProcessManager.kill_process(agent.agent_id, pid, force: true)
    end

    test "returns error for offline agent" do
      agent = create_test_agent(status: :offline)
      pid = 1234

      assert {:error, "Agent is offline"} = ProcessManager.kill_process(agent.agent_id, pid)
    end
  end

  describe "suspend_process/2" do
    test "sends suspend command with valid PID" do
      agent = create_test_agent()
      pid = 1234

      assert {:ok, _result} = ProcessManager.suspend_process(agent.agent_id, pid)
    end

    test "returns error for offline agent" do
      agent = create_test_agent(status: :offline)
      pid = 1234

      assert {:error, "Agent is offline"} = ProcessManager.suspend_process(agent.agent_id, pid)
    end
  end

  describe "resume_process/2" do
    test "sends resume command with valid PID" do
      agent = create_test_agent()
      pid = 1234

      assert {:ok, _result} = ProcessManager.resume_process(agent.agent_id, pid)
    end

    test "returns error for offline agent" do
      agent = create_test_agent(status: :offline)
      pid = 1234

      assert {:error, "Agent is offline"} = ProcessManager.resume_process(agent.agent_id, pid)
    end
  end

  describe "set_process_priority/3" do
    test "sets priority with valid level" do
      agent = create_test_agent()
      pid = 1234

      for priority <- ["realtime", "high", "above_normal", "normal", "below_normal", "idle", "low"] do
        assert {:ok, _result} =
                 ProcessManager.set_process_priority(agent.agent_id, pid, priority)
      end
    end

    test "returns error for invalid priority" do
      agent = create_test_agent()
      pid = 1234

      assert {:error, "Invalid priority: invalid"} =
               ProcessManager.set_process_priority(agent.agent_id, pid, "invalid")
    end

    test "returns error for offline agent" do
      agent = create_test_agent(status: :offline)
      pid = 1234

      assert {:error, "Agent is offline"} =
               ProcessManager.set_process_priority(agent.agent_id, pid, "normal")
    end
  end

  describe "list_handles/3" do
    test "lists all handles by default" do
      agent = create_test_agent()
      pid = 1234

      assert {:ok, _result} = ProcessManager.list_handles(agent.agent_id, pid)
    end

    test "filters handles by type" do
      agent = create_test_agent()
      pid = 1234

      assert {:ok, _result} =
               ProcessManager.list_handles(agent.agent_id, pid, type: "file")
    end

    test "returns error for offline agent" do
      agent = create_test_agent(status: :offline)
      pid = 1234

      assert {:error, "Agent is offline"} = ProcessManager.list_handles(agent.agent_id, pid)
    end
  end

  describe "create_process_dump/3" do
    test "creates dump without strings by default" do
      agent = create_test_agent()
      pid = 1234

      assert {:ok, _result} = ProcessManager.create_process_dump(agent.agent_id, pid)
    end

    test "creates dump with strings when requested" do
      agent = create_test_agent()
      pid = 1234

      assert {:ok, _result} =
               ProcessManager.create_process_dump(agent.agent_id, pid, include_strings: true)
    end

    test "returns error for offline agent" do
      agent = create_test_agent(status: :offline)
      pid = 1234

      assert {:error, "Agent is offline"} =
               ProcessManager.create_process_dump(agent.agent_id, pid)
    end
  end

  describe "kill_processes/3" do
    test "kills multiple processes" do
      agent = create_test_agent()
      pids = [1234, 5678, 9012]

      assert {:ok, %{succeeded: succeeded, failed: failed}} =
               ProcessManager.kill_processes(agent.agent_id, pids)

      assert is_list(succeeded)
      assert is_list(failed)
    end

    test "handles mix of success and failure" do
      agent = create_test_agent()
      pids = [1234, 5678]

      # In a real test, you'd mock some to succeed and some to fail
      assert {:ok, %{succeeded: _succeeded, failed: _failed}} =
               ProcessManager.kill_processes(agent.agent_id, pids)
    end

    test "supports force option" do
      agent = create_test_agent()
      pids = [1234, 5678]

      assert {:ok, %{succeeded: _succeeded, failed: _failed}} =
               ProcessManager.kill_processes(agent.agent_id, pids, force: true)
    end
  end

  # Helper functions

  defp create_test_agent(attrs \\ %{}) do
    default_attrs = %{
      agent_id: Ecto.UUID.generate(),
      hostname: "test-host",
      ip_address: "192.168.1.100",
      os_type: "linux",
      os_version: "Ubuntu 22.04",
      agent_version: "1.0.0",
      status: :online,
      last_seen: DateTime.utc_now()
    }

    attrs = Map.merge(default_attrs, Enum.into(attrs, %{}))

    {:ok, agent} = Agents.create_agent(attrs)
    agent
  end
end
