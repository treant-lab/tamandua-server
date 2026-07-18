defmodule TamanduaServer.Response.ExecutorTest do
  @moduledoc """
  Tests covering the persisted remote dispatch path of `TamanduaServer.Response.Executor`.

  These tests focus narrowly on the `dispatch_to_agent/2` helper and on the
  remote-target routing inside `execute_response/2`. The executor queues a
  persisted `AgentCommand`; the agent worker is responsible for pushing the
  command over the live channel.
  """

  use TamanduaServerWeb.ChannelCase, async: false

  @organization_id "33333333-3333-4333-8333-333333333333"

  alias TamanduaServer.Agents.{AgentCommand, CommandManager, Registry}
  alias TamanduaServer.Repo
  alias TamanduaServer.Response.Executor

  setup do
    agent_id = "test-agent-" <> Integer.to_string(System.unique_integer([:positive]))
    # Register the agent in the in-memory registry with a live worker_pid
    # (using self/0 so Process.alive?/1 returns true).
    :ok =
      Registry.register(agent_id, %{
        hostname: "ws-dispatch-host",
        os_type: "linux",
        organization_id: @organization_id,
        worker_pid: self()
      })

    on_exit(fn -> Registry.unregister(agent_id) end)

    {:ok, agent_id: agent_id}
  end

  describe "dispatch_to_agent/2" do
    test "queues a persisted command for the live agent", %{agent_id: agent_id} do
      command = %{command_type: "kill_process", payload: %{pid: 4242}}

      assert {:ok, %{dispatched: true, transport: :websocket, command_id: command_id}} =
               Executor.dispatch_to_agent(agent_id, command)

      assert {:ok, %AgentCommand{} = persisted} = CommandManager.get_command(command_id)
      assert persisted.agent_id == agent_id
      assert persisted.command_type == "kill_process"
      assert persisted.command_params == %{"pid" => 4242}
      assert persisted.status == "pending"
      assert_receive :send_pending_commands
    end

    test "returns {:error, :agent_offline} when no live worker is registered" do
      missing_agent_id = "missing-" <> Integer.to_string(System.unique_integer([:positive]))

      assert {:error, :agent_offline} =
               Executor.dispatch_to_agent(missing_agent_id, %{command_type: "noop", payload: %{}})
    end
  end

  describe "execute_response/2 with target_agent_id" do
    test "routes remote-targeted actions through dispatch_to_agent/2", %{agent_id: agent_id} do
      action = %{
        action_type: "isolate_network",
        agent_id: agent_id,
        params: %{allowed_ips: []},
        target_agent_id: agent_id
      }

      assert {:ok, %{dispatched: true, transport: :websocket, command_id: command_id}} =
               Executor.execute_response(nil, action)

      assert %AgentCommand{
               command_type: "isolate_network",
               command_params: %{"allowed_ips" => []}
             } = Repo.get!(AgentCommand, command_id)
    end

    test "also accepts string-keyed target_agent_id", %{agent_id: agent_id} do
      action = %{
        "target_agent_id" => agent_id,
        action_type: "kill_process",
        agent_id: agent_id,
        params: %{pid: 1}
      }

      assert {:ok, %{dispatched: true, transport: :websocket, command_id: command_id}} =
               Executor.execute_response(nil, action)

      assert %AgentCommand{
               command_type: "kill_process",
               command_params: %{"pid" => 1}
             } = Repo.get!(AgentCommand, command_id)
    end
  end
end
