defmodule TamanduaServer.Response.ExecutorTest do
  @moduledoc """
  Tests covering the WebSocket dispatch path of `TamanduaServer.Response.Executor`.

  These tests focus narrowly on the `dispatch_to_agent/2` helper and on the
  remote-target routing inside `execute_response/2`.  They subscribe to the
  agent's channel topic on `TamanduaServerWeb.Endpoint` and assert that the
  `"command"` event is broadcast when a live worker is registered.
  """

  use TamanduaServerWeb.ChannelCase, async: false

  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.Response.Executor

  setup do
    agent_id = "test-agent-" <> Integer.to_string(System.unique_integer([:positive]))
    topic = "agent:" <> agent_id

    # Register the agent in the in-memory registry with a live worker_pid
    # (using self/0 so Process.alive?/1 returns true).
    :ok =
      Registry.register(agent_id, %{
        hostname: "ws-dispatch-host",
        os_type: "linux",
        worker_pid: self()
      })

    on_exit(fn -> Registry.unregister(agent_id) end)

    # Subscribe so the test process receives broadcasts on the agent topic.
    :ok = @endpoint.subscribe(topic)

    {:ok, agent_id: agent_id, topic: topic}
  end

  describe "dispatch_to_agent/2" do
    test "broadcasts a command event on the agent's channel topic", %{
      agent_id: agent_id,
      topic: topic
    } do
      command = %{command_type: "kill_process", payload: %{pid: 4242}}

      assert {:ok, %{dispatched: true, transport: :websocket}} =
               Executor.dispatch_to_agent(agent_id, command)

      assert_broadcast("command", ^command)
      assert_received %Phoenix.Socket.Broadcast{topic: ^topic, event: "command", payload: ^command}
    end

    test "returns {:error, :agent_offline} when no live worker is registered" do
      missing_agent_id = "missing-" <> Integer.to_string(System.unique_integer([:positive]))

      assert {:error, :agent_offline} =
               Executor.dispatch_to_agent(missing_agent_id, %{command_type: "noop", payload: %{}})
    end
  end

  describe "execute_response/2 with target_agent_id" do
    test "routes remote-targeted actions through dispatch_to_agent/2", %{
      agent_id: agent_id,
      topic: topic
    } do
      action = %{
        action_type: "isolate_network",
        agent_id: agent_id,
        params: %{allowed_ips: []},
        target_agent_id: agent_id
      }

      assert {:ok, %{dispatched: true, transport: :websocket}} =
               Executor.execute_response(nil, action)

      assert_receive %Phoenix.Socket.Broadcast{
                       topic: ^topic,
                       event: "command",
                       payload: %{command_type: "isolate_network", payload: %{allowed_ips: []}}
                     },
                     1_000
    end

    test "also accepts string-keyed target_agent_id", %{agent_id: agent_id, topic: topic} do
      action = %{
        action_type: "kill_process",
        agent_id: agent_id,
        params: %{pid: 1},
        "target_agent_id" => agent_id
      }

      assert {:ok, %{dispatched: true, transport: :websocket}} =
               Executor.execute_response(nil, action)

      assert_receive %Phoenix.Socket.Broadcast{topic: ^topic, event: "command"}, 1_000
    end
  end
end
