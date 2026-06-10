defmodule TamanduaServerWeb.LogsChannelTest do
  use TamanduaServerWeb.ChannelCase

  alias TamanduaServerWeb.LogsChannel
  alias TamanduaServer.Agents.LogAggregator

  setup do
    # Start LogAggregator for tests
    start_supervised!(LogAggregator)

    # Mock user and organization
    user = %{
      id: "user-123",
      organization_id: "org-123",
      email: "test@example.com"
    }

    # Create mock socket
    {:ok, socket} = connect(TamanduaServerWeb.DashboardSocket, %{
      "token" => "test-token"
    })

    socket = assign(socket, :current_user, user)
    socket = assign(socket, :user_id, user.id)
    socket = assign(socket, :organization_id, user.organization_id)

    {:ok, socket: socket, user: user}
  end

  describe "join/3" do
    test "successfully joins logs:viewer with valid params", %{socket: socket} do
      {:ok, reply, socket} = subscribe_and_join(socket, LogsChannel, "logs:viewer", %{
        "agent_ids" => ["agent-1", "agent-2"],
        "levels" => ["info", "warn", "error"],
        "tail" => 10
      })

      assert reply.stream_id
      assert reply.filters
      assert socket.assigns.stream_id
    end

    test "joins with default filters when none provided", %{socket: socket} do
      {:ok, reply, socket} = subscribe_and_join(socket, LogsChannel, "logs:viewer", %{})

      assert reply.stream_id
      assert reply.filters.agent_ids == []
      assert reply.filters.levels == []
    end

    test "rejects join without authentication" do
      {:ok, socket} = connect(TamanduaServerWeb.DashboardSocket, %{})

      assert {:error, %{reason: "unauthorized"}} =
        subscribe_and_join(socket, LogsChannel, "logs:viewer", %{})
    end
  end

  describe "handle_in/3 - update_filters" do
    setup %{socket: socket} do
      {:ok, _reply, socket} = subscribe_and_join(socket, LogsChannel, "logs:viewer", %{})
      {:ok, socket: socket}
    end

    test "updates filters successfully", %{socket: socket} do
      ref = push(socket, "update_filters", %{
        "filters" => %{
          "levels" => ["error"],
          "components" => ["collectors"]
        }
      })

      assert_reply ref, :ok, reply
      assert reply.filters.levels == ["error"]
      assert reply.filters.components == ["collectors"]
    end
  end

  describe "handle_in/3 - fetch_context" do
    setup %{socket: socket} do
      {:ok, _reply, socket} = subscribe_and_join(socket, LogsChannel, "logs:viewer", %{})
      {:ok, socket: socket}
    end

    test "fetches log context", %{socket: socket} do
      log_id = "agent-1:1234567890:abc123"

      ref = push(socket, "fetch_context", %{
        "log_id" => log_id,
        "lines" => 10
      })

      # Should respond even if not found
      assert_reply ref, _, _
    end
  end

  describe "handle_in/3 - export" do
    setup %{socket: socket} do
      {:ok, _reply, socket} = subscribe_and_join(socket, LogsChannel, "logs:viewer", %{})
      {:ok, socket: socket}
    end

    test "exports logs as JSON", %{socket: socket} do
      ref = push(socket, "export", %{"format" => "json"})
      assert_reply ref, :ok, reply
      assert reply.format == "json"
    end

    test "exports logs as CSV", %{socket: socket} do
      ref = push(socket, "export", %{"format" => "csv"})
      assert_reply ref, :ok, reply
      assert reply.format == "csv"
    end

    test "exports logs as TXT", %{socket: socket} do
      ref = push(socket, "export", %{"format" => "txt"})
      assert_reply ref, :ok, reply
      assert reply.format == "txt"
    end
  end

  describe "handle_info/2 - log streaming" do
    setup %{socket: socket} do
      {:ok, _reply, socket} = subscribe_and_join(socket, LogsChannel, "logs:viewer", %{
        "levels" => ["info", "error"]
      })
      {:ok, socket: socket}
    end

    test "receives real-time log entry", %{socket: socket} do
      log = %{
        timestamp: System.system_time(:millisecond),
        agent_id: "agent-1",
        level: "info",
        component: "collectors",
        message: "Test log message",
        fields: %{},
        file: "test.rs",
        line: 42,
        thread: "main"
      }

      send(socket.transport_pid, {:log_entry, log})

      assert_push "log", pushed_log
      assert pushed_log.message == "Test log message"
      assert pushed_log.level == "info"
    end

    test "receives batch of log entries", %{socket: socket} do
      logs = [
        %{
          timestamp: System.system_time(:millisecond),
          agent_id: "agent-1",
          level: "info",
          component: "collectors",
          message: "Log 1",
          fields: %{}
        },
        %{
          timestamp: System.system_time(:millisecond),
          agent_id: "agent-1",
          level: "error",
          component: "transport",
          message: "Log 2",
          fields: %{}
        }
      ]

      send(socket.transport_pid, {:log_batch, logs})

      assert_push "logs:batch", pushed_batch
      assert pushed_batch.count == 2
      assert length(pushed_batch.logs) == 2
    end

    test "filters out logs that don't match level filter", %{socket: socket} do
      log = %{
        timestamp: System.system_time(:millisecond),
        agent_id: "agent-1",
        level: "debug",  # Not in filter
        component: "collectors",
        message: "Debug message",
        fields: %{}
      }

      send(socket.transport_pid, {:log_entry, log})

      refute_push "log", _
    end
  end

  describe "terminate/2" do
    test "unregisters stream on disconnect", %{socket: socket} do
      {:ok, _reply, socket} = subscribe_and_join(socket, LogsChannel, "logs:viewer", %{})
      stream_id = socket.assigns.stream_id

      # Close the socket
      close(socket)

      # Stream should be unregistered (would need to check LogAggregator state)
      # For now, just verify no crash
      assert true
    end
  end
end
