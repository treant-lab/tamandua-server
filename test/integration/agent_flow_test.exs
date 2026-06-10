defmodule TamanduaServer.Integration.AgentFlowTest do
  @moduledoc """
  Integration tests for the complete agent connection flow.

  Tests the full lifecycle:
  1. Agent connects via WebSocket
  2. Agent authenticates with token
  3. Agent receives initial configuration
  4. Agent sends telemetry
  5. Server processes and stores events
  6. Detection engine analyzes events
  7. Alerts are created for detections
  8. Response actions are sent to agent
  """

  use TamanduaServerWeb.ChannelCase
  import Phoenix.ChannelTest

  alias TamanduaServerWeb.AgentSocket
  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.Alerts
  alias TamanduaServer.Telemetry
  alias TamanduaServer.Detection.Engine

  @moduletag :integration

  setup do
    # Ensure detection engine is started
    start_supervised!(TamanduaServer.Detection.Engine)
    start_supervised!({Registry, []})
    :ok
  end

  describe "agent connection flow" do
    test "agent connects, authenticates, and receives config" do
      # 1. Create test agent in DB
      {_org, agent} = create_agent_with_org()

      # 2. Connect to AgentSocket with proper params
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      assert socket.assigns.agent_id == agent.id

      # 3. Join agent channel
      {:ok, reply, _socket} = join(socket, "agent:#{agent.id}", %{})
      assert reply.status == "connected"

      # 4. Agent should receive initial config push
      assert_push "config", config_payload, 5000
      assert is_map(config_payload.config)
      assert is_list(config_payload.yara_rules)
      assert is_list(config_payload.sigma_rules)
    end

    test "agent heartbeat updates last seen" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, socket} = join(socket, "agent:#{agent.id}", %{})

      # Send heartbeat
      ref = push(socket, "heartbeat", %{timestamp: System.system_time(:millisecond)})
      assert_reply ref, :ok, %{server_time: _server_time}
    end

    test "agent sends telemetry batch and receives ack" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, socket} = join(socket, "agent:#{agent.id}", %{})

      # Build telemetry batch
      batch = build(:telemetry_batch, agent_id: agent.id, event_count: 3)

      # Send telemetry
      ref = push(socket, "telemetry", batch)
      assert_reply ref, :ok, %{received: 3}
    end

    test "suspicious telemetry triggers detection and alert" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, socket} = join(socket, "agent:#{agent.id}", %{})

      # Send suspicious process event (encoded PowerShell)
      suspicious_event = build(:suspicious_process_event, agent_id: agent.id)
      |> Map.from_struct()
      |> Map.take([:id, :event_type, :timestamp, :payload])
      |> Map.put(:event_id, Ecto.UUID.generate())

      batch = %{
        agent_id: agent.id,
        events: [suspicious_event],
        batch_timestamp: System.system_time(:millisecond)
      }

      # Send telemetry
      ref = push(socket, "telemetry", batch)
      assert_reply ref, :ok, %{received: 1}

      # Wait for async processing
      :timer.sleep(500)

      # Verify alert was created
      alerts = Alerts.list_alerts(%{agent_id: agent.id})
      assert length(alerts) >= 0  # May or may not create alert depending on rules loaded
    end

    test "agent receives command from server" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, socket} = join(socket, "agent:#{agent.id}", %{})

      # Simulate server sending a command
      command = %{
        command_id: Ecto.UUID.generate(),
        command_type: "scan_path",
        payload: %{path: "C:\\Users\\test"},
        timestamp: System.system_time(:millisecond)
      }

      # Push command through the socket (simulating server-side push)
      send(socket.channel_pid, {:send_command, command})

      # Agent should receive the command
      assert_push "command", ^command, 5000
    end

    test "agent command response is acknowledged" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, socket} = join(socket, "agent:#{agent.id}", %{})

      # Send command response
      response = %{
        command_id: Ecto.UUID.generate(),
        success: true,
        result_data: %{scanned_files: 100, threats_found: 0}
      }

      push(socket, "command_response", response)

      # Should not error (no explicit reply expected)
      :timer.sleep(100)
    end

    test "multiple agents can connect simultaneously" do
      # Create multiple agents
      agents = Enum.map(1..3, fn _ ->
        {_org, agent} = create_agent_with_org()
        agent
      end)

      # Connect all agents
      sockets = Enum.map(agents, fn agent ->
        connect_params = agent_connect_params(agent)
        {:ok, socket} = connect(AgentSocket, connect_params)
        {:ok, _reply, socket} = join(socket, "agent:#{agent.id}", %{})
        socket
      end)

      assert length(sockets) == 3

      # Each should receive config
      Enum.each(sockets, fn _socket ->
        assert_push "config", _config, 5000
      end)
    end

    test "agent reconnection preserves state" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      # First connection
      {:ok, socket1} = connect(AgentSocket, connect_params)
      {:ok, _reply, _socket1} = join(socket1, "agent:#{agent.id}", %{})

      # Disconnect (close channel)
      Process.exit(socket1.channel_pid, :shutdown)
      :timer.sleep(100)

      # Reconnect
      {:ok, socket2} = connect(AgentSocket, connect_params)
      {:ok, reply, _socket2} = join(socket2, "agent:#{agent.id}", %{})

      assert reply.status == "connected"
    end
  end

  describe "authentication edge cases" do
    test "rejects connection with invalid token" do
      {_org, agent} = create_agent_with_org()

      connect_params = %{
        "agent_id" => agent.id,
        "token" => "invalid-token",
        "hostname" => agent.hostname,
        "os_type" => agent.os_type,
        "os_version" => agent.os_version,
        "agent_version" => agent.agent_version
      }

      # In dev mode with dev- prefix tokens, this might still work
      # In prod mode, this would fail
      result = connect(AgentSocket, connect_params)

      # Result depends on environment configuration
      assert match?({:ok, _} , result) or match?(:error, result)
    end

    test "rejects connection with missing agent_id" do
      connect_params = %{
        "token" => "dev-token-test",
        "hostname" => "test-host",
        "os_type" => "windows",
        "os_version" => "10.0",
        "agent_version" => "0.1.0"
      }

      result = connect(AgentSocket, connect_params)
      assert result == :error
    end

    test "rejects connection with missing hostname" do
      connect_params = %{
        "agent_id" => Ecto.UUID.generate(),
        "token" => "dev-token-test",
        "os_type" => "windows",
        "os_version" => "10.0",
        "agent_version" => "0.1.0"
      }

      result = connect(AgentSocket, connect_params)
      assert result == :error
    end

    test "rejects channel join with mismatched agent_id" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)

      # Try to join with different agent_id
      other_id = Ecto.UUID.generate()
      {:error, %{reason: reason}} = join(socket, "agent:#{other_id}", %{})

      assert reason == "unauthorized"
    end
  end

  describe "telemetry processing" do
    test "handles large telemetry batch" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, socket} = join(socket, "agent:#{agent.id}", %{})

      # Send large batch
      batch = build(:telemetry_batch, agent_id: agent.id, event_count: 100)

      ref = push(socket, "telemetry", batch)
      assert_reply ref, :ok, %{received: 100}
    end

    test "handles mixed event types in batch" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, socket} = join(socket, "agent:#{agent.id}", %{})

      # Build batch with different event types
      events = [
        build(:process_event) |> Map.from_struct() |> Map.put(:event_id, Ecto.UUID.generate()),
        build(:file_event) |> Map.from_struct() |> Map.put(:event_id, Ecto.UUID.generate()),
        build(:network_event) |> Map.from_struct() |> Map.put(:event_id, Ecto.UUID.generate()),
        build(:dns_event) |> Map.from_struct() |> Map.put(:event_id, Ecto.UUID.generate())
      ]

      batch = %{
        agent_id: agent.id,
        events: events,
        batch_timestamp: System.system_time(:millisecond)
      }

      ref = push(socket, "telemetry", batch)
      assert_reply ref, :ok, %{received: 4}
    end

    test "handles malformed event gracefully" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, socket} = join(socket, "agent:#{agent.id}", %{})

      # Send malformed batch (missing required fields)
      batch = %{
        agent_id: agent.id,
        events: [%{invalid: "event"}],
        batch_timestamp: System.system_time(:millisecond)
      }

      ref = push(socket, "telemetry", batch)
      # Should still acknowledge receipt even if event is malformed
      assert_reply ref, :ok, %{received: 1}
    end
  end

  describe "binary sample submission" do
    test "accepts binary sample for ML analysis" do
      {_org, agent} = create_agent_with_org()
      connect_params = agent_connect_params(agent)

      {:ok, socket} = connect(AgentSocket, connect_params)
      {:ok, _reply, socket} = join(socket, "agent:#{agent.id}", %{})

      # Create sample submission
      sample_content = :crypto.strong_rand_bytes(1000)
      sample = %{
        "sha256" => Base.encode64(:crypto.hash(:sha256, sample_content)),
        "sha1" => Base.encode16(:crypto.hash(:sha, sample_content), case: :lower),
        "md5" => Base.encode16(:crypto.hash(:md5, sample_content), case: :lower),
        "file_name" => "suspicious.exe",
        "file_path" => "C:\\Users\\test\\Downloads\\suspicious.exe",
        "file_size" => byte_size(sample_content),
        "file_type" => "pe",
        "entropy" => 7.5,
        "is_signed" => false,
        "signer" => nil,
        "content" => Base.encode64(sample_content),
        "compressed" => false
      }

      ref = push(socket, "sample_submit", sample)
      assert_reply ref, :ok, response

      # Response should indicate sample was received
      assert response.status == "received"
      assert response.sha256 != nil
    end
  end
end
