defmodule TamanduaServer.LoadTest.AgentSimulationTest do
  @moduledoc """
  In-process load testing for agent WebSocket connections.

  These tests simulate concurrent agent behavior using Phoenix.ChannelTest
  to validate connection handling, telemetry processing, and resource usage.

  Run with: mix test --only load
  """

  use TamanduaServerWeb.ChannelCase, async: false

  alias TamanduaServer.Agents.AgentRegistry
  alias TamanduaServerWeb.AgentSocket

  # Mark as load test - excluded from regular test runs
  @moduletag :load
  @moduletag timeout: :infinity

  # Test configuration
  @agent_count_small 50
  @agent_count_medium 100
  @agent_count_large 200
  @heartbeat_count 10
  @telemetry_batch_size 100
  @telemetry_batches_per_agent 5

  describe "concurrent agent connections" do
    test "simulates 100 concurrent agent connections" do
      start_time = System.monotonic_time(:millisecond)

      # Track connection metrics
      connection_times = []
      join_latencies = []

      # Spawn 100 agent tasks concurrently
      tasks =
        Enum.map(1..@agent_count_medium, fn i ->
          Task.async(fn ->
            agent_id = "load-test-agent-#{i}-#{:rand.uniform(100000)}"
            connect_start = System.monotonic_time(:millisecond)

            # Connect to socket
            {:ok, socket} = connect_agent(agent_id)
            connect_time = System.monotonic_time(:millisecond) - connect_start

            join_start = System.monotonic_time(:millisecond)

            # Join agent channel
            {:ok, _reply, _socket} = subscribe_and_join(socket, "agent:#{agent_id}", %{})
            join_time = System.monotonic_time(:millisecond) - join_start

            # Send heartbeats
            Enum.each(1..@heartbeat_count, fn _ ->
              ref = push(socket, "heartbeat", %{})
              assert_reply ref, :ok, %{server_time: _time}
              Process.sleep(100)
            end)

            # Clean disconnect
            leave(socket)

            {connect_time, join_time}
          end)
        end)

      # Wait for all agents to complete
      results = Task.await_many(tasks, 60_000)

      # Extract metrics
      {connection_times, join_latencies} = Enum.unzip(results)

      total_time = System.monotonic_time(:millisecond) - start_time

      # Report metrics
      IO.puts("\n=== 100 Concurrent Agents Test ===")
      IO.puts("Total time: #{total_time}ms")
      IO.puts("Average connection time: #{avg(connection_times)}ms")
      IO.puts("Average join latency: #{avg(join_latencies)}ms")
      IO.puts("Max connection time: #{Enum.max(connection_times)}ms")
      IO.puts("Max join latency: #{Enum.max(join_latencies)}ms")

      # Assertions
      assert Enum.all?(connection_times, &(&1 < 5000)), "Some connections took > 5s"
      assert Enum.all?(join_latencies, &(&1 < 2000)), "Some joins took > 2s"
      assert total_time < 120_000, "Test took > 2 minutes"
    end

    test "handles telemetry burst from multiple agents" do
      start_time = System.monotonic_time(:millisecond)
      agent_count = @agent_count_small

      # Connect agents
      sockets =
        Enum.map(1..agent_count, fn i ->
          agent_id = "burst-test-agent-#{i}-#{:rand.uniform(100000)}"
          {:ok, socket} = connect_agent(agent_id)
          {:ok, _reply, socket} = subscribe_and_join(socket, "agent:#{agent_id}", %{})
          socket
        end)

      # Each agent sends multiple telemetry batches
      telemetry_start = System.monotonic_time(:millisecond)
      ack_count = Enum.reduce(sockets, 0, fn socket, acc ->
        Enum.reduce(1..@telemetry_batches_per_agent, acc, fn _, inner_acc ->
          events = generate_events(@telemetry_batch_size, socket.assigns.agent_id)
          ref = push(socket, "telemetry", %{"events" => events})

          # Wait for acknowledgment
          assert_reply ref, :ok, %{received: count}, 5000
          assert count == @telemetry_batch_size

          inner_acc + 1
        end)
      end)

      telemetry_time = System.monotonic_time(:millisecond) - telemetry_start
      total_events = agent_count * @telemetry_batches_per_agent * @telemetry_batch_size

      # Clean up
      Enum.each(sockets, &leave/1)

      total_time = System.monotonic_time(:millisecond) - start_time

      # Report metrics
      IO.puts("\n=== Telemetry Burst Test ===")
      IO.puts("Agents: #{agent_count}")
      IO.puts("Total events sent: #{total_events}")
      IO.puts("Batches acknowledged: #{ack_count}")
      IO.puts("Telemetry processing time: #{telemetry_time}ms")
      IO.puts("Throughput: #{trunc(total_events / (telemetry_time / 1000))} events/sec")
      IO.puts("Total time: #{total_time}ms")

      # Assertions
      assert ack_count == agent_count * @telemetry_batches_per_agent,
             "Not all batches acknowledged"

      assert telemetry_time < 30_000, "Telemetry processing took > 30s"
    end

    test "survives rapid connect/disconnect cycles" do
      iterations = 200
      start_time = System.monotonic_time(:millisecond)

      # Get initial ETS table sizes
      initial_registry_size = get_registry_size()

      # Perform rapid cycles
      Enum.each(1..iterations, fn i ->
        agent_id = "cycle-test-agent-#{i}"

        # Connect
        {:ok, socket} = connect_agent(agent_id)
        {:ok, _reply, socket} = subscribe_and_join(socket, "agent:#{agent_id}", %{})

        # Send single heartbeat
        ref = push(socket, "heartbeat", %{})
        assert_reply ref, :ok, _response

        # Disconnect
        leave(socket)

        # Small delay to avoid overwhelming supervisor
        if rem(i, 50) == 0 do
          Process.sleep(100)
          IO.write(".")
        end
      end)

      total_time = System.monotonic_time(:millisecond) - start_time

      # Allow cleanup time
      Process.sleep(1000)

      # Get final ETS table sizes
      final_registry_size = get_registry_size()

      # Report metrics
      IO.puts("\n\n=== Rapid Connect/Disconnect Test ===")
      IO.puts("Iterations: #{iterations}")
      IO.puts("Total time: #{total_time}ms")
      IO.puts("Average cycle time: #{trunc(total_time / iterations)}ms")
      IO.puts("Initial registry size: #{initial_registry_size}")
      IO.puts("Final registry size: #{final_registry_size}")

      # Assertions
      assert total_time < 60_000, "Rapid cycles took > 60s"

      # Allow small registry growth (some pending cleanup)
      assert final_registry_size < initial_registry_size + 10,
             "Registry leaked #{final_registry_size - initial_registry_size} entries"
    end
  end

  describe "performance benchmarks" do
    @tag :benchmark
    test "benchmarks single agent message throughput" do
      agent_id = "benchmark-agent-#{:rand.uniform(100000)}"
      {:ok, socket} = connect_agent(agent_id)
      {:ok, _reply, socket} = subscribe_and_join(socket, "agent:#{agent_id}", %{})

      message_count = 1000
      start_time = System.monotonic_time(:millisecond)

      # Send messages as fast as possible
      Enum.each(1..message_count, fn _ ->
        ref = push(socket, "heartbeat", %{})
        assert_reply ref, :ok, _response, 5000
      end)

      duration = System.monotonic_time(:millisecond) - start_time
      throughput = trunc(message_count / (duration / 1000))

      leave(socket)

      IO.puts("\n=== Single Agent Throughput Benchmark ===")
      IO.puts("Messages: #{message_count}")
      IO.puts("Duration: #{duration}ms")
      IO.puts("Throughput: #{throughput} messages/sec")

      # Should handle at least 100 messages/sec per agent
      assert throughput > 100, "Throughput too low: #{throughput} msg/s"
    end

    @tag :benchmark
    test "measures Broadway pipeline processing latency" do
      agent_id = "pipeline-bench-agent-#{:rand.uniform(100000)}"
      {:ok, socket} = connect_agent(agent_id)
      {:ok, _reply, socket} = subscribe_and_join(socket, "agent:#{agent_id}", %{})

      batch_sizes = [10, 50, 100, 500]

      results =
        Enum.map(batch_sizes, fn size ->
          events = generate_events(size, agent_id)

          start_time = System.monotonic_time(:millisecond)
          ref = push(socket, "telemetry", %{"events" => events})
          assert_reply ref, :ok, %{received: ^size}, 10_000
          latency = System.monotonic_time(:millisecond) - start_time

          {size, latency}
        end)

      leave(socket)

      IO.puts("\n=== Broadway Pipeline Latency ===")

      Enum.each(results, fn {size, latency} ->
        IO.puts("Batch size #{size}: #{latency}ms (#{trunc(latency / size)}ms per event)")
      end)

      # All batches should be acknowledged within 5 seconds
      Enum.each(results, fn {_size, latency} ->
        assert latency < 5000, "Batch processing took > 5s"
      end)
    end
  end

  # Helper functions

  defp connect_agent(agent_id) do
    # Generate test token (simplified for testing)
    token = generate_test_token(agent_id)

    # Connect with agent parameters
    params = %{
      "token" => token,
      "agent_id" => agent_id,
      "hostname" => "load-test-host",
      "os_type" => "linux",
      "os_version" => "5.15.0",
      "agent_version" => "1.0.0",
      "machine_id" => agent_id,
      "capabilities" => ["process", "file", "network"]
    }

    connect(AgentSocket, params)
  end

  defp generate_test_token(agent_id) do
    # Simple test token for load testing
    # In production, use Guardian.encode_and_sign
    "test_token_#{agent_id}"
  end

  defp generate_events(count, agent_id) do
    event_types = ["process", "file", "network", "dns"]

    Enum.map(1..count, fn i ->
      event_type = Enum.random(event_types)

      %{
        "event_type" => event_type,
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601(),
        "agent_id" => agent_id,
        "payload" => generate_event_payload(event_type, i)
      }
    end)
  end

  defp generate_event_payload("process", i) do
    %{
      "pid" => 1000 + i,
      "ppid" => 100,
      "process_name" => "test_process_#{rem(i, 10)}.exe",
      "command_line" => "test command #{i}",
      "user" => "testuser",
      "is_elevated" => false
    }
  end

  defp generate_event_payload("file", i) do
    %{
      "path" => "/tmp/test_file_#{i}.txt",
      "action" => Enum.random(["create", "modify", "delete"]),
      "size" => 1024 * i,
      "hash" => "abc123def456#{i}"
    }
  end

  defp generate_event_payload("network", i) do
    %{
      "src_ip" => "192.168.1.#{rem(i, 254) + 1}",
      "dst_ip" => "8.8.8.8",
      "src_port" => 10000 + i,
      "dst_port" => Enum.random([80, 443, 8080]),
      "protocol" => "tcp",
      "bytes" => 500 + i * 10
    }
  end

  defp generate_event_payload("dns", i) do
    %{
      "query" => "test#{i}.example.com",
      "query_type" => "A",
      "response" => "1.2.3.#{rem(i, 254) + 1}"
    }
  end

  defp get_registry_size do
    # Check AgentRegistry ETS table size
    # Note: This requires access to the registry's ETS table
    case :ets.info(AgentRegistry) do
      :undefined -> 0
      info -> Keyword.get(info, :size, 0)
    end
  rescue
    _ -> 0
  end

  defp avg([]), do: 0

  defp avg(list) do
    sum = Enum.sum(list)
    count = length(list)
    trunc(sum / count)
  end
end
