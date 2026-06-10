defmodule TamanduaServer.Agents.LogAggregatorTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Agents.LogAggregator

  setup do
    # Start the LogAggregator
    start_supervised!(LogAggregator)
    :ok
  end

  describe "stream registration" do
    test "registers a new stream" do
      stream_id = "test-stream-#{:erlang.unique_integer()}"
      filters = %{
        agent_ids: ["agent-1"],
        levels: ["info", "error"],
        components: [],
        keyword: nil,
        regex: nil,
        time_start: nil,
        time_end: nil
      }

      assert :ok = LogAggregator.register_stream(stream_id, self(), filters)
    end

    test "updates stream filters" do
      stream_id = "test-stream-#{:erlang.unique_integer()}"
      filters = %{
        agent_ids: ["agent-1"],
        levels: ["info"],
        components: [],
        keyword: nil,
        regex: nil,
        time_start: nil,
        time_end: nil
      }

      :ok = LogAggregator.register_stream(stream_id, self(), filters)

      new_filters = %{filters | levels: ["error", "warn"]}
      assert :ok = LogAggregator.update_stream(stream_id, new_filters)
    end

    test "unregisters a stream" do
      stream_id = "test-stream-#{:erlang.unique_integer()}"
      filters = %{
        agent_ids: [],
        levels: [],
        components: [],
        keyword: nil,
        regex: nil,
        time_start: nil,
        time_end: nil
      }

      :ok = LogAggregator.register_stream(stream_id, self(), filters)
      assert :ok = LogAggregator.unregister_stream(stream_id)
    end

    test "returns error when unregistering non-existent stream" do
      assert {:error, :not_found} = LogAggregator.unregister_stream("non-existent")
    end
  end

  describe "log processing" do
    test "processes single log entry" do
      stream_id = "test-stream-#{:erlang.unique_integer()}"
      filters = %{
        agent_ids: ["agent-1"],
        levels: ["info"],
        components: [],
        keyword: nil,
        regex: nil,
        time_start: nil,
        time_end: nil
      }

      :ok = LogAggregator.register_stream(stream_id, self(), filters)

      log_entry = %{
        timestamp: System.system_time(:millisecond),
        level: "info",
        component: "collectors",
        message: "Test log message",
        fields: %{},
        file: "test.rs",
        line: 42,
        thread: nil
      }

      LogAggregator.process_log("agent-1", log_entry)

      # Should receive the log entry
      assert_receive {:log_entry, received_log}, 1000
      assert received_log.message == "Test log message"
      assert received_log.agent_id == "agent-1"
    end

    test "processes batch of log entries" do
      stream_id = "test-stream-#{:erlang.unique_integer()}"
      filters = %{
        agent_ids: ["agent-1"],
        levels: ["info", "error"],
        components: [],
        keyword: nil,
        regex: nil,
        time_start: nil,
        time_end: nil
      }

      :ok = LogAggregator.register_stream(stream_id, self(), filters)

      logs = [
        %{
          timestamp: System.system_time(:millisecond),
          level: "info",
          component: "collectors",
          message: "Log 1",
          fields: %{}
        },
        %{
          timestamp: System.system_time(:millisecond),
          level: "error",
          component: "transport",
          message: "Log 2",
          fields: %{}
        }
      ]

      LogAggregator.process_log_batch("agent-1", logs)

      # Should receive batch
      assert_receive {:log_batch, received_logs}, 1000
      assert length(received_logs) == 2
    end

    test "filters logs by level" do
      stream_id = "test-stream-#{:erlang.unique_integer()}"
      filters = %{
        agent_ids: [],
        levels: ["error"],  # Only errors
        components: [],
        keyword: nil,
        regex: nil,
        time_start: nil,
        time_end: nil
      }

      :ok = LogAggregator.register_stream(stream_id, self(), filters)

      # Info log should be filtered out
      info_log = %{
        timestamp: System.system_time(:millisecond),
        level: "info",
        component: "collectors",
        message: "Info message",
        fields: %{}
      }

      LogAggregator.process_log("agent-1", info_log)
      refute_receive {:log_entry, _}, 500

      # Error log should come through
      error_log = %{
        timestamp: System.system_time(:millisecond),
        level: "error",
        component: "collectors",
        message: "Error message",
        fields: %{}
      }

      LogAggregator.process_log("agent-1", error_log)
      assert_receive {:log_entry, _}, 1000
    end

    test "filters logs by keyword" do
      stream_id = "test-stream-#{:erlang.unique_integer()}"
      filters = %{
        agent_ids: [],
        levels: [],
        components: [],
        keyword: "timeout",
        regex: nil,
        time_start: nil,
        time_end: nil
      }

      :ok = LogAggregator.register_stream(stream_id, self(), filters)

      # Log without keyword
      log1 = %{
        timestamp: System.system_time(:millisecond),
        level: "info",
        component: "collectors",
        message: "Process started",
        fields: %{}
      }

      LogAggregator.process_log("agent-1", log1)
      refute_receive {:log_entry, _}, 500

      # Log with keyword
      log2 = %{
        timestamp: System.system_time(:millisecond),
        level: "error",
        component: "transport",
        message: "Connection timeout after 30s",
        fields: %{}
      }

      LogAggregator.process_log("agent-1", log2)
      assert_receive {:log_entry, _}, 1000
    end
  end

  describe "error pattern detection" do
    test "detects panic patterns" do
      log_entry = %{
        timestamp: System.system_time(:millisecond),
        level: "error",
        component: "collectors",
        message: "thread 'main' panicked at 'index out of bounds'",
        fields: %{}
      }

      LogAggregator.process_log("agent-1", log_entry)

      # Pattern should be detected and stored
      {:ok, patterns} = LogAggregator.get_error_patterns(10)
      assert Enum.any?(patterns, fn p -> p.category == :panic end)
    end

    test "detects timeout patterns" do
      log_entry = %{
        timestamp: System.system_time(:millisecond),
        level: "warn",
        component: "transport",
        message: "Request timeout after 30 seconds",
        fields: %{}
      }

      LogAggregator.process_log("agent-1", log_entry)

      {:ok, patterns} = LogAggregator.get_error_patterns(10)
      assert Enum.any?(patterns, fn p -> p.category == :timeout end)
    end
  end

  describe "metrics extraction" do
    test "extracts CPU usage from logs" do
      log_entry = %{
        timestamp: System.system_time(:millisecond),
        level: "info",
        component: "collectors",
        message: "System metrics: CPU: 45.2%, Memory: 1024 MB",
        fields: %{}
      }

      LogAggregator.process_log("agent-1", log_entry)

      # Wait for metrics processing
      Process.sleep(100)

      {:ok, metrics} = LogAggregator.get_metrics(60)
      assert metrics[:cpu_usage] != nil
    end

    test "extracts event rate from logs" do
      log_entry = %{
        timestamp: System.system_time(:millisecond),
        level: "info",
        component: "collectors",
        message: "Processing 150 events/sec",
        fields: %{}
      }

      LogAggregator.process_log("agent-1", log_entry)

      Process.sleep(100)

      {:ok, metrics} = LogAggregator.get_metrics(60)
      assert metrics[:event_rate] != nil
    end
  end
end
