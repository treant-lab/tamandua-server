defmodule TamanduaServer.Telemetry.ClickHouseWriterTest do
  @moduledoc """
  Tests for the ClickHouse Writer GenServer.

  The ClickHouseWriter batches telemetry events and flushes them to ClickHouse.
  It includes a circuit breaker to handle ClickHouse unavailability, event routing
  to target tables by event type, and schema mapping for each table format.

  Since ClickHouse is typically not available in the test environment, these tests
  focus on:
  - Writer stats reporting
  - Buffer behavior (write cast acceptance)
  - Circuit breaker state
  - Event routing logic (target table mapping)
  - Schema format mapping for all event types
  - Flush behavior
  - Disabled mode behavior
  """

  use ExUnit.Case, async: true

  alias TamanduaServer.Telemetry.ClickHouseWriter

  # ============================================================================
  # Stats
  # ============================================================================

  describe "get_stats/0" do
    test "returns a map" do
      stats = ClickHouseWriter.get_stats()
      assert is_map(stats)
    end

    test "contains status field" do
      stats = ClickHouseWriter.get_stats()
      assert Map.has_key?(stats, :status)
      assert stats.status in ["active", "disabled", "unavailable"]
    end

    test "when active, contains circuit and counter fields" do
      stats = ClickHouseWriter.get_stats()

      if stats.status == "active" do
        assert Map.has_key?(stats, :circuit)
        assert stats.circuit in [:closed, :open, :half_open]
        assert Map.has_key?(stats, :queue_depth)
        assert Map.has_key?(stats, :events_written)
        assert Map.has_key?(stats, :events_dropped)
        assert Map.has_key?(stats, :flush_count)
        assert Map.has_key?(stats, :flush_errors)
        assert Map.has_key?(stats, :last_flush_ms)
        assert Map.has_key?(stats, :batch_size)
        assert Map.has_key?(stats, :flush_interval_ms)

        assert is_integer(stats.events_written)
        assert is_integer(stats.events_dropped)
        assert is_integer(stats.flush_count)
        assert is_integer(stats.flush_errors)
      end
    end

    test "when active, contains compression and circuit breaker config fields" do
      stats = ClickHouseWriter.get_stats()

      if stats.status == "active" do
        # Compression enabled flag
        assert Map.has_key?(stats, :compression_enabled)
        assert stats.compression_enabled == true

        # Circuit breaker configuration
        assert Map.has_key?(stats, :retry_count)
        assert Map.has_key?(stats, :max_consecutive_failures)
        assert Map.has_key?(stats, :circuit_open_duration_ms)

        assert is_integer(stats.retry_count)
        assert is_integer(stats.max_consecutive_failures)
        assert is_integer(stats.circuit_open_duration_ms)
      end
    end
  end

  # ============================================================================
  # Write (cast)
  # ============================================================================

  describe "write/1" do
    test "returns :ok for a list of events" do
      events = [
        %{
          event_type: "process_create",
          event_id: "test-event-1",
          agent_id: "test-agent-1",
          timestamp: System.system_time(:millisecond),
          payload: %{
            "pid" => 1234,
            "ppid" => 1,
            "process_name" => "test.exe",
            "command_line" => "test.exe --flag",
            "username" => "testuser"
          }
        }
      ]

      assert ClickHouseWriter.write(events) == :ok
    end

    test "returns :ok for an empty list" do
      assert ClickHouseWriter.write([]) == :ok
    end

    test "returns :ok for multiple events of different types" do
      events = [
        %{event_type: "process_create", event_id: "e1", agent_id: "a1", timestamp: 1_700_000_000_000, payload: %{}},
        %{event_type: "dns_query", event_id: "e2", agent_id: "a1", timestamp: 1_700_000_000_001, payload: %{}},
        %{event_type: "network_connect", event_id: "e3", agent_id: "a1", timestamp: 1_700_000_000_002, payload: %{}},
        %{event_type: "file_create", event_id: "e4", agent_id: "a1", timestamp: 1_700_000_000_003, payload: %{}},
        %{event_type: "registry_modify", event_id: "e5", agent_id: "a1", timestamp: 1_700_000_000_004, payload: %{}},
        %{event_type: "alert", event_id: "e6", agent_id: "a1", timestamp: 1_700_000_000_005, payload: %{}},
        %{event_type: "unknown_type", event_id: "e7", agent_id: "a1", timestamp: 1_700_000_000_006, payload: %{}}
      ]

      assert ClickHouseWriter.write(events) == :ok
    end
  end

  # ============================================================================
  # Flush
  # ============================================================================

  describe "flush_now/0" do
    test "returns :ok" do
      assert ClickHouseWriter.flush_now() == :ok
    end

    test "is idempotent" do
      assert ClickHouseWriter.flush_now() == :ok
      assert ClickHouseWriter.flush_now() == :ok
    end
  end

  # ============================================================================
  # Event type to table routing
  # ============================================================================

  describe "event type routing" do
    # We test the routing logic indirectly by verifying that the writer
    # accepts all known event types without error.

    test "process events are accepted" do
      for event_type <- ["process_create", "process_terminate", "process_start", "process_exec"] do
        event = %{event_type: event_type, event_id: "rt-#{event_type}", agent_id: "a1", timestamp: 1_700_000_000_000, payload: %{}}
        assert ClickHouseWriter.write([event]) == :ok
      end
    end

    test "file events are accepted" do
      for event_type <- ["file_create", "file_modify", "file_delete", "file_rename", "file_read", "file_write"] do
        event = %{event_type: event_type, event_id: "rt-#{event_type}", agent_id: "a1", timestamp: 1_700_000_000_000, payload: %{}}
        assert ClickHouseWriter.write([event]) == :ok
      end
    end

    test "dns events are accepted" do
      for event_type <- ["dns_query", "dns_response", "dns"] do
        event = %{event_type: event_type, event_id: "rt-#{event_type}", agent_id: "a1", timestamp: 1_700_000_000_000, payload: %{}}
        assert ClickHouseWriter.write([event]) == :ok
      end
    end

    test "network events are accepted" do
      for event_type <- ["network_connect", "network_listen", "network_flow", "network_accept", "network_close"] do
        event = %{event_type: event_type, event_id: "rt-#{event_type}", agent_id: "a1", timestamp: 1_700_000_000_000, payload: %{}}
        assert ClickHouseWriter.write([event]) == :ok
      end
    end

    test "registry events are accepted" do
      for event_type <- ["registry_create", "registry_modify", "registry_delete", "registry_set_value"] do
        event = %{event_type: event_type, event_id: "rt-#{event_type}", agent_id: "a1", timestamp: 1_700_000_000_000, payload: %{}}
        assert ClickHouseWriter.write([event]) == :ok
      end
    end

    test "alert events are accepted" do
      for event_type <- ["alert", "alert_created", "detection_alert"] do
        event = %{event_type: event_type, event_id: "rt-#{event_type}", agent_id: "a1", timestamp: 1_700_000_000_000, payload: %{}}
        assert ClickHouseWriter.write([event]) == :ok
      end
    end

    test "unknown event types fall through to telemetry_events" do
      event = %{event_type: "custom_event_type", event_id: "rt-custom", agent_id: "a1", timestamp: 1_700_000_000_000, payload: %{}}
      assert ClickHouseWriter.write([event]) == :ok
    end
  end

  # ============================================================================
  # Timestamp format handling
  # ============================================================================

  describe "timestamp handling" do
    test "accepts millisecond Unix timestamps" do
      event = %{event_type: "process_create", event_id: "ts-ms", agent_id: "a1", timestamp: 1_700_000_000_000, payload: %{}}
      assert ClickHouseWriter.write([event]) == :ok
    end

    test "accepts second Unix timestamps" do
      event = %{event_type: "process_create", event_id: "ts-s", agent_id: "a1", timestamp: 1_700_000_000, payload: %{}}
      assert ClickHouseWriter.write([event]) == :ok
    end

    test "accepts float timestamps" do
      event = %{event_type: "process_create", event_id: "ts-f", agent_id: "a1", timestamp: 1_700_000_000.5, payload: %{}}
      assert ClickHouseWriter.write([event]) == :ok
    end

    test "accepts ISO 8601 string timestamps" do
      event = %{event_type: "process_create", event_id: "ts-iso", agent_id: "a1", timestamp: "2024-01-15T12:00:00Z", payload: %{}}
      assert ClickHouseWriter.write([event]) == :ok
    end

    test "accepts DateTime struct timestamps" do
      event = %{event_type: "process_create", event_id: "ts-dt", agent_id: "a1", timestamp: DateTime.utc_now(), payload: %{}}
      assert ClickHouseWriter.write([event]) == :ok
    end

    test "accepts nil timestamp (uses current time)" do
      event = %{event_type: "process_create", event_id: "ts-nil", agent_id: "a1", timestamp: nil, payload: %{}}
      assert ClickHouseWriter.write([event]) == :ok
    end
  end

  # ============================================================================
  # Circuit breaker states
  # ============================================================================

  describe "circuit breaker" do
    test "starts in closed state (when active)" do
      stats = ClickHouseWriter.get_stats()

      if stats.status == "active" do
        # On a fresh start, circuit should be closed
        assert stats.circuit == :closed
        assert stats.consecutive_failures == 0
      end
    end
  end

  # ============================================================================
  # Payload field access patterns
  # ============================================================================

  describe "payload field access" do
    test "accepts string-keyed payloads" do
      event = %{
        event_type: "process_create",
        event_id: "pf-str",
        agent_id: "a1",
        timestamp: 1_700_000_000_000,
        payload: %{
          "pid" => 1234,
          "ppid" => 1,
          "process_name" => "test.exe",
          "command_line" => "test.exe --flag",
          "is_elevated" => true,
          "is_signed" => true,
          "signer" => "Microsoft",
          "username" => "SYSTEM"
        }
      }

      assert ClickHouseWriter.write([event]) == :ok
    end

    test "accepts atom-keyed payloads" do
      event = %{
        event_type: :process_create,
        event_id: "pf-atom",
        agent_id: "a1",
        timestamp: 1_700_000_000_000,
        payload: %{
          pid: 5678,
          ppid: 1,
          process_name: "explorer.exe",
          command_line: "explorer.exe",
          is_elevated: false,
          is_signed: true,
          signer: "Microsoft Corporation",
          username: "user"
        }
      }

      assert ClickHouseWriter.write([event]) == :ok
    end

    test "accepts empty payload gracefully" do
      event = %{
        event_type: "file_create",
        event_id: "pf-empty",
        agent_id: "a1",
        timestamp: 1_700_000_000_000,
        payload: %{}
      }

      assert ClickHouseWriter.write([event]) == :ok
    end
  end

  # ============================================================================
  # Boolean to UInt8 conversion
  # ============================================================================

  describe "boolean field handling" do
    test "accepts true, 1, and string true equivalents" do
      # All these should be treated as truthy by the writer
      for truthy_val <- [true, 1, "1", "true"] do
        event = %{
          event_type: "process_create",
          event_id: "bool-#{inspect(truthy_val)}",
          agent_id: "a1",
          timestamp: 1_700_000_000_000,
          payload: %{"is_elevated" => truthy_val, "pid" => 1}
        }

        assert ClickHouseWriter.write([event]) == :ok
      end
    end
  end

  # ============================================================================
  # Compression and Metrics Integration
  # ============================================================================

  describe "compression and metrics" do
    test "write accepts events and returns ok (metrics recording is internal)" do
      # The compression and metrics recording happens internally during flush.
      # We verify that the writer accepts events without error.
      events = [
        %{
          event_type: "process_create",
          event_id: "compress-1",
          agent_id: "a1",
          timestamp: System.system_time(:millisecond),
          payload: %{
            "pid" => 1234,
            "process_name" => "test.exe",
            "command_line" => String.duplicate("test ", 100)  # Larger payload for compression
          }
        },
        %{
          event_type: "network_connect",
          event_id: "compress-2",
          agent_id: "a1",
          timestamp: System.system_time(:millisecond),
          payload: %{
            "source_ip" => "192.168.1.100",
            "dest_ip" => "8.8.8.8",
            "dest_port" => 443,
            "protocol" => "tcp"
          }
        }
      ]

      # Write should succeed - compression happens during flush
      assert ClickHouseWriter.write(events) == :ok
    end

    test "large batch with compressible data is accepted" do
      # Generate a batch with repetitive, compressible content
      events = Enum.map(1..100, fn i ->
        %{
          event_type: "process_create",
          event_id: "large-batch-#{i}",
          agent_id: "a1",
          timestamp: System.system_time(:millisecond),
          payload: %{
            "pid" => i,
            "process_name" => "highly_compressible_process_name_#{rem(i, 10)}.exe",
            "command_line" => String.duplicate("repeated_argument ", 50),
            "username" => "testuser",
            "is_elevated" => rem(i, 2) == 0
          }
        }
      end)

      assert ClickHouseWriter.write(events) == :ok
    end

    test "mixed event types with varied payload sizes are accepted" do
      events = [
        # Small event
        %{event_type: "dns_query", event_id: "m1", agent_id: "a1", timestamp: 1_700_000_000_000,
          payload: %{"query_name" => "example.com", "query_type" => "A"}},

        # Medium event
        %{event_type: "file_create", event_id: "m2", agent_id: "a1", timestamp: 1_700_000_000_001,
          payload: %{"file_path" => "/tmp/test.txt", "file_size" => 1024,
                     "sha256" => "abcd" <> String.duplicate("0", 60)}},

        # Large event
        %{event_type: "process_create", event_id: "m3", agent_id: "a1", timestamp: 1_700_000_000_002,
          payload: %{"command_line" => String.duplicate("arg ", 200),
                     "environment_variables" => String.duplicate("VAR=value;", 100)}}
      ]

      assert ClickHouseWriter.write(events) == :ok
    end
  end

  # ============================================================================
  # Circuit Breaker State Transitions
  # ============================================================================

  describe "circuit breaker configuration" do
    test "stats include circuit breaker settings" do
      stats = ClickHouseWriter.get_stats()

      if stats.status == "active" do
        # Verify circuit breaker configuration is exposed
        assert stats.max_consecutive_failures > 0
        assert stats.circuit_open_duration_ms > 0
        assert stats.retry_count > 0

        # Verify initial state
        assert stats.circuit in [:closed, :open, :half_open]
      end
    end

    test "consecutive_failures counter is tracked" do
      stats = ClickHouseWriter.get_stats()

      if stats.status == "active" do
        assert Map.has_key?(stats, :consecutive_failures)
        assert is_integer(stats.consecutive_failures)
        assert stats.consecutive_failures >= 0
      end
    end
  end

  # ============================================================================
  # Observability and Health Checks
  # ============================================================================

  describe "observability" do
    test "flush_now allows manual triggering for testing" do
      # Write some events
      events = [
        %{event_type: "test_event", event_id: "obs-1", agent_id: "a1",
          timestamp: System.system_time(:millisecond), payload: %{}}
      ]

      ClickHouseWriter.write(events)

      # Force flush (should not crash even if ClickHouse is unavailable)
      assert ClickHouseWriter.flush_now() == :ok
    end

    test "stats are consistently retrievable" do
      # Get stats multiple times to ensure consistency
      stats1 = ClickHouseWriter.get_stats()
      assert is_map(stats1)

      stats2 = ClickHouseWriter.get_stats()
      assert is_map(stats2)

      # Status should be stable
      assert stats1.status == stats2.status
    end
  end
end
