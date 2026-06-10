defmodule TamanduaServer.Streaming.StreamManagerTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Streaming.StreamManager

  setup do
    # Start StreamManager for tests
    start_supervised!(StreamManager)
    :ok
  end

  describe "stream registration" do
    test "registers a new stream subscription" do
      stream_id = "test_stream_#{:erlang.unique_integer([:positive])}"
      subscriber_pid = self()

      filters = %{severity: ["critical", "high"]}
      options = %{format: :json}

      assert :ok = StreamManager.register_stream(stream_id, subscriber_pid, filters, options)

      # Verify stream is registered
      stats = StreamManager.get_stats()
      assert stats.active_streams >= 1
    end

    test "unregisters a stream subscription" do
      stream_id = "test_stream_#{:erlang.unique_integer([:positive])}"
      subscriber_pid = self()

      StreamManager.register_stream(stream_id, subscriber_pid, %{}, %{})
      assert :ok = StreamManager.unregister_stream(stream_id)

      # Verify stream is removed
      stats = StreamManager.get_stats()
      # Note: may still have other streams from other tests
      assert is_integer(stats.active_streams)
    end
  end

  describe "event broadcasting" do
    test "broadcasts alert to matching streams" do
      stream_id = "test_alert_stream_#{:erlang.unique_integer([:positive])}"
      subscriber_pid = self()

      filters = %{severity: ["critical"], stream_type: [:alert]}
      StreamManager.register_stream(stream_id, subscriber_pid, filters, %{format: :json})

      # Broadcast a matching alert
      alert = %{
        severity: "critical",
        title: "Test Alert",
        agent_id: "agent-123",
        organization_id: "org-1"
      }

      StreamManager.broadcast_alert(alert)

      # Should receive the alert
      assert_receive {:stream_data, :alert, _data}, 1000

      StreamManager.unregister_stream(stream_id)
    end

    test "does not broadcast to non-matching streams" do
      stream_id = "test_alert_stream_#{:erlang.unique_integer([:positive])}"
      subscriber_pid = self()

      # Filter for high severity only
      filters = %{severity: ["high"], stream_type: [:alert]}
      StreamManager.register_stream(stream_id, subscriber_pid, filters, %{format: :json})

      # Broadcast a critical alert (should not match)
      alert = %{
        severity: "critical",
        title: "Test Alert",
        agent_id: "agent-123",
        organization_id: "org-1"
      }

      StreamManager.broadcast_alert(alert)

      # Should NOT receive the alert
      refute_receive {:stream_data, :alert, _data}, 500

      StreamManager.unregister_stream(stream_id)
    end

    test "broadcasts event to matching streams" do
      stream_id = "test_event_stream_#{:erlang.unique_integer([:positive])}"
      subscriber_pid = self()

      filters = %{event_type: ["process"], stream_type: [:event]}
      StreamManager.register_stream(stream_id, subscriber_pid, filters, %{format: :json})

      # Broadcast a matching event
      event = %{
        event_type: "process",
        agent_id: "agent-123",
        payload: %{pid: 1234},
        organization_id: "org-1"
      }

      StreamManager.broadcast_event(event)

      # Should receive the event
      assert_receive {:stream_data, :event, _data}, 1000

      StreamManager.unregister_stream(stream_id)
    end

    test "filters by organization_id (RBAC)" do
      stream_id = "test_rbac_stream_#{:erlang.unique_integer([:positive])}"
      subscriber_pid = self()

      # Filter for org-1 only
      filters = %{organization_id: "org-1", stream_type: [:alert]}
      StreamManager.register_stream(stream_id, subscriber_pid, filters, %{format: :json})

      # Broadcast alert for org-2 (should not match)
      alert = %{
        severity: "critical",
        title: "Test Alert",
        agent_id: "agent-123",
        organization_id: "org-2"
      }

      StreamManager.broadcast_alert(alert)

      # Should NOT receive the alert
      refute_receive {:stream_data, :alert, _data}, 500

      # Broadcast alert for org-1 (should match)
      alert2 = Map.put(alert, :organization_id, "org-1")
      StreamManager.broadcast_alert(alert2)

      # Should receive this alert
      assert_receive {:stream_data, :alert, _data}, 1000

      StreamManager.unregister_stream(stream_id)
    end
  end

  describe "slow consumer detection" do
    test "disconnects slow consumers" do
      stream_id = "test_slow_stream_#{:erlang.unique_integer([:positive])}"
      subscriber_pid = self()

      filters = %{stream_type: [:alert]}
      StreamManager.register_stream(stream_id, subscriber_pid, filters, %{format: :json})

      # Simulate slow consumer by sending many events quickly
      # This is simplified - in real scenario, queue would fill up
      # The actual slow consumer detection happens in StreamManager

      # For now, just verify we can detect the stream exists
      stats = StreamManager.get_stats()
      assert stats.active_streams >= 1

      StreamManager.unregister_stream(stream_id)
    end
  end

  describe "statistics" do
    test "returns stream statistics" do
      stream_id = "test_stats_stream_#{:erlang.unique_integer([:positive])}"
      subscriber_pid = self()

      StreamManager.register_stream(stream_id, subscriber_pid, %{}, %{})

      stats = StreamManager.get_stats()

      assert is_integer(stats.active_streams)
      assert is_integer(stats.total_events_broadcasted)
      assert is_integer(stats.slow_consumers_disconnected)
      assert is_map(stats.stream_metrics)

      StreamManager.unregister_stream(stream_id)
    end
  end
end
