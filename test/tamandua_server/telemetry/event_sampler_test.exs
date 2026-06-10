defmodule TamanduaServer.Telemetry.EventSamplerTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Telemetry.EventSampler

  describe "high_value_event?/1" do
    test "identifies process creation as high-value" do
      event = %{event_type: "process_creation", severity: "info"}
      assert EventSampler.high_value_event?(event)
    end

    test "identifies network connection as high-value" do
      event = %{event_type: "network_connection", severity: "info"}
      assert EventSampler.high_value_event?(event)
    end

    test "identifies file modification as high-value" do
      event = %{event_type: "file_modification", severity: "info"}
      assert EventSampler.high_value_event?(event)
    end

    test "identifies events with detections as high-value" do
      event = %{
        event_type: "file_read",
        severity: "info",
        detections: [%{rule: "test", score: 0.9}]
      }

      assert EventSampler.high_value_event?(event)
    end

    test "identifies high severity events as high-value" do
      event = %{event_type: "dns_query", severity: "critical"}
      assert EventSampler.high_value_event?(event)
    end

    test "identifies events with alerts as high-value" do
      event = %{
        event_type: "file_read",
        severity: "info",
        enrichment: %{
          analysis: %{
            alerts: [%{id: "alert-123"}]
          }
        }
      }

      assert EventSampler.high_value_event?(event)
    end

    test "identifies DNS to suspicious TLD as high-value" do
      event = %{
        event_type: "dns_query",
        severity: "info",
        payload: %{query: "malware.tk"}
      }

      assert EventSampler.high_value_event?(event)
    end

    test "identifies DGA-like DNS as high-value" do
      event = %{
        event_type: "dns_query",
        severity: "info",
        payload: %{query: "xj8f92hf82hf928hf92h8f9h2.com"}
      }

      assert EventSampler.high_value_event?(event)
    end

    test "identifies connection to unusual port as high-value" do
      event = %{
        event_type: "network_connection",
        severity: "info",
        payload: %{remote_port: 4444}
      }

      assert EventSampler.high_value_event?(event)
    end

    test "identifies low-value DNS query" do
      event = %{
        event_type: "dns_query",
        severity: "info",
        payload: %{query: "google.com"}
      }

      refute EventSampler.high_value_event?(event)
    end

    test "identifies low-value file read" do
      event = %{
        event_type: "file_read",
        severity: "info"
      }

      refute EventSampler.high_value_event?(event)
    end

    test "identifies low-value system health" do
      event = %{
        event_type: "system_health",
        severity: "info"
      }

      refute EventSampler.high_value_event?(event)
    end
  end

  describe "sample_events/2" do
    test "splits events into keep and drop based on sampling rate" do
      events =
        for i <- 1..100 do
          %{
            id: "event-#{i}",
            event_type: "file_read",
            severity: "info"
          }
        end

      {to_keep, to_drop} = EventSampler.sample_events(events, 0.1)

      # Should be approximately 10% kept (deterministic sampling may vary)
      assert length(to_keep) + length(to_drop) == 100
      assert length(to_keep) > 0
      assert length(to_drop) > 0
      # Allow for variance in hash-based sampling
      assert length(to_keep) >= 5 and length(to_keep) <= 20
    end

    test "sampling is deterministic based on event ID" do
      events =
        for i <- 1..50 do
          %{
            id: "event-#{i}",
            event_type: "file_read",
            severity: "info"
          }
        end

      {to_keep1, to_drop1} = EventSampler.sample_events(events, 0.1)
      {to_keep2, to_drop2} = EventSampler.sample_events(events, 0.1)

      # Same events should always get same decision
      assert MapSet.new(to_keep1, & &1.id) == MapSet.new(to_keep2, & &1.id)
      assert MapSet.new(to_drop1, & &1.id) == MapSet.new(to_drop2, & &1.id)
    end

    test "keeps all events with 100% sampling rate" do
      events =
        for i <- 1..50 do
          %{id: "event-#{i}", event_type: "file_read", severity: "info"}
        end

      {to_keep, to_drop} = EventSampler.sample_events(events, 1.0)

      assert length(to_keep) == 50
      assert length(to_drop) == 0
    end

    test "drops all events with 0% sampling rate" do
      events =
        for i <- 1..50 do
          %{id: "event-#{i}", event_type: "file_read", severity: "info"}
        end

      {to_keep, to_drop} = EventSampler.sample_events(events, 0.0)

      assert length(to_keep) == 0
      assert length(to_drop) == 50
    end
  end

  describe "should_keep_event?/2" do
    test "deterministically keeps or drops based on event ID" do
      event = %{id: "test-event-123", event_type: "file_read"}

      # Same event should always get same result
      result1 = EventSampler.should_keep_event?(event, 0.5)
      result2 = EventSampler.should_keep_event?(event, 0.5)

      assert result1 == result2
    end

    test "handles events without ID gracefully" do
      event = %{event_type: "file_read"}

      # Should not crash, uses random sampling
      result = EventSampler.should_keep_event?(event, 0.5)
      assert is_boolean(result)
    end
  end
end
