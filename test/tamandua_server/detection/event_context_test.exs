defmodule TamanduaServer.Detection.EventContextTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.EventContext

  test "normalizes collector and profile context from event payload" do
    context =
      EventContext.build(%{
        event_type: "network_connect",
        payload: %{
          "collector" => "network-dpi",
          "performance_profile" => "high_value_asset",
          "src_ip" => "10.0.0.10",
          "dest_ip" => "10.0.0.20",
          "protocol" => "tcp"
        }
      })

    assert context.event_type == "network_connect"
    assert context.family == "network"
    assert context.collector == "network_dpi"
    assert context.profile == "high_value_asset"
    assert context.quality == 1.0
    assert context.risk_multiplier > 1.0
  end

  test "penalizes low quality lightweight telemetry without dropping context" do
    context =
      EventContext.build(%{
        "event_type" => "process_create",
        "profile" => "lightweight",
        "payload" => %{"process_name" => "cmd.exe"}
      })

    assert context.collector == "process"
    assert context.profile == "lightweight"
    assert "pid" in context.missing_fields
    assert "command_line" in context.missing_fields
    assert context.quality < 1.0
    assert context.risk_multiplier < 1.0
  end

  test "attaches context for the engine without changing public event fields" do
    event = %{event_type: "dns_query", payload: %{"query" => "example.com"}}

    attached = EventContext.attach(event)

    assert attached.event_type == "dns_query"
    assert attached.payload == event.payload
    assert attached._detection_context.collector == "dns"
  end
end
