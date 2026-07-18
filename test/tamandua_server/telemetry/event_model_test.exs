defmodule TamanduaServer.Telemetry.EventModelTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Telemetry.EventModel

  test "validates the minimum v1 envelope" do
    envelope = %{
      schema_version: EventModel.version(),
      routing: %{
        tenant_id: "org-1",
        agent_id: "agent-1",
        platform: "linux",
        collector_id: "process",
        event_type: "process_start",
        observed_at: "2026-07-13T12:00:00Z",
        ingested_at: "2026-07-13T12:00:01Z"
      },
      event: %{category: "process", action: "start", outcome: "success"}
    }

    assert :ok = EventModel.validate(envelope)
    assert EventModel.descriptor().schema == "schemas/event_envelope_v1.schema.json"
  end

  test "reports stable field paths" do
    assert {:error, errors} =
             EventModel.validate(%{schema_version: "v0", routing: %{}, event: %{outcome: "maybe"}})

    assert %{path: "schema_version", reason: "unsupported"} in errors
    assert %{path: "routing.tenant_id", reason: "required"} in errors
    assert %{path: "event.category", reason: "required"} in errors
    assert %{path: "event.outcome", reason: "invalid"} in errors
  end
end
