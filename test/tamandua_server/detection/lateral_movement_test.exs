defmodule TamanduaServer.Detection.LateralMovementTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.LateralMovement

  describe "extract_lateral_movement/1" do
    test "propagates source event id and dedup key from network events" do
      event_id = "550e8400-e29b-41d4-a716-446655440000"

      attrs =
        LateralMovement.extract_lateral_movement(%{
          event_type: "network_connect",
          event_id: event_id,
          dedup_key: "network:agent-1:10.0.0.20",
          agent_id: "agent-1",
          timestamp: ~U[2026-07-13 12:00:00Z],
          payload: %{
            local_ip: "10.0.0.10",
            remote_ip: "10.0.0.20",
            remote_port: 445,
            username: "alice"
          }
        })

      assert attrs.event_id == event_id
      assert attrs.dedup_key == "network:agent-1:10.0.0.20"
      assert attrs.source_ip == "10.0.0.10"
      assert attrs.dest_ip == "10.0.0.20"
      assert attrs.protocol == "smb"
    end

    test "uses payload event id when top-level id is absent" do
      event_id = "550e8400-e29b-41d4-a716-446655440001"

      attrs =
        LateralMovement.extract_lateral_movement(%{
          "event_type" => "authentication",
          "agent_id" => "agent-1",
          "payload" => %{
            "event_id" => event_id,
            "source_ip" => "10.0.0.11",
            "dest_ip" => "10.0.0.21",
            "logon_type" => 10
          }
        })

      assert attrs.event_id == event_id
      assert attrs.protocol == "rdp"
    end
  end
end
