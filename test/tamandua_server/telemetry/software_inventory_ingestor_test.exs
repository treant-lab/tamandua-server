defmodule TamanduaServer.Telemetry.SoftwareInventoryIngestorTest do
  use TamanduaServer.DataCase, async: false

  import Ecto.Query

  alias Broadway.Message
  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.Ingestor

  describe "software inventory projection" do
    test "accepts direct software payloads and nested software payloads" do
      {_org, agent} = create_agent_with_org()

      direct =
        ingest(%{
          "agent_id" => agent.id,
          "event_type" => "software_inventory",
          "payload" => %{
            "name" => "OpenSSL",
            "version" => "1.1.1k",
            "vendor" => "OpenSSL"
          }
        })

      assert direct[:processed_at]

      direct_list =
        ingest(%{
          "agent_id" => agent.id,
          "event_type" => "software_inventory",
          "payload" => [
            %{
              "name" => "curl",
              "version" => "8.7.1",
              "vendor" => "curl"
            }
          ]
        })

      assert direct_list[:processed_at]

      nested_map =
        ingest(%{
          "agent_id" => agent.id,
          "event_type" => "software_install",
          "payload" => %{
            "software" => %{
              "name" => "Git",
              "version" => "2.45.0",
              "vendor" => "Git"
            }
          }
        })

      assert nested_map[:processed_at]

      nested_list =
        ingest(%{
          agent_id: agent.id,
          event_type: :software_change,
          payload: %{
            software: [
              %{
                name: "Node.js",
                version: "20.11.1",
                vendor: "OpenJS"
              }
            ]
          }
        })

      assert nested_list[:processed_at]

      rows =
        Repo.all(
          from s in "software_inventory",
            where: s.agent_id == ^agent.id,
            select: {s.name, s.version, s.vendor, s.organization_id}
        )

      assert {"OpenSSL", "1.1.1k", "OpenSSL", agent.organization_id} in rows
      assert {"curl", "8.7.1", "curl", agent.organization_id} in rows
      assert {"Git", "2.45.0", "Git", agent.organization_id} in rows
      assert {"Node.js", "20.11.1", "OpenJS", agent.organization_id} in rows

      snapshot =
        ingest(%{
          "agent_id" => agent.id,
          "event_type" => "software_inventory",
          "payload" => %{
            "inventory_scope" => "full",
            "snapshot_complete" => true,
            "software" => [
              %{
                "name" => "OpenSSL",
                "version" => "1.1.1k",
                "vendor" => "OpenSSL"
              }
            ]
          }
        })

      assert snapshot[:processed_at]

      assert %{installed: false, removed_at: snapshot_removed_at} =
               Repo.one!(
                 from s in "software_inventory",
                   where: s.agent_id == ^agent.id and s.name == "Git" and s.version == "2.45.0",
                   select: %{installed: s.installed, removed_at: s.removed_at}
               )

      assert snapshot_removed_at

      uninstall =
        ingest(%{
          "agent_id" => agent.id,
          "event_type" => "software_uninstall",
          "payload" => %{
            "name" => "curl",
            "version" => "8.7.1",
            "vendor" => "curl"
          }
        })

      assert uninstall[:processed_at]

      assert %{installed: false, removed_at: removed_at} =
               Repo.one!(
                 from s in "software_inventory",
                   where: s.agent_id == ^agent.id and s.name == "curl" and s.version == "8.7.1",
                   select: %{installed: s.installed, removed_at: s.removed_at}
               )

      assert removed_at
    end
  end

  defp ingest(event) do
    message = %Message{
      data: event,
      acknowledger: {Broadway.NoopAcknowledger, nil, nil}
    }

    assert %Message{data: normalized} = Ingestor.handle_message(:default, message, %{})
    normalized
  end
end
