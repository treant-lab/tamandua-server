defmodule TamanduaServer.Telemetry.HuntSearchTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Telemetry

  describe "hunt_search/4 simple field contract" do
    test "process.name matches the real process_name payload field" do
      {org, agent} = create_agent_with_org()

      matching =
        insert!(:event, %{
          agent: agent,
          organization_id: org.id,
          event_type: "process_create",
          payload: %{
            "process_name" => "powershell.exe",
            "name" => "legacy-name.exe"
          }
        })

      insert!(:event, %{
        agent: agent,
        organization_id: org.id,
        event_type: "process_create",
        payload: %{
          "process_name" => "cmd.exe",
          "name" => "powershell.exe"
        }
      })

      results =
        Telemetry.hunt_search("process.name:powershell.exe", "24h", 10,
          organization_id: org.id
        )

      assert Enum.map(results, & &1.id) == [matching.id]
    end

    test "regex operator filters payload text with :~ syntax" do
      {org, agent} = create_agent_with_org()

      matching =
        insert!(:event, %{
          agent: agent,
          organization_id: org.id,
          event_type: "dns_query",
          payload: %{"query" => "beacon.example.xyz"}
        })

      insert!(:event, %{
        agent: agent,
        organization_id: org.id,
        event_type: "dns_query",
        payload: %{"query" => "updates.example.com"}
      })

      results =
        Telemetry.hunt_search(~S(dns.query:~.*\.(xyz|top)$), "24h", 10,
          organization_id: org.id
        )

      assert Enum.map(results, & &1.id) == [matching.id]
    end
  end
end
