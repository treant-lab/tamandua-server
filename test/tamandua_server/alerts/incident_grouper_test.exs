defmodule TamanduaServer.Alerts.IncidentGrouperTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Alerts.{Alert, IncidentGrouper}

  describe "assign_incident_metadata/2" do
    test "groups same hash and process lineage on the same host inside the time window" do
      {org, agent} = create_agent_with_org()

      sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

      base_attrs = %{
        organization_id: org.id,
        agent_id: agent.id,
        severity: "high",
        evidence: %{
          "process" => %{
            "name" => "powershell.exe",
            "pid" => 4242,
            "ppid" => 1000,
            "sha256" => sha256
          }
        },
        process_chain: [
          %{"name" => "explorer.exe", "pid" => 1000, "ppid" => 512},
          %{"name" => "powershell.exe", "pid" => 4242, "ppid" => 1000}
        ]
      }

      {:ok, yara_alert} =
        base_attrs
        |> Map.merge(%{
          title: "YARA malware match",
          detection_metadata: %{"rule_type" => "yara", "rule_name" => "MalwareRule"}
        })
        |> IncidentGrouper.assign_incident_metadata(window_seconds: 3600)
        |> insert_alert()

      {:ok, ml_alert} =
        base_attrs
        |> Map.merge(%{
          title: "ML malicious binary",
          detection_metadata: %{"rule_type" => "ml", "rule_name" => "OfflineModel"}
        })
        |> IncidentGrouper.assign_incident_metadata(window_seconds: 3600)
        |> insert_alert()

      incident_key = get_in(yara_alert.correlation_data, ["incident_key"])

      assert is_binary(incident_key)
      assert get_in(ml_alert.correlation_data, ["incident_key"]) == incident_key
      assert ml_alert.storyline_id == incident_key
      assert get_in(ml_alert.correlation_data, ["incident_components", "hash"]) == sha256
    end

    test "does not group same hash across different hosts" do
      {org, agent1} = create_agent_with_org()
      agent2 = insert!(:agent, organization: org)
      sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

      attrs = fn agent ->
        %{
          organization_id: org.id,
          agent_id: agent.id,
          title: "Same hash",
          severity: "medium",
          evidence: %{"process" => %{"name" => "payload.exe", "sha256" => sha256}}
        }
      end

      {:ok, first} =
        agent1
        |> attrs.()
        |> IncidentGrouper.assign_incident_metadata()
        |> insert_alert()

      {:ok, second} =
        agent2
        |> attrs.()
        |> IncidentGrouper.assign_incident_metadata()
        |> insert_alert()

      refute get_in(first.correlation_data, ["incident_key"]) ==
               get_in(second.correlation_data, ["incident_key"])
    end
  end

  defp insert_alert(attrs) do
    %Alert{}
    |> Alert.changeset(attrs)
    |> Repo.insert()
  end
end
