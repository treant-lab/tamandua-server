defmodule TamanduaServer.Alerts.AutoInvestigationMobileTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Mobile.{DeviceV2, MDMCommand}

  describe "mobile auto-investigation" do
    test "queues MDMCommand when a DeviceV2 row is resolved" do
      {org, agent} =
        create_agent_with_org(%{
          os_type: "android",
          machine_id: "android-auto-investigation-1",
          config: %{"source" => "tamandua_mobile"}
        })

      device =
        Repo.insert!(%DeviceV2{
          organization_id: org.id,
          device_id: "android-auto-investigation-1",
          device_name: "Pixel 8",
          platform: "android",
          mdm_enrolled: true,
          mdm_provider: "tamandua_mobile"
        })

      {:ok, alert} =
        Alerts.create_alert(%{
          organization_id: org.id,
          agent_id: agent.id,
          severity: "high",
          title: "Mobile DNS exfiltration",
          description: "High confidence mobile alert missing investigation context",
          threat_score: 0.91,
          detection_metadata: %{
            "platform" => "android",
            "source" => "app_guard",
            "event_type" => "dns_query",
            "mobile_device_id" => device.device_id
          },
          evidence: %{"dns" => %{"query" => "wallet-drain.example"}},
          raw_event: %{"payload" => %{"platform" => "android", "device_id" => device.device_id}}
        })

      assert eventually(fn ->
               MDMCommand
               |> where([c], c.organization_id == ^org.id and c.device_id == ^device.id)
               |> Repo.all()
             end, &(&1 != []))

      commands =
        MDMCommand
        |> where([c], c.organization_id == ^org.id and c.device_id == ^device.id)
        |> Repo.all()

      assert Enum.all?(commands, &(&1.requested_by == "auto_investigation"))
      assert Enum.all?(commands, &(get_in(&1.payload || %{}, ["alert_id"]) == alert.id))
      assert Enum.any?(commands, &(&1.command_type == "collect_diagnostics"))
      assert Enum.any?(commands, &(&1.command_type == "list_network_flows"))

      updated_alert = Repo.get!(Alert, alert.id)
      plan = get_in(updated_alert.detection_metadata, ["investigation_enrichment"])

      assert plan["status"] == "mobile_requested"
      assert Enum.all?(plan["queued_commands"], &(&1["runtime"] == "mobile_mdm"))
      assert Enum.any?(plan["queued_commands"], &(&1["status"] == "queued"))
    end

    test "marks capability_degraded when a mobile alert cannot resolve DeviceV2" do
      {org, agent} =
        create_agent_with_org(%{
          os_type: "android",
          machine_id: "android-missing-device",
          config: %{"source" => "tamandua_mobile"}
        })

      {:ok, alert} =
        Alerts.create_alert(%{
          organization_id: org.id,
          agent_id: agent.id,
          severity: "high",
          title: "Mobile app integrity alert",
          description: "High confidence mobile alert without DeviceV2 mapping",
          threat_score: 0.82,
          detection_metadata: %{
            "platform" => "android",
            "source" => "app_guard",
            "mobile_device_id" => "missing-device"
          },
          evidence: %{"app" => %{"package_or_bundle_id" => "com.example.wallet"}},
          raw_event: %{"payload" => %{"platform" => "android", "device_id" => "missing-device"}}
        })

      assert eventually(fn ->
               alert = Repo.get!(Alert, alert.id)
               get_in(alert.detection_metadata, ["investigation_enrichment", "status"])
             end, &(&1 == "capability_degraded"))

      refute Repo.get_by(MDMCommand, organization_id: org.id)

      updated_alert = Repo.get!(Alert, alert.id)
      plan = get_in(updated_alert.detection_metadata, ["investigation_enrichment"])

      assert plan["error"] == "mobile_device_not_resolved"
      assert [
               %{
                 "runtime" => "mobile_mdm",
                 "status" => "capability_degraded",
                 "reason" => "mobile_device_not_resolved"
               }
             ] = plan["queued_commands"]

      assert get_in(updated_alert.enrichment, ["auto_investigation", "status"]) == "capability_degraded"
    end
  end

  defp eventually(fun, predicate, attempts \\ 20)

  defp eventually(fun, predicate, attempts) when attempts > 0 do
    value = fun.()

    if predicate.(value) do
      true
    else
      Process.sleep(25)
      eventually(fun, predicate, attempts - 1)
    end
  end

  defp eventually(fun, predicate, 0), do: predicate.(fun.())
end
