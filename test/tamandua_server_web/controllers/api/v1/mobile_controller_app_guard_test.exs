defmodule TamanduaServerWeb.Controllers.API.V1.MobileControllerAppGuardTest do
  use TamanduaServerWeb.ConnCase, async: false

  import Ecto.Query
  import TamanduaServer.Factory

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Accounts.{Permission, Role, RolePermission, UserRole}
  alias TamanduaServer.Mobile
  alias TamanduaServer.Mobile.DeviceV2
  alias TamanduaServer.Mobile.MDMCommand
  alias TamanduaServer.Mobile.MobileEvent
  alias TamanduaServer.Repo

  setup %{conn: conn} do
    put_app_guard_unsigned_compatibility(true)

    {org_a, _agent_a} = create_agent_with_org()
    user_a = insert!(:user, %{organization: org_a, role: "admin"})
    grant_permission!(user_a, org_a, :response_isolate)
    {:ok, token_a, _claims} = TamanduaServer.Guardian.encode_and_sign(user_a)

    {other_org, _agent_b} = create_agent_with_org()
    user_b = insert!(:user, %{organization: other_org, role: "admin"})
    grant_permission!(user_b, other_org, :response_isolate)
    {:ok, token_b, _claims} = TamanduaServer.Guardian.encode_and_sign(user_b)

    %{
      conn_a: put_req_header(conn, "authorization", "Bearer #{token_a}"),
      conn_b: put_req_header(conn, "authorization", "Bearer #{token_b}"),
      token_a: token_a,
      token_b: token_b,
      org_a: org_a
    }
  end

  describe "mobile configuration" do
    test "returns persisted per-organization config merged with defaults", %{conn_a: conn} do
      update_body = %{
        "agent" => %{"heartbeat_interval_seconds" => 45},
        "security" => %{"detect_debugger" => false},
        "network" => %{"blocklist_domains" => ["example.test"]}
      }

      update_conn = put(conn, "/api/v1/mobile/config", update_body)
      assert json_response(update_conn, 200)["success"] == true

      conn = get(conn, "/api/v1/mobile/config")
      body = json_response(conn, 200)["data"]

      assert body["agent"]["heartbeat_interval_seconds"] == 45
      assert body["agent"]["event_batch_size"] == 50
      assert body["security"]["detect_debugger"] == false
      assert body["security"]["detect_root"] == true
      assert body["network"]["blocklist_domains"] == ["example.test"]
      assert body["collection"]["collect_device_info"] == true
    end
  end

  describe "mobile agent web overview" do
    test "resolves the mobile device linked to an endpoint agent", %{conn_a: conn, org_a: org} do
      {:ok, device} =
        Mobile.register_device(%{
          "organization_id" => org.id,
          "device_id" => "android-web-overview-1",
          "platform" => "android",
          "model" => "Pixel 8",
          "os_version" => "15",
          "agent_version" => "1.2.3",
          "passcode_enabled" => true,
          "encryption_enabled" => true
        })

      {:ok, _sync} =
        Mobile.sync_device_apps(device.id, [
          %{
            "bundle_id" => "com.example.wallet",
            "app_name" => "Example Wallet",
            "version" => "2.0.0",
            "installer" => "sideload",
            "permissions" => ["android.permission.SYSTEM_ALERT_WINDOW"],
            "risk_level" => "high"
          }
        ])

      command_device =
        Repo.insert!(%TamanduaServer.Mobile.DeviceV2{
          organization_id: org.id,
          device_id: "android-web-overview-1",
          device_name: "Pixel 8",
          platform: "android",
          mdm_enrolled: true,
          mdm_provider: "tamandua_mobile"
        })

      older_command =
        Repo.insert!(%MDMCommand{
          organization_id: org.id,
          device_id: command_device.id,
          command_type: "locate",
          status: "completed",
          payload: %{"precision" => "coarse"},
          result: %{"location" => "operator-confirmed"},
          requested_by: "operator@example.test",
          inserted_at: ~U[2026-07-05 10:00:00.000000Z],
          updated_at: ~U[2026-07-05 10:01:00.000000Z]
        })

      latest_command =
        Repo.insert!(%MDMCommand{
          organization_id: org.id,
          device_id: command_device.id,
          command_type: "ring",
          status: "failed",
          payload: %{},
          result: %{"reason" => "unsupported_on_mobile_app_endpoint"},
          requested_by: "operator@example.test",
          inserted_at: ~U[2026-07-05 10:05:00.000000Z],
          updated_at: ~U[2026-07-05 10:06:00.000000Z]
        })

      agent = Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-web-overview-1")

      conn = get(conn, "/api/v1/mobile/agents/#{agent.id}/overview")
      body = json_response(conn, 200)["data"]

      assert body["mobile"] == true
      assert body["linked"] == true
      assert body["device"]["id"] == device.id
      assert body["command_device"]["id"] == command_device.id
      assert body["command_device"]["device_id"] == "android-web-overview-1"
      assert body["last_command"]["id"] == latest_command.id
      assert body["last_command"]["status"] == "failed"

      assert Enum.map(body["command_history"], & &1["id"]) == [
               latest_command.id,
               older_command.id
             ]

      assert body["command_history"] |> List.last() |> Map.get("result") == %{
               "location" => "operator-confirmed"
             }

      assert body["posture"]["risk_score"] == device.risk_score
      assert [%{"bundle_id" => "com.example.wallet"}] = body["app_inventory"]["apps"]
      assert body["app_inventory"]["total"] == 1
      assert body["app_inventory"]["high_risk"] == 1
      assert body["app_inventory"]["sideloaded"] == 1
      assert body["app_guard"]["total_recent_events"] == 0
      assert is_list(body["app_guard"]["protected_apps"])
      assert body["app_guard"]["readiness"]["status"] == "missing_protected_app"
      assert "no_recent_app_guard_events" in body["app_guard"]["readiness"]["gaps"]
      assert body["app_guard"]["readiness"]["claim_boundary"] =~ "does not prove binary shielding"
      assert Enum.map(body["commands"], & &1["id"]) == ["locate", "lock", "wipe"]

      assert Enum.find(body["commands"], &(&1["id"] == "locate"))["execution_scope"] ==
               "mobile_app_endpoint"

      assert Enum.find(body["commands"], &(&1["id"] == "lock"))["execution_scope"] ==
               "mdm_provider"

      assert Enum.find(body["commands"], &(&1["id"] == "lock"))["command_risk"] ==
               "privileged_device_action"

      assert Enum.find(body["commands"], &(&1["id"] == "wipe"))["supported_by_mobile_app"] ==
               false

      assert Enum.find(body["commands"], &(&1["id"] == "wipe"))["command_risk"] ==
               "destructive_device_action"

      assert "Auditable operator approval for destructive actions" in Enum.find(
               body["commands"],
               &(&1["id"] == "wipe")
             )["requirements"]
    end

    test "returns unlinked overview when an agent has no mobile identifier", %{
      conn_a: conn,
      org_a: org
    } do
      agent = insert!(:agent, %{organization: org, machine_id: nil, config: %{}})

      conn = get(conn, "/api/v1/mobile/agents/#{agent.id}/overview")
      body = json_response(conn, 200)["data"]

      assert body["agent_id"] == agent.id
      assert body["linked"] == false
      assert body["device"] == nil
    end

    test "provisions a command device from explicit v2 mobile agent identity", %{
      conn_a: conn,
      org_a: org
    } do
      agent =
        insert!(:agent, %{
          organization: org,
          os_type: "unknown",
          machine_id: nil,
          tags: ["mobile-v2"],
          config: %{
            "source" => "tamandua_mobile_v2",
            "device" => %{"device_id" => "android-managed-nested-1"},
            "model" => "Managed Android"
          }
        })

      conn = get(conn, "/api/v1/mobile/agents/#{agent.id}/overview")
      body = json_response(conn, 200)["data"]
      reloaded_agent = Repo.get!(Agent, agent.id)

      assert body["mobile"] == true
      assert body["linked"] == true
      assert body["command_device"]["device_id"] == "android-managed-nested-1"
      assert body["command_device"]["agent_id"] == agent.id
      assert body["command_device"]["device_name"] == "Managed Android"
      assert body["command_device"]["mdm_provider"] == "tamandua_endpoint"
      assert body["link_status"]["reason"] == "linked"
      assert reloaded_agent.machine_id == "android-managed-nested-1"
      assert Repo.aggregate(from(a in Agent, where: a.organization_id == ^org.id), :count) == 1
    end

    test "provisions overview link from mobile endpoint tag and machine id", %{
      conn_a: conn,
      org_a: org
    } do
      agent =
        insert!(:agent, %{
          organization: org,
          os_type: "unknown",
          machine_id: "android-tagged-endpoint-1",
          hostname: "Tagged Android",
          tags: ["mobile_endpoint"],
          config: %{
            "model" => "Tagged Android",
            "capabilities" => %{"app_guard" => true},
            "posture" => %{
              "risk_score" => 42,
              "security_checks" => %{"frida_detected" => false}
            }
          }
        })

      conn = get(conn, "/api/v1/mobile/agents/#{agent.id}/overview")
      body = json_response(conn, 200)["data"]
      reloaded_agent = Repo.get!(Agent, agent.id)

      assert body["mobile"] == true
      assert body["linked"] == true
      assert body["command_device"]["device_id"] == "android-tagged-endpoint-1"
      assert body["command_device"]["agent_id"] == agent.id
      assert body["device"]["device_name"] == "Tagged Android"
      assert body["device"]["capabilities"]["app_guard"] == true
      assert body["posture"]["risk_score"] == 42
      assert body["posture"]["security_checks"]["frida_detected"] == false
      assert body["link_status"]["reason"] == "linked"
      assert reloaded_agent.config["source"] == "tamandua_mobile_v2"
      assert reloaded_agent.config["mobile_device_external_id"] == "android-tagged-endpoint-1"
    end

    test "projects mobile events and timeline when filtered by linked agent id", %{
      conn_a: conn,
      org_a: org
    } do
      {:ok, device} =
        Mobile.register_device(%{
          "organization_id" => org.id,
          "device_id" => "android-agent-filter-1",
          "platform" => "android",
          "model" => "Pixel Filter"
        })

      agent = Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-agent-filter-1")

      {:ok, event} =
        Mobile.ingest_event(%{
          device_id: device.id,
          organization_id: org.id,
          event_type: "tampering_detected",
          severity: "medium",
          timestamp: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second),
          payload: %{
            "schema" => "tamandua.app_guard.event/v1",
            "app" => %{"package_or_bundle_id" => "io.tamandua.appguard.samplewallet"}
          }
        })

      events_conn = get(conn, "/api/v1/events?agent_id=#{agent.id}&limit=10")
      events = json_response(events_conn, 200)["data"]

      assert Enum.any?(events, fn row ->
               row["id"] == event.id and row["agent_id"] == agent.id and
                 row["payload"]["mobile_device_id"] == "android-agent-filter-1"
             end)

      timeline_conn = get(conn, "/api/v1/timeline?agent_ids=#{agent.id}&limit=10")
      timeline = json_response(timeline_conn, 200)["data"]

      projected_row =
        Enum.find(timeline, fn row ->
          row["id"] == event.id and row["agentId"] == agent.id and
            row["details"]["mobile_device_id"] == "android-agent-filter-1"
        end)

      assert projected_row
      assert projected_row["entities"] == %{}
      assert projected_row["telemetryQuality"]["level"] == "good"
      assert projected_row["telemetryQuality"]["present"] == ["mobile_event"]
      assert projected_row["telemetryQuality"]["missing"] == []
      assert projected_row["telemetryContract"]["schemaVersion"] == "tamandua.mobile.event/v1"
      assert projected_row["telemetryContract"]["correlationReady"] == true
      assert projected_row["telemetryContract"]["requiredFields"] == []
    end

    test "rejects host-only response surfaces for mobile agent mirrors", %{
      conn_a: conn,
      org_a: org
    } do
      {:ok, _device} =
        Mobile.register_device(%{
          "organization_id" => org.id,
          "device_id" => "android-host-action-1",
          "platform" => "android",
          "model" => "Pixel Host Action"
        })

      agent = Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-host-action-1")

      isolate_conn = post(conn, "/api/v1/agents/#{agent.id}/isolate", %{})
      isolate_body = json_response(isolate_conn, 422)
      assert isolate_body["platform"] == "mobile"
      assert isolate_body["supported_surface"] == "mobile endpoint commands"

      live_conn = post(conn, "/api/v1/live-response/sessions", %{"agent_id" => agent.id})
      live_body = json_response(live_conn, 422)
      assert live_body["platform"] == "mobile"
      assert live_body["supported_surface"] == "mobile endpoint commands"

      token_conn = post(conn, "/api/v1/live-response/#{agent.id}/cli-token", %{})
      token_body = json_response(token_conn, 422)
      assert token_body["platform"] == "mobile"
      assert token_body["supported_surface"] == "mobile endpoint commands"
    end

    test "rejects host-only response surfaces for v2 mobile agents with unknown os", %{
      conn_a: conn,
      org_a: org
    } do
      agent =
        insert!(:agent, %{
          organization: org,
          os_type: "unknown",
          machine_id: nil,
          tags: ["mobile-v2"],
          config: %{
            "source" => "tamandua_mobile_v2",
            "device" => %{"device_id" => "android-v2-host-action-unknown-os-1"}
          }
        })

      isolate_conn = post(conn, "/api/v1/agents/#{agent.id}/isolate", %{})
      isolate_body = json_response(isolate_conn, 422)

      assert isolate_body["platform"] == "mobile"
      assert isolate_body["supported_surface"] == "mobile endpoint commands"

      live_conn = post(conn, "/api/v1/live-response/sessions", %{"agent_id" => agent.id})
      live_body = json_response(live_conn, 422)

      assert live_body["platform"] == "mobile"
      assert live_body["supported_surface"] == "mobile endpoint commands"
    end

    test "device event listing preserves linked agent context", %{conn_a: conn, org_a: org} do
      {:ok, device} =
        Mobile.register_device(%{
          "organization_id" => org.id,
          "device_id" => "android-device-events-linked-1",
          "platform" => "android",
          "model" => "Pixel Event Link"
        })

      agent =
        Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-device-events-linked-1")

      {:ok, event} =
        Mobile.ingest_event(%{
          device_id: device.id,
          organization_id: org.id,
          event_type: "debugger_detected",
          severity: "medium",
          timestamp: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second),
          payload: %{
            "schema" => "tamandua.app_guard.event/v1",
            "event_id" => "evt-device-event-linked-1",
            "app" => %{"package_or_bundle_id" => "io.tamandua.appguard.samplewallet"}
          }
        })

      events_conn = get(conn, "/api/v1/mobile/devices/#{device.id}/events?limit=5")
      events = json_response(events_conn, 200)["data"]

      row = Enum.find(events, &(&1["id"] == event.id))
      assert row["agent_id"] == agent.id
      assert row["agentId"] == agent.id
      assert row["hostname"] == "Pixel Event Link"
      assert row["device"]["device_id"] == "android-device-events-linked-1"
    end

    test "rejects mobile agent isolation before host-only RBAC checks", %{org_a: org} do
      analyst = insert!(:user, %{organization: org, role: "analyst"})
      {:ok, analyst_token, _claims} = TamanduaServer.Guardian.encode_and_sign(analyst)

      {:ok, _device} =
        Mobile.register_device(%{
          "organization_id" => org.id,
          "device_id" => "android-host-action-no-rbac-1",
          "platform" => "android",
          "model" => "Pixel Host Action No RBAC"
        })

      agent =
        Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-host-action-no-rbac-1")

      conn =
        auth_conn(analyst_token)
        |> post("/api/v1/agents/#{agent.id}/isolate", %{})

      body = json_response(conn, 422)
      assert body["platform"] == "mobile"
      assert body["supported_surface"] == "mobile endpoint commands"
    end

    test "keeps recently checked-in mobile mirrors online without a host worker", %{
      conn_a: conn,
      org_a: org
    } do
      ten_minutes_ago =
        NaiveDateTime.utc_now()
        |> NaiveDateTime.truncate(:second)
        |> NaiveDateTime.add(-10 * 60, :second)

      {:ok, _device} =
        Mobile.register_device(%{
          "organization_id" => org.id,
          "device_id" => "android-agent-list-status-1",
          "platform" => "android",
          "model" => "Pixel Agent List"
        })

      mobile_agent =
        Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-agent-list-status-1")

      mobile_agent
      |> Ecto.Changeset.change(%{status: "online", last_seen_at: ten_minutes_ago})
      |> Repo.update!()

      desktop_agent =
        insert!(:agent, %{
          organization: org,
          hostname: "stale-desktop-agent",
          os_type: "windows",
          status: "online",
          last_seen_at: ten_minutes_ago
        })

      assert {:ok, count} = Agents.mark_stale_online_agents_offline([], 120)
      assert count >= 1

      conn = get(conn, "/api/v1/agents")
      agents = json_response(conn, 200)["data"]

      assert Enum.find(agents, &(&1["id"] == mobile_agent.id))["status"] == "online"
      assert Enum.find(agents, &(&1["id"] == desktop_agent.id))["status"] == "offline"
    end

    test "rejects batch network isolation for mobile agent mirrors", %{
      conn_a: conn,
      org_a: org
    } do
      {:ok, _device} =
        Mobile.register_device(%{
          "organization_id" => org.id,
          "device_id" => "android-batch-host-action-1",
          "platform" => "android",
          "model" => "Pixel Batch Action"
        })

      agent =
        Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-batch-host-action-1")

      conn =
        post(conn, "/api/v1/agents/batch/isolate", %{
          "agent_ids" => [agent.id],
          "reason" => "mobile parity regression test"
        })

      body = json_response(conn, 422)
      assert body["platform"] == "mobile"
      assert body["supported_surface"] == "mobile endpoint commands"
      assert body["unsupported_agent_ids"] == [agent.id]
    end

    test "returns not found for mobile commands against unknown devices", %{conn_a: conn} do
      conn = post(conn, "/api/v1/mobile/devices/#{Ecto.UUID.generate()}/commands/lock", %{})

      assert json_response(conn, 404)["error"] == "Device not found"
    end

    test "requires response permission for mobile device commands", %{org_a: org} do
      analyst = insert!(:user, %{organization: org, role: "analyst"})
      {:ok, analyst_token, _claims} = TamanduaServer.Guardian.encode_and_sign(analyst)

      {:ok, device} =
        Mobile.register_device(%{
          "organization_id" => org.id,
          "device_id" => "android-command-authz-1",
          "platform" => "android",
          "model" => "Pixel 8"
        })

      conn =
        auth_conn(analyst_token)
        |> post("/api/v1/mobile/devices/#{device.id}/commands/locate", %{})

      body = json_response(conn, 403)
      assert body["error"] == "forbidden"
      assert body["required_permission"] == "agents_command"
    end

    test "allows admins to run safe mobile locate command", %{conn_a: conn, org_a: org} do
      {:ok, device} =
        Mobile.register_device(%{
          "organization_id" => org.id,
          "device_id" => "android-command-admin-1",
          "platform" => "android",
          "model" => "Pixel 8"
        })

      conn = post(conn, "/api/v1/mobile/devices/#{device.id}/commands/locate", %{})
      body = json_response(conn, 200)

      assert body["success"] == true
      assert body["command"] == "locate"
      assert body["device_id"] == "android-command-admin-1"
    end
  end

  describe "mobile v2 device and command APIs" do
    test "creates a v2 device, syncs agent projection, and stays scoped by org", %{
      conn_a: conn_a,
      conn_b: conn_b,
      org_a: org
    } do
      conn =
        post(conn_a, "/api/v1/mobile/v2/devices", %{
          "device_id" => "android-v2-contract-1",
          "device_name" => "Pixel V2 Contract",
          "platform" => "android",
          "os_version" => "15",
          "model" => "Pixel 9",
          "owner_email" => "owner@example.test",
          "mdm_enrolled" => true,
          "mdm_provider" => "tamandua_mobile",
          "compliance_status" => "compliant",
          "encryption_enabled" => true,
          "passcode_set" => true,
          "capabilities" => %{
            "screen_capture" => %{"available" => true},
            "network_status" => %{"available" => true}
          }
        })

      response = json_response(conn, 201)
      body = response["data"]

      assert body["device_id"] == "android-v2-contract-1"
      assert body["platform"] == "android"
      assert body["mdm_enrolled"] == true
      assert body["agent_id"]
      assert body["agent_status"] == "online"
      assert body["agent_version"] == "mobile-v2"
      assert body["live_response"] == "mdm_actions_only"
      assert body["capabilities"]["native_endpoint_agent"] == false
      assert body["capabilities"]["network_status"]["available"] == true
      assert response["agent_projection"] == %{
               "ok" => true,
               "agent_id" => body["agent_id"],
               "machine_id" => "android-v2-contract-1",
               "status" => "online",
               "agent_version" => "mobile-v2",
               "source" => "tamandua_mobile_v2"
             }

      assert body["command_identity"] == %{
               "agent_machine_id" => "android-v2-contract-1",
               "background_sync_device_id" => body["id"],
               "command_device_id" => body["id"],
               "external_device_id" => "android-v2-contract-1"
             }

      agent = Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-v2-contract-1")
      assert agent.id == body["agent_id"]
      assert agent.os_type == "android"
      assert "mobile-v2" in agent.tags

      native_conn =
        post(conn_a, "/api/v1/mobile/v2/devices", %{
          "device_id" => "android-v2-native-contract-1",
          "device_name" => "Pixel V2 Native Contract",
          "platform" => "android",
          "os_version" => "15",
          "model" => "Pixel 9",
          "owner_email" => "owner@example.test",
          "mdm_enrolled" => true,
          "mdm_provider" => "tamandua_mobile",
          "compliance_status" => "compliant",
          "capabilities" => %{
            "native_endpoint_agent" => true,
            "network_status" => %{"available" => true}
          }
        })

      native_body = json_response(native_conn, 201)["data"]
      assert native_body["capabilities"]["native_endpoint_agent"] == true

      command =
        Repo.insert!(%MDMCommand{
          organization_id: org.id,
          device_id: body["id"],
          command_type: "locate",
          status: "pending",
          requested_by: "operator@example.test"
        })

      app_guard_conn =
        post(
          conn_a,
          "/api/v1/mobile/app_guard/events",
          app_guard_payload()
          |> put_in(["device", "device_id"], "android-v2-contract-1")
          |> put_in(["platform"], "android")
          |> put_in(["event_id"], "evt-android-v2-contract-1")
        )

      assert json_response(app_guard_conn, 201)["data"]["event_id"] == "evt-android-v2-contract-1"

      overview_conn = get(conn_a, "/api/v1/mobile/agents/#{agent.id}/overview")
      overview = json_response(overview_conn, 200)["data"]

      assert overview["linked"] == true
      assert overview["device"]["id"] == body["id"]
      assert overview["device"]["device_id"] == "android-v2-contract-1"
      assert overview["command_device"]["id"] == body["id"]
      assert overview["last_command"]["id"] == command.id
      assert Enum.map(overview["command_history"], & &1["id"]) == [command.id]
      assert overview["posture"]["platform"] == "android"
      assert overview["compliance"]["local_compliant"] == true
      assert overview["app_inventory"]["reported"] == false
      assert overview["app_inventory"]["coverage"] == "not_reported"
      assert overview["app_inventory"]["total"] == nil
      assert overview["app_inventory"]["high_risk"] == nil
      assert overview["app_inventory"]["sideloaded"] == nil
      assert overview["app_guard"]["total_recent_events"] == 1
      assert overview["app_guard"]["readiness"]["status"] == "missing_protected_app"
      assert overview["app_guard"]["readiness"]["recent_event_count"] == 1
      assert overview["app_guard"]["readiness"]["runtime_signals"] == ["emulator_detected"]
      refute "no_recent_app_guard_events" in overview["app_guard"]["readiness"]["gaps"]

      assert [%{"payload" => %{"event_id" => "evt-android-v2-contract-1"}}] =
               overview["app_guard"]["events"]

      v2_events =
        conn_a |> get("/api/v1/mobile/v2/events?limit=10&hours=72") |> json_response(200)

      assert [%{"event_type" => "commercial_spyware_suspected"}] = v2_events["data"]

      assert get_in(v2_events, ["data", Access.at(0), "device", "device_id"]) ==
               "android-v2-contract-1"

      conn = get(conn_b, "/api/v1/mobile/v2/devices?platform=android")
      assert json_response(conn, 200)["data"] == []
    end

    test "returns v2 stats and posture envelopes used by the mobile web dashboard", %{
      conn_a: conn,
      org_a: org
    } do
      now = DateTime.utc_now(:microsecond)

      Repo.insert!(%DeviceV2{
        organization_id: org.id,
        device_id: "android-v2-dashboard-stats-1",
        device_name: "Android Dashboard Stats",
        platform: "android",
        compliance_status: "compliant",
        mdm_enrolled: true,
        encryption_enabled: true,
        jailbroken: false,
        passcode_set: true,
        last_seen_at: now,
        enrolled_at: now
      })

      Repo.insert!(%DeviceV2{
        organization_id: org.id,
        device_id: "ios-v2-dashboard-stats-1",
        device_name: "iOS Dashboard Stats",
        platform: "ios",
        compliance_status: "non_compliant",
        mdm_enrolled: false,
        encryption_enabled: false,
        jailbroken: true,
        passcode_set: false,
        last_seen_at: now,
        enrolled_at: now
      })

      stats = conn |> get("/api/v1/mobile/v2/stats") |> json_response(200)

      assert stats["data"]["total"] == 2
      assert stats["data"]["by_platform"] == %{"android" => 1, "ios" => 1}
      assert stats["data"]["by_compliance"] == %{"compliant" => 1, "non_compliant" => 1}
      assert stats["data"]["mdm_enrolled"] == 1
      assert stats["data"]["not_enrolled"] == 1
      assert stats["data"]["jailbroken"] == 1
      assert stats["data"]["stale_24h"] == 0

      posture = conn |> get("/api/v1/mobile/v2/posture") |> json_response(200)

      assert posture["data"]["total"] == 2
      assert posture["data"]["pct_compliant"] == 50.0
      assert posture["data"]["pct_encrypted"] == 50.0
      assert posture["data"]["pct_jailbroken"] == 50.0
      assert posture["data"]["pct_passcode_set"] == 50.0
      assert posture["data"]["pct_mdm_enrolled"] == 50.0
      assert posture["data"]["compliant"] == 1
      assert posture["data"]["encrypted"] == 1
      assert posture["data"]["jailbroken"] == 1
      assert posture["data"]["passcode_set"] == 1
      assert posture["data"]["mdm_enrolled"] == 1
      assert posture["data"]["score"] == 51
    end

    test "requires response permission before creating v2 mobile commands", %{org_a: org} do
      analyst = insert!(:user, %{organization: org, role: "analyst"})
      {:ok, analyst_token, _claims} = TamanduaServer.Guardian.encode_and_sign(analyst)

      device =
        Repo.insert!(%TamanduaServer.Mobile.DeviceV2{
          organization_id: org.id,
          device_id: "android-v2-rbac-1",
          device_name: "Pixel V2 RBAC",
          platform: "android",
          mdm_enrolled: true,
          mdm_provider: "tamandua_mobile"
        })

      conn =
        auth_conn(analyst_token)
        |> post("/api/v1/mobile/v2/commands", %{
          "device_id" => device.id,
          "command_type" => "lock",
          "payload" => %{"reason" => "rbac regression"}
        })

      body = json_response(conn, 403)
      assert body["error"] == "forbidden"
      assert body["required_permission"] == "agents_command"
      refute Repo.get_by(MDMCommand, device_id: device.id)
    end

    test "preserves managed_shell while gating shell_execute without privileged capability", %{
      conn_a: conn,
      org_a: org
    } do
      create_conn =
        post(conn, "/api/v1/mobile/v2/devices", %{
          "device_id" => "android-v2-shell-gated-1",
          "device_name" => "Pixel V2 Shell Gated",
          "platform" => "android",
          "mdm_enrolled" => true,
          "mdm_provider" => "tamandua_mobile"
        })

      device = json_response(create_conn, 201)["data"]

      managed_conn =
        post(conn, "/api/v1/mobile/v2/commands", %{
          "device_id" => device["id"],
          "command_type" => "managed_shell",
          "payload" => %{"command" => "posture"}
        })

      managed = json_response(managed_conn, 201)["data"]
      assert managed["command_type"] == "managed_shell"
      assert managed["status"] == "pending"

      shell_conn =
        post(conn, "/api/v1/mobile/v2/commands", %{
          "device_id" => device["id"],
          "command_type" => "shell_execute",
          "payload" => %{"command" => "id"}
        })

      body = json_response(shell_conn, 422)
      assert body["error"] == "privileged_shell_disabled"
      assert body["required_manifest_flag"] == "tamandua.endpoint.allow_privileged_shell"
      assert body["fallback_command_type"] == "managed_shell"

      refute Repo.get_by(MDMCommand,
               organization_id: org.id,
               device_id: device["id"],
               command_type: "shell_execute"
             )
    end

    test "preserves v2 endpoint hardening posture in synced agent overview", %{
      conn_a: conn,
      org_a: org
    } do
      create_conn =
        post(conn, "/api/v1/mobile/v2/devices", %{
          "device_id" => "android-v2-hardening-1",
          "device_name" => "Pixel V2 Hardening",
          "platform" => "android",
          "mdm_enrolled" => true,
          "mdm_provider" => "tamandua_mobile",
          "risk_score" => 95,
          "risk_factors" => [
            "frida_detected",
            "app_integrity_violation",
            "runtime_memory_tamper_detected",
            "code_signature_drift_detected"
          ],
          "collected_at" => "2026-07-15T09:20:00Z",
          "security_checks" => %{
            "jailbroken_or_rooted" => true,
            "passcode_enabled" => true,
            "encryption_enabled" => true,
            "developer_mode" => true,
            "adb_enabled" => true,
            "debugger_detected" => false,
            "frida_detected" => true,
            "hook_framework_detected" => true,
            "native_hook_detected" => true,
            "app_integrity_violation" => true,
            "runtime_memory_tamper_detected" => true,
            "code_signature_drift_detected" => true,
            "tampering_detected" => true
          },
          "hardening" => %{
            "frida" => "frida_indicator_present",
            "hook" => "hook_indicator_present",
            "runtime_memory_tamper" => "runtime_memory_tamper_indicator_present"
          }
        })

      device = json_response(create_conn, 201)["data"]
      assert device["security_checks"]["frida_detected"] == true
      assert device["security_checks"]["runtime_memory_tamper_detected"] == true
      assert device["hardening"]["frida"] == "frida_indicator_present"
      assert device["risk_score"] == 95

      agent = Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-v2-hardening-1")
      assert get_in(agent.config, ["posture", "security_checks", "frida_detected"]) == true
      assert get_in(agent.config, ["posture", "hardening", "hook"]) == "hook_indicator_present"

      overview_conn = get(conn, "/api/v1/mobile/agents/#{agent.id}/overview")
      overview = json_response(overview_conn, 200)["data"]
      posture = overview["posture"]

      assert overview["linked"] == true
      assert overview["command_device"]["id"] == device["id"]
      assert overview["command_device"]["device_id"] == "android-v2-hardening-1"
      assert overview["command_identity"]["command_device_id"] == device["id"]
      assert overview["command_identity"]["external_device_id"] == "android-v2-hardening-1"
      assert overview["device"]["command_identity"]["command_device_id"] == device["id"]
      assert posture["risk_score"] == 95

      assert posture["risk_factors"] == [
               "frida_detected",
               "app_integrity_violation",
               "runtime_memory_tamper_detected",
               "code_signature_drift_detected"
             ]

      assert posture["security_checks"]["hook_framework_detected"] == true
      assert posture["security_checks"]["app_integrity_violation"] == true
      assert posture["security_checks"]["code_signature_drift_detected"] == true
      assert posture["debugger_detected"] == false
      assert posture["frida_detected"] == true
      assert posture["hook_framework_detected"] == true
      assert posture["native_hook_detected"] == true
      assert posture["app_integrity_violation"] == true
      assert posture["runtime_memory_tamper_detected"] == true
      assert posture["code_signature_drift_detected"] == true
      assert posture["tampering_detected"] == true
      assert posture["last_assessment"] == "2026-07-15T09:20:00Z"
    end

    test "allows shell_execute only when linked endpoint reports privileged shell capability", %{
      conn_a: conn,
      org_a: org
    } do
      create_conn =
        post(conn, "/api/v1/mobile/v2/devices", %{
          "device_id" => "android-v2-shell-enabled-1",
          "device_name" => "Pixel V2 Shell Enabled",
          "platform" => "android",
          "mdm_enrolled" => true,
          "mdm_provider" => "tamandua_mobile"
        })

      device = json_response(create_conn, 201)["data"]

      agent =
        Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-v2-shell-enabled-1")

      agent
      |> Ecto.Changeset.change(%{
        config: %{
          "source" => "tamandua_mobile_v2",
          "capabilities" => %{"privileged_shell" => true}
        }
      })
      |> Repo.update!()

      shell_conn =
        post(conn, "/api/v1/mobile/v2/commands", %{
          "device_id" => device["id"],
          "command_type" => "shell_execute",
          "payload" => %{"command" => "id"}
        })

      shell = json_response(shell_conn, 201)["data"]
      assert shell["command_type"] == "shell_execute"
      assert shell["status"] == "pending"
    end

    test "lists pending v2 commands and records completion status", %{conn_a: conn, org_a: org} do
      create_conn =
        post(conn, "/api/v1/mobile/v2/devices", %{
          "device_id" => "android-v2-command-1",
          "device_name" => "Pixel V2 Command",
          "platform" => "android",
          "mdm_enrolled" => true,
          "mdm_provider" => "tamandua_mobile"
        })

      device = json_response(create_conn, 201)["data"]

      command_conn =
        post(conn, "/api/v1/mobile/v2/commands", %{
          "device_id" => device["id"],
          "command_type" => "locate",
          "payload" => %{"precision" => "coarse"}
        })

      command = json_response(command_conn, 201)["data"]
      assert command["device_id"] == device["id"]
      assert command["command_type"] == "locate"
      assert command["status"] == "pending"
      assert command["requested_by"]

      pending_conn =
        get(conn, "/api/v1/mobile/v2/commands?device_id=#{device["id"]}&status=pending")

      assert [pending] = json_response(pending_conn, 200)["data"]
      assert pending["id"] == command["id"]

      completed_conn =
        patch(conn, "/api/v1/mobile/v2/commands/#{command["id"]}/status", %{
          "device_id" => device["id"],
          "status" => "completed",
          "result" => %{"location" => "operator-confirmed"}
        })

      completed = json_response(completed_conn, 200)["data"]
      assert completed["status"] == "completed"
      assert completed["completed_at"]
      assert completed["result"]["location"] == "operator-confirmed"

      stored = Repo.get_by!(MDMCommand, organization_id: org.id, id: command["id"])
      assert stored.status == "completed"
      assert stored.completed_at
    end

    test "preserves alert linkage for non-network mobile commands", %{
      conn_a: conn,
      org_a: org
    } do
      create_conn =
        post(conn, "/api/v1/mobile/v2/devices", %{
          "device_id" => "android-v2-locate-alert-link-1",
          "device_name" => "Pixel V2 Alert Link",
          "platform" => "android",
          "mdm_enrolled" => true,
          "mdm_provider" => "tamandua_mobile"
        })

      device = json_response(create_conn, 201)["data"]

      agent =
        Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-v2-locate-alert-link-1")

      alert = insert!(:alert, %{organization_id: org.id, agent_id: agent.id})

      command_conn =
        post(conn, "/api/v1/mobile/v2/commands", %{
          "device_id" => device["id"],
          "command_type" => "locate",
          "alert_id" => alert.id,
          "payload" => %{"reason" => "alert_response"}
        })

      command = json_response(command_conn, 201)["data"]
      assert command["payload"]["alert_id"] == alert.id
      assert command["payload"]["reason"] == "alert_response"

      filtered_conn = get(conn, "/api/v1/mobile/v2/commands?alert_id=#{alert.id}")
      assert [filtered] = json_response(filtered_conn, 200)["data"]
      assert filtered["id"] == command["id"]
    end

    test "normalizes mobile network command payloads and filters them by alert", %{
      conn_a: conn,
      org_a: org
    } do
      create_conn =
        post(conn, "/api/v1/mobile/v2/devices", %{
          "device_id" => "android-v2-network-contract-1",
          "device_name" => "Pixel V2 Network Contract",
          "platform" => "android",
          "mdm_enrolled" => true,
          "mdm_provider" => "tamandua_mobile"
        })

      device = json_response(create_conn, 201)["data"]

      agent =
        Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-v2-network-contract-1")

      alert = insert!(:alert, %{organization_id: org.id, agent_id: agent.id})

      command_conn =
        post(conn, "/api/v1/mobile/v2/commands", %{
          "device_id" => device["id"],
          "command_type" => "network_status",
          "alert_id" => alert.id,
          "payload" => %{"protocol" => "tcp"}
        })

      command = json_response(command_conn, 201)["data"]
      assert command["status"] == "pending"
      assert command["payload"]["schema"] == "tamandua.mobile.network_status.request/v1"
      assert command["payload"]["collector"] == "mobile_network_status"
      assert command["payload"]["alert_id"] == alert.id
      assert command["payload"]["external_device_id"] == "android-v2-network-contract-1"

      filtered_conn = get(conn, "/api/v1/mobile/v2/commands?alert_id=#{alert.id}")
      assert [filtered] = json_response(filtered_conn, 200)["data"]
      assert filtered["id"] == command["id"]

      missing_alert_conn =
        post(conn, "/api/v1/mobile/v2/commands", %{
          "device_id" => device["id"],
          "command_type" => "network_status",
          "alert_id" => Ecto.UUID.generate()
        })

      assert json_response(missing_alert_conn, 404)["error"] == "Alert not found"
    end

    test "queues DNS-forwarder network flow command without claiming packet collector", %{
      conn_a: conn,
      org_a: org
    } do
      create_conn =
        post(conn, "/api/v1/mobile/v2/devices", %{
          "device_id" => "android-v2-packet-missing-1",
          "device_name" => "Pixel V2 Packet Missing",
          "platform" => "android",
          "mdm_enrolled" => true,
          "mdm_provider" => "tamandua_mobile"
        })

      device = json_response(create_conn, 201)["data"]

      agent =
        Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-v2-packet-missing-1")

      alert = insert!(:alert, %{organization_id: org.id, agent_id: agent.id})

      command_conn =
        post(conn, "/api/v1/mobile/v2/commands", %{
          "device_id" => device["id"],
          "command_type" => "list_network_flows",
          "alert_id" => alert.id,
          "payload" => %{
            "remote_address" => "203.0.113.10",
            "remote_port" => 443,
            "protocol" => "tcp"
          }
        })

      command = json_response(command_conn, 201)["data"]
      assert command["status"] == "pending"
      assert command["payload"]["schema"] == "tamandua.mobile.network_flows.request/v1"
      assert command["payload"]["collector"] == "dns_forwarder"
      assert command["payload"]["coverage"] == "dns_forwarder_counters_only_no_pcap"
      assert command["payload"]["requires_collector"] == "dns_forwarder_or_packet_collector"
      assert command["payload"]["visibility_mode"] == "dns_metadata_summary"
      assert "dns_status" in command["payload"]["alternative_visibility"]

      assert Enum.any?(
               command["payload"]["limitations"],
               &String.contains?(&1, "encrypted DNS")
             )

      assert command["payload"]["filters"]["alert_id"] == alert.id
      assert command["payload"]["filters"]["remote_address"] == "203.0.113.10"
    end

    test "returns honest failed result when packet inspection collector is absent", %{
      conn_a: conn,
      org_a: org
    } do
      create_conn =
        post(conn, "/api/v1/mobile/v2/devices", %{
          "device_id" => "android-v2-packet-missing-2",
          "device_name" => "Pixel V2 Packet Missing 2",
          "platform" => "android",
          "mdm_enrolled" => true,
          "mdm_provider" => "tamandua_mobile"
        })

      device = json_response(create_conn, 201)["data"]

      agent =
        Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-v2-packet-missing-2")

      alert = insert!(:alert, %{organization_id: org.id, agent_id: agent.id})

      command_conn =
        post(conn, "/api/v1/mobile/v2/commands", %{
          "device_id" => device["id"],
          "command_type" => "inspect_packet",
          "alert_id" => alert.id,
          "payload" => %{"protocol" => "udp", "remote_port" => 53}
        })

      command = json_response(command_conn, 201)["data"]
      assert command["status"] == "failed"
      assert command["completed_at"]
      assert command["payload"]["schema"] == "tamandua.mobile.packet_inspection.request/v1"
      assert command["payload"]["requires_collector"] == "packet_collector"
      assert command["payload"]["visibility_mode"] == "packet_collector_required"

      assert command["payload"]["fallback_commands"] == [
               "list_network_flows",
               "dns_status",
               "network_status"
             ]

      assert command["payload"]["filters"]["alert_id"] == alert.id
      assert command["result"]["schema"] == "tamandua.mobile.packet_inspection.result/v1"
      assert command["result"]["ok"] == false
      assert command["result"]["executed"] == false
      assert command["result"]["reason"] == "requires_packet_collector"
      assert command["result"]["visibility_mode"] == "degraded_dns_metadata_available"

      assert command["result"]["fallback_commands"] == [
               "list_network_flows",
               "dns_status",
               "network_status"
             ]

      assert command["result"]["alternative_visibility"]["dns_forwarder"] =~ "DNS query counters"
      assert command["result"]["filters"]["alert_id"] == alert.id
    end

    test "normalizes endpoint-reported packet collector absence on status update", %{
      conn_a: conn,
      org_a: org
    } do
      device =
        Repo.insert!(%TamanduaServer.Mobile.DeviceV2{
          organization_id: org.id,
          device_id: "android-v2-packet-status-1",
          device_name: "Pixel V2 Packet Status",
          platform: "android",
          mdm_enrolled: true,
          mdm_provider: "tamandua_mobile"
        })

      command =
        Repo.insert!(%MDMCommand{
          organization_id: org.id,
          device_id: device.id,
          command_type: "inspect_packet",
          status: "pending",
          payload: %{"schema" => "tamandua.mobile.packet_inspection.request/v1"},
          requested_by: "operator@example.test"
        })

      completed_conn =
        patch(conn, "/api/v1/mobile/v2/commands/#{command.id}/status", %{
          "device_id" => device.id,
          "status" => "completed",
          "result" => %{
            "ok" => false,
            "executed" => false,
            "reason" => "requires_packet_collector"
          }
        })

      completed = json_response(completed_conn, 200)["data"]
      assert completed["status"] == "failed"
      assert completed["completed_at"]
      assert completed["result"]["schema"] == "tamandua.mobile.packet_inspection.result/v1"
      assert completed["result"]["command_type"] == "inspect_packet"
      assert completed["result"]["reason"] == "requires_packet_collector"
      assert completed["result"]["collector"] == "packet_collector"
      assert completed["result"]["visibility_mode"] == "degraded_dns_metadata_available"
      assert "list_network_flows" in completed["result"]["fallback_commands"]
    end

    test "treats terminal command result replay with the same result hash as idempotent", %{
      conn_a: conn,
      org_a: org
    } do
      completed_at = ~U[2026-07-05 10:05:00.000000Z]

      device =
        Repo.insert!(%TamanduaServer.Mobile.DeviceV2{
          organization_id: org.id,
          device_id: "android-v2-command-replay-1",
          device_name: "Pixel V2 Replay",
          platform: "android",
          mdm_enrolled: true,
          mdm_provider: "tamandua_mobile"
        })

      command =
        Repo.insert!(%MDMCommand{
          organization_id: org.id,
          device_id: device.id,
          command_type: "managed_shell",
          status: "completed",
          payload: %{"command" => "posture"},
          result: %{
            "ok" => true,
            "output" => "posture",
            "result_sha256" => "aabbcc"
          },
          completed_at: completed_at,
          requested_by: "operator@example.test"
        })

      replay_conn =
        patch(conn, "/api/v1/mobile/v2/commands/#{command.id}/status", %{
          "device_id" => device.id,
          "status" => "completed",
          "result" => %{
            "ok" => true,
            "output" => "posture",
            "result_sha256" => "aabbcc"
          }
        })

      replayed = json_response(replay_conn, 200)["data"]
      assert replayed["status"] == "completed"

      stored = Repo.get!(MDMCommand, command.id)
      assert stored.completed_at == completed_at
      assert stored.result["result_sha256"] == "aabbcc"
    end

    test "rejects terminal command result replay with a different result hash", %{
      conn_a: conn,
      org_a: org
    } do
      completed_at = ~U[2026-07-05 10:06:00.000000Z]

      device =
        Repo.insert!(%TamanduaServer.Mobile.DeviceV2{
          organization_id: org.id,
          device_id: "android-v2-command-replay-conflict-1",
          device_name: "Pixel V2 Replay Conflict",
          platform: "android",
          mdm_enrolled: true,
          mdm_provider: "tamandua_mobile"
        })

      command =
        Repo.insert!(%MDMCommand{
          organization_id: org.id,
          device_id: device.id,
          command_type: "managed_shell",
          status: "completed",
          payload: %{"command" => "dns"},
          result: %{
            "ok" => true,
            "output" => "dns",
            "result_sha256" => "old-hash"
          },
          completed_at: completed_at,
          requested_by: "operator@example.test"
        })

      conflict_conn =
        patch(conn, "/api/v1/mobile/v2/commands/#{command.id}/status", %{
          "device_id" => device.id,
          "status" => "completed",
          "result" => %{
            "ok" => true,
            "output" => "tampered",
            "result_sha256" => "new-hash"
          }
        })

      body = json_response(conflict_conn, 409)
      assert body["error"] == "Command terminal result replay conflict"
      assert body["existing_result_sha256"] == "old-hash"
      assert body["incoming_result_sha256"] == "new-hash"

      stored = Repo.get!(MDMCommand, command.id)
      assert stored.completed_at == completed_at
      assert stored.result["output"] == "dns"
      assert stored.result["result_sha256"] == "old-hash"
    end

    test "rejects v2 command status updates without matching device identity", %{
      conn_a: conn,
      org_a: org
    } do
      device =
        Repo.insert!(%TamanduaServer.Mobile.DeviceV2{
          organization_id: org.id,
          device_id: "android-v2-command-identity-1",
          device_name: "Pixel V2 Identity",
          platform: "android",
          mdm_enrolled: true,
          mdm_provider: "tamandua_mobile"
        })

      command =
        Repo.insert!(%MDMCommand{
          organization_id: org.id,
          device_id: device.id,
          command_type: "locate",
          status: "pending",
          requested_by: "operator@example.test"
        })

      conn =
        patch(conn, "/api/v1/mobile/v2/commands/#{command.id}/status", %{
          "device_id" => Ecto.UUID.generate(),
          "status" => "completed",
          "result" => %{"location" => "wrong-device"}
        })

      body = json_response(conn, 422)
      assert body["error"] == "Command device identity mismatch"
      assert body["required_field"] == "device_id"

      stored = Repo.get!(MDMCommand, command.id)
      assert stored.status == "pending"
      assert stored.completed_at == nil
    end
  end

  describe "POST /api/v1/mobile/app_guard/events" do
    test "ingests App Guard SDK events as mobile telemetry", %{conn_a: conn, org_a: org} do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "mobile:events")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "app_guard:event")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "mobile:app_guard_event")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "security:app_guard")

      conn = post(conn, "/api/v1/mobile/app_guard/events", app_guard_payload())

      body = json_response(conn, 201)
      assert body["success"] == true
      assert body["data"]["event_type"] == "emulator_detected"
      assert body["data"]["app_bundle_id"] == "com.example.wallet"

      device = Mobile.get_device_by_device_id(org.id, "ios-device-1")
      assert device.platform == "ios"
      assert device.agent_version == "app_guard"

      command_device = Repo.get_by!(DeviceV2, organization_id: org.id, device_id: "ios-device-1")
      assert command_device.platform == "ios"

      command_agent = Repo.get_by!(Agent, organization_id: org.id, machine_id: "ios-device-1")
      assert command_agent.config["mobile_device_v2_id"] == command_device.id
      assert command_agent.config["capabilities"]["app_guard"] == true

      event = Repo.get!(MobileEvent, body["data"]["id"])
      assert event.organization_id == org.id
      assert event.payload["schema"] == "tamandua.app_guard.event/v1"
      assert event.timestamp == ~N[2026-06-26 12:00:00]

      assert_receive {:mobile_event, mobile_payload}, 500
      assert mobile_payload["schema"] == "tamandua.app_guard.event/v1"
      assert mobile_payload["server_event_id"] == event.id
      assert mobile_payload["organization_id"] == org.id

      for _ <- 1..3 do
        assert_receive {:app_guard_event, app_guard_payload}, 500
        assert app_guard_payload["schema"] == "tamandua.app_guard.event/v1"
        assert app_guard_payload["event_id"] == "evt-app-guard-1"
        assert app_guard_payload["device"]["device_id"] == "ios-device-1"
        assert app_guard_payload["server_event_id"] == event.id
      end
    end

    test "creates App Guard alerts for high severity SDK events", %{conn_a: conn, org_a: org} do
      payload =
        app_guard_payload()
        |> put_in(["event_type"], "debugger_detected")
        |> put_in(["severity"], "high")
        |> put_in(["risk", "decision"], "step_up")
        |> put_in(["risk", "score"], 82)
        |> put_in(["risk", "reasons"], ["debugger_detected", "unmanaged_device"])
        |> put_in(["risk", "thresholds"], %{"step_up" => 75, "block" => 90})
        |> put_in(["evidence", "integrity_snapshot"], %{
          "state" => "modified",
          "tamper_class" => "debugger",
          "artifact_sha256" => "abc123"
        })
        |> put_in(["evidence", "iocs"], [%{"type" => "sha256", "value" => "abc123"}])
        |> Map.put("agent_id", "synthetic-mobile-agent-that-is-not-linked")

      conn = post(conn, "/api/v1/mobile/app_guard/events", payload)

      body = json_response(conn, 201)
      event = Repo.get!(MobileEvent, body["data"]["id"])
      event = Repo.get!(MobileEvent, event.id)
      alert = Repo.get!(Alert, event.alert_id)
      agent = Repo.get_by!(Agent, organization_id: org.id, machine_id: "ios-device-1")

      assert event.alerted == true
      assert event.organization_id == org.id
      assert alert.organization_id == org.id
      assert alert.agent_id == agent.id
      assert alert.agent_id != payload["agent_id"]
      assert alert.agent_id != nil
      assert alert.severity == "high"
      assert alert.title == "[App Guard] App Guard debugger_detected"
      assert alert.detection_metadata["source"] == "app_guard"
      assert alert.detection_metadata["event_type"] == "debugger_detected"
      assert alert.detection_metadata["rule_name"] == "App Guard debugger_detected"
      assert alert.detection_metadata["detection_type"] == "mobile_app_guard"
      assert alert.detection_metadata["app_bundle_id"] == "com.example.wallet"
      assert alert.detection_metadata["decision"] == "step_up"
      assert alert.detection_metadata["risk_reasons"] == ["debugger_detected", "unmanaged_device"]
      assert alert.evidence["detection"]["rule_name"] == "App Guard debugger_detected"
      assert alert.evidence["detection"]["detection_type"] == "mobile_app_guard"
      assert alert.evidence["app_guard"]["protected_app"]["bundle_id"] == "com.example.wallet"
      assert alert.evidence["policy"]["decision"] == "step_up"
      assert alert.evidence["decision_trace"]["decision"] == "step_up"
      assert alert.evidence["evidence_snapshot"]["policy_decision"]["decision"] == "step_up"

      assert alert.evidence["evidence_snapshot"]["thresholds"] == %{
               "block" => 90,
               "step_up" => 75
             }

      assert "debugger_detected" in alert.evidence["evidence_snapshot"]["signals"]
      assert alert.evidence["evidence_snapshot"]["device_identity"]["model"] == "iPhone 15"

      assert alert.evidence["evidence_snapshot"]["app_identity"]["package_or_bundle_id"] ==
               "com.example.wallet"

      assert alert.evidence["evidence_snapshot"]["integrity"]["state"] == "modified"
      assert alert.detection_metadata["telemetry_quality"]["category"] == "app_guard"
      assert alert.detection_metadata["telemetry_quality"]["missing"] == []
      assert alert.detection_metadata["alert_claim_strength"] == "evidence_supported"
      assert alert.detection_metadata["fp_review_required"] == false
      assert alert.detection_metadata["correlation_ready"] == true

      assert %{"type" => "package", "value" => "com.example.wallet"} =
               Enum.find(alert.evidence["iocs"], &(&1["type"] == "package"))

      assert %{"type" => "sha256", "value" => "abc123"} =
               Enum.find(alert.evidence["iocs"], &(&1["type"] == "sha256"))

      assert alert.raw_event["mobile_event_id"] == event.id
      assert alert.raw_event["payload"]["risk"]["decision"] == "step_up"
    end

    test "marks App Guard alerts with missing integrity evidence as triage-only", %{conn_a: conn} do
      payload =
        app_guard_payload()
        |> put_in(["event_type"], "browser_tamper_detected")
        |> put_in(["severity"], "high")
        |> put_in(["risk", "decision"], "step_up")
        |> put_in(["risk", "score"], 65)
        |> put_in(["risk", "reasons"], ["browser_tamper_detected"])

      conn = post(conn, "/api/v1/mobile/app_guard/events", payload)

      body = json_response(conn, 201)
      event = Repo.get!(MobileEvent, body["data"]["id"])
      alert = Repo.get!(Alert, event.alert_id)

      assert alert.detection_metadata["telemetry_quality"]["category"] == "app_guard"
      assert "app_guard.integrity" in alert.detection_metadata["telemetry_quality"]["missing"]
      assert alert.detection_metadata["alert_claim_strength"] == "triage_only"
      assert alert.detection_metadata["fp_review_required"] == true
      assert alert.detection_metadata["correlation_ready"] == false
    end

    test "preserves Android input provenance as observe-only App Guard context", %{
      conn_a: conn,
      org_a: org
    } do
      input_provenance = %{
        "schema" => "tamandua.input_provenance.aggregate/v1",
        "platform" => "android",
        "collector" => "android_motion_event",
        "collector_state" => "supported",
        "evidence_type" => "metadata_only",
        "privacy_mode" => "aggregate_no_content",
        "policy_mode" => "observe_only",
        "external_claim_allowed" => false,
        "workflow_class" => "login",
        "sample_count_bucket" => "2_5",
        "source_classes_observed" => ["touchscreen"],
        "tool_types_observed" => ["finger"],
        "assistive_technology_context" => "not_observed",
        "obscured" => %{"window_obscured" => false, "partial_obscured" => false},
        "cadence" => %{"bucket" => "human_interaction"},
        "completeness" => %{"status" => "complete", "degraded_reasons" => []}
      }

      payload =
        app_guard_payload()
        |> put_in(["event_id"], "evt-app-guard-input-provenance-1")
        |> put_in(["event_type"], "tampering_detected")
        |> put_in(["severity"], "high")
        |> put_in(["platform"], "android")
        |> put_in(["device", "device_id"], "android-input-provenance-1")
        |> put_in(["device", "model"], "Pixel 8")
        |> put_in(["device", "manufacturer"], "Google")
        |> put_in(["device", "os_version"], "16")
        |> put_in(["app", "package_or_bundle_id"], "io.tamandua.samplewallet")
        |> put_in(["risk", "decision"], "observe")
        |> put_in(["risk", "score"], 76)
        |> put_in(["risk", "reasons"], ["input_provenance_observed"])
        |> put_in(["evidence", "input_provenance"], input_provenance)

      conn = post(conn, "/api/v1/mobile/app_guard/events", payload)

      body = json_response(conn, 201)
      event = Repo.get!(MobileEvent, body["data"]["id"])
      alert = Repo.get!(Alert, event.alert_id)

      assert event.organization_id == org.id
      assert event.payload["evidence"]["input_provenance"] == input_provenance
      assert alert.raw_event["payload"]["evidence"]["input_provenance"] == input_provenance

      assert alert.evidence["app_guard"]["input_provenance"]["schema"] ==
               "tamandua.input_provenance.aggregate/v1"

      assert alert.evidence["app_guard"]["input_provenance"]["policy_mode"] == "observe_only"
      assert alert.evidence["app_guard"]["input_provenance"]["external_claim_allowed"] == false

      assert alert.evidence["evidence_snapshot"]["input_provenance"]["workflow_class"] ==
               "login"

      assert alert.evidence["evidence_snapshot"]["input_provenance"]["claim_boundary"] =~
               "not enforcement"

      assert alert.detection_metadata["decision"] == "observe"
    end

    test "accepts App Guard events signed with the SDK HMAC envelope", %{conn_a: conn, org_a: org} do
      secret = put_app_guard_signing_secret("test-app-guard-secret")
      raw_body = Jason.encode!(app_guard_payload())

      conn =
        conn
        |> put_signed_app_guard_headers(raw_body, secret)
        |> post("/api/v1/mobile/app_guard/events", raw_body)

      body = json_response(conn, 201)
      event = Repo.get!(MobileEvent, body["data"]["id"])

      assert body["success"] == true
      assert body["data"]["id"] == event.id
      assert body["data"]["event_id"] == "evt-app-guard-1"
      assert event.organization_id == org.id
      assert event.payload["schema"] == "tamandua.app_guard.event/v1"
      assert event.payload["event_id"] == "evt-app-guard-1"
      assert event.payload["server_ingestion"]["signed"] == true
      assert event.payload["server_ingestion"]["signing_key_id"] == "test-key-1"
      assert event.payload["server_ingestion"]["payload_sha256"] == sha256(raw_body)
      assert event.payload["server_ingestion"]["nonce"] == "evt-app-guard-1"
      assert event.payload["server_ingestion"]["anti_replay"]["checked"] == true

      assert event.payload["server_ingestion"]["anti_replay"]["method"] ==
               "persistent_payload_sha256_and_nonce_reservation"
    end

    test "accepts App Guard events signed over canonical SDK JSON", %{conn_a: conn, org_a: org} do
      secret = put_app_guard_signing_secret("test-app-guard-secret")

      payload =
        app_guard_payload()
        |> put_in(["event_id"], "evt-app-guard-canonical-1")
        |> put_in(["device", "device_id"], "ios-device-canonical-1")

      raw_body = Jason.encode!(payload, pretty: true)
      canonical_body = canonical_json(payload)

      conn =
        conn
        |> put_signed_app_guard_headers(raw_body, secret, signing_payload: canonical_body)
        |> post("/api/v1/mobile/app_guard/events", raw_body)

      body = json_response(conn, 201)
      event = Repo.get!(MobileEvent, body["data"]["id"])

      assert event.organization_id == org.id
      assert event.payload["event_id"] == "evt-app-guard-canonical-1"

      assert event.payload["server_ingestion"]["canonicalization"] ==
               "json-sort-keys-separators-comma-colon-utf8"
    end

    test "rejects duplicate signed App Guard request replays", %{conn_a: conn, org_a: org} do
      secret = put_app_guard_signing_secret("test-app-guard-secret")
      raw_body = Jason.encode!(app_guard_payload())
      payload_sha256 = sha256(raw_body)

      first_conn =
        conn
        |> put_signed_app_guard_headers(raw_body, secret)
        |> post("/api/v1/mobile/app_guard/events", raw_body)

      first_body = json_response(first_conn, 201)
      first_event = Repo.get!(MobileEvent, first_body["data"]["id"])

      assert first_body["success"] == true
      assert first_body["data"]["event_id"] == "evt-app-guard-1"
      assert first_event.payload["server_ingestion"]["payload_sha256"] == payload_sha256
      assert first_event.payload["server_ingestion"]["nonce"] == "evt-app-guard-1"

      assert app_guard_replay_reservation_count(
               org.id,
               "test-key-1",
               "payload_sha256",
               payload_sha256
             ) == 1

      replay_conn =
        conn
        |> recycle()
        |> put_req_header("authorization", List.first(get_req_header(conn, "authorization")))
        |> put_signed_app_guard_headers(raw_body, secret)
        |> post("/api/v1/mobile/app_guard/events", raw_body)

      body = json_response(replay_conn, 409)
      assert body["error"] == "Duplicate App Guard event replay"
      assert "duplicate signed App Guard event payload" in body["details"]
      refute Map.has_key?(body, "data")

      assert app_guard_replay_reservation_count(
               org.id,
               "test-key-1",
               "payload_sha256",
               payload_sha256
             ) == 1

      assert Repo.aggregate(
               from(event in MobileEvent,
                 where:
                   event.organization_id == ^org.id and
                     fragment("?->>? = ?", event.payload, "event_id", "evt-app-guard-1")
               ),
               :count
             ) == 1
    end

    test "rejects duplicate signed App Guard nonces across different payloads", %{
      conn_a: conn,
      org_a: org
    } do
      secret = put_app_guard_signing_secret("test-app-guard-secret")
      nonce = "nonce-app-guard-replay-1"

      first_payload =
        app_guard_payload()
        |> put_in(["event_id"], "evt-app-guard-nonce-1")
        |> put_in(["device", "device_id"], "ios-device-nonce-1")

      first_raw_body = Jason.encode!(first_payload)

      first_conn =
        conn
        |> put_signed_app_guard_headers(first_raw_body, secret, nonce: nonce)
        |> post("/api/v1/mobile/app_guard/events", first_raw_body)

      first_body = json_response(first_conn, 201)
      first_payload_sha256 = sha256(first_raw_body)

      assert first_body["success"] == true
      assert first_body["data"]["event_id"] == "evt-app-guard-nonce-1"

      assert app_guard_replay_reservation_count(org.id, "test-key-1", "nonce", nonce) == 1

      assert app_guard_replay_reservation_count(
               org.id,
               "test-key-1",
               "payload_sha256",
               first_payload_sha256
             ) == 1

      second_payload =
        app_guard_payload()
        |> put_in(["event_id"], "evt-app-guard-nonce-2")
        |> put_in(["device", "device_id"], "ios-device-nonce-2")
        |> put_in(["risk", "score"], 73)

      second_raw_body = Jason.encode!(second_payload)
      second_payload_sha256 = sha256(second_raw_body)

      replay_conn =
        conn
        |> recycle()
        |> put_req_header("authorization", List.first(get_req_header(conn, "authorization")))
        |> put_signed_app_guard_headers(second_raw_body, secret, nonce: nonce)
        |> post("/api/v1/mobile/app_guard/events", second_raw_body)

      body = json_response(replay_conn, 409)
      assert body["error"] == "Duplicate App Guard event replay"
      assert "duplicate signed App Guard event nonce" in body["details"]
      refute Map.has_key?(body, "data")

      assert app_guard_replay_reservation_count(org.id, "test-key-1", "nonce", nonce) == 1

      assert app_guard_replay_reservation_count(
               org.id,
               "test-key-1",
               "payload_sha256",
               second_payload_sha256
             ) == 0

      assert Repo.aggregate(
               from(event in MobileEvent,
                 where:
                   event.organization_id == ^org.id and
                     fragment("?->>? = ?", event.payload, "event_id", "evt-app-guard-nonce-2")
               ),
               :count
             ) == 0
    end

    test "rejects duplicate signed App Guard event_id even when nonce and payload differ", %{
      conn_a: conn,
      org_a: org
    } do
      secret = put_app_guard_signing_secret("test-app-guard-secret")

      first_payload =
        app_guard_payload()
        |> put_in(["event_id"], "evt-app-guard-event-id-replay-1")
        |> put_in(["device", "device_id"], "ios-device-event-id-replay-1")

      first_raw_body = Jason.encode!(first_payload)

      first_conn =
        conn
        |> put_signed_app_guard_headers(first_raw_body, secret, nonce: "nonce-event-id-replay-1")
        |> post("/api/v1/mobile/app_guard/events", first_raw_body)

      assert json_response(first_conn, 201)["data"]["event_id"] ==
               "evt-app-guard-event-id-replay-1"

      second_payload =
        app_guard_payload()
        |> put_in(["event_id"], "evt-app-guard-event-id-replay-1")
        |> put_in(["device", "device_id"], "ios-device-event-id-replay-2")
        |> put_in(["risk", "score"], 74)

      second_raw_body = Jason.encode!(second_payload)

      replay_conn =
        conn
        |> recycle()
        |> put_req_header("authorization", List.first(get_req_header(conn, "authorization")))
        |> put_signed_app_guard_headers(second_raw_body, secret, nonce: "nonce-event-id-replay-2")
        |> post("/api/v1/mobile/app_guard/events", second_raw_body)

      body = json_response(replay_conn, 409)
      assert body["error"] == "Duplicate App Guard event replay"
      assert "duplicate App Guard event_id" in body["details"]

      assert Repo.aggregate(
               from(event in MobileEvent,
                 where:
                   event.organization_id == ^org.id and
                     fragment(
                       "?->>? = ?",
                       event.payload,
                       "event_id",
                       "evt-app-guard-event-id-replay-1"
                     )
               ),
               :count
             ) == 1
    end

    test "rejects signed App Guard requests outside timestamp replay window", %{conn_a: conn} do
      secret = put_app_guard_signing_secret("test-app-guard-secret")
      raw_body = Jason.encode!(app_guard_payload())

      stale_timestamp =
        DateTime.utc_now()
        |> DateTime.add(-600, :second)
        |> DateTime.to_iso8601()

      conn =
        conn
        |> put_signed_app_guard_headers(raw_body, secret, timestamp: stale_timestamp)
        |> post("/api/v1/mobile/app_guard/events", raw_body)

      body = json_response(conn, 401)
      assert body["error"] == "Invalid App Guard event signature"
      assert "X-Tamandua-Timestamp is outside the App Guard anti-replay window" in body["details"]
    end

    test "records unsigned compatibility limitation when signing headers are absent", %{
      conn_a: conn,
      org_a: org
    } do
      conn =
        post(
          conn,
          "/api/v1/mobile/app_guard/events",
          app_guard_payload()
          |> put_in(["event_id"], "evt-app-guard-unsigned-compat-1")
          |> put_in(["device", "device_id"], "ios-device-unsigned-compat-1")
        )

      body = json_response(conn, 201)
      event = Repo.get!(MobileEvent, body["data"]["id"])

      assert event.organization_id == org.id
      assert event.payload["server_ingestion"]["signed"] == false

      assert event.payload["server_ingestion"]["telemetry_quality"]["status"] ==
               "accepted_unsigned_compatibility"

      assert "Anti-replay checks require signed payload metadata." in event.payload[
               "server_ingestion"
             ]["telemetry_quality"]["limitations"]
    end

    test "rejects duplicate unsigned App Guard event_id replays", %{
      conn_a: conn,
      org_a: org
    } do
      payload =
        app_guard_payload()
        |> put_in(["event_id"], "evt-app-guard-unsigned-replay-1")
        |> put_in(["device", "device_id"], "ios-device-unsigned-replay-1")

      first_conn = post(conn, "/api/v1/mobile/app_guard/events", payload)

      assert json_response(first_conn, 201)["data"]["event_id"] ==
               "evt-app-guard-unsigned-replay-1"

      replay_conn =
        conn
        |> recycle()
        |> put_req_header("authorization", List.first(get_req_header(conn, "authorization")))
        |> post("/api/v1/mobile/app_guard/events", payload)

      body = json_response(replay_conn, 409)
      assert body["error"] == "Duplicate App Guard event replay"
      assert "duplicate App Guard event_id" in body["details"]

      assert Repo.aggregate(
               from(event in MobileEvent,
                 where:
                   event.organization_id == ^org.id and
                     fragment(
                       "?->>? = ?",
                       event.payload,
                       "event_id",
                       "evt-app-guard-unsigned-replay-1"
                     )
               ),
               :count
             ) == 1
    end

    test ~s(rejects signed App Guard requests without timestamp), %{conn_a: conn} do
      secret = put_app_guard_signing_secret(~s(test-app-guard-secret))
      raw_body = Jason.encode!(app_guard_payload())

      conn =
        conn
        |> put_signed_app_guard_headers(raw_body, secret, timestamp: :omit)
        |> post(~s(/api/v1/mobile/app_guard/events), raw_body)

      body = json_response(conn, 401)
      assert body[~s(error)] == ~s(Invalid App Guard event signature)
      assert ~s(X-Tamandua-Timestamp is required) in body[~s(details)]
    end

    test ~s(rejects unsigned App Guard events by default), %{conn_a: conn} do
      put_app_guard_unsigned_compatibility(false)
      conn = post(conn, ~s(/api/v1/mobile/app_guard/events), app_guard_payload())
      body = json_response(conn, 401)
      assert body[~s(error)] == ~s(Invalid App Guard event signature)
      assert ~s(signed App Guard event envelope is required) in body[~s(details)]
    end

    test ~s(never enables unsigned compatibility in production), %{conn_a: conn} do
      put_app_guard_environment(:prod)
      put_app_guard_unsigned_compatibility(true)
      conn = post(conn, ~s(/api/v1/mobile/app_guard/events), app_guard_payload())
      body = json_response(conn, 401)
      assert body[~s(error)] == ~s(Invalid App Guard event signature)
      assert ~s(signed App Guard event envelope is required) in body[~s(details)]
    end

    test ~s(accepts App Guard events signed with a file-backed SDK HMAC secret), %{
      conn_a: conn,
      org_a: org
    } do
      clear_app_guard_signing_secret()
      secret = ~s(test-app-guard-file-secret)
      raw_body = Jason.encode!(app_guard_payload())

      secret_file =
        Path.join(
          System.tmp_dir!(),
          ~s(tamandua-app-guard-secret-) <> Integer.to_string(System.unique_integer([:positive]))
        )

      File.write!(secret_file, ~s( ) <> secret <> <<10>>)
      System.put_env(~s(TAMANDUA_APP_GUARD_SIGNING_SECRET_FILE), secret_file)

      on_exit(fn -> File.rm(secret_file) end)

      conn =
        conn
        |> put_signed_app_guard_headers(raw_body, secret)
        |> post(~s(/api/v1/mobile/app_guard/events), raw_body)

      body = json_response(conn, 201)
      event = Repo.get!(MobileEvent, body[~s(data)][~s(id)])

      assert event.organization_id == org.id
      assert event.payload[~s(event_id)] == ~s(evt-app-guard-1)
    end

    test "rejects App Guard events with invalid SDK HMAC envelope", %{conn_a: conn} do
      secret = put_app_guard_signing_secret("test-app-guard-secret")
      raw_body = Jason.encode!(app_guard_payload())

      conn =
        conn
        |> put_signed_app_guard_headers(raw_body, secret,
          signature: "sha256=" <> String.duplicate("0", 64)
        )
        |> post("/api/v1/mobile/app_guard/events", raw_body)

      body = json_response(conn, 401)
      assert body["error"] == "Invalid App Guard event signature"
      assert "X-Tamandua-Signature does not match canonical payload" in body["details"]
    end

    test "rejects signed App Guard events when server signing secret is missing", %{conn_a: conn} do
      clear_app_guard_signing_secret()
      raw_body = Jason.encode!(app_guard_payload())

      conn =
        conn
        |> put_signed_app_guard_headers(raw_body, "test-app-guard-secret")
        |> post("/api/v1/mobile/app_guard/events", raw_body)

      body = json_response(conn, 401)
      assert body["error"] == "Invalid App Guard event signature"
      assert "App Guard signing secret is not configured" in body["details"]
    end

    test "rejects signed App Guard events without signing key id", %{conn_a: conn} do
      secret = put_app_guard_signing_secret("test-app-guard-secret")
      raw_body = Jason.encode!(app_guard_payload())

      conn =
        conn
        |> put_signed_app_guard_headers(raw_body, secret, signing_key_id: nil)
        |> post("/api/v1/mobile/app_guard/events", raw_body)

      body = json_response(conn, 401)
      assert body["error"] == "Invalid App Guard event signature"
      assert "X-Tamandua-Signing-Key-ID is required" in body["details"]
    end

    test "ingests RASP-derived App Guard events and creates enriched alerts", %{
      conn_a: conn,
      org_a: org
    } do
      payload =
        app_guard_payload()
        |> put_in(["event_id"], "evt-app-guard-rasp-1")
        |> put_in(["event_type"], "browser_tamper_detected")
        |> put_in(["severity"], "high")
        |> put_in(["platform"], "android")
        |> put_in(["device", "device_id"], "android-rasp-1")
        |> put_in(["device", "model"], "Pixel 8")
        |> put_in(["device", "manufacturer"], "Google")
        |> put_in(["policy_id"], "policy_app_guard_browser")
        |> put_in(["mode"], "enforce")
        |> put_in(["risk", "decision"], "step_up")
        |> put_in(["risk", "score"], 65)
        |> put_in(["risk", "thresholds"], %{"step_up" => 60, "block" => 90})
        |> put_in(["risk", "reasons"], ["automation_detected", "browser_tamper_detected"])
        |> put_in(["evidence"], %{
          "collector" => "protected-webview",
          "privacy_mode" => "metadata_only",
          "url" => "https://risk.example/login",
          "network" => %{
            "domain" => "risk.example",
            "destination_category" => "temporary_tunnel",
            "host_hash" => "sha256:example",
            "request_count" => 3
          }
        })

      conn = post(conn, "/api/v1/mobile/app_guard/events", payload)

      body = json_response(conn, 201)
      event = Repo.get!(MobileEvent, body["data"]["id"])
      alert = Repo.get!(Alert, event.alert_id)

      assert event.organization_id == org.id
      assert event.event_type == "browser_tamper_detected"
      assert event.title == "App Guard browser_tamper_detected"
      assert event.alerted == true
      assert alert.title == "[App Guard] App Guard browser_tamper_detected"
      assert alert.detection_metadata["source"] == "app_guard"
      assert alert.detection_metadata["category"] == "app_guard"
      assert alert.detection_metadata["event_type"] == "browser_tamper_detected"
      assert alert.detection_metadata["rule_id"] == "evt-app-guard-rasp-1"
      assert alert.detection_metadata["rule_name"] == "App Guard browser_tamper_detected"
      assert alert.detection_metadata["rule_type"] == "app_guard"
      assert alert.detection_metadata["type"] == "mobile_app_guard"
      assert alert.detection_metadata["policy_id"] == "policy_app_guard_browser"
      assert alert.detection_metadata["mode"] == "enforce"
      assert alert.detection_metadata["decision"] == "step_up"
      assert alert.detection_metadata["thresholds"]["block"] == 90
      assert alert.detection_metadata["device_model"] == "Pixel 8"
      assert alert.detection_metadata["device_manufacturer"] == "Google"
      assert alert.source_event_id == event.id
      assert alert.event_ids == [event.id]
      assert alert.recommended_response =~ "App Guard evidence"
      assert alert.evidence["privacy_mode"] == "metadata_only"
      assert alert.evidence["network"]["domain"] == "risk.example"
      assert alert.evidence["network"]["url"] == "https://risk.example/login"
      assert alert.evidence["risk"]["score"] == 65
      assert alert.evidence["detection"]["rule_id"] == "evt-app-guard-rasp-1"
      assert alert.evidence["detection"]["rule_type"] == "app_guard"
      assert alert.evidence["detection"]["category"] == "app_guard"
      assert alert.evidence["app_guard"]["event_type"] == "browser_tamper_detected"
      assert alert.evidence["app_guard"]["url"] == "https://risk.example/login"
      assert alert.evidence["app_guard"]["domain"] == "risk.example"

      assert alert.evidence["app_guard"]["protected_app"]["package_or_bundle_id"] ==
               "com.example.wallet"

      assert alert.evidence["app_guard"]["protected_app"]["bundle_id"] == "com.example.wallet"
      assert alert.evidence["app_guard"]["protected_app"]["version"] == "1.2.3"
      assert alert.evidence["app_guard"]["policy"]["id"] == "policy_app_guard_browser"
      assert alert.evidence["app_guard"]["decision"]["decision"] == "step_up"
      assert alert.evidence["policy"]["id"] == "policy_app_guard_browser"
      assert alert.evidence["policy"]["mode"] == "enforce"
      assert alert.evidence["decision_trace"]["decision"] == "step_up"
      assert alert.evidence["decision_trace"]["thresholds"]["step_up"] == 60

      assert Enum.any?(
               alert.evidence["iocs"],
               &match?(%{"type" => "domain", "value" => "risk.example"}, &1)
             )

      refute Enum.any?(alert.evidence["evidence_gaps"], &(&1["code"] == "iocs_not_extracted"))
      assert alert.raw_event["payload"]["evidence"]["privacy_mode"] == "metadata_only"
      assert "T1622" in alert.mitre_techniques
    end

    test "ingests commercial spyware suspected App Guard triage events", %{
      conn_a: conn,
      org_a: org
    } do
      payload =
        app_guard_payload()
        |> put_in(["event_id"], "evt-app-guard-spyware-1")
        |> put_in(["event_type"], "commercial_spyware_suspected")
        |> put_in(["severity"], "critical")
        |> put_in(["platform"], "ios")
        |> put_in(["risk", "decision"], "block")
        |> put_in(["risk", "score"], 100)
        |> put_in(["risk", "reasons"], [
          "commercial_spyware_suspected",
          "network_exfiltration_suspected",
          "integrity_snapshot_changed"
        ])
        |> put_in(["evidence"], %{
          "collector" => "app-guard-protected-app-triage",
          "privacy_mode" => "metadata_only",
          "spyware_taxonomy" => %{
            "schema" => "tamandua.app_guard.commercial_spyware_taxonomy/v1",
            "family" => "mercenary_spyware_general",
            "evidence_lane" => "protected_app_network_anomaly",
            "confidence" => "medium",
            "limitations" => [
              "suspected protected-app triage signal only",
              "not device-wide forensic evidence"
            ]
          }
        })

      conn = post(conn, "/api/v1/mobile/app_guard/events", payload)

      body = json_response(conn, 201)
      event = Repo.get!(MobileEvent, body["data"]["id"])
      alert = Repo.get!(Alert, event.alert_id)

      assert event.event_type == "commercial_spyware_suspected"
      assert event.severity == "critical"
      assert event.title == "App Guard commercial_spyware_suspected"
      assert alert.title == "[App Guard] App Guard commercial_spyware_suspected"
      assert alert.detection_metadata["source"] == "app_guard"
      assert alert.detection_metadata["event_type"] == "commercial_spyware_suspected"
      assert alert.detection_metadata["confidence"] == "medium"
      assert alert.detection_metadata["claim_boundary"] =~ "metadata-only"
      assert alert.source_event_id == event.id
      assert alert.event_ids == [event.id]
      assert alert.recommended_response =~ "mobile forensic workflow"
      assert alert.evidence["privacy_mode"] == "metadata_only"
      assert alert.evidence["spyware_taxonomy"]["confidence"] == "medium"
      assert alert.evidence["claim_boundary"] =~ "not device-wide forensic evidence"
      assert "not device-wide forensic evidence" in alert.evidence["limitations"]
      assert alert.raw_event["payload"]["evidence"]["privacy_mode"] == "metadata_only"
      assert alert.raw_event["payload"]["evidence"]["spyware_taxonomy"]["confidence"] == "medium"
      assert "T1639" in alert.mitre_techniques
      assert event.organization_id == org.id
    end

    test "does not promote synthetic App Guard parity events to customer-facing alerts", %{
      conn_a: conn,
      org_a: org
    } do
      payload =
        app_guard_payload()
        |> put_in(["event_id"], "evt_app_guard_spyware_parity_20260708070101")
        |> put_in(["event_type"], "commercial_spyware_suspected")
        |> put_in(["severity"], "critical")
        |> put_in(["platform"], "android")
        |> put_in(["device", "device_id"], "mobile-endpoint-parity-20260708070101")
        |> put_in(["device", "serial_number"], "parity-20260708070101")
        |> put_in(["risk", "decision"], "block")
        |> put_in(["risk", "score"], 100)
        |> put_in(["risk", "reasons"], ["commercial_spyware_suspected"])
        |> put_in(["evidence"], %{
          "collector" => "app-guard-protected-app-triage",
          "privacy_mode" => "metadata_only",
          "source" => "live-backend-parity",
          "parity_run_id" => "20260708070101"
        })

      conn = post(conn, "/api/v1/mobile/app_guard/events", payload)

      body = json_response(conn, 201)
      event = Repo.get!(MobileEvent, body["data"]["id"])

      assert event.event_type == "commercial_spyware_suspected"
      assert event.severity == "critical"
      assert event.organization_id == org.id
      refute event.alerted
      assert is_nil(event.alert_id)
      refute Repo.get_by(Alert, source_event_id: event.id)
    end

    test "accepts shielding interference App Guard events from the shared schema", %{
      conn_a: conn
    } do
      payload =
        app_guard_payload()
        |> put_in(["event_id"], "evt-app-guard-shielding-interference-1")
        |> put_in(["event_type"], "shielding_interference_suspected")
        |> put_in(["severity"], "medium")
        |> put_in(["platform"], "android")
        |> put_in(["risk", "decision"], "observe")
        |> put_in(["risk", "score"], 35)
        |> put_in(["risk", "reasons"], ["shielding_interference_suspected"])
        |> put_in(["evidence", "active_signals"], [
          %{
            "name" => "shielding_interference_suspected",
            "weight" => 35,
            "source" => "android_runtime",
            "category" => "rasp",
            "confidence" => "medium"
          }
        ])

      conn = post(conn, "/api/v1/mobile/app_guard/events", payload)

      body = json_response(conn, 201)
      event = Repo.get!(MobileEvent, body["data"]["id"])

      assert event.event_type == "shielding_interference_suspected"

      assert event.payload["evidence"]["active_signals"] == [
               %{
                 "name" => "shielding_interference_suspected",
                 "weight" => 35,
                 "source" => "android_runtime",
                 "category" => "rasp",
                 "confidence" => "medium"
               }
             ]
    end

    test "rejects unsupported App Guard schemas", %{conn_a: conn} do
      conn = post(conn, "/api/v1/mobile/app_guard/events", %{"schema" => "unknown"})

      assert json_response(conn, 422)["error"] == "Unsupported App Guard event schema"
    end

    test "rejects incomplete App Guard contract payloads", %{conn_a: conn} do
      payload = app_guard_payload() |> put_in(["app", "version"], "")

      conn = post(conn, "/api/v1/mobile/app_guard/events", payload)

      body = json_response(conn, 422)
      assert body["error"] == "Invalid App Guard event payload"
      assert "app.version is required" in body["details"]
    end

    test "rejects App Guard contract payloads without event ids", %{conn_a: conn} do
      payload = Map.delete(app_guard_payload(), "event_id")

      conn = post(conn, "/api/v1/mobile/app_guard/events", payload)

      body = json_response(conn, 422)
      assert body["error"] == "Invalid App Guard event payload"
      assert "event_id is required" in body["details"]
    end
  end

  describe "App Guard protected apps and build manifests" do
    test "registers and lists protected apps for the current organization", %{
      conn_a: conn,
      token_a: token,
      org_a: org
    } do
      conn = post(conn, "/api/v1/mobile/app_guard/apps", protected_app_payload())

      body = json_response(conn, 201)
      assert body["success"] == true
      assert body["data"]["schema"] == "tamandua.app_guard.protected_app/v1"
      assert body["data"]["app_id"] == "agapp_wallet_prod"
      assert body["data"]["organization_id"] == org.id
      assert body["data"]["ingestion"]["public_key_id"] == "agpk_wallet_prod_202606"
      assert body["data"]["ingestion"]["secret_ref"] =~ "vault://"
      refute Map.has_key?(body["data"]["ingestion"], "secret")

      conn = get(auth_conn(token), "/api/v1/mobile/app_guard/apps")
      list_body = json_response(conn, 200)

      assert [%{"app_id" => "agapp_wallet_prod", "policy" => %{"default_decision" => "step_up"}}] =
               list_body["data"]

      conn = get(auth_conn(token), "/api/v1/mobile/app_guard/apps/agapp_wallet_prod")
      show_body = json_response(conn, 200)
      assert show_body["data"]["package_or_bundle_id"] == "io.tamandua.appguard.samplewallet"
    end

    test "does not expose protected apps across organizations", %{
      conn_a: conn_a,
      token_b: token_b
    } do
      conn_a = post(conn_a, "/api/v1/mobile/app_guard/apps", protected_app_payload())
      assert json_response(conn_a, 201)["success"] == true

      conn_b = get(auth_conn(token_b), "/api/v1/mobile/app_guard/apps/agapp_wallet_prod")
      assert json_response(conn_b, 404)["error"] == "App Guard protected app not found"

      conn_b = get(auth_conn(token_b), "/api/v1/mobile/app_guard/apps")
      assert json_response(conn_b, 200)["data"] == []
    end

    test "stores build manifests only for registered protected apps", %{
      conn_a: conn,
      token_a: token
    } do
      missing_app_conn = post(conn, "/api/v1/mobile/app_guard/builds", build_manifest_payload())

      assert json_response(missing_app_conn, 422)["error"] ==
               "App Guard protected app must be registered before build manifests"

      conn = post(auth_conn(token), "/api/v1/mobile/app_guard/apps", protected_app_payload())
      assert json_response(conn, 201)["success"] == true

      conn = post(auth_conn(token), "/api/v1/mobile/app_guard/builds", build_manifest_payload())
      body = json_response(conn, 201)

      assert body["success"] == true
      assert body["data"]["schema"] == "tamandua.app_guard.build_manifest/v1"
      assert body["data"]["build_id"] == "agbld_wallet_android_20260627_001"
      assert body["data"]["app_id"] == "agapp_wallet_prod"
      assert body["data"]["artifact"]["sha256"] == String.duplicate("3", 64)
      assert body["data"]["signing"]["certificate_sha256"] == String.duplicate("1", 64)

      conn = get(auth_conn(token), "/api/v1/mobile/app_guard/builds?app_id=agapp_wallet_prod")
      list_body = json_response(conn, 200)
      assert [%{"build_id" => "agbld_wallet_android_20260627_001"}] = list_body["data"]
    end

    test "verifies build manifest digests without storing binary", %{
      conn_a: conn,
      token_a: token
    } do
      conn = post(conn, "/api/v1/mobile/app_guard/apps", protected_app_payload())
      assert json_response(conn, 201)["success"] == true

      conn = post(auth_conn(token), "/api/v1/mobile/app_guard/builds", build_manifest_payload())
      assert json_response(conn, 201)["success"] == true

      conn =
        post(
          auth_conn(token),
          "/api/v1/mobile/app_guard/builds/agbld_wallet_android_20260627_001/verify",
          %{
            "artifact_sha256" => String.duplicate("3", 64),
            "certificate_sha256" => String.duplicate("1", 64),
            "config_sha256" => String.duplicate("2", 64)
          }
        )

      body = json_response(conn, 200)
      assert body["data"]["schema"] == "tamandua.app_guard.build_verification/v1"
      assert body["data"]["verified"] == true
      assert body["data"]["checks"]["artifact_sha256"] == true
      assert body["data"]["checks"]["certificate_sha256"] == true
      assert body["data"]["checks"]["config_sha256"] == true
      assert body["data"]["claim_boundary"] == "metadata_only_no_binary_upload_or_fusion"

      conn =
        post(
          auth_conn(token),
          "/api/v1/mobile/app_guard/builds/agbld_wallet_android_20260627_001/verify",
          %{"artifact_sha256" => String.duplicate("a", 64)}
        )

      body = json_response(conn, 200)
      assert body["data"]["verified"] == false
      assert body["data"]["checks"]["artifact_sha256"] == false
      assert body["data"]["checks"]["certificate_sha256"] == nil
      assert body["data"]["checks"]["config_sha256"] == nil
    end

    test "build verification requires digests and is scoped by organization", %{
      conn_a: conn,
      token_a: token_a,
      token_b: token_b
    } do
      conn = post(conn, "/api/v1/mobile/app_guard/apps", protected_app_payload())
      assert json_response(conn, 201)["success"] == true

      conn = post(auth_conn(token_a), "/api/v1/mobile/app_guard/builds", build_manifest_payload())
      assert json_response(conn, 201)["success"] == true

      conn =
        post(
          auth_conn(token_a),
          "/api/v1/mobile/app_guard/builds/agbld_wallet_android_20260627_001/verify",
          %{}
        )

      assert json_response(conn, 422)["error"] =~ "at least one"

      conn =
        post(
          auth_conn(token_b),
          "/api/v1/mobile/app_guard/builds/agbld_wallet_android_20260627_001/verify",
          %{"artifact_sha256" => String.duplicate("3", 64)}
        )

      assert json_response(conn, 404)["error"] == "Build manifest not found"
    end

    test "rejects unsupported protected app and build schemas", %{conn_a: conn, token_a: token} do
      conn = post(conn, "/api/v1/mobile/app_guard/apps", %{"schema" => "unknown"})
      assert json_response(conn, 422)["error"] == "Unsupported App Guard protected app schema"

      conn = post(auth_conn(token), "/api/v1/mobile/app_guard/builds", %{"schema" => "unknown"})
      assert json_response(conn, 422)["error"] == "Unsupported App Guard build manifest schema"
    end
  end

  describe "App Guard research programs and reviewer submissions" do
    test "creates research programs, queues submissions, and stores reviewer validation", %{
      conn_a: conn,
      token_a: token,
      org_a: org
    } do
      conn = post(conn, "/api/v1/mobile/app_guard/research/programs", research_program_payload())
      program_body = json_response(conn, 201)

      assert program_body["success"] == true
      assert program_body["data"]["schema"] == "tamandua.app_guard.research_program/v1"
      assert program_body["data"]["program_id"] == "agres_wallet_private_202606"
      assert program_body["data"]["organization_id"] == org.id

      assert [%{"target_type" => "build_manifest"}] =
               Enum.filter(
                 program_body["data"]["scope"]["targets"],
                 &(&1["target_type"] == "build_manifest")
               )

      conn =
        post(
          auth_conn(token),
          "/api/v1/mobile/app_guard/research/submissions",
          research_submission_payload()
        )

      submission_body = json_response(conn, 201)

      assert submission_body["success"] == true
      assert submission_body["data"]["schema"] == "tamandua.app_guard.research_submission/v1"
      assert submission_body["data"]["submission_id"] == "agsub_wallet_withdrawal_hook_001"
      assert submission_body["data"]["status"] == "submitted"

      assert submission_body["data"]["evidence_links"]["app_guard_event_ids"] == [
               "evt_app_guard_20260626_0001"
             ]

      conn =
        post(
          auth_conn(token),
          "/api/v1/mobile/app_guard/research/submissions/agsub_wallet_withdrawal_hook_001/validate",
          %{
            "status" => "needs_more_info",
            "decision" => "needs_more_info",
            "reviewer_id" => "reviewer_appguard_triage_001",
            "notes" => "Need physical-device proof before acceptance.",
            "reviewed_at" => "2026-06-28T01:00:00Z"
          }
        )

      validation_body = json_response(conn, 200)
      assert validation_body["success"] == true
      assert validation_body["data"]["status"] == "needs_more_info"
      assert validation_body["data"]["validation"]["decision"] == "needs_more_info"

      conn =
        get(
          auth_conn(token),
          "/api/v1/mobile/app_guard/research/submissions?program_id=agres_wallet_private_202606"
        )

      list_body = json_response(conn, 200)
      assert [%{"submission_id" => "agsub_wallet_withdrawal_hook_001"}] = list_body["data"]
    end

    test "does not expose research programs or submissions across organizations", %{
      conn_a: conn_a,
      token_a: token_a,
      token_b: token_b
    } do
      conn_a =
        post(conn_a, "/api/v1/mobile/app_guard/research/programs", research_program_payload())

      assert json_response(conn_a, 201)["success"] == true

      conn_a =
        post(
          auth_conn(token_a),
          "/api/v1/mobile/app_guard/research/submissions",
          research_submission_payload()
        )

      assert json_response(conn_a, 201)["success"] == true

      conn_b = get(auth_conn(token_b), "/api/v1/mobile/app_guard/research/programs")
      assert json_response(conn_b, 200)["data"] == []

      conn_b = get(auth_conn(token_b), "/api/v1/mobile/app_guard/research/submissions")
      assert json_response(conn_b, 200)["data"] == []

      conn_b =
        post(
          auth_conn(token_b),
          "/api/v1/mobile/app_guard/research/submissions/agsub_wallet_withdrawal_hook_001/validate",
          %{
            "status" => "accepted",
            "decision" => "accepted",
            "reviewer_id" => "cross-tenant-reviewer"
          }
        )

      assert json_response(conn_b, 404)["error"] == "App Guard research submission not found"
    end

    test "rejects submissions outside program build-manifest scope", %{
      conn_a: conn,
      token_a: token
    } do
      conn = post(conn, "/api/v1/mobile/app_guard/research/programs", research_program_payload())
      assert json_response(conn, 201)["success"] == true

      payload =
        research_submission_payload()
        |> put_in(["evidence_links", "fixed_build_manifest_ids"], ["agbld_out_of_scope"])

      conn = post(auth_conn(token), "/api/v1/mobile/app_guard/research/submissions", payload)

      assert json_response(conn, 422)["error"] ==
               "App Guard research submission evidence is outside program scope"
    end

    test "rejects uninvited researchers for private programs", %{conn_a: conn, token_a: token} do
      conn = post(conn, "/api/v1/mobile/app_guard/research/programs", research_program_payload())
      assert json_response(conn, 201)["success"] == true

      payload =
        research_submission_payload()
        |> put_in(["researcher_id"], "researcher_not_invited")

      conn = post(auth_conn(token), "/api/v1/mobile/app_guard/research/submissions", payload)

      assert json_response(conn, 403)["error"] ==
               "App Guard research submission researcher is not invited to this private program"
    end

    test "rejects unsupported research schemas", %{conn_a: conn, token_a: token} do
      conn = post(conn, "/api/v1/mobile/app_guard/research/programs", %{"schema" => "unknown"})
      assert json_response(conn, 422)["error"] == "Unsupported App Guard research program schema"

      conn =
        post(auth_conn(token), "/api/v1/mobile/app_guard/research/submissions", %{
          "schema" => "unknown"
        })

      assert json_response(conn, 422)["error"] ==
               "Unsupported App Guard research submission schema"
    end
  end

  describe "legacy mobile device tenant isolation" do
    test "enrolls the current mobile app endpoint idempotently", %{
      conn_a: conn,
      org_a: org
    } do
      payload = %{
        "device_id" => "tmnd-mobile-app-1",
        "platform" => "android",
        "model" => "Moto G9",
        "manufacturer" => "Motorola",
        "os_version" => "15",
        "agent_version" => "1.0.0+42",
        "user_email" => "victor@test.com",
        "custom_attributes" => %{
          "app_ownership" => "tamandua_mobile_endpoint"
        }
      }

      conn = post(conn, "/api/v1/mobile/devices/enroll", payload)

      body = json_response(conn, 201)
      assert body["data"]["device_id"] == "tmnd-mobile-app-1"
      assert body["data"]["platform"] == "android"
      assert body["data"]["status"] == "active"
      assert body["message"] == "Device enrolled successfully."

      device = Mobile.get_device_by_device_id(org.id, "tmnd-mobile-app-1")
      assert device.user_email == "victor@test.com"
      assert device.custom_attributes["app_ownership"] == "tamandua_mobile_endpoint"
      assert device.status == "active"

      agent = Repo.get_by!(Agent, organization_id: org.id, machine_id: "tmnd-mobile-app-1")
      assert agent.hostname == "Moto G9"
      assert agent.os_type == "android"
      assert agent.os_version == "15"
      assert agent.agent_version == "1.0.0+42"
      assert agent.status == "online"
      assert agent.config["source"] == "tamandua_mobile"
      assert agent.config["mobile_device_id"] == device.id
      assert "mobile_endpoint" in agent.tags

      conn =
        post(conn, "/api/v1/mobile/devices/enroll", Map.put(payload, "model", "Moto G9 Play"))

      body = json_response(conn, 201)
      assert body["data"]["id"] == device.id
      assert body["data"]["model"] == "Moto G9 Play"

      assert Repo.get_by!(Agent, organization_id: org.id, machine_id: "tmnd-mobile-app-1").hostname ==
               "Moto G9 Play"

      assert Repo.aggregate(
               from(a in Agent,
                 where: a.organization_id == ^org.id and a.machine_id == ^"tmnd-mobile-app-1"
               ),
               :count
             ) == 1

      assert length(elem(Mobile.list_devices(org.id), 0)) == 1
    end

    test "does not expose another organization's legacy mobile device", %{
      conn_b: conn,
      org_a: org_a
    } do
      {:ok, device} =
        Mobile.register_device(%{
          "organization_id" => org_a.id,
          "device_id" => "org-a-phone",
          "platform" => "android",
          "model" => "Pixel"
        })

      conn = get(conn, "/api/v1/mobile/devices/#{device.id}")

      assert json_response(conn, 404)["error"] == "Device not found"
    end

    test "updates and reads posture through external mobile install id", %{
      conn_a: conn,
      org_a: org
    } do
      {:ok, device} =
        Mobile.register_device(%{
          "organization_id" => org.id,
          "device_id" => "tmnd-posture-readback-1",
          "platform" => "android",
          "model" => "Moto G9"
        })

      payload = %{
        "collected_at" => "2026-07-04T14:47:55Z",
        "last_seen" => "2026-07-04T14:47:55Z",
        "security_checks" => %{
          "jailbroken_or_rooted" => true,
          "passcode_enabled" => true,
          "encryption_enabled" => true,
          "developer_mode" => true,
          "adb_enabled" => true,
          "foreground_service_running" => true
        }
      }

      conn = post(conn, "/api/v1/mobile/devices/tmnd-posture-readback-1/posture", payload)
      body = json_response(conn, 200)["data"]

      assert body["risk_score"] == 60
      assert "jailbroken_or_rooted" in body["risk_factors"]
      assert "developer_mode_enabled" in body["risk_factors"]
      assert "usb_debugging_enabled" in body["risk_factors"]

      updated = Mobile.get_device_by_device_id(org.id, "tmnd-posture-readback-1")
      assert updated.id == device.id
      assert updated.last_seen_at == ~N[2026-07-04 14:47:55]
      assert updated.is_rooted == true
      assert updated.passcode_enabled == true
      assert updated.encryption_enabled == true
      assert updated.developer_mode_enabled == true
      assert updated.usb_debugging_enabled == true

      agent = Repo.get_by!(Agent, organization_id: org.id, machine_id: "tmnd-posture-readback-1")
      assert agent.last_seen_at == ~N[2026-07-04 14:47:55]
      assert agent.status == "online"

      conn = get(conn, "/api/v1/mobile/devices/tmnd-posture-readback-1/posture")
      posture = json_response(conn, 200)["data"]

      assert posture["id"] == device.id
      assert posture["device_id"] == "tmnd-posture-readback-1"
      assert posture["external_device_id"] == "tmnd-posture-readback-1"
      assert posture["last_assessment"] == "2026-07-04T14:47:55"
      assert posture["security_checks"]["jailbroken_or_rooted"] == true
      assert posture["security_checks"]["developer_mode"] == true
      assert posture["security_checks"]["usb_debugging"] == true
    end
  end

  defp grant_permission!(user, organization, permission_slug) do
    permission_slug_string = Atom.to_string(permission_slug)

    permission =
      Repo.get_by(Permission, slug: permission_slug_string) ||
        %Permission{}
        |> Permission.changeset(%{
          name: permission_slug_string,
          slug: permission_slug_string,
          description: Permission.description(permission_slug) || permission_slug_string,
          category: "response"
        })
        |> Repo.insert!()

    role =
      %Role{}
      |> Role.changeset(%{
        name: "Mobile response test role",
        slug: "mobile_response_test_#{user.id}",
        builtin: false,
        priority: 70,
        organization_id: organization.id
      })
      |> Repo.insert!()

    %RolePermission{}
    |> RolePermission.changeset(%{
      role_id: role.id,
      permission_id: permission.id
    })
    |> Repo.insert!()

    %UserRole{}
    |> UserRole.changeset(%{
      user_id: user.id,
      role_id: role.id,
      granted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    })
    |> Repo.insert!()
  end

  defp app_guard_payload do
    %{
      "schema" => "tamandua.app_guard.event/v1",
      "event_id" => "evt-app-guard-1",
      "event_type" => "emulator_detected",
      "severity" => "medium",
      "timestamp" => "2026-06-26T12:00:00Z",
      "platform" => "iOS",
      "device" => %{
        "device_id" => "ios-device-1",
        "model" => "iPhone 15",
        "manufacturer" => "Apple",
        "os_version" => "18.5",
        "managed" => true
      },
      "app" => %{
        "package_or_bundle_id" => "com.example.wallet",
        "display_name" => "Example Wallet",
        "version" => "1.2.3"
      },
      "risk" => %{
        "decision" => "observe",
        "score" => 72,
        "reasons" => ["emulator_detected"]
      },
      "evidence" => %{
        "domain" => "risk.example",
        "remote_address" => "203.0.113.10",
        "remote_port" => 443
      }
    }
  end

  defp auth_conn(token) do
    build_conn()
    |> put_req_header("authorization", "Bearer #{token}")
  end

  defp protected_app_payload do
    %{
      "schema" => "tamandua.app_guard.protected_app/v1",
      "app_id" => "agapp_wallet_prod",
      "organization_id" => "client-supplied-org-is-ignored",
      "display_name" => "Tamandua Sample Wallet",
      "platform" => "android",
      "package_or_bundle_id" => "io.tamandua.appguard.samplewallet",
      "status" => "active",
      "ingestion" => %{
        "public_key_id" => "agpk_wallet_prod_202606",
        "secret_ref" => "vault://tamandua/app_guard/agapp_wallet_prod/ingestion_hmac",
        "hmac_algorithm" => "HMAC-SHA256",
        "rate_limit_per_minute" => 1200,
        "allowed_origins" => ["app://io.tamandua.appguard.samplewallet"],
        "allowed_ip_cidrs" => [],
        "rotation" => %{
          "status" => "current",
          "last_rotated_at" => "2026-06-27T00:00:00Z",
          "next_rotation_due_at" => "2026-09-27T00:00:00Z"
        }
      },
      "policy" => %{
        "policy_id" => "policy_app_guard_default",
        "protected_workflows" => ["login", "withdrawal", "transaction_signing"],
        "default_decision" => "step_up"
      },
      "created_at" => "2026-06-27T00:00:00Z",
      "updated_at" => "2026-06-27T00:00:00Z"
    }
  end

  defp build_manifest_payload do
    %{
      "schema" => "tamandua.app_guard.build_manifest/v1",
      "build_id" => "agbld_wallet_android_20260627_001",
      "app_id" => "agapp_wallet_prod",
      "platform" => "android",
      "version" => %{"name" => "1.0.0", "code" => "100"},
      "artifact" => %{
        "type" => "apk",
        "filename" => "sample-wallet-debug.apk",
        "sha256" => String.duplicate("3", 64),
        "size_bytes" => 846_357
      },
      "signing" => %{
        "scheme" => "android_apk_signature_v2_v3",
        "certificate_sha256" => String.duplicate("1", 64),
        "key_alias" => "tamandua-app-guard-sample"
      },
      "sdk" => %{
        "version" => "0.1.0",
        "config_sha256" => String.duplicate("2", 64),
        "enabled_signals" => ["root_detected", "debugger_detected", "hook_framework_detected"]
      },
      "policy_id" => "policy_app_guard_default",
      "created_at" => "2026-06-27T00:00:00Z"
    }
  end

  defp research_program_payload do
    %{
      "schema" => "tamandua.app_guard.research_program/v1",
      "program_id" => "agres_wallet_private_202606",
      "organization_id" => "client-supplied-org-is-ignored",
      "app" => %{
        "platform" => "android",
        "package_or_bundle_id" => "io.tamandua.appguard.samplewallet",
        "display_name" => "Tamandua Sample Wallet",
        "allowed_versions" => ["1.0.0"],
        "protected_workflows" => ["login", "withdrawal", "transaction_signing"]
      },
      "name" => "Sample Wallet Private App Guard Program",
      "description" => "Private validation program for App Guard mobile runtime protections.",
      "status" => "beta",
      "visibility" => "private",
      "program_type" => "app_guard_assessment",
      "scope" => %{
        "targets" => [
          %{
            "target_type" => "mobile_app",
            "value" => "io.tamandua.appguard.samplewallet",
            "description" => "Protected Android sample wallet application"
          },
          %{
            "target_type" => "workflow",
            "value" => "withdrawal",
            "description" => "High-risk protected transaction workflow"
          },
          %{
            "target_type" => "build_manifest",
            "value" => "agbld_wallet_android_20260627_001",
            "description" => "Known App Guard SDK build manifest under assessment"
          }
        ],
        "out_of_scope" => [
          "production customer data",
          "destructive testing",
          "social engineering"
        ]
      },
      "rules" =>
        "Submit metadata-only proof of concept details, App Guard event IDs, and reproduction steps.",
      "reward" => %{"currency" => "USD", "budget" => 5000},
      "invited_researchers" => ["researcher_mobile_redteam_001"],
      "created_at" => "2026-06-28T00:00:00Z",
      "updated_at" => "2026-06-28T00:00:00Z"
    }
  end

  defp research_submission_payload do
    %{
      "schema" => "tamandua.app_guard.research_submission/v1",
      "submission_id" => "agsub_wallet_withdrawal_hook_001",
      "program_id" => "agres_wallet_private_202606",
      "researcher_id" => "researcher_mobile_redteam_001",
      "title" => "Withdrawal workflow can be forced into hook-framework block path",
      "description" => "A controlled test build produced a high-risk App Guard event.",
      "severity" => "high",
      "status" => "submitted",
      "cvss" => %{
        "score" => 8.1,
        "vector" => "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"
      },
      "technical_details" => %{
        "vulnerability_type" => "runtime_hooking",
        "proof_of_concept" => "Metadata-only proof linked to App Guard event evidence.",
        "reproduction_steps" => [
          "Install the protected sample wallet build.",
          "Launch the withdrawal workflow.",
          "Attach the approved lab hook framework profile.",
          "Attempt to alter the withdrawal amount.",
          "Confirm App Guard emits the linked event and blocks the workflow."
        ],
        "impact" => "The reviewer can validate policy and telemetry coverage.",
        "recommendation" => "Require physical-device evidence before acceptance."
      },
      "evidence_links" => %{
        "app_guard_event_ids" => ["evt_app_guard_20260626_0001"],
        "mobile_session_ids" => ["mobile-session-appguard-001"],
        "detection_validation_run_ids" => ["dv-appguard-native-compromise-20260628"],
        "fixed_build_manifest_ids" => ["agbld_wallet_android_20260627_001"]
      },
      "attachments" => [
        %{
          "attachment_id" => "att_wallet_hook_repro_log_001",
          "filename" => "wallet-hook-reproduction-redacted.json",
          "content_type" => "application/json",
          "sha256" => String.duplicate("a", 64),
          "size_bytes" => 2048
        }
      ],
      "submitted_at" => "2026-06-28T00:30:00Z"
    }
  end

  defp put_app_guard_signing_secret(secret) do
    previous = Application.get_env(:tamandua_server, :app_guard_signing_secret)
    Application.put_env(:tamandua_server, :app_guard_signing_secret, secret)

    on_exit(fn ->
      if is_nil(previous) do
        Application.delete_env(:tamandua_server, :app_guard_signing_secret)
      else
        Application.put_env(:tamandua_server, :app_guard_signing_secret, previous)
      end
    end)

    secret
  end

  defp clear_app_guard_signing_secret do
    previous = Application.get_env(:tamandua_server, :app_guard_signing_secret)
    previous_app_guard_env = System.get_env(~s(TAMANDUA_APP_GUARD_SIGNING_SECRET))
    previous_mobile_sdk_env = System.get_env(~s(TAMANDUA_MOBILE_SDK_SIGNING_SECRET))
    previous_app_guard_file_env = System.get_env(~s(TAMANDUA_APP_GUARD_SIGNING_SECRET_FILE))
    previous_mobile_sdk_file_env = System.get_env(~s(TAMANDUA_MOBILE_SDK_SIGNING_SECRET_FILE))

    Application.delete_env(:tamandua_server, :app_guard_signing_secret)
    System.delete_env(~s(TAMANDUA_APP_GUARD_SIGNING_SECRET))
    System.delete_env(~s(TAMANDUA_MOBILE_SDK_SIGNING_SECRET))
    System.delete_env(~s(TAMANDUA_APP_GUARD_SIGNING_SECRET_FILE))
    System.delete_env(~s(TAMANDUA_MOBILE_SDK_SIGNING_SECRET_FILE))

    on_exit(fn ->
      if is_nil(previous) do
        Application.delete_env(:tamandua_server, :app_guard_signing_secret)
      else
        Application.put_env(:tamandua_server, :app_guard_signing_secret, previous)
      end

      restore_env(~s(TAMANDUA_APP_GUARD_SIGNING_SECRET), previous_app_guard_env)
      restore_env(~s(TAMANDUA_MOBILE_SDK_SIGNING_SECRET), previous_mobile_sdk_env)
      restore_env(~s(TAMANDUA_APP_GUARD_SIGNING_SECRET_FILE), previous_app_guard_file_env)
      restore_env(~s(TAMANDUA_MOBILE_SDK_SIGNING_SECRET_FILE), previous_mobile_sdk_file_env)
    end)
  end

  defp restore_env(name, nil), do: System.delete_env(name)
  defp restore_env(name, value), do: System.put_env(name, value)

  defp put_signed_app_guard_headers(conn, raw_body, secret, opts \\ []) do
    signing_payload = Keyword.get(opts, :signing_payload, raw_body)
    signature = Keyword.get(opts, :signature, "sha256=" <> hmac_sha256(secret, signing_payload))
    signing_key_id = Keyword.get(opts, :signing_key_id, "test-key-1")

    conn =
      conn
      |> put_req_header("content-type", "application/json")
      |> put_req_header("x-tamandua-payload-sha256", sha256(signing_payload))
      |> put_req_header("x-tamandua-signature-algorithm", "HMAC-SHA256")
      |> put_req_header("x-tamandua-signature", signature)

    if is_nil(signing_key_id) do
      conn
    else
      conn
      |> put_req_header("x-tamandua-signing-key-id", signing_key_id)
      |> maybe_put_signed_app_guard_header("x-tamandua-timestamp", Keyword.get(opts, :timestamp))
      |> maybe_put_signed_app_guard_header("x-tamandua-nonce", Keyword.get(opts, :nonce))
    end
  end

  defp maybe_put_signed_app_guard_header(conn, name, nil) do
    if name == ~s(x-tamandua-timestamp) do
      timestamp = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
      put_req_header(conn, name, timestamp)
    else
      conn
    end
  end

  defp maybe_put_signed_app_guard_header(conn, _name, :omit), do: conn
  defp maybe_put_signed_app_guard_header(conn, name, value), do: put_req_header(conn, name, value)

  defp sha256(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)

  defp app_guard_replay_reservation_count(
         organization_id,
         signing_key_id,
         reservation_type,
         value
       ) do
    %{rows: [[count]]} =
      Repo.query!(
        """
        SELECT count(*)
        FROM app_guard_replay_reservations
        WHERE organization_id = $1
          AND signing_key_id = $2
          AND reservation_type = $3
          AND reservation_value = $4
        """,
        [organization_id, signing_key_id, reservation_type, value]
      )

    count
  end

  defp hmac_sha256(secret, value) do
    :crypto.mac(:hmac, :sha256, secret, value) |> Base.encode16(case: :lower)
  end

  defp canonical_json(value) when is_map(value) do
    encoded =
      value
      |> Enum.sort_by(fn {key, _value} -> to_string(key) end)
      |> Enum.map(fn {key, item} ->
        Jason.encode!(to_string(key)) <> ":" <> canonical_json(item)
      end)
      |> Enum.join(",")

    "{" <> encoded <> "}"
  end

  defp canonical_json(value) when is_list(value) do
    encoded =
      value
      |> Enum.map(&canonical_json/1)
      |> Enum.join(",")

    "[" <> encoded <> "]"
  end

  defp canonical_json(value), do: Jason.encode!(value)

  defp put_app_guard_unsigned_compatibility(enabled) do
    previous = Application.get_env(:tamandua_server, :allow_unsigned_app_guard_ingestion)
    Application.put_env(:tamandua_server, :allow_unsigned_app_guard_ingestion, enabled)

    on_exit(fn ->
      if is_nil(previous) do
        Application.delete_env(:tamandua_server, :allow_unsigned_app_guard_ingestion)
      else
        Application.put_env(:tamandua_server, :allow_unsigned_app_guard_ingestion, previous)
      end
    end)
  end

  defp put_app_guard_environment(environment) do
    previous = Application.get_env(:tamandua_server, :env)
    Application.put_env(:tamandua_server, :env, environment)

    on_exit(fn ->
      if is_nil(previous) do
        Application.delete_env(:tamandua_server, :env)
      else
        Application.put_env(:tamandua_server, :env, previous)
      end
    end)
  end
end
