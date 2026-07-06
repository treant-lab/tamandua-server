defmodule TamanduaServerWeb.Controllers.API.V1.MobileControllerAppGuardTest do
  use TamanduaServerWeb.ConnCase, async: false

  import Ecto.Query
  import TamanduaServer.Factory

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Accounts.{Permission, Role, RolePermission, UserRole}
  alias TamanduaServer.Mobile
  alias TamanduaServer.Mobile.MDMCommand
  alias TamanduaServer.Mobile.MobileEvent
  alias TamanduaServer.Repo

  setup %{conn: conn} do
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
          inserted_at: ~U[2026-07-05 10:00:00Z],
          updated_at: ~U[2026-07-05 10:01:00Z]
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
          inserted_at: ~U[2026-07-05 10:05:00Z],
          updated_at: ~U[2026-07-05 10:06:00Z]
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
      assert Enum.map(body["commands"], & &1["id"]) == ["locate", "lock", "wipe"]
      assert Enum.find(body["commands"], &(&1["id"] == "locate"))["execution_scope"] == "mobile_app_endpoint"
      assert Enum.find(body["commands"], &(&1["id"] == "lock"))["execution_scope"] == "mdm_provider"
      assert Enum.find(body["commands"], &(&1["id"] == "wipe"))["supported_by_mobile_app"] == false
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

      assert Enum.any?(timeline, fn row ->
               row["id"] == event.id and row["agentId"] == agent.id and
                 row["details"]["mobile_device_id"] == "android-agent-filter-1"
             end)
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
          "passcode_set" => true
        })

      body = json_response(conn, 201)["data"]

      assert body["device_id"] == "android-v2-contract-1"
      assert body["platform"] == "android"
      assert body["mdm_enrolled"] == true
      assert body["agent_id"]

      agent = Repo.get_by!(Agent, organization_id: org.id, machine_id: "android-v2-contract-1")
      assert agent.id == body["agent_id"]
      assert agent.os_type == "android"
      assert "mobile-v2" in agent.tags

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
      assert overview["app_guard"]["total_recent_events"] == 1
      assert [%{"payload" => %{"event_id" => "evt-android-v2-contract-1"}}] =
               overview["app_guard"]["events"]

      conn = get(conn_b, "/api/v1/mobile/v2/devices?platform=android")
      assert json_response(conn, 200)["data"] == []
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
      assert alert.agent_id != nil
      assert alert.severity == "high"
      assert alert.title == "[App Guard] App Guard debugger_detected"
      assert alert.detection_metadata["source"] == "app_guard"
      assert alert.detection_metadata["event_type"] == "debugger_detected"
      assert alert.detection_metadata["app_bundle_id"] == "com.example.wallet"
      assert alert.raw_event["mobile_event_id"] == event.id
      assert alert.raw_event["payload"]["risk"]["decision"] == "step_up"
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

      assert event.organization_id == org.id
      assert event.payload["schema"] == "tamandua.app_guard.event/v1"
      assert event.payload["event_id"] == "evt-app-guard-1"
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
      assert "X-Tamandua-Signature does not match request body" in body["details"]
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

    test "ingests RASP-derived App Guard events and creates alerts", %{conn_a: conn, org_a: org} do
      payload =
        app_guard_payload()
        |> put_in(["event_id"], "evt-app-guard-rasp-1")
        |> put_in(["event_type"], "network_exfiltration_suspected")
        |> put_in(["severity"], "high")
        |> put_in(["platform"], "android")
        |> put_in(["device", "device_id"], "android-rasp-1")
        |> put_in(["device", "model"], "Pixel 8")
        |> put_in(["device", "manufacturer"], "Google")
        |> put_in(["risk", "decision"], "step_up")
        |> put_in(["risk", "score"], 65)
        |> put_in(["risk", "reasons"], ["automation_detected", "network_exfiltration_suspected"])
        |> put_in(["evidence"], %{
          "collector" => "protected-webview",
          "privacy_mode" => "metadata_only",
          "network" => %{
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
      assert event.event_type == "network_exfiltration_suspected"
      assert event.title == "App Guard network_exfiltration_suspected"
      assert event.alerted == true
      assert alert.title == "[App Guard] App Guard network_exfiltration_suspected"
      assert alert.detection_metadata["source"] == "app_guard"
      assert alert.detection_metadata["event_type"] == "network_exfiltration_suspected"
      assert alert.raw_event["payload"]["evidence"]["privacy_mode"] == "metadata_only"
      assert "T1446" in alert.mitre_techniques
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
          "collector" => "app-guard-commercial-spyware-triage",
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
      assert alert.raw_event["payload"]["evidence"]["privacy_mode"] == "metadata_only"
      assert alert.raw_event["payload"]["evidence"]["spyware_taxonomy"]["confidence"] == "medium"
      assert "T1639" in alert.mitre_techniques
      assert event.organization_id == org.id
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
    previous_app_guard_env = System.get_env("TAMANDUA_APP_GUARD_SIGNING_SECRET")
    previous_mobile_sdk_env = System.get_env("TAMANDUA_MOBILE_SDK_SIGNING_SECRET")
    Application.delete_env(:tamandua_server, :app_guard_signing_secret)
    System.delete_env("TAMANDUA_APP_GUARD_SIGNING_SECRET")
    System.delete_env("TAMANDUA_MOBILE_SDK_SIGNING_SECRET")

    on_exit(fn ->
      if is_nil(previous) do
        Application.delete_env(:tamandua_server, :app_guard_signing_secret)
      else
        Application.put_env(:tamandua_server, :app_guard_signing_secret, previous)
      end

      restore_env("TAMANDUA_APP_GUARD_SIGNING_SECRET", previous_app_guard_env)
      restore_env("TAMANDUA_MOBILE_SDK_SIGNING_SECRET", previous_mobile_sdk_env)
    end)
  end

  defp restore_env(name, nil), do: System.delete_env(name)
  defp restore_env(name, value), do: System.put_env(name, value)

  defp put_signed_app_guard_headers(conn, raw_body, secret, opts \\ []) do
    signature = Keyword.get(opts, :signature, "sha256=" <> hmac_sha256(secret, raw_body))
    signing_key_id = Keyword.get(opts, :signing_key_id, "test-key-1")

    conn =
      conn
      |> put_req_header("content-type", "application/json")
      |> put_req_header("x-tamandua-payload-sha256", sha256(raw_body))
      |> put_req_header("x-tamandua-signature-algorithm", "HMAC-SHA256")
      |> put_req_header("x-tamandua-signature", signature)

    if is_nil(signing_key_id) do
      conn
    else
      put_req_header(conn, "x-tamandua-signing-key-id", signing_key_id)
    end
  end

  defp sha256(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)

  defp hmac_sha256(secret, value) do
    :crypto.mac(:hmac, :sha256, secret, value) |> Base.encode16(case: :lower)
  end
end
