defmodule TamanduaServerWeb.Controllers.API.V1.MobileControllerAppGuardTest do
  use TamanduaServerWeb.ConnCase, async: true

  import TamanduaServer.Factory

  alias TamanduaServer.Mobile
  alias TamanduaServer.Mobile.MobileEvent
  alias TamanduaServer.Repo

  setup %{conn: conn} do
    {org_a, _agent_a} = create_agent_with_org()
    user_a = insert!(:user, %{organization_id: org_a.id, role: "admin"})
    {:ok, token_a, _claims} = TamanduaServer.Guardian.encode_and_sign(user_a)

    {other_org, _agent_b} = create_agent_with_org()
    user_b = insert!(:user, %{organization_id: other_org.id, role: "admin"})
    {:ok, token_b, _claims} = TamanduaServer.Guardian.encode_and_sign(user_b)

    %{
      conn_a: put_req_header(conn, "authorization", "Bearer #{token_a}"),
      conn_b: put_req_header(conn, "authorization", "Bearer #{token_b}"),
      org_a: org_a
    }
  end

  describe "POST /api/v1/mobile/app_guard/events" do
    test "ingests App Guard SDK events as mobile telemetry", %{conn_a: conn, org_a: org} do
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
    end

    test "rejects unsupported App Guard schemas", %{conn_a: conn} do
      conn = post(conn, "/api/v1/mobile/app_guard/events", %{"schema" => "unknown"})

      assert json_response(conn, 422)["error"] == "Unsupported App Guard event schema"
    end
  end

  describe "legacy mobile device tenant isolation" do
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
        "display_name" => "Example Wallet"
      },
      "risk" => %{
        "decision" => "monitor",
        "score" => 72,
        "reasons" => ["emulator"]
      },
      "evidence" => %{
        "domain" => "risk.example",
        "remote_address" => "203.0.113.10",
        "remote_port" => 443
      }
    }
  end
end
