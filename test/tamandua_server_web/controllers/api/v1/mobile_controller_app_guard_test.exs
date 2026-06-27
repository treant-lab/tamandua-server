defmodule TamanduaServerWeb.Controllers.API.V1.MobileControllerAppGuardTest do
  use TamanduaServerWeb.ConnCase, async: false

  import TamanduaServer.Factory

  alias TamanduaServer.Alerts.Alert
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

      assert event.alerted == true
      assert event.organization_id == org.id
      assert alert.organization_id == org.id
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
        |> put_signed_app_guard_headers(raw_body, secret, signature: "sha256=" <> String.duplicate("0", 64))
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
