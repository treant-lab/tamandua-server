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
      token_a: token_a,
      token_b: token_b,
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
