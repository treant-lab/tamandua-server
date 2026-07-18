defmodule TamanduaServerWeb.API.V1.MobileSignedPostureControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.{Role, UserRole}

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentity,
    MobileDeviceIdentityChallenge,
    MobileDeviceIdentityKey,
    MobileSignedPostureRequest,
    SignedPosture
  }

  alias TamanduaServer.Repo

  @now ~U[2026-07-16 12:00:00.000000Z]

  setup %{conn: conn} do
    organization = insert(:organization)
    admin = insert(:user, organization_id: organization.id)
    viewer = insert(:user, organization_id: organization.id)

    role =
      Repo.insert!(%Role{
        name: "Signed posture admin",
        slug: "admin",
        builtin: true,
        priority: 100,
        organization_id: organization.id
      })

    Repo.insert!(%UserRole{
      user_id: admin.id,
      role_id: role.id,
      granted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    })

    base =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header("content-type", "application/json")

    admin_conn =
      base
      |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(admin)}")
      |> assign(:current_user, admin)
      |> assign(:current_organization_id, organization.id)

    viewer_conn =
      base
      |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(viewer)}")
      |> assign(:current_user, viewer)
      |> assign(:current_organization_id, organization.id)

    {:ok, conn: admin_conn, viewer_conn: viewer_conn, organization: organization}
  end

  test "requires authentication and agents_update on every action", %{viewer_conn: viewer_conn} do
    assert post(build_conn(), "/api/v1/mobile/signed-posture/challenge", %{
             "installation_id" => "tmnd-http"
           })
           |> json_response(401)

    responses = [
      post(viewer_conn, "/api/v1/mobile/signed-posture/challenge", %{
        "installation_id" => "tmnd-http"
      }),
      post(viewer_conn, "/api/v1/mobile/signed-posture", %{
        "envelope" => %{},
        "posture" => %{}
      }),
      get(viewer_conn, "/api/v1/mobile/signed-posture/requests/not-authorized")
    ]

    for response <- responses do
      assert %{"required_permission" => "agents_update"} = json_response(response, 403)
      assert get_resp_header(response, "cache-control") == ["no-store"]
    end
  end

  test "rejects tenant spoofing and extra fields with no-store", %{
    conn: conn,
    organization: organization
  } do
    response =
      post(conn, "/api/v1/mobile/signed-posture/challenge", %{
        "installation_id" => "tmnd-http",
        "organization_id" => organization.id
      })

    assert %{"error" => %{"code" => "signed_posture_request_invalid"}} =
             json_response(response, 400)

    assert get_resp_header(response, "cache-control") == ["no-store"]
  end

  test "challenge, verify, replay and status remain redacted", %{
    conn: conn,
    organization: organization
  } do
    fixture = identity_fixture(organization, "tmnd-http-signed-posture")

    challenge_response =
      post(conn, "/api/v1/mobile/signed-posture/challenge", %{
        "installation_id" => fixture.installation_id
      })

    issued = json_response(challenge_response, 201)["data"]
    assert get_resp_header(challenge_response, "cache-control") == ["no-store"]
    assert issued["organization_id"] == organization.id

    assert Enum.sort(Map.keys(issued)) ==
             Enum.sort(
               ~w(challenge_id device_key_id expires_at installation_id issued_at key_scope_id nonce organization_id platform request_id)
             )

    request =
      Repo.get_by!(MobileSignedPostureRequest,
        organization_id: organization.id,
        installation_id: fixture.installation_id
      )

    assert request.requested_by_id == conn.assigns.current_user.id
    assert request.auth_method == "bearer_user"

    status = get(conn, "/api/v1/mobile/signed-posture/requests/#{issued["request_id"]}")
    status_data = json_response(status, 200)["data"]
    assert status_data == %{"state" => "pending"}
    assert get_resp_header(status, "cache-control") == ["no-store"]

    {envelope, posture} = signed_submission(fixture, issued)

    verified =
      post(conn, "/api/v1/mobile/signed-posture", %{"envelope" => envelope, "posture" => posture})

    verified_data = json_response(verified, 200)["data"]
    assert verified_data["state"] == "verified"

    assert Enum.sort(Map.keys(verified_data)) ==
             Enum.sort(
               ~w(device_key_id installation_id observed_at posture_sha256 receipt_id state verified_at)
             )

    assert get_resp_header(verified, "cache-control") == ["no-store"]

    replay =
      post(conn, "/api/v1/mobile/signed-posture", %{"envelope" => envelope, "posture" => posture})

    assert %{"error" => %{"code" => "signed_posture_request_unavailable"}} =
             json_response(replay, 409)

    assert get_resp_header(replay, "cache-control") == ["no-store"]

    consumed_status =
      get(conn, "/api/v1/mobile/signed-posture/requests/#{issued["request_id"]}")

    assert json_response(consumed_status, 200)["data"] == %{"state" => "unavailable"}
    assert get_resp_header(consumed_status, "cache-control") == ["no-store"]
  end

  defp identity_fixture(organization, installation_id) do
    {private_key, spki} = p256_keypair()
    device_key_id = MobileDeviceIdentity.derive_device_key_id(organization.id, spki)
    key_scope_id = "tmdks_v1_" <> String.duplicate("s", 43)

    challenge =
      Repo.insert!(%MobileDeviceIdentityChallenge{
        organization_id: organization.id,
        installation_id: installation_id,
        platform: "android",
        purpose: "enroll",
        key_scope_id: key_scope_id,
        challenge_digest: :crypto.hash(:sha256, installation_id),
        state: "consumed",
        issued_at: @now,
        expires_at: DateTime.add(@now, 300, :second),
        consumed_at: @now
      })

    Repo.insert!(%MobileDeviceIdentityKey{
      organization_id: organization.id,
      proof_challenge_id: challenge.id,
      installation_id: installation_id,
      platform: "android",
      key_scope_id: key_scope_id,
      device_key_id: device_key_id,
      public_key_spki: spki,
      algorithm: "ecdsa-p256-sha256",
      proof_state: "verified",
      attestation_state: "not_requested",
      lifecycle_state: "active",
      activated_at: @now,
      last_proof_at: @now
    })

    %{
      organization: organization,
      installation_id: installation_id,
      private_key: private_key,
      device_key_id: device_key_id,
      key_scope_id: key_scope_id
    }
  end

  defp signed_submission(fixture, issued) do
    posture = %{
      "schema" => "tamandua.mobile.endpoint-posture/v1",
      "observed_at" => issued["issued_at"],
      "source" => "android_foreground_online",
      "risk_score" => 42,
      "security_checks" =>
        Map.new(
          ~w(app_integrity_violation debugger_detected emulator_detected frida_detected hook_framework_detected root_detected),
          &{&1, false}
        )
    }

    {:ok, posture_sha256} = SignedPosture.posture_digest(posture)

    envelope = %{
      "protocol" => "tamandua.mobile.endpoint-telemetry/v1",
      "message_type" => "endpoint_posture",
      "message_version" => "1",
      "organization_id" => fixture.organization.id,
      "installation_id" => fixture.installation_id,
      "platform" => "android",
      "device_key_id" => fixture.device_key_id,
      "key_scope_id" => fixture.key_scope_id,
      "request_id" => issued["request_id"],
      "challenge_id" => issued["challenge_id"],
      "nonce" => issued["nonce"],
      "posture_sha256" => posture_sha256,
      "algorithm" => "ecdsa-p256-sha256",
      "issued_at" => issued["issued_at"],
      "expires_at" => issued["expires_at"],
      "external_claim_allowed" => false,
      "hardware_attestation_verified" => false,
      "verification_state" => "locally_signed_server_verification_required"
    }

    {:ok, payload} = SignedPosture.canonical_payload(envelope)

    envelope =
      envelope
      |> Map.put(
        "signed_payload_sha256",
        :crypto.hash(:sha256, payload) |> Base.url_encode64(padding: false)
      )
      |> Map.put(
        "signature",
        :public_key.sign(payload, :sha256, fixture.private_key)
        |> Base.url_encode64(padding: false)
      )

    {envelope, posture}
  end

  defp p256_keypair do
    {:ECPrivateKey, _version, _private, params, public, _attrs} =
      private_key = :public_key.generate_key({:namedCurve, :secp256r1})

    spki =
      :public_key.der_encode(
        :SubjectPublicKeyInfo,
        {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, {1, 2, 840, 10045, 2, 1}, params}, public}
      )

    {private_key, spki}
  end
end
