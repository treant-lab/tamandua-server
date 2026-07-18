defmodule TamanduaServerWeb.API.V1.MobileDeviceIdentityControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.{Role, UserRole}
  alias TamanduaServer.Mobile.{MobileDeviceIdentity, MobileDeviceIdentityChallenge}
  alias TamanduaServer.Repo

  @public_key "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC5iM0/c6FZmhIJ1pO/PIsyQ2HqESS7LO/VAgEUL/ZFHugMKNzBWyeCKU+UMqW2ubv2/1WF/AU7vIbj+a8aw/BA=="
  @private_key "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1B1d3lTMW90U2JsSkREczAKdGVCM2cvK3V5aWJsS3pFeWJxaGVrS3VRTktlaFJBTkNBQVFMbUl6VDl6b1ZtYUVnbldrNzg4aXpKRFllb1JKTApzczc5VUNBUlF2OWtVZTZBd28zTUZiSjRJcFQ1UXlwYmE1dS9iL1ZZWDhCVHU4aHVQNXJ4ckQ4RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
  @algorithm "ecdsa-p256-sha256"

  setup %{conn: conn} do
    organization = insert(:organization)
    user = insert(:user, organization_id: organization.id)

    admin_role =
      Repo.insert!(%Role{
        name: "Mobile identity test admin",
        slug: "admin",
        builtin: true,
        priority: 100,
        organization_id: organization.id
      })

    Repo.insert!(%UserRole{
      user_id: user.id,
      role_id: admin_role.id,
      granted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    })

    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header("content-type", "application/json")
      |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(user)}")
      |> assign(:current_user, user)
      |> assign(:current_organization_id, organization.id)

    {:ok, conn: conn, organization: organization}
  end

  test "challenge is tenant-owned and ignores payload organization_id", %{
    conn: conn,
    organization: organization
  } do
    other_organization = insert(:organization)

    response =
      post(conn, "/api/v1/mobile/device-identity/challenge", %{
        "organization_id" => other_organization.id,
        "installation_id" => "http-pop-install-1",
        "platform" => "android",
        "purpose" => "enroll"
      })

    assert %{"data" => %{"challenge_id" => challenge_id, "organization_id" => organization_id}} =
             json_response(response, 201)

    assert organization_id == organization.id

    assert Repo.get!(MobileDeviceIdentityChallenge, challenge_id).organization_id ==
             organization.id
  end

  test "enroll returns a redacted identity and status never exposes key material", %{
    conn: conn,
    organization: organization
  } do
    installation_id = "http-pop-install-2"
    issued = issue_challenge(conn, installation_id, "enroll")
    proof = signed_proof(organization.id, issued)

    enrolled =
      conn
      |> post("/api/v1/mobile/device-identity/enroll", proof)
      |> json_response(200)
      |> Map.fetch!("data")

    assert enrolled["installation_id"] == installation_id
    assert enrolled["proof_state"] == "verified"
    refute Map.has_key?(enrolled, "public_key_spki")
    refute Map.has_key?(enrolled, "proof_challenge_id")

    status =
      conn
      |> get("/api/v1/mobile/device-identity/#{installation_id}/status")
      |> json_response(200)
      |> Map.fetch!("data")

    assert status["proof_required"]
    assert status["active_key"]["device_key_id"] == enrolled["device_key_id"]
    refute inspect(status) =~ "public_key_spki"
    refute inspect(status) =~ "challenge_digest"
  end

  test "rotate endpoint cannot consume an enrollment challenge", %{
    conn: conn,
    organization: organization
  } do
    issued = issue_challenge(conn, "http-pop-install-3", "enroll")
    proof = signed_proof(organization.id, issued)

    assert %{"error" => %{"code" => "device_proof_invalid"}} =
             conn
             |> post("/api/v1/mobile/device-identity/rotate", proof)
             |> json_response(422)

    assert Repo.get!(MobileDeviceIdentityChallenge, issued["challenge_id"]).state == "pending"
  end

  test "invalid cryptographic details are normalized", %{conn: conn} do
    issued = issue_challenge(conn, "http-pop-install-4", "enroll")

    response =
      post(conn, "/api/v1/mobile/device-identity/enroll", %{
        "challenge_id" => issued["challenge_id"],
        "challenge" => issued["challenge"],
        "algorithm" => @algorithm,
        "public_key_spki" => Base.url_encode64(Base.decode64!(@public_key), padding: false),
        "device_key_id" => "tmdk_v1_" <> String.duplicate("a", 43),
        "signature" => Base.url_encode64(<<48, 6, 2, 1, 1, 2, 1, 1>>, padding: false)
      })

    assert %{"error" => %{"code" => "device_proof_invalid"}} = json_response(response, 422)
    refute response.resp_body =~ "signature"
    refute response.resp_body =~ "public_key"
  end

  test "revoke requires delete authorization and active-key binding", %{
    conn: conn,
    organization: organization
  } do
    installation_id = "http-pop-install-5"
    issued = issue_challenge(conn, installation_id, "enroll")
    proof = signed_proof(organization.id, issued)

    key =
      conn
      |> post("/api/v1/mobile/device-identity/enroll", proof)
      |> json_response(200)
      |> Map.fetch!("data")

    viewer = insert(:user, organization_id: organization.id)

    viewer_conn =
      conn
      |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(viewer)}")
      |> assign(:current_user, viewer)

    assert %{"error" => "forbidden", "required_permission" => "agents_delete"} =
             viewer_conn
             |> post("/api/v1/mobile/device-identity/#{installation_id}/revoke", %{
               "device_key_id" => key["device_key_id"]
             })
             |> json_response(403)

    assert %{"error" => %{"code" => "identity_not_found"}} =
             conn
             |> post("/api/v1/mobile/device-identity/#{installation_id}/revoke", %{
               "device_key_id" => "tmdk_v1_" <> String.duplicate("a", 43)
             })
             |> json_response(404)

    assert %{"data" => %{"lifecycle_state" => "revoked"}} =
             conn
             |> post("/api/v1/mobile/device-identity/#{installation_id}/revoke", %{
               "device_key_id" => key["device_key_id"]
             })
             |> json_response(200)

    assert %{
             "data" => %{
               "active_key" => nil,
               "proof_required" => true,
               "latest_lifecycle_state" => "revoked"
             }
           } =
             conn
             |> get("/api/v1/mobile/device-identity/#{installation_id}/status")
             |> json_response(200)
  end

  test "recovery intents are issued once, redacted, tenant-bound, and token-gated", %{
    conn: conn,
    organization: organization
  } do
    installation_id = "http-pop-recovery-install-1"
    issued = issue_challenge(conn, installation_id, "enroll")
    proof = signed_proof(organization.id, issued)

    active_key =
      conn
      |> post("/api/v1/mobile/device-identity/enroll", proof)
      |> json_response(200)
      |> Map.fetch!("data")

    issue_response =
      post(conn, "/api/v1/mobile/device-identity/recovery-intents", %{
        "installation_id" => installation_id,
        "purpose" => "rebind",
        "old_device_key_id" => active_key["device_key_id"],
        "reason" => "operator-approved-device-recovery"
      })

    assert %{
             "data" => %{
               "id" => intent_id,
               "installation_id" => ^installation_id,
               "purpose" => "rebind",
               "state" => "pending",
               "authorization_state" => "pending_authorization",
               "step_up_required" => true,
               "recovery_token" => recovery_token,
               "token_exposure" => "one_time"
             }
           } = json_response(issue_response, 201)

    refute issue_response.resp_body =~ "token_digest"

    status_response = get(conn, "/api/v1/mobile/device-identity/recovery-intents/#{intent_id}")

    assert %{"data" => %{"id" => ^intent_id, "state" => "pending"}} =
             json_response(status_response, 200)

    refute status_response.resp_body =~ recovery_token
    refute status_response.resp_body =~ "token_digest"

    assert %{"error" => %{"code" => "recovery_intent_unavailable"}} =
             conn
             |> post("/api/v1/mobile/device-identity/recovery-intents/#{intent_id}/resolve", %{
               "recovery_token" => "wrong-token"
             })
             |> json_response(404)

    resolved_response =
      post(conn, "/api/v1/mobile/device-identity/recovery-intents/#{intent_id}/resolve", %{
        "recovery_token" => recovery_token
      })

    assert %{
             "data" => %{
               "id" => ^intent_id,
               "state" => "pending",
               "authorization_state" => "pending_authorization",
               "token_consumed_at" => consumed_at
             }
           } = json_response(resolved_response, 202)

    assert is_binary(consumed_at)
    refute resolved_response.resp_body =~ "token_digest"

    assert %{"error" => %{"code" => "recovery_intent_unavailable"}} =
             conn
             |> post("/api/v1/mobile/device-identity/recovery-intents/#{intent_id}/resolve", %{
               "recovery_token" => recovery_token
             })
             |> json_response(404)
  end

  test "status is isolated across tenants", %{conn: conn} do
    other_organization = insert(:organization)
    installation_id = "another-tenant-install"

    assert {:ok, issued} =
             MobileDeviceIdentity.issue_challenge(other_organization.id, %{
               installation_id: installation_id,
               platform: "android",
               purpose: "enroll"
             })

    assert {:ok, _key} =
             MobileDeviceIdentity.verify_and_bind(
               other_organization.id,
               signed_proof(other_organization.id, issued)
             )

    assert %{
             "data" => %{
               "active_key" => nil,
               "proof_required" => false,
               "latest_lifecycle_state" => "unbound"
             }
           } =
             conn
             |> get("/api/v1/mobile/device-identity/#{installation_id}/status")
             |> json_response(200)
  end

  test "routes require authentication" do
    response =
      build_conn()
      |> post("/api/v1/mobile/device-identity/challenge", %{
        "installation_id" => "anonymous-install",
        "platform" => "android",
        "purpose" => "enroll"
      })

    assert response.status == 401
  end

  defp issue_challenge(conn, installation_id, purpose) do
    conn
    |> post("/api/v1/mobile/device-identity/challenge", %{
      "installation_id" => installation_id,
      "platform" => "android",
      "purpose" => purpose
    })
    |> json_response(201)
    |> Map.fetch!("data")
  end

  defp signed_proof(organization_id, issued) do
    challenge_id = field(issued, "challenge_id")
    cleartext_challenge = field(issued, "challenge")
    challenge = Repo.get!(MobileDeviceIdentityChallenge, challenge_id)
    spki = Base.decode64!(@public_key)
    device_key_id = MobileDeviceIdentity.derive_device_key_id(organization_id, spki)

    payload =
      MobileDeviceIdentity.canonical_payload(
        challenge,
        cleartext_challenge,
        device_key_id,
        @algorithm
      )

    signature = :public_key.sign(payload, :sha256, decode_private_key(@private_key))

    %{
      "challenge_id" => challenge_id,
      "challenge" => cleartext_challenge,
      "installation_id" => field(issued, "installation_id"),
      "platform" => field(issued, "platform"),
      "purpose" => field(issued, "purpose"),
      "key_scope_id" => field(issued, "key_scope_id"),
      "algorithm" => @algorithm,
      "public_key_spki" => Base.url_encode64(spki, padding: false),
      "device_key_id" => device_key_id,
      "signature" => Base.url_encode64(signature, padding: false)
    }
  end

  defp decode_private_key(encoded) do
    encoded
    |> Base.decode64!()
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp field(map, name), do: Map.get(map, name, Map.get(map, String.to_existing_atom(name)))
end
