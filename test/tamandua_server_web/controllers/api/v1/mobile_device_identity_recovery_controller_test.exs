defmodule TamanduaServerWeb.API.V1.MobileDeviceIdentityRecoveryControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.{Permission, Role, RolePermission, UserRole}
  alias TamanduaServer.Authorization.RBAC

  alias TamanduaServer.Mobile.{
    DeviceV2,
    MobileDeviceIdentityChallenge,
    MobileDeviceIdentityKey,
    MobileDeviceIdentityRecovery,
    MobileMutationAuthorization,
    MobileMutationProof
  }

  alias TamanduaServer.Repo

  @old_key_id "tmdk_v1_ccccccccccccccccccccccccccccccccccccccccccc"
  @candidate_key_id "tmdk_v1_ddddddddddddddddddddddddddddddddddddddddddd"
  @mutation_public_key "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC5iM0/c6FZmhIJ1pO/PIsyQ2HqESS7LO/VAgEUL/ZFHugMKNzBWyeCKU+UMqW2ubv2/1WF/AU7vIbj+a8aw/BA=="
  @mutation_private_key "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1B1d3lTMW90U2JsSkREczAKdGVCM2cvK3V5aWJsS3pFeWJxaGVrS3VRTktlaFJBTkNBQVFMbUl6VDl6b1ZtYUVnbldrNzg4aXpKRFllb1JKTApzczc5VUNBUlF2OWtVZTZBd28zTUZiSjRJcFQ1UXlwYmE1dS9iL1ZZWDhCVHU4aHVQNXJ4ckQ4RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="

  setup %{conn: conn} do
    organization = insert(:organization)
    user = insert(:user, organization_id: organization.id)

    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header("content-type", "application/json")
      |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(user)}")
      |> assign(:current_user, user)
      |> assign(:current_organization_id, organization.id)

    {:ok, conn: conn, organization: organization, user: user}
  end

  test "rebind ignores client authorization claims and redacts token after issuance", %{
    conn: conn,
    organization: organization,
    user: user
  } do
    grant_permissions!(user, organization, [:agents_delete])
    insert_identity_key(organization.id, "http-recovery-1")

    issued =
      conn
      |> post("/api/v1/mobile/device-identity/recovery-intents", %{
        "organization_id" => insert(:organization).id,
        "installation_id" => "http-recovery-1",
        "purpose" => "rebind",
        "old_device_key_id" => @old_key_id,
        "candidate_device_key_id" => @candidate_key_id,
        "reason" => "key_lost",
        "state" => "consumed",
        "authorization_state" => "authorized",
        "step_up_required" => false,
        "step_up_verified" => true,
        "token_digest" => "client-token-digest"
      })
      |> json_response(201)
      |> Map.fetch!("data")

    assert issued["state"] == "pending"
    assert issued["authorization_state"] == "pending_authorization"
    assert issued["step_up_required"]
    assert issued["authorization_provenance"]["step_up_evidence"] == "not_verified"
    assert issued["token_exposure"] == "one_time"
    assert is_binary(issued["recovery_token"])
    refute Map.has_key?(issued, "token_digest")

    status =
      conn
      |> get("/api/v1/mobile/device-identity/recovery-intents/#{issued["id"]}")
      |> json_response(200)
      |> Map.fetch!("data")

    refute Map.has_key?(status, "recovery_token")
    refute Map.has_key?(status, "token_digest")
    refute inspect(status) =~ "public_key_spki"

    resolved =
      conn
      |> post(
        "/api/v1/mobile/device-identity/recovery-intents/#{issued["id"]}/resolve",
        %{
          "recovery_token" => issued["recovery_token"],
          "authorize" => true,
          "step_up_verified" => true
        }
      )
      |> json_response(202)
      |> Map.fetch!("data")

    assert resolved["state"] == "pending"
    assert resolved["authorization_state"] == "pending_authorization"
    refute Map.has_key?(resolved, "recovery_token")

    assert Repo.one!(from(key in MobileDeviceIdentityKey, select: key.device_key_id)) ==
             @old_key_id
  end

  test "rebind requires destructive agent permission while rotation reconciliation does not", %{
    conn: conn,
    organization: organization
  } do
    insert_identity_key(organization.id, "http-recovery-authz")

    assert %{"error" => %{"code" => "recovery_authorization_required"}} =
             conn
             |> post("/api/v1/mobile/device-identity/recovery-intents", %{
               "installation_id" => "http-recovery-authz",
               "purpose" => "rebind",
               "old_device_key_id" => @old_key_id,
               "candidate_device_key_id" => @candidate_key_id,
               "reason" => "key_lost"
             })
             |> json_response(403)

    rotation =
      conn
      |> post("/api/v1/mobile/device-identity/recovery-intents", %{
        "installation_id" => "http-recovery-authz",
        "purpose" => "reconcile_rotation",
        "old_device_key_id" => @old_key_id,
        "candidate_device_key_id" => @candidate_key_id,
        "reason" => "response_lost"
      })
      |> json_response(201)
      |> Map.fetch!("data")

    assert rotation["purpose"] == "reconcile_rotation"
    assert rotation["authorization_state"] == "not_required"
    assert rotation["step_up_required"] == false
    assert is_binary(rotation["recovery_token"])
  end

  test "rotation reconciliation is one-shot, tenant isolated, and key read-only", %{
    conn: conn,
    organization: organization
  } do
    key = insert_identity_key(organization.id, "http-recovery-2")

    issued =
      conn
      |> post("/api/v1/mobile/device-identity/recovery-intents", %{
        "installation_id" => "http-recovery-2",
        "purpose" => "reconcile_rotation",
        "old_device_key_id" => @old_key_id,
        "candidate_device_key_id" => @candidate_key_id,
        "reason" => "response_lost"
      })
      |> json_response(201)
      |> Map.fetch!("data")

    before_key = Repo.get!(MobileDeviceIdentityKey, key.id)

    resolved =
      conn
      |> post(
        "/api/v1/mobile/device-identity/recovery-intents/#{issued["id"]}/resolve",
        %{"recovery_token" => issued["recovery_token"]}
      )
      |> json_response(200)
      |> Map.fetch!("data")

    assert resolved["state"] == "consumed"
    assert resolved["resolution"] == "previous_key_confirmed"

    assert Repo.get!(MobileDeviceIdentityKey, key.id).lifecycle_state ==
             before_key.lifecycle_state

    assert Repo.get!(MobileDeviceIdentityKey, key.id).public_key_spki ==
             before_key.public_key_spki

    assert %{"error" => %{"code" => "recovery_intent_unavailable"}} =
             conn
             |> post(
               "/api/v1/mobile/device-identity/recovery-intents/#{issued["id"]}/resolve",
               %{"recovery_token" => issued["recovery_token"]}
             )
             |> json_response(404)

    other_organization = insert(:organization)
    other_user = insert(:user, organization_id: other_organization.id)

    other_conn =
      conn
      |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(other_user)}")
      |> assign(:current_user, other_user)
      |> assign(:current_organization_id, other_organization.id)

    assert %{"error" => %{"code" => "recovery_intent_unavailable"}} =
             other_conn
             |> get("/api/v1/mobile/device-identity/recovery-intents/#{issued["id"]}")
             |> json_response(404)
  end

  test "status and resolution routes require authentication" do
    response =
      build_conn()
      |> get("/api/v1/mobile/device-identity/recovery-intents/#{Ecto.UUID.generate()}")

    assert response.status == 401
  end

  test "fresh mutation proof atomically creates v2 device and records verified assurance", %{
    conn: conn,
    organization: organization,
    user: user
  } do
    installation_id = "http-v2-fresh-pop-1"
    insert_identity_key(organization.id, installation_id, Base.decode64!(@mutation_public_key))

    body = %{
      "device_id" => installation_id,
      "device_name" => "Fresh PoP device",
      "platform" => "android"
    }

    assert {:ok, issued} =
             MobileMutationProof.issue(organization.id, %{
               actor_id: user.id,
               installation_id: installation_id,
               resource_id: installation_id,
               body: body
             })

    signature =
      :public_key.sign(issued.payload, :sha256, decode_private_key(@mutation_private_key))

    response =
      conn
      |> post(
        "/api/v1/mobile/v2/devices",
        Map.put(body, "mutation_authorization", %{
          "authorization_id" => issued.authorization_id,
          "challenge_id" => issued.challenge_id,
          "nonce" => issued.nonce,
          "signature" => Base.url_encode64(signature, padding: false)
        })
      )
      |> json_response(201)

    assert response["data"]["device_id"] == installation_id
    assert response["agent_projection"]["machine_id"] == installation_id

    assert response["device_identity"] == %{
             "assurance" => "server_verified_pop",
             "mode" => "fresh_mutation_authorization",
             "proof_state" => "verified"
           }

    authorization = Repo.get!(MobileMutationAuthorization, issued.authorization_id)
    assert authorization.consumed_at
    assert authorization.result_outcome == "created"
    assert authorization.result_resource_id == installation_id
  end

  test "bound v2 mutations reject static identity, rename, and delete without fresh proof", %{
    conn: conn,
    organization: organization
  } do
    installation_id = "http-v2-bound-barrier-1"
    key = insert_identity_key(organization.id, installation_id)

    device =
      %DeviceV2{}
      |> DeviceV2.changeset(%{
        organization_id: organization.id,
        device_id: installation_id,
        platform: "android"
      })
      |> Repo.insert!()

    static_context = %{
      "installation_id" => installation_id,
      "device_key_id" => key.device_key_id,
      "key_scope_id" => key.key_scope_id,
      "proof_state" => "verified",
      "proof_required" => true
    }

    assert %{"error" => %{"code" => "device_identity_proof_required"}} =
             conn
             |> post("/api/v1/mobile/v2/devices", %{
               "device_id" => installation_id,
               "platform" => "android",
               "device_identity" => static_context
             })
             |> json_response(409)

    assert %{"error" => %{"code" => "device_identity_proof_required"}} =
             conn
             |> put("/api/v1/mobile/v2/devices/#{device.id}", %{
               "device_name" => "must not update",
               "device_identity" => static_context
             })
             |> json_response(409)

    assert %{"error" => %{"code" => "mobile_v2_device_id_immutable"}} =
             conn
             |> put("/api/v1/mobile/v2/devices/#{device.id}", %{
               "device_id" => "http-v2-renamed-forbidden"
             })
             |> json_response(409)

    assert %{"error" => %{"code" => "device_identity_proof_required"}} =
             conn
             |> delete("/api/v1/mobile/v2/devices/#{device.id}")
             |> json_response(409)

    assert Repo.get!(DeviceV2, device.id).device_id == installation_id
  end

  defp insert_identity_key(
         organization_id,
         installation_id,
         public_key_spki \\ :crypto.strong_rand_bytes(91)
       ) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    challenge =
      %MobileDeviceIdentityChallenge{}
      |> MobileDeviceIdentityChallenge.changeset(%{
        organization_id: organization_id,
        installation_id: installation_id,
        platform: "android",
        purpose: "enroll",
        key_scope_id: "tmdks_v1_http_recovery_scope",
        challenge_digest: :crypto.strong_rand_bytes(32),
        state: "consumed",
        issued_at: now,
        expires_at: DateTime.add(now, 300, :second),
        consumed_at: now
      })
      |> Repo.insert!()

    %MobileDeviceIdentityKey{}
    |> MobileDeviceIdentityKey.changeset(%{
      organization_id: organization_id,
      proof_challenge_id: challenge.id,
      installation_id: installation_id,
      platform: "android",
      key_scope_id: "tmdks_v1_http_recovery_scope",
      device_key_id: @old_key_id,
      public_key_spki: public_key_spki,
      algorithm: "ecdsa-p256-sha256",
      proof_state: "verified",
      attestation_state: "present_unverified",
      lifecycle_state: "active",
      activated_at: now,
      last_proof_at: now
    })
    |> Repo.insert!()
  end

  defp decode_private_key(encoded) do
    encoded
    |> Base.decode64!()
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp grant_permissions!(user, organization, permission_slugs) do
    role =
      %Role{}
      |> Role.changeset(%{
        name: "Mobile recovery permission test role",
        slug: "mobile_recovery_permission_test_#{user.id}",
        builtin: false,
        priority: 80,
        organization_id: organization.id
      })
      |> Repo.insert!()

    Enum.each(permission_slugs, fn permission_slug ->
      slug = Atom.to_string(permission_slug)

      permission =
        Repo.get_by(Permission, slug: slug) ||
          %Permission{}
          |> Permission.changeset(%{
            name: slug,
            slug: slug,
            description: slug,
            category: "agents"
          })
          |> Repo.insert!()

      %RolePermission{}
      |> RolePermission.changeset(%{role_id: role.id, permission_id: permission.id})
      |> Repo.insert!()
    end)

    %UserRole{}
    |> UserRole.changeset(%{
      user_id: user.id,
      role_id: role.id,
      granted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    })
    |> Repo.insert!()

    RBAC.invalidate_cache(user)
  end
end
