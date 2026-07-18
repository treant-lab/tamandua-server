defmodule TamanduaServerWeb.API.V1.MobileDeviceMutationAuthorizationControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  import Ecto.Query

  alias TamanduaServer.Accounts

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentity,
    MobileDeviceIdentityChallenge,
    MobileMutationAuthorization,
    MobileDeviceIdentityRecovery
  }

  alias TamanduaServer.Repo

  @public_key "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC5iM0/c6FZmhIJ1pO/PIsyQ2HqESS7LO/VAgEUL/ZFHugMKNzBWyeCKU+UMqW2ubv2/1WF/AU7vIbj+a8aw/BA=="
  @private_key "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1B1d3lTMW90U2JsSkREczAKdGVCM2cvK3V5aWJsS3pFeWJxaGVrS3VRTktlaFJBTkNBQVFMbUl6VDl6b1ZtYUVnbldrNzg4aXpKRFllb1JKTApzczc5VUNBUlF2OWtVZTZBd28zTUZiSjRJcFQ1UXlwYmE1dS9iL1ZZWDhCVHU4aHVQNXJ4ckQ4RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
  @algorithm "ecdsa-p256-sha256"

  setup %{conn: conn} do
    organization = insert(:organization)
    user = insert(:user, organization_id: organization.id)

    conn = authenticated_conn(conn, user, organization.id)
    body = %{"device_id" => "device-v2-http-001", "platform" => "android"}

    {:ok,
     conn: conn,
     organization: organization,
     user: user,
     body: body,
     installation_id: "mutation-http-installation"}
  end

  test "issues an exact no-store authorization without persisting clear secrets", context do
    key = bind_key!(context.organization.id, context.installation_id)

    response =
      context.conn
      |> post("/api/v1/mobile/v2/device-mutations/challenge", request(context))

    assert get_resp_header(response, "cache-control") == ["no-store"]

    authorization = json_response(response, 201)
    assert Enum.sort(Map.keys(authorization)) == ["authorization_id", "signed_fields"]
    assert map_size(authorization["signed_fields"]) == 20
    assert authorization["signed_fields"]["organization_id"] == context.organization.id
    assert authorization["signed_fields"]["actor_id"] == context.user.id
    assert authorization["signed_fields"]["device_key_id"] == key.device_key_id
    assert authorization["signed_fields"]["resource_id"] == context.body["device_id"]

    persisted = Repo.get!(MobileMutationAuthorization, authorization["authorization_id"])
    refute inspect(persisted) =~ authorization["signed_fields"]["challenge_id"]
    refute inspect(persisted) =~ authorization["signed_fields"]["nonce"]
    assert byte_size(persisted.challenge_digest) == 32
    assert byte_size(persisted.nonce_digest) == 32
  end

  test "rejects client-controlled bindings, invalid operation, and unbound installations",
       context do
    forbidden = ~w(organization_id actor_id route_id body_sha256)

    for field <- forbidden do
      assert %{"error" => %{"code" => "invalid_mobile_mutation_authorization_request"}} =
               context.conn
               |> post(
                 "/api/v1/mobile/v2/device-mutations/challenge",
                 Map.put(request(context), field, "client-controlled")
               )
               |> json_response(400)
    end

    assert %{"error" => %{"code" => "invalid_mobile_mutation_authorization_request"}} =
             context.conn
             |> post(
               "/api/v1/mobile/v2/device-mutations/challenge",
               %{request(context) | "operation" => "delete"}
             )
             |> json_response(400)

    assert %{"error" => %{"code" => "mobile_mutation_authorization_unavailable"}} =
             context.conn
             |> post("/api/v1/mobile/v2/device-mutations/challenge", request(context))
             |> json_response(409)
  end

  test "live recovery blocks authorization issuance", context do
    key = bind_key!(context.organization.id, context.installation_id)

    assert {:ok, _intent} =
             MobileDeviceIdentityRecovery.issue(
               context.organization.id,
               %{
                 installation_id: context.installation_id,
                 purpose: "rebind",
                 old_device_key_id: key.device_key_id,
                 reason: "controller recovery barrier test"
               },
               ttl_seconds: 60
             )

    assert %{"error" => %{"code" => "mobile_mutation_authorization_unavailable"}} =
             context.conn
             |> post("/api/v1/mobile/v2/device-mutations/challenge", request(context))
             |> json_response(409)
  end

  test "status is actor and tenant scoped and exposes only pending or result metadata", context do
    bind_key!(context.organization.id, context.installation_id)

    issued =
      context.conn
      |> post("/api/v1/mobile/v2/device-mutations/challenge", request(context))
      |> json_response(201)

    pending_response =
      get(
        context.conn,
        "/api/v1/mobile/v2/device-mutations/#{issued["authorization_id"]}"
      )

    assert get_resp_header(pending_response, "cache-control") == ["no-store"]

    assert %{
             "authorization_id" => issued["authorization_id"],
             "status" => "pending"
           } == json_response(pending_response, 200)

    other_user = insert(:user, organization_id: context.organization.id)
    other_actor_conn = authenticated_conn(context.conn, other_user, context.organization.id)

    assert unavailable(other_actor_conn, issued["authorization_id"])

    other_organization = insert(:organization)
    other_tenant_user = insert(:user, organization_id: other_organization.id)
    other_tenant_conn = authenticated_conn(context.conn, other_tenant_user, other_organization.id)

    assert unavailable(other_tenant_conn, issued["authorization_id"])

    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    authorization_id = issued["authorization_id"]

    Repo.update_all(
      from(candidate in MobileMutationAuthorization,
        where: candidate.id == ^authorization_id
      ),
      set: [
        consumed_at: now,
        result_outcome: "created",
        result_resource_id: context.body["device_id"],
        updated_at: now
      ]
    )

    consumed =
      context.conn
      |> get("/api/v1/mobile/v2/device-mutations/#{issued["authorization_id"]}")
      |> json_response(200)

    assert consumed == %{
             "authorization_id" => issued["authorization_id"],
             "status" => "consumed",
             "result" => %{
               "outcome" => "created",
               "resource_id" => context.body["device_id"]
             }
           }

    refute inspect(consumed) =~ "challenge_id"
    refute inspect(consumed) =~ "nonce"
    refute inspect(consumed) =~ "signature"
  end

  test "routes require authentication and unavailable ids use a generic no-store 404", context do
    unauthorized =
      build_conn()
      |> get("/api/v1/mobile/v2/device-mutations/#{Ecto.UUID.generate()}")

    assert unauthorized.status == 401
    assert get_resp_header(unauthorized, "cache-control") == ["no-store"]

    missing =
      context.conn
      |> get("/api/v1/mobile/v2/device-mutations/not-an-id")

    assert get_resp_header(missing, "cache-control") == ["no-store"]

    assert %{"error" => %{"code" => "mobile_mutation_authorization_unavailable"}} =
             json_response(missing, 404)
  end

  test "an unconsumed authorization becomes minimally expired at its exact boundary", context do
    bind_key!(context.organization.id, context.installation_id)

    issued =
      context.conn
      |> post("/api/v1/mobile/v2/device-mutations/challenge", request(context))
      |> json_response(201)

    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    authorization_id = issued["authorization_id"]

    Repo.update_all(
      from(candidate in MobileMutationAuthorization,
        where: candidate.id == ^authorization_id
      ),
      set: [expires_at: now, updated_at: now]
    )

    response =
      context.conn
      |> get("/api/v1/mobile/v2/device-mutations/#{issued["authorization_id"]}")

    assert get_resp_header(response, "cache-control") == ["no-store"]

    assert json_response(response, 200) == %{
             "authorization_id" => issued["authorization_id"],
             "status" => "expired"
           }
  end

  test "suspended selected tenants are forbidden by local validation with no-store", context do
    context.organization
    |> Ecto.Changeset.change(is_active: false)
    |> Repo.update!()

    response =
      context.conn
      |> get("/api/v1/mobile/v2/device-mutations/#{Ecto.UUID.generate()}")

    assert response.status == 403
    assert get_resp_header(response, "cache-control") == ["no-store"]
    assert %{"error" => %{"code" => "tenant_inactive"}} = json_response(response, 403)
  end

  test "bearer tenant cannot be rebound by a conflicting API key header", context do
    bind_key!(context.organization.id, context.installation_id)

    issued =
      context.conn
      |> put_req_header("x-api-key", "tmnd_api_key_for_another_tenant")
      |> post("/api/v1/mobile/v2/device-mutations/challenge", request(context))
      |> json_response(201)

    assert issued["signed_fields"]["organization_id"] == context.organization.id
    assert issued["signed_fields"]["actor_id"] == context.user.id
  end

  test "super admin keeps the tenant explicitly selected by API auth", context do
    selected_organization = insert(:organization)
    super_admin = insert(:user, organization_id: context.organization.id, role: "super_admin")
    bind_key!(selected_organization.id, context.installation_id)

    conn =
      context.conn
      |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(super_admin)}")
      |> put_req_header("x-tenant-id", selected_organization.id)

    issued =
      conn
      |> post("/api/v1/mobile/v2/device-mutations/challenge", request(context))
      |> json_response(201)

    assert issued["signed_fields"]["organization_id"] == selected_organization.id
    assert issued["signed_fields"]["actor_id"] == super_admin.id
  end

  test "not acceptable responses inherit no-store before the API pipeline", context do
    response =
      context.conn
      |> put_req_header("accept", "text/plain")
      |> get("/api/v1/mobile/v2/device-mutations/#{Ecto.UUID.generate()}")

    assert response.status == 406
    assert get_resp_header(response, "cache-control") == ["no-store"]
  end

  defp request(context) do
    %{
      "installation_id" => context.installation_id,
      "operation" => "mobile_device_v2_upsert",
      "body" => context.body
    }
  end

  defp unavailable(conn, authorization_id) do
    %{"error" => %{"code" => "mobile_mutation_authorization_unavailable"}} ==
      conn
      |> get("/api/v1/mobile/v2/device-mutations/#{authorization_id}")
      |> json_response(404)
  end

  defp authenticated_conn(conn, user, organization_id) do
    conn
    |> put_req_header("accept", "application/json")
    |> put_req_header("content-type", "application/json")
    |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(user)}")
    |> assign(:current_user, user)
    |> assign(:current_organization_id, organization_id)
  end

  defp bind_key!(organization_id, installation_id) do
    assert {:ok, issued} =
             MobileDeviceIdentity.issue_challenge(organization_id, %{
               installation_id: installation_id,
               platform: "android",
               purpose: "enroll"
             })

    challenge = Repo.get!(MobileDeviceIdentityChallenge, issued.challenge_id)
    spki = Base.decode64!(@public_key)
    device_key_id = MobileDeviceIdentity.derive_device_key_id(organization_id, spki)

    payload =
      MobileDeviceIdentity.canonical_payload(
        challenge,
        issued.challenge,
        device_key_id,
        @algorithm
      )

    proof = %{
      challenge_id: issued.challenge_id,
      challenge: issued.challenge,
      installation_id: installation_id,
      platform: "android",
      purpose: "enroll",
      key_scope_id: issued.key_scope_id,
      algorithm: @algorithm,
      public_key_spki: base64url(spki),
      device_key_id: device_key_id,
      signature:
        payload
        |> :public_key.sign(:sha256, decode_private_key(@private_key))
        |> base64url()
    }

    assert {:ok, key} = MobileDeviceIdentity.verify_and_bind(organization_id, proof)
    key
  end

  defp decode_private_key(encoded) do
    encoded
    |> Base.decode64!()
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp base64url(value), do: Base.url_encode64(value, padding: false)
end
