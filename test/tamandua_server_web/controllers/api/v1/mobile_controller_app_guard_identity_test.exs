defmodule TamanduaServerWeb.API.V1.MobileControllerAppGuardIdentityTest do
  use TamanduaServerWeb.ConnCase, async: false

  import Ecto.Query

  alias TamanduaServer.Accounts
  alias TamanduaServer.Agents.Agent

  alias TamanduaServer.Mobile.{
    Device,
    DeviceV2,
    MobileDeviceIdentity,
    MobileDeviceIdentityChallenge,
    MobileEvent
  }

  alias TamanduaServer.Repo

  @public_key "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC5iM0/c6FZmhIJ1pO/PIsyQ2HqESS7LO/VAgEUL/ZFHugMKNzBWyeCKU+UMqW2ubv2/1WF/AU7vIbj+a8aw/BA=="
  @private_key "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1B1d3lTMW90U2JsSkREczAKdGVCM2cvK3V5aWJsS3pFeWJxaGVrS3VRTktlaFJBTkNBQVFMbUl6VDl6b1ZtYUVnbldrNzg4aXpKRFllb1JKTApzczc5VUNBUlF2OWtVZTZBd28zTUZiSjRJcFQ1UXlwYmE1dS9iL1ZZWDhCVHU4aHVQNXJ4ckQ4RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
  @algorithm "ecdsa-p256-sha256"
  @signing_secret "app-guard-identity-test-secret"
  @signing_key_id "app-guard-identity-test-key"

  setup %{conn: conn} do
    previous_secret = Application.get_env(:tamandua_server, :app_guard_signing_secret)
    previous_key_id = Application.get_env(:tamandua_server, :app_guard_signing_key_id)
    previous_unsigned = Application.get_env(:tamandua_server, :allow_unsigned_app_guard_ingestion)

    previous_replay_store =
      Application.get_env(:tamandua_server, :app_guard_replay_reservation_store)

    Application.put_env(:tamandua_server, :app_guard_signing_secret, @signing_secret)
    Application.put_env(:tamandua_server, :app_guard_signing_key_id, @signing_key_id)
    Application.put_env(:tamandua_server, :allow_unsigned_app_guard_ingestion, false)
    Application.put_env(:tamandua_server, :app_guard_replay_reservation_store, :db)

    on_exit(fn ->
      restore_env(:app_guard_signing_secret, previous_secret)
      restore_env(:app_guard_signing_key_id, previous_key_id)
      restore_env(:allow_unsigned_app_guard_ingestion, previous_unsigned)
      restore_env(:app_guard_replay_reservation_store, previous_replay_store)
    end)

    organization = insert(:organization)
    other_organization = insert(:organization)

    {:ok,
     conn: authenticated_conn(conn, organization),
     other_conn: authenticated_conn(build_conn(), other_organization),
     organization: organization,
     other_organization: other_organization}
  end

  test "bound signed telemetry uses the existing projection without mutating Device or Agent", %{
    conn: conn,
    organization: organization
  } do
    installation_id = "app-guard-bound-existing"
    device = insert_legacy_device!(organization.id, installation_id, "Original model")
    agent = Repo.get_by!(Agent, organization_id: organization.id, machine_id: installation_id)
    bind_identity!(organization.id, installation_id)

    payload =
      payload("evt-app-guard-bound-existing", installation_id)
      |> put_in(["device", "model"], "Client mutation attempt")
      |> put_in(["device", "os_version"], "99")
      |> put_in(["device", "managed"], true)

    response = signed_post(conn, payload)
    assert json_response(response, 201)["data"]["event_id"] == payload["event_id"]

    unchanged_device = Repo.get!(Device, device.id)
    unchanged_agent = Repo.get!(Agent, agent.id)

    assert_fields_unchanged(device, unchanged_device, [
      :model,
      :os_version,
      :mdm_enrolled,
      :updated_at
    ])

    assert_fields_unchanged(agent, unchanged_agent, [:hostname, :config, :updated_at])
    refute Repo.get_by(DeviceV2, organization_id: organization.id, device_id: installation_id)

    assert event_for(organization.id, payload["event_id"])
  end

  test "bound signed telemetry without an existing projection is proof-required and consumes replay",
       %{
         conn: conn,
         organization: organization
       } do
    installation_id = "app-guard-bound-missing"
    bind_identity!(organization.id, installation_id)
    payload = payload("evt-app-guard-bound-missing", installation_id)
    raw_body = Jason.encode!(payload)

    response = signed_post(conn, raw_body)

    assert %{"error" => %{"code" => "device_identity_proof_required"}} =
             json_response(response, 409)

    refute Repo.get_by(Device, organization_id: organization.id, device_id: installation_id)
    refute Repo.get_by(Agent, organization_id: organization.id, machine_id: installation_id)
    refute Repo.get_by(DeviceV2, organization_id: organization.id, device_id: installation_id)

    refute event_for(organization.id, payload["event_id"])

    replay = signed_post(conn, raw_body)
    assert json_response(replay, 409)["error"] == "Duplicate App Guard event replay"
  end

  test "unbound signed telemetry commits an atomic device graph before the event", %{
    conn: conn,
    organization: organization
  } do
    installation_id = "app-guard-unbound-graph"
    payload = payload("evt-app-guard-unbound-graph", installation_id)

    response = signed_post(conn, payload)
    assert json_response(response, 201)["data"]["event_id"] == payload["event_id"]

    device = Repo.get_by!(Device, organization_id: organization.id, device_id: installation_id)
    assert device.agent_version == "app_guard"
    assert Repo.get_by!(DeviceV2, organization_id: organization.id, device_id: installation_id)
    assert Repo.get_by!(Agent, organization_id: organization.id, machine_id: installation_id)

    assert event_for(organization.id, payload["event_id"])
  end

  test "a DeviceV2 graph failure rolls back legacy Device and Agent before event commit", %{
    conn: conn,
    organization: organization
  } do
    installation_id = "app-guard-unbound-rollback"

    payload =
      payload("evt-app-guard-unbound-rollback", installation_id)
      |> put_in(["device", "owner_email"], %{"invalid" => true})

    raw_body = Jason.encode!(payload)
    response = signed_post(conn, raw_body)
    assert response.status == 422

    refute Repo.get_by(Device, organization_id: organization.id, device_id: installation_id)
    refute Repo.get_by(Agent, organization_id: organization.id, machine_id: installation_id)
    refute Repo.get_by(DeviceV2, organization_id: organization.id, device_id: installation_id)

    refute event_for(organization.id, payload["event_id"])

    replay = signed_post(conn, raw_body)
    assert json_response(replay, 409)["error"] == "Duplicate App Guard event replay"
  end

  test "tenant scope ignores client organization claims and invalid HMAC writes nothing", %{
    conn: conn,
    other_conn: other_conn,
    organization: organization,
    other_organization: other_organization
  } do
    installation_id = "app-guard-tenant-scope"

    payload =
      payload("evt-app-guard-invalid-hmac", installation_id)
      |> Map.put("organization_id", other_organization.id)

    invalid = signed_post(conn, payload, secret: "wrong-secret")
    assert json_response(invalid, 401)["error"] == "Invalid App Guard event signature"
    refute Repo.get_by(Device, organization_id: organization.id, device_id: installation_id)

    other_payload =
      payload("evt-app-guard-other-tenant", installation_id)
      |> Map.put("organization_id", organization.id)

    assert json_response(signed_post(other_conn, other_payload), 201)["data"]["event_id"] ==
             other_payload["event_id"]

    assert Repo.get_by!(Device,
             organization_id: other_organization.id,
             device_id: installation_id
           )

    refute Repo.get_by(Device, organization_id: organization.id, device_id: installation_id)
  end

  defp authenticated_conn(conn, organization) do
    user = insert(:user, organization_id: organization.id)

    conn
    |> put_req_header("accept", "application/json")
    |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(user)}")
  end

  defp signed_post(conn, payload_or_raw, opts \\ []) do
    raw_body =
      if is_binary(payload_or_raw), do: payload_or_raw, else: Jason.encode!(payload_or_raw)

    secret = Keyword.get(opts, :secret, @signing_secret)
    timestamp = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()

    conn
    |> put_req_header("content-type", "application/json")
    |> put_req_header("x-tamandua-payload-sha256", sha256(raw_body))
    |> put_req_header("x-tamandua-signature-algorithm", "HMAC-SHA256")
    |> put_req_header("x-tamandua-signing-key-id", @signing_key_id)
    |> put_req_header("x-tamandua-timestamp", timestamp)
    |> put_req_header("x-tamandua-signature", "sha256=" <> hmac(secret, raw_body))
    |> post("/api/v1/mobile/app_guard/events", raw_body)
  end

  defp payload(event_id, installation_id) do
    %{
      "schema" => "tamandua.app_guard.event/v1",
      "event_id" => event_id,
      "event_type" => "emulator_detected",
      "severity" => "medium",
      "timestamp" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601(),
      "platform" => "ios",
      "device" => %{
        "device_id" => installation_id,
        "model" => "iPhone 15",
        "manufacturer" => "Apple",
        "os_version" => "18.5",
        "managed" => false
      },
      "app" => %{
        "package_or_bundle_id" => "com.example.identity",
        "display_name" => "Identity Test",
        "version" => "1.0.0"
      },
      "risk" => %{
        "decision" => "observe",
        "score" => 42,
        "reasons" => ["emulator_detected"]
      },
      "evidence" => %{}
    }
  end

  defp insert_legacy_device!(organization_id, installation_id, model) do
    assert {:ok, device} =
             TamanduaServer.Mobile.register_device(%{
               "organization_id" => organization_id,
               "device_id" => installation_id,
               "platform" => "ios",
               "model" => model,
               "os_version" => "18.0"
             })

    device
  end

  defp event_for(organization_id, event_id) do
    MobileEvent
    |> where(
      [event],
      event.organization_id == ^organization_id and
        fragment("?->>'event_id' = ?", event.payload, ^event_id)
    )
    |> Repo.one()
  end

  defp assert_fields_unchanged(before, after_value, fields) do
    assert Map.take(after_value, fields) == Map.take(before, fields)
  end

  defp bind_identity!(organization_id, installation_id) do
    assert {:ok, issued} =
             MobileDeviceIdentity.issue_challenge(organization_id, %{
               installation_id: installation_id,
               platform: "ios",
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

    signature = :public_key.sign(payload, :sha256, decode_private_key(@private_key))

    assert {:ok, key} =
             MobileDeviceIdentity.verify_and_bind(organization_id, %{
               challenge_id: issued.challenge_id,
               challenge: issued.challenge,
               installation_id: installation_id,
               platform: "ios",
               purpose: "enroll",
               key_scope_id: issued.key_scope_id,
               algorithm: @algorithm,
               public_key_spki: Base.url_encode64(spki, padding: false),
               device_key_id: device_key_id,
               signature: Base.url_encode64(signature, padding: false)
             })

    key
  end

  defp decode_private_key(encoded) do
    encoded
    |> Base.decode64!()
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp sha256(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)

  defp hmac(secret, value),
    do: :crypto.mac(:hmac, :sha256, secret, value) |> Base.encode16(case: :lower)

  defp restore_env(key, nil), do: Application.delete_env(:tamandua_server, key)
  defp restore_env(key, value), do: Application.put_env(:tamandua_server, key, value)
end
