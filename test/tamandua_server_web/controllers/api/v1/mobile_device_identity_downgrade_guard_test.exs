defmodule TamanduaServerWeb.API.V1.MobileDeviceIdentityDowngradeGuardTest do
  use TamanduaServerWeb.ConnCase, async: false

  import Ecto.Query

  alias TamanduaServer.Accounts
  alias TamanduaServer.Agents.Agent

  alias TamanduaServer.Mobile.{
    Device,
    DeviceV2,
    MobileDeviceIdentity,
    MobileDeviceIdentityChallenge
  }

  alias TamanduaServer.Repo

  @public_key "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC5iM0/c6FZmhIJ1pO/PIsyQ2HqESS7LO/VAgEUL/ZFHugMKNzBWyeCKU+UMqW2ubv2/1WF/AU7vIbj+a8aw/BA=="
  @private_key "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1B1d3lTMW90U2JsSkREczAKdGVCM2cvK3V5aWJsS3pFeWJxaGVrS3VRTktlaFJBTkNBQVFMbUl6VDl6b1ZtYUVnbldrNzg4aXpKRFllb1JKTApzczc5VUNBUlF2OWtVZTZBd28zTUZiSjRJcFQ1UXlwYmE1dS9iL1ZZWDhCVHU4aHVQNXJ4ckQ4RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
  @algorithm "ecdsa-p256-sha256"

  setup %{conn: conn} do
    organization = insert(:organization)
    user = insert(:user, organization_id: organization.id)

    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header("content-type", "application/json")
      |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(user)}")

    {:ok, conn: conn, organization: organization}
  end

  test "unbound legacy registration remains allowed and explicitly unverified", %{
    conn: conn,
    organization: organization
  } do
    installation_id = "legacy-unbound-install"

    response =
      post(conn, "/api/v1/mobile/devices/register", %{
        "device_id" => installation_id,
        "platform" => "android",
        "model" => "Unbound test device"
      })

    assert %{
             "device_identity" => %{
               "assurance" => "unverified",
               "mode" => "legacy_unbound",
               "proof_state" => "not_provided"
             }
           } = json_response(response, 201)

    assert Repo.get_by(Device,
             organization_id: organization.id,
             device_id: installation_id
           )

    assert Repo.get_by(Agent,
             organization_id: organization.id,
             machine_id: installation_id
           )
  end

  test "bound identity denies legacy registration, ignores client proof claims, and writes nothing",
       %{
         conn: conn,
         organization: organization
       } do
    installation_id = "legacy-bound-install"
    bind_identity!(organization.id, installation_id)
    device_count = count_for_org(Device, organization.id)
    agent_count = count_for_org(Agent, organization.id)

    response =
      post(conn, "/api/v1/mobile/devices/register", %{
        "device_id" => installation_id,
        "platform" => "android",
        "device_identity_proof" => %{"proof_state" => "verified"},
        "custom_attributes" => %{
          "device_identity_verified" => true,
          "device_key_id" => "client-controlled"
        }
      })

    assert proof_required_response(response)
    assert count_for_org(Device, organization.id) == device_count
    assert count_for_org(Agent, organization.id) == agent_count
    refute Repo.get_by(Device, organization_id: organization.id, device_id: installation_id)
  end

  test "revoked identity denies legacy update and MDM enrollment", %{
    conn: conn,
    organization: organization
  } do
    installation_id = "legacy-revoked-install"
    device = insert_legacy_device!(organization.id, installation_id, "Original model")
    bind_identity!(organization.id, installation_id)
    assert {:ok, _revoked} = MobileDeviceIdentity.revoke_active(organization.id, installation_id)

    update_response =
      put(conn, "/api/v1/mobile/devices/#{device.id}", %{"model" => "Mutated model"})

    assert proof_required_response(update_response)
    assert Repo.get!(Device, device.id).model == "Original model"

    enroll_response =
      post(conn, "/api/v1/mobile/devices/#{device.id}/enroll", %{
        "mdm_provider" => "intune"
      })

    assert proof_required_response(enroll_response)
    assert Repo.get!(Device, device.id).model == "Original model"
  end

  test "unbound legacy MDM enrollment fails closed before DeviceRegistry side effects", %{
    conn: conn,
    organization: organization
  } do
    installation_id = "legacy-unbound-mdm-install"
    device = insert_legacy_device!(organization.id, installation_id, "Unbound MDM device")

    response =
      post(conn, "/api/v1/mobile/devices/#{device.id}/enroll", %{
        "mdm_provider" => "intune"
      })

    assert proof_required_response(response)

    unchanged = Repo.get!(Device, device.id)
    assert unchanged.mdm_enrolled == false
    assert unchanged.mdm_provider == "none"
  end

  test "identity history in another tenant does not block an unbound installation", %{
    conn: _conn,
    organization: other_organization
  } do
    installation_id = "tenant-isolated-install"
    bound_organization = insert(:organization)
    bind_identity!(bound_organization.id, installation_id)
    conn = authenticated_conn(other_organization)

    response =
      post(conn, "/api/v1/mobile/devices/register", %{
        "device_id" => installation_id,
        "platform" => "android",
        "organization_id" => bound_organization.id
      })

    assert %{"device_identity" => %{"assurance" => "unverified"}} =
             json_response(response, 201)

    assert Repo.get_by(Device,
             organization_id: other_organization.id,
             device_id: installation_id
           )

    refute Repo.get_by(Device,
             organization_id: bound_organization.id,
             device_id: installation_id
           )
  end

  test "bound V2 identity denies update before device or Agent mutation", %{
    conn: conn,
    organization: organization
  } do
    installation_id = "v2-bound-install"

    device =
      %DeviceV2{}
      |> DeviceV2.changeset(%{
        organization_id: organization.id,
        device_id: installation_id,
        device_name: "Original V2 name",
        platform: "android"
      })
      |> Repo.insert!()

    bind_identity!(organization.id, installation_id)
    agent_count = count_for_org(Agent, organization.id)

    response =
      put(conn, "/api/v1/mobile/v2/devices/#{device.id}", %{
        "device_name" => "Mutated V2 name",
        "device_identity" => %{"proof_state" => "verified"}
      })

    assert proof_required_response(response)
    assert Repo.get!(DeviceV2, device.id).device_name == "Original V2 name"
    assert count_for_org(Agent, organization.id) == agent_count
  end

  test "unbound V2 device cannot be rebound to a bound candidate device_id", %{
    conn: conn,
    organization: organization
  } do
    current_installation_id = "v2-current-unbound-install"
    bound_candidate_id = "v2-bound-candidate-install"

    device =
      %DeviceV2{}
      |> DeviceV2.changeset(%{
        organization_id: organization.id,
        device_id: current_installation_id,
        device_name: "Unbound V2 device",
        platform: "android"
      })
      |> Repo.insert!()

    bind_identity!(organization.id, bound_candidate_id)
    agent_count = count_for_org(Agent, organization.id)

    response =
      put(conn, "/api/v1/mobile/v2/devices/#{device.id}", %{
        "device_id" => bound_candidate_id,
        "device_name" => "Attempted rebind"
      })

    assert %{"error" => %{"code" => "mobile_v2_device_id_immutable"}} =
             json_response(response, 409)

    unchanged = Repo.get!(DeviceV2, device.id)
    assert unchanged.device_id == current_installation_id
    assert unchanged.device_name == "Unbound V2 device"
    assert count_for_org(Agent, organization.id) == agent_count
  end

  defp authenticated_conn(organization) do
    user = insert(:user, organization_id: organization.id)

    build_conn()
    |> put_req_header("accept", "application/json")
    |> put_req_header("content-type", "application/json")
    |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(user)}")
  end

  defp proof_required_response(conn) do
    assert %{"error" => %{"code" => "device_identity_proof_required"}} =
             json_response(conn, 409)

    true
  end

  defp insert_legacy_device!(organization_id, installation_id, model) do
    %Device{}
    |> Device.registration_changeset(%{
      organization_id: organization_id,
      device_id: installation_id,
      platform: "android",
      model: model
    })
    |> Repo.insert!()
  end

  defp count_for_org(schema, organization_id) do
    schema
    |> where([record], record.organization_id == ^organization_id)
    |> Repo.aggregate(:count)
  end

  defp bind_identity!(organization_id, installation_id) do
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

    signature = :public_key.sign(payload, :sha256, decode_private_key(@private_key))

    assert {:ok, key} =
             MobileDeviceIdentity.verify_and_bind(organization_id, %{
               challenge_id: issued.challenge_id,
               challenge: issued.challenge,
               installation_id: installation_id,
               platform: "android",
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
end
