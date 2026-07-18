defmodule TamanduaServerWeb.API.V1.MobileDeviceIdentityAppleAppAttestControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Accounts
  alias TamanduaServer.AppleAppAttestFixture
  alias TamanduaServer.Mobile.MobileDeviceIdentityAppleAppAttest

  setup %{conn: conn} do
    organization = insert(:organization)
    user = insert(:user, organization: organization)

    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header("content-type", "application/json")
      |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(user)}")
      |> assign(:current_user, user)
      |> assign(:current_organization_id, organization.id)

    {:ok, conn: conn, organization: organization}
  end

  test "challenge route uses session tenant and rejects a mismatched body echo", %{
    conn: conn,
    organization: organization
  } do
    other = insert(:organization)
    key = app_key()
    template = AppleAppAttestFixture.build(:crypto.strong_rand_bytes(32), "template", key: key)

    with_apple_config(template.profile, fn ->
      request = challenge_request(organization.id, "http-app-attest-challenge")

      response =
        conn
        |> post("/api/v1/mobile/device-identity/app-attest/challenge", request)
        |> json_response(201)
        |> Map.fetch!("data")

      assert response["organization_id"] == organization.id
      assert response["phase"] == "attest"
      assert response["purpose"] == "bind"
      assert response["platform"] == "ios"

      assert byte_size(
               Base.url_decode64!(response["client_data"]["sha256_base64url"], padding: false)
             ) == 32

      assert %{"error" => %{"code" => "device_proof_invalid"}} =
               conn
               |> post(
                 "/api/v1/mobile/device-identity/app-attest/challenge",
                 challenge_request(other.id, "http-app-attest-wrong-tenant")
               )
               |> json_response(422)
    end)
  end

  test "attestation and assertion routes expose bounded receipts and normalize credential conflict",
       %{
         conn: conn,
         organization: organization
       } do
    key = app_key()
    root = AppleAppAttestFixture.root()

    template =
      AppleAppAttestFixture.build(:crypto.strong_rand_bytes(32), "template", key: key, root: root)

    with_apple_config(template.profile, fn ->
      first = http_stage(conn, organization.id, "http-app-attest-first", key, root)

      assert first.attestation["phase"] == "attest"
      assert first.attestation["state"] == "verified"
      assert first.attestation["attestation_state"] == "verified_app_attest"
      assert first.attestation["assertion_challenge"]["phase"] == "assert"
      refute first.attestation |> inspect() |> String.contains?("attestation_object_base64url")
      refute first.attestation |> inspect() |> String.contains?("x5c")

      assertion_response =
        conn
        |> post(
          "/api/v1/mobile/device-identity/app-attest/assertion",
          assertion_request(first.attestation, key, root)
        )
        |> json_response(200)
        |> Map.fetch!("data")

      assert assertion_response["phase"] == "assert"
      assert assertion_response["assertion_state"] == "verified"

      assert assertion_response["parent_attestation_receipt_id"] ==
               first.attestation["receipt_id"]

      refute inspect(assertion_response) =~ "assertion_base64url"
      refute inspect(assertion_response) =~ "public_key_spki"

      second = http_stage(conn, organization.id, "http-app-attest-conflict", key, root)

      conflict =
        post(
          conn,
          "/api/v1/mobile/device-identity/app-attest/assertion",
          assertion_request(second.attestation, key, root)
        )

      assert %{"error" => %{"code" => "device_identity_conflict"}} =
               json_response(conflict, 409)

      refute conflict.resp_body =~ "credential"
      refute conflict.resp_body =~ "key_id"
      refute conflict.resp_body =~ "assertion"
    end)
  end

  defp http_stage(conn, organization_id, installation_id, key, root) do
    challenge =
      conn
      |> post(
        "/api/v1/mobile/device-identity/app-attest/challenge",
        challenge_request(organization_id, installation_id)
      )
      |> json_response(201)
      |> Map.fetch!("data")

    payload = Base.url_decode64!(challenge["client_data"]["payload_base64url"], padding: false)
    fixture = AppleAppAttestFixture.build(payload, "unused", key: key, root: root)

    params = %{
      "protocol" => challenge["protocol"],
      "provider" => challenge["provider"],
      "challenge_id" => challenge["challenge_id"],
      "organization_id" => challenge["organization_id"],
      "installation_id" => challenge["installation_id"],
      "profile" => challenge["profile"],
      "client_data" => challenge["client_data"],
      "key_id_base64url" => fixture.evidence["key_id_base64url"],
      "attestation_object_base64url" => fixture.evidence["attestation_object_base64url"]
    }

    attestation =
      conn
      |> post("/api/v1/mobile/device-identity/app-attest/attestation", params)
      |> json_response(200)
      |> Map.fetch!("data")

    %{challenge: challenge, attestation: attestation}
  end

  defp assertion_request(attestation, key, root) do
    challenge = attestation["assertion_challenge"]
    payload = Base.url_decode64!(challenge["client_data"]["payload_base64url"], padding: false)

    fixture =
      AppleAppAttestFixture.build(:crypto.strong_rand_bytes(32), payload, key: key, root: root)

    %{
      "protocol" => challenge["protocol"],
      "provider" => challenge["provider"],
      "challenge_id" => challenge["challenge_id"],
      "organization_id" => challenge["organization_id"],
      "installation_id" => challenge["installation_id"],
      "profile" => challenge["profile"],
      "client_data" => challenge["client_data"],
      "key_id_base64url" => fixture.evidence["key_id_base64url"],
      "parent_attestation_receipt_id" => attestation["receipt_id"],
      "parent_attestation_challenge_id" => attestation["challenge_id"],
      "assertion_base64url" => fixture.evidence["assertion_base64url"]
    }
  end

  defp challenge_request(organization_id, installation_id) do
    %{
      "protocol" => "tamandua.mobile.app-attest/v1",
      "provider" => "apple_app_attest",
      "organization_id" => organization_id,
      "installation_id" => installation_id,
      "platform" => "ios",
      "purpose" => "bind"
    }
  end

  defp app_key, do: :public_key.generate_key({:namedCurve, :secp256r1})

  defp with_apple_config(profile, callback) do
    previous = Application.get_env(:tamandua_server, MobileDeviceIdentityAppleAppAttest, :missing)
    [profile_id] = Map.keys(profile)

    Application.put_env(
      :tamandua_server,
      MobileDeviceIdentityAppleAppAttest,
      app_profiles: profile,
      default_profile_id: profile_id,
      unverified_evidence_policy: :reject
    )

    try do
      callback.()
    after
      case previous do
        :missing -> Application.delete_env(:tamandua_server, MobileDeviceIdentityAppleAppAttest)
        value -> Application.put_env(:tamandua_server, MobileDeviceIdentityAppleAppAttest, value)
      end
    end
  end
end
