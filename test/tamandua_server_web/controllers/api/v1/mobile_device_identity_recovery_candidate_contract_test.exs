defmodule TamanduaServerWeb.API.V1.MobileDeviceIdentityRecoveryCandidateContractTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Accounts
  alias TamanduaServer.Mobile.MobileDeviceIdentityRecovery
  alias TamanduaServer.Repo

  @old_key_id "tmdk_v1_" <> String.duplicate("o", 43)

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

    {:ok, conn: conn}
  end

  test "missing, null, and empty candidates share one generic 422 contract", %{conn: conn} do
    base = %{
      "installation_id" => "candidate-required-installation",
      "purpose" => "reconcile_rotation",
      "old_device_key_id" => @old_key_id,
      "reason" => "candidate_contract"
    }

    candidates = [
      base,
      Map.put(base, "candidate_device_key_id", nil),
      Map.put(base, "candidate_device_key_id", "")
    ]

    for params <- candidates do
      conn = post(conn, "/api/v1/mobile/device-identity/recovery-intents", params)
      assert get_resp_header(conn, "cache-control") == ["no-store"]

      response =
        conn
        |> json_response(422)

      assert response == %{"error" => %{"code" => "recovery_intent_invalid"}}
      refute Map.has_key?(response, "data")
      refute inspect(response) =~ "candidate_device_key_id"
      refute inspect(response) =~ "binding"
      refute inspect(response) =~ "reservation"
      refute inspect(response) =~ "recovery_token"
    end

    assert Repo.aggregate(MobileDeviceIdentityRecovery, :count) == 0
  end

  test "whitespace-only candidate preserves the generic 400 request contract", %{conn: conn} do
    conn =
      conn
      |> post("/api/v1/mobile/device-identity/recovery-intents", %{
        "installation_id" => "candidate-whitespace-installation",
        "purpose" => "reconcile_rotation",
        "old_device_key_id" => @old_key_id,
        "candidate_device_key_id" => "   ",
        "reason" => "candidate_contract"
      })

    assert get_resp_header(conn, "cache-control") == ["no-store"]

    response =
      conn
      |> json_response(400)

    assert response == %{"error" => %{"code" => "recovery_request_invalid"}}
    refute Map.has_key?(response, "data")
    refute inspect(response) =~ "candidate_device_key_id"
    refute inspect(response) =~ "binding"
    refute inspect(response) =~ "reservation"
    refute inspect(response) =~ "recovery_token"
    assert Repo.aggregate(MobileDeviceIdentityRecovery, :count) == 0
  end
end
