defmodule TamanduaServerWeb.API.V1.AnalystControllerAuthorizationTest do
  use TamanduaServerWeb.ConnCase, async: false

  setup %{conn: conn} do
    organization = insert(:organization)
    viewer = insert(:user, organization: organization, role: "viewer")
    {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(viewer)

    %{conn: put_req_header(conn, "authorization", "Bearer #{token}")}
  end

  test "starting an AI investigation requires investigations_create", %{conn: conn} do
    response =
      post(conn, "/api/v1/analyst/investigate", %{
        "trigger" => "alert",
        "trigger_id" => Ecto.UUID.generate()
      })

    assert json_response(response, 403)["required_permission"] == "investigations_create"
  end

  test "automatic triage requires investigations_create", %{conn: conn} do
    response =
      post(conn, "/api/v1/analyst/triage", %{
        "alert_ids" => [Ecto.UUID.generate()]
      })

    assert json_response(response, 403)["required_permission"] == "investigations_create"
  end

  test "investigation reads and feedback use their dedicated permissions", %{conn: conn} do
    investigation_id = "inv-authz-test"

    list_response = get(conn, "/api/v1/analyst/investigations")
    assert json_response(list_response, 403)["required_permission"] == "investigations_read"

    feedback_response =
      post(conn, "/api/v1/analyst/investigations/#{investigation_id}/feedback", %{
        "investigation_id" => investigation_id,
        "feedback_type" => "accuracy",
        "rating" => 3
      })

    assert json_response(feedback_response, 403)["required_permission"] ==
             "investigations_update"
  end
end
