defmodule TamanduaServerWeb.Controllers.API.V1.AIControllerTest do
  use TamanduaServerWeb.ConnCase, async: true

  import TamanduaServer.Factory

  setup %{conn: conn} do
    org = insert(:organization)
    user = insert(:user, %{organization_id: org.id, role: "analyst"})
    {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(user)

    %{conn: put_req_header(conn, "authorization", "Bearer #{token}"), org: org}
  end

  describe "POST /api/v1/ai/chat" do
    test "handles prior alert context without Regex.scan argument errors", %{conn: conn} do
      alert_id = Ecto.UUID.generate()

      conn =
        post(conn, "/api/v1/ai/chat", %{
          "message" => "explique os ultimos alerts",
          "context" => %{
            "previous_messages" => [
              %{
                "role" => "assistant",
                "content" => "Alert is still in context: #{alert_id}"
              }
            ]
          }
        })

      body = json_response(conn, 200)["data"]

      assert is_binary(body["message"])
      refute body["message"] =~ "Regex.scan"
      refute body["message"] =~ "function clause"
    end
  end
end
