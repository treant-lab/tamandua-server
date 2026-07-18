defmodule TamanduaServerWeb.Controllers.API.V1.HuntingControllerTest do
  use TamanduaServerWeb.ConnCase, async: true

  alias TamanduaServer.Hunting.SavedQuery
  alias TamanduaServer.Repo

  setup %{conn: conn} do
    org = insert!(:organization)
    user = insert!(:user, %{organization_id: org.id, role: "analyst"})
    {:ok, token, _} = TamanduaServer.Guardian.encode_and_sign(user)

    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header("authorization", "Bearer #{token}")

    %{conn: conn, org: org, user: user}
  end

  describe "GET /api/v1/hunting/templates" do
    test "marks static fallback templates as degraded", %{conn: conn} do
      conn = get(conn, "/api/v1/hunting/templates")

      data = json_response(conn, 200)["data"]
      assert data["source"] == "static"
      assert data["static"] == true
      assert data["degraded"] == true

      first_template =
        data["templates"]
        |> Map.values()
        |> List.flatten()
        |> hd()

      assert first_template["source"] == "static"
      assert first_template["static"] == true
      assert first_template["degraded"] == true
    end

    test "marks database templates as non-degraded", %{conn: conn, org: org, user: user} do
      Repo.insert!(%SavedQuery{
        name: "Seeded PowerShell Hunt",
        description: "Seeded template",
        query: "process.name:powershell.exe",
        category: "Execution",
        is_template: true,
        organization_id: org.id,
        created_by: user.id,
        use_count: 3
      })

      conn = get(conn, "/api/v1/hunting/templates")

      data = json_response(conn, 200)["data"]
      assert data["source"] == "database"
      assert data["static"] == false
      assert data["degraded"] == false

      [template] = data["templates"]["Execution"]
      assert template["name"] == "Seeded PowerShell Hunt"
      assert template["source"] == "database"
      assert template["static"] == false
      assert template["degraded"] == false
      assert template["use_count"] == 3
    end
  end
end
