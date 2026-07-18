defmodule TamanduaServerWeb.Plugs.APIAuthTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Accounts
  alias TamanduaServerWeb.Plugs.APIAuth

  describe "normalize_organization_id/1" do
    test "treats empty tenant ids as absent" do
      assert APIAuth.normalize_organization_id(nil) == nil
      assert APIAuth.normalize_organization_id("") == nil
      assert APIAuth.normalize_organization_id("   ") == nil
    end

    test "preserves non-empty tenant ids" do
      organization_id = Ecto.UUID.generate()

      assert APIAuth.normalize_organization_id(organization_id) == organization_id
      assert APIAuth.normalize_organization_id("  #{organization_id}  ") == organization_id
      assert APIAuth.normalize_organization_id(:system) == :system
    end
  end

  test "bearer authentication explicitly receives no persistent session provenance" do
    source = File.read!("lib/tamandua_server_web/plugs/api_auth.ex")

    assert source =~ "assign_user_context(conn, user, nil)"
    assert source =~ "assign(:persistent_session_ref, persistent_session_ref)"
    refute source =~ "assign_user_context(conn, user, token)"
  end

  test "malformed or multiple authorization headers never fall back to a cookie session", %{
    conn: conn
  } do
    user = insert(:user)
    session_token = Accounts.generate_user_session_token(user)

    malformed =
      conn
      |> init_test_session(%{user_token: session_token})
      |> put_req_header("authorization", "Basic invalid")
      |> APIAuth.call([])

    assert malformed.halted
    assert malformed.status == 401

    multiple = %{
      conn
      | req_headers: [
          {"authorization", "Bearer valid-looking"},
          {"authorization", "Bearer second"}
        ]
    }

    multiple = multiple |> init_test_session(%{user_token: session_token}) |> APIAuth.call([])
    assert multiple.halted
    assert multiple.status == 401
  end

  test "valid API bearer authentication explicitly clears persistent provenance", %{conn: conn} do
    user = insert(:user)
    api_token = Accounts.generate_api_token(user)

    authenticated =
      conn
      |> put_req_header("authorization", "Bearer #{api_token}")
      |> APIAuth.call([])

    refute authenticated.halted
    assert authenticated.assigns.current_user.id == user.id
    assert authenticated.assigns.persistent_session_ref == nil
  end
end
