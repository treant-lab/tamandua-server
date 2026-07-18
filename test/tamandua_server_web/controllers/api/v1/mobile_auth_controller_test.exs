defmodule TamanduaServerWeb.API.V1.MobileAuthControllerTest do
  use TamanduaServerWeb.ConnCase, async: true

  alias TamanduaServer.Accounts

  describe "POST /api/v1/auth/login" do
    test "returns bearer token and user envelope for valid mobile credentials", %{conn: conn} do
      user = insert(:user, email: "mobile-login@example.com", role: "analyst")

      conn =
        post(conn, "/api/v1/auth/login", %{
          "email" => user.email,
          "password" => "password123"
        })

      assert %{
               "data" => %{
                 "token" => token,
                 "token_type" => "Bearer",
                 "user" => %{
                   "id" => user_id,
                   "email" => "mobile-login@example.com",
                   "role" => "analyst"
                 }
               }
             } = json_response(conn, 200)

      assert is_binary(token)
      assert user_id == user.id
      assert Accounts.get_user_by_api_token(token).id == user.id
    end

    test "returns 401 for invalid mobile credentials", %{conn: conn} do
      user = insert(:user, email: "mobile-invalid@example.com")

      conn =
        post(conn, "/api/v1/auth/login", %{
          "email" => user.email,
          "password" => "wrong-password"
        })

      assert %{"message" => "Invalid email or password"} = json_response(conn, 401)
    end

    test "returns 401 instead of 500 for malformed password hashes", %{conn: conn} do
      user = insert(:user, email: "mobile-bad-hash@example.com", password_hash: "legacy-bad-hash")

      conn =
        post(conn, "/api/v1/auth/login", %{
          "email" => user.email,
          "password" => "password123"
        })

      assert %{"message" => "Invalid email or password"} = json_response(conn, 401)
    end

    test "returns 400 for malformed login request", %{conn: conn} do
      conn = post(conn, "/api/v1/auth/login", %{"email" => "missing-password@example.com"})

      assert %{"message" => "Missing email or password"} = json_response(conn, 400)
    end
  end

  describe "POST /api/v1/auth/refresh" do
    test "rotates a valid mobile bearer token", %{conn: conn} do
      user = insert(:user)
      token = Accounts.generate_api_token(user)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> post("/api/v1/auth/refresh", %{})

      assert %{
               "data" => %{
                 "token" => new_token,
                 "token_type" => "Bearer",
                 "user" => %{"id" => user_id}
               }
             } = json_response(conn, 200)

      assert new_token != token
      assert user_id == user.id
      assert Accounts.get_user_by_api_token(token) == nil
      assert Accounts.get_user_by_api_token(new_token).id == user.id
    end
  end

  describe "POST /api/v1/auth/logout" do
    test "revokes a valid mobile bearer token", %{conn: conn} do
      user = insert(:user)
      token = Accounts.generate_api_token(user)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> post("/api/v1/auth/logout", %{})

      assert %{"data" => %{"ok" => true}} = json_response(conn, 200)
      assert Accounts.get_user_by_api_token(token) == nil
    end
  end
end
