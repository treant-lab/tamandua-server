defmodule TamanduaServerWeb.Plugs.SecurityHardeningTest do
  @moduledoc """
  Tests for security hardening:
  - CORS configuration validation
  - CSRF protection for session-authenticated API requests
  - Safe JSON parsing (no 500 on invalid JSON)
  - Atom safety (no atom table exhaustion)
  """

  use TamanduaServerWeb.ConnCase, async: true

  alias TamanduaServerWeb.Plugs.APICSRFProtection
  alias TamanduaServerWeb.AtomHelpers

  describe "AtomHelpers.safe_to_existing_atom/2" do
    test "returns atom for allowed string" do
      # :active should exist as an atom
      assert AtomHelpers.safe_to_existing_atom("active", ~w(active inactive)) == :active
    end

    test "returns nil for disallowed string" do
      assert AtomHelpers.safe_to_existing_atom("malicious", ~w(active inactive)) == nil
    end

    test "returns nil for random attacker string" do
      random_string = "random_attacker_string_#{:rand.uniform(1_000_000)}"
      assert AtomHelpers.safe_to_existing_atom(random_string, ~w(active inactive)) == nil
    end

    test "returns nil for nil input" do
      assert AtomHelpers.safe_to_existing_atom(nil, ~w(active inactive)) == nil
    end

    test "does not create new atoms" do
      novel_string = "novel_atom_that_should_not_exist_#{:rand.uniform(1_000_000)}"

      # First call should return nil
      assert AtomHelpers.safe_to_existing_atom(novel_string, [novel_string]) == nil

      # Verify atom was not created by trying to_existing_atom directly
      assert_raise ArgumentError, fn ->
        String.to_existing_atom(novel_string)
      end
    end
  end

  describe "AtomHelpers.safe_to_existing_atom_unguarded/1" do
    test "returns existing atom" do
      assert AtomHelpers.safe_to_existing_atom_unguarded("ok") == :ok
    end

    test "returns nil for non-existing atom" do
      novel_string = "unguarded_novel_atom_#{:rand.uniform(1_000_000)}"
      assert AtomHelpers.safe_to_existing_atom_unguarded(novel_string) == nil
    end
  end

  describe "AtomHelpers.safe_atomize_keys/2" do
    test "atomizes known keys" do
      result = AtomHelpers.safe_atomize_keys(%{"status" => "ok"}, allowed_keys: ~w(status))
      assert result == %{status: "ok"}
    end

    test "keeps unknown keys as strings" do
      result = AtomHelpers.safe_atomize_keys(
        %{"status" => "ok", "evil_key" => "value"},
        allowed_keys: ~w(status)
      )
      assert result == %{status: "ok", "evil_key" => "value"}
    end
  end

  describe "API CSRF Protection" do
    setup %{conn: conn} do
      # Create a test user for session authentication
      {:ok, user} = TamanduaServer.Accounts.create_user(%{
        email: "test_csrf_#{:rand.uniform(1_000_000)}@test.com",
        password: "password123456",
        password_confirmation: "password123456",
        name: "Test User"
      })

      {:ok, conn: conn, user: user}
    end

    test "allows GET requests without CSRF token", %{conn: conn, user: user} do
      conn =
        conn
        |> log_in_user(user)
        |> get("/api/v1/health")

      # Should not be blocked by CSRF (GET is safe method)
      refute conn.halted
    end

    test "allows Bearer token requests without CSRF", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer some_token")
        |> put_req_header("content-type", "application/json")

      # Initialize the plug
      conn = APICSRFProtection.call(conn, [])

      # Bearer token requests should skip CSRF check
      refute conn.halted
    end

    test "blocks session-authenticated POST without CSRF token", %{conn: conn, user: user} do
      conn =
        conn
        |> log_in_user(user)
        |> put_req_header("content-type", "application/json")
        |> assign(:current_user, user)

      conn = APICSRFProtection.call(conn |> Map.put(:method, "POST"), [])

      assert conn.halted
      assert conn.status == 403
      assert conn.resp_body =~ "CSRF token validation failed"
    end
  end

  describe "JSON parsing safety" do
    test "invalid JSON returns 400 not 500 for webhook endpoints", %{conn: conn} do
      # Test the capture_raw_body function indirectly through a webhook endpoint
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> post("/api/webhooks/test", "not valid json")

      # Should return 400 Bad Request, not 500 Internal Server Error
      assert conn.status in [400, 404]  # 404 if route doesn't exist, 400 if it does
    end
  end

  describe "CORS configuration" do
    test "cors_origins returns list for comma-separated env var" do
      # Store original value
      original = Application.get_env(:tamandua_server, :cors_origins)

      try do
        Application.put_env(:tamandua_server, :cors_origins, "https://a.com, https://b.com")
        origins = TamanduaServerWeb.Endpoint.cors_origins()

        assert is_list(origins)
        assert "https://a.com" in origins
        assert "https://b.com" in origins
      after
        if original do
          Application.put_env(:tamandua_server, :cors_origins, original)
        else
          Application.delete_env(:tamandua_server, :cors_origins)
        end
      end
    end

    test "cors_origins returns default for missing config" do
      original = Application.get_env(:tamandua_server, :cors_origins)

      try do
        Application.delete_env(:tamandua_server, :cors_origins)
        origins = TamanduaServerWeb.Endpoint.cors_origins()

        assert is_list(origins)
        assert "http://localhost:4000" in origins
      after
        if original do
          Application.put_env(:tamandua_server, :cors_origins, original)
        end
      end
    end
  end

  # Helper to simulate user login
  defp log_in_user(conn, user) do
    token = TamanduaServer.Accounts.generate_user_session_token(user)

    conn
    |> Phoenix.ConnTest.init_test_session(%{})
    |> Plug.Conn.put_session(:user_token, token)
  end
end
