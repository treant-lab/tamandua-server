defmodule TamanduaServerWeb.API.V1.StreamControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Accounts
  alias TamanduaServer.Streaming.StreamManager

  setup do
    # Create test organization
    {:ok, org} = Accounts.create_organization(%{
      name: "Test Org",
      slug: "test-org-#{:erlang.unique_integer([:positive])}"
    })

    # Create test user
    {:ok, user} = Accounts.create_user(%{
      email: "test-#{:erlang.unique_integer([:positive])}@example.com",
      password: "password123",
      organization_id: org.id,
      active: true
    })

    # Generate JWT token
    {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(user)

    # Start StreamManager if not already started
    start_supervised!(StreamManager)

    %{user: user, org: org, token: token}
  end

  describe "GET /api/v1/stream/alerts" do
    test "requires authentication", %{conn: conn} do
      conn = get(conn, "/api/v1/stream/alerts")
      assert json_response(conn, 401)["error"] == "Authentication required"
    end

    test "streams alerts with valid token", %{conn: conn, token: token} do
      # Note: This is a simplified test - actual SSE streaming is hard to test
      # In a real scenario, you'd use a client that can handle chunked responses

      conn = conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/stream/alerts")

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["text/event-stream"]
    end

    test "accepts filter parameters", %{conn: conn, token: token} do
      conn = conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/stream/alerts?severity=critical,high&agent_id=agent-123")

      assert conn.status == 200
    end
  end

  describe "GET /api/v1/stream/events" do
    test "requires authentication", %{conn: conn} do
      conn = get(conn, "/api/v1/stream/events")
      assert json_response(conn, 401)["error"] == "Authentication required"
    end

    test "streams events with valid token", %{conn: conn, token: token} do
      conn = conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/stream/events")

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["text/event-stream"]
    end
  end

  describe "GET /api/v1/stream/detections" do
    test "requires authentication", %{conn: conn} do
      conn = get(conn, "/api/v1/stream/detections")
      assert json_response(conn, 401)["error"] == "Authentication required"
    end

    test "streams detections with valid token", %{conn: conn, token: token} do
      conn = conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/stream/detections")

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["text/event-stream"]
    end
  end
end
