defmodule TamanduaServerWeb.API.V1.PollControllerTest do
  use TamanduaServerWeb.ConnCase, async: true

  alias TamanduaServer.Accounts
  alias TamanduaServer.Alerts

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

    %{user: user, org: org, token: token}
  end

  describe "GET /api/v1/poll/alerts" do
    test "requires authentication", %{conn: conn} do
      since = System.system_time(:millisecond)
      conn = get(conn, "/api/v1/poll/alerts?since=#{since}")
      assert json_response(conn, 401)["error"] == "Authentication required"
    end

    test "requires since parameter", %{conn: conn, token: token} do
      conn = conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/poll/alerts")

      response = json_response(conn, 400)
      assert response["error"] =~ "since parameter is required"
    end

    test "returns empty array when no new alerts", %{conn: conn, token: token, org: org} do
      since = System.system_time(:millisecond)

      conn = conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/poll/alerts?since=#{since}")

      response = json_response(conn, 200)
      assert response["data"] == []
      assert response["count"] == 0
      assert response["has_more"] == false
    end

    test "returns alerts created after since timestamp", %{conn: conn, token: token, org: org} do
      # Get timestamp before creating alert
      since = System.system_time(:millisecond) - 1000

      # Create test alert
      {:ok, _alert} = Alerts.create_alert_for_org(org.id, %{
        severity: "critical",
        title: "Test Alert",
        description: "Test",
        agent_id: "agent-123"
      })

      # Poll for alerts
      conn = conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/poll/alerts?since=#{since}")

      response = json_response(conn, 200)
      assert length(response["data"]) >= 1
      assert response["count"] >= 1
    end

    test "filters by severity", %{conn: conn, token: token, org: org} do
      since = System.system_time(:millisecond) - 1000

      # Create alerts with different severities
      {:ok, _} = Alerts.create_alert_for_org(org.id, %{
        severity: "critical",
        title: "Critical Alert",
        description: "Test"
      })

      {:ok, _} = Alerts.create_alert_for_org(org.id, %{
        severity: "low",
        title: "Low Alert",
        description: "Test"
      })

      # Poll for critical alerts only
      conn = conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/poll/alerts?since=#{since}&severity=critical")

      response = json_response(conn, 200)
      assert length(response["data"]) >= 1

      # All returned alerts should be critical
      for alert <- response["data"] do
        assert alert["severity"] == "critical"
      end
    end

    test "supports pagination", %{conn: conn, token: token, org: org} do
      since = System.system_time(:millisecond) - 1000

      # Create multiple alerts
      for i <- 1..5 do
        Alerts.create_alert_for_org(org.id, %{
          severity: "medium",
          title: "Alert #{i}",
          description: "Test"
        })
      end

      # Get first page
      conn1 = conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/poll/alerts?since=#{since}&limit=2")

      response1 = json_response(conn1, 200)
      assert length(response1["data"]) == 2
      assert response1["has_more"] == true

      # Get second page
      conn2 = build_conn()
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/poll/alerts?since=#{since}&limit=2&offset=2")

      response2 = json_response(conn2, 200)
      assert length(response2["data"]) == 2
    end
  end

  describe "GET /api/v1/poll/events" do
    test "requires authentication", %{conn: conn} do
      since = System.system_time(:millisecond)
      conn = get(conn, "/api/v1/poll/events?since=#{since}")
      assert json_response(conn, 401)["error"] == "Authentication required"
    end

    test "requires since parameter", %{conn: conn, token: token} do
      conn = conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/poll/events")

      response = json_response(conn, 400)
      assert response["error"] =~ "since parameter is required"
    end

    test "returns empty array when no new events", %{conn: conn, token: token} do
      since = System.system_time(:millisecond)

      conn = conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/poll/events?since=#{since}")

      response = json_response(conn, 200)
      assert response["data"] == []
      assert response["count"] == 0
      assert response["has_more"] == false
    end
  end
end
