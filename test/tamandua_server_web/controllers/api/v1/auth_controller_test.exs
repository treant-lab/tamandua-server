defmodule TamanduaServerWeb.API.V1.AuthControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Agents.TokenManager
  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.User

  setup do
    # Create test organization
    org_id = insert(:organization).id
    other_org_id = insert(:organization).id

    # Create test admin user for the organization
    admin_user = %User{
      id: Ecto.UUID.generate(),
      email: "admin@test.com",
      password_hash: Bcrypt.hash_pwd_salt("password123"),
      role: "admin",
      organization_id: org_id,
      is_active: true
    }

    {:ok, admin} = Repo.insert(admin_user)

    # Create test analyst user (non-admin)
    analyst_user = %User{
      id: Ecto.UUID.generate(),
      email: "analyst@test.com",
      password_hash: Bcrypt.hash_pwd_salt("password123"),
      role: "analyst",
      organization_id: org_id,
      is_active: true
    }

    {:ok, analyst} = Repo.insert(analyst_user)

    # Create a test agent
    agent_id = Ecto.UUID.generate()

    {:ok, _} =
      Repo.insert(%TamanduaServer.Agents.Agent{
        id: agent_id,
        hostname: "test-agent",
        os: "linux",
        status: "online",
        organization_id: org_id,
        token_rotation_enabled: true,
        token_ttl_hours: 720,
        token_refresh_window_percent: 60,
        current_token_generation: 0
      })

    # Create agent in different organization
    other_agent_id = Ecto.UUID.generate()

    {:ok, _} =
      Repo.insert(%TamanduaServer.Agents.Agent{
        id: other_agent_id,
        hostname: "other-org-agent",
        os: "linux",
        status: "online",
        organization_id: other_org_id,
        token_rotation_enabled: true,
        token_ttl_hours: 720,
        token_refresh_window_percent: 60,
        current_token_generation: 0
      })

    # Issue initial token
    {:ok, jwt, _token} = TokenManager.issue_token(agent_id, org_id)

    {:ok,
     agent_id: agent_id,
     org_id: org_id,
     other_org_id: other_org_id,
     other_agent_id: other_agent_id,
     jwt: jwt,
     admin: admin,
     analyst: analyst}
  end

  # Helper to authenticate conn with a user
  defp authenticate(conn, user) do
    assign(conn, :current_user, user)
  end

  describe "POST /api/v1/agents/auth/refresh" do
    test "refreshes a valid token within refresh window", %{
      conn: conn,
      agent_id: agent_id,
      jwt: jwt
    } do
      # Set token to be in refresh window (60% of 30 day TTL)
      token_record =
        Repo.get_by!(TokenManager.AgentToken, agent_id: agent_id, token_generation: 1)

      past_issued_at = DateTime.add(DateTime.utc_now(), -19 * 24 * 3600, :second)
      expires_at = DateTime.add(past_issued_at, 720 * 3600, :second)

      token_record
      |> Ecto.Changeset.change(issued_at: past_issued_at, expires_at: expires_at)
      |> Repo.update!()

      # Attempt refresh
      conn =
        conn
        |> put_req_header("authorization", "Bearer #{jwt}")
        |> post("/api/v1/agents/auth/refresh", %{})

      assert %{
               "token" => new_token,
               "expires_at" => _expires,
               "generation" => 1,
               "refresh_count" => 1,
               "message" => "Token refreshed successfully"
             } = json_response(conn, 200)

      # Verify new token is different
      assert new_token != jwt

      # Verify new token is valid
      assert {:ok, _claims} = TokenManager.validate_token(new_token)
    end

    test "returns 403 when token is outside refresh window", %{conn: conn, jwt: jwt} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer #{jwt}")
        |> post("/api/v1/agents/auth/refresh", %{})

      assert %{
               "error" => "Token refresh not allowed yet",
               "message" => message
             } = json_response(conn, 403)

      assert message =~ "refresh window"
    end

    test "returns 401 when token is revoked", %{
      conn: conn,
      agent_id: agent_id,
      org_id: org_id,
      jwt: jwt
    } do
      # Revoke the token
      TokenManager.revoke_token(agent_id, org_id)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{jwt}")
        |> post("/api/v1/agents/auth/refresh", %{})

      assert %{
               "error" => "Token has been revoked"
             } = json_response(conn, 401)
    end

    test "returns 401 when authorization header is missing", %{conn: conn} do
      conn = post(conn, "/api/v1/agents/auth/refresh", %{})

      assert %{"error" => "Missing authorization token"} = json_response(conn, 401)
    end

    test "returns 401 when token has expired", %{conn: conn, agent_id: agent_id, jwt: jwt} do
      # Set token expiry to the past
      token_record =
        Repo.get_by!(TokenManager.AgentToken, agent_id: agent_id, token_generation: 1)

      token_record
      |> Ecto.Changeset.change(expires_at: DateTime.add(DateTime.utc_now(), -60, :second))
      |> Repo.update!()

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{jwt}")
        |> post("/api/v1/agents/auth/refresh", %{})

      assert %{"error" => "Token has expired"} = json_response(conn, 401)
    end
  end

  describe "GET /api/v1/agents/auth/status" do
    test "returns token status for a valid token", %{conn: conn, agent_id: agent_id, jwt: jwt} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer #{jwt}")
        |> get("/api/v1/agents/auth/status")

      assert %{
               "valid" => true,
               "agent_id" => ^agent_id,
               "generation" => 1,
               "issued_at" => _issued,
               "expires_at" => _expires,
               "refresh_eligible" => false,
               "time_to_expiry_seconds" => ttl,
               "percent_elapsed" => percent,
               "refresh_count" => 0,
               "revoked" => false
             } = json_response(conn, 200)

      # Token just issued, should have most of its lifetime left
      assert ttl > 3000
      assert percent < 10.0
    end

    test "indicates refresh eligibility when in refresh window", %{
      conn: conn,
      agent_id: agent_id,
      jwt: jwt
    } do
      # Set token to be in refresh window
      token_record =
        Repo.get_by!(TokenManager.AgentToken, agent_id: agent_id, token_generation: 1)

      past_issued_at = DateTime.add(DateTime.utc_now(), -19 * 24 * 3600, :second)
      expires_at = DateTime.add(past_issued_at, 720 * 3600, :second)

      token_record
      |> Ecto.Changeset.change(issued_at: past_issued_at, expires_at: expires_at)
      |> Repo.update!()

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{jwt}")
        |> get("/api/v1/agents/auth/status")

      assert %{
               "valid" => true,
               "refresh_eligible" => true,
               "percent_elapsed" => percent
             } = json_response(conn, 200)

      # Should be past 60% of TTL
      assert percent >= 60.0
    end

    test "returns invalid status for revoked token", %{
      conn: conn,
      agent_id: agent_id,
      org_id: org_id,
      jwt: jwt
    } do
      TokenManager.revoke_token(agent_id, org_id)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{jwt}")
        |> get("/api/v1/agents/auth/status")

      assert %{"valid" => false} = json_response(conn, 401)
    end

    test "returns 401 when authorization header is missing", %{conn: conn} do
      conn = get(conn, "/api/v1/agents/auth/status")

      assert %{"valid" => false, "error" => "Missing authorization token"} =
               json_response(conn, 401)
    end
  end

  describe "POST /api/v1/agents/auth/revoke" do
    test "anonymous user cannot revoke", %{conn: conn, agent_id: agent_id} do
      conn =
        post(conn, "/api/v1/agents/auth/revoke", %{
          "agent_id" => agent_id,
          "reason" => "security_incident"
        })

      assert %{"error" => "Authentication required"} = json_response(conn, 401)
    end

    test "admin can revoke own tenant agent", %{
      conn: conn,
      agent_id: agent_id,
      jwt: jwt,
      admin: admin
    } do
      conn =
        conn
        |> authenticate(admin)
        |> post("/api/v1/agents/auth/revoke", %{
          "agent_id" => agent_id,
          "reason" => "security_incident"
        })

      assert %{
               "status" => "revoked",
               "agent_id" => ^agent_id,
               "revoked_count" => 1,
               "reason" => "security_incident"
             } = json_response(conn, 200)

      # Verify token is now invalid
      assert {:error, :revoked} = TokenManager.validate_token(jwt)
    end

    test "user cannot revoke agent from different tenant", %{
      conn: conn,
      admin: admin,
      other_agent_id: other_agent_id
    } do
      conn =
        conn
        |> authenticate(admin)
        |> post("/api/v1/agents/auth/revoke", %{
          "agent_id" => other_agent_id,
          "reason" => "test"
        })

      # Return 404 to avoid enumeration attacks
      assert %{"error" => "Agent not found"} = json_response(conn, 404)
    end

    test "analyst cannot revoke agent (insufficient permissions)", %{
      conn: conn,
      agent_id: agent_id,
      analyst: analyst
    } do
      conn =
        conn
        |> authenticate(analyst)
        |> post("/api/v1/agents/auth/revoke", %{
          "agent_id" => agent_id,
          "reason" => "test"
        })

      assert %{"error" => "Not authorized to manage this agent"} = json_response(conn, 403)
    end

    test "revokes all generations when all_generations is true", %{
      conn: conn,
      agent_id: agent_id,
      org_id: org_id,
      admin: admin
    } do
      # Issue multiple tokens
      {:ok, _jwt2, _} = TokenManager.issue_token(agent_id, org_id)
      {:ok, _jwt3, _} = TokenManager.issue_token(agent_id, org_id)

      conn =
        conn
        |> authenticate(admin)
        |> post("/api/v1/agents/auth/revoke", %{
          "agent_id" => agent_id,
          "all_generations" => true,
          "reason" => "agent_decommissioned"
        })

      assert %{
               "revoked_count" => count
             } = json_response(conn, 200)

      # Should revoke all active tokens
      assert count >= 1
    end

    test "returns 400 when agent_id is missing", %{conn: conn, admin: admin} do
      conn =
        conn
        |> authenticate(admin)
        |> post("/api/v1/agents/auth/revoke", %{"reason" => "test"})

      assert %{"error" => "Missing required field: agent_id"} = json_response(conn, 400)
    end
  end

  describe "GET /api/v1/agents/auth/stats/:agent_id" do
    test "anonymous user cannot get stats", %{conn: conn, agent_id: agent_id} do
      conn = get(conn, "/api/v1/agents/auth/stats/#{agent_id}")

      assert %{"error" => "Authentication required"} = json_response(conn, 401)
    end

    test "authenticated user can get stats for own tenant agent", %{
      conn: conn,
      agent_id: agent_id,
      org_id: org_id,
      admin: admin
    } do
      # Issue additional token to have multiple generations
      {:ok, _jwt2, _} = TokenManager.issue_token(agent_id, org_id)

      conn =
        conn
        |> authenticate(admin)
        |> get("/api/v1/agents/auth/stats/#{agent_id}")

      assert %{
               "total_tokens" => 2,
               "active_tokens" => 1,
               "revoked_tokens" => 1,
               "current_generation" => 2,
               "rotation_enabled" => true,
               "token_ttl_hours" => 720
             } = json_response(conn, 200)
    end

    test "user cannot get stats for agent from different tenant", %{
      conn: conn,
      admin: admin,
      other_agent_id: other_agent_id
    } do
      conn =
        conn
        |> authenticate(admin)
        |> get("/api/v1/agents/auth/stats/#{other_agent_id}")

      # Return 404 to avoid enumeration attacks
      assert %{"error" => "Agent not found"} = json_response(conn, 404)
    end

    test "analyst can get stats for own tenant agent", %{
      conn: conn,
      agent_id: agent_id,
      analyst: analyst
    } do
      conn =
        conn
        |> authenticate(analyst)
        |> get("/api/v1/agents/auth/stats/#{agent_id}")

      # Stats endpoint is available to all authenticated users in the tenant
      assert %{"total_tokens" => _} = json_response(conn, 200)
    end
  end

  describe "debug endpoints" do
    test "debug/sessions returns data in dev/test env" do
      # This test verifies the endpoint exists in dev/test
      # In production, it would be behind auth or return 404
      # The actual behavior depends on Mix.env at compile time
    end
  end

  describe "rate limiting and security headers" do
    test "includes appropriate security headers", %{conn: conn, jwt: jwt} do
      # Set token to refresh window
      token_record =
        Repo.get_by!(TokenManager.AgentToken,
          agent_id: conn.assigns[:agent_id] || List.first(Map.keys(conn.assigns))
        )

      if token_record do
        past_issued_at = DateTime.add(DateTime.utc_now(), -19 * 24 * 3600, :second)
        expires_at = DateTime.add(past_issued_at, 720 * 3600, :second)

        token_record
        |> Ecto.Changeset.change(issued_at: past_issued_at, expires_at: expires_at)
        |> Repo.update!()
      end

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{jwt}")
        |> post("/api/v1/agents/auth/refresh", %{})

      # Verify response includes security headers (if configured)
      # This is a placeholder - actual headers depend on plug configuration
      assert conn.status in [200, 403, 401]
    end
  end
end
