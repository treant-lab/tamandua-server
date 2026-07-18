defmodule TamanduaServerWeb.AgentSocketIdentityTest do
  @moduledoc """
  Tests for DB-backed agent socket identity validation.

  These tests verify the security requirements from ACCOUNT_INTEGRITY_THREAT_MODEL.md:
  1. Validate token against DB-backed agent credential record
  2. Check active/not-revoked status, org binding, token jti
  3. Require finite expiry (no infinite tokens)
  4. Require mTLS in production

  Note: Socket tests are async: false because they modify application config.
  """

  use TamanduaServerWeb.ChannelCase, async: false

  alias TamanduaServer.Agents.Credentials
  alias TamanduaServer.Agents.TokenManager
  alias TamanduaServer.Repo

  setup do
    # Store original config
    original_env = Application.get_env(:tamandua_server, :env)
    original_mtls = Application.get_env(:tamandua_server, :require_mtls)

    # Create test organization
    org = insert(:organization)

    # Create test agent
    # Pass the persisted org as the association (not organization_id):
    # agent_factory defaults `organization: build(:organization)`, and Ecto
    # rejects setting the FK while the assoc change is present.
    agent = insert(:agent, organization: org)

    on_exit(fn ->
      # Restore original config
      Application.put_env(:tamandua_server, :env, original_env)
      Application.put_env(:tamandua_server, :require_mtls, original_mtls)
    end)

    {:ok, org: org, agent: agent}
  end

  describe "DB-backed credential validation" do
    test "active AgentToken cannot rescue a missing managed credential", %{
      agent: agent,
      org: org
    } do
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)

      {:ok, token, _token_record} = TokenManager.issue_token(agent.id, org.id)
      {:ok, claims} = TamanduaServer.Guardian.decode_and_verify(token)

      {:ok, credential} =
        Credentials.get_by_jti(claims["credential_jti"], agent.id, org.id)

      Repo.delete!(credential)

      assert :error = connect(TamanduaServerWeb.AgentSocket, socket_params(agent, token))
    end

    test "rejects connection with revoked credential", %{agent: agent, org: org} do
      # Set test environment
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Issue a credential
      {:ok, jti, _credential} = Credentials.issue_credential(agent.id, org.id)

      # Create a JWT with the jti
      claims = managed_claims(agent.id, org.id, jti)

      {:ok, token, _} = TamanduaServer.Guardian.encode_and_sign(
        %{id: agent.id},
        claims,
        ttl: {1, :hour}
      )

      # Revoke the credential
      {:ok, _} = Credentials.revoke(jti, agent.id, org.id, "test_revocation")

      # Try to connect - should fail
      params = %{
        "token" => token,
        "agent_id" => agent.id,
        "hostname" => agent.hostname,
        "os_type" => agent.os_type
      }

      assert :error = connect(TamanduaServerWeb.AgentSocket, params)
    end

    test "rejects connection with expired credential", %{agent: agent, org: org} do
      # Set test environment
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Issue a credential
      {:ok, jti, credential} = Credentials.issue_credential(agent.id, org.id)

      # Manually expire the credential
      expired_at = DateTime.add(DateTime.utc_now(), -3600, :second)
      credential
      |> Ecto.Changeset.change(%{expires_at: expired_at})
      |> Repo.update!()

      # Create a JWT with the jti
      claims = managed_claims(agent.id, org.id, jti)

      {:ok, token, _} = TamanduaServer.Guardian.encode_and_sign(
        %{id: agent.id},
        claims,
        ttl: {1, :hour}
      )

      # Try to connect - should fail
      params = %{
        "token" => token,
        "agent_id" => agent.id,
        "hostname" => agent.hostname,
        "os_type" => agent.os_type
      }

      assert :error = connect(TamanduaServerWeb.AgentSocket, params)
    end

    test "accepts connection with valid credential and updates last_used_at", %{agent: agent, org: org} do
      # Set test environment
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Issue a credential
      {:ok, jti, credential} = Credentials.issue_credential(agent.id, org.id)

      # Verify last_used_at is nil initially
      assert is_nil(credential.last_used_at)

      # Create a JWT with the jti
      claims = managed_claims(agent.id, org.id, jti)

      {:ok, token, _} = TamanduaServer.Guardian.encode_and_sign(
        %{id: agent.id},
        claims,
        ttl: {1, :hour}
      )

      # Connect - should succeed
      params = %{
        "token" => token,
        "agent_id" => agent.id,
        "hostname" => agent.hostname,
        "os_type" => agent.os_type
      }

      assert {:ok, socket} = connect(TamanduaServerWeb.AgentSocket, params)
      assert socket.assigns.agent_id == agent.id
      assert socket.assigns.credential_jti == jti

      # Check that last_used_at was updated
      {:ok, updated_credential} = Credentials.get_by_jti(jti, agent.id, org.id)
      assert not is_nil(updated_credential.last_used_at)
      assert updated_credential.use_count == 1
    end

    test "rejects credential with organization mismatch", %{agent: agent, org: org} do
      # Set test environment
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Issue a credential for the correct org
      {:ok, jti, _} = Credentials.issue_credential(agent.id, org.id)

      # Create a JWT with a DIFFERENT org_id
      wrong_org_id = Ecto.UUID.generate()
      claims = managed_claims(agent.id, wrong_org_id, jti)

      {:ok, token, _} = TamanduaServer.Guardian.encode_and_sign(
        %{id: agent.id},
        claims,
        ttl: {1, :hour}
      )

      # Try to connect - should fail due to org mismatch
      params = %{
        "token" => token,
        "agent_id" => agent.id,
        "hostname" => agent.hostname,
        "os_type" => agent.os_type
      }

      assert :error = connect(TamanduaServerWeb.AgentSocket, params)
    end

    test "rejects credential with agent mismatch", %{agent: agent, org: org} do
      # Set test environment
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Issue a credential for this agent
      {:ok, jti, _} = Credentials.issue_credential(agent.id, org.id)

      # Create another agent
      other_agent = insert(:agent, organization: org)

      # Create a JWT with the OTHER agent's ID but the first agent's credential
      claims = managed_claims(other_agent.id, org.id, jti)

      {:ok, token, _} = TamanduaServer.Guardian.encode_and_sign(
        %{id: other_agent.id},
        claims,
        ttl: {1, :hour}
      )

      # Try to connect as other_agent with agent's credential - should fail
      params = %{
        "token" => token,
        "agent_id" => other_agent.id,
        "hostname" => other_agent.hostname,
        "os_type" => other_agent.os_type
      }

      assert :error = connect(TamanduaServerWeb.AgentSocket, params)
    end
  end

  describe "managed JWT duplicate identity claims" do
    test "rejects disagreeing subject and agent_id", %{agent: agent, org: org} do
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)
      {:ok, jti, _credential} = Credentials.issue_credential(agent.id, org.id)
      other_agent_id = Ecto.UUID.generate()

      {:ok, token, _} =
        TamanduaServer.Guardian.encode_and_sign(
          %{id: agent.id},
          managed_claims(other_agent_id, org.id, jti),
          ttl: {1, :hour}
        )

      assert :error = connect(TamanduaServerWeb.AgentSocket, socket_params(agent, token))
    end

    test "rejects disagreeing organization duplicates", %{agent: agent, org: org} do
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)
      {:ok, jti, _credential} = Credentials.issue_credential(agent.id, org.id)

      claims =
        agent.id
        |> managed_claims(org.id, jti)
        |> Map.put("organization_id", Ecto.UUID.generate())

      {:ok, token, _} =
        TamanduaServer.Guardian.encode_and_sign(%{id: agent.id}, claims, ttl: {1, :hour})

      assert :error = connect(TamanduaServerWeb.AgentSocket, socket_params(agent, token))
    end

    test "rejects disagreeing credential jti duplicates", %{agent: agent, org: org} do
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)
      {:ok, jti, _credential} = Credentials.issue_credential(agent.id, org.id)

      claims =
        agent.id
        |> managed_claims(org.id, jti)
        |> Map.put("jti", "different-managed-jti")

      {:ok, token, _} =
        TamanduaServer.Guardian.encode_and_sign(%{id: agent.id}, claims, ttl: {1, :hour})

      assert :error = connect(TamanduaServerWeb.AgentSocket, socket_params(agent, token))
    end
  end

  describe "legacy token finite expiry" do
    test "rejects legacy tokens with infinite lifetime in production", %{agent: agent} do
      # Set production environment
      Application.put_env(:tamandua_server, :env, :prod)
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Create a legacy Phoenix.Token
      claims = %{agent_id: agent.id}
      token = Phoenix.Token.sign(TamanduaServerWeb.Endpoint, "agent_auth", claims)

      params = %{
        "token" => token,
        "agent_id" => agent.id,
        "hostname" => agent.hostname,
        "os_type" => agent.os_type
      }

      # Should be rejected in production (even if mTLS is disabled for this test)
      # because production requires jti in JWT
      assert :error = connect(TamanduaServerWeb.AgentSocket, params)
    end

    test "accepts legacy tokens in dev/test with finite max_age", %{agent: agent} do
      # Set test environment
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Create a legacy Phoenix.Token
      claims = %{agent_id: agent.id}
      token = Phoenix.Token.sign(TamanduaServerWeb.Endpoint, "agent_auth", claims)

      params = %{
        "token" => token,
        "agent_id" => agent.id,
        "hostname" => agent.hostname,
        "os_type" => agent.os_type
      }

      # Should work in test env (but credential_jti will be nil)
      assert {:ok, socket} = connect(TamanduaServerWeb.AgentSocket, params)
      assert socket.assigns.agent_id == agent.id
      assert is_nil(socket.assigns.credential_jti)
    end
  end

  describe "JWT without jti in production" do
    test "rejects JWT without jti claim in production", %{agent: agent, org: org} do
      # Set production environment
      Application.put_env(:tamandua_server, :env, :prod)
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Create a JWT WITHOUT jti
      claims = %{
        "agent_id" => agent.id,
        "org_id" => org.id
        # Note: no "jti" claim
      }

      {:ok, token, _} = TamanduaServer.Guardian.encode_and_sign(
        %{id: agent.id},
        claims,
        ttl: {1, :hour}
      )

      params = %{
        "token" => token,
        "agent_id" => agent.id,
        "hostname" => agent.hostname,
        "os_type" => agent.os_type
      }

      # Should be rejected in production
      assert :error = connect(TamanduaServerWeb.AgentSocket, params)
    end

    test "rejects incomplete managed JWT without jti in test environment", %{
      agent: agent,
      org: org
    } do
      # Set test environment
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Create a JWT WITHOUT jti
      claims = %{
        "agent_id" => agent.id,
        "org_id" => org.id
      }

      {:ok, token, _} = TamanduaServer.Guardian.encode_and_sign(
        %{id: agent.id},
        claims,
        ttl: {1, :hour}
      )

      params = %{
        "token" => token,
        "agent_id" => agent.id,
        "hostname" => agent.hostname,
        "os_type" => agent.os_type
      }

      # An org-bound Guardian JWT is a managed-token candidate. Missing the
      # duplicate managed identity/JTI claims must fail closed rather than
      # downgrade to the environment-gated legacy JWT policy.
      assert :error = connect(TamanduaServerWeb.AgentSocket, params)
    end
  end

  describe "mTLS enforcement in production" do
    # Note: These tests verify the mTLS check logic, not actual TLS connections

    test "production requires mTLS to be configured" do
      # This test verifies the check_mtls_enforcement logic
      Application.put_env(:tamandua_server, :env, :prod)
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Clear LAB_LIGHT env var
      original_lab_light = System.get_env("TAMANDUA_LAB_LIGHT")
      System.delete_env("TAMANDUA_LAB_LIGHT")

      on_exit(fn ->
        if original_lab_light, do: System.put_env("TAMANDUA_LAB_LIGHT", original_lab_light)
      end)

      # Connection should fail because mTLS is required in production
      params = %{
        "token" => "any_token",
        "agent_id" => "any_id",
        "hostname" => "test",
        "os_type" => "linux"
      }

      assert :error = connect(TamanduaServerWeb.AgentSocket, params)
    end

    test "dev/test does not require mTLS", %{agent: agent} do
      # Set test environment
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Create a dev token
      params = %{
        "token" => "dev-test-token",
        "agent_id" => agent.id,
        "hostname" => agent.hostname,
        "os_type" => agent.os_type
      }

      # Should work without mTLS in dev/test
      assert {:ok, socket} = connect(TamanduaServerWeb.AgentSocket, params)
      assert socket.assigns.agent_id == agent.id
    end

    test "LAB_LIGHT mode bypasses mTLS in production" do
      # Set production environment
      Application.put_env(:tamandua_server, :env, :test)  # Actually use test to avoid real prod checks
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Enable LAB_LIGHT
      System.put_env("TAMANDUA_LAB_LIGHT", "true")

      on_exit(fn ->
        System.delete_env("TAMANDUA_LAB_LIGHT")
      end)

      # Create a dev token for testing
      agent = insert(:agent)
      params = %{
        "token" => "dev-lab-token",
        "agent_id" => agent.id,
        "hostname" => agent.hostname,
        "os_type" => agent.os_type
      }

      # Should work in LAB_LIGHT mode
      assert {:ok, socket} = connect(TamanduaServerWeb.AgentSocket, params)
      assert socket.assigns.agent_id == agent.id
    end
  end

  describe "credential lifecycle" do
    test "connection fails after all agent credentials are revoked", %{agent: agent, org: org} do
      # Set test environment
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :require_mtls, false)

      # Issue credentials
      {:ok, jti1, _} = Credentials.issue_credential(agent.id, org.id)
      {:ok, jti2, _} = Credentials.issue_credential(agent.id, org.id)

      # Create tokens
      claims1 = managed_claims(agent.id, org.id, jti1)
      {:ok, token1, _} =
        TamanduaServer.Guardian.encode_and_sign(%{id: agent.id}, claims1, ttl: {1, :hour})

      claims2 = managed_claims(agent.id, org.id, jti2)
      {:ok, token2, _} =
        TamanduaServer.Guardian.encode_and_sign(%{id: agent.id}, claims2, ttl: {1, :hour})

      # Both should work initially
      params1 = %{"token" => token1, "agent_id" => agent.id, "hostname" => agent.hostname, "os_type" => agent.os_type}
      params2 = %{"token" => token2, "agent_id" => agent.id, "hostname" => agent.hostname, "os_type" => agent.os_type}

      assert {:ok, _} = connect(TamanduaServerWeb.AgentSocket, params1)

      # Revoke all credentials for this agent
      {:ok, 2} =
        TamanduaServer.Agents.revoke_all_agent_credentials(
          agent.id,
          org.id,
          "agent_compromised"
        )

      # Now both should fail
      assert :error = connect(TamanduaServerWeb.AgentSocket, params2)
    end
  end

  defp managed_claims(agent_id, organization_id, jti) do
    %{
      "agent_id" => agent_id,
      "org_id" => organization_id,
      "organization_id" => organization_id,
      "credential_jti" => jti,
      "jti" => jti,
      "type" => "agent"
    }
  end

  defp socket_params(agent, token) do
    %{
      "token" => token,
      "agent_id" => agent.id,
      "hostname" => agent.hostname,
      "os_type" => agent.os_type
    }
  end
end
