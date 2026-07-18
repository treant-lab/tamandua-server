defmodule TamanduaServer.Agents.TokenManagerTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Agents.TokenManager
  alias TamanduaServer.Agents.AgentCredential
  alias TamanduaServer.Agents.Credentials
  alias TamanduaServer.Enrollment
  alias TamanduaServer.Repo

  setup do
    # Create a test agent
    agent_id = Ecto.UUID.generate()
    organization = insert(:organization)

    {:ok, _} =
      Repo.insert(%TamanduaServer.Agents.Agent{
        id: agent_id,
        hostname: "test-agent",
        os: "linux",
        status: "online",
        organization_id: organization.id,
        token_rotation_enabled: true,
        token_ttl_hours: 720,
        token_refresh_window_percent: 60,
        current_token_generation: 0
      })

    {:ok, agent_id: agent_id, organization_id: organization.id}
  end

  describe "issue_token/2" do
    test "credential explicit expiry rejects invalid and non-future values", %{
      agent_id: agent_id,
      organization_id: organization_id
    } do
      assert {:error, :invalid_credential_expiry} =
               Credentials.issue_credential(agent_id, organization_id, expires_at: "invalid")

      assert {:error, :invalid_credential_issued_at} =
               Credentials.issue_credential(agent_id, organization_id, issued_at: "invalid")

      assert {:error, :invalid_credential_expiry} =
               Credentials.issue_credential(agent_id, organization_id,
                 expires_at: DateTime.add(DateTime.utc_now(), -1, :second)
               )

      assert Repo.aggregate(AgentCredential, :count) == 0
    end

    test "legacy credential expiry extension fails closed", %{
      agent_id: agent_id,
      organization_id: organization_id
    } do
      assert {:ok, _jti, credential} =
               Credentials.issue_credential(agent_id, organization_id)

      original_expiry = credential.expires_at

      assert {:error, :unsupported_legacy_expiry_extension} =
               Credentials.extend_expiry(
                 credential.jti,
                 DateTime.add(original_expiry, 365 * 24 * 3600, :second)
               )

      assert Repo.get!(AgentCredential, credential.id).expires_at == original_expiry
    end

    test "legacy arities fail closed without an organization", %{agent_id: agent_id} do
      assert {:error, :organization_scope_required} = TokenManager.issue_token(agent_id)

      assert {:error, :organization_scope_required} =
               TokenManager.issue_token(agent_id, ip_address: "127.0.0.1")
    end

    test "rejects an invalid organization before entering the GenServer", %{agent_id: agent_id} do
      assert {:error, :organization_scope_required} =
               TokenManager.issue_token(agent_id, "not-a-uuid")

      assert {:error, :organization_scope_required} = TokenManager.issue_token(agent_id, nil)
    end

    test "does not disclose or mutate an agent from another organization", %{agent_id: agent_id} do
      organization_id = agent_organization_id(agent_id)
      other_organization_id = Ecto.UUID.generate()

      assert {:error, :agent_not_found} =
               TokenManager.issue_token(agent_id, other_organization_id)

      agent = Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      assert agent.organization_id == organization_id
      assert agent.current_token_generation == 0
      assert Repo.aggregate(TokenManager.AgentToken, :count) == 0
      assert Repo.aggregate(AgentCredential, :count) == 0
    end

    test "issues a new JWT token for an agent", %{agent_id: agent_id} do
      organization_id = agent_organization_id(agent_id)

      assert {:ok, jwt, token_record} =
               TokenManager.issue_token(agent_id, organization_id)

      # Verify JWT is a non-empty string
      assert is_binary(jwt)
      assert String.length(jwt) > 0

      # Verify token record
      assert token_record.agent_id == agent_id
      assert token_record.token_generation == 1
      assert token_record.refresh_count == 0
      assert is_nil(token_record.revoked_at)
      assert not is_nil(token_record.issued_at)
      assert not is_nil(token_record.expires_at)

      # Verify token hash is stored
      assert String.length(token_record.token_hash) == 64

      assert {:ok, claims} = TokenManager.validate_token(jwt)
      assert claims["org_id"] == organization_id
      assert claims["organization_id"] == organization_id
      assert claims["iat"] == DateTime.to_unix(token_record.issued_at)
      assert claims["exp"] == DateTime.to_unix(token_record.expires_at)

      credential = Repo.get_by!(AgentCredential, jti: claims["credential_jti"])

      assert DateTime.compare(credential.issued_at, token_record.issued_at) == :eq

      assert DateTime.diff(credential.expires_at, token_record.expires_at, :second) ==
               TokenManager.refresh_grace_seconds()
    end

    test "treats nil and zero as not-yet-issued generation", %{
      agent_id: agent_id,
      organization_id: organization_id
    } do
      Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      |> Ecto.Changeset.change(current_token_generation: nil)
      |> Repo.update!()

      assert {:ok, _jwt, token} = TokenManager.issue_token(agent_id, organization_id)
      assert token.token_generation == 1
    end

    test "rolls back generation, credential, and revocation when token storage fails", %{
      agent_id: agent_id
    } do
      organization_id = agent_organization_id(agent_id)
      now = DateTime.utc_now()

      Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      |> Ecto.Changeset.change(current_token_generation: 1)
      |> Repo.update!()

      {:ok, previous_token} =
        %TokenManager.AgentToken{}
        |> TokenManager.AgentToken.changeset(%{
          agent_id: agent_id,
          token_generation: 1,
          token_hash: String.duplicate("a", 64),
          issued_at: now,
          expires_at: DateTime.add(now, 720 * 3600, :second)
        })
        |> Repo.insert()

      {:ok, _conflicting_token} =
        %TokenManager.AgentToken{}
        |> TokenManager.AgentToken.changeset(%{
          agent_id: agent_id,
          token_generation: 2,
          token_hash: String.duplicate("b", 64),
          issued_at: now,
          expires_at: DateTime.add(now, 720 * 3600, :second)
        })
        |> Repo.insert()

      assert {:error, :token_storage_failed} =
               TokenManager.issue_token(agent_id, organization_id)

      agent = Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      persisted_previous_token = Repo.get!(TokenManager.AgentToken, previous_token.id)

      assert agent.current_token_generation == 1
      assert is_nil(persisted_previous_token.revoked_at)
      assert Repo.aggregate(AgentCredential, :count) == 0
    end

    test "rolls back when token plus credential grace exceeds the 90 day lifetime cap", %{
      agent_id: agent_id,
      organization_id: organization_id
    } do
      Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      |> Ecto.Changeset.change(token_ttl_hours: 90 * 24)
      |> Repo.update!()

      assert {:error, :credential_storage_failed} =
               TokenManager.issue_token(agent_id, organization_id)

      agent = Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      assert agent.current_token_generation == 0
      assert Repo.aggregate(TokenManager.AgentToken, :count) == 0
      assert Repo.aggregate(AgentCredential, :count) == 0
    end

    test "increments generation on subsequent issue", %{agent_id: agent_id} do
      organization_id = agent_organization_id(agent_id)
      {:ok, _jwt1, token1} = TokenManager.issue_token(agent_id, organization_id)
      {:ok, _jwt2, token2} = TokenManager.issue_token(agent_id, organization_id)

      assert token2.token_generation == token1.token_generation + 1
      assert token2.token_generation == 2
    end

    test "revokes previous tokens when issuing new token", %{agent_id: agent_id} do
      organization_id = agent_organization_id(agent_id)
      {:ok, jwt1, token1} = TokenManager.issue_token(agent_id, organization_id)
      {:ok, old_claims} = TamanduaServer.Guardian.decode_and_verify(jwt1)

      {:ok, _jwt2, _token2} =
        TokenManager.issue_token(agent_id, organization_id)

      # Reload token1 from database
      reloaded = Repo.get(TokenManager.AgentToken, token1.id)

      assert not is_nil(reloaded.revoked_at)
      assert String.starts_with?(reloaded.revocation_reason, "superseded_by_generation_")

      old_credential =
        Repo.get_by!(AgentCredential, jti: old_claims["credential_jti"])

      assert old_credential.revocation_reason == "token_rotated"
      assert not is_nil(old_credential.revoked_at)
    end

    test "returns error when token rotation is disabled", %{agent_id: agent_id} do
      # Disable rotation
      Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      |> Ecto.Changeset.change(token_rotation_enabled: false)
      |> Repo.update!()

      assert {:error, :token_rotation_disabled} =
               TokenManager.issue_token(agent_id, agent_organization_id(agent_id))
    end
  end

  describe "Enrollment tenant collision" do
    test "recovery token from organization B cannot mutate or mint for agent in A", %{
      agent_id: agent_id,
      organization_id: organization_id
    } do
      other_organization = insert(:organization)

      {:ok, cleartext, installation_token} =
        Enrollment.generate_token(%{
          organization_id: other_organization.id,
          max_uses: 1,
          name: "cross-tenant-recovery-regression"
        })

      installation_token
      |> Ecto.Changeset.change(
        use_count: 1,
        consumed_at: DateTime.utc_now(),
        consumed_agent_id: agent_id
      )
      |> Repo.update!()

      assert {:error, :enrollment_unavailable} =
               Enrollment.enroll_with_csr(cleartext, "invalid-csr", %{"agent_id" => agent_id})

      agent = Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      assert agent.organization_id == organization_id
      assert agent.current_token_generation == 0
      assert Repo.aggregate(TokenManager.AgentToken, :count) == 0
      assert Repo.aggregate(AgentCredential, :count) == 0
    end
  end

  describe "refresh_token/2" do
    test "refreshes a valid token within refresh window", %{agent_id: agent_id} do
      # Issue initial token
      {:ok, jwt1, _token1} = TokenManager.issue_token(agent_id, agent_organization_id(agent_id))

      # Wait to enter refresh window (60% of 30 day TTL = 18 days)
      # For testing, we'll manipulate the issued_at timestamp
      token_record =
        Repo.get_by!(TokenManager.AgentToken, agent_id: agent_id, token_generation: 1)

      # Set issued_at to 19 days ago (past 60% of 30 day TTL)
      past_issued_at = DateTime.add(DateTime.utc_now(), -19 * 24 * 3600, :second)
      expires_at = DateTime.add(past_issued_at, 720 * 3600, :second)

      token_record
      |> Ecto.Changeset.change(issued_at: past_issued_at, expires_at: expires_at)
      |> Repo.update!()

      {:ok, old_claims} = TamanduaServer.Guardian.decode_and_verify(jwt1)

      # Attempt refresh
      assert {:ok, jwt2, refreshed_token} = TokenManager.refresh_token(jwt1)

      # Verify new token is different
      assert jwt2 != jwt1

      # Verify refresh count incremented
      assert refreshed_token.refresh_count == 1

      # Verify last_refreshed_at is set
      assert not is_nil(refreshed_token.last_refreshed_at)

      # Refresh is a one-time transition: the previous presentation and JTI
      # are invalid immediately after commit.
      assert {:error, :stale_token} = TokenManager.validate_token(jwt1)
      assert {:ok, new_claims} = TokenManager.validate_token(jwt2)
      refute new_claims["credential_jti"] == old_claims["credential_jti"]

      old_credential = Repo.get_by!(AgentCredential, jti: old_claims["credential_jti"])
      assert old_credential.revocation_reason == "token_refreshed"
      assert not is_nil(old_credential.revoked_at)
    end

    test "returns error when token is outside refresh window", %{agent_id: agent_id} do
      {:ok, jwt, _token} = TokenManager.issue_token(agent_id, agent_organization_id(agent_id))

      # Token was just issued, so it's at 0% of TTL (outside the refresh window)
      assert {:error, :too_early_to_refresh} = TokenManager.refresh_token(jwt)
    end

    test "does not refresh or mutate credentials when rotation is disabled", %{
      agent_id: agent_id
    } do
      organization_id = agent_organization_id(agent_id)
      {:ok, jwt, token} = TokenManager.issue_token(agent_id, organization_id)
      credential = Repo.get_by!(AgentCredential, agent_id: agent_id)

      Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      |> Ecto.Changeset.change(token_rotation_enabled: false)
      |> Repo.update!()

      assert {:error, :token_rotation_disabled} = TokenManager.refresh_token(jwt)

      persisted_token = Repo.get!(TokenManager.AgentToken, token.id)
      persisted_credential = Repo.get!(AgentCredential, credential.id)
      assert persisted_token.token_hash == token.token_hash
      assert persisted_token.refresh_count == token.refresh_count
      assert is_nil(persisted_credential.revoked_at)
      assert Repo.aggregate(AgentCredential, :count) == 1
    end

    test "refreshes expired DB-backed token inside grace without refresh-window deadlock", %{
      agent_id: agent_id
    } do
      agent = Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      now = DateTime.utc_now()
      jwt_expired_at = DateTime.add(now, -60, :second)
      issued_at = DateTime.add(jwt_expired_at, -720 * 3600, :second)

      credential_expires_at =
        DateTime.add(jwt_expired_at, TokenManager.refresh_grace_seconds(), :second)

      generation = 1
      jti = "expired-refresh-window-regression"

      claims = %{
        agent_id: agent_id,
        org_id: agent.organization_id,
        organization_id: agent.organization_id,
        generation: generation,
        credential_jti: jti,
        jti: jti,
        type: "agent",
        iat: DateTime.to_unix(issued_at),
        exp: DateTime.to_unix(jwt_expired_at)
      }

      {:ok, expired_jwt, _claims} =
        TamanduaServer.Guardian.encode_and_sign(%{id: agent_id}, claims, ttl: {-60, :second})

      token_hash = :crypto.hash(:sha256, expired_jwt) |> Base.encode16(case: :lower)

      Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      |> Ecto.Changeset.change(current_token_generation: generation)
      |> Repo.update!()

      %TokenManager.AgentToken{}
      |> TokenManager.AgentToken.changeset(%{
        agent_id: agent_id,
        token_generation: generation,
        token_hash: token_hash,
        issued_at: issued_at,
        expires_at: jwt_expired_at
      })
      |> Repo.insert!()

      Repo.insert!(%AgentCredential{
        agent_id: agent_id,
        organization_id: agent.organization_id,
        jti: jti,
        issued_at: issued_at,
        expires_at: credential_expires_at
      })

      assert {:ok, new_jwt, refreshed_token} = TokenManager.refresh_token(expired_jwt)
      assert new_jwt != expired_jwt
      assert refreshed_token.refresh_count == 1

      {:ok, new_claims} = TamanduaServer.Guardian.decode_and_verify(new_jwt)
      new_credential = Repo.get_by!(AgentCredential, jti: new_claims["credential_jti"])

      assert DateTime.compare(refreshed_token.issued_at, refreshed_token.last_refreshed_at) == :eq
      assert new_claims["iat"] == DateTime.to_unix(refreshed_token.issued_at)
      assert new_claims["iat"] == DateTime.to_unix(refreshed_token.last_refreshed_at)
      assert new_claims["exp"] == DateTime.to_unix(refreshed_token.expires_at)
      assert DateTime.compare(new_credential.issued_at, refreshed_token.last_refreshed_at) == :eq

      assert DateTime.diff(new_credential.expires_at, refreshed_token.expires_at, :second) ==
               TokenManager.refresh_grace_seconds()
    end

    test "rejects an expired token outside grace without mutation", %{agent_id: agent_id} do
      agent = Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      now = DateTime.utc_now()
      expires_at = DateTime.add(now, -8 * 24 * 3600, :second)
      issued_at = DateTime.add(expires_at, -720 * 3600, :second)
      jti = "outside-refresh-grace"

      claims = %{
        agent_id: agent_id,
        org_id: agent.organization_id,
        organization_id: agent.organization_id,
        generation: 1,
        credential_jti: jti,
        jti: jti,
        type: "agent",
        iat: DateTime.to_unix(issued_at),
        exp: DateTime.to_unix(expires_at)
      }

      {:ok, jwt, _claims} =
        TamanduaServer.Guardian.encode_and_sign(%{id: agent_id}, claims,
          ttl: {-8 * 24 * 3600, :second}
        )

      token_hash = :crypto.hash(:sha256, jwt) |> Base.encode16(case: :lower)

      agent
      |> Ecto.Changeset.change(current_token_generation: 1)
      |> Repo.update!()

      token =
        %TokenManager.AgentToken{}
        |> TokenManager.AgentToken.changeset(%{
          agent_id: agent_id,
          token_generation: 1,
          token_hash: token_hash,
          issued_at: issued_at,
          expires_at: expires_at
        })
        |> Repo.insert!()

      credential =
        Repo.insert!(%AgentCredential{
          agent_id: agent_id,
          organization_id: agent.organization_id,
          jti: jti,
          issued_at: issued_at,
          expires_at: DateTime.add(expires_at, 7 * 24 * 3600, :second)
        })

      assert {:error, :refresh_grace_expired} = TokenManager.refresh_token(jwt)

      persisted_token = Repo.get!(TokenManager.AgentToken, token.id)
      persisted_credential = Repo.get!(AgentCredential, credential.id)
      assert persisted_token.token_hash == token.token_hash
      assert persisted_token.refresh_count == token.refresh_count
      assert is_nil(persisted_credential.revoked_at)
    end

    test "returns error when token is revoked", %{agent_id: agent_id} do
      {:ok, jwt, token} = TokenManager.issue_token(agent_id, agent_organization_id(agent_id))

      # Revoke the token
      token
      |> Ecto.Changeset.change(revoked_at: DateTime.utc_now(), revocation_reason: "test")
      |> Repo.update!()

      # Add to cache
      :ets.insert(:agent_token_revocations, {{agent_id, 1}, DateTime.utc_now(), "test"})

      assert {:error, :token_revoked} = TokenManager.refresh_token(jwt)
    end

    test "does not mutate token when its tenant-bound credential is unavailable", %{
      agent_id: agent_id
    } do
      {:ok, jwt, token} = TokenManager.issue_token(agent_id, agent_organization_id(agent_id))
      past_issued_at = DateTime.add(DateTime.utc_now(), -19 * 24 * 3600, :second)
      expires_at = DateTime.add(past_issued_at, 720 * 3600, :second)

      token =
        token
        |> Ecto.Changeset.change(issued_at: past_issued_at, expires_at: expires_at)
        |> Repo.update!()

      credential = Repo.get_by!(AgentCredential, agent_id: agent_id)

      credential
      |> AgentCredential.revoke_changeset("fixture_unavailable")
      |> Repo.update!()

      assert {:error, :credential_revoked} = TokenManager.refresh_token(jwt)

      persisted = Repo.get!(TokenManager.AgentToken, token.id)
      assert persisted.token_hash == token.token_hash
      assert persisted.refresh_count == token.refresh_count
      assert Repo.aggregate(AgentCredential, :count) == 1
    end

    test "does not refresh with an expired credential", %{agent_id: agent_id} do
      {:ok, jwt, token} = TokenManager.issue_token(agent_id, agent_organization_id(agent_id))
      past_issued_at = DateTime.add(DateTime.utc_now(), -19 * 24 * 3600, :second)
      expires_at = DateTime.add(past_issued_at, 720 * 3600, :second)

      token =
        token
        |> Ecto.Changeset.change(issued_at: past_issued_at, expires_at: expires_at)
        |> Repo.update!()

      credential = Repo.get_by!(AgentCredential, agent_id: agent_id)

      credential
      |> Ecto.Changeset.change(expires_at: DateTime.add(DateTime.utc_now(), -1, :second))
      |> Repo.update!()

      assert {:error, :credential_expired} = TokenManager.refresh_token(jwt)
      persisted = Repo.get!(TokenManager.AgentToken, token.id)
      assert persisted.token_hash == token.token_hash
      assert persisted.refresh_count == token.refresh_count
      assert Repo.aggregate(AgentCredential, :count) == 1
    end
  end

  describe "refresh grace configuration" do
    test "defaults to seven days" do
      with_refresh_grace_config(:delete, fn ->
        assert TokenManager.refresh_grace_seconds() == 7 * 24 * 3600
      end)
    end

    test "caps oversized values at thirty days" do
      with_refresh_grace_config(365 * 24 * 3600, fn ->
        assert TokenManager.refresh_grace_seconds() == 30 * 24 * 3600
      end)
    end

    test "invalid and negative values fail safe to zero" do
      for invalid <- [-1, "604800", nil] do
        with_refresh_grace_config(invalid, fn ->
          assert TokenManager.refresh_grace_seconds() == 0
        end)
      end
    end
  end

  describe "validate_token/1" do
    test "validates a valid, non-revoked token", %{agent_id: agent_id} do
      {:ok, jwt, _token} = TokenManager.issue_token(agent_id, agent_organization_id(agent_id))

      assert {:ok, claims} = TokenManager.validate_token(jwt)
      assert claims["agent_id"] == agent_id
      assert claims["generation"] == 1
    end

    test "validates directly while the TokenManager process is busy", %{agent_id: agent_id} do
      {:ok, jwt, _token} = TokenManager.issue_token(agent_id, agent_organization_id(agent_id))

      :ok = :sys.suspend(TokenManager)

      try do
        assert {:ok, claims} = TokenManager.validate_token(jwt)
        assert claims["agent_id"] == agent_id
        assert claims["generation"] == 1
      after
        :ok = :sys.resume(TokenManager)
      end
    end

    test "returns error for revoked token", %{agent_id: agent_id} do
      {:ok, jwt, _token} = TokenManager.issue_token(agent_id, agent_organization_id(agent_id))

      # Revoke the token
      TokenManager.revoke_token(agent_id, agent_organization_id(agent_id))

      assert {:error, :revoked} = TokenManager.validate_token(jwt)
    end

    test "returns error for expired token", %{agent_id: agent_id} do
      {:ok, jwt, token} = TokenManager.issue_token(agent_id, agent_organization_id(agent_id))

      # Set expiry to the past
      token
      |> Ecto.Changeset.change(expires_at: DateTime.add(DateTime.utc_now(), -60, :second))
      |> Repo.update!()

      assert {:error, :expired} = TokenManager.validate_token(jwt)
    end

    test "returns error for token with mismatched generation", %{agent_id: agent_id} do
      organization_id = agent_organization_id(agent_id)
      {:ok, jwt1, _token1} = TokenManager.issue_token(agent_id, organization_id)

      {:ok, _jwt2, _token2} =
        TokenManager.issue_token(agent_id, organization_id)

      # jwt1 is now generation 1, but current generation is 2
      assert {:error, :generation_mismatch} = TokenManager.validate_token(jwt1)
    end
  end

  describe "revoke_token/2" do
    test "legacy organization-less arities fail closed", %{agent_id: agent_id} do
      assert {:error, :organization_scope_required} = TokenManager.revoke_token(agent_id)

      assert {:error, :organization_scope_required} =
               TokenManager.revoke_token(agent_id, reason: "unsafe_legacy_call")
    end

    test "wrong organization cannot revoke token or credential", %{
      agent_id: agent_id,
      organization_id: organization_id
    } do
      {:ok, jwt, _token} = TokenManager.issue_token(agent_id, organization_id)
      other_organization_id = insert(:organization).id

      assert {:error, :agent_not_found} =
               TokenManager.revoke_token(agent_id, other_organization_id)

      assert {:ok, _claims} = TokenManager.validate_token(jwt)
      credential = Repo.get_by!(AgentCredential, agent_id: agent_id)
      assert is_nil(credential.revoked_at)
    end

    test "revokes current generation token", %{agent_id: agent_id} do
      {:ok, jwt, _token} = TokenManager.issue_token(agent_id, agent_organization_id(agent_id))

      assert {:ok, %{revoked_count: 1}} =
               TokenManager.revoke_token(
                 agent_id,
                 agent_organization_id(agent_id),
                 reason: "test_revocation"
               )

      # Verify token is revoked
      assert {:error, :revoked} = TokenManager.validate_token(jwt)

      # Verify revocation is in ETS cache
      assert [{_, _revoked_at, "test_revocation"}] =
               :ets.lookup(:agent_token_revocations, {agent_id, 1})

      credential = Repo.get_by!(AgentCredential, agent_id: agent_id)
      assert credential.revocation_reason == "test_revocation"
      assert not is_nil(credential.revoked_at)
    end

    test "revokes all generations when all_generations is true", %{agent_id: agent_id} do
      organization_id = agent_organization_id(agent_id)
      {:ok, _jwt1, _token1} = TokenManager.issue_token(agent_id, organization_id)

      {:ok, _jwt2, _token2} = TokenManager.issue_token(agent_id, organization_id)

      {:ok, jwt3, _token3} = TokenManager.issue_token(agent_id, organization_id)

      # Should have generations 1, 2, 3 (1 and 2 already auto-revoked)
      # But let's un-revoke them for this test
      from(t in TokenManager.AgentToken, where: t.agent_id == ^agent_id)
      |> Repo.update_all(set: [revoked_at: nil])

      assert {:ok, %{revoked_count: 3}} =
               TokenManager.revoke_token(agent_id, organization_id,
                 all_generations: true,
                 reason: "bulk_revoke"
               )

      # All should be revoked
      assert {:error, :revoked} = TokenManager.validate_token(jwt3)
    end
  end

  describe "get_token_stats/1" do
    test "legacy organization-less arity fails closed", %{agent_id: agent_id} do
      assert {:error, :organization_scope_required} = TokenManager.get_token_stats(agent_id)
    end

    test "wrong organization cannot read statistics", %{agent_id: agent_id} do
      other_organization_id = insert(:organization).id

      assert {:error, :agent_not_found} =
               TokenManager.get_token_stats(agent_id, other_organization_id)
    end

    test "returns token statistics for an agent", %{agent_id: agent_id} do
      # Issue multiple tokens
      organization_id = agent_organization_id(agent_id)
      {:ok, _jwt1, _token1} = TokenManager.issue_token(agent_id, organization_id)

      {:ok, _jwt2, _token2} = TokenManager.issue_token(agent_id, organization_id)

      assert {:ok, stats} = TokenManager.get_token_stats(agent_id, organization_id)

      assert stats.total_tokens == 2
      assert stats.active_tokens == 1
      assert stats.revoked_tokens == 1
      assert stats.current_generation == 2
      assert stats.rotation_enabled == true
      assert stats.token_ttl_hours == 720
    end
  end

  describe "cleanup" do
    test "removes expired tokens from database", %{agent_id: agent_id} do
      # Create an old expired token (manually insert)
      old_expires = DateTime.add(DateTime.utc_now(), -8 * 24 * 3600, :second)

      # 8 days ago

      {:ok, _} =
        %TokenManager.AgentToken{}
        |> TokenManager.AgentToken.changeset(%{
          agent_id: agent_id,
          token_generation: 1,
          token_hash: "old_hash",
          issued_at: DateTime.add(old_expires, -3600, :second),
          expires_at: old_expires
        })
        |> Repo.insert()

      # Trigger cleanup (send message to GenServer)
      send(Process.whereis(TokenManager), :cleanup)

      # Wait for cleanup to complete
      Process.sleep(100)

      # Verify old token was deleted
      assert is_nil(Repo.get_by(TokenManager.AgentToken, agent_id: agent_id))
    end
  end

  describe "concurrent refresh" do
    test "handles concurrent refresh requests gracefully", %{agent_id: agent_id} do
      {:ok, jwt, _token} = TokenManager.issue_token(agent_id, agent_organization_id(agent_id))

      # Set token to be in refresh window
      token_record =
        Repo.get_by!(TokenManager.AgentToken, agent_id: agent_id, token_generation: 1)

      past_issued_at = DateTime.add(DateTime.utc_now(), -19 * 24 * 3600, :second)
      expires_at = DateTime.add(past_issued_at, 720 * 3600, :second)

      token_record
      |> Ecto.Changeset.change(issued_at: past_issued_at, expires_at: expires_at)
      |> Repo.update!()

      # Spawn multiple concurrent refresh requests
      tasks =
        for _ <- 1..5 do
          Task.async(fn ->
            TokenManager.refresh_token(jwt)
          end)
        end

      results = Task.await_many(tasks)

      # The row lock plus presented-hash check admits exactly one transition.
      successful = Enum.filter(results, fn result -> match?({:ok, _, _}, result) end)
      assert length(successful) == 1

      stale = Enum.filter(results, &(&1 == {:error, :stale_token}))
      assert length(stale) == 4
    end
  end

  defp agent_organization_id(agent_id) do
    Repo.get!(TamanduaServer.Agents.Agent, agent_id).organization_id
  end

  defp with_refresh_grace_config(value, fun) do
    key = :agent_token_refresh_grace_seconds
    previous = Application.fetch_env(:tamandua_server, key)

    if value == :delete do
      Application.delete_env(:tamandua_server, key)
    else
      Application.put_env(:tamandua_server, key, value)
    end

    try do
      fun.()
    after
      case previous do
        {:ok, old_value} -> Application.put_env(:tamandua_server, key, old_value)
        :error -> Application.delete_env(:tamandua_server, key)
      end
    end
  end
end
