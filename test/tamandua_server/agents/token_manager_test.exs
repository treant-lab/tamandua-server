defmodule TamanduaServer.Agents.TokenManagerTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Agents.TokenManager
  alias TamanduaServer.Repo

  setup do
    # Create a test agent
    agent_id = Ecto.UUID.generate()

    {:ok, _} =
      Repo.insert(%TamanduaServer.Agents.Agent{
        id: agent_id,
        hostname: "test-agent",
        os: "linux",
        status: "online",
        organization_id: Ecto.UUID.generate(),
        token_rotation_enabled: true,
        token_ttl_hours: 720,
        token_refresh_window_percent: 60,
        current_token_generation: 0
      })

    {:ok, agent_id: agent_id}
  end

  describe "issue_token/2" do
    test "issues a new JWT token for an agent", %{agent_id: agent_id} do
      assert {:ok, jwt, token_record} = TokenManager.issue_token(agent_id)

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
    end

    test "increments generation on subsequent issue", %{agent_id: agent_id} do
      {:ok, _jwt1, token1} = TokenManager.issue_token(agent_id)
      {:ok, _jwt2, token2} = TokenManager.issue_token(agent_id)

      assert token2.token_generation == token1.token_generation + 1
      assert token2.token_generation == 2
    end

    test "revokes previous tokens when issuing new token", %{agent_id: agent_id} do
      {:ok, _jwt1, token1} = TokenManager.issue_token(agent_id)
      {:ok, _jwt2, _token2} = TokenManager.issue_token(agent_id)

      # Reload token1 from database
      reloaded = Repo.get(TokenManager.AgentToken, token1.id)

      assert not is_nil(reloaded.revoked_at)
      assert String.starts_with?(reloaded.revocation_reason, "superseded_by_generation_")
    end

    test "returns error when token rotation is disabled", %{agent_id: agent_id} do
      # Disable rotation
      Repo.get!(TamanduaServer.Agents.Agent, agent_id)
      |> Ecto.Changeset.change(token_rotation_enabled: false)
      |> Repo.update!()

      assert {:error, :token_rotation_disabled} = TokenManager.issue_token(agent_id)
    end
  end

  describe "refresh_token/2" do
    test "refreshes a valid token within refresh window", %{agent_id: agent_id} do
      # Issue initial token
      {:ok, jwt1, _token1} = TokenManager.issue_token(agent_id)

      # Wait to enter refresh window (60% of 30 day TTL = 18 days)
      # For testing, we'll manipulate the issued_at timestamp
      token_record = Repo.get_by!(TokenManager.AgentToken, agent_id: agent_id, token_generation: 1)

      # Set issued_at to 19 days ago (past 60% of 30 day TTL)
      past_issued_at = DateTime.add(DateTime.utc_now(), -19 * 24 * 3600, :second)
      expires_at = DateTime.add(past_issued_at, 720 * 3600, :second)

      token_record
      |> Ecto.Changeset.change(issued_at: past_issued_at, expires_at: expires_at)
      |> Repo.update!()

      # Attempt refresh
      assert {:ok, jwt2, refreshed_token} = TokenManager.refresh_token(jwt1)

      # Verify new token is different
      assert jwt2 != jwt1

      # Verify refresh count incremented
      assert refreshed_token.refresh_count == 1

      # Verify last_refreshed_at is set
      assert not is_nil(refreshed_token.last_refreshed_at)
    end

    test "returns error when token is outside refresh window", %{agent_id: agent_id} do
      {:ok, jwt, _token} = TokenManager.issue_token(agent_id)

      # Token was just issued, so it's at 0% of TTL (outside the refresh window)
      assert {:error, :too_early_to_refresh} = TokenManager.refresh_token(jwt)
    end

    test "returns error when token is revoked", %{agent_id: agent_id} do
      {:ok, jwt, token} = TokenManager.issue_token(agent_id)

      # Revoke the token
      token
      |> Ecto.Changeset.change(revoked_at: DateTime.utc_now(), revocation_reason: "test")
      |> Repo.update!()

      # Add to cache
      :ets.insert(:agent_token_revocations, {{agent_id, 1}, DateTime.utc_now(), "test"})

      assert {:error, :token_revoked} = TokenManager.refresh_token(jwt)
    end
  end

  describe "validate_token/1" do
    test "validates a valid, non-revoked token", %{agent_id: agent_id} do
      {:ok, jwt, _token} = TokenManager.issue_token(agent_id)

      assert {:ok, claims} = TokenManager.validate_token(jwt)
      assert claims["agent_id"] == agent_id
      assert claims["generation"] == 1
    end

    test "returns error for revoked token", %{agent_id: agent_id} do
      {:ok, jwt, _token} = TokenManager.issue_token(agent_id)

      # Revoke the token
      TokenManager.revoke_token(agent_id)

      assert {:error, :revoked} = TokenManager.validate_token(jwt)
    end

    test "returns error for expired token", %{agent_id: agent_id} do
      {:ok, jwt, token} = TokenManager.issue_token(agent_id)

      # Set expiry to the past
      token
      |> Ecto.Changeset.change(expires_at: DateTime.add(DateTime.utc_now(), -60, :second))
      |> Repo.update!()

      assert {:error, :expired} = TokenManager.validate_token(jwt)
    end

    test "returns error for token with mismatched generation", %{agent_id: agent_id} do
      {:ok, jwt1, _token1} = TokenManager.issue_token(agent_id)
      {:ok, _jwt2, _token2} = TokenManager.issue_token(agent_id)

      # jwt1 is now generation 1, but current generation is 2
      assert {:error, :generation_mismatch} = TokenManager.validate_token(jwt1)
    end
  end

  describe "revoke_token/2" do
    test "revokes current generation token", %{agent_id: agent_id} do
      {:ok, jwt, _token} = TokenManager.issue_token(agent_id)

      assert {:ok, %{revoked_count: 1}} = TokenManager.revoke_token(agent_id, reason: "test_revocation")

      # Verify token is revoked
      assert {:error, :revoked} = TokenManager.validate_token(jwt)

      # Verify revocation is in ETS cache
      assert [{_, _revoked_at, "test_revocation"}] =
               :ets.lookup(:agent_token_revocations, {agent_id, 1})
    end

    test "revokes all generations when all_generations is true", %{agent_id: agent_id} do
      {:ok, _jwt1, _token1} = TokenManager.issue_token(agent_id)
      {:ok, _jwt2, _token2} = TokenManager.issue_token(agent_id)
      {:ok, jwt3, _token3} = TokenManager.issue_token(agent_id)

      # Should have generations 1, 2, 3 (1 and 2 already auto-revoked)
      # But let's un-revoke them for this test
      from(t in TokenManager.AgentToken, where: t.agent_id == ^agent_id)
      |> Repo.update_all(set: [revoked_at: nil])

      assert {:ok, %{revoked_count: 3}} =
               TokenManager.revoke_token(agent_id, all_generations: true, reason: "bulk_revoke")

      # All should be revoked
      assert {:error, :revoked} = TokenManager.validate_token(jwt3)
    end
  end

  describe "get_token_stats/1" do
    test "returns token statistics for an agent", %{agent_id: agent_id} do
      # Issue multiple tokens
      {:ok, _jwt1, _token1} = TokenManager.issue_token(agent_id)
      {:ok, _jwt2, _token2} = TokenManager.issue_token(agent_id)

      assert {:ok, stats} = TokenManager.get_token_stats(agent_id)

      assert stats.total_tokens == 2
      assert stats.active_tokens == 1
      assert stats.revoked_tokens == 1
      assert stats.current_generation == 2
      assert stats.rotation_enabled == true
      assert stats.token_ttl_hours == 720
    end
  end

  describe "cleanup" do
    test "removes expired tokens from database" do
      # Create an old expired token (manually insert)
      agent_id = Ecto.UUID.generate()
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
      {:ok, jwt, _token} = TokenManager.issue_token(agent_id)

      # Set token to be in refresh window
      token_record = Repo.get_by!(TokenManager.AgentToken, agent_id: agent_id, token_generation: 1)
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

      # At least one should succeed
      successful = Enum.filter(results, fn result -> match?({:ok, _, _}, result) end)
      assert length(successful) >= 1

      # All successful refreshes should return the same new token
      tokens = Enum.map(successful, fn {:ok, token, _} -> token end)
      assert Enum.uniq(tokens) |> length() == 1
    end
  end
end
