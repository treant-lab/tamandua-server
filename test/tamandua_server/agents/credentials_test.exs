defmodule TamanduaServer.Agents.CredentialsTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Agents.{Credentials, AgentCredential}
  alias TamanduaServer.Repo

  setup do
    # Create test organization
    org = insert(:organization)

    # Create test agent
    agent = insert(:agent, organization_id: org.id)

    {:ok, org: org, agent: agent}
  end

  describe "issue_credential/3" do
    test "issues a new credential with valid jti", %{agent: agent, org: org} do
      assert {:ok, jti, credential} = Credentials.issue_credential(agent.id, org.id)

      assert is_binary(jti)
      assert String.length(jti) > 20
      assert credential.agent_id == agent.id
      assert credential.organization_id == org.id
      assert credential.jti == jti
      assert not is_nil(credential.issued_at)
      assert not is_nil(credential.expires_at)
      assert is_nil(credential.revoked_at)
      assert credential.use_count == 0
    end

    test "uses 30 day default TTL", %{agent: agent, org: org} do
      {:ok, _jti, credential} = Credentials.issue_credential(agent.id, org.id)

      diff = DateTime.diff(credential.expires_at, credential.issued_at, :second)
      assert diff == 720 * 3600
    end

    test "floors short custom TTL to 30 days", %{agent: agent, org: org} do
      {:ok, _jti, credential} = Credentials.issue_credential(agent.id, org.id, ttl_hours: 1)

      diff = DateTime.diff(credential.expires_at, credential.issued_at, :second)
      assert diff == 720 * 3600
    end

    test "respects custom TTL above the floor", %{agent: agent, org: org} do
      {:ok, _jti, credential} = Credentials.issue_credential(agent.id, org.id, ttl_hours: 800)

      diff = DateTime.diff(credential.expires_at, credential.issued_at, :second)
      assert diff == 800 * 3600
    end

    test "stores IP address when provided", %{agent: agent, org: org} do
      {:ok, _jti, credential} =
        Credentials.issue_credential(
          agent.id,
          org.id,
          ip_address: "192.168.1.100"
        )

      assert credential.issued_from_ip == "192.168.1.100"
    end

    test "generates unique jti for each credential", %{agent: agent, org: org} do
      {:ok, jti1, _} = Credentials.issue_credential(agent.id, org.id)
      {:ok, jti2, _} = Credentials.issue_credential(agent.id, org.id)

      assert jti1 != jti2
    end

    test "rejects oversized or unknown issuance options", %{agent: agent, org: org} do
      assert {:error, :invalid_jti} =
               Credentials.issue_credential(agent.id, org.id, jti: String.duplicate("x", 256))

      assert {:error, :invalid_ip_address} =
               Credentials.issue_credential(agent.id, org.id,
                 ip_address: String.duplicate("x", 65)
               )

      assert {:error, :invalid_credential_ttl} =
               Credentials.issue_credential(agent.id, org.id, ttl_hours: 2_161)

      assert {:error, :invalid_options} =
               Credentials.issue_credential(agent.id, org.id, unexpected: true)
    end

    test "rejects a caller-provided issuance time in the future", %{agent: agent, org: org} do
      future = DateTime.add(DateTime.utc_now(), 3600, :second)

      assert {:error, :invalid_credential_issued_at} =
               Credentials.issue_credential(agent.id, org.id,
                 issued_at: future,
                 expires_at: DateTime.add(future, 720 * 3600, :second)
               )
    end

    test "rejects binding an agent to a different organization", %{agent: agent} do
      other_org = insert(:organization)

      assert {:error, :agent_not_found} =
               Credentials.issue_credential(agent.id, other_org.id)
    end
  end

  describe "validate_and_record_use/4" do
    test "validates and updates usage for valid credential", %{agent: agent, org: org} do
      {:ok, jti, _} = Credentials.issue_credential(agent.id, org.id)

      assert {:ok, credential} =
               Credentials.validate_and_record_use(jti, agent.id, org.id, "10.0.0.1")

      assert credential.use_count == 1
      assert credential.last_used_ip == "10.0.0.1"
      assert not is_nil(credential.last_used_at)
    end

    test "increments use_count on subsequent validations", %{agent: agent, org: org} do
      {:ok, jti, _} = Credentials.issue_credential(agent.id, org.id)

      {:ok, _} = Credentials.validate_and_record_use(jti, agent.id, org.id)
      {:ok, _} = Credentials.validate_and_record_use(jti, agent.id, org.id)
      {:ok, credential} = Credentials.validate_and_record_use(jti, agent.id, org.id)

      assert credential.use_count == 3
    end

    test "returns error for non-existent credential", %{agent: agent, org: org} do
      assert {:error, :credential_not_found} =
               Credentials.validate_and_record_use("nonexistent_jti", agent.id, org.id)
    end

    test "returns error for revoked credential", %{agent: agent, org: org} do
      {:ok, jti, _} = Credentials.issue_credential(agent.id, org.id)

      # Revoke the credential
      {:ok, _} = Credentials.revoke(jti, agent.id, org.id, "test_revocation")

      assert {:error, :credential_revoked} =
               Credentials.validate_and_record_use(jti, agent.id, org.id)
    end

    test "returns error for expired credential", %{agent: agent, org: org} do
      {:ok, jti, credential} = Credentials.issue_credential(agent.id, org.id)

      # Manually expire the credential
      expired_at = DateTime.add(DateTime.utc_now(), -3600, :second)

      credential
      |> Ecto.Changeset.change(%{expires_at: expired_at})
      |> Repo.update!()

      assert {:error, :credential_expired} =
               Credentials.validate_and_record_use(jti, agent.id, org.id)
    end

    test "returns error for agent mismatch", %{agent: agent, org: org} do
      {:ok, jti, _} = Credentials.issue_credential(agent.id, org.id)

      other_agent_id = Ecto.UUID.generate()

      assert {:error, :credential_not_found} =
               Credentials.validate_and_record_use(jti, other_agent_id, org.id)
    end

    test "returns error for organization mismatch", %{agent: agent, org: org} do
      {:ok, jti, _} = Credentials.issue_credential(agent.id, org.id)

      other_org_id = Ecto.UUID.generate()

      assert {:error, :credential_not_found} =
               Credentials.validate_and_record_use(jti, agent.id, other_org_id)
    end
  end

  describe "validate/3" do
    test "validates without updating usage", %{agent: agent, org: org} do
      {:ok, jti, _} = Credentials.issue_credential(agent.id, org.id)

      # Validate multiple times
      {:ok, _} = Credentials.validate(jti, agent.id, org.id)
      {:ok, _} = Credentials.validate(jti, agent.id, org.id)
      {:ok, credential} = Credentials.validate(jti, agent.id, org.id)

      # Use count should still be 0
      assert credential.use_count == 0
      assert is_nil(credential.last_used_at)
    end
  end

  describe "valid?/3" do
    test "returns true for valid credential", %{agent: agent, org: org} do
      {:ok, jti, _} = Credentials.issue_credential(agent.id, org.id)

      assert Credentials.valid?(jti, agent.id, org.id) == true
    end

    test "returns false for non-existent credential", %{agent: agent, org: org} do
      assert Credentials.valid?("nonexistent", agent.id, org.id) == false
    end

    test "returns false for revoked credential", %{agent: agent, org: org} do
      {:ok, jti, _} = Credentials.issue_credential(agent.id, org.id)
      {:ok, _} = Credentials.revoke(jti, agent.id, org.id, "test")

      assert Credentials.valid?(jti, agent.id, org.id) == false
    end
  end

  describe "revoke/4" do
    test "revokes a credential", %{agent: agent, org: org} do
      {:ok, jti, _} = Credentials.issue_credential(agent.id, org.id)

      assert {:ok, revoked} = Credentials.revoke(jti, agent.id, org.id, "test_reason")

      assert not is_nil(revoked.revoked_at)
      assert revoked.revocation_reason == "test_reason"
    end

    test "returns error for non-existent credential", %{agent: agent, org: org} do
      assert {:error, :credential_not_found} =
               Credentials.revoke("nonexistent", agent.id, org.id, "test")
    end

    test "rejects an oversized revocation reason", %{agent: agent, org: org} do
      {:ok, jti, _credential} = Credentials.issue_credential(agent.id, org.id)

      assert {:error, :invalid_revocation_reason} =
               Credentials.revoke(jti, agent.id, org.id, String.duplicate("x", 513))
    end
  end

  describe "revoke_all_for_agent/3" do
    test "revokes all credentials for an agent", %{agent: agent, org: org} do
      {:ok, jti1, _} = Credentials.issue_credential(agent.id, org.id)
      {:ok, jti2, _} = Credentials.issue_credential(agent.id, org.id)
      {:ok, jti3, _} = Credentials.issue_credential(agent.id, org.id)

      assert {:ok, 3} = Credentials.revoke_all_for_agent(agent.id, org.id, "bulk_revoke")

      # All should be invalid now
      assert Credentials.valid?(jti1, agent.id, org.id) == false
      assert Credentials.valid?(jti2, agent.id, org.id) == false
      assert Credentials.valid?(jti3, agent.id, org.id) == false
    end

    test "does not affect already-revoked credentials", %{agent: agent, org: org} do
      {:ok, jti1, _} = Credentials.issue_credential(agent.id, org.id)
      {:ok, _jti2, _} = Credentials.issue_credential(agent.id, org.id)

      # Revoke one first
      {:ok, _} = Credentials.revoke(jti1, agent.id, org.id, "first_revoke")

      # Now bulk revoke - should only affect the one remaining
      assert {:ok, 1} = Credentials.revoke_all_for_agent(agent.id, org.id, "bulk_revoke")
    end

    test "returns 0 when no active credentials exist", %{agent: agent, org: org} do
      assert {:ok, 0} =
               Credentials.revoke_all_for_agent(agent.id, org.id, "nothing_to_revoke")
    end
  end

  describe "revoke_all_for_organization/2" do
    test "revokes all credentials for an organization", %{org: org} do
      # Create multiple agents in the same org
      agent1 = insert(:agent, organization_id: org.id)
      agent2 = insert(:agent, organization_id: org.id)

      {:ok, jti1, _} = Credentials.issue_credential(agent1.id, org.id)
      {:ok, jti2, _} = Credentials.issue_credential(agent2.id, org.id)

      assert {:ok, 2} = Credentials.revoke_all_for_organization(org.id, "org_suspended")

      assert Credentials.valid?(jti1, agent1.id, org.id) == false
      assert Credentials.valid?(jti2, agent2.id, org.id) == false
    end
  end

  describe "list_active_for_agent/3" do
    test "returns only active credentials", %{agent: agent, org: org} do
      {:ok, jti1, _} = Credentials.issue_credential(agent.id, org.id)
      {:ok, _jti2, cred2} = Credentials.issue_credential(agent.id, org.id)
      {:ok, jti3, _} = Credentials.issue_credential(agent.id, org.id)

      # Revoke one
      Credentials.revoke(jti1, agent.id, org.id, "test")

      # Expire another
      expired_at = DateTime.add(DateTime.utc_now(), -3600, :second)

      cred2
      |> Ecto.Changeset.change(%{expires_at: expired_at})
      |> Repo.update!()

      active = Credentials.list_active_for_agent(agent.id, org.id)

      assert length(active) == 1
      assert hd(active).jti == jti3
    end
  end

  describe "get_stats/2" do
    test "returns correct statistics", %{agent: agent, org: org} do
      {:ok, jti1, _} = Credentials.issue_credential(agent.id, org.id)
      {:ok, _jti2, cred2} = Credentials.issue_credential(agent.id, org.id)
      {:ok, jti3, _} = Credentials.issue_credential(agent.id, org.id)

      # Use one credential a few times
      Credentials.validate_and_record_use(jti1, agent.id, org.id)
      Credentials.validate_and_record_use(jti1, agent.id, org.id)
      Credentials.validate_and_record_use(jti3, agent.id, org.id)

      # Revoke one
      Credentials.revoke(jti1, agent.id, org.id, "test")

      # Expire another
      expired_at = DateTime.add(DateTime.utc_now(), -3600, :second)

      cred2
      |> Ecto.Changeset.change(%{expires_at: expired_at})
      |> Repo.update!()

      stats = Credentials.get_stats(agent.id, org.id)

      assert stats.total == 3
      assert stats.active == 1
      assert stats.revoked == 1
      assert stats.expired == 1
      assert stats.total_uses == 3

      assert stats.last_used != nil
      assert stats.last_used.jti == jti3
    end
  end

  describe "cleanup_expired/3" do
    test "removes old expired credentials", %{agent: agent, org: org} do
      {:ok, _jti, credential} = Credentials.issue_credential(agent.id, org.id)

      # Set expiry to 40 days ago
      old_expires = DateTime.add(DateTime.utc_now(), -40 * 24 * 3600, :second)

      credential
      |> Ecto.Changeset.change(%{expires_at: old_expires})
      |> Repo.update!()

      assert {:ok, 1} = Credentials.cleanup_expired(org.id, 30)

      # Credential should be gone
      assert is_nil(Repo.get(AgentCredential, credential.id))
    end

    test "does not remove recent expired credentials", %{agent: agent, org: org} do
      {:ok, _jti, credential} = Credentials.issue_credential(agent.id, org.id)

      # Set expiry to 10 days ago (within 30 day window)
      recent_expires = DateTime.add(DateTime.utc_now(), -10 * 24 * 3600, :second)

      credential
      |> Ecto.Changeset.change(%{expires_at: recent_expires})
      |> Repo.update!()

      assert {:ok, 0} = Credentials.cleanup_expired(org.id, 30)

      # Credential should still exist
      assert Repo.get(AgentCredential, credential.id) != nil
    end

    test "does not remove another tenant's expired credential", %{org: org} do
      other_org = insert(:organization)
      other_agent = insert(:agent, organization_id: other_org.id)
      {:ok, _jti, credential} = Credentials.issue_credential(other_agent.id, other_org.id)

      old_expires = DateTime.add(DateTime.utc_now(), -40 * 24 * 3600, :second)
      credential |> Ecto.Changeset.change(%{expires_at: old_expires}) |> Repo.update!()

      assert {:ok, 0} = Credentials.cleanup_expired(org.id, 30)
      assert Repo.get(AgentCredential, credential.id) != nil
    end

    test "rejects unsafe retention and batch bounds", %{org: org} do
      assert {:error, :invalid_retention_days} = Credentials.cleanup_expired(org.id, 0)
      assert {:error, :invalid_retention_days} = Credentials.cleanup_expired(org.id, -30)
      assert {:error, :invalid_retention_days} = Credentials.cleanup_expired(org.id, 366)
      assert {:error, :invalid_limit} = Credentials.cleanup_expired(org.id, 30, limit: 1_001)
    end
  end

  describe "legacy organization-less entrypoints" do
    test "fail closed", %{agent: agent} do
      assert {:error, :organization_scope_required} = Credentials.get_by_jti("jti")
      assert {:error, :organization_scope_required} = Credentials.revoke("jti")
      assert {:error, :organization_scope_required} = Credentials.revoke("jti", "reason")
      assert {:error, :organization_scope_required} = Credentials.revoke_all_for_agent(agent.id)

      assert {:error, :organization_scope_required} =
               Credentials.revoke_all_for_agent(agent.id, "reason")

      assert {:error, :organization_scope_required} = Credentials.list_active_for_agent(agent.id)
      assert {:error, :organization_scope_required} = Credentials.get_stats(agent.id)
      assert {:error, :organization_scope_required} = Credentials.cleanup_expired()
      assert {:error, :organization_scope_required} = Credentials.cleanup_expired(30)
      refute Credentials.valid?("jti")
    end
  end

  describe "AgentCredential schema validation" do
    test "requires finite expiry", %{agent: agent, org: org} do
      now = DateTime.utc_now()

      # Expiry cannot be before issued_at
      changeset =
        AgentCredential.changeset(%AgentCredential{}, %{
          agent_id: agent.id,
          organization_id: org.id,
          jti: "test_jti",
          issued_at: now,
          expires_at: DateTime.add(now, -3600, :second)
        })

      assert {:error, changeset} = Repo.insert(changeset)
      assert "must be after issued_at" in errors_on(changeset).expires_at
    end

    test "enforces maximum 90 day token lifetime", %{agent: agent, org: org} do
      now = DateTime.utc_now()

      # Try to create a credential that expires in 100 days
      changeset =
        AgentCredential.changeset(%AgentCredential{}, %{
          agent_id: agent.id,
          organization_id: org.id,
          jti: "test_jti",
          issued_at: now,
          expires_at: DateTime.add(now, 100 * 24 * 3600, :second)
        })

      assert {:error, changeset} = Repo.insert(changeset)
      assert "token lifetime cannot exceed 90 days" in errors_on(changeset).expires_at
    end

    test "enforces unique jti", %{agent: agent, org: org} do
      {:ok, jti, _} = Credentials.issue_credential(agent.id, org.id)

      # Try to create another credential with the same jti
      now = DateTime.utc_now()

      changeset =
        AgentCredential.changeset(%AgentCredential{}, %{
          agent_id: agent.id,
          organization_id: org.id,
          jti: jti,
          issued_at: now,
          expires_at: DateTime.add(now, 3600, :second)
        })

      assert {:error, changeset} = Repo.insert(changeset)
      assert changeset.errors[:jti] != nil
    end
  end
end
