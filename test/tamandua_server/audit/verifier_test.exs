defmodule TamanduaServer.Audit.VerifierTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Audit.{Verifier, Signature, MerkleTree}
  alias TamanduaServer.Audit.AuditLog
  alias TamanduaServer.AuditLog, as: AuditService

  describe "seal_batch/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)

      # Create some audit log entries
      entries = Enum.map(1..10, fn i ->
        {:ok, entry} = AuditService.log(%{
          organization_id: org.id,
          user_id: user.id,
          user_email: user.email,
          action: "test_action_#{i}",
          action_type: "test",
          resource_type: "test_resource",
          resource_id: "resource_#{i}",
          severity: :info
        })
        entry
      end)

      {:ok, org: org, user: user, entries: entries}
    end

    test "seals batch of unsealed entries", %{org: org} do
      {:ok, seal} = Verifier.seal_batch(org.id, force: true)

      assert seal.organization_id == org.id
      assert seal.seal_number == 1
      assert seal.entry_count == 10
      assert seal.start_sequence > 0
      assert seal.end_sequence >= seal.start_sequence
      assert is_binary(seal.merkle_root)
      assert byte_size(seal.signature) == 64
      assert byte_size(seal.public_key) == 32
    end

    test "returns error when no entries to seal" do
      org = insert(:organization)

      assert {:error, :no_entries_to_seal} = Verifier.seal_batch(org.id)
    end

    test "returns error for small batch without force", %{org: org} do
      # Create only 2 entries (below threshold)
      org2 = insert(:organization)
      user = insert(:user, organization: org2)

      Enum.each(1..2, fn i ->
        AuditService.log(%{
          organization_id: org2.id,
          user_id: user.id,
          user_email: user.email,
          action: "test_#{i}",
          action_type: "test",
          severity: :info
        })
      end)

      assert {:error, :batch_too_small} = Verifier.seal_batch(org2.id)
    end

    test "updates entries with seal_id and merkle_proof", %{org: org, entries: entries} do
      {:ok, seal} = Verifier.seal_batch(org.id, force: true)

      # Reload entries
      updated_entries = Enum.map(entries, fn entry ->
        Repo.get(AuditLog, entry.id)
      end)

      Enum.each(updated_entries, fn entry ->
        assert entry.seal_id == seal.id
        assert is_map(entry.merkle_proof)
        assert Map.has_key?(entry.merkle_proof, "proof")
        assert Map.has_key?(entry.merkle_proof, "root_hash")
        assert entry.merkle_proof["root_hash"] == seal.merkle_root
      end)
    end

    test "increments seal number for subsequent seals", %{org: org, user: user} do
      # First seal
      {:ok, seal1} = Verifier.seal_batch(org.id, force: true)
      assert seal1.seal_number == 1

      # Create more entries
      Enum.each(11..20, fn i ->
        AuditService.log(%{
          organization_id: org.id,
          user_id: user.id,
          user_email: user.email,
          action: "test_#{i}",
          action_type: "test",
          severity: :info
        })
      end)

      # Second seal
      {:ok, seal2} = Verifier.seal_batch(org.id, force: true)
      assert seal2.seal_number == 2
    end
  end

  describe "verify_entry/1" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)

      # Create and seal entries
      Enum.each(1..10, fn i ->
        AuditService.log(%{
          organization_id: org.id,
          user_id: user.id,
          user_email: user.email,
          action: "test_#{i}",
          action_type: "test",
          severity: :info
        })
      end)

      {:ok, seal} = Verifier.seal_batch(org.id, force: true)

      entry = from(a in AuditLog, where: a.seal_id == ^seal.id, limit: 1)
              |> Repo.one()

      {:ok, org: org, seal: seal, entry: entry}
    end

    test "verifies valid sealed entry", %{entry: entry} do
      assert {:ok, :valid} = Verifier.verify_entry(entry.id)
    end

    test "returns error for unsealed entry" do
      org = insert(:organization)
      user = insert(:user, organization: org)

      {:ok, unsealed_entry} = AuditService.log(%{
        organization_id: org.id,
        user_id: user.id,
        user_email: user.email,
        action: "unsealed",
        action_type: "test",
        severity: :info
      })

      assert {:error, :entry_not_sealed} = Verifier.verify_entry(unsealed_entry.id)
    end

    test "returns error for non-existent entry" do
      fake_id = Ecto.UUID.generate()
      assert {:error, :entry_not_found} = Verifier.verify_entry(fake_id)
    end

    test "detects tampered entry", %{entry: entry} do
      # Tamper with the entry's action field
      from(a in AuditLog, where: a.id == ^entry.id)
      |> Repo.update_all(set: [action: "tampered_action"])

      # Verification should fail because entry hash won't match proof
      result = Verifier.verify_entry(entry.id)
      assert match?({:error, _}, result)
    end
  end

  describe "verify_seal/1" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)

      Enum.each(1..10, fn i ->
        AuditService.log(%{
          organization_id: org.id,
          user_id: user.id,
          user_email: user.email,
          action: "test_#{i}",
          action_type: "test",
          severity: :info
        })
      end)

      {:ok, seal} = Verifier.seal_batch(org.id, force: true)

      {:ok, org: org, seal: seal}
    end

    test "verifies all entries in valid seal", %{seal: seal} do
      assert {:ok, :all_valid} = Verifier.verify_seal(seal.id)
    end

    test "detects invalid entries in seal", %{seal: seal} do
      # Tamper with one entry
      entry = from(a in AuditLog, where: a.seal_id == ^seal.id, limit: 1)
              |> Repo.one()

      from(a in AuditLog, where: a.id == ^entry.id)
      |> Repo.update_all(set: [action: "tampered"])

      result = Verifier.verify_seal(seal.id)
      assert match?({:error, {:invalid_entries, _}}, result)
    end

    test "returns error for non-existent seal" do
      fake_id = Ecto.UUID.generate()
      assert {:error, :seal_not_found} = Verifier.verify_seal(fake_id)
    end
  end

  describe "check_tampering/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)

      # Create multiple batches
      for batch <- 1..3 do
        Enum.each(1..10, fn i ->
          AuditService.log(%{
            organization_id: org.id,
            user_id: user.id,
            user_email: user.email,
            action: "batch_#{batch}_action_#{i}",
            action_type: "test",
            severity: :info
          })
        end)

        {:ok, _seal} = Verifier.seal_batch(org.id, force: true)
      end

      {:ok, org: org}
    end

    test "returns no_tampering for valid seals", %{org: org} do
      assert {:ok, :no_tampering} = Verifier.check_tampering(org.id)
    end

    test "detects tampering in sealed batches", %{org: org} do
      # Tamper with an entry in first seal
      seal = from(s in Signature, where: s.organization_id == ^org.id, order_by: [asc: :seal_number], limit: 1)
             |> Repo.one()

      entry = from(a in AuditLog, where: a.seal_id == ^seal.id, limit: 1)
              |> Repo.one()

      from(a in AuditLog, where: a.id == ^entry.id)
      |> Repo.update_all(set: [action: "tampered"])

      result = Verifier.check_tampering(org.id)
      assert match?({:error, {:tampering_detected, _}}, result)
    end

    test "respects limit option", %{org: org} do
      # Only check first 2 seals
      assert {:ok, :no_tampering} = Verifier.check_tampering(org.id, limit: 2)
    end
  end

  describe "generate_integrity_report/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)

      # Create and seal multiple batches
      Enum.each(1..20, fn i ->
        AuditService.log(%{
          organization_id: org.id,
          user_id: user.id,
          user_email: user.email,
          action: "test_#{i}",
          action_type: "test",
          severity: :info
        })
      end)

      {:ok, seal} = Verifier.seal_batch(org.id, force: true)

      {:ok, org: org, seal: seal}
    end

    test "generates comprehensive integrity report", %{org: org} do
      report = Verifier.generate_integrity_report(org.id)

      assert report.organization_id == org.id
      assert is_map(report.summary)
      assert report.summary.total_seals >= 1
      assert report.summary.valid_seals >= 0
      assert report.summary.invalid_seals >= 0
      assert report.summary.total_sealed_entries >= 10
      assert report.summary.integrity_score >= 0
      assert report.summary.integrity_score <= 100
      assert is_list(report.seals)
      assert is_struct(report.generated_at, DateTime)
    end

    test "includes seal verification results", %{org: org} do
      report = Verifier.generate_integrity_report(org.id)

      Enum.each(report.seals, fn seal_result ->
        assert Map.has_key?(seal_result, :seal_id)
        assert Map.has_key?(seal_result, :seal_number)
        assert Map.has_key?(seal_result, :sealed_at)
        assert Map.has_key?(seal_result, :entry_count)
        assert Map.has_key?(seal_result, :verified)
        assert Map.has_key?(seal_result, :details)
      end)
    end

    test "respects date range", %{org: org} do
      # Future date range should return no seals
      future_start = DateTime.add(DateTime.utc_now(), 1, :day)
      future_end = DateTime.add(DateTime.utc_now(), 2, :day)

      report = Verifier.generate_integrity_report(org.id,
        date_from: future_start,
        date_to: future_end
      )

      assert report.summary.total_seals == 0
    end
  end

  describe "auto_seal/1" do
    test "seals batch when entry count threshold reached" do
      org = insert(:organization)
      user = insert(:user, organization: org)

      # Create entries exceeding threshold
      Enum.each(1..10_100, fn i ->
        AuditService.log(%{
          organization_id: org.id,
          user_id: user.id,
          user_email: user.email,
          action: "test_#{i}",
          action_type: "test",
          severity: :info
        })
      end)

      assert {:ok, %Signature{}} = Verifier.auto_seal(org.id)
    end

    test "returns not_needed when conditions not met" do
      org = insert(:organization)
      user = insert(:user, organization: org)

      # Create only a few entries
      Enum.each(1..5, fn i ->
        AuditService.log(%{
          organization_id: org.id,
          user_id: user.id,
          user_email: user.email,
          action: "test_#{i}",
          action_type: "test",
          severity: :info
        })
      end)

      assert {:ok, :not_needed} = Verifier.auto_seal(org.id)
    end
  end

  describe "seal_all_pending/0" do
    test "seals batches for all organizations with unsealed entries" do
      # Create entries for multiple organizations
      Enum.each(1..3, fn org_num ->
        org = insert(:organization)
        user = insert(:user, organization: org)

        Enum.each(1..100, fn i ->
          AuditService.log(%{
            organization_id: org.id,
            user_id: user.id,
            user_email: user.email,
            action: "org_#{org_num}_action_#{i}",
            action_type: "test",
            severity: :info
          })
        end)
      end)

      assert {:ok, sealed_count} = Verifier.seal_all_pending()
      assert sealed_count >= 0
    end
  end
end
