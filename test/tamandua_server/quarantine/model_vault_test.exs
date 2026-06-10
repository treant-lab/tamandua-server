defmodule TamanduaServer.Quarantine.ModelVaultTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Quarantine.ModelVault

  setup do
    # Start the ModelVault for tests
    start_supervised!(ModelVault)
    :ok
  end

  describe "store_receipt/1" do
    test "stores a quarantine receipt and returns receipt_id" do
      receipt = %{
        "receipt_id" => "test-receipt-001",
        "agent_id" => "agent-001",
        "original_path" => "/models/malicious.pkl",
        "sha256" => "abc123def456",
        "model_format" => "pickle",
        "quarantined_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
        "reason" => "malicious_payload",
        "recovery_key" => Base.encode64(:crypto.strong_rand_bytes(32)),
        "affected_processes" => [%{"pid" => 1234, "name" => "python"}]
      }

      assert {:ok, "test-receipt-001"} = ModelVault.store_receipt(receipt)
    end

    test "encrypts the recovery key" do
      receipt = %{
        "receipt_id" => "test-receipt-002",
        "agent_id" => "agent-001",
        "original_path" => "/models/test.pkl",
        "sha256" => "abc123",
        "recovery_key" => Base.encode64("test-recovery-key-32-bytes-long!")
      }

      {:ok, receipt_id} = ModelVault.store_receipt(receipt)

      # Get receipt should NOT include the encrypted key
      {:ok, stored} = ModelVault.get_receipt(receipt_id)
      refute Map.has_key?(stored, :recovery_key_encrypted)
      refute Map.has_key?(stored, :recovery_key_iv)
    end
  end

  describe "get_receipt/1" do
    test "returns receipt by ID" do
      receipt = %{
        "receipt_id" => "test-receipt-003",
        "agent_id" => "agent-002",
        "original_path" => "/models/test.pkl",
        "sha256" => "xyz789",
        "recovery_key" => Base.encode64(:crypto.strong_rand_bytes(32))
      }

      {:ok, _} = ModelVault.store_receipt(receipt)

      assert {:ok, stored} = ModelVault.get_receipt("test-receipt-003")
      assert stored.receipt_id == "test-receipt-003"
      assert stored.agent_id == "agent-002"
      assert stored.sha256 == "xyz789"
    end

    test "returns error for non-existent receipt" do
      assert {:error, :not_found} = ModelVault.get_receipt("non-existent")
    end
  end

  describe "list_receipts/1" do
    test "lists all receipts" do
      for i <- 1..3 do
        receipt = %{
          "receipt_id" => "list-test-#{i}",
          "agent_id" => "agent-#{i}",
          "original_path" => "/models/model#{i}.pkl",
          "sha256" => "hash#{i}",
          "recovery_key" => Base.encode64(:crypto.strong_rand_bytes(32))
        }
        ModelVault.store_receipt(receipt)
      end

      receipts = ModelVault.list_receipts()
      list_test_receipts = Enum.filter(receipts, &String.starts_with?(&1.receipt_id, "list-test-"))

      assert length(list_test_receipts) >= 3
    end

    test "filters by agent_id" do
      for i <- 1..2 do
        receipt = %{
          "receipt_id" => "filter-agent-#{i}",
          "agent_id" => "filter-agent-001",
          "original_path" => "/models/model#{i}.pkl",
          "sha256" => "hash#{i}",
          "recovery_key" => Base.encode64(:crypto.strong_rand_bytes(32))
        }
        ModelVault.store_receipt(receipt)
      end

      receipt = %{
        "receipt_id" => "filter-agent-other",
        "agent_id" => "other-agent",
        "original_path" => "/models/other.pkl",
        "sha256" => "hash-other",
        "recovery_key" => Base.encode64(:crypto.strong_rand_bytes(32))
      }
      ModelVault.store_receipt(receipt)

      receipts = ModelVault.list_receipts(agent_id: "filter-agent-001")
      assert Enum.all?(receipts, &(&1.agent_id == "filter-agent-001"))
    end
  end

  describe "initiate_restore/4" do
    test "returns recovery key with valid authorization" do
      recovery_key = :crypto.strong_rand_bytes(32)

      receipt = %{
        "receipt_id" => "restore-test-001",
        "agent_id" => "agent-001",
        "original_path" => "/models/test.pkl",
        "sha256" => "abc123",
        "recovery_key" => Base.encode64(recovery_key)
      }

      {:ok, _} = ModelVault.store_receipt(receipt)

      authorization = %{role: "admin"}
      {:ok, returned_key} = ModelVault.initiate_restore(
        "restore-test-001",
        "/models/restored.pkl",
        "test-user",
        authorization
      )

      # The returned key should decrypt to the original
      assert {:ok, decoded} = Base.decode64(returned_key)
      assert decoded == recovery_key
    end

    test "rejects unauthorized restore attempts" do
      receipt = %{
        "receipt_id" => "restore-test-002",
        "agent_id" => "agent-001",
        "original_path" => "/models/test.pkl",
        "sha256" => "abc123",
        "recovery_key" => Base.encode64(:crypto.strong_rand_bytes(32))
      }

      {:ok, _} = ModelVault.store_receipt(receipt)

      authorization = %{role: "viewer"}  # Not authorized
      assert {:error, :unauthorized} = ModelVault.initiate_restore(
        "restore-test-002",
        "/models/restored.pkl",
        "unauthorized-user",
        authorization
      )
    end

    test "rejects restore for deleted models" do
      receipt = %{
        "receipt_id" => "restore-test-003",
        "agent_id" => "agent-001",
        "original_path" => "/models/test.pkl",
        "sha256" => "abc123",
        "recovery_key" => Base.encode64(:crypto.strong_rand_bytes(32))
      }

      {:ok, _} = ModelVault.store_receipt(receipt)
      :ok = ModelVault.mark_deleted("restore-test-003", "test-user")

      authorization = %{role: "admin"}
      assert {:error, :model_deleted} = ModelVault.initiate_restore(
        "restore-test-003",
        "/models/restored.pkl",
        "test-user",
        authorization
      )
    end
  end

  describe "mark_deleted/2" do
    test "marks receipt as deleted" do
      receipt = %{
        "receipt_id" => "delete-test-001",
        "agent_id" => "agent-001",
        "original_path" => "/models/test.pkl",
        "sha256" => "abc123",
        "recovery_key" => Base.encode64(:crypto.strong_rand_bytes(32))
      }

      {:ok, _} = ModelVault.store_receipt(receipt)
      :ok = ModelVault.mark_deleted("delete-test-001", "test-user")

      {:ok, stored} = ModelVault.get_receipt("delete-test-001")
      assert stored.is_deleted == true
      assert stored.can_restore == false
    end
  end

  describe "get_stats/1" do
    test "returns statistics about quarantined models" do
      # Store some test receipts with different reasons
      for {reason, i} <- Enum.with_index(["malicious_payload", "neural_backdoor", "malicious_payload"]) do
        receipt = %{
          "receipt_id" => "stats-test-#{i}",
          "agent_id" => "agent-stats",
          "original_path" => "/models/model#{i}.pkl",
          "sha256" => "hash#{i}",
          "reason" => reason,
          "model_format" => "pickle",
          "recovery_key" => Base.encode64(:crypto.strong_rand_bytes(32))
        }
        ModelVault.store_receipt(receipt)
      end

      stats = ModelVault.get_stats(agent_id: "agent-stats")

      assert is_integer(stats.total_quarantined)
      assert is_map(stats.by_reason)
      assert is_map(stats.by_format)
      assert is_list(stats.recent_quarantines)
    end
  end

  describe "get_audit_log/1" do
    test "returns audit entries for a receipt" do
      receipt = %{
        "receipt_id" => "audit-test-001",
        "agent_id" => "agent-001",
        "original_path" => "/models/test.pkl",
        "sha256" => "abc123",
        "recovery_key" => Base.encode64(:crypto.strong_rand_bytes(32))
      }

      {:ok, _} = ModelVault.store_receipt(receipt)

      entries = ModelVault.get_audit_log("audit-test-001")

      # Should have at least the quarantine entry
      assert length(entries) >= 1
      assert Enum.any?(entries, &(&1.action == "quarantine"))
    end
  end
end
