defmodule TamanduaServer.Audit.MerkleTreeTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Audit.MerkleTree

  describe "build/1" do
    test "returns nil for empty list" do
      assert MerkleTree.build([]) == nil
    end

    test "builds tree from single entry" do
      entry = create_test_entry(1)
      tree = MerkleTree.build([entry])

      assert tree != nil
      assert tree.entry_id == entry.id
      assert tree.hash != nil
    end

    test "builds tree from two entries" do
      entries = [create_test_entry(1), create_test_entry(2)]
      tree = MerkleTree.build(entries)

      assert tree != nil
      assert tree.left != nil
      assert tree.right != nil
      assert tree.entry_id == nil # Non-leaf node
    end

    test "builds tree from four entries" do
      entries = Enum.map(1..4, &create_test_entry/1)
      tree = MerkleTree.build(entries)

      assert tree != nil
      # Root should have two children, each with two leaves
      assert tree.left.left != nil
      assert tree.left.right != nil
      assert tree.right.left != nil
      assert tree.right.right != nil
    end

    test "handles odd number of entries" do
      entries = Enum.map(1..3, &create_test_entry/1)
      tree = MerkleTree.build(entries)

      # Should build tree with duplicated last entry
      assert tree != nil
      assert tree.left != nil
      assert tree.right != nil
    end
  end

  describe "root_hash/1" do
    test "returns nil for nil tree" do
      assert MerkleTree.root_hash(nil) == nil
    end

    test "returns hash for single entry tree" do
      entry = create_test_entry(1)
      tree = MerkleTree.build([entry])
      hash = MerkleTree.root_hash(tree)

      assert is_binary(hash)
      assert String.length(hash) == 64 # SHA256 hex = 64 chars
    end

    test "returns different hashes for different entries" do
      tree1 = MerkleTree.build([create_test_entry(1)])
      tree2 = MerkleTree.build([create_test_entry(2)])

      hash1 = MerkleTree.root_hash(tree1)
      hash2 = MerkleTree.root_hash(tree2)

      assert hash1 != hash2
    end

    test "returns same hash for same entries" do
      entries = Enum.map(1..4, &create_test_entry/1)

      tree1 = MerkleTree.build(entries)
      tree2 = MerkleTree.build(entries)

      assert MerkleTree.root_hash(tree1) == MerkleTree.root_hash(tree2)
    end
  end

  describe "generate_proof/2" do
    test "returns nil for nil tree" do
      assert MerkleTree.generate_proof(nil, "some-id") == nil
    end

    test "returns nil for non-existent entry" do
      entries = Enum.map(1..4, &create_test_entry/1)
      tree = MerkleTree.build(entries)

      assert MerkleTree.generate_proof(tree, "non-existent-id") == nil
    end

    test "generates proof for entry in tree" do
      entries = Enum.map(1..4, &create_test_entry/1)
      tree = MerkleTree.build(entries)

      proof = MerkleTree.generate_proof(tree, List.first(entries).id)

      assert is_list(proof)
      assert length(proof) > 0

      # Each proof element should have hash and position
      Enum.each(proof, fn element ->
        assert Map.has_key?(element, :hash)
        assert Map.has_key?(element, :position)
        assert element.position in [:left, :right]
      end)
    end

    test "proof length is log2(n) for balanced tree" do
      # 8 entries should have proof length 3 (log2(8))
      entries = Enum.map(1..8, &create_test_entry/1)
      tree = MerkleTree.build(entries)

      proof = MerkleTree.generate_proof(tree, List.first(entries).id)

      assert length(proof) == 3
    end
  end

  describe "verify_proof/3" do
    test "returns false for nil proof" do
      entry = create_test_entry(1)
      assert MerkleTree.verify_proof(entry, nil, "some-hash") == false
    end

    test "returns false for nil root hash" do
      entry = create_test_entry(1)
      assert MerkleTree.verify_proof(entry, [], nil) == false
    end

    test "verifies valid proof" do
      entries = Enum.map(1..4, &create_test_entry/1)
      tree = MerkleTree.build(entries)
      root_hash = MerkleTree.root_hash(tree)

      entry = List.first(entries)
      proof = MerkleTree.generate_proof(tree, entry.id)

      assert MerkleTree.verify_proof(entry, proof, root_hash) == true
    end

    test "rejects invalid proof (wrong root hash)" do
      entries = Enum.map(1..4, &create_test_entry/1)
      tree = MerkleTree.build(entries)

      entry = List.first(entries)
      proof = MerkleTree.generate_proof(tree, entry.id)

      assert MerkleTree.verify_proof(entry, proof, "invalid-hash") == false
    end

    test "rejects tampered entry" do
      entries = Enum.map(1..4, &create_test_entry/1)
      tree = MerkleTree.build(entries)
      root_hash = MerkleTree.root_hash(tree)

      entry = List.first(entries)
      proof = MerkleTree.generate_proof(tree, entry.id)

      # Tamper with entry
      tampered_entry = %{entry | action: "tampered_action"}

      assert MerkleTree.verify_proof(tampered_entry, proof, root_hash) == false
    end

    test "verifies all entries in tree" do
      entries = Enum.map(1..8, &create_test_entry/1)
      tree = MerkleTree.build(entries)
      root_hash = MerkleTree.root_hash(tree)

      # All entries should verify
      Enum.each(entries, fn entry ->
        proof = MerkleTree.generate_proof(tree, entry.id)
        assert MerkleTree.verify_proof(entry, proof, root_hash) == true
      end)
    end
  end

  describe "generate_all_proofs/2" do
    test "generates proofs for all entries" do
      entries = Enum.map(1..4, &create_test_entry/1)
      tree = MerkleTree.build(entries)

      proofs = MerkleTree.generate_all_proofs(tree, entries)

      assert map_size(proofs) == 4

      # All entries should have proofs
      Enum.each(entries, fn entry ->
        assert Map.has_key?(proofs, entry.id)
        assert is_list(proofs[entry.id])
      end)
    end
  end

  describe "verify_tree/1" do
    test "returns {:ok, 0} for nil tree" do
      assert MerkleTree.verify_tree(nil) == {:ok, 0}
    end

    test "verifies valid tree structure" do
      entries = Enum.map(1..4, &create_test_entry/1)
      tree = MerkleTree.build(entries)

      assert {:ok, node_count} = MerkleTree.verify_tree(tree)
      assert node_count > 0
    end

    test "detects corrupted tree structure" do
      entries = Enum.map(1..4, &create_test_entry/1)
      tree = MerkleTree.build(entries)

      # Corrupt the tree by changing a hash
      corrupted_tree = %{tree | hash: "corrupted-hash"}

      assert {:error, :hash_mismatch} = MerkleTree.verify_tree(corrupted_tree)
    end
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp create_test_entry(sequence) do
    %{
      id: Ecto.UUID.generate(),
      sequence_number: sequence,
      action: "test_action_#{sequence}",
      action_type: "test",
      user_id: Ecto.UUID.generate(),
      resource_type: "test_resource",
      resource_id: "resource_#{sequence}",
      inserted_at: DateTime.utc_now(),
      entry_hash: "hash_#{sequence}"
    }
  end
end
