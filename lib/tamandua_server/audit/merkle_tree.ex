defmodule TamanduaServer.Audit.MerkleTree do
  @moduledoc """
  Merkle tree implementation for audit log integrity verification.

  A Merkle tree (hash tree) is a cryptographic data structure where:
  - Each leaf node is a hash of a log entry
  - Each non-leaf node is a hash of its children
  - The root hash represents the entire set of entries

  This enables:
  - Efficient verification of specific entries (O(log n))
  - Detection of any tampering
  - Proof generation without exposing all data

  ## Example

      # Build tree from audit log entries
      entries = [entry1, entry2, entry3, entry4]
      tree = MerkleTree.build(entries)

      # Get root hash for signing
      root_hash = MerkleTree.root_hash(tree)

      # Generate proof for specific entry
      proof = MerkleTree.generate_proof(tree, entry2.id)

      # Verify proof
      MerkleTree.verify_proof(entry2, proof, root_hash)
      # => true
  """

  require Logger

  @hash_algorithm :sha256

  defmodule Node do
    @moduledoc false
    defstruct [:hash, :left, :right, :entry_id]
  end

  @doc """
  Build a Merkle tree from audit log entries.

  ## Parameters
    - entries: List of audit log entries (must have :id and hashable fields)

  ## Returns
    - %Node{} representing the root of the tree
  """
  def build([]), do: nil

  def build(entries) when is_list(entries) do
    # Create leaf nodes from entries
    leaves = Enum.map(entries, &create_leaf/1)

    # Build tree bottom-up
    build_tree(leaves)
  end

  @doc """
  Get the root hash of the Merkle tree.

  ## Parameters
    - tree: The Merkle tree root node

  ## Returns
    - String hash in hex format, or nil if tree is empty
  """
  def root_hash(nil), do: nil
  def root_hash(%Node{hash: hash}), do: hash

  @doc """
  Generate a Merkle proof for a specific entry.

  The proof consists of sibling hashes along the path from the leaf to the root.

  ## Parameters
    - tree: The Merkle tree root node
    - entry_id: ID of the entry to prove

  ## Returns
    - List of proof elements %{hash: String.t(), position: :left | :right}
    - nil if entry not found
  """
  def generate_proof(nil, _entry_id), do: nil

  def generate_proof(tree, entry_id) do
    case find_path(tree, entry_id, []) do
      nil -> nil
      path -> build_proof(path)
    end
  end

  @doc """
  Verify a Merkle proof for an entry.

  ## Parameters
    - entry: The audit log entry to verify
    - proof: List of proof elements from generate_proof/2
    - root_hash: Expected root hash from signature

  ## Returns
    - true if proof is valid
    - false otherwise
  """
  def verify_proof(_entry, nil, _root_hash), do: false
  def verify_proof(_entry, _proof, nil), do: false

  def verify_proof(entry, proof, root_hash) do
    # Start with leaf hash
    leaf_hash = hash_entry(entry)

    # Rebuild root hash using proof
    computed_root = Enum.reduce(proof, leaf_hash, fn element, current_hash ->
      case element.position do
        :left -> hash_pair(element.hash, current_hash)
        :right -> hash_pair(current_hash, element.hash)
      end
    end)

    computed_root == root_hash
  end

  @doc """
  Generate Merkle proofs for all entries in a tree.

  Useful for sealing: store proof with each entry for later verification.

  ## Parameters
    - tree: The Merkle tree root node
    - entries: List of audit log entries (must match tree structure)

  ## Returns
    - Map of %{entry_id => proof}
  """
  def generate_all_proofs(tree, entries) do
    entries
    |> Enum.map(fn entry ->
      proof = generate_proof(tree, entry.id)
      {entry.id, proof}
    end)
    |> Map.new()
  end

  @doc """
  Verify entire tree integrity by checking all nodes.

  ## Parameters
    - tree: The Merkle tree root node

  ## Returns
    - {:ok, node_count} if tree is valid
    - {:error, reason} if tree structure is invalid
  """
  def verify_tree(nil), do: {:ok, 0}

  def verify_tree(%Node{left: nil, right: nil} = _node) do
    # Leaf node - always valid
    {:ok, 1}
  end

  def verify_tree(%Node{hash: hash, left: left, right: right} = _node) do
    with {:ok, left_count} <- verify_tree(left),
         {:ok, right_count} <- verify_tree(right) do
      # Verify hash matches children
      expected_hash = hash_pair(left.hash, right && right.hash)

      if hash == expected_hash do
        {:ok, left_count + right_count + 1}
      else
        {:error, :hash_mismatch}
      end
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  # Create a leaf node from an audit log entry
  defp create_leaf(entry) do
    %Node{
      hash: hash_entry(entry),
      left: nil,
      right: nil,
      entry_id: entry.id
    }
  end

  # Build tree from list of nodes (bottom-up)
  defp build_tree([node]), do: node

  defp build_tree(nodes) when is_list(nodes) do
    # Pair up nodes and create parent level
    parent_level = nodes
    |> Enum.chunk_every(2)
    |> Enum.map(fn
      [left, right] ->
        %Node{
          hash: hash_pair(left.hash, right.hash),
          left: left,
          right: right,
          entry_id: nil
        }

      [left] ->
        # Odd number of nodes - promote single node
        # Duplicate it to maintain tree structure
        %Node{
          hash: hash_pair(left.hash, left.hash),
          left: left,
          right: left,
          entry_id: nil
        }
    end)

    build_tree(parent_level)
  end

  # Hash a single audit log entry
  defp hash_entry(entry) do
    # Create deterministic representation
    data = %{
      id: entry.id,
      sequence_number: entry.sequence_number,
      action: entry.action,
      action_type: entry.action_type,
      user_id: entry.user_id,
      resource_type: entry.resource_type,
      resource_id: entry.resource_id,
      timestamp: entry.inserted_at |> DateTime.to_iso8601(),
      entry_hash: entry.entry_hash
    }

    :crypto.hash(@hash_algorithm, Jason.encode!(data))
    |> Base.encode16(case: :lower)
  end

  # Hash a pair of hashes
  defp hash_pair(left_hash, nil), do: left_hash

  defp hash_pair(left_hash, right_hash) do
    :crypto.hash(@hash_algorithm, left_hash <> right_hash)
    |> Base.encode16(case: :lower)
  end

  # Find path from root to entry (for proof generation)
  defp find_path(%Node{entry_id: entry_id} = node, entry_id, path) do
    # Found the entry - return path
    Enum.reverse([node | path])
  end

  defp find_path(%Node{left: nil, right: nil}, _entry_id, _path) do
    # Leaf node but not the one we're looking for
    nil
  end

  defp find_path(%Node{left: left, right: right} = node, entry_id, path) do
    # Try left subtree
    case find_path(left, entry_id, [node | path]) do
      nil ->
        # Not in left subtree, try right
        if right do
          find_path(right, entry_id, [node | path])
        else
          nil
        end

      path ->
        path
    end
  end

  # Build proof from path (sibling hashes)
  defp build_proof(path) do
    # Skip the leaf itself, get parent nodes
    path
    |> Enum.drop(1)
    |> Enum.reduce({List.first(path), []}, fn parent, {child, proof} ->
      # Determine if child is left or right of parent
      sibling = if parent.left == child do
        # Child is left, sibling is right
        if parent.right do
          %{hash: parent.right.hash, position: :right}
        else
          nil
        end
      else
        # Child is right, sibling is left
        %{hash: parent.left.hash, position: :left}
      end

      new_proof = if sibling, do: [sibling | proof], else: proof
      {parent, new_proof}
    end)
    |> elem(1)
    |> Enum.reverse()
  end
end
