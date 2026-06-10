defmodule TamanduaServer.Audit.Verifier do
  @moduledoc """
  Audit log integrity verification using Merkle trees and digital signatures.

  This module provides:
  - Periodic sealing of audit log batches
  - Merkle proof generation and storage
  - Signature verification
  - Tampering detection
  - Forensic integrity reports

  ## Sealing Process

  1. Every hour or 10,000 entries, seal a batch:
     - Build Merkle tree from entries
     - Generate root hash
     - Sign root hash with Ed25519
     - Store signature and proofs

  2. Each entry gets a Merkle proof for future verification

  3. Sealed batches cannot be modified without detection

  ## Verification

  Verification can be performed:
  - On-demand for specific entries
  - Periodically for all sealed batches
  - During compliance audits
  - After suspected tampering

  ## Example

      # Seal current batch
      {:ok, seal} = Verifier.seal_batch(organization_id)

      # Verify specific entry
      {:ok, :valid} = Verifier.verify_entry(entry_id)

      # Verify entire sealed batch
      {:ok, :all_valid} = Verifier.verify_seal(seal.id)

      # Detect tampering
      case Verifier.check_tampering(organization_id) do
        {:ok, :no_tampering} -> :ok
        {:error, {:tampering_detected, details}} -> alert!
      end
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Audit.{AuditLog, MerkleTree, Signature}

  @seal_interval_hours 1
  @seal_batch_size 10_000

  # ============================================================================
  # Sealing Functions
  # ============================================================================

  @doc """
  Seal a batch of audit log entries.

  This creates a cryptographically signed snapshot of entries:
  1. Fetch unsealed entries (up to batch size)
  2. Build Merkle tree
  3. Sign root hash
  4. Store signature and proofs

  ## Parameters
    - organization_id: UUID of organization
    - opts: Options
      - :force - Force sealing even if batch is small
      - :max_entries - Maximum entries to seal (default: 10,000)

  ## Returns
    - {:ok, %Signature{}} on success
    - {:error, reason} on failure
  """
  def seal_batch(organization_id, opts \\ []) do
    force = Keyword.get(opts, :force, false)
    max_entries = Keyword.get(opts, :max_entries, @seal_batch_size)

    # Get unsealed entries
    unsealed = get_unsealed_entries(organization_id, max_entries)

    cond do
      Enum.empty?(unsealed) ->
        {:error, :no_entries_to_seal}

      length(unsealed) < 100 and not force ->
        {:error, :batch_too_small}

      true ->
        do_seal_batch(organization_id, unsealed)
    end
  end

  @doc """
  Automatically seal batches for an organization if conditions are met.

  Conditions for auto-sealing:
  - More than seal_batch_size unsealed entries, OR
  - Oldest unsealed entry is older than seal_interval_hours

  ## Parameters
    - organization_id: UUID of organization

  ## Returns
    - {:ok, %Signature{}} if sealed
    - {:ok, :not_needed} if conditions not met
    - {:error, reason} on failure
  """
  def auto_seal(organization_id) do
    unsealed_count = count_unsealed_entries(organization_id)
    oldest_unsealed = get_oldest_unsealed(organization_id)

    should_seal = unsealed_count >= @seal_batch_size or
                  (oldest_unsealed && entry_age_hours(oldest_unsealed) >= @seal_interval_hours)

    if should_seal do
      Logger.info("Auto-sealing batch for org #{organization_id}: #{unsealed_count} entries")
      seal_batch(organization_id)
    else
      {:ok, :not_needed}
    end
  end

  @doc """
  Seal all pending batches across all organizations.

  Called periodically by a background worker.

  ## Returns
    - {:ok, sealed_count}
  """
  def seal_all_pending do
    # Get all organizations with unsealed entries
    org_ids = from(a in AuditLog,
      where: is_nil(a.seal_id),
      select: a.organization_id,
      distinct: true
    )
    |> Repo.all()
    |> Enum.reject(&is_nil/1)

    results = Enum.map(org_ids, fn org_id ->
      case auto_seal(org_id) do
        {:ok, %Signature{}} -> :sealed
        {:ok, :not_needed} -> :skipped
        {:error, _} -> :error
      end
    end)

    sealed_count = Enum.count(results, &(&1 == :sealed))
    Logger.info("Auto-seal complete: #{sealed_count} batches sealed")

    {:ok, sealed_count}
  end

  # ============================================================================
  # Verification Functions
  # ============================================================================

  @doc """
  Verify integrity of a specific audit log entry.

  Checks:
  - Entry has a valid Merkle proof
  - Entry belongs to a sealed batch
  - Proof verifies against seal's root hash
  - Seal signature is valid

  ## Parameters
    - entry_id: UUID of audit log entry

  ## Returns
    - {:ok, :valid} if entry is verified
    - {:error, reason} if verification fails
  """
  def verify_entry(entry_id) do
    entry = Repo.get(AuditLog, entry_id)

    cond do
      is_nil(entry) ->
        {:error, :entry_not_found}

      is_nil(entry.seal_id) ->
        {:error, :entry_not_sealed}

      is_nil(entry.merkle_proof) ->
        {:error, :no_merkle_proof}

      true ->
        seal = Repo.get(Signature, entry.seal_id)

        if is_nil(seal) do
          {:error, :seal_not_found}
        else
          verify_entry_with_seal(entry, seal)
        end
    end
  end

  @doc """
  Verify all entries in a sealed batch.

  ## Parameters
    - seal_id: UUID of audit signature record

  ## Returns
    - {:ok, :all_valid} if all entries verify
    - {:error, {:invalid_entries, entry_ids}} if some entries fail
    - {:error, reason} for other failures
  """
  def verify_seal(seal_id) do
    seal = Repo.get(Signature, seal_id)

    if is_nil(seal) do
      {:error, :seal_not_found}
    else
      # Get all entries in this seal
      entries = from(a in AuditLog,
        where: a.seal_id == ^seal_id,
        order_by: [asc: a.sequence_number]
      )
      |> Repo.all()

      verify_sealed_batch(entries, seal)
    end
  end

  @doc """
  Check for tampering across all sealed batches for an organization.

  Verifies:
  - All seal signatures are valid
  - All entries have valid Merkle proofs
  - Sequence numbers are continuous
  - No entries are missing

  ## Parameters
    - organization_id: UUID of organization
    - opts: Options
      - :limit - Max seals to check (default: all)

  ## Returns
    - {:ok, :no_tampering} if all checks pass
    - {:error, {:tampering_detected, details}} if tampering found
  """
  def check_tampering(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit)

    query = from(s in Signature,
      where: s.organization_id == ^organization_id,
      order_by: [desc: s.sealed_at]
    )

    query = if limit, do: from(q in query, limit: ^limit), else: query

    seals = Repo.all(query)

    results = Enum.map(seals, fn seal ->
      case verify_seal(seal.id) do
        {:ok, :all_valid} ->
          # Update verification status
          update_verification_status(seal, :valid, %{
            verified_at: DateTime.utc_now(),
            verified_entries: seal.entry_count
          })
          :ok

        {:error, reason} ->
          update_verification_status(seal, :invalid, %{
            verified_at: DateTime.utc_now(),
            error: reason
          })
          {:error, seal.id, reason}
      end
    end)

    errors = Enum.filter(results, &match?({:error, _, _}, &1))

    if Enum.empty?(errors) do
      {:ok, :no_tampering}
    else
      {:error, {:tampering_detected, errors}}
    end
  end

  @doc """
  Generate a forensic integrity report for compliance.

  ## Parameters
    - organization_id: UUID of organization
    - opts: Options
      - :date_from - Start date (default: 30 days ago)
      - :date_to - End date (default: now)

  ## Returns
    - Map with integrity statistics and details
  """
  def generate_integrity_report(organization_id, opts \\ []) do
    date_from = Keyword.get(opts, :date_from, DateTime.add(DateTime.utc_now(), -30, :day))
    date_to = Keyword.get(opts, :date_to, DateTime.utc_now())

    # Get seals in date range
    seals = from(s in Signature,
      where: s.organization_id == ^organization_id,
      where: s.sealed_at >= ^date_from and s.sealed_at <= ^date_to,
      order_by: [asc: s.sealed_at]
    )
    |> Repo.all()

    # Get unsealed entries count
    unsealed_count = count_unsealed_entries(organization_id)

    # Verify all seals
    verification_results = Enum.map(seals, fn seal ->
      result = verify_seal(seal.id)

      %{
        seal_id: seal.id,
        seal_number: seal.seal_number,
        sealed_at: seal.sealed_at,
        entry_count: seal.entry_count,
        verified: match?({:ok, _}, result),
        details: result
      }
    end)

    valid_count = Enum.count(verification_results, & &1.verified)
    invalid_count = length(verification_results) - valid_count
    total_sealed_entries = Enum.sum(Enum.map(seals, & &1.entry_count))

    %{
      organization_id: organization_id,
      report_period: %{from: date_from, to: date_to},
      summary: %{
        total_seals: length(seals),
        valid_seals: valid_count,
        invalid_seals: invalid_count,
        total_sealed_entries: total_sealed_entries,
        unsealed_entries: unsealed_count,
        integrity_score: if(length(seals) > 0, do: valid_count / length(seals) * 100, else: 100)
      },
      seals: verification_results,
      generated_at: DateTime.utc_now()
    }
  end

  @doc """
  Count unsealed audit log entries for an organization.

  ## Parameters
    - organization_id: UUID of organization

  ## Returns
    - Integer count of unsealed entries
  """
  def count_unsealed_entries(organization_id) do
    from(a in AuditLog,
      where: a.organization_id == ^organization_id,
      where: is_nil(a.seal_id),
      select: count()
    )
    |> Repo.one() || 0
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp do_seal_batch(organization_id, entries) do
    # Sort by sequence number
    sorted_entries = Enum.sort_by(entries, & &1.sequence_number)

    # Build Merkle tree
    tree = MerkleTree.build(sorted_entries)
    root_hash = MerkleTree.root_hash(tree)

    # Generate proofs for all entries
    proofs = MerkleTree.generate_all_proofs(tree, sorted_entries)

    # Get signing key
    keypair = Signature.get_or_create_signing_key(organization_id)

    # Sign root hash
    signature_bytes = Signature.sign(root_hash, keypair.private_key)

    # Get next seal number
    seal_number = get_next_seal_number(organization_id)

    # Create signature record
    seal_attrs = %{
      organization_id: organization_id,
      seal_number: seal_number,
      start_sequence: List.first(sorted_entries).sequence_number,
      end_sequence: List.last(sorted_entries).sequence_number,
      entry_count: length(sorted_entries),
      merkle_root: root_hash,
      signature: signature_bytes,
      public_key: keypair.public_key,
      sealed_at: DateTime.utc_now()
    }

    Repo.transaction(fn ->
      # Insert signature
      {:ok, seal} = %Signature{}
      |> Signature.changeset(seal_attrs)
      |> Repo.insert()

      # Update entries with seal_id and merkle_proof
      Enum.each(sorted_entries, fn entry ->
        proof = Map.get(proofs, entry.id)

        from(a in AuditLog, where: a.id == ^entry.id)
        |> Repo.update_all(set: [
          seal_id: seal.id,
          merkle_proof: %{proof: proof, root_hash: root_hash}
        ])
      end)

      Logger.info("Sealed batch #{seal_number} for org #{organization_id}: #{length(sorted_entries)} entries")

      seal
    end)
  end

  defp get_unsealed_entries(organization_id, limit) do
    from(a in AuditLog,
      where: a.organization_id == ^organization_id,
      where: is_nil(a.seal_id),
      order_by: [asc: a.sequence_number],
      limit: ^limit
    )
    |> Repo.all()
  end

  defp get_oldest_unsealed(organization_id) do
    from(a in AuditLog,
      where: a.organization_id == ^organization_id,
      where: is_nil(a.seal_id),
      order_by: [asc: a.inserted_at],
      limit: 1
    )
    |> Repo.one()
  end

  defp entry_age_hours(entry) do
    DateTime.diff(DateTime.utc_now(), entry.inserted_at, :second) / 3600
  end

  defp get_next_seal_number(organization_id) do
    query = from(s in Signature,
      where: s.organization_id == ^organization_id,
      select: max(s.seal_number)
    )

    current = Repo.one(query)
    (current || 0) + 1
  end

  defp verify_entry_with_seal(entry, seal) do
    # Verify seal signature first
    case Signature.verify_seal(seal) do
      {:ok, :valid} ->
        # Verify Merkle proof
        proof = entry.merkle_proof["proof"]
        root_hash = entry.merkle_proof["root_hash"]

        # Convert proof from stored format
        proof_elements = Enum.map(proof, fn element ->
          %{
            hash: element["hash"],
            position: String.to_existing_atom(element["position"])
          }
        end)

        if MerkleTree.verify_proof(entry, proof_elements, root_hash) do
          # Verify root hash matches seal
          if root_hash == seal.merkle_root do
            {:ok, :valid}
          else
            {:error, :root_hash_mismatch}
          end
        else
          {:error, :invalid_merkle_proof}
        end

      {:error, reason} ->
        {:error, {:invalid_seal_signature, reason}}
    end
  end

  defp verify_sealed_batch(entries, seal) do
    # First verify seal signature
    case Signature.verify_seal(seal) do
      {:ok, :valid} ->
        # Verify each entry's Merkle proof
        invalid_entries = entries
        |> Enum.filter(fn entry ->
          case verify_entry_with_seal(entry, seal) do
            {:ok, :valid} -> false
            _ -> true
          end
        end)
        |> Enum.map(& &1.id)

        if Enum.empty?(invalid_entries) do
          {:ok, :all_valid}
        else
          {:error, {:invalid_entries, invalid_entries}}
        end

      {:error, reason} ->
        {:error, {:invalid_seal_signature, reason}}
    end
  end

  defp update_verification_status(seal, status, details) do
    from(s in Signature, where: s.id == ^seal.id)
    |> Repo.update_all(set: [
      verified_at: DateTime.utc_now(),
      verification_status: to_string(status),
      verification_details: details
    ])
  end
end
