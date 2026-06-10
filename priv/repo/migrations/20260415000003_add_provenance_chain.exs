defmodule TamanduaServer.Repo.Migrations.AddProvenanceChain do
  @moduledoc """
  Add provenance chain table for SLSA-style model provenance tracking.

  This migration creates the `provenance_entries` table which stores
  cryptographically signed provenance entries for AI models. Each entry
  is linked to a `model_provenance` record and forms a hash chain for
  tamper detection.

  ## SLSA Compliance

  The schema supports SLSA Build Level requirements:
  - L1: Attestation exists (entries stored)
  - L2: Signed attestation (signature and signer_public_key)
  - L3: Hardened build (builder and materials fields)
  """

  use Ecto.Migration

  def change do
    create table(:provenance_entries, primary_key: false) do
      add :id, :binary_id, primary_key: true

      # Link to model provenance record
      add :model_provenance_id, references(:model_provenance, type: :binary_id, on_delete: :delete_all)

      # Event information
      add :event_type, :string, null: false

      # Chain linking (blockchain-style)
      add :previous_hash, :string  # Hash of previous entry for chain integrity (nil for genesis)
      add :entry_hash, :string, null: false  # SHA256 hash of this entry's content

      # Cryptographic signature (Ed25519)
      add :signature, :text  # Base64-encoded Ed25519 signature
      add :signer_public_key, :string  # Hex-encoded public key of signer

      # SLSA provenance fields
      add :subject, :map, null: false  # Model being tracked {name, digest, uri}
      add :builder, :map, default: %{}  # Build system info {id, version}
      add :materials, {:array, :map}, default: []  # Input artifacts [{uri, digest}, ...]
      add :metadata, :map, default: %{}  # Additional context

      timestamps(type: :utc_datetime_usec)
    end

    # Index for efficient lookups
    create index(:provenance_entries, [:model_provenance_id])
    create index(:provenance_entries, [:event_type])
    create index(:provenance_entries, [:entry_hash])

    # Unique constraint for chain integrity (only one entry can follow a previous hash)
    create unique_index(:provenance_entries, [:model_provenance_id, :previous_hash],
             name: :provenance_entries_chain_index,
             where: "previous_hash IS NOT NULL")
  end
end
