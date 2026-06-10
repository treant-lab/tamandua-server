defmodule TamanduaServer.Solana.HealthAttestation do
  @moduledoc """
  Ecto schema for health attestations on the Solana blockchain.

  Health attestations provide a privacy-preserving on-chain proof that an
  endpoint was monitored for a given time window. They include aggregate
  security metrics (alert counts by severity) but never expose identifying
  information like hostnames, IP addresses, or usernames.

  ## Privacy Guarantees

  **What DOES go on-chain:**
  - agent_pseudonym: SHA256(agent_id)[:12] - 12 hex chars of hash
  - window_hours: Duration of the attestation window
  - critical_alerts: Count of critical severity alerts in window
  - high_alerts: Count of high severity alerts in window
  - policy_profile: "aggressive" | "balanced" | "lightweight"
  - health_hash: SHA256 of all fields for verification
  - timestamps

  **What NEVER goes on-chain:**
  - Real agent IDs
  - Hostnames
  - IP addresses
  - Raw alert data
  - Any PII
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Agents.Agent

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @policy_profiles ~w(aggressive balanced lightweight default)

  schema "health_attestations" do
    # SHA256(agent_id)[:12] - pseudonymized agent identifier (12 hex chars)
    field :agent_pseudonym, :string

    # Time window for the attestation (default 24 hours)
    field :window_hours, :integer, default: 24

    # Alert counts by severity in the window
    field :critical_alerts, :integer, default: 0
    field :high_alerts, :integer, default: 0
    field :medium_alerts, :integer, default: 0
    field :low_alerts, :integer, default: 0

    # Last time the agent was seen online
    field :last_seen, :utc_datetime

    # Policy profile applied to the agent
    # "aggressive" | "balanced" | "lightweight" | "default"
    field :policy_profile, :string, default: "balanced"

    # SHA256 hash of all fields for verification
    field :health_hash, :string

    # Solana transaction signature (set after successful attestation)
    field :solana_signature, :string

    # When the attestation was recorded on-chain
    field :attested_at, :utc_datetime

    # Reference to the actual agent (for internal queries)
    belongs_to :agent, Agent

    # Organization for multi-tenancy
    field :organization_id, :binary_id

    timestamps()
  end

  @doc """
  Changeset for creating a new health attestation.
  """
  def changeset(attestation, attrs) do
    attestation
    |> cast(attrs, [
      :agent_pseudonym,
      :window_hours,
      :critical_alerts,
      :high_alerts,
      :medium_alerts,
      :low_alerts,
      :last_seen,
      :policy_profile,
      :health_hash,
      :solana_signature,
      :attested_at,
      :agent_id,
      :organization_id
    ])
    |> validate_required([:agent_pseudonym, :window_hours, :health_hash])
    |> validate_number(:window_hours, greater_than: 0, less_than_or_equal_to: 168)
    |> validate_number(:critical_alerts, greater_than_or_equal_to: 0)
    |> validate_number(:high_alerts, greater_than_or_equal_to: 0)
    |> validate_number(:medium_alerts, greater_than_or_equal_to: 0)
    |> validate_number(:low_alerts, greater_than_or_equal_to: 0)
    |> validate_inclusion(:policy_profile, @policy_profiles)
    |> validate_length(:agent_pseudonym, min: 12, max: 64)
    |> validate_length(:health_hash, min: 64, max: 64)
    |> foreign_key_constraint(:agent_id)
  end

  @doc """
  Changeset for updating an attestation after Solana submission.
  """
  def solana_changeset(attestation, attrs) do
    attestation
    |> cast(attrs, [:solana_signature, :attested_at])
    |> validate_required([:solana_signature, :attested_at])
    |> validate_length(:solana_signature, min: 80, max: 100)
  end
end
