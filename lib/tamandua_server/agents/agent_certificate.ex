defmodule TamanduaServer.Agents.AgentCertificate do
  @moduledoc """
  Schema for tracking and pinning agent TLS certificates.

  When an agent first connects with mTLS, its certificate is "pinned" to establish
  a trusted relationship. Subsequent connections must present the same certificate
  (verified by fingerprint and public key hash).

  This provides defense-in-depth against compromised CA certificates or
  unauthorized certificate issuance.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Agents.Agent

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "agent_certificates" do
    field :fingerprint, :string
    field :public_key_hash, :binary
    field :subject_dn, :string
    field :issuer_dn, :string
    field :serial_number, :string
    field :valid_from, :utc_datetime
    field :valid_until, :utc_datetime
    field :first_seen_at, :utc_datetime
    field :last_seen_at, :utc_datetime
    field :pinned, :boolean, default: true
    field :metadata, :map, default: %{}

    belongs_to :agent, Agent

    timestamps()
  end

  @doc false
  def changeset(cert, attrs) do
    cert
    |> cast(attrs, [
      :agent_id,
      :fingerprint,
      :public_key_hash,
      :subject_dn,
      :issuer_dn,
      :serial_number,
      :valid_from,
      :valid_until,
      :first_seen_at,
      :last_seen_at,
      :pinned,
      :metadata
    ])
    |> validate_required([
      :agent_id,
      :fingerprint,
      :public_key_hash,
      :valid_from,
      :valid_until,
      :first_seen_at,
      :last_seen_at
    ])
    |> unique_constraint(:fingerprint)
    |> foreign_key_constraint(:agent_id)
  end
end
