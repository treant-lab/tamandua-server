defmodule TamanduaServer.Agents.RevokedCertificate do
  @moduledoc """
  Schema for tracking revoked agent certificates.

  Certificates can be revoked for various reasons:
  - Agent compromise
  - Certificate rotation
  - Decommissioned agent
  - Security policy enforcement

  Revoked certificates are checked during connection authentication
  and will be rejected even if otherwise valid.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Accounts.User

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "revoked_certificates" do
    field :fingerprint, :string
    field :serial_number, :string
    field :revoked_at, :utc_datetime
    field :reason, :string
    field :notes, :string
    field :metadata, :map, default: %{}

    belongs_to :agent, Agent
    belongs_to :revoked_by, User

    timestamps()
  end

  @doc false
  def changeset(revocation, attrs) do
    revocation
    |> cast(attrs, [
      :fingerprint,
      :serial_number,
      :agent_id,
      :revoked_at,
      :revoked_by_id,
      :reason,
      :notes,
      :metadata
    ])
    |> validate_required([:fingerprint, :revoked_at])
    |> validate_inclusion(:reason, [
      "compromised",
      "rotation",
      "decommissioned",
      "policy_violation",
      "expired",
      "other"
    ])
    |> unique_constraint(:fingerprint)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:revoked_by_id)
  end

  @doc """
  Sets the revoked_at timestamp to the current time if not provided.
  """
  def set_revoked_at(changeset) do
    case get_field(changeset, :revoked_at) do
      nil -> put_change(changeset, :revoked_at, DateTime.utc_now() |> DateTime.truncate(:second))
      _ -> changeset
    end
  end
end
