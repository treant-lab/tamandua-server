defmodule TamanduaServer.Agents.AgentCredential do
  @moduledoc """
  Schema for agent socket credentials.

  Implements DB-backed identity validation for agent WebSocket connections
  as required by ACCOUNT_INTEGRITY_THREAT_MODEL.md:

  1. Each credential is tied to a specific agent and organization
  2. Credentials have a finite expiry (no infinite tokens)
  3. Credentials can be revoked at any time
  4. Usage is tracked for auditing and anomaly detection

  ## Security Model

  - Every JWT issued to an agent has a unique `jti` (JWT ID) claim
  - On socket connect, the `jti` is validated against this table
  - Revoked or expired credentials are rejected
  - Organization binding is verified (agent must belong to the org in the token)
  - `last_used_at` is updated on each successful connection for audit trails
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Accounts.User

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "agent_credentials" do
    belongs_to :agent, Agent
    belongs_to :organization, Organization
    belongs_to :issued_by_user, User

    # JWT ID - unique identifier for this credential
    field :jti, :string

    # Token lifecycle
    field :issued_at, :utc_datetime_usec
    field :expires_at, :utc_datetime_usec

    # Revocation
    field :revoked_at, :utc_datetime_usec
    field :revocation_reason, :string

    # Usage tracking
    field :last_used_at, :utc_datetime_usec
    field :last_used_ip, :string
    field :use_count, :integer, default: 0

    # Connection metadata
    field :issued_from_ip, :string

    timestamps()
  end

  @required_fields [:agent_id, :organization_id, :jti, :issued_at, :expires_at]
  @optional_fields [:revoked_at, :revocation_reason, :last_used_at, :last_used_ip,
                    :use_count, :issued_from_ip, :issued_by_user_id]

  @doc """
  Changeset for creating a new agent credential.
  """
  def changeset(credential, attrs) do
    credential
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_expiry()
    |> unique_constraint(:jti)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:issued_by_user_id)
  end

  @doc """
  Changeset for revoking a credential.
  """
  def revoke_changeset(credential, reason \\ "manual_revocation") do
    credential
    |> change(%{
      revoked_at: DateTime.utc_now(),
      revocation_reason: reason
    })
  end

  @doc """
  Changeset for updating usage tracking.
  """
  def usage_changeset(credential, ip_address) do
    credential
    |> change(%{
      last_used_at: DateTime.utc_now(),
      last_used_ip: ip_address,
      use_count: (credential.use_count || 0) + 1
    })
  end

  # Private validation

  defp validate_expiry(changeset) do
    expires_at = get_field(changeset, :expires_at)
    issued_at = get_field(changeset, :issued_at)

    cond do
      is_nil(expires_at) ->
        changeset

      is_nil(issued_at) ->
        changeset

      DateTime.compare(expires_at, issued_at) != :gt ->
        add_error(changeset, :expires_at, "must be after issued_at")

      true ->
        # Enforce maximum token lifetime of 90 days
        max_lifetime_seconds = 90 * 24 * 60 * 60
        diff = DateTime.diff(expires_at, issued_at, :second)

        if diff > max_lifetime_seconds do
          add_error(changeset, :expires_at, "token lifetime cannot exceed 90 days")
        else
          changeset
        end
    end
  end

  @doc """
  Check if this credential is valid for use.
  Returns :ok or {:error, reason}.
  """
  def validate(credential) do
    now = DateTime.utc_now()

    cond do
      not is_nil(credential.revoked_at) ->
        {:error, :credential_revoked}

      DateTime.compare(now, credential.expires_at) != :lt ->
        {:error, :credential_expired}

      true ->
        :ok
    end
  end
end
