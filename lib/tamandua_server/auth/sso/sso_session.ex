defmodule TamanduaServer.Auth.SSO.SSOSession do
  @moduledoc """
  Schema for tracking SSO sessions.

  Used for:
  - Session management
  - Single Logout (SLO) support
  - Audit trail
  - Session expiry enforcement
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{User, Organization}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @providers [:saml, :oidc, :azure_ad, :okta, :google_workspace, :onelogin, :ping_identity]

  schema "sso_sessions" do
    belongs_to :user, User
    belongs_to :organization, Organization

    field :provider, Ecto.Enum, values: @providers
    field :provider_user_id, :string
    field :session_index, :string  # SAML SessionIndex for SLO

    field :expires_at, :utc_datetime_usec
    field :last_activity_at, :utc_datetime_usec
    field :ip_address, :string
    field :user_agent, :string

    field :is_active, :boolean, default: true
    field :terminated_at, :utc_datetime_usec
    field :termination_reason, :string

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(user_id organization_id provider)a
  @optional_fields ~w(
    provider_user_id session_index expires_at last_activity_at
    ip_address user_agent is_active terminated_at termination_reason
  )a

  @doc """
  Changeset for SSO session.
  """
  def changeset(session, attrs) do
    session
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:provider, @providers)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Returns the list of supported providers.
  """
  def providers, do: @providers
end
