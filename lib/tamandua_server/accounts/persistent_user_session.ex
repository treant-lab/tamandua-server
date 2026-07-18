defmodule TamanduaServer.Accounts.PersistentUserSession do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "persistent_user_sessions" do
    field(:token_digest, :binary)
    field(:binding_digest, :binary)
    field(:auth_epoch, :integer)
    field(:auth_method, Ecto.Enum, values: [:password, :wallet, :mfa])
    field(:authenticated_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:revoked_at, :utc_datetime_usec)
    field(:last_seen_at, :utc_datetime_usec)

    belongs_to(:user, TamanduaServer.Accounts.User)
    belongs_to(:organization, TamanduaServer.Accounts.Organization)
    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def create_changeset(session, attrs) do
    session
    |> cast(attrs, [
      :user_id,
      :organization_id,
      :token_digest,
      :binding_digest,
      :auth_epoch,
      :auth_method,
      :authenticated_at,
      :expires_at,
      :last_seen_at
    ])
    |> validate_required([
      :user_id,
      :organization_id,
      :token_digest,
      :binding_digest,
      :auth_epoch,
      :auth_method,
      :authenticated_at,
      :expires_at,
      :last_seen_at
    ])
    |> validate_number(:auth_epoch, greater_than_or_equal_to: 0)
    |> unique_constraint(:token_digest)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end
end
