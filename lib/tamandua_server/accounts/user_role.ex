defmodule TamanduaServer.Accounts.UserRole do
  @moduledoc """
  Join table between users and roles.

  Supports optional scope for resource-level permissions.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "user_roles" do
    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :role, TamanduaServer.Accounts.Role

    # Optional scope for resource-level permissions
    # e.g., scope_type: "agent_group", scope_id: "group-uuid"
    field :scope_type, :string
    field :scope_id, :binary_id

    # Grant/revoke tracking
    field :granted_by, :binary_id
    field :granted_at, :utc_datetime_usec
    field :expires_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(user_id role_id)a
  @optional_fields ~w(scope_type scope_id granted_by granted_at expires_at)a

  def changeset(user_role, attrs) do
    user_role
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_scope()
    |> unique_constraint([:user_id, :role_id, :scope_type, :scope_id])
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:role_id)
  end

  defp validate_scope(changeset) do
    scope_type = get_field(changeset, :scope_type)
    scope_id = get_field(changeset, :scope_id)

    cond do
      is_nil(scope_type) and not is_nil(scope_id) ->
        add_error(changeset, :scope_id, "scope_type required when scope_id is set")

      not is_nil(scope_type) and is_nil(scope_id) ->
        add_error(changeset, :scope_type, "scope_id required when scope_type is set")

      true ->
        changeset
    end
  end
end
