defmodule TamanduaServer.Accounts.RolePermission do
  @moduledoc """
  Join table between roles and permissions.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "role_permissions" do
    belongs_to :role, TamanduaServer.Accounts.Role
    belongs_to :permission, TamanduaServer.Accounts.Permission

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(role_permission, attrs) do
    role_permission
    |> cast(attrs, [:role_id, :permission_id])
    |> validate_required([:role_id, :permission_id])
    |> unique_constraint([:role_id, :permission_id])
  end
end
