defmodule TamanduaServerWeb.GraphQL.Middleware.SystemOperatorAuthorization do
  @moduledoc """
  Requires both ordinary RBAC/API-key authorization and system-operator identity.

  Tenant administrators may hold broad permissions, including `:system_all`,
  but that must not grant access to cross-tenant or global-catalog mutations.
  """

  @behaviour Absinthe.Middleware

  alias TamanduaServerWeb.GraphQL.Middleware.Authorization

  @impl true
  def call(resolution, permission) do
    resolution = Authorization.call(resolution, permission)

    if resolution.state == :resolved do
      resolution
    else
      user =
        resolution.context[:current_user_id] &&
          TamanduaServer.Accounts.get_user(resolution.context[:current_user_id])

      if system_operator?(user) do
        resolution
      else
        Absinthe.Resolution.put_result(resolution, {:error, "Insufficient permissions"})
      end
    end
  end

  @doc false
  def system_operator?(user) when is_map(user) do
    Map.get(user, :is_super_admin) == true or Map.get(user, :role) == "super_admin"
  end

  def system_operator?(_user), do: false
end
