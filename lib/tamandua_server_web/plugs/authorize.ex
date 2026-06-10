defmodule TamanduaServerWeb.Plugs.Authorize do
  @moduledoc """
  Authorization plug for enforcing permission checks.

  ## Usage

  In your controller:

      plug TamanduaServerWeb.Plugs.Authorize, :alerts_read when action in [:index, :show]
      plug TamanduaServerWeb.Plugs.Authorize, :alerts_update when action in [:update]

  Or with resource-based authorization:

      plug TamanduaServerWeb.Plugs.Authorize, {:alerts_update, :alert}

  ## Options

  - Permission atom: `:alerts_read`
  - Permission with resource: `{:alerts_update, :alert}`
  - List of permissions (any): `[:alerts_read, :events_read]`
  """

  import Plug.Conn
  import Phoenix.Controller

  alias TamanduaServer.Authorization.RBAC

  def init(permission), do: permission

  def call(conn, permission) when is_atom(permission) do
    authorize(conn, permission, nil)
  end

  def call(conn, {permission, resource_key}) when is_atom(permission) and is_atom(resource_key) do
    resource = conn.assigns[resource_key]
    authorize(conn, permission, resource)
  end

  def call(conn, permissions) when is_list(permissions) do
    authorize_any(conn, permissions)
  end

  defp authorize(conn, permission, resource) do
    user = conn.assigns[:current_user]

    if RBAC.can?(user, permission, resource) do
      conn
    else
      unauthorized(conn, permission)
    end
  end

  defp authorize_any(conn, permissions) do
    user = conn.assigns[:current_user]

    if RBAC.can_any?(user, permissions) do
      conn
    else
      unauthorized(conn, hd(permissions))
    end
  end

  defp unauthorized(conn, permission) do
    conn
    |> put_status(:forbidden)
    |> put_view(json: TamanduaServerWeb.ErrorJSON)
    |> render(:error, %{
      error: "forbidden",
      message: "You don't have permission to perform this action",
      required_permission: permission
    })
    |> halt()
  end
end

defmodule TamanduaServerWeb.Plugs.RequireRole do
  @moduledoc """
  Plug to require specific role(s).

  ## Usage

      plug TamanduaServerWeb.Plugs.RequireRole, :admin
      plug TamanduaServerWeb.Plugs.RequireRole, [:admin, :analyst]
  """

  import Plug.Conn
  import Phoenix.Controller

  alias TamanduaServer.Authorization.RBAC

  def init(roles) when is_atom(roles), do: [roles]
  def init(roles) when is_list(roles), do: roles

  def call(conn, required_roles) do
    user = conn.assigns[:current_user]
    user_roles = RBAC.roles_for(user) |> Enum.map(& &1.slug) |> Enum.map(&String.to_atom/1)

    if Enum.any?(required_roles, &(&1 in user_roles)) do
      conn
    else
      conn
      |> put_status(:forbidden)
      |> put_view(json: TamanduaServerWeb.ErrorJSON)
      |> render(:error, %{
        error: "forbidden",
        message: "This action requires one of the following roles: #{inspect(required_roles)}"
      })
      |> halt()
    end
  end
end

defmodule TamanduaServerWeb.Plugs.EnsureTenant do
  @moduledoc """
  Plug to ensure requests are properly scoped to a tenant.

  Adds tenant information to the connection assigns and
  ensures multi-tenant isolation.
  """

  import Plug.Conn
  import Phoenix.Controller

  def init(opts), do: opts

  def call(conn, _opts) do
    user = conn.assigns[:current_user]

    case user do
      %{organization_id: org_id} when not is_nil(org_id) ->
        conn
        |> assign(:current_organization_id, org_id)
        |> assign(:tenant_id, org_id)

      _ ->
        conn
        |> put_status(:forbidden)
        |> put_view(json: TamanduaServerWeb.ErrorJSON)
        |> render(:error, %{
          error: "no_tenant",
          message: "User must belong to an organization"
        })
        |> halt()
    end
  end
end
