defmodule TamanduaServerWeb.API.V1.UserController do
  @moduledoc """
  User Management API Controller.

  Provides user CRUD operations within an organization.
  All operations are tenant-scoped - users can only manage
  users within their own organization.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Authorization.RBAC

  import Ecto.Query

  action_fallback TamanduaServerWeb.FallbackController

  # Authorization plugs
  plug TamanduaServerWeb.Plugs.RBAC, [permission: :users_read] when action in [:index, :show]
  plug TamanduaServerWeb.Plugs.RBAC, [permission: :users_create] when action in [:create]
  plug TamanduaServerWeb.Plugs.RBAC, [permission: :users_update] when action in [:update, :update_role, :toggle_mfa, :update_status]
  plug TamanduaServerWeb.Plugs.RBAC, [permission: :users_delete] when action in [:delete]

  @doc """
  List all users in the current organization.

  ## Query Parameters
  - limit: Number of users per page (default: 50)
  - offset: Pagination offset
  - search: Search by email or name
  - role: Filter by role slug
  """
  def index(conn, params) do
    org_id = conn.assigns[:current_user].organization_id
    limit = parse_int(params["limit"], 50)
    offset = parse_int(params["offset"], 0)

    query =
      from u in User,
        where: u.organization_id == ^org_id,
        order_by: [asc: u.email],
        limit: ^limit,
        offset: ^offset,
        preload: [roles: ^from(r in Accounts.Role, order_by: [desc: r.priority])]

    # Search filter
    query =
      case params["search"] do
        nil -> query
        "" -> query
        term ->
          search_term = "%#{term}%"
          from u in query, where: ilike(u.email, ^search_term) or ilike(u.name, ^search_term)
      end

    # Role filter
    query =
      case params["role"] do
        nil -> query
        role_slug ->
          from u in query,
            join: ur in assoc(u, :user_roles),
            join: r in assoc(ur, :role),
            where: r.slug == ^role_slug
      end

    users = Repo.all(query)
    total = Repo.aggregate(from(u in User, where: u.organization_id == ^org_id), :count)

    json(conn, %{
      data: Enum.map(users, &serialize_user/1),
      meta: %{
        total: total,
        limit: limit,
        offset: offset
      }
    })
  end

  @doc """
  Get a specific user by ID.
  """
  def show(conn, %{"id" => user_id}) do
    org_id = conn.assigns[:current_user].organization_id

    case get_user_in_org(user_id, org_id) do
      nil ->
        {:error, :not_found}

      user ->
        user = Repo.preload(user, roles: from(r in Accounts.Role, order_by: [desc: r.priority]))
        permissions = RBAC.permissions_for(user)

        json(conn, %{
          data: %{
            user: serialize_user(user),
            permissions: permissions,
            permission_count: length(permissions)
          }
        })
    end
  end

  @doc """
  Get the current authenticated user.
  """
  def me(conn, _params) do
    user = conn.assigns[:current_user]
    user = Repo.preload(user, roles: from(r in Accounts.Role, order_by: [desc: r.priority]))
    permissions = RBAC.permissions_for(user)

    json(conn, %{
      data: %{
        user: serialize_user(user),
        permissions: permissions,
        permission_count: length(permissions)
      }
    })
  end

  @doc """
  Create a new user in the organization.

  ## Body Parameters
  - email: User email (required)
  - name: Display name
  - password: Initial password (required)
  - role_id: Initial role to assign
  """
  def create(conn, params) do
    org_id = conn.assigns[:current_user].organization_id
    actor = conn.assigns[:current_user]

    attrs = %{
      email: params["email"],
      name: params["name"],
      password: params["password"],
      organization_id: org_id
    }

    case struct(User)
         |> User.registration_changeset(attrs)
         |> Repo.insert() do
      {:ok, user} ->
        # Assign initial role if provided
        if params["role_id"] do
          assign_initial_role(user, params["role_id"], actor, org_id)
        end

        conn
        |> put_status(:created)
        |> json(%{
          data: serialize_user(user),
          message: "User created successfully"
        })

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Update a user.
  """
  def update(conn, %{"id" => user_id} = params) do
    org_id = conn.assigns[:current_user].organization_id

    case get_user_in_org(user_id, org_id) do
      nil ->
        {:error, :not_found}

      user ->
        attrs =
          params
          |> Map.take(["name", "email"])
          |> Enum.reject(fn {_, v} -> is_nil(v) end)
          |> Map.new()

        # Handle password update separately
        attrs =
          if params["password"] do
            Map.put(attrs, "password", params["password"])
          else
            attrs
          end

        case Accounts.update_user(user, attrs) do
          {:ok, updated_user} ->
            json(conn, %{
              data: serialize_user(updated_user),
              message: "User updated successfully"
            })

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  @doc """
  Delete (deactivate) a user.

  Users are soft-deleted by removing their organization association.
  """
  def delete(conn, %{"id" => user_id}) do
    org_id = conn.assigns[:current_user].organization_id
    current_user = conn.assigns[:current_user]

    cond do
      user_id == current_user.id ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Cannot delete yourself"})

      true ->
        case get_user_in_org(user_id, org_id) do
          nil ->
            {:error, :not_found}

          user ->
            case Accounts.delete_user(user) do
              {:ok, _} ->
                json(conn, %{message: "User deleted successfully"})

              {:error, reason} ->
                {:error, reason}
            end
        end
    end
  end

  @doc """
  Update user role assignment.

  ## Body Parameters
  - role_id: ID of the role to assign
  """
  def update_role(conn, %{"id" => user_id, "role_id" => role_id}) do
    org_id = conn.assigns[:current_user].organization_id
    actor = conn.assigns[:current_user]

    case get_user_in_org(user_id, org_id) do
      nil ->
        {:error, :not_found}

      user ->
        # Get the role
        role =
          from(r in Accounts.Role,
            where: r.id == ^role_id,
            where: is_nil(r.organization_id) or r.organization_id == ^org_id
          )
          |> Repo.one()

        if role do
          # Remove existing roles and assign the new one
          from(ur in Accounts.UserRole, where: ur.user_id == ^user.id)
          |> Repo.delete_all()

          case Accounts.assign_role_to_user(user, role, actor: actor) do
            {:ok, _user_role} ->
              user = Repo.preload(user, [roles: from(r in Accounts.Role, order_by: [desc: r.priority])], force: true)
              json(conn, %{
                data: serialize_user(user),
                message: "Role updated successfully"
              })

            {:error, changeset} ->
              {:error, changeset}
          end
        else
          conn
          |> put_status(:not_found)
          |> json(%{error: "Role not found"})
        end
    end
  end

  @doc """
  Toggle MFA for a user.

  ## Body Parameters
  - enabled: Boolean to enable/disable MFA
  """
  def toggle_mfa(conn, %{"id" => user_id, "enabled" => enabled}) do
    org_id = conn.assigns[:current_user].organization_id

    case get_user_in_org(user_id, org_id) do
      nil ->
        {:error, :not_found}

      user ->
        # For disabling MFA, we can just set mfa_enabled to false
        # For enabling, normally you'd go through the MFA setup flow,
        # but for admin override, we'll allow direct enable
        attrs = %{mfa_enabled: enabled}

        # If enabling without a secret, generate one
        attrs =
          if enabled && !user.mfa_secret do
            secret = :crypto.strong_rand_bytes(20) |> Base.encode32(padding: false)
            Map.put(attrs, :mfa_secret, secret)
          else
            attrs
          end

        case Accounts.update_user(user, attrs) do
          {:ok, updated_user} ->
            json(conn, %{
              data: serialize_user(updated_user),
              message: if(enabled, do: "MFA enabled", else: "MFA disabled")
            })

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  @doc """
  Update user status (activate/deactivate).

  ## Body Parameters
  - status: "active" or "inactive"
  """
  def update_status(conn, %{"id" => user_id, "status" => status}) do
    org_id = conn.assigns[:current_user].organization_id
    current_user = conn.assigns[:current_user]

    cond do
      user_id == current_user.id ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Cannot change your own status"})

      true ->
        case get_user_in_org(user_id, org_id) do
          nil ->
            {:error, :not_found}

          user ->
            is_active = status == "active"

            case Accounts.update_user(user, %{is_active: is_active}) do
              {:ok, updated_user} ->
                json(conn, %{
                  data: serialize_user(updated_user),
                  message: if(is_active, do: "User activated", else: "User deactivated")
                })

              {:error, changeset} ->
                {:error, changeset}
            end
        end
    end
  end

  # -------------------------------------------------------------------
  # Private Helpers
  # -------------------------------------------------------------------

  defp get_user_in_org(user_id, org_id) do
    from(u in User,
      where: u.id == ^user_id and u.organization_id == ^org_id
    )
    |> Repo.one()
  end

  defp serialize_user(user) do
    roles = if Ecto.assoc_loaded?(user.roles), do: user.roles, else: []

    %{
      id: user.id,
      email: user.email,
      name: user.name,
      mfa_enabled: user.mfa_enabled,
      is_active: Map.get(user, :is_active, true),
      last_login_at: user.last_login_at,
      organization_id: user.organization_id,
      roles: Enum.map(roles, fn r -> %{id: r.id, name: r.name, slug: r.slug} end),
      inserted_at: user.inserted_at,
      updated_at: user.updated_at
    }
  end

  defp assign_initial_role(user, role_id, actor, org_id) do
    role =
      from(r in Accounts.Role,
        where: r.id == ^role_id,
        where: is_nil(r.organization_id) or r.organization_id == ^org_id
      )
      |> Repo.one()

    if role do
      Accounts.assign_role_to_user(user, role, actor: actor)
    end
  end

  defp parse_int(str, default) when is_binary(str) do
    case Integer.parse(str) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(int, _default) when is_integer(int), do: int
  defp parse_int(_, default), do: default
end
