defmodule TamanduaServerWeb.API.V1.RBACController do
  @moduledoc """
  RBAC Management API Controller.

  Provides endpoints for:
  - Role management (CRUD, clone, templates)
  - User role assignments (including temporary elevation)
  - Permission definitions and conflict detection
  - Authorization checks
  - Audit log viewing
  - Role hierarchy and inheritance
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.{Role, Permission, UserRole, RBACAuditLog}
  alias TamanduaServer.Authorization.RBAC

  import Ecto.Query

  action_fallback TamanduaServerWeb.FallbackController

  plug TamanduaServerWeb.Plugs.Authorize, :roles_read when action in [:list_roles, :show_role, :list_templates, :role_hierarchy, :effective_permissions]
  plug TamanduaServerWeb.Plugs.Authorize, :roles_create when action in [:create_role, :clone_role, :create_from_template]
  plug TamanduaServerWeb.Plugs.Authorize, :roles_update when action in [:update_role, :update_role_permissions]
  plug TamanduaServerWeb.Plugs.Authorize, :roles_delete when action in [:delete_role]
  plug TamanduaServerWeb.Plugs.Authorize, :users_role_assign when action in [:assign_role, :revoke_role, :user_roles, :elevate_role, :bulk_assign]
  plug TamanduaServerWeb.Plugs.Authorize, :system_audit when action in [:audit_log, :user_audit_log]

  # -------------------------------------------------------------------
  # Role Management
  # -------------------------------------------------------------------

  @doc """
  List all roles.

  Returns both builtin and custom roles for the organization.
  """
  def list_roles(conn, params) do
    org_id = conn.assigns[:current_user].organization_id

    query =
      from r in Role,
        where: is_nil(r.organization_id) or r.organization_id == ^org_id,
        order_by: [desc: r.priority, asc: r.name]

    query =
      if params["builtin_only"] == "true" do
        from r in query, where: r.builtin == true
      else
        query
      end

    roles = Repo.all(query)

    json(conn, %{
      data: Enum.map(roles, &serialize_role/1),
      meta: %{
        total: length(roles),
        builtin_count: Enum.count(roles, & &1.builtin),
        custom_count: Enum.count(roles, &(not &1.builtin))
      }
    })
  end

  @doc """
  Get role details including permissions.
  """
  def show_role(conn, %{"id" => role_id}) do
    org_id = conn.assigns[:current_user].organization_id

    case get_role(role_id, org_id) do
      nil ->
        {:error, :not_found}

      role ->
        permissions =
          if role.builtin do
            role.slug |> String.to_existing_atom() |> Role.default_permissions()
          else
            from(rp in TamanduaServer.Accounts.RolePermission,
              join: p in Permission, on: p.id == rp.permission_id,
              where: rp.role_id == ^role.id,
              select: p.slug
            )
            |> Repo.all()
            |> Enum.map(&String.to_existing_atom/1)
          end

        json(conn, %{
          data: %{
            role: serialize_role(role),
            permissions: permissions,
            user_count: count_role_users(role.id)
          }
        })
    end
  end

  @doc """
  Create a new custom role.

  ## Body Parameters
  - name: Role display name
  - slug: Unique identifier (lowercase, underscores)
  - description: Optional description
  - permissions: List of permission slugs
  """
  def create_role(conn, params) do
    org_id = conn.assigns[:current_user].organization_id

    attrs = %{
      name: params["name"],
      slug: params["slug"],
      description: params["description"],
      organization_id: org_id,
      builtin: false,
      priority: params["priority"] || 50
    }

    permissions = (params["permissions"] || []) |> Enum.map(&to_atom_safe/1)

    case RBAC.create_role(attrs, permissions) do
      {:ok, role} ->
        conn
        |> put_status(:created)
        |> json(%{
          data: serialize_role(role),
          message: "Role created successfully"
        })

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Update a custom role.
  """
  def update_role(conn, %{"id" => role_id} = params) do
    org_id = conn.assigns[:current_user].organization_id

    case get_role(role_id, org_id) do
      nil ->
        {:error, :not_found}

      %{builtin: true} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Cannot modify builtin roles"})

      role ->
        attrs =
          params
          |> Map.take(["name", "description", "priority"])
          |> Enum.reject(fn {_, v} -> is_nil(v) end)
          |> Map.new(fn {k, v} ->
            key = try do
              String.to_existing_atom(k)
            rescue
              ArgumentError -> k
            end
            {key, v}
          end)

        case role |> Role.changeset(attrs) |> Repo.update() do
          {:ok, updated_role} ->
            RBAC.invalidate_all_caches()
            json(conn, %{data: serialize_role(updated_role)})

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  @doc """
  Update role permissions.
  """
  def update_role_permissions(conn, %{"id" => role_id, "permissions" => permissions}) do
    org_id = conn.assigns[:current_user].organization_id

    case get_role(role_id, org_id) do
      nil ->
        {:error, :not_found}

      %{builtin: true} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Cannot modify builtin role permissions"})

      role ->
        permission_atoms = Enum.map(permissions, &to_atom_safe/1)

        case RBAC.update_role_permissions(role, permission_atoms) do
          {:ok, updated_role} ->
            json(conn, %{
              data: serialize_role(updated_role),
              message: "Permissions updated successfully"
            })

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  @doc """
  Delete a custom role.
  """
  def delete_role(conn, %{"id" => role_id}) do
    org_id = conn.assigns[:current_user].organization_id

    case get_role(role_id, org_id) do
      nil ->
        {:error, :not_found}

      %{builtin: true} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Cannot delete builtin roles"})

      role ->
        case Repo.delete(role) do
          {:ok, _} ->
            RBAC.invalidate_all_caches()
            json(conn, %{message: "Role deleted successfully"})

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  # -------------------------------------------------------------------
  # User Role Assignments
  # -------------------------------------------------------------------

  @doc """
  List roles assigned to a user.
  """
  def user_roles(conn, %{"user_id" => user_id}) do
    user = Accounts.get_user(user_id)

    unless user && user.organization_id == conn.assigns[:current_user].organization_id do
      {:error, :not_found}
    else
      roles = RBAC.roles_for(user)
      permissions = RBAC.permissions_for(user)

      json(conn, %{
        data: %{
          user_id: user_id,
          roles: Enum.map(roles, &serialize_role/1),
          effective_permissions: permissions
        }
      })
    end
  end

  @doc """
  Assign a role to a user.

  ## Body Parameters
  - role_id: Role to assign
  - scope_type: Optional scope type (e.g., "agent_group")
  - scope_id: Optional scope ID
  - expires_at: Optional expiration datetime
  """
  def assign_role(conn, %{"user_id" => user_id, "role_id" => role_id} = params) do
    org_id = conn.assigns[:current_user].organization_id
    actor = conn.assigns[:current_user]

    with user when not is_nil(user) <- Accounts.get_user(user_id),
         true <- user.organization_id == org_id,
         role when not is_nil(role) <- get_role(role_id, org_id) do

      opts = [
        scope_type: params["scope_type"],
        scope_id: params["scope_id"],
        granted_by: actor.id,
        expires_at: parse_datetime(params["expires_at"]),
        actor: actor,
        ip_address: get_client_ip(conn),
        user_agent: get_user_agent(conn)
      ]

      # Use Accounts module which includes audit logging
      case Accounts.assign_role_to_user(user, role, opts) do
        {:ok, _user_role} ->
          json(conn, %{
            message: "Role assigned successfully",
            data: %{
              user_id: user_id,
              role: serialize_role(role)
            }
          })

        {:error, changeset} ->
          {:error, changeset}
      end
    else
      nil -> {:error, :not_found}
      false -> {:error, :not_found}
    end
  end

  @doc """
  Revoke a role from a user.
  """
  def revoke_role(conn, %{"user_id" => user_id, "role_id" => role_id} = params) do
    org_id = conn.assigns[:current_user].organization_id
    actor = conn.assigns[:current_user]

    with user when not is_nil(user) <- Accounts.get_user(user_id),
         true <- user.organization_id == org_id,
         role when not is_nil(role) <- get_role(role_id, org_id) do

      opts = [
        scope_type: params["scope_type"],
        scope_id: params["scope_id"],
        actor: actor,
        ip_address: get_client_ip(conn),
        user_agent: get_user_agent(conn)
      ]

      # Use Accounts module which includes audit logging
      case Accounts.revoke_role_from_user(user, role, opts) do
        {:ok, _count} ->
          json(conn, %{message: "Role revoked successfully"})

        {:error, :not_found} ->
          conn
          |> put_status(:not_found)
          |> json(%{error: "Role assignment not found"})
      end
    else
      nil -> {:error, :not_found}
      false -> {:error, :not_found}
    end
  end

  defp get_client_ip(conn) do
    forwarded_for = Plug.Conn.get_req_header(conn, "x-forwarded-for")

    case forwarded_for do
      [ip | _] -> ip |> String.split(",") |> List.first() |> String.trim()
      [] ->
        case conn.remote_ip do
          {a, b, c, d} -> "#{a}.#{b}.#{c}.#{d}"
          _ -> nil
        end
    end
  end

  defp get_user_agent(conn) do
    case Plug.Conn.get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> nil
    end
  end

  # -------------------------------------------------------------------
  # Permission Definitions
  # -------------------------------------------------------------------

  @doc """
  List all available permissions.
  """
  def list_permissions(conn, _params) do
    definitions = Permission.definitions()

    data =
      definitions
      |> Enum.map(fn {category, perms} ->
        %{
          category: category,
          permissions: Enum.map(perms, fn {slug, desc, _cat} ->
            %{
              slug: slug,
              description: desc
            }
          end)
        }
      end)

    json(conn, %{
      data: data,
      meta: %{
        categories: Permission.categories(),
        total: length(Permission.all_permissions())
      }
    })
  end

  @doc """
  Check if current user has a specific permission.
  """
  def check_permission(conn, %{"permission" => permission_str}) do
    user = conn.assigns[:current_user]
    permission = to_atom_safe(permission_str)

    result = RBAC.can?(user, permission)

    json(conn, %{
      data: %{
        permission: permission,
        allowed: result
      }
    })
  end

  @doc """
  Check multiple permissions at once.
  """
  def check_permissions(conn, %{"permissions" => permissions_list}) do
    user = conn.assigns[:current_user]

    results =
      permissions_list
      |> Enum.map(fn perm_str ->
        permission = to_atom_safe(perm_str)
        {permission, RBAC.can?(user, permission)}
      end)
      |> Map.new()

    json(conn, %{
      data: %{
        permissions: results,
        all_allowed: Enum.all?(results, fn {_, v} -> v end),
        any_allowed: Enum.any?(results, fn {_, v} -> v end)
      }
    })
  end

  @doc """
  Get current user's permissions.
  """
  def my_permissions(conn, _params) do
    user = conn.assigns[:current_user]
    roles = RBAC.roles_for(user)
    permissions = RBAC.permissions_for(user)

    json(conn, %{
      data: %{
        user_id: user.id,
        roles: Enum.map(roles, fn r -> %{slug: r.slug, name: r.name} end),
        permissions: permissions,
        permission_count: length(permissions)
      }
    })
  end

  # -------------------------------------------------------------------
  # Private Helpers
  # -------------------------------------------------------------------

  defp get_role(role_id, org_id) do
    from(r in Role,
      where: r.id == ^role_id,
      where: is_nil(r.organization_id) or r.organization_id == ^org_id
    )
    |> Repo.one()
  end

  defp serialize_role(role) when is_map(role) do
    %{
      id: role.id,
      name: role.name,
      slug: role.slug,
      description: role.description,
      builtin: role.builtin,
      priority: role.priority,
      organization_id: role.organization_id,
      inserted_at: role.inserted_at
    }
  end

  defp count_role_users(role_id) do
    from(ur in UserRole, where: ur.role_id == ^role_id, select: count())
    |> Repo.one()
  end

  defp to_atom_safe(str) when is_binary(str) do
    String.to_existing_atom(str)
  rescue
    ArgumentError -> nil
  end

  defp to_atom_safe(atom) when is_atom(atom), do: atom

  defp parse_datetime(nil), do: nil
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  # -------------------------------------------------------------------
  # Audit Log
  # -------------------------------------------------------------------

  @doc """
  Get RBAC audit log entries.

  ## Query Parameters
  - limit: Number of entries (default: 100, max: 1000)
  - offset: Pagination offset
  - action: Filter by action type
  - target_type: Filter by target type (user, role)
  - target_id: Filter by specific target
  - from: Start date (ISO8601)
  - to: End date (ISO8601)
  """
  def audit_log(conn, params) do
    org_id = conn.assigns[:current_user].organization_id

    limit = min(parse_int(params["limit"], 100), 1000)
    offset = parse_int(params["offset"], 0)

    opts = [
      limit: limit,
      offset: offset,
      action: params["action"],
      target_type: params["target_type"],
      target_id: params["target_id"],
      from: parse_datetime(params["from"]),
      to: parse_datetime(params["to"])
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    entries = RBACAuditLog.list_for_organization(org_id, opts)
    total = RBACAuditLog.count_for_organization(org_id)

    json(conn, %{
      data: Enum.map(entries, &serialize_audit_entry/1),
      meta: %{
        total: total,
        limit: limit,
        offset: offset
      }
    })
  end

  defp serialize_audit_entry(entry) do
    %{
      id: entry.id,
      action: entry.action,
      target_type: entry.target_type,
      target_id: entry.target_id,
      target_name: entry.target_name,
      changes: entry.changes,
      metadata: entry.metadata,
      actor: if(entry.actor, do: %{id: entry.actor.id, email: entry.actor.email}, else: nil),
      ip_address: entry.ip_address,
      timestamp: entry.inserted_at
    }
  end

  defp parse_int(str, default) when is_binary(str) do
    case Integer.parse(str) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(int, _default) when is_integer(int), do: int
  defp parse_int(_, default), do: default

  # -------------------------------------------------------------------
  # Role Templates
  # -------------------------------------------------------------------

  @doc """
  List available role templates.
  """
  def list_templates(conn, _params) do
    templates = Role.list_templates()

    json(conn, %{
      data: templates,
      meta: %{
        count: length(templates)
      }
    })
  end

  @doc """
  Create a role from a template.

  ## Body Parameters
  - template: Template key (e.g., "security_analyst")
  - name: Optional custom name
  - slug: Optional custom slug
  - description: Optional custom description
  """
  def create_from_template(conn, %{"template" => template_key} = params) do
    org_id = conn.assigns[:current_user].organization_id
    actor = conn.assigns[:current_user]

    case Role.get_template(template_key) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Template not found", available: Map.keys(Role.role_templates())})

      template ->
        slug = params["slug"] || template_key

        attrs = %{
          name: params["name"] || template.name,
          slug: slug,
          description: params["description"] || template.description,
          organization_id: org_id,
          builtin: false,
          priority: params["priority"] || 50,
          color: params["color"] || "#6366f1"
        }

        permissions = template.permissions

        case RBAC.create_role(attrs, permissions) do
          {:ok, role} ->
            RBACAuditLog.log_role_created(org_id, actor, role, [
              ip_address: get_client_ip(conn),
              user_agent: get_user_agent(conn),
              template: template_key
            ])

            conn
            |> put_status(:created)
            |> json(%{
              data: serialize_role(role),
              message: "Role created from template '#{template_key}'"
            })

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  # -------------------------------------------------------------------
  # Clone Role
  # -------------------------------------------------------------------

  @doc """
  Clone an existing role.

  ## Body Parameters
  - name: New role name
  - slug: New role slug
  - description: Optional description
  """
  def clone_role(conn, %{"id" => source_role_id} = params) do
    org_id = conn.assigns[:current_user].organization_id
    actor = conn.assigns[:current_user]

    case get_role(source_role_id, org_id) do
      nil ->
        {:error, :not_found}

      source_role ->
        # Get source role permissions
        source_permissions =
          if source_role.builtin do
            source_role.slug |> String.to_existing_atom() |> Role.default_permissions()
          else
            from(rp in TamanduaServer.Accounts.RolePermission,
              join: p in Permission, on: p.id == rp.permission_id,
              where: rp.role_id == ^source_role.id,
              select: p.slug
            )
            |> Repo.all()
            |> Enum.map(&String.to_existing_atom/1)
          end

        attrs = %{
          name: params["name"] || "#{source_role.name} (Copy)",
          slug: params["slug"] || "#{source_role.slug}_copy",
          description: params["description"] || source_role.description,
          organization_id: org_id,
          builtin: false,
          priority: params["priority"] || source_role.priority,
          color: params["color"] || source_role.color || "#6366f1"
        }

        case RBAC.create_role(attrs, source_permissions) do
          {:ok, role} ->
            RBACAuditLog.log_role_created(org_id, actor, role, [
              ip_address: get_client_ip(conn),
              user_agent: get_user_agent(conn),
              cloned_from: source_role.id
            ])

            conn
            |> put_status(:created)
            |> json(%{
              data: serialize_role(role),
              message: "Role cloned from '#{source_role.name}'"
            })

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  # -------------------------------------------------------------------
  # Role Hierarchy
  # -------------------------------------------------------------------

  @doc """
  Get role hierarchy information.
  """
  def role_hierarchy(conn, _params) do
    org_id = conn.assigns[:current_user].organization_id

    roles = from(r in Role,
      where: is_nil(r.organization_id) or r.organization_id == ^org_id,
      order_by: [desc: r.priority]
    )
    |> Repo.all()

    hierarchy = Role.role_hierarchy()

    json(conn, %{
      data: %{
        hierarchy: hierarchy,
        roles: Enum.map(roles, fn role ->
          %{
            id: role.id,
            name: role.name,
            slug: role.slug,
            priority: role.priority,
            builtin: role.builtin,
            level: Role.hierarchy_level(role.slug),
            inherit_from_id: role.inherit_from_id
          }
        end)
      }
    })
  end

  # -------------------------------------------------------------------
  # Effective Permissions
  # -------------------------------------------------------------------

  @doc """
  Get effective permissions for a user, showing inheritance chain.
  """
  def effective_permissions(conn, %{"user_id" => user_id}) do
    org_id = conn.assigns[:current_user].organization_id

    user = Accounts.get_user(user_id)

    unless user && user.organization_id == org_id do
      {:error, :not_found}
    else
      roles = RBAC.roles_for(user)
      all_permissions = RBAC.permissions_for(user)

      # Build permission breakdown by role
      permission_breakdown =
        roles
        |> Enum.map(fn role ->
          role_perms =
            if role.builtin do
              role.slug |> String.to_existing_atom() |> Role.default_permissions()
            else
              from(rp in TamanduaServer.Accounts.RolePermission,
                join: p in Permission, on: p.id == rp.permission_id,
                where: rp.role_id == ^role.id,
                select: p.slug
              )
              |> Repo.all()
              |> Enum.map(&String.to_existing_atom/1)
            end

          %{
            role: serialize_role(role),
            permissions: role_perms
          }
        end)

      # Group permissions by category
      permissions_by_category =
        Permission.definitions()
        |> Enum.map(fn {category, perms} ->
          category_perms =
            perms
            |> Enum.map(fn {slug, desc, _cat} ->
              %{
                slug: slug,
                description: desc,
                granted: slug in all_permissions
              }
            end)

          %{
            category: category,
            permissions: category_perms,
            granted_count: Enum.count(category_perms, & &1.granted),
            total_count: length(category_perms)
          }
        end)

      json(conn, %{
        data: %{
          user_id: user_id,
          roles: Enum.map(roles, &serialize_role/1),
          effective_permissions: all_permissions,
          permission_count: length(all_permissions),
          breakdown_by_role: permission_breakdown,
          breakdown_by_category: permissions_by_category
        }
      })
    end
  end

  # -------------------------------------------------------------------
  # Temporary Role Elevation
  # -------------------------------------------------------------------

  @doc """
  Temporarily elevate a user's role with an expiration time.

  ## Body Parameters
  - role_id: Role to grant temporarily
  - duration_hours: How long the elevation should last (max 72 hours)
  - reason: Justification for the elevation
  """
  def elevate_role(conn, %{"user_id" => user_id, "role_id" => role_id} = params) do
    org_id = conn.assigns[:current_user].organization_id
    actor = conn.assigns[:current_user]

    duration_hours = min(parse_int(params["duration_hours"], 4), 72)
    reason = params["reason"] || "Temporary elevation"

    with user when not is_nil(user) <- Accounts.get_user(user_id),
         true <- user.organization_id == org_id,
         role when not is_nil(role) <- get_role(role_id, org_id) do

      expires_at = DateTime.utc_now() |> DateTime.add(duration_hours * 3600, :second)

      opts = [
        granted_by: actor.id,
        expires_at: expires_at,
        actor: actor,
        ip_address: get_client_ip(conn),
        user_agent: get_user_agent(conn)
      ]

      case Accounts.assign_role_to_user(user, role, opts) do
        {:ok, _user_role} ->
          # Log with reason
          RBACAuditLog.log_role_assigned(org_id, actor, user, role, [
            ip_address: get_client_ip(conn),
            user_agent: get_user_agent(conn),
            reason: reason,
            temporary: true,
            duration_hours: duration_hours
          ])

          json(conn, %{
            data: %{
              user_id: user_id,
              role: serialize_role(role),
              expires_at: expires_at,
              duration_hours: duration_hours
            },
            message: "Role elevation granted until #{expires_at}"
          })

        {:error, changeset} ->
          {:error, changeset}
      end
    else
      nil -> {:error, :not_found}
      false -> {:error, :not_found}
    end
  end

  # -------------------------------------------------------------------
  # Bulk Role Assignment
  # -------------------------------------------------------------------

  @doc """
  Assign a role to multiple users at once.

  ## Body Parameters
  - user_ids: List of user IDs
  - role_id: Role to assign
  - expires_at: Optional expiration
  """
  def bulk_assign(conn, %{"user_ids" => user_ids, "role_id" => role_id} = params)
      when is_list(user_ids) do
    org_id = conn.assigns[:current_user].organization_id
    actor = conn.assigns[:current_user]

    role = get_role(role_id, org_id)

    unless role do
      {:error, :not_found}
    else
      expires_at = parse_datetime(params["expires_at"])

      results =
        user_ids
        |> Enum.map(fn user_id ->
          user = Accounts.get_user(user_id)

          cond do
            is_nil(user) ->
              {user_id, {:error, :not_found}}

            user.organization_id != org_id ->
              {user_id, {:error, :not_found}}

            true ->
              opts = [
                granted_by: actor.id,
                expires_at: expires_at,
                actor: actor
              ]

              case Accounts.assign_role_to_user(user, role, opts) do
                {:ok, _} -> {user_id, :ok}
                {:error, reason} -> {user_id, {:error, reason}}
              end
          end
        end)

      successful = Enum.count(results, fn {_, result} -> result == :ok end)
      failed = Enum.count(results, fn {_, result} -> result != :ok end)

      json(conn, %{
        data: %{
          role: serialize_role(role),
          successful: successful,
          failed: failed,
          results: Enum.map(results, fn {user_id, result} ->
            %{user_id: user_id, success: result == :ok}
          end)
        },
        message: "Assigned role to #{successful} users (#{failed} failed)"
      })
    end
  end

  # -------------------------------------------------------------------
  # User Audit Log
  # -------------------------------------------------------------------

  @doc """
  Get RBAC audit log for a specific user.
  """
  def user_audit_log(conn, %{"user_id" => user_id} = params) do
    org_id = conn.assigns[:current_user].organization_id

    user = Accounts.get_user(user_id)

    unless user && user.organization_id == org_id do
      {:error, :not_found}
    else
      limit = min(parse_int(params["limit"], 50), 500)
      offset = parse_int(params["offset"], 0)

      entries = RBACAuditLog.list_for_user(org_id, user_id, limit: limit, offset: offset)

      json(conn, %{
        data: %{
          user_id: user_id,
          user_email: user.email,
          entries: Enum.map(entries, &serialize_audit_entry/1)
        },
        meta: %{
          limit: limit,
          offset: offset
        }
      })
    end
  end

  # -------------------------------------------------------------------
  # Permission Conflict Detection
  # -------------------------------------------------------------------

  @doc """
  Detect permission conflicts for a proposed permission set.

  Conflicts occur when permissions are both granted and denied through
  different mechanisms (e.g., one role grants, another would deny).
  """
  def detect_conflicts(conn, %{"permissions" => permissions}) when is_list(permissions) do
    permission_atoms = permissions |> Enum.map(&to_atom_safe/1) |> Enum.reject(&is_nil/1)

    # Check for conflicting pairs (e.g., both read and no_read)
    conflicts =
      permission_atoms
      |> Enum.flat_map(fn perm ->
        perm_str = Atom.to_string(perm)
        negated_str = "no_" <> perm_str
        negated = try do
          String.to_existing_atom(negated_str)
        rescue
          ArgumentError -> nil
        end

        if negated && negated in permission_atoms do
          [%{permission: perm, conflict: negated, type: :explicit_denial}]
        else
          []
        end
      end)

    # Check for escalation risks (e.g., having delete without update)
    escalation_risks =
      check_escalation_risks(permission_atoms)

    json(conn, %{
      data: %{
        conflicts: conflicts,
        escalation_risks: escalation_risks,
        has_conflicts: length(conflicts) > 0,
        has_risks: length(escalation_risks) > 0
      }
    })
  end

  defp check_escalation_risks(permissions) do
    risks = []

    # Check: users_delete without users_read
    risks =
      if :users_delete in permissions and :users_read not in permissions do
        [%{permission: :users_delete, missing: :users_read, risk: "Can delete users without viewing them"} | risks]
      else
        risks
      end

    # Check: roles_update without roles_read
    risks =
      if :roles_update in permissions and :roles_read not in permissions do
        [%{permission: :roles_update, missing: :roles_read, risk: "Can modify roles without viewing them"} | risks]
      else
        risks
      end

    # Check: live_response_admin without live_response_access
    risks =
      if :live_response_admin in permissions and :live_response_access not in permissions do
        [%{permission: :live_response_admin, missing: :live_response_access, risk: "Admin shell without session access"} | risks]
      else
        risks
      end

    risks
  end
end
