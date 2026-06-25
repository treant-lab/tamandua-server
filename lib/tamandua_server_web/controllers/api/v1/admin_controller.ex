defmodule TamanduaServerWeb.API.V1.AdminController do
  @moduledoc """
  Admin Tenant Management API Controller.

  Provides endpoints for system administrators to manage tenants
  (organizations) in the Tamandua EDR platform. Used by the admin
  frontend pages (Tenants, TenantDetail, TenantCreate).

  All endpoints require system-level admin permissions via the
  `:system_settings` RBAC permission.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Tenants
  alias TamanduaServer.TenantScope
  alias TamanduaServer.Auth.InvitationManager

  import Ecto.Query

  require Logger

  action_fallback TamanduaServerWeb.FallbackController

  # All admin endpoints require system_settings permission
  plug TamanduaServerWeb.Plugs.RBAC, permission: :system_settings

  # ===========================================================================
  # Tenant CRUD
  # ===========================================================================

  @doc """
  List all tenants with pagination and filtering.

  ## Query Parameters
  - `page` - Page number (default: 1)
  - `per_page` - Items per page (default: 25, max: 100)
  - `search` - Search by name or slug
  - `plan` / `license_tier` - Filter by plan (trial, starter, professional, enterprise)
  - `status` - Filter by status (active, suspended, pending, deactivated)
  - `sort_by` - Sort field (name, created_at, agent_count) (default: name)
  - `sort_order` - Sort direction (asc, desc) (default: asc)
  """
  def index(conn, params) do
    per_page = params |> Map.get("per_page", "25") |> parse_int(25) |> min(100)
    page = params |> Map.get("page", "1") |> parse_int(1) |> max(1)
    offset = (page - 1) * per_page

    query = from(o in Organization, order_by: [asc: o.name])

    # Search filter
    query =
      case Map.get(params, "search") do
        nil -> query
        "" -> query
        term ->
          search_term = "%#{term}%"
          from o in query,
            where: ilike(o.name, ^search_term) or ilike(o.slug, ^search_term)
      end

    # Plan/license_tier filter (frontend may send as "plan" or "license_tier")
    tier = Map.get(params, "plan") || Map.get(params, "license_tier")
    query =
      case tier do
        nil -> query
        "" -> query
        t -> from o in query, where: o.license_tier == ^t
      end

    # Status filter
    query =
      case Map.get(params, "status") do
        "active" -> from o in query, where: o.is_active == true
        "suspended" -> from o in query, where: o.is_active == false
        "deactivated" -> from o in query, where: o.is_active == false
        _ -> query
      end

    # Get total before pagination
    total = Repo.aggregate(query, :count)

    # Apply pagination
    tenants =
      query
      |> limit(^per_page)
      |> offset(^offset)
      |> Repo.all()

    # Enrich each tenant with usage counts
    enriched_tenants = Enum.map(tenants, &serialize_tenant_with_stats/1)

    # Compute aggregate stats for the page header
    all_orgs_query = from(o in Organization)
    total_tenants = Repo.aggregate(all_orgs_query, :count)
    active_tenants = Repo.aggregate(from(o in Organization, where: o.is_active == true), :count)

    trial_tenants =
      Repo.aggregate(from(o in Organization, where: o.license_tier == :trial), :count)

    total_agents = safe_count(TamanduaServer.Agents.Agent)
    total_users = safe_count(User)

    json(conn, %{
      data: enriched_tenants,
      total: total,
      stats: %{
        total_tenants: total_tenants,
        active_tenants: active_tenants,
        trial_tenants: trial_tenants,
        total_agents: total_agents,
        total_users: total_users
      },
      meta: %{
        page: page,
        per_page: per_page,
        total: total,
        total_pages: ceil(total / per_page)
      }
    })
  end

  @doc """
  Show a single tenant with users, API keys, and usage stats.

  Returns enriched tenant data matching the TenantDetailPageProps
  expected by the frontend.
  """
  def show(conn, %{"id" => id}) do
    case Tenants.get_organization(id) do
      {:ok, org} ->
        tenant = serialize_tenant_with_stats(org)

        # Get users for this organization
        users = list_tenant_users(org.id)

        # Get API keys
        api_keys = Tenants.list_api_keys(org.id)

        # Get usage stats
        usage_stats = Tenants.get_usage_stats(org.id)

        # Build license info
        license = build_license_info(org)

        # Get pending invitations for this organization
        {:ok, invitations} = InvitationManager.list(org.id)

        json(conn, %{
          data: %{
            tenant: tenant,
            users: users,
            invitations: Enum.map(invitations, &serialize_invitation/1),
            api_keys: Enum.map(api_keys, &serialize_api_key/1),
            usage_stats: [serialize_usage_stats(org.id, usage_stats)],
            license: license
          }
        })

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Create a new tenant.

  Provisions the organization with an admin user if admin_email is provided.
  Otherwise creates just the organization record.

  ## Body Parameters
  - `name` - Tenant name (required)
  - `slug` - URL-safe identifier (required)
  - `domain` - Custom domain (optional)
  - `plan` - License tier: trial, starter, professional, enterprise (default: trial)
  - `admin_email` - Admin user email (optional, triggers full provisioning)
  - `admin_name` - Admin user name (required if admin_email provided)
  """
  def create(conn, params) do
    admin_email = params["admin_email"]

    if admin_email && admin_email != "" do
      # Full provisioning with admin user
      org_attrs = %{
        name: params["name"],
        slug: params["slug"],
        settings: params["settings"] || %{},
        is_active: true
      }

      # Map frontend plan names to license tier
      license_tier = map_plan_to_tier(params["plan"] || "trial")

      admin_attrs = %{
        email: admin_email,
        name: params["admin_name"] || "Admin",
        password: generate_temp_password()
      }

      case Tenants.provision_tenant(org_attrs, admin_attrs, license_tier: license_tier) do
        {:ok, result} ->
          tenant = serialize_tenant_with_stats(result.organization)

          conn
          |> put_status(:created)
          |> json(%{
            tenant: tenant,
            admin: %{
              id: result.admin.id,
              email: result.admin.email,
              name: result.admin.name
            },
            message: "Tenant created successfully"
          })

        {:error, {:organization, changeset}} ->
          {:error, changeset}

        {:error, {:admin, changeset}} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: "Failed to create admin user", details: format_changeset_errors(changeset)})

        {:error, {step, reason}} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: "Provisioning failed at step: #{step}", details: inspect(reason)})
      end
    else
      # Simple organization creation without admin
      license_tier = map_plan_to_tier(params["plan"] || "trial")

      attrs = %{
        name: params["name"],
        slug: params["slug"],
        license_tier: license_tier,
        settings: params["settings"] || %{},
        features: Organization.default_features(license_tier),
        is_active: true
      }

      case Tenants.create_organization(attrs) do
        {:ok, org} ->
          # Create default roles for the organization
          Tenants.create_default_roles(org.id)

          tenant = serialize_tenant_with_stats(org)

          conn
          |> put_status(:created)
          |> json(%{
            tenant: tenant,
            message: "Tenant created successfully"
          })

        {:error, changeset} ->
          {:error, changeset}
      end
    end
  end

  @doc """
  Update a tenant.

  ## Body Parameters
  - `name` - Organization name
  - `settings` - Organization settings map
  - `license_tier` - License tier
  - `max_agents` - Maximum agents override
  - `features` - Feature flags map
  """
  def update(conn, %{"id" => id} = params) do
    case Tenants.get_organization(id) do
      {:ok, org} ->
        attrs =
          params
          |> Map.take(["name", "settings", "license_tier", "max_agents", "features"])
          |> Enum.reject(fn {_, v} -> is_nil(v) end)
          |> Map.new()

        case Tenants.update_organization(org, attrs) do
          {:ok, updated_org} ->
            json(conn, %{
              data: serialize_tenant_with_stats(updated_org),
              message: "Tenant updated successfully"
            })

          {:error, changeset} ->
            {:error, changeset}
        end

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Delete (archive) a tenant.

  Performs a soft delete by deactivating the organization.
  Data is preserved but all access is disabled.
  """
  def delete(conn, %{"id" => id}) do
    case Tenants.get_organization(id) do
      {:ok, org} ->
        case Tenants.suspend_organization(org, "Deleted by admin") do
          {:ok, _} ->
            json(conn, %{message: "Tenant archived successfully"})

          {:error, reason} ->
            {:error, reason}
        end

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  # ===========================================================================
  # Tenant Status Actions
  # ===========================================================================

  @doc """
  Suspend a tenant, disabling all access.
  """
  def suspend(conn, %{"id" => id} = params) do
    reason = Map.get(params, "reason", "Suspended by admin")

    case Tenants.get_organization(id) do
      {:ok, org} ->
        case Tenants.suspend_organization(org, reason) do
          {:ok, updated_org} ->
            json(conn, %{
              data: serialize_tenant_with_stats(updated_org),
              message: "Tenant suspended successfully"
            })

          {:error, reason} ->
            {:error, reason}
        end

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Reactivate a suspended tenant.
  """
  def activate(conn, %{"id" => id}) do
    case Tenants.get_organization(id) do
      {:ok, org} ->
        case Tenants.reactivate_organization(org) do
          {:ok, updated_org} ->
            json(conn, %{
              data: serialize_tenant_with_stats(updated_org),
              message: "Tenant activated successfully"
            })

          {:error, reason} ->
            {:error, reason}
        end

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  # ===========================================================================
  # Invitations
  # ===========================================================================

  @doc """
  List invitations for a tenant.

  Returns all pending invitations for the organization. Pass `?status=all`
  to include accepted, expired, and revoked invitations.
  """
  def list_invitations(conn, %{"id" => id} = params) do
    case Tenants.get_organization(id) do
      {:ok, _org} ->
        opts =
          case Map.get(params, "status") do
            "all" -> [status: :all]
            nil -> [status: :pending]
            other -> [status: invitation_status(other)]
          end

        {:ok, invitations} = InvitationManager.list(id, opts)

        json(conn, %{
          data: Enum.map(invitations, &serialize_invitation/1),
          total: length(invitations)
        })

      {:error, :not_found} ->
        {:error, :not_found}
    end
  rescue
    ArgumentError ->
      json(conn, %{data: [], total: 0})
  end

  @doc """
  Create an invitation for a tenant user.

  Generates a secure token, validates input, and stores the invitation.

  ## Body Parameters
  - `email` (required) - Email address of the invitee
  - `role` (optional, default: "analyst") - Role: admin, analyst, viewer, responder
  """
  def create_invitation(conn, %{"id" => id} = params) do
    case Tenants.get_organization(id) do
      {:ok, _org} ->
        created_by =
          case conn.assigns do
            %{current_user: %{id: user_id}} -> user_id
            _ -> nil
          end

        attrs = %{
          email: params["email"],
          role: params["role"] || "analyst",
          organization_id: id,
          created_by: created_by
        }

        case InvitationManager.create(attrs) do
          {:ok, invitation} ->
            Logger.info(
              "[AdminController] Created invitation for #{invitation.email} " <>
                "in org #{id} with role #{invitation.role} (by #{created_by || "unknown"})"
            )

            conn
            |> put_status(:created)
            |> json(%{data: serialize_invitation(invitation), message: "Invitation created"})

          {:error, reason} when is_binary(reason) ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: reason})
        end

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Delete (revoke) an invitation.

  Marks the invitation as revoked so it can no longer be accepted.
  """
  def delete_invitation(conn, %{"id" => id, "invitation_id" => invitation_id}) do
    case Tenants.get_organization(id) do
      {:ok, _org} ->
        case InvitationManager.revoke(invitation_id) do
          {:ok, invitation} ->
            Logger.info(
              "[AdminController] Revoked invitation #{invitation_id} for #{invitation.email} in org #{id}"
            )

            json(conn, %{message: "Invitation revoked"})

          {:error, :not_found} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Invitation not found"})

          {:error, :already_accepted} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Cannot revoke an already accepted invitation"})
        end

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  # ===========================================================================
  # Tenant User Management
  # ===========================================================================

  @doc """
  Remove a user from a tenant.

  Deletes the user from the organization. This is a destructive operation.
  """
  def remove_user(conn, %{"id" => tenant_id, "user_id" => user_id}) do
    case Tenants.get_organization(tenant_id) do
      {:ok, _org} ->
        case Repo.get(User, user_id) do
          nil ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "User not found"})

          user ->
            # Verify user belongs to this organization
            if user.organization_id == tenant_id do
              case Accounts.delete_user(user) do
                {:ok, _} ->
                  Logger.info("[AdminController] Removed user #{user_id} from tenant #{tenant_id}")
                  json(conn, %{status: "removed"})

                {:error, changeset} ->
                  conn
                  |> put_status(:unprocessable_entity)
                  |> json(%{error: "Failed to remove user", details: format_changeset_errors(changeset)})
              end
            else
              conn
              |> put_status(:unprocessable_entity)
              |> json(%{error: "User does not belong to this tenant"})
            end
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Tenant not found"})
    end
  rescue
    e ->
      Logger.warning("[AdminController] remove_user failed: #{Exception.message(e)}")
      conn
      |> put_status(:internal_server_error)
      |> json(%{error: "Failed to remove user"})
  end

  # ===========================================================================
  # Tenant API Key Management
  # ===========================================================================

  @doc """
  Create an API key for a tenant.

  ## Body Parameters
  - `name` (required) - API key name
  - `scopes` (optional) - List of scopes/permissions
  - `expires_at` (optional) - Expiration date
  """
  def create_api_key(conn, %{"id" => tenant_id} = params) do
    case Tenants.get_organization(tenant_id) do
      {:ok, _org} ->
        attrs = %{
          name: params["name"] || "API Key",
          permissions: params["scopes"] || [],
          scope: params["scope"] || "full"
        }

        # Parse expires_at if provided
        attrs =
          case params["expires_at"] do
            nil ->
              attrs

            expires_str when is_binary(expires_str) ->
              case DateTime.from_iso8601(expires_str) do
                {:ok, dt, _} -> Map.put(attrs, :expires_at, dt)
                _ -> attrs
              end

            _ ->
              attrs
          end

        case Tenants.create_api_key(tenant_id, attrs) do
          {:ok, api_key} ->
            Logger.info("[AdminController] Created API key #{api_key.id} for tenant #{tenant_id}")

            conn
            |> put_status(:created)
            |> json(%{
              data: %{
                id: api_key.id,
                name: api_key.name,
                key: api_key.raw_key,
                key_prefix: api_key.key_prefix,
                scopes: api_key.permissions || [],
                scope: api_key.scope,
                created_at: api_key.inserted_at,
                expires_at: api_key.expires_at
              },
              message: "API key created successfully"
            })

          {:error, :api_key_limit_reached} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "API key limit reached for this tenant"})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to create API key", details: format_changeset_errors(changeset)})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Tenant not found"})
    end
  rescue
    e ->
      Logger.warning("[AdminController] create_api_key failed: #{Exception.message(e)}")
      conn
      |> put_status(:internal_server_error)
      |> json(%{error: "Failed to create API key"})
  end

  @doc """
  Revoke (deactivate) an API key for a tenant.
  """
  def revoke_api_key(conn, %{"id" => tenant_id, "key_id" => key_id}) do
    case Tenants.get_organization(tenant_id) do
      {:ok, _org} ->
        case Tenants.get_api_key(tenant_id, key_id) do
          {:ok, api_key} ->
            case Tenants.deactivate_api_key(api_key) do
              {:ok, _} ->
                Logger.info("[AdminController] Revoked API key #{key_id} for tenant #{tenant_id}")
                json(conn, %{status: "revoked", message: "API key revoked successfully"})

              {:error, changeset} ->
                conn
                |> put_status(:unprocessable_entity)
                |> json(%{error: "Failed to revoke API key", details: format_changeset_errors(changeset)})
            end

          {:error, :not_found} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "API key not found"})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Tenant not found"})
    end
  rescue
    e ->
      Logger.warning("[AdminController] revoke_api_key failed: #{Exception.message(e)}")
      conn
      |> put_status(:internal_server_error)
      |> json(%{error: "Failed to revoke API key"})
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp serialize_invitation(invitation) do
    %{
      id: invitation.id,
      tenant_id: invitation.organization_id,
      email: invitation.email,
      role: invitation.role,
      status: invitation.status,
      created_by: invitation.created_by,
      created_at: invitation.created_at |> DateTime.to_iso8601(),
      expires_at: invitation.expires_at |> DateTime.to_iso8601()
    }
  end

  defp serialize_tenant_with_stats(org) when is_map(org) do
    agent_count = safe_tenant_count(TamanduaServer.Agents.Agent, org.id)
    user_count = safe_tenant_count(User, org.id)
    event_count_30d = count_recent_events(org.id, 30)

    %{
      id: org.id,
      name: org.name,
      slug: org.slug,
      domain: Map.get(org.settings || %{}, "domain") || Map.get(org.settings || %{}, :domain),
      status: tenant_status(org),
      plan: to_string(org.license_tier || "trial"),
      logo_url: get_in_settings(org, "logo_url"),
      primary_color: get_in_settings(org, "primary_color"),
      created_at: org.inserted_at,
      updated_at: org.updated_at,
      settings: org.settings,
      features: org.features,
      license_tier: org.license_tier,
      max_agents: org.max_agents,
      is_active: org.is_active,
      subscription_expires_at: org.subscription_expires_at,
      agent_count: agent_count,
      user_count: user_count,
      event_count_30d: event_count_30d,
      storage_used_mb: 0
    }
  end

  defp tenant_status(%{is_active: false}), do: "suspended"
  defp tenant_status(%{is_active: true} = org) do
    if Organization.subscription_active?(org), do: "active", else: "deactivated"
  end

  defp get_in_settings(%{settings: nil}, _key), do: nil
  defp get_in_settings(%{settings: settings}, key) when is_map(settings) do
    Map.get(settings, key) || Map.get(settings, settings_key(key))
  rescue
    _ -> nil
  end

  defp list_tenant_users(org_id) do
    users =
      from(u in User,
        where: u.organization_id == ^org_id,
        order_by: [asc: u.email]
      )
      |> Repo.all()

    Enum.map(users, fn u ->
      %{
        id: u.id,
        tenant_id: org_id,
        user_id: u.id,
        role: u.role || "analyst",
        user: %{
          id: u.id,
          name: u.name || u.email,
          email: u.email
        },
        joined_at: u.inserted_at,
        last_active_at: u.last_login_at,
        is_primary_contact: u.role == "admin"
      }
    end)
  end

  defp serialize_api_key(key) do
    %{
      id: key.id,
      name: key.name,
      key_prefix: key.key_prefix,
      is_active: key.is_active,
      scopes: key.permissions || [],
      scope: key.scope,
      created_at: key.inserted_at,
      last_used_at: key.last_used_at,
      expires_at: key.expires_at
    }
  end

  defp serialize_usage_stats(org_id, stats) do
    %{
      tenant_id: org_id,
      period: "daily",
      agents_active: stats.agents,
      agents_total: stats.agents,
      events_ingested: 0,
      alerts_generated: stats.alerts,
      storage_used_mb: 0,
      api_calls: 0,
      date: Date.utc_today() |> Date.to_iso8601()
    }
  end

  defp build_license_info(org) when is_map(org) do
    usage_stats = Tenants.get_usage_stats(org.id)

    defaults = tier_limits(org.license_tier)

    %{
      tenant_id: org.id,
      plan: to_string(org.license_tier || "trial"),
      status: if(Organization.subscription_active?(org), do: "active", else: "expired"),
      started_at: org.inserted_at |> to_string(),
      expires_at: (org.subscription_expires_at || DateTime.add(DateTime.utc_now(), 365 * 86400, :second)) |> to_string(),
      auto_renew: false,
      limits: %{
        max_agents: org.max_agents || defaults.max_agents,
        max_users: defaults.max_users,
        max_events_per_day: defaults.max_events_per_day,
        retention_days: defaults.retention_days,
        features: Map.keys(org.features || %{}) |> Enum.filter(fn k -> Map.get(org.features || %{}, k) == true end)
      },
      usage: %{
        agents: usage_stats.agents,
        users: usage_stats.users,
        events_today: 0
      }
    }
  end

  defp tier_limits(tier) do
    case to_string(tier) do
      "enterprise" -> %{max_agents: 10_000, max_users: 500, max_events_per_day: 10_000_000, retention_days: 365}
      "professional" -> %{max_agents: 100, max_users: 50, max_events_per_day: 1_000_000, retention_days: 90}
      "starter" -> %{max_agents: 25, max_users: 10, max_events_per_day: 100_000, retention_days: 30}
      _ -> %{max_agents: 5, max_users: 3, max_events_per_day: 10_000, retention_days: 7}
    end
  end

  defp count_recent_events(org_id, days) do
    since = DateTime.utc_now() |> DateTime.add(-days * 24 * 3600, :second)

    from(a in TamanduaServer.Alerts.Alert,
      where: a.organization_id == ^org_id and a.inserted_at >= ^since,
      select: count()
    )
    |> Repo.one()
  rescue
    _ -> 0
  end

  defp safe_tenant_count(schema, org_id) do
    TenantScope.count_for_tenant(schema, org_id)
  rescue
    _ -> 0
  end

  defp safe_count(schema) do
    Repo.aggregate(schema, :count)
  rescue
    _ -> 0
  end

  defp map_plan_to_tier(plan) do
    case plan do
      "enterprise" -> :enterprise
      "professional" -> :enterprise
      "starter" -> :pro
      "pro" -> :pro
      "trial" -> :trial
      _ -> :trial
    end
  end

  defp generate_temp_password do
    :crypto.strong_rand_bytes(24)
    |> Base.url_encode64(padding: false)
  end

  defp format_changeset_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
  defp format_changeset_errors(other), do: inspect(other)

  defp parse_int(str, default) when is_binary(str) do
    case Integer.parse(str) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(int, _default) when is_integer(int), do: int
  defp parse_int(_, default), do: default

  defp settings_key("logo_url"), do: :logo_url
  defp settings_key("primary_color"), do: :primary_color
  defp settings_key(key), do: key

  defp invitation_status("pending"), do: :pending
  defp invitation_status("accepted"), do: :accepted
  defp invitation_status("expired"), do: :expired
  defp invitation_status("revoked"), do: :revoked
  defp invitation_status(_), do: :pending
end
