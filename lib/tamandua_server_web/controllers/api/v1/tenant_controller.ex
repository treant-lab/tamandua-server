defmodule TamanduaServerWeb.API.V1.TenantController do
  @moduledoc """
  Tenant Management API Controller.

  Provides full CRUD operations for tenants (organizations) plus
  suspension/reactivation for billing and compliance purposes.

  All operations require system admin permissions except for
  tenant-scoped reads of their own organization.

  ## Endpoints

  - `GET /api/v1/tenants` - List all tenants (admin only)
  - `GET /api/v1/tenants/:id` - Get tenant details
  - `POST /api/v1/tenants` - Create new tenant (admin only)
  - `PUT /api/v1/tenants/:id` - Update tenant settings
  - `DELETE /api/v1/tenants/:id` - Deactivate tenant (admin only)
  - `POST /api/v1/tenants/:id/suspend` - Suspend tenant (admin only)
  - `POST /api/v1/tenants/:id/reactivate` - Reactivate tenant (admin only)
  - `POST /api/v1/tenants/provision` - Provision new tenant with admin (admin only)
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Tenants
  alias TamanduaServer.Accounts.Organization

  action_fallback TamanduaServerWeb.FallbackController

  # Authorization plugs
  plug TamanduaServerWeb.Plugs.RBAC, [permission: :system_settings] when action in [
    :index, :create, :delete, :suspend, :reactivate, :provision
  ]
  plug TamanduaServerWeb.Plugs.RBAC, [permission: :organization_read] when action in [:show]
  plug TamanduaServerWeb.Plugs.RBAC, [permission: :organization_update] when action in [:update]

  @doc """
  List all tenants with pagination and filters.

  ## Query Parameters
  - `limit` - Max results (default: 50, max: 100)
  - `offset` - Pagination offset
  - `active` - Filter by active status ("true" or "false")
  - `license_tier` - Filter by tier ("trial", "pro", "enterprise")

  ## Response

      {
        "data": [{ tenant... }],
        "meta": { "limit": 50, "offset": 0, "total": 123 }
      }
  """
  def index(conn, params) do
    opts = [
      limit: params["limit"] |> parse_int(50) |> max(1) |> min(100),
      offset: params["offset"] |> parse_int(0) |> max(0) |> min(100_000),
      active_only: params["active"] == "true"
    ]

    tenants = Tenants.list_organizations(opts)

    json(conn, %{
      data: Enum.map(tenants, &serialize_tenant/1),
      meta: %{
        limit: opts[:limit],
        offset: opts[:offset]
      }
    })
  end

  @doc """
  Get a single tenant by ID.

  Users can view their own organization. System admins can view any organization.
  Response includes usage statistics.
  """
  def show(conn, %{"id" => id}) do
    user = conn.assigns[:current_user]

    with {:ok, org} <- Tenants.get_organization(id),
         true <- can_view_tenant?(user, org) do
      usage = Tenants.get_usage_stats(org.id)

      json(conn, %{
        data: serialize_tenant(org, include_usage: true, usage: usage)
      })
    else
      {:error, :not_found} -> {:error, :not_found}
      false -> {:error, :forbidden}
    end
  end

  @doc """
  Create a new tenant (organization only, no admin user).

  For full provisioning with admin user, use `POST /tenants/provision`.

  ## Body Parameters
  - `name` - Organization name (required)
  - `slug` - URL-safe identifier (required)
  - `license_tier` - "trial" | "pro" | "enterprise" (default: "trial")
  - `settings` - Organization settings map
  - `region` - Data residency region
  """
  def create(conn, params) do
    attrs = %{
      name: params["name"],
      slug: params["slug"],
      license_tier: parse_license_tier(params["license_tier"]),
      settings: params["settings"] || %{},
      region: parse_region(params["region"])
    }

    case Tenants.create_organization(attrs) do
      {:ok, org} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_tenant(org)})

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Update a tenant's settings.

  Users can update their own organization. System admins can update any organization.

  ## Body Parameters
  - `name` - Organization name
  - `settings` - Organization settings map
  - `max_agents` - Maximum agent count (admin only)
  """
  def update(conn, %{"id" => id} = params) do
    user = conn.assigns[:current_user]

    with {:ok, org} <- Tenants.get_organization(id),
         true <- can_manage_tenant?(user, org) do
      # Filter allowed attributes based on permission level
      attrs =
        if system_admin?(user) do
          params
          |> Map.take(["name", "settings", "max_agents"])
          |> compact_params()
        else
          params
          |> Map.take(["name", "settings"])
          |> compact_params()
        end

      case Tenants.update_organization(org, attrs) do
        {:ok, updated} ->
          json(conn, %{data: serialize_tenant(updated)})

        {:error, changeset} ->
          {:error, changeset}
      end
    else
      {:error, :not_found} -> {:error, :not_found}
      false -> {:error, :forbidden}
    end
  end

  @doc """
  Delete a tenant (soft delete - marks as inactive).

  This suspends the organization rather than permanently deleting data.
  Use for deprovisioning or compliance holds.
  """
  def delete(conn, %{"id" => id}) do
    with {:ok, org} <- Tenants.get_organization(id),
         {:ok, _} <- Tenants.suspend_organization(org, "Deleted via API") do
      json(conn, %{message: "Tenant deactivated successfully"})
    end
  end

  @doc """
  Suspend a tenant, blocking all access.

  Suspended tenants cannot log in, and their agents cannot connect.
  Data is preserved and can be reactivated.

  ## Body Parameters
  - `reason` - Suspension reason for audit trail
  """
  def suspend(conn, %{"id" => id} = params) do
    reason = params["reason"] || "Suspended via API"

    with {:ok, org} <- Tenants.get_organization(id),
         {:ok, updated} <- Tenants.suspend_organization(org, reason) do
      json(conn, %{
        data: serialize_tenant(updated),
        message: "Tenant suspended"
      })
    end
  end

  @doc """
  Reactivate a suspended tenant.

  Restores full access to the organization.
  """
  def reactivate(conn, %{"id" => id}) do
    with {:ok, org} <- Tenants.get_organization(id),
         {:ok, updated} <- Tenants.reactivate_organization(org) do
      json(conn, %{
        data: serialize_tenant(updated),
        message: "Tenant reactivated"
      })
    end
  end

  @doc """
  Provision a new tenant with full setup.

  Creates:
  - The organization record
  - Default RBAC roles
  - An admin user with the admin role
  - Default rate limits based on license tier

  ## Body Parameters

      {
        "organization": {
          "name": "ACME Corp",
          "slug": "acme-corp",
          "settings": {},
          "region": "us"
        },
        "admin": {
          "email": "admin@acme.com",
          "password": "secure123!",
          "name": "Admin User"
        },
        "license_tier": "enterprise"
      }
  """
  def provision(conn, params) do
    org_attrs = %{
      name: get_in(params, ["organization", "name"]),
      slug: get_in(params, ["organization", "slug"]),
      settings: get_in(params, ["organization", "settings"]) || %{},
      region: parse_region(get_in(params, ["organization", "region"]))
    }

    admin_attrs = %{
      email: get_in(params, ["admin", "email"]),
      password: get_in(params, ["admin", "password"]),
      name: get_in(params, ["admin", "name"])
    }

    tier = parse_license_tier(params["license_tier"])

    case Tenants.provision_tenant(org_attrs, admin_attrs, license_tier: tier) do
      {:ok, result} ->
        conn
        |> put_status(:created)
        |> json(%{
          data: %{
            tenant: serialize_tenant(result.organization),
            admin: %{
              id: result.admin.id,
              email: result.admin.email,
              name: result.admin.name
            },
            roles_created: length(result.roles)
          }
        })

      {:error, {step, changeset}} when is_atom(step) ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Provisioning failed at #{step}", details: format_errors(changeset)})
    end
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp serialize_tenant(org, opts \\ []) do
    base = %{
      id: org.id,
      name: org.name,
      slug: org.slug,
      license_tier: org.license_tier,
      max_agents: org.max_agents,
      is_active: org.is_active,
      region: org.region,
      subscription_expires_at: org.subscription_expires_at,
      subscription_active: Organization.subscription_active?(org),
      features: org.features,
      settings: org.settings,
      inserted_at: org.inserted_at,
      updated_at: org.updated_at
    }

    if opts[:include_usage] && opts[:usage] do
      Map.put(base, :usage, opts[:usage])
    else
      base
    end
  end

  defp can_view_tenant?(user, org) do
    user.organization_id == org.id || system_admin?(user)
  end

  defp can_manage_tenant?(user, org) do
    user.organization_id == org.id || system_admin?(user)
  end

  defp system_admin?(user) do
    TamanduaServer.Authorization.RBAC.can?(user, :system_settings)
  end

  defp parse_int(nil, default), do: default
  defp parse_int(str, default) when is_binary(str) do
    case Integer.parse(str) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(int, _) when is_integer(int), do: int

  defp parse_region(nil), do: nil
  defp parse_region("eu"), do: :eu
  defp parse_region("us"), do: :us
  defp parse_region("apac"), do: :apac
  defp parse_region("ca"), do: :ca
  defp parse_region("uk"), do: :uk
  defp parse_region("au"), do: :au
  defp parse_region("jp"), do: :jp
  defp parse_region("in"), do: :in
  defp parse_region(_), do: nil

  defp parse_license_tier(nil), do: :trial
  defp parse_license_tier("trial"), do: :trial
  defp parse_license_tier("pro"), do: :pro
  defp parse_license_tier("enterprise"), do: :enterprise
  defp parse_license_tier(_), do: :trial

  defp compact_params(map) do
    map
    |> Enum.reject(fn {_, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
  defp format_errors(other), do: inspect(other)
end
