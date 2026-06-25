defmodule TamanduaServerWeb.API.V1.OrganizationController do
  @moduledoc """
  Organization Management API Controller.

  Provides CRUD operations for organizations (tenants).
  Most operations are restricted to system administrators or
  organization owners.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Agents
  alias TamanduaServer.TenantScope

  import Ecto.Query

  action_fallback TamanduaServerWeb.FallbackController

  alias TamanduaServer.Tenants

  # Authorization plugs
  plug TamanduaServerWeb.Plugs.RBAC, [permission: :organization_read] when action in [:show, :current]
  plug TamanduaServerWeb.Plugs.RBAC, [permission: :organization_update] when action in [:update]
  plug TamanduaServerWeb.Plugs.RBAC, [permission: :system_settings] when action in [:index, :create, :delete, :suspend, :reactivate, :provision]

  @doc """
  List all organizations.

  Requires system admin permissions. Normal users can only see their own organization.
  """
  def index(conn, params) do
    limit = Map.get(params, "limit", "50") |> parse_int(50)
    offset = Map.get(params, "offset", "0") |> parse_int(0)

    query =
      from o in Organization,
        order_by: [asc: o.name],
        limit: ^limit,
        offset: ^offset

    # Filter by license tier
    query =
      case params["license_tier"] do
        nil -> query
        tier -> from o in query, where: o.license_tier == ^tier
      end

    # Filter by active status
    query =
      case params["active"] do
        "true" -> from o in query, where: o.is_active == true
        "false" -> from o in query, where: o.is_active == false
        _ -> query
      end

    organizations = Repo.all(query)
    total = Repo.aggregate(Organization, :count)

    json(conn, %{
      data: Enum.map(organizations, &serialize_organization/1),
      meta: %{
        total: total,
        limit: limit,
        offset: offset
      }
    })
  end

  @doc """
  Get the current user's organization.
  """
  def current(conn, _params) do
    org_id = conn.assigns[:current_user].organization_id

    case Repo.get(Organization, org_id) do
      nil ->
        {:error, :not_found}

      org ->
        agent_count = count_agents(org_id)

        json(conn, %{
          data: serialize_organization(org, include_stats: true, agent_count: agent_count)
        })
    end
  end

  @doc """
  Get a specific organization by ID or slug.
  """
  def show(conn, %{"id" => id_or_slug}) do
    user = conn.assigns[:current_user]

    org =
      if Ecto.UUID.cast(id_or_slug) == :error do
        # Lookup by slug
        Repo.get_by(Organization, slug: id_or_slug)
      else
        Repo.get(Organization, id_or_slug)
      end

    cond do
      is_nil(org) ->
        {:error, :not_found}

      # Users can only view their own organization unless they're system admins
      org.id != user.organization_id and not system_admin?(user) ->
        {:error, :not_found}

      true ->
        agent_count = count_agents(org.id)

        json(conn, %{
          data: serialize_organization(org, include_stats: true, agent_count: agent_count)
        })
    end
  end

  @doc """
  Create a new organization.

  ## Body Parameters
  - name: Organization name (required)
  - slug: URL-safe identifier (required)
  - license_tier: trial | pro | enterprise (default: trial)
  - max_agents: Override default agent limit
  - settings: Organization settings map
  """
  def create(conn, params) do
    attrs = %{
      name: params["name"],
      slug: params["slug"],
      license_tier: params["license_tier"] || "trial",
      max_agents: params["max_agents"],
      settings: params["settings"] || %{},
      features: params["features"] || %{},
      is_active: true
    }

    case struct(Organization)
         |> Organization.changeset(attrs)
         |> Repo.insert() do
      {:ok, org} ->
        # Initialize builtin roles for this organization
        initialize_org_roles(org)

        conn
        |> put_status(:created)
        |> json(%{
          data: serialize_organization(org),
          message: "Organization created successfully"
        })

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Update an organization.

  Users can update their own organization settings.
  System admins can update any organization.
  """
  def update(conn, %{"id" => id} = params) do
    user = conn.assigns[:current_user]

    with org when not is_nil(org) <- Repo.get(Organization, id),
         true <- can_manage_org?(user, org) do
      # Separate settings updates from license updates
      attrs =
        params
        |> Map.take(["name", "settings"])
        |> Enum.reject(fn {_, v} -> is_nil(v) end)
        |> Map.new()

      case org
           |> Organization.changeset(attrs)
           |> Repo.update() do
        {:ok, updated_org} ->
          json(conn, %{
            data: serialize_organization(updated_org),
            message: "Organization updated successfully"
          })

        {:error, changeset} ->
          {:error, changeset}
      end
    else
      nil -> {:error, :not_found}
      false -> {:error, :forbidden}
    end
  end

  @doc """
  Update organization license tier (system admin only).
  """
  def update_license(conn, %{"id" => id} = params) do
    with org when not is_nil(org) <- Repo.get(Organization, id) do
      attrs = %{
        license_tier: params["license_tier"],
        max_agents: params["max_agents"],
        subscription_expires_at: parse_datetime(params["subscription_expires_at"]),
        features: params["features"]
      }

      case org
           |> Organization.license_changeset(attrs)
           |> Repo.update() do
        {:ok, updated_org} ->
          json(conn, %{
            data: serialize_organization(updated_org),
            message: "License updated successfully"
          })

        {:error, changeset} ->
          {:error, changeset}
      end
    else
      nil -> {:error, :not_found}
    end
  end

  @doc """
  Delete an organization (soft delete by deactivating).

  System admin only. Marks organization as inactive rather than
  actually deleting data.
  """
  def delete(conn, %{"id" => id}) do
    case Repo.get(Organization, id) do
      nil ->
        {:error, :not_found}

      org ->
        case org
             |> Ecto.Changeset.change(is_active: false)
             |> Repo.update() do
          {:ok, _} ->
            json(conn, %{message: "Organization deactivated successfully"})

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  @doc """
  Get organization usage statistics.
  """
  def usage(conn, %{"id" => id}) do
    user = conn.assigns[:current_user]

    with org when not is_nil(org) <- Repo.get(Organization, id),
         true <- can_manage_org?(user, org) do
      stats = %{
        agent_count: count_agents(org.id),
        max_agents: org.max_agents,
        agent_usage_percent: calculate_usage_percent(count_agents(org.id), org.max_agents),
        user_count: count_users(org.id),
        alert_count_30d: count_recent_alerts(org.id, 30),
        event_count_24h: count_recent_events(org.id, 1),
        storage_used_mb: 0,  # Placeholder for storage calculation
        features_enabled: get_enabled_features(org)
      }

      json(conn, %{data: stats})
    else
      nil -> {:error, :not_found}
      false -> {:error, :forbidden}
    end
  end

  @doc """
  Suspend an organization.

  Suspending an organization disables all access for users and agents
  in that organization. The data is preserved and can be reactivated.

  System admin only.
  """
  def suspend(conn, %{"id" => id} = params) do
    reason = params["reason"]

    with {:ok, org} <- Tenants.get_organization(id),
         {:ok, updated_org} <- Tenants.suspend_organization(org, reason) do
      json(conn, %{
        data: serialize_organization(updated_org),
        message: "Organization suspended successfully"
      })
    end
  end

  @doc """
  Reactivate a suspended organization.

  System admin only.
  """
  def reactivate(conn, %{"id" => id}) do
    with {:ok, org} <- Tenants.get_organization(id),
         {:ok, updated_org} <- Tenants.reactivate_organization(org) do
      json(conn, %{
        data: serialize_organization(updated_org),
        message: "Organization reactivated successfully"
      })
    end
  end

  @doc """
  Provision a new tenant with full setup.

  Creates:
  - The organization
  - Default RBAC roles
  - An admin user
  - Default rate limits

  System admin only.

  ## Body Parameters
  - organization: Map with name and slug (required)
  - admin: Map with email, password, and name (required)
  - license_tier: trial | pro | enterprise (default: trial)
  """
  def provision(conn, params) do
    org_attrs = %{
      name: get_in(params, ["organization", "name"]),
      slug: get_in(params, ["organization", "slug"]),
      settings: get_in(params, ["organization", "settings"]) || %{}
    }

    admin_attrs = %{
      email: get_in(params, ["admin", "email"]),
      password: get_in(params, ["admin", "password"]),
      name: get_in(params, ["admin", "name"])
    }

    opts = [
      license_tier: parse_license_tier(params["license_tier"])
    ]

    case Tenants.provision_tenant(org_attrs, admin_attrs, opts) do
      {:ok, result} ->
        conn
        |> put_status(:created)
        |> json(%{
          data: %{
            organization: serialize_organization(result.organization),
            admin: %{
              id: result.admin.id,
              email: result.admin.email,
              name: result.admin.name,
              role: result.admin.role
            },
            roles_created: length(result.roles)
          },
          message: "Tenant provisioned successfully"
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
        |> json(%{error: "Failed at step: #{step}", details: inspect(reason)})
    end
  end

  defp format_changeset_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
  defp format_changeset_errors(other), do: inspect(other)

  # -------------------------------------------------------------------
  # Private Helpers
  # -------------------------------------------------------------------

  defp serialize_organization(org, opts \\ []) do
    base = %{
      id: org.id,
      name: org.name,
      slug: org.slug,
      license_tier: org.license_tier,
      max_agents: org.max_agents,
      is_active: org.is_active,
      subscription_expires_at: org.subscription_expires_at,
      subscription_active: Organization.subscription_active?(org),
      settings: org.settings,
      features: org.features,
      inserted_at: org.inserted_at,
      updated_at: org.updated_at
    }

    if opts[:include_stats] do
      Map.merge(base, %{
        agent_count: opts[:agent_count] || 0,
        available_features: Organization.default_features(org.license_tier)
      })
    else
      base
    end
  end

  defp count_agents(org_id) do
    TenantScope.count_for_tenant(TamanduaServer.Agents.Agent, org_id)
  end

  defp count_users(org_id) do
    TenantScope.count_for_tenant(TamanduaServer.Accounts.User, org_id)
  end

  defp count_recent_alerts(org_id, days) do
    since = DateTime.utc_now() |> DateTime.add(-days * 24 * 60 * 60, :second)

    from(a in TamanduaServer.Alerts.Alert,
      where: a.organization_id == ^org_id and a.inserted_at >= ^since,
      select: count()
    )
    |> Repo.one()
  end

  defp count_recent_events(org_id, days) do
    since = DateTime.utc_now() |> DateTime.add(-days * 24 * 60 * 60, :second)

    # Events are associated through agents, so we need to join
    from(e in TamanduaServer.Telemetry.Event,
      join: a in assoc(e, :agent),
      where: a.organization_id == ^org_id and e.created_at >= ^since,
      select: count()
    )
    |> Repo.one()
  rescue
    _ -> 0  # Events table might not exist or have different timestamp column
  end

  defp get_enabled_features(org) do
    Organization.default_features(org.license_tier)
    |> Map.merge(org.features || %{})
    |> Enum.filter(fn {_, v} -> v == true end)
    |> Enum.map(fn {k, _} -> k end)
  end

  defp calculate_usage_percent(current, max) when max > 0 do
    Float.round(current / max * 100, 1)
  end

  defp calculate_usage_percent(_, _), do: 0.0

  defp can_manage_org?(user, org) do
    user.organization_id == org.id or system_admin?(user)
  end

  defp system_admin?(user) do
    # Check if user has system-level admin permissions
    TamanduaServer.Authorization.RBAC.can?(user, :system_settings)
  end

  defp initialize_org_roles(org) do
    # Create organization-specific custom roles can be done here
    # Builtin roles are global and don't need per-org creation
    :ok
  end

  defp parse_int(str, default) when is_binary(str) do
    case Integer.parse(str) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(int, _default) when is_integer(int), do: int
  defp parse_int(_, default), do: default

  defp parse_license_tier("trial"), do: :trial
  defp parse_license_tier("starter"), do: :pro
  defp parse_license_tier("pro"), do: :pro
  defp parse_license_tier("professional"), do: :enterprise
  defp parse_license_tier("enterprise"), do: :enterprise
  defp parse_license_tier(:trial), do: :trial
  defp parse_license_tier(:pro), do: :pro
  defp parse_license_tier(:enterprise), do: :enterprise
  defp parse_license_tier(_), do: :trial

  defp parse_datetime(nil), do: nil
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

end
