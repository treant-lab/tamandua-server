defmodule TamanduaServer.Tenants do
  @moduledoc """
  Context module for multi-tenant management.

  This module provides comprehensive tenant (organization) management including:
  - Organization CRUD operations
  - Tenant provisioning with admin user and default configuration
  - License tier management
  - Tenant suspension/reactivation
  - API key management
  - Rate limit configuration

  ## Tenant Isolation

  All data in Tamandua is isolated per tenant. This module works in conjunction
  with `TamanduaServer.TenantScope` to ensure proper data isolation.

  ## MSSP Support

  This module is designed to support Managed Security Service Provider (MSSP)
  deployments where a single Tamandua instance serves multiple customer organizations.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.{Organization, User, APIKey, TenantRateLimit, Role}

  require Logger

  # ===========================================================================
  # Organization CRUD
  # ===========================================================================

  @doc """
  Lists all organizations.

  ## Options
  - `:active_only` - Only return active organizations (default: false)
  - `:limit` - Maximum number of results
  - `:offset` - Offset for pagination
  """
  def list_organizations(opts \\ []) do
    query = from(o in Organization, order_by: [asc: o.name])

    query =
      if Keyword.get(opts, :active_only, false) do
        where(query, [o], o.is_active == true)
      else
        query
      end

    query =
      if limit = Keyword.get(opts, :limit) do
        limit(query, ^limit)
      else
        query
      end

    query =
      if offset = Keyword.get(opts, :offset) do
        offset(query, ^offset)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Gets an organization by ID.
  """
  def get_organization(id) do
    case Repo.get(Organization, id) do
      nil -> {:error, :not_found}
      org -> {:ok, org}
    end
  end

  @doc """
  Gets an organization by ID, raises if not found.
  """
  def get_organization!(id), do: Repo.get!(Organization, id)

  @doc """
  Gets an organization by slug.
  """
  def get_organization_by_slug(slug) do
    Repo.get_by(Organization, slug: slug)
  end

  @doc """
  Creates a new organization.

  Note: This is a simple insert without post-creation setup.
  For full tenant provisioning (with Sigma templates, roles, etc.),
  use `provision_tenant/3` instead.
  """
  def create_organization(attrs) do
    do_create_organization(attrs)
  end

  # Private helper for organization creation without setup hooks
  defp do_create_organization(attrs) do
    %Organization{}
    |> Organization.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates an organization.
  """
  def update_organization(%Organization{} = org, attrs) do
    org
    |> Organization.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes an organization and all associated data.

  WARNING: This is a destructive operation that cannot be undone.
  Consider using `suspend_organization/1` instead.
  """
  def delete_organization(%Organization{} = org) do
    Repo.delete(org)
  end

  # ===========================================================================
  # Tenant Provisioning
  # ===========================================================================

  @doc """
  Provisions a new tenant with full setup.

  This creates:
  1. The organization record
  2. Default RBAC roles for the organization
  3. An admin user with the admin role
  4. Default rate limits based on license tier
  5. Default configuration settings

  ## Parameters
  - `org_attrs` - Organization attributes (name, slug required)
  - `admin_attrs` - Admin user attributes (email, password required)
  - `opts` - Additional options:
    - `:license_tier` - License tier (default: :trial)
    - `:skip_roles` - Skip creating default roles (default: false)

  ## Returns
  - `{:ok, %{organization: org, admin: user, roles: roles}}`
  - `{:error, failed_operation, changeset, changes_so_far}`

  ## Example

      iex> provision_tenant(
      ...>   %{name: "ACME Corp", slug: "acme-corp"},
      ...>   %{email: "admin@acme.com", password: "secure123", name: "Admin User"}
      ...> )
      {:ok, %{organization: %Organization{}, admin: %User{}, ...}}
  """
  def provision_tenant(org_attrs, admin_attrs, opts \\ []) do
    license_tier = Keyword.get(opts, :license_tier, :trial)

    # Set license tier and default features
    org_attrs =
      org_attrs
      |> Map.put(:license_tier, license_tier)
      |> Map.put(:features, Organization.default_features(license_tier))

    alias TamanduaServer.Accounts.OrganizationSetup

    Repo.transaction(fn ->
      # 1. Create organization (skip automatic setup - we do it manually at step 6)
      org =
        case do_create_organization(org_attrs) do
          {:ok, org} -> org
          {:error, changeset} -> Repo.rollback({:organization, changeset})
        end

      # 2. Create default RBAC roles
      roles =
        unless Keyword.get(opts, :skip_roles, false) do
          case create_default_roles(org.id) do
            {:ok, roles} -> roles
            {:error, reason} -> Repo.rollback({:roles, reason})
          end
        else
          []
        end

      # 3. Create admin user
      admin_attrs =
        admin_attrs
        |> Map.put(:organization_id, org.id)
        |> Map.put(:role, "admin")

      admin =
        case Accounts.create_user(admin_attrs) do
          {:ok, user} -> user
          {:error, changeset} -> Repo.rollback({:admin, changeset})
        end

      # 4. Assign admin role to user
      admin_role = Enum.find(roles, fn r -> r.slug == "admin" end)
      if admin_role do
        case Accounts.assign_role_to_user(admin, admin_role) do
          {:ok, _} -> :ok
          {:error, reason} -> Repo.rollback({:role_assignment, reason})
        end
      end

      # 5. Create default rate limits
      rate_limits =
        case create_rate_limits(org.id, license_tier) do
          {:ok, limits} -> limits
          {:error, changeset} -> Repo.rollback({:rate_limits, changeset})
        end

      # 6. Run organization setup (Sigma templates, default settings, etc.)
      setup_opts = Keyword.take(opts, [:skip_sigma_templates, :skip_settings])
      case OrganizationSetup.setup_new_organization(org, setup_opts) do
        {:ok, _} -> :ok
        {:error, reason} -> Repo.rollback({:organization_setup, reason})
      end

      %{
        organization: org,
        admin: admin,
        roles: roles,
        rate_limits: rate_limits
      }
    end)
  end

  @doc """
  Creates default RBAC roles for an organization.
  """
  def create_default_roles(organization_id) do
    builtin_roles = [
      %{
        name: "Administrator",
        slug: "admin",
        description: "Full access to all features",
        builtin: true,
        priority: 100
      },
      %{
        name: "Analyst",
        slug: "analyst",
        description: "View and investigate alerts and events",
        builtin: true,
        priority: 50
      },
      %{
        name: "Responder",
        slug: "responder",
        description: "Analyst permissions plus response actions",
        builtin: true,
        priority: 60
      },
      %{
        name: "Hunter",
        slug: "hunter",
        description: "Advanced threat hunting and detection engineering",
        builtin: true,
        priority: 70
      },
      %{
        name: "Viewer",
        slug: "viewer",
        description: "Read-only access to dashboards and reports",
        builtin: true,
        priority: 10
      },
      %{
        name: "Compliance Officer",
        slug: "compliance_officer",
        description: "Compliance and audit focused access",
        builtin: true,
        priority: 40
      },
      %{
        name: "API Only",
        slug: "api_only",
        description: "Programmatic API access only",
        builtin: true,
        priority: 20,
        api_only: true
      }
    ]

    roles =
      Enum.map(builtin_roles, fn role_attrs ->
        role_attrs = Map.put(role_attrs, :organization_id, organization_id)

        case %Role{} |> Role.changeset(role_attrs) |> Repo.insert() do
          {:ok, role} ->
            # Assign default permissions to role
            assign_default_permissions(role)
            role

          {:error, changeset} ->
            Logger.warning("Failed to create role #{role_attrs.slug}: #{inspect(changeset.errors)}")
            nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    {:ok, roles}
  end

  defp assign_default_permissions(role) do
    permissions = Role.default_permissions(String.to_atom(role.slug))

    Enum.each(permissions, fn permission_slug ->
      # Find or create the permission
      case Repo.get_by(Accounts.Permission, slug: to_string(permission_slug)) do
        nil ->
          Logger.debug("Permission #{permission_slug} not found, skipping")

        permission ->
          %Accounts.RolePermission{}
          |> Accounts.RolePermission.changeset(%{
            role_id: role.id,
            permission_id: permission.id
          })
          |> Repo.insert(on_conflict: :nothing)
      end
    end)
  end

  @doc """
  Creates rate limits for an organization based on license tier.
  """
  def create_rate_limits(organization_id, tier \\ :trial) do
    defaults = TenantRateLimit.defaults_for_tier(tier)
    attrs = Map.put(defaults, :organization_id, organization_id)

    %TenantRateLimit{}
    |> TenantRateLimit.changeset(attrs)
    |> Repo.insert()
  end

  # ===========================================================================
  # License Management
  # ===========================================================================

  @doc """
  Updates an organization's license tier.

  This also updates the rate limits and features to match the new tier.
  """
  def update_license(%Organization{} = org, tier, opts \\ []) when tier in [:trial, :pro, :enterprise] do
    expires_at = Keyword.get(opts, :expires_at)
    custom_max_agents = Keyword.get(opts, :max_agents)
    custom_features = Keyword.get(opts, :features, %{})

    # Merge default features with any custom overrides
    features =
      tier
      |> Organization.default_features()
      |> Map.merge(custom_features)

    attrs = %{
      license_tier: tier,
      features: features,
      subscription_expires_at: expires_at
    }

    attrs =
      if custom_max_agents do
        Map.put(attrs, :max_agents, custom_max_agents)
      else
        attrs
      end

    Repo.transaction(fn ->
      # Update organization
      org =
        case org |> Organization.license_changeset(attrs) |> Repo.update() do
          {:ok, org} -> org
          {:error, changeset} -> Repo.rollback({:organization, changeset})
        end

      # Update rate limits
      case get_rate_limits(org.id) do
        {:ok, limits} ->
          new_limits = TenantRateLimit.defaults_for_tier(tier)
          case limits |> TenantRateLimit.changeset(new_limits) |> Repo.update() do
            {:ok, _} -> :ok
            {:error, changeset} -> Repo.rollback({:rate_limits, changeset})
          end

        {:error, :not_found} ->
          case create_rate_limits(org.id, tier) do
            {:ok, _} -> :ok
            {:error, changeset} -> Repo.rollback({:rate_limits, changeset})
          end
      end

      org
    end)
  end

  # ===========================================================================
  # Tenant Suspension
  # ===========================================================================

  @doc """
  Suspends a tenant, disabling all access.

  This is a soft delete - data is preserved but the organization
  cannot be used until reactivated.
  """
  def suspend_organization(%Organization{} = org, reason \\ nil) do
    Logger.info("Suspending organization #{org.id} (#{org.slug}): #{reason || "no reason given"}")

    org
    |> Ecto.Changeset.change(%{is_active: false})
    |> Repo.update()
  end

  @doc """
  Reactivates a suspended tenant.
  """
  def reactivate_organization(%Organization{} = org) do
    Logger.info("Reactivating organization #{org.id} (#{org.slug})")

    org
    |> Ecto.Changeset.change(%{is_active: true})
    |> Repo.update()
  end

  @doc """
  Checks if an organization is active and has a valid subscription.
  """
  def organization_active?(%Organization{} = org) do
    org.is_active && Organization.subscription_active?(org)
  end

  # ===========================================================================
  # API Key Management
  # ===========================================================================

  @doc """
  Creates an API key for an organization.

  Returns `{:ok, api_key}` where `api_key.raw_key` contains the actual key.
  The raw key is only available at creation time and cannot be retrieved later.
  """
  def create_api_key(organization_id, attrs, opts \\ []) do
    attrs = Map.put(attrs, :organization_id, organization_id)

    # Check if we're under the limit
    with {:ok, limits} <- get_rate_limits(organization_id),
         current_count <- count_api_keys(organization_id),
         true <- current_count < limits.max_api_keys do

      %APIKey{}
      |> APIKey.create_changeset(attrs, opts)
      |> Repo.insert()
    else
      false ->
        {:error, :api_key_limit_reached}

      {:error, :not_found} ->
        # No rate limits configured, allow creation
        %APIKey{}
        |> APIKey.create_changeset(attrs, opts)
        |> Repo.insert()

      error ->
        error
    end
  end

  @doc """
  Lists API keys for an organization.
  """
  def list_api_keys(organization_id) do
    APIKey
    |> where([k], k.organization_id == ^organization_id)
    |> order_by([k], [desc: k.inserted_at])
    |> Repo.all()
  end

  @doc """
  Gets an API key by ID, scoped to organization.
  """
  def get_api_key(organization_id, key_id) do
    case Repo.get_by(APIKey, id: key_id, organization_id: organization_id) do
      nil -> {:error, :not_found}
      key -> {:ok, key}
    end
  end

  @doc """
  Finds an API key by its raw value.

  This extracts the prefix, finds matching keys, and verifies the hash.
  """
  def find_api_key_by_value(raw_key) do
    prefix = APIKey.extract_prefix(raw_key)

    if prefix do
      APIKey
      |> where([k], k.key_prefix == ^prefix and k.is_active == true)
      |> Repo.all()
      |> Enum.find(fn key ->
        APIKey.verify_key(raw_key, key.key_hash)
      end)
      |> case do
        nil -> {:error, :invalid_key}
        key -> {:ok, key}
      end
    else
      {:error, :invalid_key_format}
    end
  end

  @doc """
  Updates an API key.
  """
  def update_api_key(%APIKey{} = key, attrs) do
    key
    |> APIKey.update_changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deactivates an API key.
  """
  def deactivate_api_key(%APIKey{} = key) do
    update_api_key(key, %{is_active: false})
  end

  @doc """
  Deletes an API key.
  """
  def delete_api_key(%APIKey{} = key) do
    Repo.delete(key)
  end

  @doc """
  Records API key usage (updates last_used_at).
  """
  def touch_api_key(%APIKey{} = key) do
    key
    |> APIKey.touch_changeset()
    |> Repo.update()
  end

  @doc """
  Counts API keys for an organization.
  """
  def count_api_keys(organization_id) do
    APIKey
    |> where([k], k.organization_id == ^organization_id)
    |> Repo.aggregate(:count)
  end

  # ===========================================================================
  # Rate Limit Management
  # ===========================================================================

  @doc """
  Gets rate limits for an organization.
  """
  def get_rate_limits(organization_id) do
    case Repo.get_by(TenantRateLimit, organization_id: organization_id) do
      nil -> {:error, :not_found}
      limits -> {:ok, limits}
    end
  end

  @doc """
  Updates rate limits for an organization.
  """
  def update_rate_limits(%TenantRateLimit{} = limits, attrs) do
    limits
    |> TenantRateLimit.changeset(attrs)
    |> Repo.update()
  end

  # ===========================================================================
  # Usage Statistics
  # ===========================================================================

  @doc """
  Gets usage statistics for an organization.
  """
  def get_usage_stats(organization_id) do
    agent_count = count_resource(TamanduaServer.Agents.Agent, organization_id)
    user_count = count_resource(User, organization_id)
    alert_count = count_resource(TamanduaServer.Alerts.Alert, organization_id)
    api_key_count = count_api_keys(organization_id)

    # Get playbook count if table exists
    playbook_count =
      try do
        count_resource(TamanduaServer.Response.Playbook.Schema, organization_id)
      rescue
        _ -> 0
      end

    %{
      agents: agent_count,
      users: user_count,
      alerts: alert_count,
      api_keys: api_key_count,
      playbooks: playbook_count
    }
  end

  defp count_resource(schema, organization_id) do
    schema
    |> where([r], r.organization_id == ^organization_id)
    |> Repo.aggregate(:count)
  rescue
    _ -> 0
  end

  @doc """
  Checks if an organization can add more agents.
  """
  def can_add_agent?(organization_id) do
    case get_organization(organization_id) do
      {:ok, org} ->
        if organization_active?(org) do
          current_count = count_resource(TamanduaServer.Agents.Agent, organization_id)
          Organization.can_add_agent?(org, current_count)
        else
          false
        end

      _ ->
        false
    end
  end

  # ===========================================================================
  # Feature Access
  # ===========================================================================

  @doc """
  Checks if an organization has access to a feature.
  """
  def has_feature?(organization_id, feature) when is_atom(feature) do
    case get_organization(organization_id) do
      {:ok, org} -> Organization.has_feature?(org, feature)
      _ -> false
    end
  end

  def has_feature?(%Organization{} = org, feature) when is_atom(feature) do
    Organization.has_feature?(org, feature)
  end
end
