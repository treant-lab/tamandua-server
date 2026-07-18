defmodule TamanduaServer.Auth.SSO.Provisioner do
  @moduledoc """
  Just-In-Time (JIT) user provisioning and synchronization for SSO.

  Handles:
  - Automatic user creation on first login
  - User attribute synchronization (name, email, etc.)
  - Group-to-role mapping (IdP groups → Tamandua RBAC roles)
  - Domain restrictions
  - User deprovisioning (account disabling)
  - Audit logging for provisioning events

  ## Examples

      # Provision a user from SAML attributes
      attrs = %{
        email: "user@example.com",
        name: "John Doe",
        groups: ["Admins", "Security Team"],
        provider_user_id: "abc123"
      }

      {:ok, user} = Provisioner.provision_user(sso_config, attrs)

      # Sync existing user attributes
      {:ok, user} = Provisioner.sync_user_attributes(user, sso_config, attrs)

      # Deprovision (disable) a user
      :ok = Provisioner.deprovision_user(user, "Removed from IdP")
  """

  require Logger
  alias TamanduaServer.{Accounts}
  alias TamanduaServer.Auth.SSO.SSOConfig
  alias TamanduaServer.AuditLog

  @doc """
  Provision a user from SSO attributes.

  Creates a new user if JIT provisioning is enabled, or returns an existing user.
  Also synchronizes user attributes and role mappings.
  """
  @spec provision_user(SSOConfig.t(), map()) :: {:ok, Accounts.User.t()} | {:error, atom() | String.t()}
  def provision_user(%SSOConfig{} = config, attrs) do
    email = attrs[:email] || attrs["email"]

    unless email do
      {:error, :missing_email}
    else
      # Check domain restriction
      case check_domain_restriction(config, email) do
        :ok ->
          case Accounts.get_user_by_email(email) do
            nil -> create_user_from_sso(config, attrs)
            user -> sync_user_attributes(user, config, attrs)
          end

        error ->
          error
      end
    end
  end

  @doc """
  Create a new user from SSO attributes (JIT provisioning).
  """
  @spec create_user_from_sso(SSOConfig.t(), map()) :: {:ok, Accounts.User.t()} | {:error, atom() | String.t()}
  def create_user_from_sso(%SSOConfig{jit_provisioning: false}, _attrs) do
    {:error, :jit_provisioning_disabled}
  end

  def create_user_from_sso(%SSOConfig{} = config, attrs) do
    email = attrs[:email] || attrs["email"]
    name = attrs[:name] || attrs["name"] || email
    groups = attrs[:groups] || attrs["groups"] || []

    # Map SSO groups to Tamandua role
    role = map_groups_to_role(config, groups)

    user_attrs = %{
      email: email,
      name: name,
      organization_id: config.organization_id,
      password_hash: generate_random_password_hash(),
      role: role,
      is_active: true
    }

    case Accounts.create_user(user_attrs) do
      {:ok, user} ->
        log_provisioning_event(config, :user_created, user, %{
          role: role,
          groups: groups,
          sso_provider: config.provider
        })

        # Assign RBAC roles based on group mappings
        assign_roles_from_groups(user, config, groups)

        {:ok, user}

      {:error, changeset} ->
        Logger.error("[SSO Provisioner] Failed to create user #{email}: #{inspect(changeset)}")
        {:error, :user_creation_failed}
    end
  end

  @doc """
  Synchronize user attributes from SSO.

  Updates name, role, and RBAC role assignments based on current SSO attributes.
  """
  @spec sync_user_attributes(Accounts.User.t(), SSOConfig.t(), map()) ::
          {:ok, Accounts.User.t()} | {:error, atom() | String.t()}
  def sync_user_attributes(%Accounts.User{} = user, %SSOConfig{} = config, attrs) do
    # Verify user belongs to the correct organization
    if user.organization_id != config.organization_id do
      {:error, :user_belongs_to_different_org}
    else
      updates = build_user_updates(user, config, attrs)

      if map_size(updates) > 0 do
        case Accounts.update_user(user, updates) do
          {:ok, updated_user} ->
            log_provisioning_event(config, :user_updated, updated_user, updates)

            # Re-sync RBAC roles based on current groups
            groups = attrs[:groups] || attrs["groups"] || []
            sync_roles_from_groups(updated_user, config, groups)

            {:ok, updated_user}

          error ->
            error
        end
      else
        # Still sync roles even if no attribute changes
        groups = attrs[:groups] || attrs["groups"] || []
        sync_roles_from_groups(user, config, groups)

        {:ok, user}
      end
    end
  end

  @doc """
  Deprovision (disable) a user.

  Sets `is_active: false` and optionally removes role assignments.
  """
  @spec deprovision_user(Accounts.User.t(), String.t()) :: :ok | {:error, term()}
  def deprovision_user(%Accounts.User{} = user, reason \\ "Removed from IdP") do
    case Accounts.update_user(user, %{is_active: false}) do
      {:ok, updated_user} ->
        AuditLog.log(%{
          organization_id: user.organization_id,
          action: "sso.user_deprovisioned",
          actor_id: nil,
          resource_type: "user",
          resource_id: user.id,
          details: %{
            email: user.email,
            reason: reason
          }
        })

        # Optionally revoke all role assignments
        revoke_all_roles(updated_user)

        :ok

      {:error, _changeset} = error ->
        error
    end
  end

  @doc """
  Re-provision (re-enable) a deprovisioned user.
  """
  @spec reprovision_user(Accounts.User.t(), SSOConfig.t(), map()) ::
          {:ok, Accounts.User.t()} | {:error, term()}
  def reprovision_user(%Accounts.User{} = user, %SSOConfig{} = config, attrs) do
    updates = %{is_active: true}

    case Accounts.update_user(user, updates) do
      {:ok, updated_user} ->
        log_provisioning_event(config, :user_reprovisioned, updated_user, %{
          previous_state: "inactive"
        })

        # Re-sync attributes and roles
        sync_user_attributes(updated_user, config, attrs)

      error ->
        error
    end
  end

  @doc """
  Map SSO groups to a Tamandua role based on configuration.

  Returns the highest-priority matching role, or the default role.
  """
  @spec map_groups_to_role(SSOConfig.t(), list(String.t())) :: String.t()
  def map_groups_to_role(%SSOConfig{} = config, groups) when is_list(groups) do
    mappings = config.group_role_mappings || %{}

    # Role priority (higher number = higher privilege)
    role_priority = %{
      "super_admin" => 6,
      "admin" => 5,
      "compliance_officer" => 4,
      "responder" => 3,
      "hunter" => 3,
      "analyst" => 2,
      "viewer" => 1,
      "api_only" => 0
    }

    matched_role =
      Enum.reduce(groups, nil, fn group, best ->
        case Map.get(mappings, group) do
          nil ->
            best

          role ->
            p = Map.get(role_priority, role, 0)
            best_p = if best, do: Map.get(role_priority, best, 0), else: -1

            if p > best_p, do: role, else: best
        end
      end)

    matched_role || config.default_role || "analyst"
  end

  def map_groups_to_role(%SSOConfig{} = config, _groups) do
    config.default_role || "analyst"
  end

  @doc """
  Validate SSO user attributes before provisioning.
  """
  @spec validate_sso_attributes(map()) :: :ok | {:error, atom()}
  def validate_sso_attributes(attrs) do
    cond do
      is_nil(attrs[:email]) and is_nil(attrs["email"]) ->
        {:error, :missing_email}

      true ->
        :ok
    end
  end

  # ================================================================
  # Private Functions
  # ================================================================

  defp check_domain_restriction(%SSOConfig{allowed_domains: []}, _email), do: :ok

  defp check_domain_restriction(%SSOConfig{allowed_domains: allowed_domains}, email) do
    domain =
      email
      |> String.split("@")
      |> List.last()
      |> String.downcase()

    if Enum.any?(allowed_domains, &(String.downcase(&1) == domain)) do
      :ok
    else
      {:error, :domain_not_allowed}
    end
  end

  defp build_user_updates(user, config, attrs) do
    updates = %{}

    name = attrs[:name] || attrs["name"]
    groups = attrs[:groups] || attrs["groups"] || []

    # Update name if changed
    updates =
      if name && name != user.name do
        Map.put(updates, :name, name)
      else
        updates
      end

    # Re-evaluate role from groups
    if groups != [] do
      new_role = map_groups_to_role(config, groups)

      if new_role != user.role do
        Map.put(updates, :role, new_role)
      else
        updates
      end
    else
      updates
    end
  end

  defp assign_roles_from_groups(user, config, groups) do
    mappings = config.group_role_mappings || %{}

    # Get unique role assignments from group mappings
    roles_to_assign =
      groups
      |> Enum.map(&Map.get(mappings, &1))
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    # Assign each role using the RBAC system
    Enum.each(roles_to_assign, fn role_slug ->
      case Accounts.get_role_by_slug(config.organization_id, role_slug) do
        nil ->
          Logger.warning("[SSO Provisioner] Role not found: #{role_slug}")
          :ok

        role ->
          Accounts.assign_role_to_user(user, role, actor: nil, source: "sso_provisioning")
      end
    end)
  end

  defp sync_roles_from_groups(user, config, groups) do
    mappings = config.group_role_mappings || %{}

    # Get roles that should be assigned based on current groups
    expected_roles =
      groups
      |> Enum.map(&Map.get(mappings, &1))
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()
      |> MapSet.new()

    # Get currently assigned roles
    current_role_slugs =
      user
      |> Accounts.get_user_roles()
      |> Enum.map(& &1.slug)
      |> MapSet.new()

    # Roles to add
    roles_to_add = MapSet.difference(expected_roles, current_role_slugs)

    # Roles to remove (only SSO-managed roles)
    roles_to_remove = MapSet.difference(current_role_slugs, expected_roles)

    # Add new roles
    Enum.each(roles_to_add, fn role_slug ->
      case Accounts.get_role_by_slug(config.organization_id, role_slug) do
        nil ->
          Logger.warning("[SSO Provisioner] Role not found: #{role_slug}")

        role ->
          Accounts.assign_role_to_user(user, role, actor: nil, source: "sso_sync")
      end
    end)

    # Remove roles that are no longer in groups
    Enum.each(roles_to_remove, fn role_slug ->
      case Accounts.get_role_by_slug(config.organization_id, role_slug) do
        nil ->
          :ok

        role ->
          # Only remove if it was assigned via SSO
          Accounts.revoke_role_from_user(user, role, actor: nil, source: "sso_sync")
      end
    end)

    :ok
  end

  defp revoke_all_roles(user) do
    user
    |> Accounts.get_user_roles()
    |> Enum.each(fn role ->
      Accounts.revoke_role_from_user(user, role, actor: nil, source: "deprovisioning")
    end)
  rescue
    _ -> :ok
  end

  defp generate_random_password_hash do
    :crypto.strong_rand_bytes(32)
    |> Base.encode64()
    |> Bcrypt.hash_pwd_salt()
  end

  defp log_provisioning_event(config, event_type, user, details) do
    AuditLog.log(%{
      organization_id: config.organization_id,
      action: "sso.#{event_type}",
      actor_id: nil,
      resource_type: "user",
      resource_id: user.id,
      details:
        Map.merge(details, %{
          email: user.email,
          sso_provider: config.provider,
          sso_config_id: config.id
        })
    })
  rescue
    e ->
      Logger.error("[SSO Provisioner] Failed to log event: #{inspect(e)}")
      :ok
  end
end
