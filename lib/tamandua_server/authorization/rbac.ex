defmodule TamanduaServer.Authorization.RBAC do
  @moduledoc """
  Enterprise-Grade Role-Based Access Control (RBAC) with ABAC Extensions.

  Provides comprehensive authorization with:
  - Role-Based Access Control (RBAC)
  - Attribute-Based Access Control (ABAC)
  - Time-based access restrictions (business hours)
  - Location-based access (IP restrictions, CIDR ranges)
  - Resource-level fine-grained permissions
  - Multi-tenant isolation for 1000+ tenant support
  - ETS-based caching for high-performance lookups

  ## Architecture

  Access decisions are made using a policy evaluation engine that considers:
  1. User attributes (role, department, clearance level, etc.)
  2. Resource attributes (sensitivity, owner, classification)
  3. Environment attributes (time, IP, device, location)
  4. Action being performed

  ## Usage

      # Simple permission check
      RBAC.can?(user, :alerts_read)

      # Check with resource context
      RBAC.can?(user, :agents_command, agent, context)

      # Check with full ABAC policy
      RBAC.evaluate_policy(user, :response_execute, resource, %{
        ip_address: "192.168.1.100",
        time: DateTime.utc_now(),
        device_id: "trusted-device-123"
      })

      # Authorize (raises if denied)
      RBAC.authorize!(user, :response_execute)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Accounts.{User, Role, Permission, UserRole}
  alias TamanduaServer.Authorization.{AccessPolicy}
  alias TamanduaServer.Repo

  import Ecto.Query
  import Bitwise

  @cache_table :rbac_permission_cache
  @role_cache_table :rbac_role_cache
  @policy_cache_table :rbac_policy_cache
  @cache_ttl_seconds 300

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if a user has a specific permission.

  Returns `true` if the user has the permission, `false` otherwise.
  """
  def can?(%User{} = user, permission) when is_atom(permission) do
    can?(user, permission, nil, %{})
  end

  def can?(%User{} = user, permission, resource) when is_atom(permission) do
    can?(user, permission, resource, %{})
  end

  def can?(%User{} = user, permission, resource, context) when is_atom(permission) do
    # First check basic RBAC permissions
    permissions = get_cached_permissions(user)

    has_permission = cond do
      # Super admin has all permissions
      :system_all in permissions -> true
      # Check direct permission
      permission in permissions -> true
      true -> false
    end

    if has_permission do
      # Apply ABAC policy evaluation
      evaluate_abac_policies(user, permission, resource, context)
    else
      false
    end
  end

  def can?(nil, _permission, _resource, _context), do: false
  def can?(_user, _permission, _resource, _context), do: false

  @doc """
  Full ABAC policy evaluation with detailed result.

  Returns `{:allow, reason}` or `{:deny, reason}` with explanation.
  """
  def evaluate_policy(%User{} = user, permission, resource, context \\ %{}) do
    if can?(user, permission, resource, context) do
      {:allow, "Access granted by policy evaluation"}
    else
      {:deny, get_denial_reason(user, permission, resource, context)}
    end
  end

  @doc """
  Same as `can?/2` but raises `TamanduaServer.Authorization.UnauthorizedError` if denied.
  """
  def authorize!(%User{} = user, permission) do
    authorize!(user, permission, nil, %{})
  end

  def authorize!(%User{} = user, permission, resource) do
    authorize!(user, permission, resource, %{})
  end

  def authorize!(%User{} = user, permission, resource, context) do
    if can?(user, permission, resource, context) do
      :ok
    else
      raise TamanduaServer.Authorization.UnauthorizedError,
        user: user,
        permission: permission,
        resource: resource,
        reason: get_denial_reason(user, permission, resource, context)
    end
  end

  @doc """
  Get all effective permissions for a user.
  """
  def permissions_for(%User{} = user) do
    get_cached_permissions(user)
  end

  @doc """
  Get all roles for a user.
  """
  def roles_for(%User{} = user) do
    get_cached_roles(user)
  end

  @doc """
  Check if user has any of the given permissions.
  """
  def can_any?(%User{} = user, permissions) when is_list(permissions) do
    user_permissions = get_cached_permissions(user)
    Enum.any?(permissions, &(&1 in user_permissions))
  end

  @doc """
  Check if user has all of the given permissions.
  """
  def can_all?(%User{} = user, permissions) when is_list(permissions) do
    user_permissions = get_cached_permissions(user)
    Enum.all?(permissions, &(&1 in user_permissions))
  end

  @doc """
  Invalidate cache for a user.
  """
  def invalidate_cache(%User{id: user_id}) do
    GenServer.cast(__MODULE__, {:invalidate_user, user_id})
  end

  @doc """
  Invalidate all caches.
  """
  def invalidate_all_caches do
    GenServer.cast(__MODULE__, :invalidate_all)
  end

  @doc """
  Assign a role to a user.
  """
  def assign_role(%User{} = user, %Role{} = role, opts \\ []) do
    attrs = %{
      user_id: user.id,
      role_id: role.id,
      scope_type: opts[:scope_type],
      scope_id: opts[:scope_id],
      granted_by: opts[:granted_by],
      granted_at: DateTime.utc_now(),
      expires_at: opts[:expires_at]
    }

    case %UserRole{}
         |> UserRole.changeset(attrs)
         |> Repo.insert() do
      {:ok, user_role} ->
        invalidate_cache(user)
        {:ok, user_role}

      error ->
        error
    end
  end

  @doc """
  Remove a role from a user.
  """
  def revoke_role(%User{} = user, %Role{} = role, opts \\ []) do
    query =
      from ur in UserRole,
        where: ur.user_id == ^user.id and ur.role_id == ^role.id

    query =
      if opts[:scope_type] do
        from ur in query,
          where: ur.scope_type == ^opts[:scope_type] and ur.scope_id == ^opts[:scope_id]
      else
        query
      end

    case Repo.delete_all(query) do
      {count, _} when count > 0 ->
        invalidate_cache(user)
        {:ok, count}

      {0, _} ->
        {:error, :not_found}
    end
  end

  @doc """
  Create a custom role with permissions.
  """
  def create_role(attrs, permission_slugs) do
    Repo.transaction(fn ->
      with {:ok, role} <- %Role{} |> Role.changeset(attrs) |> Repo.insert(),
           :ok <- assign_permissions_to_role(role, permission_slugs) do
        role
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  @doc """
  Update role permissions.
  """
  def update_role_permissions(%Role{} = role, permission_slugs) do
    Repo.transaction(fn ->
      # Remove existing permissions
      from(rp in TamanduaServer.Accounts.RolePermission, where: rp.role_id == ^role.id)
      |> Repo.delete_all()

      # Add new permissions
      case assign_permissions_to_role(role, permission_slugs) do
        :ok ->
          invalidate_all_caches()
          role

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
  end

  # ==========================================================================
  # ABAC Policy Management
  # ==========================================================================

  @doc """
  Create an access policy with conditions.

  ## Example

      RBAC.create_access_policy(%{
        name: "Business Hours Only Response",
        organization_id: org.id,
        permission: :response_execute,
        conditions: %{
          time_restriction: %{
            type: :business_hours,
            timezone: "America/New_York",
            start_hour: 9,
            end_hour: 17,
            days: [1, 2, 3, 4, 5]  # Monday-Friday
          },
          ip_restriction: %{
            type: :cidr,
            allowed: ["10.0.0.0/8", "192.168.0.0/16"]
          }
        },
        effect: :allow,
        priority: 100
      })
  """
  def create_access_policy(attrs) do
    %AccessPolicy{}
    |> AccessPolicy.changeset(attrs)
    |> Repo.insert()
    |> tap(fn
      {:ok, _} -> invalidate_policy_cache()
      _ -> :ok
    end)
  end

  @doc """
  Update an existing access policy.
  """
  def update_access_policy(%AccessPolicy{} = policy, attrs) do
    policy
    |> AccessPolicy.changeset(attrs)
    |> Repo.update()
    |> tap(fn
      {:ok, _} -> invalidate_policy_cache()
      _ -> :ok
    end)
  end

  @doc """
  Delete an access policy.
  """
  def delete_access_policy(%AccessPolicy{} = policy) do
    Repo.delete(policy)
    |> tap(fn
      {:ok, _} -> invalidate_policy_cache()
      _ -> :ok
    end)
  end

  @doc """
  List access policies for an organization.
  """
  def list_access_policies(organization_id) do
    from(p in AccessPolicy,
      where: p.organization_id == ^organization_id or is_nil(p.organization_id),
      order_by: [desc: p.priority, asc: p.name]
    )
    |> Repo.all()
  end

  @doc """
  Get access policy by ID.
  """
  def get_access_policy(id) do
    Repo.get(AccessPolicy, id)
  end

  # ==========================================================================
  # Time-Based Access Control
  # ==========================================================================

  @doc """
  Check if current time is within allowed business hours.

  ## Options

  - `:timezone` - Timezone to use (default: "UTC")
  - `:start_hour` - Start of business hours (0-23, default: 9)
  - `:end_hour` - End of business hours (0-23, default: 17)
  - `:days` - Allowed days (1=Monday, 7=Sunday, default: [1,2,3,4,5])
  """
  def within_business_hours?(opts \\ []) do
    timezone = Keyword.get(opts, :timezone, "UTC")
    start_hour = Keyword.get(opts, :start_hour, 9)
    end_hour = Keyword.get(opts, :end_hour, 17)
    allowed_days = Keyword.get(opts, :days, [1, 2, 3, 4, 5])

    now = DateTime.utc_now()

    # Convert to local timezone if available
    local_time = case Calendar.get_time_zone_database().time_zone_database() do
      Tzdata.TimeZoneDatabase ->
        case DateTime.shift_zone(now, timezone) do
          {:ok, shifted} -> shifted
          _ -> now
        end
      _ -> now
    end

    day_of_week = Date.day_of_week(DateTime.to_date(local_time))
    hour = local_time.hour

    day_of_week in allowed_days and hour >= start_hour and hour < end_hour
  end

  @doc """
  Check if access is within a specified time window.
  """
  def within_time_window?(start_datetime, end_datetime) do
    now = DateTime.utc_now()
    DateTime.compare(now, start_datetime) != :lt and DateTime.compare(now, end_datetime) != :gt
  end

  # ==========================================================================
  # Location-Based Access Control
  # ==========================================================================

  @doc """
  Check if an IP address is within allowed CIDR ranges.

  ## Example

      RBAC.ip_allowed?("192.168.1.100", ["192.168.0.0/16", "10.0.0.0/8"])
  """
  def ip_allowed?(ip_address, allowed_cidrs) when is_binary(ip_address) and is_list(allowed_cidrs) do
    case :inet.parse_address(String.to_charlist(ip_address)) do
      {:ok, ip_tuple} ->
        Enum.any?(allowed_cidrs, fn cidr ->
          ip_in_cidr?(ip_tuple, cidr)
        end)

      _ ->
        false
    end
  end

  def ip_allowed?(_, _), do: false

  @doc """
  Check if an IP address is in a blocklist.
  """
  def ip_blocked?(ip_address, blocked_cidrs) when is_binary(ip_address) and is_list(blocked_cidrs) do
    ip_allowed?(ip_address, blocked_cidrs)
  end

  def ip_blocked?(_, _), do: false

  defp ip_in_cidr?(ip_tuple, cidr) when is_binary(cidr) do
    case String.split(cidr, "/") do
      [network_str, prefix_str] ->
        case {:inet.parse_address(String.to_charlist(network_str)), Integer.parse(prefix_str)} do
          {{:ok, network_tuple}, {prefix_len, ""}} ->
            ip_in_network?(ip_tuple, network_tuple, prefix_len)

          _ ->
            false
        end

      [ip_str] ->
        case :inet.parse_address(String.to_charlist(ip_str)) do
          {:ok, single_ip} -> ip_tuple == single_ip
          _ -> false
        end
    end
  end

  defp ip_in_network?(ip, network, prefix_len) when tuple_size(ip) == 4 and tuple_size(network) == 4 do
    # IPv4
    ip_int = ip_to_integer(ip)
    network_int = ip_to_integer(network)
    mask = bsl(0xFFFFFFFF, 32 - prefix_len) |> band(0xFFFFFFFF)

    band(ip_int, mask) == band(network_int, mask)
  end

  defp ip_in_network?(ip, network, prefix_len) when tuple_size(ip) == 8 and tuple_size(network) == 8 do
    # IPv6
    ip_int = ipv6_to_integer(ip)
    network_int = ipv6_to_integer(network)
    mask = bsl(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 128 - prefix_len)

    Bitwise.band(ip_int, mask) == Bitwise.band(network_int, mask)
  end

  defp ip_in_network?(_, _, _), do: false

  defp ip_to_integer({a, b, c, d}) do
    bsl(a, 24) + bsl(b, 16) + bsl(c, 8) + d
  end

  defp ipv6_to_integer({a, b, c, d, e, f, g, h}) do
    bsl(a, 112) + bsl(b, 96) + bsl(c, 80) + bsl(d, 64) +
    bsl(e, 48) + bsl(f, 32) + bsl(g, 16) + h
  end

  import Bitwise

  # ==========================================================================
  # Server Callbacks
  # ==========================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables for caching
    ensure_cache_tables()

    # Initialize builtin roles
    Task.start(fn -> initialize_builtin_roles() end)

    # Schedule periodic cache cleanup
    :timer.send_interval(60_000, :cleanup_expired)

    Logger.info("RBAC authorization service started with ABAC extensions")
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:invalidate_user, user_id}, state) do
    invalidate_user_entries(@cache_table, user_id)
    invalidate_user_entries(@role_cache_table, user_id)
    {:noreply, state}
  end

  @impl true
  def handle_cast(:invalidate_all, state) do
    safe_ets_delete_all(@cache_table)
    safe_ets_delete_all(@role_cache_table)
    safe_ets_delete_all(@policy_cache_table)
    {:noreply, state}
  end

  @impl true
  def handle_cast(:invalidate_policies, state) do
    safe_ets_delete_all(@policy_cache_table)
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_expired, state) do
    now = System.system_time(:second)

    # Clean expired cache entries
    [@cache_table, @role_cache_table, @policy_cache_table]
    |> Enum.each(fn table ->
      expired = safe_ets_foldl(
        fn
          {key, _data, cached_at}, acc when is_integer(cached_at) ->
            if now - cached_at > @cache_ttl_seconds, do: [key | acc], else: acc
          _, acc ->
            acc
        end,
        [],
        table
      )

      Enum.each(expired, &safe_ets_delete(table, &1))
    end)

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ==========================================================================
  # Private Functions
  # ==========================================================================

  defp ensure_cache_tables do
    ensure_cache_table(@cache_table)
    ensure_cache_table(@role_cache_table)
    ensure_cache_table(@policy_cache_table)
  end

  defp ensure_cache_table(table) do
    case :ets.whereis(table) do
      :undefined ->
        try do
          :ets.new(table, [:set, :public, :named_table, read_concurrency: true])
          :ok
        rescue
          ArgumentError ->
            # Another process may have created it between whereis/2 and new/2.
            :ok
        end

      _tid ->
        :ok
    end
  end

  defp safe_ets_lookup(table, key) do
    ensure_cache_table(table)
    :ets.lookup(table, key)
  rescue
    ArgumentError ->
      []
  end

  defp safe_ets_insert(table, record) do
    ensure_cache_table(table)
    :ets.insert(table, record)
  rescue
    ArgumentError ->
      false
  end

  defp safe_ets_delete(table, key) do
    ensure_cache_table(table)
    :ets.delete(table, key)
  rescue
    ArgumentError ->
      false
  end

  defp safe_ets_delete_all(table) do
    ensure_cache_table(table)
    :ets.delete_all_objects(table)
  rescue
    ArgumentError ->
      false
  end

  defp safe_ets_foldl(fun, acc, table) do
    ensure_cache_table(table)
    :ets.foldl(fun, acc, table)
  rescue
    ArgumentError ->
      acc
  end

  defp get_cached_permissions(%User{id: user_id, organization_id: organization_id} = user) do
    cache_key = {user_id, organization_id}

    case safe_ets_lookup(@cache_table, cache_key) do
      [{^cache_key, permissions, cached_at}] ->
        if System.system_time(:second) - cached_at < @cache_ttl_seconds do
          permissions
        else
          load_and_cache_permissions(user)
        end

      [] ->
        load_and_cache_permissions(user)
    end
  end

  defp get_cached_roles(%User{id: user_id, organization_id: organization_id} = user) do
    cache_key = {user_id, organization_id}

    case safe_ets_lookup(@role_cache_table, cache_key) do
      [{^cache_key, roles, cached_at}] ->
        if System.system_time(:second) - cached_at < @cache_ttl_seconds do
          roles
        else
          load_and_cache_roles(user)
        end

      [] ->
        load_and_cache_roles(user)
    end
  end

  defp load_and_cache_permissions(%User{id: user_id, organization_id: organization_id} = user) do
    permissions = compute_effective_permissions(user)
    cache_key = {user_id, organization_id}
    safe_ets_insert(@cache_table, {cache_key, permissions, System.system_time(:second)})
    permissions
  end

  defp load_and_cache_roles(%User{id: user_id, organization_id: organization_id} = user) do
    roles = load_user_roles(user)
    cache_key = {user_id, organization_id}
    safe_ets_insert(@role_cache_table, {cache_key, roles, System.system_time(:second)})
    roles
  end

  defp compute_effective_permissions(%User{} = user) do
    # Get all user roles (both organization-wide and global)
    roles = load_user_roles(user)

    # Aggregate permissions from all roles
    roles
    |> Enum.flat_map(fn role ->
      load_role_permissions(role)
    end)
    |> Enum.uniq()
  end

  defp load_user_roles(%User{id: user_id, organization_id: org_id}) do
    # Get roles assigned to user, filtering by organization and expiry
    now = DateTime.utc_now()

    from(ur in UserRole,
      join: r in Role,
      on: r.id == ur.role_id,
      where: ur.user_id == ^user_id,
      where: is_nil(ur.expires_at) or ur.expires_at > ^now,
      where: (r.builtin == true and is_nil(r.organization_id)) or r.organization_id == ^org_id,
      select: r,
      order_by: [desc: r.priority]
    )
    |> Repo.all()
  end

  defp invalidate_user_entries(table, user_id) do
    safe_ets_foldl(
      fn
        {{^user_id, _organization_id} = cache_key, _data, _cached_at}, keys ->
          [cache_key | keys]

        _, keys ->
          keys
      end,
      [],
      table
    )
    |> Enum.each(&safe_ets_delete(table, &1))
  end

  defp load_role_permissions(%Role{id: _role_id, slug: slug, builtin: true}) do
    # For builtin roles, use predefined permissions
    role_atom = String.to_atom(slug)
    Role.default_permissions(role_atom)
  end

  defp load_role_permissions(%Role{id: role_id}) do
    # For custom roles, load from database
    from(rp in TamanduaServer.Accounts.RolePermission,
      join: p in Permission, on: p.id == rp.permission_id,
      where: rp.role_id == ^role_id,
      select: p.slug
    )
    |> Repo.all()
    |> Enum.map(&String.to_atom/1)
  end

  defp check_resource_scope(%User{} = user, _permission, resource) do
    # Get user roles with their scopes
    roles_with_scopes =
      from(ur in UserRole,
        where: ur.user_id == ^user.id,
        select: {ur.scope_type, ur.scope_id}
      )
      |> Repo.all()

    # Check if any role scope matches the resource
    resource_type = get_resource_type(resource)
    resource_id = get_resource_id(resource)

    Enum.any?(roles_with_scopes, fn
      {nil, nil} -> true  # No scope = full access
      {^resource_type, ^resource_id} -> true
      _ -> false
    end)
  end

  defp get_resource_type(%{__struct__: module}) do
    module
    |> Module.split()
    |> List.last()
    |> Macro.underscore()
  end

  defp get_resource_type(_), do: nil

  defp get_resource_id(%{id: id}), do: id
  defp get_resource_id(_), do: nil

  # ==========================================================================
  # ABAC Policy Evaluation
  # ==========================================================================

  defp evaluate_abac_policies(%User{} = user, permission, resource, context) do
    # Get applicable policies
    policies = get_cached_policies(user.organization_id)

    # Filter policies that match the permission
    applicable = Enum.filter(policies, fn policy ->
      policy.permission == to_string(permission) or policy.permission == "*"
    end)

    # If no policies, default to allow (basic RBAC passed)
    if Enum.empty?(applicable) do
      # Still check resource scope if resource provided
      if resource do
        check_resource_scope(user, permission, resource)
      else
        true
      end
    else
      # Evaluate policies in priority order
      evaluate_policy_chain(applicable, user, permission, resource, context)
    end
  end

  defp evaluate_policy_chain(policies, user, permission, resource, context) do
    # Sort by priority (highest first)
    sorted = Enum.sort_by(policies, & &1.priority, :desc)

    # Find first matching policy
    result = Enum.reduce_while(sorted, :no_match, fn policy, _acc ->
      case evaluate_single_policy(policy, user, permission, resource, context) do
        {:match, :allow} -> {:halt, {:match, :allow}}
        {:match, :deny} -> {:halt, {:match, :deny}}
        :no_match -> {:cont, :no_match}
      end
    end)

    case result do
      {:match, :allow} -> true
      {:match, :deny} -> false
      :no_match -> true  # Default allow if no policy matches
    end
  end

  defp evaluate_single_policy(policy, user, _permission, _resource, context) do
    conditions = policy.conditions || %{}

    # Evaluate all conditions
    results = [
      evaluate_time_condition(conditions["time_restriction"]),
      evaluate_ip_condition(conditions["ip_restriction"], context[:ip_address]),
      evaluate_user_attribute_condition(conditions["user_attributes"], user),
      evaluate_device_condition(conditions["device_restriction"], context[:device_id]),
      evaluate_mfa_condition(conditions["require_mfa"], user, context)
    ]

    # All conditions must pass for policy to match
    all_passed = Enum.all?(results, fn
      :skip -> true
      true -> true
      false -> false
    end)

    if all_passed do
      {:match, policy.effect}
    else
      :no_match
    end
  end

  defp evaluate_time_condition(nil), do: :skip
  defp evaluate_time_condition(%{"type" => "business_hours"} = config) do
    within_business_hours?(
      timezone: config["timezone"] || "UTC",
      start_hour: config["start_hour"] || 9,
      end_hour: config["end_hour"] || 17,
      days: config["days"] || [1, 2, 3, 4, 5]
    )
  end
  defp evaluate_time_condition(%{"type" => "time_window"} = config) do
    with {:ok, start_dt, _} <- DateTime.from_iso8601(config["start"]),
         {:ok, end_dt, _} <- DateTime.from_iso8601(config["end"]) do
      within_time_window?(start_dt, end_dt)
    else
      _ -> true
    end
  end
  defp evaluate_time_condition(_), do: :skip

  defp evaluate_ip_condition(nil, _ip), do: :skip
  defp evaluate_ip_condition(_config, nil), do: :skip
  defp evaluate_ip_condition(%{"type" => "cidr", "allowed" => allowed}, ip) when is_list(allowed) do
    ip_allowed?(ip, allowed)
  end
  defp evaluate_ip_condition(%{"type" => "cidr", "blocked" => blocked}, ip) when is_list(blocked) do
    not ip_blocked?(ip, blocked)
  end
  defp evaluate_ip_condition(_, _), do: :skip

  defp evaluate_user_attribute_condition(nil, _user), do: :skip
  defp evaluate_user_attribute_condition(attrs, user) when is_map(attrs) do
    Enum.all?(attrs, fn {attr, expected} ->
      actual = Map.get(user, String.to_existing_atom(attr), nil)
      actual == expected
    end)
  rescue
    _ -> :skip
  end
  defp evaluate_user_attribute_condition(_, _), do: :skip

  defp evaluate_device_condition(nil, _device_id), do: :skip
  defp evaluate_device_condition(_config, nil), do: :skip
  defp evaluate_device_condition(%{"trusted_devices" => devices}, device_id) when is_list(devices) do
    device_id in devices
  end
  defp evaluate_device_condition(_, _), do: :skip

  defp evaluate_mfa_condition(nil, _user, _context), do: :skip
  defp evaluate_mfa_condition(true, user, _context) do
    user.mfa_enabled == true
  end
  defp evaluate_mfa_condition(_, _, _), do: :skip

  defp get_cached_policies(organization_id) do
    cache_key = {:org_policies, organization_id}

    case safe_ets_lookup(@policy_cache_table, cache_key) do
      [{^cache_key, policies, cached_at}] ->
        if System.system_time(:second) - cached_at < @cache_ttl_seconds do
          policies
        else
          load_and_cache_policies(organization_id)
        end

      [] ->
        load_and_cache_policies(organization_id)
    end
  end

  defp load_and_cache_policies(organization_id) do
    policies = list_access_policies(organization_id)
    cache_key = {:org_policies, organization_id}
    safe_ets_insert(@policy_cache_table, {cache_key, policies, System.system_time(:second)})
    policies
  end

  defp invalidate_policy_cache do
    GenServer.cast(__MODULE__, :invalidate_policies)
  end

  defp get_denial_reason(user, permission, resource, context) do
    # Analyze why access was denied
    permissions = get_cached_permissions(user)

    cond do
      permission not in permissions and :system_all not in permissions ->
        "User lacks required permission: #{permission}"

      resource != nil and not check_resource_scope(user, permission, resource) ->
        "User lacks access to the specified resource"

      true ->
        # Check ABAC conditions
        policies = get_cached_policies(user.organization_id)
        applicable = Enum.filter(policies, fn p ->
          p.permission == to_string(permission) or p.permission == "*"
        end)

        analyze_policy_failures(applicable, user, context)
    end
  end

  defp analyze_policy_failures(policies, user, context) do
    failures = Enum.flat_map(policies, fn policy ->
      conditions = policy.conditions || %{}

      [
        if not evaluate_time_condition(conditions["time_restriction"]) == true do
          "Access denied: Outside allowed time window"
        end,
        if not evaluate_ip_condition(conditions["ip_restriction"], context[:ip_address]) == true do
          "Access denied: IP address not in allowed range"
        end,
        if not evaluate_mfa_condition(conditions["require_mfa"], user, context) == true do
          "Access denied: MFA required but not enabled"
        end
      ]
      |> Enum.reject(&is_nil/1)
    end)

    case failures do
      [] -> "Access denied by policy"
      [reason | _] -> reason
    end
  end

  # ==========================================================================
  # Initialization
  # ==========================================================================

  defp initialize_builtin_roles do
    # Give the application time to initialize
    Process.sleep(1000)

    Enum.each(Role.builtin_roles(), fn role_slug ->
      # Check if role already exists (globally)
      unless Repo.exists?(from r in Role, where: r.slug == ^role_slug and r.builtin == true) do
        Logger.info("Creating builtin role: #{role_slug}")

        attrs = %{
          name: role_slug |> String.replace("_", " ") |> String.capitalize(),
          slug: role_slug,
          description: "Builtin #{role_slug} role",
          builtin: true,
          priority: role_priority(role_slug)
        }

        case %Role{} |> Role.changeset(attrs) |> Repo.insert() do
          {:ok, _role} ->
            Logger.info("Created builtin role: #{role_slug}")

          {:error, changeset} ->
            Logger.warning("Failed to create builtin role #{role_slug}: #{inspect(changeset.errors)}")
        end
      end
    end)
  end

  defp role_priority(slug) do
    case slug do
      "admin" -> 100
      "hunter" -> 80
      "responder" -> 70
      "analyst" -> 50
      "compliance_officer" -> 40
      "viewer" -> 10
      _ -> 0
    end
  end

  defp assign_permissions_to_role(%Role{id: role_id}, permission_slugs) do
    # Get or create permission records
    Enum.each(permission_slugs, fn slug ->
      slug_str = to_string(slug)

      permission =
        case Repo.get_by(Permission, slug: slug_str) do
          nil ->
            %Permission{}
            |> Permission.changeset(%{
              name: slug_str |> String.replace("_", " ") |> String.capitalize(),
              slug: slug_str,
              description: Permission.description(slug),
              category: permission_category(slug)
            })
            |> Repo.insert!()

          p ->
            p
        end

      # Create role-permission association
      %TamanduaServer.Accounts.RolePermission{}
      |> TamanduaServer.Accounts.RolePermission.changeset(%{
        role_id: role_id,
        permission_id: permission.id
      })
      |> Repo.insert(on_conflict: :nothing)
    end)

    :ok
  end

  defp permission_category(slug) when is_atom(slug) do
    # Extract category from permission slug
    slug
    |> Atom.to_string()
    |> String.split("_")
    |> List.first()
  end
end

defmodule TamanduaServer.Authorization.UnauthorizedError do
  @moduledoc """
  Exception raised when a user lacks required permissions.
  """

  defexception [:user, :permission, :resource, :reason, :message]

  @impl true
  def exception(opts) do
    user = opts[:user]
    permission = opts[:permission]
    resource = opts[:resource]
    reason = opts[:reason] || "Access denied"

    message =
      if resource do
        "User #{user.id} lacks permission '#{permission}' for resource #{inspect(resource)}: #{reason}"
      else
        "User #{user.id} lacks permission '#{permission}': #{reason}"
      end

    %__MODULE__{
      user: user,
      permission: permission,
      resource: resource,
      reason: reason,
      message: message
    }
  end
end
