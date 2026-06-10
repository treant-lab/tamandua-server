defmodule TamanduaServer.Accounts do
  @moduledoc """
  Context module for user accounts and authentication.
  """

  import Ecto.Query
  import Bitwise
  alias TamanduaServer.Repo
  alias Ecto.Multi
  alias TamanduaServer.Accounts.{User, Organization, WalletIdentity, WalletAuthEvent}

  # -------------------------------------------------------------------
  # Users
  # -------------------------------------------------------------------

  @doc """
  Get a user by ID.
  """
  def get_user(id) do
    Repo.get(User, id)
  end

  @doc """
  Get a user by email.
  """
  def get_user_by_email(email) do
    Repo.get_by(User, email: email)
  end

  @doc """
  Authenticate a user by email and password.
  """
  def authenticate_user(email, password) do
    case get_user_by_email(email) do
      nil ->
        # Prevent timing attacks
        Bcrypt.no_user_verify()
        {:error, :invalid_credentials}

      user ->
        if Bcrypt.verify_pass(password, user.password_hash) do
          {:ok, user}
        else
          {:error, :invalid_credentials}
        end
    end
  end

  @doc """
  Create a new user.
  """
  def create_user(attrs) do
    attrs = maybe_hash_password(attrs)

    %User{}
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Create a trial organization with the submitted user as the initial admin.

  After successful creation, this automatically provisions the organization
  with default resources (Sigma templates, etc.) via OrganizationSetup.
  """
  def register_organization_owner(user_attrs, org_attrs, wallet_attrs \\ nil) do
    alias TamanduaServer.Accounts.OrganizationSetup

    Multi.new()
    |> Multi.insert(:organization, Organization.changeset(%Organization{}, org_attrs))
    |> Multi.insert(:user, fn %{organization: org} ->
      user_attrs =
        user_attrs
        |> maybe_hash_password()
        |> Map.put("organization_id", org.id)
        |> Map.put("role", "admin")

      User.changeset(%User{}, user_attrs)
    end)
    |> maybe_link_wallet(wallet_attrs)
    |> Multi.run(:organization_setup, fn _repo, %{organization: org} ->
      OrganizationSetup.setup_new_organization(org)
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{user: user, organization: org}} -> {:ok, user, org}
      {:error, _step, changeset, _changes} -> {:error, changeset}
    end
  end

  @doc """
  Get the user linked to a verified Solana wallet.
  """
  def get_user_by_wallet_identity(chain, wallet_address) do
    WalletIdentity
    |> where([w], w.chain == ^chain and w.wallet_address == ^wallet_address)
    |> join(:inner, [w], u in assoc(w, :user))
    |> preload([w, u], user: u)
    |> Repo.one()
    |> case do
      nil -> nil
      identity -> identity.user
    end
  end

  @doc """
  Persist a verified wallet identity for a user.
  """
  def link_wallet_identity(%User{} = user, attrs) do
    attrs =
      attrs
      |> Map.put("user_id", user.id)
      |> Map.put_new("chain", "solana")
      |> Map.put_new("verified_at", DateTime.utc_now())

    %WalletIdentity{}
    |> WalletIdentity.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update the last-used timestamp for a wallet identity.
  """
  def touch_wallet_identity(chain, wallet_address) do
    from(w in WalletIdentity,
      where: w.chain == ^chain and w.wallet_address == ^wallet_address
    )
    |> Repo.update_all(set: [last_used_at: DateTime.utc_now()])
  end

  @doc """
  Write an audit record for wallet authentication.
  """
  def log_wallet_auth_event(attrs) do
    %WalletAuthEvent{}
    |> WalletAuthEvent.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a user.
  """
  def update_user(%User{} = user, attrs) do
    attrs = maybe_hash_password(attrs)

    user
    |> User.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a user.
  """
  def delete_user(%User{} = user) do
    Repo.delete(user)
  end

  @doc """
  List users in an organization.
  """
  def list_users(organization_id) do
    User
    |> where([u], u.organization_id == ^organization_id)
    |> order_by([u], [asc: u.email])
    |> Repo.all()
  end

  @doc """
  List all users (admin only).
  """
  def list_all_users(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    User
    |> order_by([u], [asc: u.email])
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Update last login timestamp.
  """
  def update_last_login(%User{} = user) do
    user
    |> Ecto.Changeset.change(last_login_at: DateTime.utc_now())
    |> Repo.update()
  end

  @doc """
  Change user password.
  """
  def change_password(%User{} = user, current_password, new_password) do
    if Bcrypt.verify_pass(current_password, user.password_hash) do
      update_user(user, %{password: new_password})
    else
      {:error, :invalid_current_password}
    end
  end

  # -------------------------------------------------------------------
  # Organizations
  # -------------------------------------------------------------------

  @doc """
  Get an organization by ID.
  """
  def get_organization(id) do
    Repo.get(Organization, id)
  end

  @doc """
  Get an organization by slug.
  """
  def get_organization_by_slug(slug) do
    Repo.get_by(Organization, slug: slug)
  end

  @doc """
  Create a new organization.

  After successful creation, this automatically provisions the organization
  with default resources (Sigma templates, settings, etc.) via
  `OrganizationSetup.setup_new_organization/1`.

  ## Options

  - `:skip_setup` - Skip post-creation setup (default: false)
  - `:skip_sigma_templates` - Skip copying Sigma templates (default: false)

  ## Examples

      iex> create_organization(%{name: "ACME Corp", slug: "acme-corp"})
      {:ok, %Organization{}}

      iex> create_organization(%{name: "Test Org", slug: "test"}, skip_setup: true)
      {:ok, %Organization{}}
  """
  def create_organization(attrs, opts \\ []) do
    skip_setup = Keyword.get(opts, :skip_setup, false)

    with {:ok, org} <- do_create_organization(attrs),
         {:ok, org} <- maybe_run_setup(org, skip_setup, opts) do
      {:ok, org}
    end
  end

  defp do_create_organization(attrs) do
    %Organization{}
    |> Organization.changeset(attrs)
    |> Repo.insert()
  end

  defp maybe_run_setup(org, true = _skip, _opts), do: {:ok, org}

  defp maybe_run_setup(org, false = _skip, opts) do
    alias TamanduaServer.Accounts.OrganizationSetup
    OrganizationSetup.setup_new_organization(org, opts)
  end

  @doc """
  Update an organization.
  """
  def update_organization(%Organization{} = org, attrs) do
    org
    |> Organization.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  List all organizations.
  """
  def list_organizations do
    Organization
    |> order_by([o], [asc: o.name])
    |> Repo.all()
  end

  # -------------------------------------------------------------------
  # MFA
  # -------------------------------------------------------------------

  # TOTP configuration
  @totp_time_step 30
  @totp_digits 6
  # Allow 1 step tolerance: previous, current, and next time step
  @totp_tolerance 1
  # Rate limiting: max 5 failed attempts per 5-minute window
  @totp_rate_limit_window 300
  @totp_rate_limit_max_attempts 5
  @totp_rate_limit_table :totp_rate_limits

  @doc """
  Generate MFA secret for a user.

  Returns a 160-bit (20-byte) random secret, Base32-encoded (no padding),
  suitable for use with standard TOTP authenticator apps.
  Also returns a provisioning URI for QR code generation.
  """
  def generate_mfa_secret(%User{} = user) do
    secret = :crypto.strong_rand_bytes(20) |> Base.encode32(padding: false)

    case update_user(user, %{mfa_secret: secret}) do
      {:ok, updated_user} ->
        # Build otpauth:// URI for QR code generation in authenticator apps
        issuer = "Tamandua"
        label = URI.encode(user.email || "user")
        encoded_issuer = URI.encode(issuer)
        uri = "otpauth://totp/#{encoded_issuer}:#{label}?secret=#{secret}&issuer=#{encoded_issuer}&digits=#{@totp_digits}&period=#{@totp_time_step}"

        {:ok, updated_user, %{secret: secret, provisioning_uri: uri}}

      error ->
        error
    end
  end

  @doc """
  Enable MFA for a user (after verifying TOTP).
  """
  def enable_mfa(%User{} = user, totp_code) do
    if verify_totp(user.mfa_secret, totp_code) do
      update_user(user, %{mfa_enabled: true})
    else
      {:error, :invalid_totp}
    end
  end

  @doc """
  Verify TOTP code with rate limiting and time-step tolerance.

  Implements RFC 6238 TOTP with:
  - HMAC-SHA1 based one-time password
  - 30-second time step
  - 6-digit codes
  - 1 step tolerance (checks previous, current, and next time step)
  - Rate limiting: max #{@totp_rate_limit_max_attempts} attempts per #{@totp_rate_limit_window} seconds
  """
  def verify_totp(secret, code) when is_binary(secret) and is_binary(code) do
    # Rate limit check using secret as the key (to prevent brute force)
    rate_key = :crypto.hash(:sha256, secret) |> Base.encode16()

    case check_totp_rate_limit(rate_key) do
      :ok ->
        current_time = System.system_time(:second)
        current_step = div(current_time, @totp_time_step)

        # Check current step and +/- tolerance steps
        matched = Enum.any?(
          (current_step - @totp_tolerance)..(current_step + @totp_tolerance),
          fn step ->
            expected = generate_totp_at_step(secret, step)
            Plug.Crypto.secure_compare(expected, code)
          end
        )

        unless matched do
          record_totp_failure(rate_key)
        end

        matched

      {:error, :rate_limited} ->
        false
    end
  rescue
    _ -> false
  end

  def verify_totp(_, _), do: false

  # -------------------------------------------------------------------
  # Session Tokens (in-memory for now - use DB in production)
  # -------------------------------------------------------------------

  # Simple in-memory token storage
  # In production, use a proper UserToken schema with database
  @session_tokens_table :user_session_tokens
  @api_tokens_table :user_api_tokens

  @doc """
  Generate a session token for a user.
  """
  def generate_user_session_token(%User{} = user) do
    token = :crypto.strong_rand_bytes(32) |> Base.url_encode64()
    ensure_token_table(@session_tokens_table)
    :ets.insert(@session_tokens_table, {token, user.id, DateTime.utc_now()})
    token
  end

  @doc """
  Get a user by session token.
  """
  def get_user_by_session_token(token) when is_binary(token) do
    ensure_token_table(@session_tokens_table)

    case :ets.lookup(@session_tokens_table, token) do
      [{^token, user_id, _created_at}] ->
        get_user(user_id)

      [] ->
        nil
    end
  end

  def get_user_by_session_token(_), do: nil

  @doc """
  Delete a session token.
  """
  def delete_user_session_token(token) when is_binary(token) do
    ensure_token_table(@session_tokens_table)
    :ets.delete(@session_tokens_table, token)
    :ok
  end

  def delete_user_session_token(_), do: :ok

  @doc """
  Get a user by API token.
  """
  def get_user_by_api_token(token) when is_binary(token) do
    ensure_token_table(@api_tokens_table)

    case :ets.lookup(@api_tokens_table, token) do
      [{^token, user_id, _created_at}] ->
        get_user(user_id)

      [] ->
        nil
    end
  end

  def get_user_by_api_token(_), do: nil

  @doc """
  Revoke an API token.
  """
  def revoke_api_token(token) when is_binary(token) do
    ensure_token_table(@api_tokens_table)
    :ets.delete(@api_tokens_table, token)
    :ok
  end

  def revoke_api_token(_), do: :ok

  @doc """
  Generate an API token for a user.
  """
  def generate_api_token(%User{} = user) do
    token = :crypto.strong_rand_bytes(32) |> Base.url_encode64()
    ensure_token_table(@api_tokens_table)
    :ets.insert(@api_tokens_table, {token, user.id, DateTime.utc_now()})
    token
  end

  defp ensure_token_table(table) do
    case :ets.whereis(table) do
      :undefined ->
        :ets.new(table, [:set, :public, :named_table])

      _ ->
        :ok
    end
  end

  # -------------------------------------------------------------------
  # Private helpers
  # -------------------------------------------------------------------

  defp maybe_hash_password(%{password: password} = attrs) when is_binary(password) do
    attrs
    |> Map.delete(:password)
    |> Map.put(:password_hash, Bcrypt.hash_pwd_salt(password))
  end

  defp maybe_hash_password(%{"password" => password} = attrs) when is_binary(password) do
    attrs
    |> Map.delete("password")
    |> Map.put("password_hash", Bcrypt.hash_pwd_salt(password))
  end

  defp maybe_hash_password(attrs), do: attrs

  defp maybe_link_wallet(multi, nil), do: multi
  defp maybe_link_wallet(multi, %{} = wallet_attrs) when map_size(wallet_attrs) == 0, do: multi

  defp maybe_link_wallet(multi, wallet_attrs) do
    Multi.insert(multi, :wallet_identity, fn %{user: user} ->
      wallet_attrs =
        wallet_attrs
        |> Map.put("user_id", user.id)
        |> Map.put_new("chain", "solana")
        |> Map.put_new("verified_at", DateTime.utc_now())

      WalletIdentity.changeset(%WalletIdentity{}, wallet_attrs)
    end)
  end

  # RFC 6238 TOTP generation at a specific time step
  defp generate_totp_at_step(secret, step) do
    # Encode the time step as a big-endian 64-bit integer
    msg = <<step::unsigned-big-integer-size(64)>>

    # Decode the Base32-encoded shared secret
    decoded_secret = case Base.decode32(secret, padding: false) do
      {:ok, decoded} -> decoded
      :error -> Base.decode32!(secret)
    end

    # Compute HMAC-SHA1
    hmac = :crypto.mac(:hmac, :sha, decoded_secret, msg)

    # Dynamic truncation (RFC 4226, Section 5.4)
    offset = :binary.at(hmac, 19) &&& 0x0F

    <<_::binary-size(offset), code::unsigned-big-integer-size(32), _::binary>> = hmac
    code = (code &&& 0x7FFFFFFF) |> rem(round(:math.pow(10, @totp_digits)))

    String.pad_leading(Integer.to_string(code), @totp_digits, "0")
  end

  # Rate limiting for TOTP verification attempts
  defp ensure_totp_rate_table do
    case :ets.whereis(@totp_rate_limit_table) do
      :undefined ->
        :ets.new(@totp_rate_limit_table, [:set, :public, :named_table])
      _ ->
        :ok
    end
  end

  defp check_totp_rate_limit(rate_key) do
    ensure_totp_rate_table()
    now = System.system_time(:second)

    case :ets.lookup(@totp_rate_limit_table, rate_key) do
      [{^rate_key, attempts, window_start}] ->
        if now - window_start > @totp_rate_limit_window do
          # Window expired, reset
          :ets.delete(@totp_rate_limit_table, rate_key)
          :ok
        else
          if attempts >= @totp_rate_limit_max_attempts do
            {:error, :rate_limited}
          else
            :ok
          end
        end

      [] ->
        :ok
    end
  end

  defp record_totp_failure(rate_key) do
    ensure_totp_rate_table()
    now = System.system_time(:second)

    case :ets.lookup(@totp_rate_limit_table, rate_key) do
      [{^rate_key, attempts, window_start}] ->
        if now - window_start > @totp_rate_limit_window do
          # Window expired, start new window
          :ets.insert(@totp_rate_limit_table, {rate_key, 1, now})
        else
          :ets.insert(@totp_rate_limit_table, {rate_key, attempts + 1, window_start})
        end

      [] ->
        :ets.insert(@totp_rate_limit_table, {rate_key, 1, now})
    end
  end

  # -------------------------------------------------------------------
  # RBAC - Role-Based Access Control
  # -------------------------------------------------------------------

  alias TamanduaServer.Accounts.{Role, UserRole, RBACAuditLog}
  alias TamanduaServer.Authorization.RBAC

  @doc """
  Get a user with preloaded roles.
  """
  def get_user_with_roles(id) do
    User
    |> Repo.get(id)
    |> Repo.preload(roles: from(r in Role, order_by: [desc: r.priority]))
  end

  @doc """
  List all users in an organization with their roles.
  """
  def list_users_with_roles(organization_id) do
    roles_query = from(r in Role, order_by: [desc: r.priority])

    User
    |> where([u], u.organization_id == ^organization_id)
    |> order_by([u], [asc: u.email])
    |> preload(roles: ^roles_query)
    |> Repo.all()
  end

  @doc """
  Assign a role to a user with audit logging.
  """
  def assign_role_to_user(user, role, opts \\ []) do
    actor = opts[:actor]
    org_id = user.organization_id

    case RBAC.assign_role(user, role, opts) do
      {:ok, user_role} ->
        # Log the assignment
        RBACAuditLog.log_role_assigned(org_id, actor, user, role, opts)
        {:ok, user_role}

      error ->
        error
    end
  end

  @doc """
  Revoke a role from a user with audit logging.
  """
  def revoke_role_from_user(user, role, opts \\ []) do
    actor = opts[:actor]
    org_id = user.organization_id

    case RBAC.revoke_role(user, role, opts) do
      {:ok, count} ->
        # Log the revocation
        RBACAuditLog.log_role_revoked(org_id, actor, user, role, opts)
        {:ok, count}

      error ->
        error
    end
  end

  @doc """
  Get all roles for a user.
  """
  def get_user_roles(user) do
    RBAC.roles_for(user)
  end

  @doc """
  Get all permissions for a user.
  """
  def get_user_permissions(user) do
    RBAC.permissions_for(user)
  end

  @doc """
  Check if a user has a specific permission.
  """
  def user_can?(user, permission) do
    RBAC.can?(user, permission)
  end

  @doc """
  Check if a user has any of the specified permissions.
  """
  def user_can_any?(user, permissions) do
    RBAC.can_any?(user, permissions)
  end

  # -------------------------------------------------------------------
  # Organization Management
  # -------------------------------------------------------------------

  @doc """
  Get organization with agent count for usage tracking.
  """
  def get_organization_with_usage(id) do
    case Repo.get(Organization, id) do
      nil ->
        nil

      org ->
        agent_count =
          from(a in TamanduaServer.Agents.Agent,
            where: a.organization_id == ^id,
            select: count()
          )
          |> Repo.one()

        %{
          organization: org,
          agent_count: agent_count,
          can_add_agents: Organization.can_add_agent?(org, agent_count)
        }
    end
  end

  @doc """
  Check if organization can add more agents.
  """
  def can_add_agent?(organization_id) do
    case get_organization_with_usage(organization_id) do
      nil -> false
      %{can_add_agents: can_add} -> can_add
    end
  end

  @doc """
  Delete an organization and all associated data.

  WARNING: This is a destructive operation. Consider deactivating instead.
  """
  def delete_organization(%Organization{} = org) do
    # This will cascade delete due to foreign key constraints
    Repo.delete(org)
  end

  @doc """
  Deactivate an organization (soft delete).
  """
  def deactivate_organization(%Organization{} = org) do
    org
    |> Ecto.Changeset.change(is_active: false)
    |> Repo.update()
  end

  @doc """
  Reactivate a deactivated organization.
  """
  def reactivate_organization(%Organization{} = org) do
    org
    |> Ecto.Changeset.change(is_active: true)
    |> Repo.update()
  end

  @doc """
  Update organization license tier.
  """
  def update_organization_license(%Organization{} = org, attrs) do
    org
    |> Organization.license_changeset(attrs)
    |> Repo.update()
  end

  # -------------------------------------------------------------------
  # RBAC Audit Log
  # -------------------------------------------------------------------

  @doc """
  Get RBAC audit log entries for an organization.
  """
  def list_rbac_audit_log(organization_id, opts \\ []) do
    RBACAuditLog.list_for_organization(organization_id, opts)
  end

  @doc """
  Get RBAC audit log entries for a specific user.
  """
  def list_rbac_audit_log_for_user(organization_id, user_id, opts \\ []) do
    RBACAuditLog.list_for_user(organization_id, user_id, opts)
  end

  @doc """
  Count RBAC audit log entries for an organization.
  """
  def count_rbac_audit_log(organization_id, opts \\ []) do
    RBACAuditLog.count_for_organization(organization_id, opts)
  end

  # -------------------------------------------------------------------
  # Roles Management
  # -------------------------------------------------------------------

  @doc """
  Get a role by ID.
  """
  def get_role(id) do
    Repo.get(Role, id)
  end

  @doc """
  Get a role by slug within an organization.
  """
  def get_role_by_slug(organization_id, slug) do
    from(r in Role,
      where: r.slug == ^slug,
      where: is_nil(r.organization_id) or r.organization_id == ^organization_id
    )
    |> Repo.one()
  end

  @doc """
  Get a role with permissions preloaded.
  """
  def get_role_with_permissions(id) do
    Role
    |> Repo.get(id)
    |> Repo.preload(:permissions)
  end

  @doc """
  List all roles for an organization (including global builtin roles).
  """
  def list_roles(organization_id) do
    from(r in Role,
      where: is_nil(r.organization_id) or r.organization_id == ^organization_id,
      order_by: [desc: r.priority, asc: r.name]
    )
    |> Repo.all()
  end

  @doc """
  List roles with user counts.
  """
  def list_roles_with_user_counts(organization_id) do
    from(r in Role,
      left_join: ur in UserRole,
      on: ur.role_id == r.id,
      left_join: rp in TamanduaServer.Accounts.RolePermission,
      on: rp.role_id == r.id,
      where: is_nil(r.organization_id) or r.organization_id == ^organization_id,
      group_by: r.id,
      select: %{
        r
        | user_count: count(ur.id, :distinct),
          permission_count: count(rp.id, :distinct)
      },
      order_by: [desc: r.priority, asc: r.name]
    )
    |> Repo.all()
  end

  @doc """
  Create a role.
  """
  def create_role(attrs) do
    %Role{}
    |> Role.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a role.
  """
  def update_role(%Role{} = role, attrs) do
    role
    |> Role.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a role with audit logging.
  """
  def delete_role(%Role{} = role, opts \\ []) do
    actor = opts[:actor]
    org_id = role.organization_id

    case Repo.delete(role) do
      {:ok, deleted_role} ->
        if org_id do
          RBACAuditLog.log_role_deleted(org_id, actor, deleted_role, opts)
        end

        {:ok, deleted_role}

      error ->
        error
    end
  end

  @doc """
  Get permissions for a role (from database for custom roles).
  """
  def get_role_permissions(%Role{builtin: true, slug: slug}) do
    Role.default_permissions(String.to_atom(slug))
  end

  def get_role_permissions(%Role{id: role_id}) do
    from(rp in TamanduaServer.Accounts.RolePermission,
      join: p in Permission,
      on: p.id == rp.permission_id,
      where: rp.role_id == ^role_id,
      select: p.slug
    )
    |> Repo.all()
    |> Enum.map(&String.to_atom/1)
  end
end
