defmodule TamanduaServer.EnrollmentLocatorAccess do
  @moduledoc """
  Narrow external authority facade for locating an installation token tenant.

  A successful lookup returns only the exact token ID and organization ID.
  Every configuration, identity, ACL, query, or result-shape failure is closed
  as persistence unavailable.
  """

  alias TamanduaServer.EnrollmentLocatorRepo

  @capability_role "tamandua_authority_enrollment_locator_v1_executor"
  @owner_role "tamandua_authority_enrollment_locator_v1_owner"
  @function_name "public.authority_enrollment_locator_v1"
  @function_signature "public.authority_enrollment_locator_v1(text)"
  @digest_regex ~r/^[0-9a-f]{64}$/

  @spec locate(String.t()) ::
          {:ok, Ecto.UUID.t(), Ecto.UUID.t()}
          | {:error, :not_found | :persistence_unavailable}
  def locate(digest) when is_binary(digest) do
    with true <- Regex.match?(@digest_regex, digest),
         :ok <- require_enabled(),
         {:ok, expected_role} <- expected_database_role(),
         {:ok, rows} <- execute(expected_role, digest) do
      validate_rows(rows)
    else
      false -> {:error, :not_found}
      {:error, :not_found} = error -> error
      _error -> {:error, :persistence_unavailable}
    end
  rescue
    _error -> {:error, :persistence_unavailable}
  catch
    :exit, _reason -> {:error, :persistence_unavailable}
  end

  def locate(_digest), do: {:error, :not_found}

  defp execute(expected_role, digest) do
    repo = authority_repo()

    case repo.transaction(fn ->
           with :ok <- preflight(repo, expected_role),
                {:ok, _result} <- repo.query("SET LOCAL ROLE #{@capability_role}"),
                {:ok, %{rows: rows}} <-
                  repo.query(
                    "SELECT token_id, organization_id FROM #{@function_name}($1)",
                    [digest]
                  ) do
             rows
           else
             _error -> repo.rollback(:enrollment_locator_failed)
           end
         end) do
      {:ok, rows} -> {:ok, rows}
      _error -> {:error, :persistence_unavailable}
    end
  end

  defp validate_rows([]), do: {:error, :not_found}

  defp validate_rows([[token_id, organization_id]]) do
    with {:ok, token_id} <- canonical_uuid(token_id),
         {:ok, organization_id} <- canonical_uuid(organization_id) do
      {:ok, token_id, organization_id}
    else
      _error -> {:error, :persistence_unavailable}
    end
  end

  defp validate_rows(_rows), do: {:error, :persistence_unavailable}

  defp canonical_uuid(value) do
    case Ecto.UUID.cast(value) do
      {:ok, canonical} -> {:ok, canonical}
      :error -> Ecto.UUID.load(value)
    end
  end

  defp preflight(repo, expected_role) do
    sql = """
    SELECT (
      session_user = $1
      AND current_user = session_user
      AND login_role.rolcanlogin
      AND NOT login_role.rolsuper
      AND NOT login_role.rolbypassrls
      AND NOT login_role.rolinherit
      AND NOT login_role.rolcreatedb
      AND NOT login_role.rolcreaterole
      AND NOT login_role.rolreplication
      AND login_role.rolconfig IS NULL
      AND NOT capability.rolcanlogin
      AND NOT capability.rolsuper
      AND NOT capability.rolbypassrls
      AND NOT capability.rolinherit
      AND NOT capability.rolcreatedb
      AND NOT capability.rolcreaterole
      AND NOT capability.rolreplication
      AND capability.rolconfig IS NULL
      AND NOT function_owner.rolcanlogin
      AND NOT function_owner.rolsuper
      AND NOT function_owner.rolbypassrls
      AND NOT function_owner.rolinherit
      AND NOT function_owner.rolcreatedb
      AND NOT function_owner.rolcreaterole
      AND NOT function_owner.rolreplication
      AND function_owner.rolconfig IS NULL
      AND EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members membership
        WHERE membership.roleid = capability.oid
          AND membership.member = login_role.oid
          AND NOT membership.admin_option
          AND NOT membership.inherit_option
          AND membership.set_option
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members membership
        WHERE (membership.member = login_role.oid AND membership.roleid <> capability.oid)
           OR membership.roleid = login_role.oid
           OR membership.member = capability.oid
           OR (membership.roleid = capability.oid AND membership.member <> login_role.oid)
           OR membership.member = function_owner.oid
           OR membership.roleid = function_owner.oid
      )
      AND NOT pg_catalog.has_schema_privilege(session_user, namespace.oid, 'CREATE')
      AND pg_catalog.has_schema_privilege(capability.oid, namespace.oid, 'USAGE')
      AND NOT pg_catalog.has_schema_privilege(capability.oid, namespace.oid, 'CREATE')
      AND pg_catalog.has_schema_privilege(function_owner.oid, namespace.oid, 'USAGE')
      AND NOT pg_catalog.has_schema_privilege(function_owner.oid, namespace.oid, 'CREATE')
      AND NOT pg_catalog.has_table_privilege(
        session_user, tokens.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      )
      AND NOT pg_catalog.has_any_column_privilege(
        session_user, tokens.oid, 'SELECT,INSERT,UPDATE,REFERENCES'
      )
      AND NOT pg_catalog.has_table_privilege(
        capability.oid, tokens.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      )
      AND NOT pg_catalog.has_any_column_privilege(
        capability.oid, tokens.oid, 'SELECT,INSERT,UPDATE,REFERENCES'
      )
      AND NOT pg_catalog.has_table_privilege(
        function_owner.oid, tokens.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      )
      AND NOT pg_catalog.has_any_column_privilege(
        function_owner.oid, tokens.oid, 'INSERT,UPDATE,REFERENCES'
      )
      AND pg_catalog.has_column_privilege(function_owner.oid, tokens.oid, 'id', 'SELECT')
      AND pg_catalog.has_column_privilege(function_owner.oid, tokens.oid, 'organization_id', 'SELECT')
      AND pg_catalog.has_column_privilege(function_owner.oid, tokens.oid, 'token_digest', 'SELECT')
      AND NOT pg_catalog.has_column_privilege(function_owner.oid, tokens.oid, 'token_hash', 'SELECT')
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute attribute
        WHERE attribute.attrelid = tokens.oid AND attribute.attnum > 0 AND NOT attribute.attisdropped
          AND attribute.attname NOT IN ('id', 'organization_id', 'token_digest')
          AND pg_catalog.has_column_privilege(
            function_owner.oid, tokens.oid, attribute.attname, 'SELECT'
          )
      )
      AND function_owner.rolname = $3
      AND authority_function.prosecdef
      AND authority_function.provolatile = 's'
      AND authority_function.proretset
      AND authority_function.prolang = (
        SELECT oid FROM pg_catalog.pg_language WHERE lanname = 'sql'
      )
      AND authority_function.proconfig @> ARRAY[
        'search_path=pg_catalog', 'app.rls_bypass=true'
      ]
      AND pg_catalog.array_length(authority_function.proconfig, 1) = 2
      AND NOT pg_catalog.has_function_privilege(session_user, authority_function.oid, 'EXECUTE')
      AND pg_catalog.has_function_privilege(capability.oid, authority_function.oid, 'EXECUTE')
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          COALESCE(authority_function.proacl, pg_catalog.acldefault('f', function_owner.oid))
        ) acl
        WHERE acl.privilege_type = 'EXECUTE'
          AND (acl.grantee NOT IN (function_owner.oid, capability.oid)
               OR (acl.grantee = capability.oid AND acl.is_grantable))
      )
    )
    FROM pg_catalog.pg_roles login_role
    JOIN pg_catalog.pg_roles capability ON capability.rolname = $2
    JOIN pg_catalog.pg_namespace namespace ON namespace.nspname = 'public'
    JOIN pg_catalog.pg_class tokens
      ON tokens.relnamespace = namespace.oid AND tokens.relname = 'installation_tokens'
    JOIN pg_catalog.pg_proc authority_function
      ON authority_function.oid = $4::pg_catalog.regprocedure
    JOIN pg_catalog.pg_roles function_owner ON function_owner.oid = authority_function.proowner
    WHERE login_role.rolname = session_user
    """

    case repo.query(sql, [
           expected_role,
           @capability_role,
           @owner_role,
           @function_signature
         ]) do
      {:ok, %{rows: [[true]]}} -> :ok
      _error -> {:error, :authority_identity_or_grant_preflight_failed}
    end
  end

  defp expected_database_role do
    case Application.get_env(:tamandua_server, :enrollment_locator_database_role) do
      role when is_binary(role) and byte_size(role) >= 1 and byte_size(role) <= 63 ->
        {:ok, role}

      _other ->
        {:error, :authority_database_role_unavailable}
    end
  end

  defp require_enabled do
    repo = authority_repo()
    if repo.enabled?(), do: :ok, else: {:error, :authority_repo_disabled}
  end

  defp authority_repo do
    Application.get_env(:tamandua_server, :enrollment_locator_repo, EnrollmentLocatorRepo)
  end
end
