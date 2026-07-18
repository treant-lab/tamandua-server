defmodule TamanduaServer.AuthorityAccess do
  @moduledoc """
  Bounded facade for the separate authority database identity.

  This foundation exposes one read-only capability: discover organizations
  whose screen-capture artifacts, evidence exports, or evidence diffs are due
  for tenant-scoped retention processing. It performs no retention mutation
  and exposes no arbitrary query callback.
  """

  alias TamanduaServer.AuthorityRepo

  @capability_role "tamandua_authority_retention_executor"
  @owner_role "tamandua_authority_retention_owner"
  @function_name "public.authority_screen_evidence_retention_due_organization_ids"
  @function_signature "public.authority_screen_evidence_retention_due_organization_ids(timestamp with time zone,integer)"
  @maximum_limit 1_000

  def startup_preflight do
    with :ok <- require_enabled(),
         {:ok, expected_role} <- expected_database_role() do
      transaction(fn ->
        with :ok <- preflight(expected_role),
             {:ok, _result} <- AuthorityRepo.query("SET LOCAL ROLE #{@capability_role}"),
             {:ok, %{rows: [[@capability_role, true, true]]}} <-
               AuthorityRepo.query(
                 "SELECT current_user, pg_catalog.has_function_privilege(current_user, $1::pg_catalog.regprocedure, 'EXECUTE'), pg_catalog.has_schema_privilege(current_user, 'public', 'USAGE')",
                 [@function_signature]
               ) do
          :ok
        else
          _other -> AuthorityRepo.rollback(:authority_identity_or_grant_preflight_failed)
        end
      end)
      |> normalize_transaction_result()
    end
  end

  def discover_screen_evidence_retention_due_organization_ids(as_of, limit \\ 100)

  def discover_screen_evidence_retention_due_organization_ids(%DateTime{} = as_of, limit)
      when is_integer(limit) and limit > 0 and limit <= @maximum_limit do
    with :ok <- require_enabled(),
         {:ok, expected_role} <- expected_database_role() do
      transaction(fn ->
        with :ok <- preflight(expected_role),
             {:ok, _result} <- AuthorityRepo.query("SET LOCAL ROLE #{@capability_role}"),
             {:ok, %{rows: rows}} <-
               AuthorityRepo.query(
                 "SELECT organization_id FROM #{@function_name}($1, $2)",
                 [as_of, limit]
               ) do
          Enum.map(rows, fn [organization_id] -> organization_id end)
        else
          _other -> AuthorityRepo.rollback(:authority_retention_discovery_failed)
        end
      end)
      |> normalize_transaction_result()
    end
  end

  def discover_screen_evidence_retention_due_organization_ids(_as_of, _limit),
    do: {:error, :invalid_retention_discovery_request}

  defp preflight(expected_role) do
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
      AND EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members capability_membership
        WHERE capability_membership.roleid = capability.oid
          AND capability_membership.member = login_role.oid
          AND NOT capability_membership.admin_option
          AND NOT capability_membership.inherit_option
          AND capability_membership.set_option
      )
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members capability_membership
        WHERE capability_membership.roleid = capability.oid
          AND capability_membership.member <> login_role.oid
      )
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members login_membership
        WHERE (login_membership.member = login_role.oid
               AND login_membership.roleid <> capability.oid)
           OR login_membership.roleid = login_role.oid
           OR login_membership.member = capability.oid
      )
      AND NOT pg_catalog.has_schema_privilege(session_user, namespace.oid, 'CREATE')
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
        ) schema_acl
        WHERE schema_acl.grantee = 0 AND schema_acl.privilege_type = 'USAGE'
      )
      AND pg_catalog.has_schema_privilege(capability.oid, namespace.oid, 'USAGE')
      AND NOT pg_catalog.has_schema_privilege(capability.oid, namespace.oid, 'CREATE')
      AND EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
        ) schema_acl
        WHERE schema_acl.grantee = capability.oid
          AND schema_acl.privilege_type = 'USAGE'
          AND NOT schema_acl.is_grantable
      )
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
        ) schema_acl
        WHERE schema_acl.grantee = capability.oid
          AND (schema_acl.privilege_type <> 'USAGE' OR schema_acl.is_grantable)
      )
      AND NOT pg_catalog.has_table_privilege(session_user, artifacts.oid, 'SELECT')
      AND NOT pg_catalog.has_table_privilege(session_user, artifacts.oid, 'INSERT')
      AND NOT pg_catalog.has_table_privilege(session_user, artifacts.oid, 'UPDATE')
      AND NOT pg_catalog.has_table_privilege(session_user, artifacts.oid, 'DELETE')
      AND NOT pg_catalog.has_table_privilege(session_user, artifacts.oid, 'TRUNCATE')
      AND NOT pg_catalog.has_table_privilege(session_user, artifacts.oid, 'REFERENCES')
      AND NOT pg_catalog.has_table_privilege(session_user, artifacts.oid, 'TRIGGER')
      AND NOT pg_catalog.has_table_privilege(session_user, exports.oid, 'SELECT')
      AND NOT pg_catalog.has_table_privilege(session_user, exports.oid, 'INSERT')
      AND NOT pg_catalog.has_table_privilege(session_user, exports.oid, 'UPDATE')
      AND NOT pg_catalog.has_table_privilege(session_user, exports.oid, 'DELETE')
      AND NOT pg_catalog.has_table_privilege(session_user, exports.oid, 'TRUNCATE')
      AND NOT pg_catalog.has_table_privilege(session_user, exports.oid, 'REFERENCES')
      AND NOT pg_catalog.has_table_privilege(session_user, exports.oid, 'TRIGGER')
      AND NOT pg_catalog.has_table_privilege(session_user, diffs.oid, 'SELECT')
      AND NOT pg_catalog.has_table_privilege(session_user, diffs.oid, 'INSERT')
      AND NOT pg_catalog.has_table_privilege(session_user, diffs.oid, 'UPDATE')
      AND NOT pg_catalog.has_table_privilege(session_user, diffs.oid, 'DELETE')
      AND NOT pg_catalog.has_table_privilege(session_user, diffs.oid, 'TRUNCATE')
      AND NOT pg_catalog.has_table_privilege(session_user, diffs.oid, 'REFERENCES')
      AND NOT pg_catalog.has_table_privilege(session_user, diffs.oid, 'TRIGGER')
      AND namespace_owner.rolname <> session_user
      AND artifact_owner.rolname <> session_user
      AND export_owner.rolname <> session_user
      AND diff_owner.rolname <> session_user
      AND function_owner.rolname = $3
      AND function_owner.rolname <> session_user
      AND NOT capability.rolcanlogin
      AND NOT capability.rolsuper
      AND NOT capability.rolbypassrls
      AND NOT capability.rolinherit
      AND NOT capability.rolcreatedb
      AND NOT capability.rolcreaterole
      AND NOT capability.rolreplication
      AND NOT function_owner.rolcanlogin
      AND NOT function_owner.rolsuper
      AND NOT function_owner.rolbypassrls
      AND NOT function_owner.rolinherit
      AND NOT function_owner.rolcreatedb
      AND NOT function_owner.rolcreaterole
      AND NOT function_owner.rolreplication
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members owner_membership
        WHERE owner_membership.roleid = function_owner.oid
           OR owner_membership.member = function_owner.oid
      )
      AND authority_function.prosecdef
      AND authority_function.provolatile = 's'
      AND authority_function.proretset
      AND authority_function.prorettype = 'uuid'::pg_catalog.regtype
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
          COALESCE(
            authority_function.proacl,
            pg_catalog.acldefault('f', authority_function.proowner)
          )
        ) function_acl
        WHERE function_acl.privilege_type = 'EXECUTE'
          AND (function_acl.grantee NOT IN (function_owner.oid, capability.oid)
               OR (function_acl.grantee = capability.oid AND function_acl.is_grantable))
      )
      AND EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          COALESCE(
            authority_function.proacl,
            pg_catalog.acldefault('f', authority_function.proowner)
          )
        ) function_acl
        WHERE function_acl.grantee = capability.oid
          AND function_acl.privilege_type = 'EXECUTE'
          AND NOT function_acl.is_grantable
      )
      AND pg_catalog.has_table_privilege(function_owner.oid, artifacts.oid, 'SELECT')
      AND EXISTS (
        SELECT 1 FROM pg_catalog.aclexplode(artifacts.relacl) artifact_acl
        WHERE artifact_acl.grantee = function_owner.oid
          AND artifact_acl.privilege_type = 'SELECT' AND NOT artifact_acl.is_grantable
      )
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, artifacts.oid, 'INSERT')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, artifacts.oid, 'UPDATE')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, artifacts.oid, 'DELETE')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, artifacts.oid, 'TRUNCATE')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, artifacts.oid, 'REFERENCES')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, artifacts.oid, 'TRIGGER')
      AND pg_catalog.has_table_privilege(function_owner.oid, exports.oid, 'SELECT')
      AND EXISTS (
        SELECT 1 FROM pg_catalog.aclexplode(exports.relacl) export_acl
        WHERE export_acl.grantee = function_owner.oid
          AND export_acl.privilege_type = 'SELECT' AND NOT export_acl.is_grantable
      )
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, exports.oid, 'INSERT')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, exports.oid, 'UPDATE')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, exports.oid, 'DELETE')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, exports.oid, 'TRUNCATE')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, exports.oid, 'REFERENCES')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, exports.oid, 'TRIGGER')
      AND pg_catalog.has_table_privilege(function_owner.oid, diffs.oid, 'SELECT')
      AND EXISTS (
        SELECT 1 FROM pg_catalog.aclexplode(diffs.relacl) diff_acl
        WHERE diff_acl.grantee = function_owner.oid
          AND diff_acl.privilege_type = 'SELECT' AND NOT diff_acl.is_grantable
      )
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, diffs.oid, 'INSERT')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, diffs.oid, 'UPDATE')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, diffs.oid, 'DELETE')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, diffs.oid, 'TRUNCATE')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, diffs.oid, 'REFERENCES')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, diffs.oid, 'TRIGGER')
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles reachable_role
        WHERE reachable_role.oid NOT IN (login_role.oid, capability.oid)
          AND (
            pg_catalog.pg_has_role(login_role.oid, reachable_role.oid, 'MEMBER')
            OR pg_catalog.pg_has_role(capability.oid, reachable_role.oid, 'MEMBER')
          )
      )
    )
    FROM pg_catalog.pg_roles login_role
    JOIN pg_catalog.pg_roles capability ON capability.rolname = $2
    JOIN pg_catalog.pg_namespace namespace ON namespace.nspname = 'public'
    JOIN pg_catalog.pg_roles namespace_owner ON namespace_owner.oid = namespace.nspowner
    JOIN pg_catalog.pg_class artifacts ON artifacts.relnamespace = namespace.oid AND artifacts.relname = 'screen_capture_artifacts'
    JOIN pg_catalog.pg_roles artifact_owner ON artifact_owner.oid = artifacts.relowner
    JOIN pg_catalog.pg_class exports ON exports.relnamespace = namespace.oid AND exports.relname = 'evidence_session_exports'
    JOIN pg_catalog.pg_roles export_owner ON export_owner.oid = exports.relowner
    JOIN pg_catalog.pg_class diffs ON diffs.relnamespace = namespace.oid AND diffs.relname = 'evidence_session_diffs'
    JOIN pg_catalog.pg_roles diff_owner ON diff_owner.oid = diffs.relowner
    JOIN pg_catalog.pg_proc authority_function ON authority_function.oid = $4::pg_catalog.regprocedure
    JOIN pg_catalog.pg_roles function_owner ON function_owner.oid = authority_function.proowner
    WHERE login_role.rolname = session_user
    """

    case AuthorityRepo.query(sql, [
           expected_role,
           @capability_role,
           @owner_role,
           @function_signature
         ]) do
      {:ok, %{rows: [[true]]}} -> :ok
      _other -> {:error, :authority_identity_or_grant_preflight_failed}
    end
  end

  defp transaction(fun) do
    AuthorityRepo.transaction(fun)
  catch
    :exit, _reason -> {:error, :authority_repository_unavailable}
  end

  defp normalize_transaction_result({:ok, result}), do: result
  defp normalize_transaction_result({:error, reason}), do: {:error, reason}

  defp expected_database_role do
    case Application.get_env(:tamandua_server, :authority_database_role) do
      role when is_binary(role) and byte_size(role) > 0 and byte_size(role) <= 63 -> {:ok, role}
      _other -> {:error, :authority_database_role_unavailable}
    end
  end

  defp require_enabled do
    if AuthorityRepo.enabled?(), do: :ok, else: {:error, :authority_repo_disabled}
  end
end
