defmodule TamanduaServer.AgenticRestoreAuthorityAccess do
  @moduledoc """
  Bounded read-only facade for agentic investigation startup discovery v1.

  The database capability returns tenant UUIDs only. Snapshot identifiers,
  payloads, timestamps, states, and other tenant data never cross this pool.
  """

  alias TamanduaServer.AgenticRestoreAuthorityRepo

  @capability_role "tamandua_authority_agentic_restore_v1_executor"
  @owner_role "tamandua_authority_agentic_restore_v1_owner"
  @function_name "public.authority_agentic_restore_v1_organization_ids"
  @function_signature "public.authority_agentic_restore_v1_organization_ids(integer,integer)"
  @snapshot_version 1
  @maximum_limit 500

  @spec discover_non_terminal_organization_ids(1, pos_integer()) ::
          {:ok, [Ecto.UUID.t()], %{truncated: boolean()}} | {:error, :persistence_unavailable}
  def discover_non_terminal_organization_ids(@snapshot_version, limit)
      when is_integer(limit) and limit >= 1 and limit <= @maximum_limit do
    with :ok <- require_enabled(),
         {:ok, expected_role} <- expected_database_role(),
         {:ok, rows} <- execute_discovery(expected_role, limit),
         {:ok, organization_ids} <- validate_rows(rows, limit + 1) do
      {:ok, Enum.take(organization_ids, limit), %{truncated: length(organization_ids) > limit}}
    else
      _error -> {:error, :persistence_unavailable}
    end
  rescue
    _error -> {:error, :persistence_unavailable}
  catch
    :exit, _reason -> {:error, :persistence_unavailable}
  end

  def discover_non_terminal_organization_ids(_snapshot_version, _limit),
    do: {:error, :persistence_unavailable}

  defp execute_discovery(expected_role, limit) do
    repo = authority_repo()

    case repo.transaction(fn ->
           with :ok <- preflight(expected_role),
                {:ok, _result} <-
                  repo.query("SET LOCAL ROLE #{@capability_role}"),
                {:ok, %{rows: rows}} <-
                  repo.query(
                    "SELECT organization_id FROM #{@function_name}($1, $2)",
                    [@snapshot_version, limit]
                  ) do
             rows
           else
             _error -> repo.rollback(:agentic_restore_discovery_failed)
           end
         end) do
      {:ok, rows} -> {:ok, rows}
      _error -> {:error, :persistence_unavailable}
    end
  end

  defp validate_rows(rows, maximum_rows) when is_list(rows) and length(rows) <= maximum_rows do
    Enum.reduce_while(rows, {:ok, [], MapSet.new()}, fn
      [organization_id], {:ok, ids, seen} when is_binary(organization_id) ->
        case canonical_uuid(organization_id) do
          {:ok, canonical_id} ->
            if MapSet.member?(seen, canonical_id) do
              {:halt, {:error, :duplicate_organization_id}}
            else
              {:cont, {:ok, [canonical_id | ids], MapSet.put(seen, canonical_id)}}
            end

          :error ->
            {:halt, {:error, :invalid_organization_id}}
        end

      _row, _acc ->
        {:halt, {:error, :malformed_authority_result}}
    end)
    |> case do
      {:ok, ids, _seen} -> {:ok, Enum.reverse(ids)}
      {:error, _reason} = error -> error
    end
  end

  defp validate_rows(_rows, _maximum_rows), do: {:error, :over_limit_authority_result}

  # Raw Postgrex queries decode uuid columns to their 16-byte database form,
  # while test adapters and future typed projections may return canonical text.
  # Both representations are UUID-only and normalize to the same text key.
  defp canonical_uuid(value) do
    case Ecto.UUID.cast(value) do
      {:ok, canonical_id} -> {:ok, canonical_id}
      :error -> Ecto.UUID.load(value)
    end
  end

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
      AND login_role.rolconfig IS NULL
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
           OR membership.roleid = capability.oid AND membership.member <> login_role.oid
           OR membership.member = function_owner.oid
           OR membership.roleid = function_owner.oid
      )
      AND NOT pg_catalog.has_schema_privilege(session_user, namespace.oid, 'CREATE')
      AND pg_catalog.has_schema_privilege(capability.oid, namespace.oid, 'USAGE')
      AND NOT pg_catalog.has_schema_privilege(capability.oid, namespace.oid, 'CREATE')
      AND pg_catalog.has_schema_privilege(function_owner.oid, namespace.oid, 'USAGE')
      AND NOT pg_catalog.has_schema_privilege(function_owner.oid, namespace.oid, 'CREATE')
      AND NOT pg_catalog.has_table_privilege(session_user, snapshots.oid, 'SELECT')
      AND NOT pg_catalog.has_table_privilege(capability.oid, snapshots.oid, 'SELECT')
      AND function_owner.rolname = $3
      AND NOT function_owner.rolcanlogin
      AND NOT function_owner.rolsuper
      AND NOT function_owner.rolbypassrls
      AND NOT function_owner.rolinherit
      AND NOT function_owner.rolcreatedb
      AND NOT function_owner.rolcreaterole
      AND NOT function_owner.rolreplication
      AND function_owner.rolconfig IS NULL
      AND NOT capability.rolcanlogin
      AND NOT capability.rolsuper
      AND NOT capability.rolbypassrls
      AND NOT capability.rolinherit
      AND NOT capability.rolcreatedb
      AND NOT capability.rolcreaterole
      AND NOT capability.rolreplication
      AND capability.rolconfig IS NULL
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
            pg_catalog.acldefault('f', function_owner.oid)
          )
        ) acl
        WHERE acl.privilege_type = 'EXECUTE'
          AND (acl.grantee NOT IN (function_owner.oid, capability.oid)
               OR (acl.grantee = capability.oid AND acl.is_grantable))
      )
      AND pg_catalog.has_table_privilege(function_owner.oid, snapshots.oid, 'SELECT')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, snapshots.oid, 'INSERT')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, snapshots.oid, 'UPDATE')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, snapshots.oid, 'DELETE')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, snapshots.oid, 'TRUNCATE')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, snapshots.oid, 'REFERENCES')
      AND NOT pg_catalog.has_table_privilege(function_owner.oid, snapshots.oid, 'TRIGGER')
    )
    FROM pg_catalog.pg_roles login_role
    JOIN pg_catalog.pg_roles capability ON capability.rolname = $2
    JOIN pg_catalog.pg_namespace namespace ON namespace.nspname = 'public'
    JOIN pg_catalog.pg_class snapshots
      ON snapshots.relnamespace = namespace.oid
     AND snapshots.relname = 'ai_agentic_investigation_snapshots'
    JOIN pg_catalog.pg_proc authority_function
      ON authority_function.oid = $4::pg_catalog.regprocedure
    JOIN pg_catalog.pg_roles function_owner ON function_owner.oid = authority_function.proowner
    WHERE login_role.rolname = session_user
    """

    repo = authority_repo()

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
    case Application.get_env(:tamandua_server, :agentic_restore_authority_database_role) do
      role when is_binary(role) and byte_size(role) >= 1 and byte_size(role) <= 63 -> {:ok, role}
      _other -> {:error, :authority_database_role_unavailable}
    end
  end

  defp require_enabled do
    repo = authority_repo()

    if repo.enabled?(),
      do: :ok,
      else: {:error, :authority_repo_disabled}
  end

  defp authority_repo do
    Application.get_env(
      :tamandua_server,
      :agentic_restore_authority_repo,
      AgenticRestoreAuthorityRepo
    )
  end
end
