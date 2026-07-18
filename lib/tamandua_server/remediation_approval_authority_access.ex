defmodule TamanduaServer.RemediationApprovalAuthorityAccess do
  @moduledoc """
  UUID-only, bounded and read-only remediation approval tenant discovery.

  The privileged identity can execute one exact SECURITY DEFINER function. It
  cannot read remediation rows directly. Every malformed, duplicate, unordered
  or over-cap response fails closed.
  """

  alias TamanduaServer.RemediationApprovalAuthorityRepo

  @capability_role "tamandua_authority_remediation_approval_v1_executor"
  @owner_role "tamandua_authority_remediation_approval_v1_owner"
  @function "public.authority_remediation_approval_v1_organization_ids"
  @function_source """
  SELECT DISTINCT execution.organization_id
  FROM public.remediation_executions execution
  WHERE p_limit BETWEEN 1 AND 250
    AND (p_after IS NULL OR execution.organization_id > p_after)
    AND execution.status = 'pending_approval'
    AND execution.approval_status = 'pending'
  ORDER BY execution.organization_id ASC
  LIMIT p_limit + 1
  """
  @page_limit 250
  @global_limit 5_000

  def discover_organization_ids do
    with :ok <- require_enabled(),
         {:ok, role} <- expected_database_role(),
         {:ok, ids} <- page(role, nil, [], MapSet.new()) do
      {:ok, ids}
    else
      {:error, :authority_repo_disabled} -> {:error, :authority_repo_disabled}
      _error -> {:error, :persistence_unavailable}
    end
  rescue
    _error -> {:error, :persistence_unavailable}
  catch
    :exit, _reason -> {:error, :persistence_unavailable}
  end

  defp page(_role, _cursor, ids, _seen) when length(ids) > @global_limit,
    do: {:error, :discovery_limit_exceeded}

  defp page(role, cursor, ids, seen) do
    with {:ok, rows} <- execute_page(role, cursor),
         {:ok, page_ids} <- validate_rows(rows, cursor, seen),
         combined <- ids ++ Enum.take(page_ids, @page_limit),
         true <- length(combined) <= @global_limit do
      if length(page_ids) <= @page_limit do
        {:ok, combined}
      else
        next_cursor = Enum.at(page_ids, @page_limit - 1)

        next_seen =
          page_ids
          |> Enum.take(@page_limit)
          |> Enum.reduce(seen, &MapSet.put(&2, &1))

        page(role, next_cursor, combined, next_seen)
      end
    else
      _error -> {:error, :persistence_unavailable}
    end
  end

  defp execute_page(expected_role, cursor) do
    repo = authority_repo()

    case repo.transaction(fn ->
           with :ok <- preflight(expected_role),
                {:ok, _} <- repo.query("SET LOCAL ROLE #{@capability_role}"),
                {:ok, %{rows: rows}} <-
                  repo.query("SELECT organization_id FROM #{@function}($1, $2)", [
                    cursor,
                    @page_limit
                  ]) do
             rows
           else
             _error -> repo.rollback(:remediation_approval_discovery_failed)
           end
         end) do
      {:ok, rows} -> {:ok, rows}
      _error -> {:error, :persistence_unavailable}
    end
  end

  defp validate_rows(rows, cursor, seen)
       when is_list(rows) and length(rows) <= @page_limit + 1 do
    Enum.reduce_while(rows, {:ok, [], cursor, seen}, fn
      [value], {:ok, ids, previous, current_seen} ->
        with {:ok, id} <- canonical_uuid(value),
             true <- is_nil(previous) or id > previous,
             false <- MapSet.member?(current_seen, id) do
          {:cont, {:ok, [id | ids], id, MapSet.put(current_seen, id)}}
        else
          _error -> {:halt, {:error, :invalid_authority_response}}
        end

      _row, _acc ->
        {:halt, {:error, :invalid_authority_response}}
    end)
    |> case do
      {:ok, ids, _previous, _seen} -> {:ok, Enum.reverse(ids)}
      error -> error
    end
  end

  defp validate_rows(_rows, _cursor, _seen), do: {:error, :invalid_authority_response}

  defp canonical_uuid(value) do
    case Ecto.UUID.cast(value) do
      {:ok, id} -> {:ok, id}
      :error -> Ecto.UUID.load(value)
    end
  end

  defp preflight(expected_role) do
    sql = """
    SELECT (
      session_user = $1 AND current_user = session_user
      AND login.rolcanlogin AND NOT login.rolsuper AND NOT login.rolbypassrls
      AND NOT login.rolinherit AND NOT login.rolcreatedb AND NOT login.rolcreaterole
      AND NOT login.rolreplication AND login.rolconfig IS NULL
      AND NOT owner.rolcanlogin AND NOT owner.rolsuper AND NOT owner.rolbypassrls
      AND NOT owner.rolinherit AND NOT owner.rolcreatedb AND NOT owner.rolcreaterole
      AND NOT owner.rolreplication AND owner.rolconfig IS NULL
      AND NOT capability.rolcanlogin AND NOT capability.rolsuper
      AND NOT capability.rolbypassrls AND NOT capability.rolinherit
      AND NOT capability.rolcreatedb AND NOT capability.rolcreaterole
      AND NOT capability.rolreplication AND capability.rolconfig IS NULL
      AND EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
        WHERE m.member = login.oid AND m.roleid = capability.oid
          AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
        WHERE (m.member IN (login.oid, owner.oid, capability.oid)
          OR m.roleid IN (login.oid, owner.oid, capability.oid))
          AND NOT (m.member = login.oid AND m.roleid = capability.oid
            AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option))
      AND NOT pg_catalog.has_schema_privilege(session_user, ns.oid, 'CREATE')
      AND pg_catalog.has_schema_privilege(capability.oid, ns.oid, 'USAGE')
      AND NOT pg_catalog.has_schema_privilege(capability.oid, ns.oid, 'CREATE')
      AND pg_catalog.has_schema_privilege(owner.oid, ns.oid, 'USAGE')
      AND NOT pg_catalog.has_schema_privilege(owner.oid, ns.oid, 'CREATE')
      AND ns.nspowner = 'pg_database_owner'::pg_catalog.regrole
      AND executions.relrowsecurity AND executions.relforcerowsecurity
      AND NOT pg_catalog.has_table_privilege(session_user, executions.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
      AND NOT pg_catalog.has_any_column_privilege(session_user, executions.oid, 'SELECT,INSERT,UPDATE,REFERENCES')
      AND NOT pg_catalog.has_table_privilege(capability.oid, executions.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
      AND NOT pg_catalog.has_any_column_privilege(capability.oid, executions.oid, 'SELECT,INSERT,UPDATE,REFERENCES')
      AND pg_catalog.has_table_privilege(owner.oid, executions.oid, 'SELECT')
      AND NOT pg_catalog.has_table_privilege(owner.oid, executions.oid, 'SELECT WITH GRANT OPTION')
      AND NOT pg_catalog.has_table_privilege(owner.oid, executions.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
      AND NOT pg_catalog.has_any_column_privilege(owner.oid, executions.oid, 'INSERT,UPDATE,REFERENCES')
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute attribute
        CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) acl
        WHERE attribute.attrelid = executions.oid AND NOT attribute.attisdropped
          AND acl.grantee IN (login.oid, owner.oid, capability.oid))
      AND proc.prokind = 'f' AND proc.pronargs = 2
      AND proc.proargtypes = '2950 23'::pg_catalog.oidvector
      AND proc.prosecdef AND proc.provolatile = 's' AND proc.proretset
      AND proc.prorettype = 'uuid'::pg_catalog.regtype
      AND proc.prolang = (SELECT oid FROM pg_catalog.pg_language WHERE lanname = 'sql')
      AND NOT proc.proleakproof AND NOT proc.proisstrict AND proc.proparallel = 'u'
      AND proc.proconfig @> ARRAY['search_path=pg_catalog','row_security=on']
      AND pg_catalog.array_length(proc.proconfig, 1) = 2
      AND proc.proowner = owner.oid
      AND NOT pg_catalog.has_function_privilege(session_user, proc.oid, 'EXECUTE')
      AND pg_catalog.has_function_privilege(capability.oid, proc.oid, 'EXECUTE')
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
        COALESCE(proc.proacl, pg_catalog.acldefault('f', owner.oid))) acl
        WHERE acl.privilege_type = 'EXECUTE'
          AND (acl.grantee NOT IN (owner.oid, capability.oid) OR acl.is_grantable))
      AND EXISTS (SELECT 1 FROM pg_catalog.pg_policy policy
        WHERE policy.polrelid = executions.oid
          AND policy.polname = 'authority_remediation_approval_v1_select'
          AND policy.polcmd = 'r' AND policy.polroles = ARRAY[owner.oid]
          AND policy.polpermissive
          AND pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) = 'true'
          AND policy.polwithcheck IS NULL)
      AND (SELECT pg_catalog.count(*)
        FROM pg_catalog.pg_proc candidate
        WHERE candidate.pronamespace = ns.oid
          AND candidate.proname = 'authority_remediation_approval_v1_organization_ids') = 1
    ), proc.prosrc
    FROM pg_catalog.pg_roles login
    JOIN pg_catalog.pg_roles capability ON capability.rolname = $2
    JOIN pg_catalog.pg_roles owner ON owner.rolname = $3
    JOIN pg_catalog.pg_namespace ns ON ns.nspname = 'public'
    JOIN pg_catalog.pg_class executions ON executions.oid = 'public.remediation_executions'::pg_catalog.regclass
    JOIN pg_catalog.pg_proc proc ON proc.oid = $4::regprocedure
    WHERE login.rolname = session_user
    """

    signature = "#{@function}(uuid,integer)"

    case authority_repo().query(sql, [expected_role, @capability_role, @owner_role, signature]) do
      {:ok, %{rows: [[true, source]]}} when is_binary(source) ->
        if String.trim(source) == String.trim(@function_source),
          do: :ok,
          else: {:error, :authority_function_body_drift}

      _error -> {:error, :authority_preflight_failed}
    end
  end

  defp expected_database_role do
    case Application.get_env(:tamandua_server, :remediation_approval_authority_database_role) do
      role when is_binary(role) and byte_size(role) in 1..63 -> {:ok, role}
      _other -> {:error, :authority_role_unavailable}
    end
  end

  defp require_enabled do
    if authority_repo().enabled?(), do: :ok, else: {:error, :authority_repo_disabled}
  end

  defp authority_repo do
    Application.get_env(
      :tamandua_server,
      :remediation_approval_authority_repo,
      RemediationApprovalAuthorityRepo
    )
  end
end
