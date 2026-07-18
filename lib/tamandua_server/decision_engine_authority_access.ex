defmodule TamanduaServer.DecisionEngineAuthorityAccess do
  @moduledoc """
  UUID-only, bounded and read-only DecisionEngine discovery facade.

  All tenant data remains on the ordinary repository inside an exact tenant
  transaction. Authority errors and incomplete pagination fail closed.
  """

  alias TamanduaServer.DecisionEngineAuthorityRepo

  @capability_role "tamandua_authority_decision_engine_v1_executor"
  @owner_role "tamandua_authority_decision_engine_v1_owner"
  @restore_function "public.authority_decision_engine_restore_v1_organization_ids"
  @maintenance_function "public.authority_decision_engine_maintenance_v1_organization_ids"
  @page_limit 250
  @global_limit 5_000

  def discover_restore_organization_ids,
    do: discover(@restore_function, "restore")

  def discover_maintenance_organization_ids,
    do: discover(@maintenance_function, "maintenance")

  defp discover(function, kind) do
    with :ok <- require_enabled(),
         {:ok, role} <- expected_database_role(),
         {:ok, ids} <- page(function, kind, role, nil, [], MapSet.new()) do
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

  defp page(_function, _kind, _role, _cursor, ids, _seen)
       when length(ids) > @global_limit,
       do: {:error, :discovery_limit_exceeded}

  defp page(function, kind, role, cursor, ids, seen) do
    with {:ok, rows} <- execute_page(function, kind, role, cursor),
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

        page(function, kind, role, next_cursor, combined, next_seen)
      end
    else
      _error -> {:error, :persistence_unavailable}
    end
  end

  defp execute_page(function, kind, expected_role, cursor) do
    repo = authority_repo()

    case repo.transaction(fn ->
           with :ok <- preflight(expected_role),
                {:ok, _} <- repo.query("SET LOCAL ROLE #{@capability_role}"),
                {:ok, %{rows: rows}} <-
                  repo.query("SELECT organization_id FROM #{function}($1, $2)", [
                    cursor,
                    @page_limit
                  ]) do
             rows
           else
             _error -> repo.rollback({:decision_engine_discovery_failed, kind})
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
      AND NOT pg_catalog.has_table_privilege(session_user, 'public.autonomous_settings', 'SELECT')
      AND NOT pg_catalog.has_table_privilege(session_user, 'public.autonomous_recommendations', 'SELECT')
      AND NOT pg_catalog.has_table_privilege(capability.oid, 'public.autonomous_settings', 'SELECT')
      AND NOT pg_catalog.has_table_privilege(capability.oid, 'public.autonomous_recommendations', 'SELECT')
      AND pg_catalog.has_table_privilege(owner.oid, 'public.autonomous_settings', 'SELECT')
      AND pg_catalog.has_table_privilege(owner.oid, 'public.autonomous_recommendations', 'SELECT')
      AND NOT pg_catalog.has_table_privilege(owner.oid, 'public.autonomous_settings', 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
      AND NOT pg_catalog.has_table_privilege(owner.oid, 'public.autonomous_recommendations', 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
      AND NOT pg_catalog.has_table_privilege(owner.oid, 'public.oban_jobs', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
      AND count(proc.oid) = 2
      AND bool_and(proc.prosecdef AND proc.provolatile = 's' AND proc.proretset
        AND proc.prorettype = 'uuid'::pg_catalog.regtype
        AND proc.prolang = (SELECT oid FROM pg_catalog.pg_language WHERE lanname = 'sql')
        AND proc.proconfig @> ARRAY['search_path=pg_catalog','app.rls_bypass=true']
        AND pg_catalog.array_length(proc.proconfig, 1) = 2
        AND proc.proowner = owner.oid
        AND CASE proc.proname
          WHEN 'authority_decision_engine_restore_v1_organization_ids'
            THEN pg_catalog.md5(proc.prosrc) = '36e9101fa6a335944203422672e2a6b0'
          WHEN 'authority_decision_engine_maintenance_v1_organization_ids'
            THEN pg_catalog.md5(proc.prosrc) = '24d3bb97163e8da4d0bdfc4eddb957da'
          ELSE false
        END
        AND NOT pg_catalog.has_function_privilege(session_user, proc.oid, 'EXECUTE')
        AND pg_catalog.has_function_privilege(capability.oid, proc.oid, 'EXECUTE')
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
          COALESCE(proc.proacl, pg_catalog.acldefault('f', owner.oid))) acl
          WHERE acl.privilege_type = 'EXECUTE'
            AND (acl.grantee NOT IN (owner.oid, capability.oid)
              OR (acl.grantee = capability.oid AND acl.is_grantable))))
    )
    FROM pg_catalog.pg_roles login
    JOIN pg_catalog.pg_roles capability ON capability.rolname = $2
    JOIN pg_catalog.pg_roles owner ON owner.rolname = $3
    JOIN pg_catalog.pg_namespace ns ON ns.nspname = 'public'
    JOIN pg_catalog.pg_proc proc ON proc.oid = ANY($4::regprocedure[])
    WHERE login.rolname = session_user
    GROUP BY login.oid, capability.oid, owner.oid, ns.oid
    """

    signatures = [
      "#{@restore_function}(uuid,integer)",
      "#{@maintenance_function}(uuid,integer)"
    ]

    case authority_repo().query(sql, [expected_role, @capability_role, @owner_role, signatures]) do
      {:ok, %{rows: [[true]]}} -> :ok
      _error -> {:error, :authority_preflight_failed}
    end
  end

  defp expected_database_role do
    case Application.get_env(:tamandua_server, :decision_engine_authority_database_role) do
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
      :decision_engine_authority_repo,
      DecisionEngineAuthorityRepo
    )
  end
end
