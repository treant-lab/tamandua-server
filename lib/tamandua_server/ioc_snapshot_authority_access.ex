defmodule TamanduaServer.IocSnapshotAuthorityAccess do
  @moduledoc """
  Bounded, fail-closed reader for the external IOC snapshot authority v1.

  All pages are read in one repeatable-read, read-only transaction. This module
  is injectable and remains inert while its dedicated repository is disabled.
  It intentionally has no runtime fallback.
  """

  alias TamanduaServer.{IocSnapshotAuthorityRepo, IocSnapshotDigest}

  @login_role_config :ioc_snapshot_authority_database_role
  @executor_role "tamandua_authority_ioc_snapshot_v1_executor"
  @owner_role "tamandua_authority_ioc_snapshot_v1_owner"
  @function_signature "public.authority_ioc_snapshot_v1(bigint,uuid,integer)"
  @columns ~w(authority_epoch is_envelope has_more row_bytes id organization_id type value severity description source)
  @page_size 1_000
  @maximum_rows 100_000
  @maximum_bytes 64 * 1024 * 1024
  @maximum_row_bytes 64 * 1024
  @wall_timeout_ms 30_000
  @function_source ~S"""
  DECLARE
    snapshot_epoch bigint;
    oversized boolean;
    returned_count integer;
  BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
      RAISE EXCEPTION 'invalid IOC snapshot page limit';
    END IF;

    SELECT epoch INTO STRICT snapshot_epoch
    FROM public.ioc_authority_epochs
    WHERE singleton = true;

    IF p_expected_epoch IS NOT NULL AND p_expected_epoch <> snapshot_epoch THEN
      RAISE EXCEPTION 'IOC snapshot epoch mismatch';
    END IF;

    SELECT EXISTS (
      SELECT 1
      FROM public.iocs AS candidate
      WHERE candidate.enabled = true
        AND (p_after_uuid IS NULL OR candidate.id > p_after_uuid)
        AND pg_catalog.pg_column_size(ROW(
          candidate.id, candidate.organization_id, candidate.type, candidate.value,
          candidate.severity, candidate.description, candidate.source
        )) > 65536
      ORDER BY candidate.id ASC
      LIMIT p_limit + 1
    ) INTO oversized;

    IF oversized THEN
      RAISE EXCEPTION 'IOC snapshot row exceeds 64 KiB';
    END IF;

    RETURN QUERY
    WITH page AS MATERIALIZED (
      SELECT candidate.id, candidate.organization_id, candidate.type,
             candidate.value, candidate.severity, candidate.description,
             candidate.source,
             pg_catalog.pg_column_size(ROW(
               candidate.id, candidate.organization_id, candidate.type, candidate.value,
               candidate.severity, candidate.description, candidate.source
             ))::integer AS bytes
      FROM public.iocs AS candidate
      WHERE candidate.enabled = true
        AND (p_after_uuid IS NULL OR candidate.id > p_after_uuid)
      ORDER BY candidate.id ASC
      LIMIT p_limit + 1
    ), bounded AS (
      SELECT page.*, count(*) OVER () > p_limit AS more
      FROM page
      ORDER BY page.id ASC
      LIMIT p_limit
    )
    SELECT snapshot_epoch, false, bounded.more, bounded.bytes, bounded.id,
           bounded.organization_id, bounded.type, bounded.value, bounded.severity,
           bounded.description, bounded.source
    FROM bounded
    ORDER BY bounded.id ASC;

    GET DIAGNOSTICS returned_count = ROW_COUNT;
    IF returned_count = 0 THEN
      RETURN QUERY SELECT snapshot_epoch, true, false, 0, NULL::uuid, NULL::uuid,
        NULL::text, NULL::text, NULL::text, NULL::text, NULL::text;
    END IF;
  END;
  """

  @type snapshot :: %{
          authority_epoch: non_neg_integer(),
          row_count: non_neg_integer(),
          byte_count: non_neg_integer(),
          sha256: String.t(),
          rows: [map()]
        }

  @spec load_snapshot() :: {:ok, snapshot()} | {:error, :persistence_unavailable}
  def load_snapshot do
    started_at = System.monotonic_time(:millisecond)

    with :ok <- require_enabled(),
         {:ok, login_role} <- expected_login_role(),
         {:ok, snapshot} <- execute_snapshot(login_role, started_at) do
      {:ok, snapshot}
    else
      _error -> {:error, :persistence_unavailable}
    end
  rescue
    _error -> {:error, :persistence_unavailable}
  catch
    :exit, _reason -> {:error, :persistence_unavailable}
  end

  @spec preflight() :: :ok | {:error, :persistence_unavailable}
  def preflight do
    with :ok <- require_enabled(),
         {:ok, login_role} <- expected_login_role(),
         {:ok, :ok} <- authority_transaction(login_role, fn _repo -> :ok end) do
      :ok
    else
      _error -> {:error, :persistence_unavailable}
    end
  rescue
    _error -> {:error, :persistence_unavailable}
  catch
    :exit, _reason -> {:error, :persistence_unavailable}
  end

  @spec current_epoch() :: {:ok, non_neg_integer()} | {:error, :persistence_unavailable}
  def current_epoch do
    with :ok <- require_enabled(),
         {:ok, login_role} <- expected_login_role(),
         {:ok, {:ok, epoch}} <-
           authority_transaction(login_role, fn repo ->
             with {:ok, _} <- repo.query("SET LOCAL ROLE #{@executor_role}"),
                  {:ok, %{columns: ["authority_epoch"], rows: [[epoch]]}} <-
                    repo.query(
                      "SELECT authority_epoch FROM public.authority_ioc_snapshot_v1(NULL, NULL, 1) LIMIT 1",
                      [],
                      timeout: 5_000
                    ),
                  true <- is_integer(epoch) and epoch >= 0 do
               {:ok, epoch}
             else
               _error -> {:error, :invalid_authority_epoch_probe}
             end
           end) do
      {:ok, epoch}
    else
      _error -> {:error, :persistence_unavailable}
    end
  rescue
    _error -> {:error, :persistence_unavailable}
  catch
    :exit, _reason -> {:error, :persistence_unavailable}
  end

  defp authority_transaction(login_role, callback) do
    repo = authority_repo()

    repo.transaction(
      fn ->
        with {:ok, _} <- repo.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"),
             {:ok, _} <- repo.query("SET LOCAL statement_timeout = '5s'"),
             {:ok, _} <- repo.query("SET LOCAL lock_timeout = '1s'"),
             :ok <- preflight(repo, login_role) do
          callback.(repo)
        else
          _error -> repo.rollback(:ioc_snapshot_authority_failed)
        end
      end,
      timeout: 7_000
    )
  end

  defp execute_snapshot(login_role, started_at) do
    repo = authority_repo()

    repo.transaction(
      fn ->
        with {:ok, _} <- repo.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"),
             {:ok, _} <- repo.query("SET LOCAL statement_timeout = '5s'"),
             {:ok, _} <- repo.query("SET LOCAL lock_timeout = '1s'"),
             :ok <- preflight(repo, login_role),
             {:ok, _} <- repo.query("SET LOCAL ROLE #{@executor_role}"),
             {:ok, state} <- page(repo, nil, nil, [], 0, started_at),
             {:ok, digest} <-
               IocSnapshotDigest.sha256(
                 state.epoch,
                 length(state.rows),
                 state.byte_count,
                 state.rows
               ) do
          %{
            authority_epoch: state.epoch,
            row_count: length(state.rows),
            byte_count: state.byte_count,
            sha256: digest,
            rows: state.rows
          }
        else
          _error -> repo.rollback(:ioc_snapshot_authority_failed)
        end
      end,
      timeout: @wall_timeout_ms + 1_000
    )
    |> case do
      {:ok, snapshot} -> {:ok, snapshot}
      _error -> {:error, :persistence_unavailable}
    end
  end

  defp page(repo, expected_epoch, after_id, rows, byte_count, started_at) do
    with :ok <- within_wall_time(started_at),
         {:ok, result} <-
           repo.query(
             "SELECT * FROM public.authority_ioc_snapshot_v1($1, $2, $3)",
             [expected_epoch, after_id, @page_size],
             timeout: 5_000
           ),
         :ok <- exact_columns(result.columns),
         {:ok, page} <- validate_page(result.rows, expected_epoch, after_id),
         :ok <- within_caps(rows, byte_count, page) do
      accumulated = rows ++ page.rows
      accumulated_bytes = byte_count + page.byte_count

      if page.has_more do
        page(repo, page.epoch, page.last_id, accumulated, accumulated_bytes, started_at)
      else
        {:ok, %{epoch: page.epoch, rows: accumulated, byte_count: accumulated_bytes}}
      end
    end
  end

  defp validate_page([[epoch, true, false, 0, nil, nil, nil, nil, nil, nil, nil]], expected, nil)
       when is_integer(epoch) and epoch >= 0 and (is_nil(expected) or expected == epoch),
       do: {:ok, %{epoch: epoch, rows: [], byte_count: 0, has_more: false, last_id: nil}}

  defp validate_page(raw_rows, expected_epoch, after_id)
       when is_list(raw_rows) and raw_rows != [] and length(raw_rows) <= @page_size do
    Enum.reduce_while(raw_rows, {:ok, nil, [], 0, nil}, fn
      [
        epoch,
        false,
        has_more,
        row_bytes,
        id,
        organization_id,
        type,
        value,
        severity,
        description,
        source
      ],
      {:ok, page_epoch, rows, bytes, previous_id}
      when is_integer(epoch) and epoch >= 0 and is_boolean(has_more) and is_integer(row_bytes) and
             row_bytes >= 1 and row_bytes <= @maximum_row_bytes and is_binary(id) and
             (is_nil(organization_id) or is_binary(organization_id)) and is_binary(type) and
             is_binary(value) and is_binary(severity) and
             (is_nil(description) or is_binary(description)) and
             (is_nil(source) or is_binary(source)) ->
        canonical = %{
          id: canonical_uuid!(id),
          organization_id: nullable_uuid!(organization_id),
          type: type,
          value: value,
          severity: severity,
          description: description,
          source: source
        }

        current_id = canonical.id

        if payload_bytes(canonical) <= row_bytes and
             (is_nil(page_epoch) or page_epoch == epoch) and
             (is_nil(expected_epoch) or expected_epoch == epoch) and
             (is_nil(previous_id) or uuid_binary(current_id) > uuid_binary(previous_id)) and
             (is_nil(after_id) or uuid_binary(current_id) > uuid_binary(after_id)) do
          {:cont, {:ok, epoch, [canonical | rows], bytes + row_bytes, current_id}}
        else
          {:halt, {:error, :invalid_page_order_or_epoch}}
        end

      _row, _acc ->
        {:halt, {:error, :malformed_authority_result}}
    end)
    |> case do
      {:ok, epoch, reversed, bytes, last_id} ->
        rows = Enum.reverse(reversed)
        flags = Enum.map(raw_rows, &Enum.at(&1, 2)) |> Enum.uniq()

        if (flags == [true] and length(rows) == @page_size) or flags == [false] do
          {:ok,
           %{
             epoch: epoch,
             rows: rows,
             byte_count: bytes,
             has_more: flags == [true],
             last_id: last_id
           }}
        else
          {:error, :invalid_page_flags}
        end

      error ->
        error
    end
  rescue
    _error -> {:error, :malformed_authority_result}
  end

  defp validate_page(_rows, _expected_epoch, _after_id),
    do: {:error, :malformed_authority_result}

  defp within_caps(rows, byte_count, page) do
    if length(rows) + length(page.rows) <= @maximum_rows and
         byte_count + page.byte_count <= @maximum_bytes,
       do: :ok,
       else: {:error, :snapshot_over_limit}
  end

  defp within_wall_time(started_at) do
    if System.monotonic_time(:millisecond) - started_at < @wall_timeout_ms,
      do: :ok,
      else: {:error, :snapshot_timeout}
  end

  defp exact_columns(@columns), do: :ok
  defp exact_columns(_columns), do: {:error, :unexpected_authority_columns}

  defp canonical_uuid!(value) do
    case Ecto.UUID.cast(value) do
      {:ok, canonical} -> canonical
      :error -> Ecto.UUID.load!(value)
    end
  end

  defp nullable_uuid!(nil), do: nil
  defp nullable_uuid!(value), do: canonical_uuid!(value)
  defp uuid_binary(value), do: Ecto.UUID.dump!(value)

  defp payload_bytes(row) do
    16 +
      if(is_nil(row.organization_id), do: 0, else: 16) +
      byte_size(row.type) +
      byte_size(row.value) +
      byte_size(row.severity) +
      nullable_byte_size(row.description) +
      nullable_byte_size(row.source)
  end

  defp nullable_byte_size(nil), do: 0
  defp nullable_byte_size(value), do: byte_size(value)

  defp preflight(repo, login_role) do
    sql = """
    SELECT (
      session_user = $1 AND current_user = session_user
      AND login.rolcanlogin AND NOT login.rolsuper AND NOT login.rolbypassrls
      AND NOT login.rolinherit AND NOT login.rolcreatedb AND NOT login.rolcreaterole
      AND NOT login.rolreplication AND login.rolconfig IS NULL
      AND NOT owner.rolcanlogin AND NOT owner.rolsuper AND NOT owner.rolbypassrls
      AND NOT owner.rolinherit AND NOT owner.rolcreatedb AND NOT owner.rolcreaterole
      AND NOT owner.rolreplication AND owner.rolconfig IS NULL
      AND NOT executor.rolcanlogin AND NOT executor.rolsuper AND NOT executor.rolbypassrls
      AND NOT executor.rolinherit AND NOT executor.rolcreatedb AND NOT executor.rolcreaterole
      AND NOT executor.rolreplication AND executor.rolconfig IS NULL
      AND EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members m
        WHERE m.roleid = executor.oid AND m.member = login.oid
          AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option
      )
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members membership
        WHERE (membership.member = login.oid AND membership.roleid <> executor.oid)
           OR membership.roleid = login.oid
           OR membership.member = executor.oid
           OR (membership.roleid = executor.oid AND membership.member <> login.oid)
           OR membership.member = owner.oid
           OR membership.roleid = owner.oid
      )
      AND NOT pg_catalog.has_schema_privilege(login.oid, namespace.oid, 'CREATE')
      AND pg_catalog.has_schema_privilege(executor.oid, namespace.oid, 'USAGE')
      AND NOT pg_catalog.has_schema_privilege(executor.oid, namespace.oid, 'CREATE')
      AND pg_catalog.has_schema_privilege(owner.oid, namespace.oid, 'USAGE')
      AND NOT pg_catalog.has_schema_privilege(owner.oid, namespace.oid, 'CREATE')
      AND iocs.relrowsecurity AND iocs.relforcerowsecurity
      AND NOT pg_catalog.has_table_privilege(
        login.oid, iocs.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      )
      AND NOT pg_catalog.has_any_column_privilege(
        login.oid, iocs.oid, 'SELECT,INSERT,UPDATE,REFERENCES'
      )
      AND NOT pg_catalog.has_table_privilege(
        executor.oid, iocs.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      )
      AND NOT pg_catalog.has_any_column_privilege(
        executor.oid, iocs.oid, 'SELECT,INSERT,UPDATE,REFERENCES'
      )
      AND pg_catalog.has_table_privilege(owner.oid, iocs.oid, 'SELECT')
      AND NOT pg_catalog.has_table_privilege(owner.oid, iocs.oid, 'SELECT WITH GRANT OPTION')
      AND NOT pg_catalog.has_table_privilege(
        owner.oid, iocs.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      )
      AND NOT pg_catalog.has_any_column_privilege(
        owner.oid, iocs.oid, 'INSERT,UPDATE,REFERENCES'
      )
      AND NOT pg_catalog.has_table_privilege(
        login.oid, epochs.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      )
      AND NOT pg_catalog.has_any_column_privilege(
        login.oid, epochs.oid, 'SELECT,INSERT,UPDATE,REFERENCES'
      )
      AND NOT pg_catalog.has_table_privilege(
        executor.oid, epochs.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      )
      AND NOT pg_catalog.has_any_column_privilege(
        executor.oid, epochs.oid, 'SELECT,INSERT,UPDATE,REFERENCES'
      )
      AND pg_catalog.has_table_privilege(owner.oid, epochs.oid, 'SELECT')
      AND NOT pg_catalog.has_table_privilege(owner.oid, epochs.oid, 'SELECT WITH GRANT OPTION')
      AND NOT pg_catalog.has_table_privilege(
        owner.oid, epochs.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
      )
      AND NOT pg_catalog.has_any_column_privilege(
        owner.oid, epochs.oid, 'INSERT,UPDATE,REFERENCES'
      )
      AND function.proowner = owner.oid AND function.prosecdef AND function.provolatile = 's'
      AND function.prokind = 'f' AND function.proretset AND function.pronargs = 3
      AND NOT function.proleakproof AND function.proparallel = 'u'
      AND function.prolang = (
        SELECT oid FROM pg_catalog.pg_language WHERE lanname = 'plpgsql'
      )
      AND pg_catalog.pg_get_function_result(function.oid) =
        'TABLE(authority_epoch bigint, is_envelope boolean, has_more boolean, row_bytes integer, id uuid, organization_id uuid, type text, value text, severity text, description text, source text)'
      AND function.proconfig @> ARRAY[
        'search_path=pg_catalog','row_security=on','app.rls_bypass=off'
      ]
      AND pg_catalog.array_length(function.proconfig, 1) = 3
      AND NOT pg_catalog.has_function_privilege(login.oid, function.oid, 'EXECUTE')
      AND pg_catalog.has_function_privilege(executor.oid, function.oid, 'EXECUTE')
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.aclexplode(
          COALESCE(function.proacl, pg_catalog.acldefault('f', owner.oid))
        ) acl
        WHERE acl.privilege_type = 'EXECUTE'
          AND (acl.grantee NOT IN (owner.oid, executor.oid)
               OR (acl.grantee = executor.oid AND acl.is_grantable))
      )
      AND EXISTS (
        SELECT 1 FROM pg_catalog.pg_policy policy
        WHERE policy.polrelid = iocs.oid AND policy.polname = 'authority_ioc_snapshot_v1_select'
          AND policy.polcmd = 'r' AND policy.polroles = ARRAY[owner.oid]
          AND policy.polpermissive
          AND pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) = 'true'
          AND policy.polwithcheck IS NULL
      )
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc candidate
        JOIN pg_catalog.pg_namespace candidate_namespace
          ON candidate_namespace.oid = candidate.pronamespace
        WHERE candidate.oid <> function.oid
          AND candidate.prosecdef
          AND candidate_namespace.nspname NOT IN ('pg_catalog', 'information_schema')
          AND (
            pg_catalog.has_function_privilege(login.oid, candidate.oid, 'EXECUTE')
            OR pg_catalog.has_function_privilege(executor.oid, candidate.oid, 'EXECUTE')
          )
      )
    ), function.prosrc
    FROM pg_catalog.pg_roles login
    JOIN pg_catalog.pg_roles owner ON owner.rolname = $2
    JOIN pg_catalog.pg_roles executor ON executor.rolname = $3
    JOIN pg_catalog.pg_namespace namespace ON namespace.nspname = 'public'
    JOIN pg_catalog.pg_class iocs ON iocs.oid = 'public.iocs'::pg_catalog.regclass
    JOIN pg_catalog.pg_class epochs ON epochs.oid = 'public.ioc_authority_epochs'::pg_catalog.regclass
    JOIN pg_catalog.pg_proc function ON function.oid = $4::pg_catalog.regprocedure
    WHERE login.rolname = session_user
    """

    case repo.query(sql, [login_role, @owner_role, @executor_role, @function_signature]) do
      {:ok, %{rows: [[true, source]]}} when is_binary(source) ->
        if String.trim(source) == String.trim(@function_source),
          do: :ok,
          else: {:error, :authority_function_body_drift}

      _error ->
        {:error, :authority_identity_or_grant_preflight_failed}
    end
  end

  defp expected_login_role do
    case Application.get_env(:tamandua_server, @login_role_config) do
      role when is_binary(role) and byte_size(role) >= 1 and byte_size(role) <= 63 -> {:ok, role}
      _other -> {:error, :authority_database_role_unavailable}
    end
  end

  defp require_enabled do
    if authority_repo().enabled?(), do: :ok, else: {:error, :authority_repo_disabled}
  end

  defp authority_repo do
    Application.get_env(
      :tamandua_server,
      :ioc_snapshot_authority_repo,
      IocSnapshotAuthorityRepo
    )
  end
end
