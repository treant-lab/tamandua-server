defmodule TamanduaServer.Accounts.PlatformOperatorDBPreflight do
  @moduledoc """
  Fail-closed PostgreSQL role and ACL preflight for platform authority writes.

  This is a runtime guard, not a substitute for separate migration/runtime
  roles or a database-owned procedure boundary. It deliberately refuses to
  operate when the authority tables or their effective ACLs cannot be proven
  safe.
  """

  require Logger

  alias TamanduaServer.Repo

  @type snapshot :: %{
          role: binary(),
          superuser: boolean(),
          bypass_rls: boolean(),
          inherits_roles: boolean(),
          missing_tables: non_neg_integer(),
          owns_table: boolean(),
          member_of_owner: boolean(),
          prohibited_dml: boolean()
        }

  defmodule Probe do
    @moduledoc false

    @callback inspect_role(module()) ::
                {:ok, TamanduaServer.Accounts.PlatformOperatorDBPreflight.snapshot()}
                | {:error, term()}
  end

  defmodule PostgresProbe do
    @moduledoc false
    @behaviour Probe

    @sql """
    WITH expected(table_name) AS (
      VALUES
        ('platform_operator_grants'),
        ('platform_operator_elevation_proofs'),
        ('platform_operator_events'),
        ('platform_operator_external_receipts')
    ), current_role_row AS (
      SELECT oid, rolname, rolsuper, rolbypassrls, rolinherit
      FROM pg_catalog.pg_roles
      WHERE rolname = current_user
    ), inspected AS (
      SELECT
        expected.table_name,
        relation.oid AS relation_oid,
        relation.relowner,
        relation.oid IS NULL AS missing,
        COALESCE(relation.relowner = role_row.oid, false) AS owns_table,
        COALESCE(pg_catalog.pg_has_role(role_row.oid, relation.relowner, 'MEMBER'), false)
          AS member_of_owner,
        CASE
          WHEN relation.oid IS NULL THEN false
          ELSE EXISTS (
            SELECT 1
            FROM pg_catalog.pg_roles AS reachable_role
            WHERE pg_catalog.pg_has_role(role_row.oid, reachable_role.oid, 'MEMBER')
              AND (
                pg_catalog.has_table_privilege(reachable_role.oid, relation.oid, 'INSERT') OR
                pg_catalog.has_table_privilege(reachable_role.oid, relation.oid, 'UPDATE') OR
                pg_catalog.has_table_privilege(reachable_role.oid, relation.oid, 'DELETE') OR
                pg_catalog.has_table_privilege(reachable_role.oid, relation.oid, 'TRUNCATE') OR
                pg_catalog.has_any_column_privilege(
                  reachable_role.oid,
                  relation.oid,
                  'INSERT'
                ) OR
                pg_catalog.has_any_column_privilege(
                  reachable_role.oid,
                  relation.oid,
                  'UPDATE'
                )
              )
          )
        END AS prohibited_dml
      FROM expected
      CROSS JOIN current_role_row AS role_row
      LEFT JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.nspname = 'public'
      LEFT JOIN pg_catalog.pg_class AS relation
        ON relation.relnamespace = namespace.oid
       AND relation.relname = expected.table_name
       AND relation.relkind IN ('r', 'p')
    )
    SELECT
      role_row.rolname,
      role_row.rolsuper,
      role_row.rolbypassrls,
      role_row.rolinherit,
      COUNT(*) FILTER (WHERE inspected.missing),
      COALESCE(BOOL_OR(inspected.owns_table), false),
      COALESCE(BOOL_OR(inspected.member_of_owner), false),
      COALESCE(BOOL_OR(inspected.prohibited_dml), false)
    FROM current_role_row AS role_row
    CROSS JOIN inspected
    GROUP BY
      role_row.rolname,
      role_row.rolsuper,
      role_row.rolbypassrls,
      role_row.rolinherit
    """

    @impl true
    def inspect_role(repo) do
      case repo.query(@sql, [], log: false) do
        {:ok, %{rows: [[role, superuser, bypass_rls, inherits, missing, owns, member, dml]]}} ->
          {:ok,
           %{
             role: role,
             superuser: superuser,
             bypass_rls: bypass_rls,
             inherits_roles: inherits,
             missing_tables: missing,
             owns_table: owns,
             member_of_owner: member,
             prohibited_dml: dml
           }}

        {:ok, _unexpected} ->
          {:error, :unexpected_preflight_result}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      error -> {:error, error}
    catch
      :exit, reason -> {:error, {:exit, reason}}
    end
  end

  @doc "Run the production PostgreSQL probe."
  @spec check(module()) :: :ok | {:error, atom()}
  def check(repo \\ Repo) do
    probe =
      Application.get_env(
        :tamandua_server,
        :platform_operator_db_preflight_probe,
        PostgresProbe
      )

    check(repo, probe)
  end

  @doc false
  @spec check(module(), module()) :: :ok | {:error, atom()}
  def check(repo, probe) do
    case inspect_role(probe, repo) do
      {:ok, snapshot} ->
        case unsafe_reasons(snapshot) do
          [] ->
            :ok

          reasons ->
            emit_failure(:unsafe_database_role, snapshot.role, reasons)
            {:error, :unsafe_platform_operator_database_role}
        end

      {:error, _reason} ->
        emit_failure(:preflight_unavailable, nil, [:probe_failed])
        Logger.error("platform operator database preflight failed")

        {:error, :platform_operator_database_preflight_failed}
    end
  end

  defp inspect_role(probe, repo) do
    probe.inspect_role(repo)
  rescue
    _error -> {:error, :probe_failed}
  catch
    _kind, _reason -> {:error, :probe_failed}
  end

  @doc false
  @spec unsafe_reasons(snapshot()) :: [atom()]
  def unsafe_reasons(snapshot) do
    []
    |> maybe_add(snapshot.superuser, :superuser)
    |> maybe_add(snapshot.bypass_rls, :bypass_rls)
    |> maybe_add(snapshot.inherits_roles, :role_inheritance_enabled)
    |> maybe_add(snapshot.missing_tables != 0, :authority_tables_missing)
    |> maybe_add(snapshot.owns_table, :table_owner)
    |> maybe_add(snapshot.member_of_owner, :member_of_table_owner)
    |> maybe_add(snapshot.prohibited_dml, :prohibited_table_dml)
    |> Enum.reverse()
  end

  defp maybe_add(reasons, true, reason), do: [reason | reasons]
  defp maybe_add(reasons, false, _reason), do: reasons

  defp emit_failure(kind, role, reasons) do
    :telemetry.execute(
      [:tamandua, :platform_operator, :database_preflight_failed],
      %{count: 1},
      %{kind: kind, role: role, reasons: reasons}
    )
  end
end
