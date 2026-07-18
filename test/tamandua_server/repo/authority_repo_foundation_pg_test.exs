defmodule TamanduaServer.Repo.AuthorityRepoFoundationPGTest do
  @moduledoc """
  Destructive contract for a disposable PostgreSQL 16+ database.

  The runner must migrate through 20260716007000, provision the capability
  externally with `tools/authority_bootstrap/bootstrap.ps1`, then run the
  verify-only 20260716008000 migration. It must provision distinct ordinary,
  authority, and migrator LOGINs, expose the migrator only through
  `AUTHORITY_MIGRATOR_DATABASE_URL`, make the authority LOGIN the executor's
  only PG16 SET-only member, revoke PUBLIC USAGE on schema `public`,
  configure runtime pools with size 1, and set
  `TAMANDUA_AUTHORITY_REPO_PG_TESTS=true`.
  `TAMANDUA_AUTHORITY_MIGRATION_REHEARSAL=true` additionally enables the
  destructive down/up/re-up rehearsal. Never point this harness at a shared,
  staging, or production database.
  """

  use ExUnit.Case, async: false

  alias TamanduaServer.{AuthorityAccess, AuthorityGuard, AuthorityRepo, Repo}

  defmodule HarnessMigratorRepo do
    @moduledoc false

    use Ecto.Repo,
      otp_app: :tamandua_server,
      adapter: Ecto.Adapters.Postgres
  end

  @executor "tamandua_authority_retention_executor"
  @owner "tamandua_authority_retention_owner"
  @function_name "public.authority_screen_evidence_retention_due_organization_ids"
  @function "public.authority_screen_evidence_retention_due_organization_ids(timestamp with time zone,integer)"
  @migration_version 20_260_716_008_000

  if System.get_env("TAMANDUA_AUTHORITY_REPO_PG_TESTS") != "true" do
    @moduletag skip:
                 "requires an explicitly disposable PostgreSQL 15+ authority-boundary database"
  end

  setup_all do
    if System.get_env("TAMANDUA_AUTHORITY_REPO_PG_TESTS") == "true" do
      migrator_url = System.fetch_env!("AUTHORITY_MIGRATOR_DATABASE_URL")
      start_supervised!({HarnessMigratorRepo, url: migrator_url, pool_size: 1})
    end

    :ok
  end

  test "three pools use distinct sessions on the same database and cluster" do
    assert Keyword.fetch!(AuthorityRepo.config(), :pool_size) == 1
    assert {:ok, authority_identity} = database_identity(AuthorityRepo)
    assert {:ok, ordinary_identity} = database_identity(Repo)
    assert {:ok, migrator_identity} = database_identity(HarnessMigratorRepo)
    assert :ok = AuthorityGuard.validate_pool_boundary(authority_identity, ordinary_identity)

    {authority_user, database, system_identifier} = authority_identity
    {ordinary_user, ^database, ^system_identifier} = ordinary_identity
    {migrator_user, ^database, ^system_identifier} = migrator_identity
    assert MapSet.size(MapSet.new([authority_user, ordinary_user, migrator_user])) == 3

    assert {:ok, %{rows: [[false, false, true]]}} =
             Repo.query(
               "SELECT pg_catalog.pg_has_role(session_user, $1, 'MEMBER'), pg_catalog.has_function_privilege(session_user, $2::pg_catalog.regprocedure, 'EXECUTE'), NOT role.rolbypassrls FROM pg_catalog.pg_roles role WHERE role.rolname = session_user",
               [@executor, @function]
             )

    # Known foundation blocker: the inherited helper still trusts this
    # self-settable GUC. Atomic helper hardening belongs to a later migration.
    assert {:ok, {:ok, %{rows: [["true"]]}}} =
             Repo.transaction(fn ->
               assert {:ok, _} = Repo.query("SET LOCAL app.rls_bypass = 'true'")
               Repo.query("SELECT pg_catalog.current_setting('app.rls_bypass', true)")
             end)
  end

  test "runtime login is denied before SET ROLE and executor is narrow after SET ROLE" do
    expected_login = Application.fetch_env!(:tamandua_server, :authority_database_role)

    assert {:error, _} =
             AuthorityRepo.query("SELECT organization_id FROM public.screen_capture_artifacts")

    assert {:error, _} =
             AuthorityRepo.query("SELECT organization_id FROM #{@function_name}($1, $2)", [
               DateTime.utc_now(),
               1
             ])

    assert {:ok,
            %{
              rows: [
                [
                  ^expected_login,
                  false,
                  true,
                  true,
                  true,
                  false,
                  false,
                  false,
                  false,
                  false,
                  ^@owner,
                  true,
                  ["search_path=pg_catalog", "app.rls_bypass=true"]
                ]
              ]
            }} = AuthorityRepo.query(catalog_contract_sql(), [@executor, @owner, @function])

    assert {:ok, :capability_ready} =
             AuthorityRepo.transaction(fn ->
               assert {:ok, _} = AuthorityRepo.query("SET LOCAL ROLE #{@executor}")

               assert {:ok, %{rows: [[@executor, true, true]]}} =
                        AuthorityRepo.query(
                          "SELECT current_user, pg_catalog.has_schema_privilege(current_user, 'public', 'USAGE'), pg_catalog.has_function_privilege(current_user, $1::pg_catalog.regprocedure, 'EXECUTE')",
                          [@function]
                        )

               :capability_ready
             end)

    assert_pool_reset(expected_login)

    assert {:error, :rollback_probe} =
             AuthorityRepo.transaction(fn ->
               assert {:ok, _} = AuthorityRepo.query("SET LOCAL ROLE #{@executor}")
               AuthorityRepo.rollback(:rollback_probe)
             end)

    assert_pool_reset(expected_login)
  end

  test "due/not-due fixtures cover artifacts, exports, and diffs" do
    as_of = DateTime.utc_now()

    fixtures =
      for kind <- [:artifact, :export, :diff], due? <- [true, false] do
        fixture = insert_fixture!(kind, due?, as_of)
        on_exit(fn -> delete_fixture!(fixture.organization_id) end)
        fixture
      end

    assert :ok = AuthorityAccess.startup_preflight()

    assert {:ok, organization_ids} =
             AuthorityAccess.discover_screen_evidence_retention_due_organization_ids(as_of, 1_000)

    for %{organization_id: organization_id, due?: due?} <- fixtures do
      assert organization_id in organization_ids == due?
    end

    assert organization_ids == Enum.sort(Enum.uniq(organization_ids))
    assert_pool_reset(Application.fetch_env!(:tamandua_server, :authority_database_role))
  end

  test "unexpected executor membership fails the use-time preflight" do
    migrator_query!("CREATE ROLE tamandua_authority_membership_poison NOLOGIN")
    migrator_query!("GRANT tamandua_authority_membership_poison TO #{@executor}")

    on_exit(fn ->
      migrator_query!("REVOKE tamandua_authority_membership_poison FROM #{@executor}")
      migrator_query!("DROP ROLE IF EXISTS tamandua_authority_membership_poison")
    end)

    assert {:error, :authority_identity_or_grant_preflight_failed} =
             AuthorityAccess.startup_preflight()
  end

  if System.get_env("TAMANDUA_AUTHORITY_MIGRATION_REHEARSAL") != "true" do
    @tag skip: "set TAMANDUA_AUTHORITY_MIGRATION_REHEARSAL=true only on a disposable database"
  end

  test "migration down is non-destructive and verify-only re-up rejects squatting" do
    authority_login = Application.fetch_env!(:tamandua_server, :authority_database_role)
    migration_path = Application.app_dir(:tamandua_server, "priv/repo/migrations")

    assert [@migration_version] =
             Ecto.Migrator.run(HarnessMigratorRepo, migration_path, :down, to: @migration_version)

    assert {:ok, %{rows: [[true, true]]}} =
             HarnessMigratorRepo.query(
               "SELECT to_regprocedure($1) IS NOT NULL, EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $2)",
               [@function, @owner]
             )

    assert [@migration_version] =
             Ecto.Migrator.run(HarnessMigratorRepo, migration_path, :up, to: @migration_version)

    migrator_query!("CREATE ROLE tamandua_authority_migration_poison NOLOGIN")
    migrator_query!("GRANT tamandua_authority_migration_poison TO #{@executor}")

    assert [@migration_version] =
             Ecto.Migrator.run(HarnessMigratorRepo, migration_path, :down, to: @migration_version)

    assert_raise Postgrex.Error, ~r/authority capability role is not pristine/, fn ->
      Ecto.Migrator.run(HarnessMigratorRepo, migration_path, :up, to: @migration_version)
    end

    migrator_query!("REVOKE tamandua_authority_migration_poison FROM #{@executor}")
    migrator_query!("DROP ROLE tamandua_authority_migration_poison")

    assert [@migration_version] =
             Ecto.Migrator.run(HarnessMigratorRepo, migration_path, :up, to: @migration_version)

    assert {:ok, %{rows: [[true]]}} =
             HarnessMigratorRepo.query(
               "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members membership JOIN pg_catalog.pg_roles role ON role.oid = membership.roleid JOIN pg_catalog.pg_roles member ON member.oid = membership.member WHERE role.rolname = $1 AND member.rolname = $2 AND NOT membership.admin_option AND NOT membership.inherit_option AND membership.set_option)",
               [@executor, authority_login]
             )
  end

  defp database_identity(repo) do
    case repo.query(
           "SELECT session_user, current_database(), system_identifier FROM pg_catalog.pg_control_system()"
         ) do
      {:ok, %{rows: [[user, database, system_identifier]]}} ->
        {:ok, {user, database, system_identifier}}

      result ->
        result
    end
  end

  defp catalog_contract_sql do
    """
    SELECT
      session_user,
      pg_catalog.has_schema_privilege(session_user, 'public', 'CREATE'),
      pg_catalog.has_schema_privilege(executor.oid, namespace.oid, 'USAGE'),
      pg_catalog.has_function_privilege(executor.oid, authority_function.oid, 'EXECUTE'),
      authority_function.prosecdef,
      executor.rolcanlogin,
      executor.rolsuper,
      executor.rolbypassrls,
      owner.rolcanlogin,
      owner.rolbypassrls,
      owner.rolname,
      NOT EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
        ) acl
        WHERE acl.grantee = 0 AND acl.privilege_type = 'USAGE'
      ),
      authority_function.proconfig
    FROM pg_catalog.pg_roles executor
    JOIN pg_catalog.pg_roles owner ON owner.rolname = $2
    JOIN pg_catalog.pg_namespace namespace ON namespace.nspname = 'public'
    JOIN pg_catalog.pg_proc authority_function ON authority_function.oid = $3::pg_catalog.regprocedure
    WHERE executor.rolname = $1
      AND authority_function.proowner = owner.oid
      AND NOT pg_catalog.has_function_privilege(session_user, authority_function.oid, 'EXECUTE')
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          COALESCE(
            authority_function.proacl,
            pg_catalog.acldefault('f', authority_function.proowner)
          )
        ) acl
        WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
      )
    """
  end

  defp insert_fixture!(kind, due?, as_of) do
    organization_id = Ecto.UUID.generate()
    agent_id = Ecto.UUID.generate()
    session_id = Ecto.UUID.generate()
    left_artifact_id = Ecto.UUID.generate()
    right_artifact_id = Ecto.UUID.generate()
    target_id = Ecto.UUID.generate()
    expires_at = DateTime.add(as_of, if(due?, do: -60, else: 3_600), :second)
    future = DateTime.add(as_of, 7_200, :second)
    now = DateTime.utc_now()
    slug = "authority-pg-#{organization_id}"

    migrator_transaction!(fn ->
      migrator_query!(
        "INSERT INTO public.organizations (id, name, slug, settings, inserted_at, updated_at) VALUES ($1, $2, $3, '{}'::jsonb, $4, $4)",
        [organization_id, slug, slug, now]
      )

      migrator_query!(
        "INSERT INTO public.agents (id, organization_id, hostname, os_type, status, config, tags, capabilities, inserted_at, updated_at) VALUES ($1, $2, $3, 'linux', 'offline', '{}'::jsonb, '{}', '{}', $4, $4)",
        [agent_id, organization_id, "fixture-#{agent_id}", now]
      )

      migrator_query!(
        "INSERT INTO public.screen_capture_evidence_sessions (id, organization_id, agent_id, status, reason, capture_request, frame_count, interval_seconds, next_frame_index, approval_status, expires_at, inserted_at, updated_at) VALUES ($1, $2, $3, 'scheduled', 'authority_pg_contract', '{}'::jsonb, 2, 5, 0, 'not_required', $4, $5, $5)",
        [session_id, organization_id, agent_id, future, now]
      )

      for {artifact_id, frame_index} <- [{left_artifact_id, 0}, {right_artifact_id, 1}] do
        migrator_query!(
          "INSERT INTO public.screen_capture_artifacts (id, organization_id, agent_id, evidence_session_id, frame_index, status, display, expires_at, inserted_at, updated_at) VALUES ($1, $2, $3, $4, $5, 'failed', 'all', $6, $7, $7)",
          [artifact_id, organization_id, agent_id, session_id, frame_index, future, now]
        )
      end

      insert_target!(
        kind,
        target_id,
        organization_id,
        agent_id,
        session_id,
        left_artifact_id,
        right_artifact_id,
        expires_at,
        now
      )
    end)

    %{organization_id: organization_id, due?: due?}
  end

  defp insert_target!(
         :artifact,
         id,
         organization_id,
         agent_id,
         _session_id,
         _left,
         _right,
         expires_at,
         now
       ) do
    migrator_query!(
      "INSERT INTO public.screen_capture_artifacts (id, organization_id, agent_id, status, display, expires_at, inserted_at, updated_at) VALUES ($1, $2, $3, 'ready', 'all', $4, $5, $5)",
      [id, organization_id, agent_id, expires_at, now]
    )
  end

  defp insert_target!(
         :export,
         id,
         organization_id,
         _agent_id,
         session_id,
         _left,
         _right,
         expires_at,
         now
       ) do
    migrator_query!(
      "INSERT INTO public.evidence_session_exports (id, organization_id, evidence_session_id, sha256, size, content, expires_at, inserted_at, updated_at) VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $7)",
      [id, organization_id, session_id, String.duplicate("0", 64), <<0>>, expires_at, now]
    )
  end

  defp insert_target!(
         :diff,
         id,
         organization_id,
         _agent_id,
         session_id,
         left,
         right,
         expires_at,
         now
       ) do
    migrator_query!(
      "INSERT INTO public.evidence_session_diffs (id, organization_id, evidence_session_id, left_artifact_id, right_artifact_id, metrics, expires_at, inserted_at, updated_at) VALUES ($1, $2, $3, $4, $5, '{}'::jsonb, $6, $7, $7)",
      [id, organization_id, session_id, left, right, expires_at, now]
    )
  end

  defp delete_fixture!(organization_id) do
    migrator_transaction!(fn ->
      migrator_query!("DELETE FROM public.organizations WHERE id = $1", [organization_id])
    end)
  end

  defp migrator_transaction!(fun) do
    assert {:ok, result} =
             HarnessMigratorRepo.transaction(fn ->
               migrator_query!("SET LOCAL app.rls_bypass = 'true'")
               fun.()
             end)

    result
  end

  defp migrator_query!(sql, params \\ []) do
    assert {:ok, result} = HarnessMigratorRepo.query(sql, params)
    result
  end

  defp assert_pool_reset(expected_login) do
    assert {:ok, %{rows: [[^expected_login, bypass]]}} =
             AuthorityRepo.query(
               "SELECT current_user, pg_catalog.current_setting('app.rls_bypass', true)"
             )

    assert bypass in [nil, "", "false"]
  end

end
