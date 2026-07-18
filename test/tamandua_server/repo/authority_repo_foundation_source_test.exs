defmodule TamanduaServer.Repo.AuthorityRepoFoundationSourceTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.AuthorityAccess
  alias TamanduaServer.AuthorityGuard
  alias TamanduaServer.AuthorityRepo

  @migration "priv/repo/migrations/20260716008000_create_retention_authority_capability.exs"

  test "authority pool and facade are default-off before database access" do
    previous = Application.get_env(:tamandua_server, :authority_repo_enabled)
    Application.put_env(:tamandua_server, :authority_repo_enabled, false)

    on_exit(fn ->
      if is_nil(previous),
        do: Application.delete_env(:tamandua_server, :authority_repo_enabled),
        else: Application.put_env(:tamandua_server, :authority_repo_enabled, previous)
    end)

    refute AuthorityRepo.enabled?()

    assert {:error, :authority_repo_disabled} =
             AuthorityAccess.discover_screen_evidence_retention_due_organization_ids(
               DateTime.utc_now(),
               100
             )
  end

  test "facade exposes one bounded typed operation and no callback" do
    source = File.read!("lib/tamandua_server/authority_access.ex")

    assert source =~ "discover_screen_evidence_retention_due_organization_ids"
    assert source =~ "@maximum_limit 1_000"
    refute source =~ "is_function"
    refute source =~ "TamanduaServer.Repo"
    refute source =~ "with_bypass"
    refute source =~ "SELECT *"
  end

  test "guard requires distinct users on the same database and cluster" do
    assert :ok =
             AuthorityGuard.validate_pool_boundary(
               {"tamandua_authority", "tamandua", 42},
               {"tamandua_app", "tamandua", 42}
             )

    for {authority, ordinary} <- [
          {{"shared_login", "tamandua", 42}, {"shared_login", "tamandua", 42}},
          {{"tamandua_authority", "authority_db", 42}, {"tamandua_app", "tamandua", 42}},
          {{"tamandua_authority", "tamandua", 41}, {"tamandua_app", "tamandua", 42}}
        ] do
      assert {:error, :authority_database_boundary_mismatch} =
               AuthorityGuard.validate_pool_boundary(authority, ordinary)
    end

    guard = File.read!("lib/tamandua_server/authority_guard.ex")

    assert guard =~
             "SELECT session_user, current_database(), system_identifier FROM pg_catalog.pg_control_system()"

    assert guard =~ "database_identity(AuthorityRepo)"
    assert guard =~ "database_identity(Repo)"
  end

  test "preflight requires PG16 SET-only executor membership and an unreachable owner" do
    source = File.read!("lib/tamandua_server/authority_access.ex")

    assert source =~ "capability_membership.member = login_role.oid"
    assert source =~ "capability_membership.member <> login_role.oid"
    assert source =~ "NOT capability_membership.admin_option"
    assert source =~ "NOT capability_membership.inherit_option"
    assert source =~ "capability_membership.set_option"
    assert source =~ "owner_membership.roleid = function_owner.oid"
    assert source =~ "owner_membership.member = function_owner.oid"
    assert source =~ "has_schema_privilege(current_user, 'public', 'USAGE')"
    assert source =~ "schema_acl.is_grantable"
    assert source =~ "authority_function.prosecdef"
    assert source =~ "authority_function.provolatile = 's'"
    assert source =~ "authority_function.proconfig @>"
    assert source =~ "function_acl.grantee NOT IN"
    assert source =~ "function_acl.is_grantable"
    assert source =~ "artifact_acl.privilege_type = 'SELECT'"
  end

  test "migration is a verify-only adoption fence" do
    source = File.read!(@migration)

    assert source =~ "verify-only"
    assert source =~ "server_version_num"
    assert source =~ "authority_function.prosecdef"
    assert source =~ "search_path=pg_catalog"
    assert source =~ "app.rls_bypass=true"
    assert source =~ "screen_capture_artifacts"
    assert source =~ "evidence_session_exports"
    assert source =~ "evidence_session_diffs"
    refute source =~ "screen_capture_evidence_sessions"
    assert source =~ "pg_catalog.pg_auth_members"
    assert source =~ "inherit_option"
    assert source =~ "set_option"
    assert source =~ "def down, do: :ok"

    for forbidden <- ["CREATE ROLE", "ALTER ROLE", "DROP ROLE", "GRANT CREATE", "GRANT tamandua"] do
      refute source =~ forbidden
    end
  end

  test "runtime config requires a distinct authority URL and bounded pool" do
    source = File.read!("config/runtime.exs")
    application = File.read!("lib/tamandua_server/application.ex")

    assert source =~ "AUTHORITY_DATABASE_URL"
    assert source =~ "authority_database_url == database_url"
    assert source =~ "AUTHORITY_POOL_SIZE must be between 1 and 5"
    assert application =~ "TamanduaServer.AuthorityGuard"

    assert File.read!("lib/tamandua_server/authority_guard.ex") =~
             "validate_pool_boundary("

    refute application =~ "authority_repo_startup_preflight"
  end

  test "enabled authority guard blocks startup synchronously on invalid preflight" do
    previous_enabled = Application.get_env(:tamandua_server, :authority_repo_enabled)
    previous_role = Application.get_env(:tamandua_server, :authority_database_role)
    Application.put_env(:tamandua_server, :authority_repo_enabled, true)
    Application.put_env(:tamandua_server, :authority_database_role, "missing_authority_login")

    on_exit(fn ->
      restore_env(:authority_repo_enabled, previous_enabled)
      restore_env(:authority_database_role, previous_role)
    end)

    assert {:error, {:authority_repository_preflight_failed, :authority_repository_unavailable}} =
             AuthorityGuard.start_link()

    assert {:error,
            {:shutdown,
             {:failed_to_start_child, AuthorityGuard,
              {:authority_repository_preflight_failed, :authority_repository_unavailable}}}} =
             Supervisor.start_link([AuthorityGuard], strategy: :one_for_one)
  end

  defp restore_env(key, nil), do: Application.delete_env(:tamandua_server, key)
  defp restore_env(key, value), do: Application.put_env(:tamandua_server, key, value)
end
