defmodule TamanduaServer.Repo.Migrations.CreateRetentionAuthorityCapability do
  use Ecto.Migration

  @moduledoc """
  Verify-only adoption fence for the externally provisioned retention authority.

  Cluster roles and the security-definer capability are provisioned by the
  dedicated bootstrap operator after prerequisite tables exist. Application
  migrations never acquire role ownership or mutate cluster authority.
  """

  def up do
    execute("""
    DO $$
    DECLARE
      executor_oid oid;
      owner_oid oid;
      authority_login_oid oid;
      function_oid oid;
      table_name text;
    BEGIN
      IF pg_catalog.current_setting('server_version_num')::integer < 160000 THEN
        RAISE EXCEPTION 'retention authority requires PostgreSQL 16 or newer';
      END IF;

      SELECT oid INTO executor_oid
      FROM pg_catalog.pg_roles
      WHERE rolname = 'tamandua_authority_retention_executor'
        AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
        AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication
        AND NOT rolbypassrls AND rolconnlimit = -1 AND rolconfig IS NULL;

      SELECT oid INTO owner_oid
      FROM pg_catalog.pg_roles
      WHERE rolname = 'tamandua_authority_retention_owner'
        AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
        AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication
        AND NOT rolbypassrls AND rolconnlimit = -1 AND rolconfig IS NULL;

      IF executor_oid IS NULL OR owner_oid IS NULL THEN
        RAISE EXCEPTION 'retention authority roles are missing or have unexpected attributes';
      END IF;

      IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members
        WHERE roleid = owner_oid OR member = owner_oid OR member = executor_oid
      ) THEN
        RAISE EXCEPTION 'retention authority owner or executor has unexpected memberships';
      END IF;

      SELECT membership.member INTO authority_login_oid
      FROM pg_catalog.pg_auth_members membership
      WHERE membership.roleid = executor_oid
        AND NOT membership.admin_option
        AND NOT membership.inherit_option
        AND membership.set_option;

      IF authority_login_oid IS NULL OR (
        SELECT count(*) FROM pg_catalog.pg_auth_members WHERE roleid = executor_oid
      ) <> 1 THEN
        RAISE EXCEPTION 'retention authority executor membership is not exclusive and SET-only';
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE oid = authority_login_oid AND rolcanlogin AND NOT rolsuper
          AND NOT rolinherit AND NOT rolcreatedb AND NOT rolcreaterole
          AND NOT rolreplication AND NOT rolbypassrls
      ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members
        WHERE member = authority_login_oid AND roleid <> executor_oid
      ) THEN
        RAISE EXCEPTION 'retention authority login has unexpected attributes or memberships';
      END IF;

      IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members
        WHERE member = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
           OR roleid = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
      ) THEN
        RAISE EXCEPTION 'migration login must not have role memberships';
      END IF;

      function_oid := pg_catalog.to_regprocedure(
        'public.authority_screen_evidence_retention_due_organization_ids(timestamp with time zone,integer)'
      );

      IF function_oid IS NULL OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc authority_function
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = authority_function.pronamespace
        WHERE authority_function.oid = function_oid
          AND namespace.nspname = 'public'
          AND authority_function.proowner = owner_oid
          AND authority_function.prosecdef
          AND authority_function.provolatile = 's'
          AND authority_function.prolang = (
            SELECT oid FROM pg_catalog.pg_language WHERE lanname = 'sql'
          )
          AND authority_function.prorettype = 'uuid'::pg_catalog.regtype
          AND authority_function.proretset
          AND authority_function.proconfig @> ARRAY[
            'search_path=pg_catalog', 'app.rls_bypass=true'
          ]
          AND pg_catalog.array_length(authority_function.proconfig, 1) = 2
      ) THEN
        RAISE EXCEPTION 'retention authority function catalog contract is invalid';
      END IF;

      IF NOT pg_catalog.has_function_privilege(executor_oid, function_oid, 'EXECUTE')
         OR EXISTS (
           SELECT 1
           FROM pg_catalog.pg_namespace namespace,
                LATERAL pg_catalog.aclexplode(
                  COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
                ) acl
           WHERE namespace.nspname = 'public'
             AND acl.grantee = 0 AND acl.privilege_type = 'USAGE'
         )
         OR NOT pg_catalog.has_schema_privilege(executor_oid, 'public', 'USAGE')
         OR pg_catalog.has_schema_privilege(executor_oid, 'public', 'CREATE')
         OR NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_namespace namespace,
                LATERAL pg_catalog.aclexplode(
                  COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
                ) acl
           WHERE namespace.nspname = 'public' AND acl.grantee = executor_oid
             AND acl.privilege_type = 'USAGE' AND NOT acl.is_grantable
         )
         OR EXISTS (
           SELECT 1
           FROM pg_catalog.pg_namespace namespace,
                LATERAL pg_catalog.aclexplode(
                  COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
                ) acl
           WHERE namespace.nspname = 'public' AND acl.grantee = executor_oid
             AND (acl.privilege_type <> 'USAGE' OR acl.is_grantable)
         )
         OR EXISTS (
           SELECT 1
           FROM pg_catalog.aclexplode(
             COALESCE((SELECT proacl FROM pg_catalog.pg_proc WHERE oid = function_oid),
                      pg_catalog.acldefault('f', owner_oid))
           ) acl
           WHERE acl.privilege_type = 'EXECUTE'
             AND (acl.grantee NOT IN (owner_oid, executor_oid)
                  OR (acl.grantee = executor_oid AND acl.is_grantable))
         )
         OR NOT EXISTS (
           SELECT 1
           FROM pg_catalog.aclexplode(
             COALESCE((SELECT proacl FROM pg_catalog.pg_proc WHERE oid = function_oid),
                      pg_catalog.acldefault('f', owner_oid))
           ) acl
           WHERE acl.grantee = executor_oid AND acl.privilege_type = 'EXECUTE'
             AND NOT acl.is_grantable
         ) THEN
        RAISE EXCEPTION 'retention authority function ACL is invalid';
      END IF;

      FOREACH table_name IN ARRAY ARRAY[
        'screen_capture_artifacts', 'evidence_session_exports', 'evidence_session_diffs'
      ] LOOP
        IF pg_catalog.to_regclass('public.' || table_name) IS NULL
           OR NOT pg_catalog.has_table_privilege(owner_oid, 'public.' || table_name, 'SELECT')
           OR NOT EXISTS (
             SELECT 1
             FROM pg_catalog.pg_class relation,
                  LATERAL pg_catalog.aclexplode(
                    COALESCE(relation.relacl,
                             pg_catalog.acldefault('r', relation.relowner))
                  ) acl
             WHERE relation.oid = pg_catalog.to_regclass('public.' || table_name)
               AND acl.grantee = owner_oid AND acl.privilege_type = 'SELECT'
               AND NOT acl.is_grantable
           )
           OR pg_catalog.has_table_privilege(owner_oid, 'public.' || table_name, 'INSERT')
           OR pg_catalog.has_table_privilege(owner_oid, 'public.' || table_name, 'UPDATE')
           OR pg_catalog.has_table_privilege(owner_oid, 'public.' || table_name, 'DELETE')
           OR pg_catalog.has_table_privilege(owner_oid, 'public.' || table_name, 'TRUNCATE')
           OR pg_catalog.has_table_privilege(owner_oid, 'public.' || table_name, 'REFERENCES')
           OR pg_catalog.has_table_privilege(owner_oid, 'public.' || table_name, 'TRIGGER') THEN
          RAISE EXCEPTION 'retention authority table contract is invalid for %', table_name;
        END IF;
      END LOOP;
    END
    $$
    """)
  end

  # Authority deprovisioning is an explicit drained operator action. Migration
  # rollback intentionally cannot remove shared cluster roles or capabilities.
  def down, do: :ok
end
