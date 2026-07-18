defmodule TamanduaServer.Repo.RemediationApprovalAuthoritySourceTest do
  use ExUnit.Case, async: true

  @manager "lib/tamandua_server/remediation/approval_manager.ex"
  @restore "lib/tamandua_server/remediation/approval_restore.ex"
  @execution "lib/tamandua_server/remediation/execution.ex"
  @playbook "lib/tamandua_server/remediation/playbook.ex"
  @access "lib/tamandua_server/remediation_approval_authority_access.ex"
  @bootstrap "../../tools/authority_remediation_approval_v1/bootstrap_v1.sql"
  @verify "../../tools/authority_remediation_approval_v1/verify_v1.sql"
  @deprovision "../../tools/authority_remediation_approval_v1/deprovision_v1.sql"
  @runtime "config/runtime.exs"

  test "authority is UUID-only, bounded, keyset paged, and fail closed" do
    access = File.read!(@access)
    bootstrap = File.read!(@bootstrap)

    assert access =~ "@page_limit 250"
    assert access =~ "@global_limit 5_000"
    assert access =~ "length(rows) <= @page_limit + 1"
    assert access =~ "id > previous"
    assert access =~ ":persistence_unavailable"
    assert bootstrap =~ "p_after uuid"
    assert bootstrap =~ "execution.organization_id > p_after"
    assert bootstrap =~ "ORDER BY execution.organization_id ASC"
    assert bootstrap =~ "LIMIT p_limit + 1"
  end

  test "restore re-enters exact tenant context and validates every reference all-or-nothing" do
    restore = File.read!(@restore)
    manager = File.read!(@manager)

    assert restore =~ "MultiTenant.with_organization(canonical_id, fn ->"
    assert restore =~ "e.organization_id == ^canonical_id"
    assert restore =~ "@tenant_limit 500"
    assert restore =~ "@global_limit 5_000"
    assert restore =~ "length(rows) <= @tenant_limit"
    assert restore =~ "new_count <= @global_limit"
    refute restore =~ "acc ++ executions"
    assert restore =~ "same_tenant?(Playbook"
    assert restore =~ "optional_same_tenant?(Agent"
    assert restore =~ "optional_same_tenant?(Alert"
    assert restore =~ "optional_same_tenant?(User"
    assert manager =~ "restore_status: :degraded"
    assert manager =~ "restore_status: :ready"
    assert manager =~ "restore_status: :disabled"
    refute manager =~ "Execution.list_pending_approvals(:system)"
  end

  test "generic system CRUD is closed and execution reference IDs are immutable" do
    execution = File.read!(@execution)
    playbook = File.read!(@playbook)

    for source <- [execution, playbook] do
      refute source =~ "scoped_query(:system)"
      refute source =~ "with_scope(:system"
      refute source =~ "authorize_resource(_resource, :system)"
    end

    assert execution =~ "preserve_resource_references"

    for field <- [":organization_id", ":playbook_id", ":agent_id", ":alert_id", ":triggered_by"] do
      assert execution =~ "put_attr(#{field}, execution."
    end
  end

  test "roles, ACL, source hash, scripts, schema, and runbook are exact" do
    access = File.read!(@access)
    bootstrap = File.read!(@bootstrap)
    verify = File.read!(@verify)

    for contract <- [
          "rolconfig IS NULL",
          "pg_auth_members",
          "admin_option",
          "inherit_option",
          "set_option",
          "has_schema_privilege",
          "pg_catalog.aclexplode",
          "acl.is_grantable",
          "prolang",
          "proconfig"
        ] do
      assert access =~ contract
      assert verify =~ contract or bootstrap =~ contract
    end

    assert access =~ "String.trim(source) == String.trim(@function_source)"
    assert verify =~ "md5(function_check.prosrc)"
    assert access =~ "executions.relrowsecurity AND executions.relforcerowsecurity"
    assert access =~ "has_any_column_privilege"
    assert access =~ "NOT proc.proisstrict"
    assert access =~ "candidate.proname = 'authority_remediation_approval_v1_organization_ids'"
    assert verify =~ "NOT p.proisstrict"
    assert verify =~ "candidate.proname = 'authority_remediation_approval_v1_organization_ids'"
    assert bootstrap =~ "authority function name is overloaded"
    assert bootstrap =~ "public schema has unexpected owner"
    assert access =~ "authority_remediation_approval_v1_select"
    assert bootstrap =~ "FOR SELECT TO tamandua_authority_remediation_approval_v1_owner"
    assert bootstrap =~ "USING (true)"
    assert bootstrap =~ "SET row_security = 'on'"
    refute bootstrap =~ "SET app.rls_bypass"
    refute access =~ "app.rls_bypass=true"

    assert File.exists?("../../schemas/remediation_approval_authority_receipt_v1.schema.json")
    assert File.exists?("../../tools/authority_remediation_approval_v1/deprovision_v1.sql")
    assert File.exists?("../../docs/security/REMEDIATION_APPROVAL_AUTHORITY_V1.md")

    assert File.read!("../../tools/authority_remediation_approval_v1/verify.ps1") =~
             "REMEDIATION_APPROVAL_AUTHORITY_DATABASE_ROLE"
  end

  test "runtime identity comparison is strict, canonical, default-off, and secret-safe" do
    runtime = File.read!(@runtime)

    assert runtime =~
             ~s(System.get_env("REMEDIATION_APPROVAL_AUTHORITY_REPO_ENABLED") == "true")

    assert runtime =~ "case URI.new(url)"
    assert runtime =~ ":inet.parse_address"
    assert runtime =~ "String.trim_trailing(\".\")"
    assert runtime =~ "uri.query != nil"
    assert runtime =~ "uri.fragment != nil"
    assert runtime =~ "user must exactly match"
    assert runtime =~ "identities must be pairwise distinct"
    assert runtime =~ "roles must be pairwise distinct"
    refute runtime =~ ~r/inspect\([^\n]*(?:database_url|identity)/i
  end

  test "deprovision verifies exact owned capability before ordered restrictive removal" do
    deprovision = File.read!(@deprovision)

    assert deprovision =~ "authority function missing, overloaded, or divergent"
    assert deprovision =~ "authority role membership is divergent"
    assert deprovision =~ "authority schema ACL is divergent"
    assert deprovision =~ "authority relation ACL is divergent"
    assert deprovision =~ "authority function ACL is divergent"
    assert deprovision =~ "authority roles own unexpected objects or default privileges"

    membership_revoke =
      "REVOKE tamandua_authority_remediation_approval_v1_executor FROM"

    function_drop =
      "DROP FUNCTION public.authority_remediation_approval_v1_organization_ids(uuid, integer);"

    executor_drop = "DROP ROLE tamandua_authority_remediation_approval_v1_executor;"
    owner_drop = "DROP ROLE tamandua_authority_remediation_approval_v1_owner;"

    assert byte_offset(deprovision, membership_revoke) < byte_offset(deprovision, function_drop)
    assert byte_offset(deprovision, function_drop) < byte_offset(deprovision, executor_drop)
    assert byte_offset(deprovision, executor_drop) < byte_offset(deprovision, owner_drop)
    refute deprovision =~ "DROP OWNED"
    refute deprovision =~ "CASCADE"
  end

  defp byte_offset(source, needle) do
    {offset, _length} = :binary.match(source, needle)
    offset
  end
end
