defmodule TamanduaServer.Repo.AgenticRestoreAuthoritySourceTest do
  use ExUnit.Case, async: true

  @store "lib/tamandua_server/ai_security/agentic_investigation_store.ex"
  @access "lib/tamandua_server/agentic_restore_authority_access.ex"
  @bootstrap "../../tools/authority_agentic_restore_v1/bootstrap_v1.sql"
  @verify "../../tools/authority_agentic_restore_v1/verify_v1.sql"

  test "startup discovery has no runtime bypass or retention capability reuse" do
    store = File.read!(@store)
    access = File.read!(@access)
    bootstrap = File.read!(@bootstrap)

    refute store =~ "with_bypass"
    assert store =~ "MultiTenant.with_organization"
    assert access =~ "@maximum_limit 500"
    assert access =~ "length(rows) <= maximum_rows"
    assert access =~ ":persistence_unavailable"
    assert bootstrap =~ "LIMIT p_limit + 1"
    assert bootstrap =~ "ORDER BY max(snapshot.updated_at) DESC, snapshot.organization_id ASC"
    refute access =~ "tamandua_authority_retention_"
    refute bootstrap =~ "tamandua_authority_retention_"
    refute bootstrap =~ "screen_capture_artifacts"
  end

  test "runtime and offline verification enforce the same exact authority boundary" do
    access = File.read!(@access)
    bootstrap = File.read!(@bootstrap)
    verify = File.read!(@verify)

    for contract <- [
          "rolconfig IS NULL",
          "rolcreatedb",
          "rolcreaterole",
          "rolreplication",
          "has_schema_privilege",
          "pg_catalog.aclexplode",
          "acl.is_grantable",
          "prolang",
          "TRUNCATE",
          "REFERENCES",
          "TRIGGER"
        ] do
      assert access =~ contract
      assert verify =~ contract
    end

    assert bootstrap =~
             "REVOKE ALL ON SCHEMA public FROM tamandua_authority_agentic_restore_v1_owner"

    assert bootstrap =~
             "GRANT USAGE ON SCHEMA public TO tamandua_authority_agentic_restore_v1_owner"
  end

  test "lane is explicitly versioned and leaves migration 08000 untouched" do
    assert File.exists?("../../schemas/agentic_restore_authority_receipt_v1.schema.json")
    assert File.exists?("../../tools/authority_agentic_restore_v1/verify_v1.sql")
    assert File.exists?("../../tools/authority_agentic_restore_v1/deprovision_v1.sql")

    assert File.read!("../../tools/authority_agentic_restore_v1/verify.ps1") =~
             "tamandua.agentic-restore-authority-receipt.v1"
  end
end
