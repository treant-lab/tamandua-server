defmodule TamanduaServer.Repo.DecisionEngineAuthoritySourceTest do
  use ExUnit.Case, async: true

  @engine "lib/tamandua_server/response/decision_engine.ex"
  @access "lib/tamandua_server/decision_engine_authority_access.ex"
  @bootstrap "../../tools/authority_decision_engine_v1/bootstrap_v1.sql"
  @verify "../../tools/authority_decision_engine_v1/verify_v1.sql"

  test "restore and maintenance are UUID-only, bounded, keyset paged and fail closed" do
    engine = File.read!(@engine)
    access = File.read!(@access)
    bootstrap = File.read!(@bootstrap)

    refute engine =~ "with_bypass"
    assert access =~ "@page_limit 250"
    assert access =~ "@global_limit 5_000"
    assert access =~ "length(rows) <= @page_limit + 1"
    assert access =~ "id > previous"
    assert access =~ ":persistence_unavailable"
    assert bootstrap =~ "p_after uuid"
    assert bootstrap =~ "candidate.organization_id > p_after"
    assert bootstrap =~ "recommendation.organization_id > p_after"
    assert bootstrap =~ "ORDER BY candidate.organization_id ASC"
    assert bootstrap =~ "ORDER BY recommendation.organization_id ASC"
    assert bootstrap =~ "LIMIT p_limit + 1"
  end

  test "runtime restore and maintenance stay in exact tenant transactions" do
    engine = File.read!(@engine)

    assert engine =~ "DecisionEngineAuthorityAccess.discover_restore_organization_ids()"
    assert engine =~ "DecisionEngineAuthorityAccess.discover_maintenance_organization_ids()"
    assert engine =~ "MultiTenant.with_organization(organization_id, fn ->"
    assert engine =~ "Repo.transaction(fn ->"
    assert engine =~ "r.organization_id == ^organization_id"
    assert engine =~ "job.args->>'organization_id' = ?::text"
    assert engine =~ "restore_status: :degraded"
    assert engine =~ "autonomous_armed: MapSet.new()"
    assert engine =~ "state.restore_status == :ready"
  end

  test "roles, function ACL and receipt remain exact and external" do
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

    assert File.exists?("../../schemas/decision_engine_authority_receipt_v1.schema.json")
    assert File.exists?("../../tools/authority_decision_engine_v1/deprovision_v1.sql")

    assert File.read!("../../tools/authority_decision_engine_v1/verify.ps1") =~
             "DECISION_ENGINE_AUTHORITY_DATABASE_ROLE"
  end
end
