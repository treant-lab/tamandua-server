defmodule TamanduaServer.Detection.IOCRuntimeScopeSourceTest do
  use ExUnit.Case, async: true

  @root Path.expand("../../..", __DIR__)

  test "reload preserves scope and uses an explicit audited bypass" do
    engine = File.read!(Path.join(@root, "lib/tamandua_server/detection/engine.ex"))

    assert engine =~ "Repo.MultiTenant.with_bypass"
    assert engine =~ "organization_id: i.organization_id"
    assert engine =~ "scope = if ioc.organization_id"
    assert engine =~ "{{scope, type, value}"
  end

  test "worker uses agent authority and direct reads from the active IOC table" do
    worker = File.read!(Path.join(@root, "lib/tamandua_server/detection/engine_worker.ex"))

    assert worker =~ "lookup_iocs(event)"
    assert worker =~ "OrgLookup.get_org_id"
    assert worker =~ "RuleLoader.with_ioc_snapshot"
    assert worker =~ ":ets.lookup(table, {{:tenant, organization_id}, type, value})"
    refute worker =~ ":ets.tab2list(:detection_ioc_rules)"
  end

  test "writes require explicit tenant or system-global scope" do
    iocs = File.read!(Path.join(@root, "lib/tamandua_server/detection/iocs.ex"))

    assert iocs =~ "{:error, :organization_required}"
    assert iocs =~ "def add_global"
    assert iocs =~ "def bulk_add_global"
    assert iocs =~ "{:error, :mixed_ioc_scopes}"
    assert iocs =~ "{:error, :ioc_scope_required}"
    assert iocs =~ "[:type, :value, :organization_id]"
    assert iocs =~ "ioc_partial_global_unique_index"
  end
end
