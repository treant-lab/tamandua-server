defmodule TamanduaServer.IocSnapshotAuthoritySourceTest do
  use ExUnit.Case, async: true

  @root Path.expand("../../..", __DIR__)

  test "authority provider is default-off and wired only through the provider facade" do
    repo = source("lib/tamandua_server/ioc_snapshot_authority_repo.ex")
    access = source("lib/tamandua_server/ioc_snapshot_authority_access.ex")
    app = source("lib/tamandua_server/application.ex")
    reload = source("lib/tamandua_server/detection/ioc_reload.ex")

    assert repo =~ ":ioc_snapshot_authority_repo_enabled, false"
    assert access =~ ":ioc_snapshot_authority_repo"
    assert access =~ "REPEATABLE READ READ ONLY"
    assert access =~ "SET LOCAL statement_timeout = '5s'"
    assert access =~ "SET LOCAL lock_timeout = '1s'"
    assert access =~ "payload_bytes(canonical) <= row_bytes"
    assert access =~ "iocs.relrowsecurity AND iocs.relforcerowsecurity"
    assert access =~ "SELECT WITH GRANT OPTION"
    assert access =~ "pg_catalog.aclexplode"
    assert access =~ "String.trim(source) == String.trim(@function_source)"
    assert access =~ "'app.rls_bypass=off'"
    assert access =~ "candidate.prosecdef"
    assert app =~ "IocSnapshotAuthorityRepo.enabled?()"
    assert app =~ "IOCSnapshotProvider.initialize!()"
    refute reload =~ "IocSnapshotAuthorityAccess"
    refute access =~ "app.rls_bypass=on"
    refute access =~ "app.rls_bypass = 'on'"
  end

  test "external SQL exposes one exact bounded function without bypass helper" do
    bootstrap = external("bootstrap_v1.sql")
    verify = external("verify_v1.sql")

    for sql <- [bootstrap, verify] do
      assert sql =~ "tamandua_authority_ioc_snapshot_v1_owner"
      assert sql =~ "tamandua_authority_ioc_snapshot_v1_executor"
      assert sql =~ "authority_ioc_snapshot_v1(bigint,uuid,integer)"
      refute sql =~ "app.rls_bypass=on"
      refute sql =~ "app.rls_bypass = 'on'"
    end

    assert bootstrap =~ "FOR SELECT TO tamandua_authority_ioc_snapshot_v1_owner USING (true)"
    assert bootstrap =~ "p_limit > 1000"
    assert bootstrap =~ "> 65536"
    assert bootstrap =~ "IOC snapshot epoch mismatch"
    assert bootstrap =~ "ORDER BY candidate.id ASC"
    assert verify =~ "polroles = ARRAY[owner_oid]"
    assert verify =~ "relrowsecurity AND relforcerowsecurity"
    assert verify =~ "has_any_column_privilege"
    assert verify =~ "SELECT WITH GRANT OPTION"
    assert verify =~ "pg_get_function_result"
    assert verify =~ "btrim(function.prosrc)"
    assert verify =~ "app.rls_bypass=off"
    assert verify =~ "another SECURITY DEFINER function"
  end

  test "receipt writer is exclusive, atomic, reparse-safe and suppresses database diagnostics" do
    common = external("AuthorityIocSnapshotV1.Common.ps1")

    assert common =~ "must already exist as a protected directory"
    assert common =~ "[IO.FileAttributes]::ReparsePoint"
    assert common =~ "[IO.FileMode]::CreateNew"
    assert common =~ ".Flush($true)"
    assert common =~ "[IO.File]::Move($temporary, $target)"
    assert common =~ "database diagnostics are suppressed"
    refute common =~ "SQL failed: $bounded"
  end

  test "hard client caps and canonical digest fields remain source asserted" do
    access = source("lib/tamandua_server/ioc_snapshot_authority_access.ex")
    digest = source("lib/tamandua_server/ioc_snapshot_digest.ex")

    assert access =~ "@page_size 1_000"
    assert access =~ "@maximum_rows 100_000"
    assert access =~ "@maximum_bytes 64 * 1024 * 1024"
    assert access =~ "@maximum_row_bytes 64 * 1024"
    assert access =~ "@wall_timeout_ms 30_000"
    assert digest =~ "[:id, :organization_id, :type, :value, :severity, :description, :source]"
    assert digest =~ "tamandua.ioc-snapshot.v1"
    assert digest =~ "<<value::unsigned-big-integer-size(64)>>"
  end

  defp source(relative), do: File.read!(Path.join(@root, relative))

  defp external(relative) do
    File.read!(Path.expand("../../../../../tools/authority_ioc_snapshot_v1/#{relative}", __DIR__))
  end
end
