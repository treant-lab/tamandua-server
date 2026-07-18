defmodule TamanduaServer.Repo.AuthorityExternalBootstrapSourceTest do
  use ExUnit.Case, async: true

  @tools "../../tools/authority_bootstrap"

  test "operator scripts use only the dedicated bootstrap URL and immutable receipts" do
    common = File.read!(Path.join(@tools, "AuthorityBootstrap.Common.ps1"))
    bootstrap = File.read!(Path.join(@tools, "bootstrap.ps1"))
    verify = File.read!(Path.join(@tools, "verify.ps1"))

    assert common =~ "BOOTSTRAP_DATABASE_URL"
    refute common =~ "AUTHORITY_DATABASE_URL"
    assert common =~ "[IO.FileMode]::CreateNew"
    assert common =~ "AUTHORITY_RECEIPT_DIRECTORY"
    assert common =~ "without directories"
    assert common =~ "AUTHORITY_BOOTSTRAP_SOURCE_SHA"
    assert common =~ "16384"
    assert bootstrap =~ "authority_bootstrap.sql"
    assert verify =~ "authority_verify.sql"
    refute bootstrap =~ "Write-Output $bootstrapUrl"
    refute verify =~ "Write-Output $bootstrapUrl"
  end

  test "bootstrap is PG16, least privilege, idempotent, and fail closed" do
    sql = File.read!(Path.join(@tools, "authority_bootstrap.sql"))

    assert sql =~ "server_version_num"
    assert sql =~ "160000"
    assert sql =~ "prerequisite tables are missing"
    assert sql =~ "external cluster-owner session"
    assert sql =~ "NOLOGIN NOINHERIT NOSUPERUSER"
    assert sql =~ "WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"
    assert sql =~ "CREATE OR REPLACE FUNCTION"
    assert sql =~ "SECURITY DEFINER"
    assert sql =~ "SET search_path = pg_catalog"
    assert sql =~ "REVOKE ALL ON FUNCTION"
    assert sql =~ "acl.is_grantable"
    assert sql =~ "FROM PUBLIC"
    assert sql =~ "REVOKE ALL ON public.screen_capture_artifacts"
    assert sql =~ "authority capability role is squatted"
    refute sql =~ "AUTHORITY_DATABASE_URL"
  end

  test "deprovision is explicit, ordered, and never delegated to migration down" do
    wrapper = File.read!(Path.join(@tools, "deprovision.ps1"))
    sql = File.read!(Path.join(@tools, "authority_deprovision.sql"))

    assert wrapper =~ "AUTHORITY_DEPROVISION_CONFIRMED"
    assert wrapper =~ "disabled-drained-and-backed-up"
    assert wrapper =~ "authority_verify.sql"
    assert byte_index(sql, "REVOKE tamandua_authority_retention_executor") <
             byte_index(sql, "DROP FUNCTION")

    assert byte_index(sql, "DROP FUNCTION") < byte_index(sql, "DROP ROLE")
  end

  defp byte_index(source, needle) do
    {index, _length} = :binary.match(source, needle)
    index
  end
end
