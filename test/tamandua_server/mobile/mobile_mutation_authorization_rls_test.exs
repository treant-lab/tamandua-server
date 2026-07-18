defmodule TamanduaServer.Mobile.MobileMutationAuthorizationRLSTest do
  use ExUnit.Case, async: true

  @migration Path.expand(
               "../../../priv/repo/migrations/20260717003000_create_mobile_mutation_authorizations.exs",
               __DIR__
             )

  test "migration forces tenant-scoped row-level security for mutation authorizations" do
    source = File.read!(@migration)

    enable_position =
      source
      |> :binary.match("ALTER TABLE mobile_mutation_authorizations ENABLE ROW LEVEL SECURITY")
      |> elem(0)

    force_position =
      source
      |> :binary.match("ALTER TABLE mobile_mutation_authorizations FORCE ROW LEVEL SECURITY")
      |> elem(0)

    policy_position =
      source
      |> :binary.match("CREATE POLICY mobile_mutation_authorizations_tenant_isolation")
      |> elem(0)

    assert source =~
             "ALTER TABLE mobile_mutation_authorizations ENABLE ROW LEVEL SECURITY"

    assert source =~
             "ALTER TABLE mobile_mutation_authorizations FORCE ROW LEVEL SECURITY"

    assert source =~ "CREATE POLICY mobile_mutation_authorizations_tenant_isolation"
    assert source =~ "ON mobile_mutation_authorizations"
    assert source =~ "FOR ALL TO PUBLIC"
    assert source =~ "USING (organization_id = current_organization_id())"
    assert source =~ "WITH CHECK (organization_id = current_organization_id())"
    refute source =~ "rls_bypass_enabled"
    assert enable_position < force_position
    assert force_position < policy_position
    assert length(Regex.scan(~r/\bexecute\(/, source)) == 3
  end

  test "migration defines a reversible policy teardown" do
    source = File.read!(@migration)

    assert source =~
             "DROP POLICY IF EXISTS mobile_mutation_authorizations_tenant_isolation"

    assert source =~
             "ALTER TABLE mobile_mutation_authorizations NO FORCE ROW LEVEL SECURITY"

    assert source =~
             "ALTER TABLE mobile_mutation_authorizations DISABLE ROW LEVEL SECURITY"
  end

  test "migration module owns the exact policy catalog name" do
    source = File.read!(@migration)

    assert source =~
             "defmodule TamanduaServer.Repo.Migrations.CreateMobileMutationAuthorizations"

    assert length(:binary.matches(source, "mobile_mutation_authorizations_tenant_isolation")) == 2
  end
end
