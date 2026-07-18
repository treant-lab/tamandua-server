defmodule TamanduaServer.Repo.MultiTenantFailClosedSourceTest do
  use ExUnit.Case, async: true

  @source Path.expand("../../../lib/tamandua_server/repo/multi_tenant.ex", __DIR__)

  test "with_organization never runs the callback after tenant context setup fails" do
    source = File.read!(@source)

    assert source =~ "case put_organization_id(organization_id) do"
    assert source =~ ":ok -> fun.()"

    assert source =~
             "{:error, reason} -> Repo.rollback({:tenant_context_unavailable, reason})"

    refute source =~ "put_organization_id(organization_id)\n        fun.()"
  end

  test "tenant context SQL only interpolates canonical UUIDs" do
    source = File.read!(@source)
    repo = File.read!(Path.expand("../../../lib/tamandua_server/repo.ex", __DIR__))

    assert source =~ "current_setting('app.current_organization_id', TRUE) = $1"
    assert source =~ "THEN set_config('app.current_organization_id', $1, TRUE)"
    assert source =~ "execute_sql(conn, sql, [org_id_string])"
    refute source =~ ~S|SET LOCAL app.current_organization_id = '#{org_id_string}'|

    assert repo =~ "Process.put(:current_organization_id, canonical_id)"
    assert repo =~ ~s|:error -> raise ArgumentError, "organization_id must be a valid UUID"|
    refute repo =~ ":error -> uuid"
    assert repo =~ ~s|raise "tenant context unavailable"|
    refute repo =~ ~S|Exception setting organization context: #{inspect(error)}|
  end

  test "nested tenant context cannot switch organizations" do
    source = File.read!(@source)

    assert source =~ "Repo.put_organization_id(organization_id)"

    assert source =~
             "previous_organization_id != nil and previous_organization_id != organization_id"

    assert source =~ ~s|raise ArgumentError, "nested organization context switch is not allowed"|
    assert source =~ "previous -> Repo.put_organization_id(previous)"
  end

  test "direct context writes and Ecto.Multi transactions reject cross-tenant nesting" do
    source = File.read!(@source)

    assert source =~ "{:error, :nested_organization_context_switch}"
    assert source =~ "def transaction(organization_id, %Ecto.Multi{} = multi)"
    assert length(Regex.scan(~r/nested organization context switch is not allowed/, source)) >= 3
    assert length(Regex.scan(~r/Repo\.put_organization_id\(organization_id\)/, source)) >= 2
    assert source =~ "{:error, :active_tenant_context}"
    assert source =~ "SELECT set_config('app.current_organization_id', '', TRUE)"
  end
end
