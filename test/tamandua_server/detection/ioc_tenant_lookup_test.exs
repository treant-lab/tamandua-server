defmodule TamanduaServer.Detection.IOCTenantLookupTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Detection.{IOC, IOCs}
  alias TamanduaServer.Repo

  test "tenant lookup exposes global plus current tenant and never another tenant" do
    org_a = insert(:organization)
    org_b = insert(:organization)

    global = insert_ioc!(nil, "global-#{System.unique_integer([:positive])}.test")
    private_a = insert_ioc!(org_a.id, "a-#{System.unique_integer([:positive])}.test")
    private_b = insert_ioc!(org_b.id, "b-#{System.unique_integer([:positive])}.test")

    assert {:ok, %{id: global_id}} =
             IOCs.lookup_for_organization("domain", global.value, org_a.id)

    assert global_id == global.id

    assert {:ok, %{id: private_a_id}} =
             IOCs.lookup_for_organization("domain", private_a.value, org_a.id)

    assert private_a_id == private_a.id

    assert {:error, :not_found} =
             IOCs.lookup_for_organization("domain", private_b.value, org_a.id)

    assert {:error, :not_found} = IOCs.lookup("domain", private_a.value)
    assert {:error, :not_found} = IOCs.lookup_for_organization("domain", private_a.value, nil)
  end

  test "batch matching does not return another tenant's private indicator" do
    org_a = insert(:organization)
    org_b = insert(:organization)
    private_b = insert_ioc!(org_b.id, "batch-b-#{System.unique_integer([:positive])}.test")

    indicators = [{"domain", private_b.value}]

    assert [] == IOCs.match_batch_for_organization(indicators, org_a.id)
    assert [] == IOCs.match_batch(indicators)
    assert [%{id: id}] = IOCs.match_batch_for_organization(indicators, org_b.id)
    assert id == private_b.id
  end

  defp insert_ioc!(organization_id, value) do
    %IOC{}
    |> IOC.changeset(%{
      type: "domain",
      value: value,
      source: "tenant-scope-test",
      organization_id: organization_id,
      enabled: true
    })
    |> Repo.insert!()
  end
end
