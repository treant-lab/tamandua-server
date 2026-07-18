defmodule TamanduaServer.ThreatIntel.AttributionTenantIsolationTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.ThreatIntel.Attribution
  alias TamanduaServer.ThreatIntel.ThreatActor
  alias TamanduaServer.Repo.MultiTenant

  @org_a "11111111-1111-4111-8111-111111111111"
  @org_b "22222222-2222-4222-8222-222222222222"

  test "legacy campaign APIs fail closed" do
    assert Attribution.list_campaigns() == {:error, :organization_required}
    assert Attribution.list_campaigns([]) == {:error, :organization_required}
    assert Attribution.get_campaign("campaign") == {:error, :organization_required}
    assert Attribution.upsert_campaign(%{}) == {:error, :organization_required}

    assert Attribution.link_iocs_to_campaign("campaign", []) ==
             {:error, :organization_required}

    assert Attribution.get_actor_profile("actor") == {:error, :organization_required}
    assert Attribution.get_stats() == {:error, :organization_required}
  end

  test "campaign data and stats remain isolated between organizations" do
    id = "attribution-tenant-#{System.unique_integer([:positive])}"

    on_exit(fn ->
      :ets.delete(:attribution_campaigns, {@org_a, id})
      :ets.delete(:attribution_campaigns, {@org_b, id})
    end)

    assert {:ok, campaign_a} =
             Attribution.upsert_campaign(@org_a, %{
               "id" => id,
               "name" => "Tenant A",
               "actors" => ["Actor A"]
             })

    assert {:ok, campaign_b} =
             Attribution.upsert_campaign(@org_b, %{
               "id" => id,
               "name" => "Tenant B",
               "actors" => ["Actor B"]
             })

    assert campaign_a.organization_id == @org_a
    assert campaign_b.organization_id == @org_b
    assert {:ok, %{name: "Tenant A"}} = Attribution.get_campaign(@org_a, id)
    assert {:ok, %{name: "Tenant B"}} = Attribution.get_campaign(@org_b, id)

    assert Enum.any?(
             Attribution.list_campaigns(@org_a, []),
             &(&1.id == id and &1.name == "Tenant A")
           )

    refute Enum.any?(
             Attribution.list_campaigns(@org_a, []),
             &(&1.id == id and &1.name == "Tenant B")
           )

    assert :ok = Attribution.link_iocs_to_campaign(@org_a, id, ["ioc-a"])
    assert {:ok, %{iocs: ["ioc-a"]}} = Attribution.get_campaign(@org_a, id)
    assert {:ok, %{iocs: []}} = Attribution.get_campaign(@org_b, id)

    assert Attribution.get_stats(@org_a).campaigns_in_memory >= 1
    assert Attribution.get_stats(@org_b).campaigns_in_memory >= 1
  end

  test "payload organization mismatch is rejected without writing" do
    id = "attribution-mismatch-#{System.unique_integer([:positive])}"

    assert Attribution.upsert_campaign(@org_a, %{
             "id" => id,
             "organization_id" => @org_b,
             "name" => "Wrong tenant"
           }) == {:error, :organization_mismatch}

    assert Attribution.get_campaign(@org_a, id) == {:error, :not_found}
    assert Attribution.get_campaign(@org_b, id) == {:error, :not_found}
  end

  test "actor profiles are visible only to the actor organization" do
    org_a = insert(:organization)
    org_b = insert(:organization)

    assert {:ok, actor_a} =
             MultiTenant.with_organization(org_a.id, fn ->
               ThreatActor.create(%{name: "Tenant A actor", organization_id: org_a.id})
             end)

    assert %ThreatActor{id: actor_id, organization_id: organization_id} =
             ThreatActor.get_for_organization(org_a.id, actor_a.id)

    assert actor_id == actor_a.id
    assert organization_id == org_a.id
    assert ThreatActor.get_for_organization(org_b.id, actor_a.id) == nil

    assert {:ok, %{actor: %{id: ^actor_id}, iocs: [], ioc_count: 0}} =
             Attribution.get_actor_profile(org_a.id, actor_a.id)

    assert Attribution.get_actor_profile(org_b.id, actor_a.id) == {:error, :not_found}
  end
end
