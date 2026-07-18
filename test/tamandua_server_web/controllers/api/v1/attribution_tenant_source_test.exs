defmodule TamanduaServerWeb.API.V1.AttributionTenantSourceTest do
  use ExUnit.Case, async: true

  @root Path.expand("../../../../..", __DIR__)

  test "REST attribution campaign surfaces derive the authoritative organization" do
    controller =
      File.read!(
        Path.join(@root, "lib/tamandua_server_web/controllers/api/v1/threat_intel_controller.ex")
      )

    assert controller =~ "Attribution.list_campaigns(organization_id, opts)"
    assert controller =~ "Attribution.get_campaign(organization_id, campaign_id)"
    assert controller =~ "Attribution.get_actor_profile(organization_id, actor_id)"
    assert controller =~ "Attribution.correlate_iocs(organization_id, iocs)"
    assert controller =~ "Attribution.get_stats(organization_id)"
    assert controller =~
             "@global_actor_catalog_actions [:list_db_actors, :show_db_actor, :actor_stats, :actors_by_ttp]"

    assert controller =~
             "@misp_read_actions ++ @global_actor_catalog_actions"
  end

  test "recent attributions require tenant scope at the query and RLS layers" do
    controller =
      File.read!(
        Path.join(@root, "lib/tamandua_server_web/controllers/api/v1/threat_intel_controller.ex")
      )

    assert controller =~ "def list_attributions(conn, params)"
    assert controller =~ "where: a.organization_id == ^organization_id"

    assert controller =~
             "MultiTenant.with_organization(organization_id, fn -> Repo.all(query) end)"

    assert controller =~ ~s|json(%{error: "attribution_store_unavailable"})|
    refute controller =~ "json(conn, %{data: [], meta: %{limit: 50, offset: 0, count: 0}})"
    refute controller =~ "attributions_made: 0, campaigns_tracked: 0, iocs_linked: 0"

    assert controller =~
             "MultiTenant.with_organization(organization_id, fn -> Repo.one(query) end)"
  end

  test "automatic attribution producers pass the alert organization and reject unknown scope" do
    alerts = File.read!(Path.join(@root, "lib/tamandua_server/alerts.ex"))

    worker =
      File.read!(Path.join(@root, "lib/tamandua_server/detection/engine_worker.ex"))

    assert alerts =~ "Attribution.attribute_alert("
    assert alerts =~ "organization_id,"
    assert alerts =~ "source: :alerts"
    refute alerts =~ "Attribution.attribute_alert(alert_data)"

    assert worker =~ "Attribution.attribute_alert(organization_id, alert_data)"
    assert worker =~ "source: :engine_worker"
    refute worker =~ "Attribution.attribute_alert(alert_data)"
  end

  test "tracked campaign static routes precede the generic campaign id route" do
    router = File.read!(Path.join(@root, "lib/tamandua_server_web/router.ex"))

    {tracked_offset, _} = :binary.match(router, ~s|get("/threat-intel/campaigns/tracked"|)
    {generic_offset, _} = :binary.match(router, ~s|get("/threat-intel/campaigns/:id"|)

    assert tracked_offset < generic_offset
  end

  test "Attribution storage contract is tenant keyed and legacy calls fail closed" do
    attribution =
      File.read!(Path.join(@root, "lib/tamandua_server/threat_intel/attribution.ex"))

    assert attribution =~
             ":ets.insert(@ets_campaigns, {{organization_id, campaign_id}, campaign_data})"

    assert attribution =~ "organization_id: organization_id"
    assert attribution =~ "def get_campaign(_legacy_campaign_id)"
    assert attribution =~ "def get_actor_profile(_legacy_actor_id)"
    assert attribution =~ "def get_stats, do: organization_required(:get_stats)"
  end

  test "actor profile core uses explicit tenant lookup and tenant-keyed IOC cache" do
    attribution =
      File.read!(Path.join(@root, "lib/tamandua_server/threat_intel/attribution.ex"))

    actor = File.read!(Path.join(@root, "lib/tamandua_server/threat_intel/threat_actor.ex"))

    assert actor =~ "belongs_to(:organization, TamanduaServer.Accounts.Organization)"
    assert actor =~ "def get_for_organization(organization_id, id)"
    assert actor =~ "where: a.id == ^id and a.organization_id == ^organization_id"
    assert actor =~ "MultiTenant.with_organization(organization_id"

    assert attribution =~ "ThreatActor.get_for_organization(organization_id, actor_id)"
    assert attribution =~ "key = {organization_id, actor.id}"
    assert attribution =~ ":ets.lookup(@ets_actor_iocs, key)"
    refute attribution =~ ":ets.lookup(@ets_actor_iocs, actor_id)"
    refute attribution =~ "case ThreatActor.get(actor_id) do"
  end
end
