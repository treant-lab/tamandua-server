defmodule TamanduaServer.ThreatIntel.CampaignTrackerTenantSourceTest do
  use ExUnit.Case, async: true

  @tracker "lib/tamandua_server/threat_intel/campaign_tracker.ex"

  test "runtime keys, persistence restore and PubSub are organization partitioned" do
    source = File.read!(@tracker)

    assert source =~ "key = {organization_id, campaign_id}"
    assert source =~ "index_key = {organization_id, ioc_value}"
    assert source =~ "index_key = {organization_id, agent_id}"
    assert source =~ "{{organization_id, _id}, %{organization_id: organization_id} = campaign}"
    assert source =~ ~S("#{@topic}:#{organization_id}")
    refute source =~ "Phoenix.PubSub.broadcast(@pubsub, @topic"
  end

  test "auto detection selects, groups and updates alerts under organization scope" do
    source = File.read!(@tracker)

    assert source =~ "a.organization_id == ^organization_id"
    refute source =~ "is_nil(^organization_id) or a.organization_id"
    assert source =~ "Enum.reduce(state.known_organizations"
    assert source =~ "MultiTenant.with_organization(organization_id"
    assert source =~ "restored_organizations = restored_organizations()"
    assert source =~ "known_organizations: restored_organizations"
    assert source =~ "organization_id: a.organization_id"
    assert source =~ "{alert.organization_id, actor_name}"
    assert source =~ "create_or_update_campaign(org_id, actor_name, alerts)"
    assert source =~ "a.id in ^unlinked_alert_ids and a.organization_id == ^organization_id"
  end

  test "every mapped producer either derives authoritative organization or fails closed" do
    alerts = File.read!("lib/tamandua_server/alerts.ex")
    engine = File.read!("lib/tamandua_server/detection/engine_worker.ex")
    phishing = File.read!("lib/tamandua_server/detection/phishing.ex")
    retro = File.read!("lib/tamandua_server/threat_intel/retroactive_scanner.ex")
    aggregator = File.read!("lib/tamandua_server/threat_intel/emerging_sources/aggregator.ex")

    assert alerts =~ "record_attribution(\n                  alert.organization_id"
    assert engine =~ "record_attribution(\n                    alert.organization_id"
    assert phishing =~ "CampaignTracker.record_attribution(campaign.organization_id"
    assert retro =~ "TamanduaServer.Agents.OrgLookup.get_org_id(match.agent_id)"
    assert retro =~ "reason: :organization_mismatch"
    assert retro =~ "reason: :organization_unknown"
    assert aggregator =~ "authoritative_organization_context_required"
    refute aggregator =~ "CampaignTracker.list_campaigns("
  end

  test "REST and GraphQL projections use current organization and scope alert rows" do
    rest =
      File.read!("lib/tamandua_server_web/controllers/api/v1/threat_intel_controller.ex")

    graphql =
      File.read!("lib/tamandua_server_web/graphql/resolvers/threat_intel_resolver.ex")

    assert rest =~ "CampaignTracker.list_campaigns(organization_id"
    assert rest =~ "CampaignTracker.get_campaign(organization_id, campaign_id)"
    assert rest =~ "a.organization_id == ^organization_id"
    assert rest =~ "campaign_organization_required(conn)"
    assert graphql =~ "tracker_campaigns(org_id, [])"
    assert graphql =~ "CampaignTracker.list_campaigns(organization_id, opts)"
  end
end
