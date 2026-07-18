defmodule TamanduaServerWeb.API.V1.ThreatIntelControllerAuthorizationSourceTest do
  use ExUnit.Case, async: true

  @controller Path.expand(
                "../../../../../lib/tamandua_server_web/controllers/api/v1/threat_intel_controller.ex",
                __DIR__
              )

  test "global threat-intel mutations compose RBAC and platform authority" do
    source = File.read!(@controller)

    assert source =~ "permission: :threat_intel_read"
    assert source =~ "permission: :threat_intel_manage"
    assert source =~ "TamanduaServerWeb.Plugs.SystemOperator"

    for action <- [
          :configure_api_key,
          :add_custom_feed,
          :create_misp_instance,
          :publish_to_misp,
          :create_db_actor,
          :recalculate_all_scores,
          :upsert_attribution_campaign,
          :graph_enrich
        ] do
      assert source =~ ":#{action}"
    end


    for action <- [
          :list_misp_instances,
          :show_misp_instance,
          :list_misp_events,
          :show_misp_event,
          :list_sharing_groups
        ] do
      assert source =~ ":#{action}"
    end
  end
end
