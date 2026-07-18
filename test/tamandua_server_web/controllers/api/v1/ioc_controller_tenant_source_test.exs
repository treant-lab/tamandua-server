defmodule TamanduaServerWeb.API.V1.IOCControllerTenantSourceTest do
  use ExUnit.Case, async: true

  @root Path.expand("../../../../..", __DIR__)

  test "IOC REST CRUD derives tenant from the authenticated connection" do
    controller =
      File.read!(Path.join(@root, "lib/tamandua_server_web/controllers/api/v1/ioc_controller.ex"))

    assert controller =~ "permission: :threat_intel_read"
    assert controller =~ "permission: :threat_intel_add"
    assert controller =~ "permission: :threat_intel_manage"
    assert controller =~ "organization_id: organization_id"
    assert controller =~ "Map.put(params, \"organization_id\", organization_id)"
    assert controller =~ "get_ioc_for_organization(organization_id, id)"
    assert controller =~ "get_owned_ioc_for_organization(organization_id, id)"
    assert controller =~ "length(iocs_params) <= 100"
    assert controller =~ "Enum.all?(iocs_params, &is_map/1)"
    refute controller =~ "IOCs.get_ioc!(id)"
  end
end
