defmodule TamanduaServer.Response.ResponseAuditTenantReadsPgTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Response.Audit

  @moduletag :pending

  test "all read shapes exclude another organization's rows" do
    organization_a = insert(:organization)
    organization_b = insert(:organization)
    agent_a = insert(:agent, organization_id: organization_a.id)
    agent_b = insert(:agent, organization_id: organization_b.id)
    alert_id_a = Ecto.UUID.generate()
    alert_id_b = Ecto.UUID.generate()

    assert {:ok, _entry} =
             Audit.log_action(
               :isolate_host,
               %{"case_marker" => "tenant-a", "alert_id" => alert_id_a},
               agent_a.id,
               :system,
               organization_a.id
             )

    assert {:ok, _entry} =
             Audit.log_action(
               :kill_process,
               %{"case_marker" => "tenant-b", "alert_id" => alert_id_b},
               agent_b.id,
               :system,
               organization_b.id
             )

    assert {:ok, recent} = Audit.get_recent_actions(organization_a.id, [])
    assert Enum.all?(recent, &(&1.organization_id == organization_a.id))

    assert {:ok, agent_actions} =
             Audit.get_actions_for_agent(organization_a.id, agent_a.id, [])

    assert Enum.all?(agent_actions, &(&1.agent_id == agent_a.id))

    assert {:ok, %{"isolate_host" => 1}} = Audit.get_action_counts(organization_a.id, [])

    assert {:ok, [alert_action]} =
             Audit.get_actions_for_alert(organization_a.id, alert_id_a, [])

    assert alert_action.organization_id == organization_a.id

    assert {:ok, []} =
             Audit.get_actions_for_alert(organization_a.id, alert_id_b, [])

    assert {:ok, [found]} =
             Audit.search_by_details(
               organization_a.id,
               "case_marker",
               "tenant-a",
               []
             )

    assert found.organization_id == organization_a.id

    assert {:ok, []} =
             Audit.search_by_details(organization_a.id, "case_marker", "tenant-b", [])
  end

  test "invalid and legacy requests fail before a repository read" do
    assert {:error, :organization_scope_required} = Audit.get_recent_actions()
    assert {:error, :organization_scope_required} = Audit.get_recent_actions([])
    assert {:error, :organization_scope_required} = Audit.get_action_counts()
    assert {:error, :organization_scope_required} = Audit.get_action_counts([])

    assert {:error, :organization_scope_required} =
             Audit.get_actions_for_agent(Ecto.UUID.generate())

    assert {:error, :organization_scope_required} =
             Audit.get_actions_for_agent(Ecto.UUID.generate(), [])

    assert {:error, :organization_scope_required} = Audit.search_by_details("field", "value")
    assert {:error, :organization_scope_required} = Audit.search_by_details("field", "value", [])

    assert {:error, :invalid_organization_id} = Audit.get_recent_actions("not-a-uuid", [])

    assert {:error, :organization_scope_required} =
             Audit.get_actions_for_alert(Ecto.UUID.generate(), Ecto.UUID.generate())

    assert {:error, :invalid_alert_id} =
             Audit.get_actions_for_alert(Ecto.UUID.generate(), "not-a-uuid", [])

    assert {:error, :invalid_pagination} =
             Audit.get_recent_actions(Ecto.UUID.generate(), limit: 501)

    assert {:error, :invalid_query_options} =
             Audit.get_recent_actions(Ecto.UUID.generate(), organization_id: Ecto.UUID.generate())
  end
end
