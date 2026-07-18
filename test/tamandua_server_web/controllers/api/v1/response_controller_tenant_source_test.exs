defmodule TamanduaServerWeb.API.V1.ResponseControllerTenantSourceTest do
  use ExUnit.Case, async: true

  @controller Path.expand(
                "../../../../../lib/tamandua_server_web/controllers/api/v1/response_controller.ex",
                __DIR__
              )

  test "response targets and persisted alert references are tenant scoped" do
    source = File.read!(@controller)

    assert source =~ "Agents.get_agent_for_org!(org_id, agent_id)"
    assert source =~ "alert_id: scoped_alert_id(conn, Map.get(params, \"alert_id\"))"
    assert source =~ "Alerts.get_alert_for_org(current_organization_id(conn), alert_id)"
    assert source =~ "actor: response_actor(conn)"
    assert source =~ "action_id: result_data[:action_id]"
    assert source =~ "audit_status: result_data[:audit_status]"
    refute source =~ "alert_id: Map.get(params, \"alert_id\")"

    kill_block = Regex.run(~r/def kill_process.*?\n  end/s, source) |> List.first()
    quarantine_block = Regex.run(~r/def quarantine_file.*?\n  end/s, source) |> List.first()

    refute kill_block =~ "record_response_action("
    refute quarantine_block =~ "record_response_action("
    assert quarantine_block =~ "{:ok, result_data} ->"
    assert quarantine_block =~ "params[\"delete_after\"]"
    assert source =~ "_ -> raise Ecto.NoResultsError"
  end
end
