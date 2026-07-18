defmodule TamanduaServerWeb.API.V1.BatchControllerSecurityTest do
  use TamanduaServerWeb.ConnCase

  import TamanduaServer.Factory

  setup %{conn: conn} do
    org = insert(:organization)
    viewer = insert(:user, organization_id: org.id)

    conn =
      conn
      |> put_req_header(~s(accept), ~s(application/json))
      |> put_req_header(~s(content-type), ~s(application/json))
      |> assign(:current_organization_id, org.id)
      |> assign(:current_user, viewer)

    {:ok, conn: conn, viewer: viewer}
  end

  test ~s(batch mutations require their operation-specific permissions), %{
    conn: conn,
    viewer: viewer
  } do
    requests = [
      {~s(/api/v1/alerts/batch/close), %{~s(alert_ids) => []}, ~s(alerts_resolve)},
      {~s(/api/v1/alerts/batch/assign), %{~s(alert_ids) => [], ~s(assigned_to_id) => viewer.id},
       ~s(alerts_assign)},
      {~s(/api/v1/alerts/batch/tag), %{~s(alert_ids) => []}, ~s(alerts_update)},
      {~s(/api/v1/alerts/batch/delete), %{~s(alert_ids) => []}, ~s(alerts_delete)},
      {~s(/api/v1/iocs/batch/import), %{~s(iocs) => []}, ~s(threat_intel_add)},
      {~s(/api/v1/iocs/batch/delete), %{~s(ioc_ids) => []}, ~s(threat_intel_manage)},
      {~s(/api/v1/iocs/batch/update), %{~s(ioc_ids) => [], ~s(updates) => %{}},
       ~s(threat_intel_manage)},
      {~s(/api/v1/agents/batch/isolate), %{~s(agent_ids) => []}, ~s(response_isolate)},
      {~s(/api/v1/agents/batch/scan), %{~s(agent_ids) => []}, ~s(agents_command)},
      {~s(/api/v1/agents/batch/collect-forensics), %{~s(agent_ids) => []}, ~s(forensics_collect)}
    ]

    Enum.each(requests, fn {request_path, params, required_permission} ->
      response = post(conn, request_path, params)

      assert %{
               ~s(error) => ~s(forbidden),
               ~s(required_permission) => ^required_permission
             } = json_response(response, 403)
    end)
  end
end
