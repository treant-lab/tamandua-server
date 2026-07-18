defmodule TamanduaServerWeb.API.V1.FleetQueryControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.FleetQueries

  describe "GET /api/v1/fleet-queries" do
    test "returns tenant-scoped runs with normalized query previews", %{conn: conn} do
      org = insert!(:organization)
      other_org = insert!(:organization)
      user = insert!(:user, organization_id: org.id, role: "analyst")
      agent = insert!(:agent, organization: org, hostname: "tenant-query-host", os_type: "linux")
      other_agent = insert!(:agent, organization: other_org, hostname: "other-query-host", os_type: "linux")

      register_agent(agent, ["osquery_query"])
      register_agent(other_agent, ["osquery_query"])

      assert {:ok, run} =
               FleetQueries.create_osquery_run(org.id, %{
                 "query" => "select name,\n  version from programs\nlimit 10;",
                 "agent_ids" => [agent.id]
               })

      assert {:ok, _other_run} =
               FleetQueries.create_osquery_run(other_org.id, %{
                 "query" => "select * from os_version;",
                 "agent_ids" => [other_agent.id]
               })

      {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(user)

      response =
        conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get("/api/v1/fleet-queries")
        |> json_response(200)

      assert response["total"] == 1
      assert [serialized] = response["data"]
      assert serialized["id"] == run.id
      assert serialized["query_preview"] == "select name, version from programs limit 10;"
      refute Map.has_key?(serialized, "query")
    end
  end

  defp register_agent(agent, capabilities) do
    Registry.register(agent.id, %{
      hostname: agent.hostname,
      os_type: agent.os_type,
      organization_id: agent.organization_id,
      worker_pid: self(),
      capabilities: capabilities
    })
  end
end
