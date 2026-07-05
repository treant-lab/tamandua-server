defmodule TamanduaServerWeb.API.V1.HealingControllerOrgScopeTest do
  @moduledoc """
  Database-backed cross-organization scoping tests for the self-healing
  controller (regression tests for the cross-org response bypass where
  any authenticated user could execute healing actions on any tenant's
  agents and roll back any tenant's actions).
  """

  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Response
  alias TamanduaServerWeb.API.V1.HealingController

  defp call_action(action, conn) do
    HealingController.call(conn, HealingController.init(action))
  end

  defp build_conn(method, path, params, org_id) do
    Plug.Test.conn(method, path, params)
    |> Phoenix.Controller.put_format("json")
    |> Plug.Conn.assign(:current_organization_id, org_id)
  end

  describe "execute/2 cross-org scoping" do
    test "denies executing a healing action on another organization's agent (404)" do
      {_org_a, agent_a} = create_agent_with_org()
      org_b = insert!(:organization)

      conn =
        build_conn(
          :post,
          "/api/v1/healing/execute",
          %{"agent_id" => agent_a.id, "action_type" => "flush_dns"},
          org_b.id
        )

      conn = call_action(:execute, conn)

      assert conn.status == 404
    end

    test "allows the authorization step for a same-org agent (fails later on action validation, not authz)" do
      {org_a, agent_a} = create_agent_with_org()

      conn =
        build_conn(
          :post,
          "/api/v1/healing/execute",
          %{"agent_id" => agent_a.id, "action_type" => "definitely_not_a_real_action"},
          org_a.id
        )

      conn = call_action(:execute, conn)

      # 400 "Invalid action type" proves the request got past authorization
      # (a cross-org request would have returned 404 before validation).
      assert conn.status == 400
      assert Jason.decode!(conn.resp_body)["error"] =~ "Invalid action type"
    end
  end

  describe "rollback/2 cross-org scoping" do
    test "denies rolling back another organization's action (404)" do
      {org_a, agent_a} = create_agent_with_org()
      org_b = insert!(:organization)

      {:ok, action} =
        Response.create_action(%{
          agent_id: agent_a.id,
          action_type: "heal_restart_service",
          status: "success",
          organization_id: org_a.id
        })

      conn =
        build_conn(
          :post,
          "/api/v1/healing/rollback/#{action.id}",
          %{"action_id" => action.id},
          org_b.id
        )

      conn = call_action(:rollback, conn)

      assert conn.status == 404
    end

    test "authorizes legacy actions (nil organization_id) through the agent's tenancy" do
      {org_a, agent_a} = create_agent_with_org()

      # Legacy record: no organization stamp, still-in-progress status.
      {:ok, action} =
        Response.create_action(%{
          agent_id: agent_a.id,
          action_type: "heal_restart_service",
          status: "pending"
        })

      conn =
        build_conn(
          :post,
          "/api/v1/healing/rollback/#{action.id}",
          %{"action_id" => action.id},
          org_a.id
        )

      conn = call_action(:rollback, conn)

      # 400 "Action cannot be rolled back" (still pending) proves the caller
      # was authorized -- a cross-org caller would have received 404.
      assert conn.status == 400
      assert Jason.decode!(conn.resp_body)["error"] == "Action cannot be rolled back"
    end

    test "denies legacy actions whose agent belongs to another organization (404)" do
      {_org_a, agent_a} = create_agent_with_org()
      org_b = insert!(:organization)

      {:ok, action} =
        Response.create_action(%{
          agent_id: agent_a.id,
          action_type: "heal_restart_service",
          status: "pending"
        })

      conn =
        build_conn(
          :post,
          "/api/v1/healing/rollback/#{action.id}",
          %{"action_id" => action.id},
          org_b.id
        )

      conn = call_action(:rollback, conn)

      assert conn.status == 404
    end
  end

  describe "history/2 org scoping" do
    test "only returns the caller's organization's healing actions" do
      {org_a, agent_a} = create_agent_with_org()
      {org_b, agent_b} = create_agent_with_org()

      {:ok, action_a} =
        Response.create_action(%{
          agent_id: agent_a.id,
          action_type: "heal_flush_dns",
          status: "success",
          organization_id: org_a.id
        })

      {:ok, action_b} =
        Response.create_action(%{
          agent_id: agent_b.id,
          action_type: "heal_flush_dns",
          status: "success",
          organization_id: org_b.id
        })

      conn = build_conn(:get, "/api/v1/healing/history", %{}, org_a.id)
      conn = call_action(:history, conn)

      assert conn.status == 200
      ids = conn.resp_body |> Jason.decode!() |> Map.fetch!("data") |> Enum.map(& &1["id"])

      assert action_a.id in ids
      refute action_b.id in ids
    end
  end
end
