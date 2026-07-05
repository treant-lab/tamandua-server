defmodule TamanduaServerWeb.API.V1.HealingControllerAuthzTest do
  @moduledoc """
  Database-free authorization tests for the self-healing controller.

  These tests exercise the organization-scoping guards that run *before*
  any database or executor access, by invoking the controller module
  directly (the project has no ConnCase; the controller is a plug).
  """

  use ExUnit.Case, async: true

  alias TamanduaServerWeb.API.V1.HealingController

  defp call_action(action, conn) do
    HealingController.call(conn, HealingController.init(action))
  end

  defp build_conn(method, path, params) do
    Plug.Test.conn(method, path, params)
    |> Phoenix.Controller.put_format("json")
  end

  describe "execute/2 authorization" do
    test "returns 403 when the caller has no organization context" do
      conn =
        build_conn(:post, "/api/v1/healing/execute", %{
          "agent_id" => Ecto.UUID.generate(),
          "action_type" => "flush_dns"
        })

      conn = call_action(:execute, conn)

      assert conn.status == 403
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "forbidden"
    end

    test "returns 404 for a malformed (non-UUID) agent_id without touching the executor" do
      conn =
        build_conn(:post, "/api/v1/healing/execute", %{
          "agent_id" => "../not-a-uuid",
          "action_type" => "flush_dns"
        })
        |> Plug.Conn.assign(:current_organization_id, Ecto.UUID.generate())

      conn = call_action(:execute, conn)

      assert conn.status == 404
    end

    test "returns 400 when required parameters are missing (still no org needed to see the contract error)" do
      conn =
        build_conn(:post, "/api/v1/healing/execute", %{})
        |> Plug.Conn.assign(:current_organization_id, Ecto.UUID.generate())

      conn = call_action(:execute, conn)

      assert conn.status == 400
      assert Jason.decode!(conn.resp_body)["error"] =~ "Missing required parameters"
    end
  end

  describe "history/2 authorization" do
    test "returns 403 when the caller has no organization context" do
      conn = build_conn(:get, "/api/v1/healing/history", %{})

      conn = call_action(:history, conn)

      assert conn.status == 403
    end
  end

  describe "rollback/2 authorization" do
    test "returns 404 for a malformed (non-UUID) action_id instead of a 500" do
      conn =
        build_conn(:post, "/api/v1/healing/rollback/not-a-uuid", %{
          "action_id" => "not-a-uuid"
        })
        |> Plug.Conn.assign(:current_organization_id, Ecto.UUID.generate())

      conn = call_action(:rollback, conn)

      assert conn.status == 404
    end

    test "returns 400 when action_id is missing" do
      conn =
        build_conn(:post, "/api/v1/healing/rollback", %{})
        |> Plug.Conn.assign(:current_organization_id, Ecto.UUID.generate())

      conn = call_action(:rollback, conn)

      assert conn.status == 400
    end
  end
end
