defmodule TamanduaServerWeb.Controllers.API.V1.AIControllerTest do
  use TamanduaServerWeb.ConnCase, async: true

  import TamanduaServer.Factory

  setup %{conn: conn} do
    org = insert(:organization)
    user = insert(:user, %{organization_id: org.id, role: "analyst"})
    {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(user)

    %{conn: put_req_header(conn, "authorization", "Bearer #{token}"), org: org}
  end

  describe "POST /api/v1/ai/chat" do
    test "handles prior alert context without Regex.scan argument errors", %{conn: conn} do
      alert_id = Ecto.UUID.generate()

      conn =
        post(conn, "/api/v1/ai/chat", %{
          "message" => "explique os ultimos alerts",
          "context" => %{
            "previous_messages" => [
              %{
                "role" => "assistant",
                "content" => "Alert is still in context: #{alert_id}"
              }
            ]
          }
        })

      body = json_response(conn, 200)["data"]

      assert is_binary(body["message"])
      refute body["message"] =~ "Regex.scan"
      refute body["message"] =~ "function clause"
    end

    test "returns needs_scope instead of replaying a generic 100-event activity pivot", %{conn: conn} do
      conn =
        post(conn, "/api/v1/ai/chat", %{
          "message" => "process responsible",
          "context" => %{
            "previous_messages" => [
              %{"role" => "user", "content" => "DoH resolver 8.8.8.8:443 find all related"},
              %{"role" => "assistant", "content" => "Found 100 matching events."}
            ]
          }
        })

      data = json_response(conn, 200)["data"]

      assert data["status"] == "needs_scope"
      assert data["message"] =~ "Select an alert or process"
      assert [%{"status" => "not_run", "result_count" => 0}] = data["tool_results"]
      assert [%{"type" => "select_scope"}] = data["actions"]
      assert [%{"type" => "select_scope"}] = data["suggested_actions"]
      refute data["message"] =~ "Found 100 matching events"
    end

    test "passes current alert context to QueryInterface and returns structured fields", %{
      conn: conn,
      org: org
    } do
      agent = insert(:agent, %{organization_id: org.id})

      insert(:event, %{
        organization_id: org.id,
        agent_id: agent.id,
        agent: agent,
        event_type: "process_create",
        timestamp: DateTime.utc_now(),
        payload: %{"process_name" => "runner.exe", "pid" => "4242"}
      })

      alert =
        insert(:alert, %{
          organization_id: org.id,
          organization: org,
          agent_id: agent.id,
          agent: agent,
          evidence: %{"process" => %{"pid" => 4242}}
        })

      conn =
        post(conn, "/api/v1/ai/chat", %{
          "message" => "Which process was responsible?",
          "context" => %{"current_alert" => %{"id" => alert.id}}
        })

      data = json_response(conn, 200)["data"]

      assert [%{"tool" => "process_responsible", "status" => "completed", "result_count" => 1}] =
               data["tool_results"]

      assert Enum.any?(data["actions"], &(&1["intent"] == "process_tree"))
      assert data["suggested_actions"] == data["actions"]
    end

    test "passes current entity context and keeps network results process-scoped", %{
      conn: conn,
      org: org
    } do
      agent = insert(:agent, %{organization_id: org.id})

      insert(:event, %{
        organization_id: org.id,
        agent_id: agent.id,
        agent: agent,
        event_type: "network_connection",
        timestamp: DateTime.utc_now(),
        payload: %{"pid" => "991", "remote_ip" => "203.0.113.10"}
      })

      insert(:event, %{
        organization_id: org.id,
        agent_id: agent.id,
        agent: agent,
        event_type: "network_connection",
        timestamp: DateTime.utc_now(),
        payload: %{"pid" => "992", "remote_ip" => "198.51.100.2"}
      })

      conn =
        post(conn, "/api/v1/ai/chat", %{
          "message" => "Show network connections from this process",
          "context" => %{
            "current_entity" => %{"type" => "process", "agent_id" => agent.id, "pid" => 991}
          }
        })

      data = json_response(conn, 200)["data"]
      [tool_result] = data["tool_results"]

      assert tool_result["tool"] == "process_network"
      assert tool_result["result_count"] == 1
      assert [result] = tool_result["results"]
      assert result["payload"]["remote_ip"] == "203.0.113.10"
    end
  end
end
