defmodule TamanduaServer.Integrations.MCPServerTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.AISecurity.MCPGovernance
  alias TamanduaServer.Integrations.MCPServer

  setup do
    unless Process.whereis(MCPGovernance) do
      start_supervised!(MCPGovernance)
    end

    unless Process.whereis(MCPServer) do
      start_supervised!(MCPServer)
    end

    :ok
  end

  test "tools/list returns a JSON-RPC result envelope" do
    request = %{"jsonrpc" => "2.0", "method" => "tools/list", "params" => %{}, "id" => 1}

    assert {:ok, %{"jsonrpc" => "2.0", "id" => 1, "result" => result}} =
             MCPServer.handle_request(request)

    assert %{tools: tools} = result
    assert Enum.any?(tools, &(&1.name == "query_alerts"))
  end

  test "invalid requests return a JSON-RPC error envelope" do
    request = %{"method" => "tools/list", "params" => %{}, "id" => "bad"}

    assert {:error, %{"jsonrpc" => "2.0", "id" => "bad", "error" => error}} =
             MCPServer.handle_request(request)

    assert %{"code" => -32600, "message" => "Invalid request"} = error
  end

  test "action tools require governance parameters before execution" do
    api_key = "mcp-test-#{System.unique_integer([:positive])}"

    assert :ok =
             MCPServer.register_client(api_key, %{
               client_id: "test-client",
               permissions: [:read, :execute],
               organization_id: Ecto.UUID.generate()
             })

    request = %{
      "jsonrpc" => "2.0",
      "method" => "tools/call",
      "params" => %{
        "_api_key" => api_key,
        "name" => "take_action",
        "arguments" => %{
          "action" => "isolate",
          "agent_id" => Ecto.UUID.generate(),
          "scope" => "agent"
        }
      },
      "id" => 2
    }

    assert {:error, %{"id" => 2, "error" => error}} = MCPServer.handle_request(request)
    assert %{"code" => -32602, "message" => message} = error
    assert message =~ "reason"
  end

  test "read-only tool calls are authorized and recorded through MCP governance" do
    api_key = "mcp-read-test-#{System.unique_integer([:positive])}"

    assert :ok =
             MCPServer.register_client(api_key, %{
               client_id: "read-client",
               permissions: [:read],
               organization_id: Ecto.UUID.generate()
             })

    {:ok, context} = MCPServer.get_security_context()

    request = %{
      "jsonrpc" => "2.0",
      "method" => "get_timeline",
      "params" => %{
        "_api_key" => api_key,
        "entity_type" => "agent",
        "entity_id" => Ecto.UUID.generate()
      },
      "id" => 3
    }

    assert {:ok, %{"id" => 3, "result" => %{entity_type: "agent"}}} = MCPServer.handle_request(request)

    Process.sleep(50)

    assert Enum.any?(MCPGovernance.get_audit_log(server_id: context.server_id), fn entry ->
             entry.tool_name == "get_timeline" and entry.caller_id == "read-client" and
               entry.result_status == :success
           end)
  end

  test "dry-run action returns a simulation without queueing or executing" do
    api_key = "mcp-dry-run-test-#{System.unique_integer([:positive])}"
    org = insert!(:organization)

    assert :ok =
             MCPServer.register_client(api_key, %{
               client_id: "dry-run-client",
               permissions: [:read, :execute],
               organization_id: org.id
             })

    request = %{
      "jsonrpc" => "2.0",
      "method" => "tools/call",
      "params" => %{
        "_api_key" => api_key,
        "name" => "take_action",
        "arguments" => %{
          "action" => "isolate",
          "agent_id" => Ecto.UUID.generate(),
          "reason" => "test dry run",
          "scope" => "agent",
          "dry_run" => true
        }
      },
      "id" => 4
    }

    assert {:ok, %{"id" => 4, "result" => %{content: [%{json: result}], isError: false}}} =
             MCPServer.handle_request(request)

    assert %{status: "dry_run", dry_run: true, executed: false, would_require_approval: true} = result
  end

  test "destructive action requiring approval is queued and not executed" do
    org = insert!(:organization)
    agent = insert!(:agent, organization_id: org.id, status: "online")
    api_key = "mcp-approval-test-#{System.unique_integer([:positive])}"

    assert :ok =
             MCPServer.register_client(api_key, %{
               client_id: "approval-client",
               permissions: [:read, :execute],
               organization_id: org.id
             })

    request = %{
      "jsonrpc" => "2.0",
      "method" => "tools/call",
      "params" => %{
        "_api_key" => api_key,
        "name" => "take_action",
        "arguments" => %{
          "action" => "isolate",
          "agent_id" => agent.id,
          "reason" => "test approval queue",
          "scope" => "agent"
        }
      },
      "id" => 5
    }

    assert {:ok, %{"id" => 5, "result" => %{content: [%{json: result}], isError: false}}} =
             MCPServer.handle_request(request)

    assert %{status: "pending_approval", executed: false, approval_id: approval_id} = result

    assert {:ok, approvals} = MCPServer.list_pending_approvals(organization_id: org.id)
    assert Enum.any?(approvals, &(&1.id == approval_id and &1.action == "isolate"))
  end
end
