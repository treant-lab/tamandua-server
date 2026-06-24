defmodule TamanduaServerWeb.API.V1.MCPController do
  @moduledoc """
  MCP (Model Context Protocol) Server API controller.

  Provides JSON-RPC endpoints for MCP server integration, allowing
  AI models to interact with Tamandua's security tools and context.
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Integrations.MCPServer

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Handle JSON-RPC requests for MCP protocol.

  ## Parameters
    - method: The JSON-RPC method name
    - params: Method parameters
    - id: Request ID for response correlation

  ## Examples
      POST /api/v1/mcp/rpc
      {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
  """
  def json_rpc(conn, %{"method" => _method, "id" => _id} = request) do
    request = Map.put_new(request, "params", %{})

    conn
    |> put_status(:ok)
    |> json_rpc_response(safe_mcp_call(request, fn -> MCPServer.handle_request(request, client_context(conn)) end))
  end

  def json_rpc(conn, %{"method" => _method} = request) do
    request = request |> Map.put_new("params", %{}) |> Map.put_new("id", nil)

    conn
    |> put_status(:ok)
    |> json_rpc_response(safe_mcp_call(request, fn -> MCPServer.handle_request(request, client_context(conn)) end))
  end

  def json_rpc(conn, _params) do
    conn
    |> put_status(:ok)
    |> json(%{
      jsonrpc: "2.0",
      error: %{code: -32600, message: "Invalid Request"},
      id: nil
    })
  end

  @doc """
  List available MCP tools.

  Returns all security tools exposed through the MCP interface,
  including their schemas and descriptions.
  """
  def available_tools(conn, _params) do
    case safe_mcp_call(nil, fn -> MCPServer.list_tools() end) do
      {:ok, tools} ->
        json(conn, %{
          data: tools,
          meta: %{
            count: length(tools),
            protocol_version: "2024-11-05"
          }
        })

      {:error, %{error: %{message: message}}} ->
        tools = MCPServer.tool_catalog()

        json(conn, %{
          data: tools,
          meta: %{
            count: length(tools),
            protocol_version: "2024-11-05",
            degraded: true,
            health_message: message
          }
        })

      {:error, reason} ->
        tools = MCPServer.tool_catalog()

        json(conn, %{
          data: tools,
          meta: %{
            count: length(tools),
            protocol_version: "2024-11-05",
            degraded: true,
            health_message: to_string(reason)
          }
        })
    end
  end

  @doc """
  Get current security context for MCP sessions.

  Returns contextual information about the current security state,
  including active alerts, monitored assets, and threat levels.
  """
  def security_context(conn, params) do
    scope = Map.get(params, "scope", "default")
    user = conn.assigns[:current_user]

    opts = %{
      scope: scope,
      organization_id: conn.assigns[:current_organization_id] || (user && user.organization_id)
    }

    case safe_mcp_call(nil, fn -> MCPServer.get_security_context(opts) end) do
      {:ok, context} ->
        json(conn, %{
          data: context,
          meta: %{
            scope: scope,
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
          }
        })

      {:error, %{error: %{message: message}}} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: message, data: %{}})

      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: to_string(reason), data: %{}})
    end
  end

  defp safe_mcp_call(request, fun) when is_function(fun, 0) do
    try do
      fun.()
    rescue
      error ->
        {:error, mcp_unavailable_response(request, "MCP server call failed: #{Exception.message(error)}")}
    catch
      :exit, {:noproc, _} ->
        {:error, mcp_unavailable_response(request, "MCP server process is not running")}

      :exit, {:timeout, _} ->
        {:error, mcp_unavailable_response(request, "MCP server did not respond before timeout")}

      :exit, reason ->
        {:error, mcp_unavailable_response(request, "MCP server call failed: #{inspect(reason)}")}
    end
  end

  defp mcp_unavailable_response(request, message) do
    case request && request["method"] do
      "initialize" ->
        %{
          jsonrpc: "2.0",
          result: %{
            protocolVersion: "2024-11-05",
            serverInfo: %{name: "tamandua-mcp", title: "Tamandua MCP Server", version: "catalog"},
            capabilities: %{tools: %{listChanged: false}, resources: %{listChanged: false}, prompts: %{listChanged: false}},
            degraded: true,
            healthMessage: message
          },
          id: request["id"]
        }

      "tools/list" ->
        %{
          jsonrpc: "2.0",
          result: %{tools: MCPServer.tool_catalog(:rpc), degraded: true, healthMessage: message},
          id: request["id"]
        }

      "resources/list" ->
        %{
          jsonrpc: "2.0",
          result: %{resources: MCPServer.context_provider_catalog(:rpc), degraded: true, healthMessage: message},
          id: request["id"]
        }

      "prompts/list" ->
        %{jsonrpc: "2.0", result: %{prompts: [], degraded: true, healthMessage: message}, id: request["id"]}

      "notifications/initialized" ->
        %{jsonrpc: "2.0", result: %{}, id: request["id"]}

      _ ->
        %{
          jsonrpc: "2.0",
          error: %{code: -32603, message: message},
          id: request && request["id"]
        }
    end
  end

  defp json_rpc_response(conn, {:ok, response}) when is_map(response), do: json(conn, response)
  defp json_rpc_response(conn, {:error, response}) when is_map(response), do: json(conn, response)

  defp json_rpc_response(conn, {:error, reason}) do
    json(conn, %{
      jsonrpc: "2.0",
      error: %{code: -32603, message: to_string(reason)},
      id: nil
    })
  end

  defp client_context(conn) do
    user = conn.assigns[:current_user]

    %{
      current_user: user,
      organization_id: conn.assigns[:current_organization_id] || (user && user.organization_id),
      ip_address: conn.remote_ip |> format_ip(),
      user_agent: conn |> get_req_header("user-agent") |> List.first(),
      authorization: conn |> get_req_header("authorization") |> List.first()
    }
  end

  defp format_ip(nil), do: nil
  defp format_ip(ip) when is_tuple(ip), do: ip |> :inet.ntoa() |> to_string()
  defp format_ip(ip), do: to_string(ip)
end
