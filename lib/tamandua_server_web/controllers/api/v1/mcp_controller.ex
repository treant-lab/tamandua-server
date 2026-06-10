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
    |> json_rpc_response(MCPServer.handle_request(request, client_context(conn)))
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
    case MCPServer.list_tools() do
      {:ok, tools} ->
        json(conn, %{
          data: tools,
          meta: %{
            count: length(tools),
            protocol_version: "2024-11-05"
          }
        })

      {:error, reason} ->
        {:error, to_string(reason)}
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

    case MCPServer.get_security_context(opts) do
      {:ok, context} ->
        json(conn, %{
          data: context,
          meta: %{
            scope: scope,
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
          }
        })

      {:error, reason} ->
        {:error, to_string(reason)}
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
