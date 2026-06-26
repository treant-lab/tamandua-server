defmodule TamanduaServer.Integrations.MCPServer do
  @moduledoc """
  MCP (Model Context Protocol) Server Integration for AI tool integration.

  Enables AI assistants to interact with Tamandua EDR for security
  investigations and response actions, similar to SentinelOne's approach.

  ## Features
  - JSON-RPC 2.0 protocol support
  - Tool definitions (query_alerts, investigate_host, take_action, etc.)
  - Context providers (agent_status, recent_alerts, threat_intel)
  - Authentication and authorization
  - Rate limiting per client
  - Comprehensive audit logging
  """

  use GenServer
  import Ecto.Query
  require Logger

  @read_timeout 15_000

  alias TamanduaServer.{Agents, Alerts, AuditLog, Detection, Response}
  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.AISecurity.MCPGovernance
  alias TamanduaServer.Authorization.RBAC
  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.Event

  # Configuration
  @rate_limit_window_ms 60_000
  @rate_limit_max_requests 100
  @rate_limit_max_actions 10
  @audit_log_max_entries 10_000
  @internal_mcp_endpoint "internal://tamandua/mcp"
  @approval_required_actions ~w(isolate unisolate kill_process quarantine_file)

  # JSON-RPC 2.0 error codes
  @error_parse_error -32700
  @error_invalid_request -32600
  @error_method_not_found -32601
  @error_invalid_params -32602
  @error_internal_error -32603
  @error_unauthorized -32001
  @error_rate_limited -32002
  @error_forbidden -32003

  defstruct [
    :server_id,
    :clients,
    :tools,
    :context_providers,
    :audit_log,
    :approval_queue,
    :stats
  ]

  defmodule ClientState do
    @moduledoc false
    defstruct [:client_id, :api_key, :permissions, :organization_id, :authenticated, :user,
               :request_count, :action_count, :window_start, :last_request, :metadata]
  end

  defmodule AuditEntry do
    @moduledoc false
    defstruct [:id, :timestamp, :client_id, :method, :params,
               :result_status, :duration_ms, :ip_address, :user_agent]
  end

  defmodule ApprovalRequest do
    @moduledoc false
    defstruct [
      :id,
      :timestamp,
      :tool_name,
      :params,
      :client,
      :client_id,
      :organization_id,
      :reason_hash,
      :scope,
      :status
    ]
  end

  ## Client API

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Handle an incoming MCP request (JSON-RPC 2.0 format)."
  @spec handle_request(map(), map()) :: {:ok, map()} | {:error, map()}
  def handle_request(request, client_context \\ %{}) do
    GenServer.call(__MODULE__, {:handle_request, request, client_context}, 30_000)
  end

  @doc "Static MCP tool catalog used for discovery fallbacks when the GenServer is not running."
  def tool_catalog(format \\ :api), do: define_tools() |> serialize_tools(format)

  @doc "Static MCP context provider catalog used for discovery fallbacks."
  def context_provider_catalog(format \\ :api), do: define_context_providers() |> serialize_context_providers(format)

  @doc "List available tools with their schemas."
  def list_tools, do: GenServer.call(__MODULE__, :list_tools, @read_timeout)

  @doc "List available context providers."
  def list_context_providers, do: GenServer.call(__MODULE__, :list_context_providers, @read_timeout)

  @doc "Get context from a specific provider."
  def get_context(provider_name, params \\ %{}) do
    GenServer.call(__MODULE__, {:get_context, provider_name, params}, @read_timeout)
  end

  @doc "Get the aggregate security context exposed to MCP clients."
  def get_security_context(opts \\ %{}) do
    GenServer.call(__MODULE__, {:get_security_context, opts}, @read_timeout)
  end

  @doc "Get server statistics."
  def get_stats, do: GenServer.call(__MODULE__, :get_stats, @read_timeout)

  @doc "Get audit log entries."
  def get_audit_log(opts \\ []), do: GenServer.call(__MODULE__, {:get_audit_log, opts}, @read_timeout)

  @doc "List pending MCP action approvals."
  def list_pending_approvals(opts \\ []) do
    GenServer.call(__MODULE__, {:list_pending_approvals, opts}, @read_timeout)
  end

  @doc "Approve and execute a queued MCP action."
  def approve_tool_call(approval_id, approver_context \\ %{}) do
    GenServer.call(__MODULE__, {:approve_tool_call, approval_id, approver_context}, 30_000)
  end

  @doc "Reject a queued MCP action without executing it."
  def reject_tool_call(approval_id, approver_context \\ %{}) do
    GenServer.call(__MODULE__, {:reject_tool_call, approval_id, approver_context}, @read_timeout)
  end

  @doc "Register or update a client API key."
  def register_client(api_key, client_info) do
    GenServer.call(__MODULE__, {:register_client, api_key, client_info}, @read_timeout)
  end

  @doc "Revoke a client API key."
  def revoke_client(api_key), do: GenServer.call(__MODULE__, {:revoke_client, api_key}, @read_timeout)

  ## Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("Starting MCP Server for AI tool integration")
    tools = define_tools()
    context_providers = define_context_providers()

    {:ok, %__MODULE__{
      server_id: ensure_governance_registration(tools, context_providers),
      clients: %{},
      tools: tools,
      context_providers: context_providers,
      audit_log: :queue.new(),
      approval_queue: %{},
      stats: %{total_requests: 0, successful_requests: 0, failed_requests: 0,
               actions_executed: 0, started_at: DateTime.utc_now()}
    }}
  end

  @impl true
  def handle_call({:handle_request, request, client_context}, _from, state) do
    start_time = System.monotonic_time(:millisecond)
    {result, new_state} = process_request(request, client_context, state)
    duration_ms = System.monotonic_time(:millisecond) - start_time

    audit_entry = %AuditEntry{
      id: generate_id(), timestamp: DateTime.utc_now(),
      client_id: client_context[:client_id] || "anonymous",
      method: map_get(request, "method"), params: sanitize_params(map_get(request, "params")),
      result_status: if(match?({:ok, _}, result), do: :success, else: :error),
      duration_ms: duration_ms, ip_address: client_context[:ip_address],
      user_agent: client_context[:user_agent]
    }

    new_state = new_state |> add_audit_entry(audit_entry) |> update_stats(result)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call(:list_tools, _from, state) do
    tools = serialize_tools(state.tools, :api)
    {:reply, {:ok, tools}, state}
  end

  @impl true
  def handle_call(:list_context_providers, _from, state) do
    providers = serialize_context_providers(state.context_providers, :api)
    {:reply, {:ok, providers}, state}
  end

  @impl true
  def handle_call({:get_context, provider_name, params}, _from, state) do
    result = case Map.get(state.context_providers, provider_name) do
      nil -> {:error, :provider_not_found}
      provider -> provider.handler.(params)
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = Map.merge(state.stats, %{
      uptime_seconds: DateTime.diff(DateTime.utc_now(), state.stats.started_at),
      registered_clients: map_size(state.clients),
      audit_log_size: :queue.len(state.audit_log)
    })
    {:reply, {:ok, stats}, state}
  end

  @impl true
  def handle_call({:get_audit_log, opts}, _from, state) do
    entries = state.audit_log |> :queue.to_list() |> Enum.reverse()
      |> filter_audit_entries(opts) |> Enum.take(opts[:limit] || 100)
      |> Enum.map(&audit_entry_to_map/1)
    {:reply, {:ok, entries}, state}
  end

  @impl true
  def handle_call({:list_pending_approvals, opts}, _from, state) do
    approvals =
      state.approval_queue
      |> Map.values()
      |> Enum.filter(&(&1.status == :pending_approval))
      |> filter_approvals(opts)
      |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
      |> Enum.map(&approval_to_map/1)

    {:reply, {:ok, approvals}, state}
  end

  @impl true
  def handle_call({:approve_tool_call, approval_id, approver_context}, _from, state) do
    case Map.get(state.approval_queue, approval_id) do
      %ApprovalRequest{status: :pending_approval, tool_name: "take_action"} = approval ->
        start_time = System.monotonic_time(:millisecond)
        audit_action_approval(approval.client, approval.params, approver_context, :approved)
        result = tool_take_action(Map.put(approval.params, "approval_id", approval_id), approval.client)
        duration_ms = System.monotonic_time(:millisecond) - start_time
        status = if match?({:ok, _}, result), do: :success, else: :error

        record_governance_tool_call(state.server_id, "take_action", approval.client, approval.params, status, duration_ms, result)

        updated_approval = %{approval | status: status}
        new_queue = Map.put(state.approval_queue, approval_id, updated_approval)
        {:reply, result, %{state | approval_queue: new_queue}}

      %ApprovalRequest{} ->
        {:reply, {:error, :not_pending_approval}, state}

      nil ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:reject_tool_call, approval_id, approver_context}, _from, state) do
    case Map.get(state.approval_queue, approval_id) do
      %ApprovalRequest{status: :pending_approval} = approval ->
        audit_action_approval(approval.client, approval.params, approver_context, :rejected)
        updated_approval = %{approval | status: :rejected}
        {:reply, :ok, %{state | approval_queue: Map.put(state.approval_queue, approval_id, updated_approval)}}

      %ApprovalRequest{} ->
        {:reply, {:error, :not_pending_approval}, state}

      nil ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:register_client, api_key, info}, _from, state) do
    client = %ClientState{
      client_id: info[:client_id] || generate_id(), api_key: api_key,
      permissions: info[:permissions] || [:read], organization_id: info[:organization_id],
      request_count: 0, action_count: 0, window_start: System.monotonic_time(:millisecond),
      metadata: info[:metadata] || %{}
    }
    Logger.info("MCP client registered: #{client.client_id}")
    {:reply, :ok, %{state | clients: Map.put(state.clients, api_key, client)}}
  end

  @impl true
  def handle_call({:revoke_client, api_key}, _from, state) do
    case Map.pop(state.clients, api_key) do
      {nil, _} -> {:reply, {:error, :not_found}, state}
      {client, new_clients} ->
        Logger.info("MCP client revoked: #{client.client_id}")
        {:reply, :ok, %{state | clients: new_clients}}
    end
  end

  @impl true
  def handle_call({:get_security_context, opts}, _from, state) do
    opts = normalize_context_opts(opts)

    # Build security context for MCP operations
    context = %{
      server_id: state.server_id,
      active_clients: map_size(state.clients),
      tools_available: Map.keys(state.tools),
      capabilities: [:query, :investigate, :respond, :threat_intel],
      rate_limits: %{
        max_requests_per_minute: @rate_limit_max_requests,
        max_actions_per_minute: @rate_limit_max_actions
      },
      stats: state.stats,
      organization_filter: Map.get(opts, :organization_id) || Map.get(opts, "organization_id"),
      scope: Map.get(opts, :scope) || Map.get(opts, "scope") || "default",
      timestamp: DateTime.utc_now()
    }

    {:reply, {:ok, context}, state}
  end

  ## Request Processing

  defp process_request(request, client_context, state) do
    with {:ok, _} <- validate_json_rpc(request),
         {:ok, client, state} <- authenticate_client(request, client_context, state),
         {:ok, state} <- check_rate_limit(client, request, state),
         {:ok, method} <- get_method(request) do
      dispatch_method(method, request, client, state)
    else
      {:error, :parse_error} -> {{:error, error_response(request_id(request), @error_parse_error, "Parse error")}, state}
      {:error, :invalid_request} -> {{:error, error_response(request_id(request), @error_invalid_request, "Invalid request")}, state}
      {:error, :unauthorized} -> {{:error, error_response(request_id(request), @error_unauthorized, "Unauthorized")}, state}
      {:error, :rate_limited} -> {{:error, error_response(request_id(request), @error_rate_limited, "Rate limit exceeded")}, state}
      {:error, :method_not_found} -> {{:error, error_response(request_id(request), @error_method_not_found, "Method not found")}, state}
      {:error, :forbidden} -> {{:error, error_response(request_id(request), @error_forbidden, "Permission denied")}, state}
      {:error, {:invalid_params, msg}} -> {{:error, error_response(request_id(request), @error_invalid_params, msg)}, state}
      {:error, reason} -> {{:error, error_response(request_id(request), @error_internal_error, inspect(reason))}, state}
    end
  end

  defp validate_json_rpc(%{"jsonrpc" => "2.0", "method" => m}) when is_binary(m), do: {:ok, :valid}
  defp validate_json_rpc(_), do: {:error, :invalid_request}

  defp authenticate_client(_request, %{current_user: user} = ctx, state) when not is_nil(user) do
    client_id = "user:#{user.id}"
    api_key = client_id
    existing = Map.get(state.clients, api_key)

    client = %ClientState{
      client_id: client_id,
      api_key: api_key,
      permissions: mcp_permissions_for_user(user),
      organization_id: ctx[:organization_id] || user.organization_id,
      authenticated: true,
      user: user,
      request_count: existing && existing.request_count || 0,
      action_count: existing && existing.action_count || 0,
      window_start: existing && existing.window_start || System.monotonic_time(:millisecond),
      metadata: %{auth_method: :api_user}
    }

    {:ok, client, %{state | clients: Map.put(state.clients, api_key, client)}}
  end

  defp authenticate_client(request, ctx, state) do
    api_key = ctx[:api_key] || get_in(request, ["params", "_api_key"]) || extract_bearer(ctx[:authorization])
    client_key = api_key || anonymous_api_key(ctx)
    method = request["method"]
    public_methods = [
      "initialize",
      "notifications/initialized",
      "tools/list",
      "resources/list",
      "prompts/list",
      "list_tools",
      "list_context_providers"
    ]

    case Map.get(state.clients, client_key) do
      nil ->
        if method in public_methods do
          client = %ClientState{client_id: client_key, api_key: client_key, permissions: [:read], request_count: 0,
                            action_count: 0, window_start: System.monotonic_time(:millisecond),
                            authenticated: false}

          {:ok, client, %{state | clients: Map.put(state.clients, client_key, client)}}
        else
          {:error, :unauthorized}
        end
      client -> {:ok, %{client | authenticated: true, permissions: normalize_permissions(client.permissions)}, state}
    end
  end

  defp check_rate_limit(client, request, state) do
    now = System.monotonic_time(:millisecond)
    {req_count, act_count, win_start} = if now - client.window_start > @rate_limit_window_ms do
      {0, 0, now}
    else
      {client.request_count, client.action_count, client.window_start}
    end

    is_action = action_request?(request)
    cond do
      req_count >= @rate_limit_max_requests -> {:error, :rate_limited}
      is_action and act_count >= @rate_limit_max_actions -> {:error, :rate_limited}
      true ->
        updated = %{client | request_count: req_count + 1,
                   action_count: if(is_action, do: act_count + 1, else: act_count),
                   window_start: win_start, last_request: now}
        {:ok, %{state | clients: Map.put(state.clients, client.api_key, updated)}}
    end
  end

  defp get_method(%{"method" => m}) when is_binary(m), do: {:ok, m}
  defp get_method(_), do: {:error, :invalid_request}

  defp get_tool(method, state) do
    case Map.get(state.tools, method) do
      nil -> {:error, :method_not_found}
      tool -> {:ok, tool}
    end
  end

  defp authorize_client(client, tool) do
    if MapSet.subset?(MapSet.new(normalize_permissions(tool.required_permissions)), MapSet.new(normalize_permissions(client.permissions))),
      do: :ok, else: {:error, :forbidden}
  end

  defp validate_params(params, tool) do
    params = params || %{}
    required = tool.input_schema[:required] || []
    missing = Enum.filter(required, &(!Map.has_key?(params, &1) and !Map.has_key?(params, to_string(&1))))
    if Enum.empty?(missing), do: {:ok, params},
      else: {:error, {:invalid_params, "Missing: #{Enum.join(missing, ", ")}"}}
  end

  ## Tool Definitions

  defp define_tools do
    %{
      "query_alerts" => %{
        description: "Search and retrieve security alerts",
        input_schema: %{properties: %{severity: %{type: :string}, status: %{type: :string},
                       agent_id: %{type: :string}, limit: %{type: :integer, default: 50}}, required: []},
        required_permissions: [:read],
        handler: &tool_query_alerts/2
      },
      "investigate_host" => %{
        description: "Get comprehensive investigation data for a host",
        input_schema: %{properties: %{agent_id: %{type: :string}, hostname: %{type: :string},
                       include_processes: %{type: :boolean}, include_network: %{type: :boolean}}, required: []},
        required_permissions: [:read],
        handler: &tool_investigate_host/2
      },
      "take_action" => %{
        description: "Execute response action on endpoint (isolate, kill_process, quarantine_file, scan)",
        input_schema: %{properties: %{action: %{type: :string}, agent_id: %{type: :string},
                       target: %{type: :string}, reason: %{type: :string},
                       scope: %{type: :string, enum: ["org", "agent"]}},
                       required: ["action", "agent_id", "reason", "scope"]},
        required_permissions: [:read, :execute],
        action_tool: true,
        handler: &tool_take_action/2
      },
      "get_threat_intel" => %{
        description: "Query threat intelligence for an indicator",
        input_schema: %{properties: %{indicator_type: %{type: :string}, indicator_value: %{type: :string}},
                       required: ["indicator_type", "indicator_value"]},
        required_permissions: [:read],
        handler: &tool_get_threat_intel/2
      },
      "search_events" => %{
        description: "Search telemetry events across agents",
        input_schema: %{properties: %{event_type: %{type: :string}, query: %{type: :string},
                       agent_id: %{type: :string}, severity: %{type: :string},
                       time_range: %{type: :string}, limit: %{type: :integer}}, required: []},
        required_permissions: [:read],
        handler: &tool_search_events/2
      },
      "get_timeline" => %{
        description: "Get chronological timeline of events for an entity",
        input_schema: %{properties: %{entity_type: %{type: :string}, entity_id: %{type: :string},
                       time_range: %{type: :string}}, required: ["entity_type", "entity_id"]},
        required_permissions: [:read],
        handler: &tool_get_timeline/2
      },
      "get_agent_info" => %{
        description: "Get detailed information about a specific agent",
        input_schema: %{properties: %{agent_id: %{type: :string}}, required: ["agent_id"]},
        required_permissions: [:read],
        handler: &tool_get_agent_info/2
      },
      "list_agents" => %{
        description: "List all agents with current status",
        input_schema: %{properties: %{status: %{type: :string}, os_type: %{type: :string}}, required: []},
        required_permissions: [:read],
        handler: &tool_list_agents/2
      }
    }
  end

  defp define_context_providers do
    %{
      "agent_status" => %{description: "Current status of all agents", parameters: %{}, handler: &ctx_agent_status/1},
      "recent_alerts" => %{description: "Recent alert summary", parameters: %{limit: %{type: :integer}}, handler: &ctx_recent_alerts/1},
      "threat_landscape" => %{description: "Current threat overview", parameters: %{}, handler: &ctx_threat_landscape/1},
      "active_investigations" => %{description: "Ongoing investigations", parameters: %{}, handler: &ctx_active_investigations/1},
      "system_health" => %{description: "System health metrics", parameters: %{}, handler: &ctx_system_health/1}
    }
  end

  ## Tool Handlers

  defp execute_tool(tool, params, client) do
    Logger.info("MCP: Executing tool by client #{client.client_id}")
    tool.handler.(params, client)
  rescue
    e -> Logger.error("MCP tool error: #{inspect(e)}"); {:error, :internal_error}
  end

  defp dispatch_method("initialize", request, _client, state) do
    version =
      case Application.spec(:tamandua_server, :vsn) do
        nil -> "dev"
        vsn -> to_string(vsn)
      end

    result = %{
      protocolVersion: "2024-11-05",
      serverInfo: %{
        name: "tamandua-mcp",
        title: "Tamandua MCP Server",
        version: version
      },
      capabilities: %{
        tools: %{listChanged: false},
        resources: %{listChanged: false},
        prompts: %{listChanged: false}
      }
    }

    {{:ok, success_response(request["id"], result)}, state}
  end

  defp dispatch_method("notifications/initialized", request, _client, state) do
    {{:ok, success_response(request["id"], %{})}, state}
  end

  defp dispatch_method("resources/list", request, _client, state) do
    {{:ok, success_response(request["id"], %{resources: serialize_context_providers(state.context_providers, :rpc)})}, state}
  end

  defp dispatch_method("prompts/list", request, _client, state) do
    {{:ok, success_response(request["id"], %{prompts: []})}, state}
  end

  defp dispatch_method("tools/list", request, _client, state) do
    {{:ok, success_response(request["id"], %{tools: serialize_tools(state.tools, :rpc)})}, state}
  end

  defp dispatch_method("list_tools", request, _client, state) do
    {{:ok, success_response(request["id"], serialize_tools(state.tools, :api))}, state}
  end

  defp dispatch_method("list_context_providers", request, _client, state) do
    {{:ok, success_response(request["id"], serialize_context_providers(state.context_providers, :api))}, state}
  end

  defp serialize_tools(tools, :rpc) do
    Enum.map(tools, fn {name, tool} ->
      %{
        name: name,
        description: tool.description,
        inputSchema: normalize_input_schema(tool.input_schema),
        required_permissions: normalize_json_value(tool.required_permissions)
      }
    end)
  end

  defp serialize_tools(tools, _format) do
    Enum.map(tools, fn {name, tool} ->
      %{
        name: name,
        description: tool.description,
        input_schema: normalize_input_schema(tool.input_schema),
        required_permissions: normalize_json_value(tool.required_permissions)
      }
    end)
  end

  defp serialize_context_providers(providers, :rpc) do
    Enum.map(providers, fn {name, provider} ->
      %{
        uri: "tamandua://context/#{name}",
        name: name,
        description: provider.description,
        mimeType: "application/json"
      }
    end)
  end

  defp serialize_context_providers(providers, _format) do
    Enum.map(providers, fn {name, provider} ->
      %{name: name, description: provider.description, parameters: normalize_json_value(provider.parameters)}
    end)
  end

  defp normalize_json_value(value) when is_map(value) do
    Map.new(value, fn {key, nested_value} ->
      {normalize_json_key(key), normalize_json_value(nested_value)}
    end)
  end

  defp normalize_json_value(value) when is_list(value), do: Enum.map(value, &normalize_json_value/1)
  defp normalize_json_value(nil), do: nil
  defp normalize_json_value(value) when is_boolean(value), do: value
  defp normalize_json_value(value) when is_atom(value), do: Atom.to_string(value)
  defp normalize_json_value(value), do: value

  defp normalize_json_key(key) when is_atom(key), do: Atom.to_string(key)
  defp normalize_json_key(key), do: key

  defp normalize_input_schema(schema) do
    schema
    |> normalize_json_value()
    |> case do
      %{"type" => _} = normalized -> normalized
      normalized when is_map(normalized) -> Map.put(normalized, "type", "object")
      _ -> %{"type" => "object", "properties" => %{}, "required" => []}
    end
  end

  defp anonymous_api_key(ctx) do
    peer =
      ctx[:remote_ip] ||
        ctx[:ip_address] ||
        ctx[:client_ip] ||
        remote_ip_from_conn(ctx[:conn])

    "anonymous:#{format_peer(peer)}"
  end

  defp format_peer({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_peer(tuple) when is_tuple(tuple), do: tuple |> Tuple.to_list() |> Enum.join(":")
  defp format_peer(value) when is_binary(value), do: value
  defp format_peer(_), do: "unknown"

  defp remote_ip_from_conn(%{remote_ip: remote_ip}), do: remote_ip
  defp remote_ip_from_conn(_), do: nil

  defp dispatch_method("tools/call", request, client, state) do
    params = request["params"] || %{}
    name = params["name"] || params[:name]
    arguments = params["arguments"] || params[:arguments] || %{}

    with true <- is_binary(name) || {:error, {:invalid_params, "Missing tool name"}},
         {:ok, tool} <- get_tool(name, state),
         :ok <- authorize_governance_tool_call(state.server_id, name, client),
         :ok <- authorize_client(client, tool),
         {:ok, validated_params} <- validate_params(arguments, tool) do
      {result, state} = execute_governed_tool(name, tool, validated_params, client, state)

      case result do
        {:ok, result} ->
          {{:ok, success_response(request["id"], %{content: [%{type: "json", json: result}], isError: false})}, state}

        {:error, reason} ->
          {tool_error_response(reason, request, state), state}
      end
    else
      error -> handle_dispatch_error(error, request, state)
    end
  end

  defp dispatch_method("context/get", request, _client, state) do
    params = request["params"] || %{}
    provider_name = params["name"] || params[:name] || params["provider"] || params[:provider]
    provider_params = params["params"] || params[:params] || %{}

    case Map.get(state.context_providers, provider_name) do
      nil ->
        {{:error, error_response(request["id"], @error_invalid_params, "Context provider not found")}, state}

      provider ->
        case provider.handler.(provider_params) do
          {:ok, context} -> {{:ok, success_response(request["id"], context)}, state}
          {:error, reason} -> {{:error, error_response(request["id"], @error_internal_error, inspect(reason))}, state}
        end
    end
  end

  defp dispatch_method(method, request, client, state) do
    with {:ok, tool} <- get_tool(method, state),
         :ok <- authorize_governance_tool_call(state.server_id, method, client),
         :ok <- authorize_client(client, tool),
         {:ok, params} <- validate_params(request["params"], tool) do
      {result, state} = execute_governed_tool(method, tool, params, client, state)

      case result do
        {:ok, result} -> {{:ok, success_response(request["id"], result)}, state}
        {:error, reason} -> {tool_error_response(reason, request, state), state}
      end
    else
      error -> handle_dispatch_error(error, request, state)
    end
  end

  defp handle_dispatch_error({:error, :method_not_found}, request, state),
    do: {{:error, error_response(request["id"], @error_method_not_found, "Method not found")}, state}

  defp handle_dispatch_error({:error, :forbidden}, request, state),
    do: {{:error, error_response(request["id"], @error_forbidden, "Permission denied")}, state}

  defp handle_dispatch_error({:error, :unauthorized}, request, state),
    do: {{:error, error_response(request["id"], @error_unauthorized, "Unauthorized")}, state}

  defp handle_dispatch_error({:error, {:governance_denied, reason}}, request, state),
    do: {{:error, error_response(request["id"], @error_forbidden, "Governance denied: #{inspect(reason)}")}, state}

  defp handle_dispatch_error({:error, {:invalid_params, msg}}, request, state),
    do: {{:error, error_response(request["id"], @error_invalid_params, msg)}, state}

  defp handle_dispatch_error({:error, reason}, request, state),
    do: {{:error, error_response(request["id"], @error_internal_error, inspect(reason))}, state}

  defp tool_error_response(:forbidden, request, _state),
    do: {:error, error_response(request["id"], @error_forbidden, "Permission denied")}

  defp tool_error_response(:unauthorized, request, _state),
    do: {:error, error_response(request["id"], @error_unauthorized, "Unauthorized")}

  defp tool_error_response({:invalid_params, msg}, request, _state),
    do: {:error, error_response(request["id"], @error_invalid_params, msg)}

  defp tool_error_response({:governance_denied, reason}, request, _state),
    do: {:error, error_response(request["id"], @error_forbidden, "Governance denied: #{inspect(reason)}")}

  defp tool_error_response(reason, request, _state),
    do: {:error, error_response(request["id"], @error_internal_error, inspect(reason))}

  defp execute_governed_tool(tool_name, tool, params, client, state) do
    start_time = System.monotonic_time(:millisecond)

    {result, state} =
      case prepare_tool_execution(tool_name, tool, params, client, state) do
        {:execute, state} ->
          {execute_tool(tool, params, client), state}

        {{:ok, _} = result, state} ->
          {result, state}

        {{:error, _} = result, state} ->
          {result, state}
      end

    duration_ms = System.monotonic_time(:millisecond) - start_time
    status = if match?({:ok, _}, result), do: :success, else: :error
    record_governance_tool_call(state.server_id, tool_name, client, params, status, duration_ms, result)
    audit_tool_call(tool_name, client, params, status, duration_ms, result)

    {result, state}
  end

  defp prepare_tool_execution(tool_name, %{action_tool: true}, params, client, state) do
    case enforce_action_policy(tool_name, params, client, state) do
      {:ok, :execute, state} -> {:execute, state}
      {:ok, response, state} -> {{:ok, response}, state}
      {:error, reason} -> {{:error, reason}, state}
    end
  end

  defp prepare_tool_execution(_tool_name, _tool, _params, _client, state), do: {:execute, state}

  defp tool_query_alerts(params, _client) do
    filters = params |> Map.take(["severity", "status", "agent_id"])
      |> Enum.map(fn {k, v} -> {String.to_atom(k), v} end) |> Map.new()
    alerts = Alerts.list_alerts(filters) |> Enum.take(min(params["limit"] || 50, 200)) |> Enum.map(&alert_to_map/1)
    {:ok, %{alerts: alerts, total: length(alerts)}}
  end

  defp tool_investigate_host(params, _client) do
    agent_id = params["agent_id"]
    case Registry.get(agent_id) do
      {:ok, info} ->
        alerts = Alerts.list_alerts(%{agent_id: agent_id}) |> Enum.take(10) |> Enum.map(&alert_to_map/1)
        {:ok, %{agent_id: info.agent_id, hostname: info.hostname, os_type: info.os_type,
               status: info.status, related_alerts: alerts, investigation_time: DateTime.utc_now()}}
      {:error, :not_found} -> {:error, "Host not found"}
    end
  end

  defp tool_take_action(params, client) do
    Logger.info("MCP: Action #{params["action"]} by #{client.client_id}")
    agent_id = params["agent_id"]
    action = params["action"]

    case Registry.get(agent_id) do
      {:ok, %{status: status}} when status in [:online, "online"] ->
        execute_action(action, agent_id, params["target"], client, params)

      {:ok, %{status: status}} when status in [:offline, "offline"] ->
        {:error, "Agent offline"}

      {:ok, %{status: status}} when status in [:isolated, "isolated"] ->
        if action == "unisolate" do
          execute_action(action, agent_id, params["target"], client, params)
        else
          {:error, "Agent isolated"}
        end
      _ -> {:error, "Agent not found or invalid state"}
    end
  end

  defp execute_action(action, agent_id, target, client, params) do
    result = case action do
      "isolate" -> Response.Executor.isolate_network(agent_id)
      "unisolate" -> Response.Executor.unisolate_network(agent_id)
      "kill_process" -> Response.Executor.kill_process(agent_id, parse_int(target))
      "quarantine_file" -> Response.Executor.quarantine_file(agent_id, target)
      "scan" -> Response.Executor.scan_path(agent_id, target || "/")
      _ -> {:error, "Unknown action"}
    end
    case result do
      :ok ->
        audit_action_result(client, params, :success, nil)

        {:ok, %{action: action, agent_id: agent_id, status: "executed",
                executed_by: client.client_id, timestamp: DateTime.utc_now()}}

      {:ok, resp} ->
        audit_action_result(client, params, :success, nil)

        {:ok, %{action: action, agent_id: agent_id, status: "executed",
                response: resp, executed_by: client.client_id, timestamp: DateTime.utc_now()}}
      {:error, reason} ->
        audit_action_result(client, params, :failure, inspect(reason))
        {:error, "Action failed: #{inspect(reason)}"}
    end
  end

  defp tool_get_threat_intel(params, _client) do
    case Detection.IOCs.lookup(params["indicator_type"], params["indicator_value"]) do
      {:ok, ioc} -> {:ok, %{found: true, indicator: params["indicator_value"],
                           type: params["indicator_type"], threat_level: ioc.severity,
                           source: ioc.source, tags: ioc.tags, description: ioc.description}}
      {:error, :not_found} -> {:ok, %{found: false, indicator: params["indicator_value"],
                                     type: params["indicator_type"], message: "No threat intel found"}}
    end
  end

  defp tool_search_events(params, client) do
    with {:ok, organization_id} <- require_organization_scope(client) do
      do_search_events(params, organization_id)
    end
  end

  defp do_search_events(params, organization_id) do
    limit = params |> Map.get("limit", 50) |> parse_int() |> clamp(1, 200)
    query_text = params["query"] || params[:query]
    event_type = params["event_type"] || params[:event_type]
    agent_id = params["agent_id"] || params[:agent_id]
    severity = params["severity"] || params[:severity]
    since = mcp_time_range_start(params["time_range"] || params[:time_range] || "24h")

    events =
      Event
      |> where([e], e.timestamp >= ^since)
      |> maybe_filter_org(organization_id)
      |> maybe_filter_event_type(event_type)
      |> maybe_filter_agent_id(agent_id)
      |> maybe_filter_severity(severity)
      |> maybe_filter_event_query(query_text)
      |> order_by([e], desc: e.timestamp)
      |> limit(^limit)
      |> Repo.all()
      |> Enum.map(&mcp_event_to_map/1)

    {:ok,
     %{
       events: events,
       total: length(events),
       limit: limit,
       time_range: params["time_range"] || params[:time_range] || "24h",
       organization_scoped: not is_nil(organization_id)
     }}
  end

  defp tool_get_timeline(params, _client) do
    {:ok, %{entity_type: params["entity_type"], entity_id: params["entity_id"],
           time_range: params["time_range"] || "24h", events: [], event_count: 0}}
  end

  defp tool_get_agent_info(params, _client) do
    case Registry.get(params["agent_id"]) do
      {:ok, i} -> {:ok, %{agent_id: i.agent_id, hostname: i.hostname, os_type: i.os_type,
                         os_version: i.os_version, agent_version: i.agent_version, status: i.status,
                         last_seen: format_ts(i.last_seen_at), capabilities: i.capabilities}}
      {:error, :not_found} -> {:error, "Agent not found"}
    end
  end

  defp tool_list_agents(params, _client) do
    agents = Registry.list_all()
      |> Enum.filter(&(is_nil(params["status"]) or to_string(&1.status) == params["status"]))
      |> Enum.filter(&(is_nil(params["os_type"]) or &1.os_type == params["os_type"]))
      |> Enum.map(&%{agent_id: &1.agent_id, hostname: &1.hostname, os_type: &1.os_type,
                    status: &1.status, last_seen: format_ts(&1.last_seen_at)})
    {:ok, %{agents: agents, total: length(agents)}}
  end

  ## Context Handlers

  defp ctx_agent_status(_) do
    counts = Registry.count_by_status()
    {:ok, %{total: Enum.sum(Map.values(counts)), online: counts[:online] || 0,
           offline: counts[:offline] || 0, isolated: counts[:isolated] || 0, timestamp: DateTime.utc_now()}}
  end

  defp ctx_recent_alerts(params) do
    alerts = Alerts.list_recent(limit: params["limit"] || 10) |> Enum.map(&alert_to_map/1)
    {:ok, %{alerts: alerts, total_open: Alerts.count_open(), critical: Alerts.count_by_severity(:critical),
           high: Alerts.count_by_severity(:high), timestamp: DateTime.utc_now()}}
  end

  defp ctx_threat_landscape(_) do
    {:ok, %{active_threats: Alerts.count_by_severity(:critical) + Alerts.count_by_severity(:high),
           ioc_count: Detection.IOCs.count(), timestamp: DateTime.utc_now()}}
  end

  defp ctx_active_investigations(_) do
    investigating = Alerts.list_alerts(%{status: "investigating"}) |> Enum.map(&alert_to_map/1)
    {:ok, %{investigations: investigating, count: length(investigating), timestamp: DateTime.utc_now()}}
  end

  defp ctx_system_health(_) do
    {:ok, %{status: :healthy, agents: Registry.count_by_status(),
           detection_engine: Detection.Engine.status(), timestamp: DateTime.utc_now()}}
  end

  ## Helpers

  defp enforce_action_policy(tool_name, params, client, state) do
    with :ok <- require_authenticated_action_client(client),
         :ok <- require_execute_permission(client),
         {:ok, reason} <- require_reason(params),
         {:ok, scope} <- require_scope(params),
         {:ok, organization_id} <- require_organization_scope(client),
         :ok <- maybe_require_agent_scope(params, organization_id),
         :ok <- audit_action_request(client, params, reason, scope, organization_id) do
      cond do
        dry_run?(params) ->
          {:ok, dry_run_action_response(params, client), state}

        approval_required?(params) ->
          queue_action_approval(tool_name, params, client, reason, scope, organization_id, state)

        true ->
          {:ok, :execute, state}
      end
    end
  end

  defp require_authenticated_action_client(%ClientState{authenticated: true}), do: :ok
  defp require_authenticated_action_client(_), do: {:error, :unauthorized}

  defp require_execute_permission(client) do
    if :execute in normalize_permissions(client.permissions), do: :ok, else: {:error, :forbidden}
  end

  defp require_reason(params) do
    case params["reason"] || params[:reason] do
      reason when is_binary(reason) ->
        reason = String.trim(reason)
        if reason == "", do: {:error, {:invalid_params, "Missing reason"}}, else: {:ok, reason}

      _ ->
        {:error, {:invalid_params, "Missing reason"}}
    end
  end

  defp require_scope(params) do
    case params["scope"] || params[:scope] do
      scope when scope in ["org", "agent", :org, :agent] -> {:ok, to_string(scope)}
      _ -> {:error, {:invalid_params, "Missing or invalid scope"}}
    end
  end

  defp require_organization_scope(%ClientState{organization_id: org_id}) when is_binary(org_id),
    do: {:ok, org_id}

  defp require_organization_scope(_), do: {:error, {:invalid_params, "Missing organization scope"}}

  defp require_agent_scope(_organization_id, nil), do: {:error, {:invalid_params, "Missing agent_id"}}

  defp require_agent_scope(organization_id, agent_id) do
    case Agents.get_agent_for_org(organization_id, agent_id) do
      {:ok, _agent} -> :ok
      {:error, :not_found} -> {:error, :forbidden}
    end
  rescue
    e ->
      Logger.error("MCP action scope check failed: #{inspect(e)}")
      {:error, :forbidden}
  end

  defp maybe_require_agent_scope(params, organization_id) do
    if dry_run?(params) do
      :ok
    else
      require_agent_scope(organization_id, params["agent_id"] || params[:agent_id])
    end
  end

  defp dry_run?(params), do: truthy?(params["dry_run"] || params[:dry_run])

  defp approval_required?(params) do
    action = params["action"] || params[:action]
    action in approval_required_actions()
  end

  defp approval_required_actions do
    :tamandua_server
    |> Application.get_env(:mcp_action_policy, [])
    |> Keyword.get(:approval_required_actions, @approval_required_actions)
    |> Enum.map(&to_string/1)
  end

  defp queue_action_approval(tool_name, params, client, reason, scope, organization_id, state) do
    approval_id = generate_id()

    approval = %ApprovalRequest{
      id: approval_id,
      timestamp: DateTime.utc_now(),
      tool_name: tool_name,
      params: params,
      client: client,
      client_id: client.client_id,
      organization_id: organization_id,
      reason_hash: hash_value(reason),
      scope: scope,
      status: :pending_approval
    }

    audit_action_queued(client, params, approval_id, organization_id)

    response = %{
      action: params["action"] || params[:action],
      agent_id: params["agent_id"] || params[:agent_id],
      status: "pending_approval",
      approval_id: approval_id,
      dry_run: false,
      executed: false,
      queued_at: approval.timestamp
    }

    {:ok, response, %{state | approval_queue: Map.put(state.approval_queue, approval_id, approval)}}
  end

  defp dry_run_action_response(params, client) do
    %{
      action: params["action"] || params[:action],
      agent_id: params["agent_id"] || params[:agent_id],
      status: "dry_run",
      dry_run: true,
      executed: false,
      would_require_approval: approval_required?(params),
      executed_by: client.client_id,
      timestamp: DateTime.utc_now()
    }
  end

  defp truthy?(value) when value in [true, "true", "1", 1, :true], do: true
  defp truthy?(_), do: false

  defp audit_action_request(client, params, reason, scope, organization_id) do
    audit_action_event("mcp.response_action.requested", client, params, organization_id, %{
      reason_hash: hash_value(reason),
      scope: scope,
      result: "requested"
    })
  end

  defp audit_action_queued(client, params, approval_id, organization_id) do
    audit_action_event("mcp.response_action.pending_approval", client, params, organization_id, %{
      approval_id: approval_id,
      result: "pending_approval"
    })
  end

  defp audit_action_approval(client, params, approver_context, decision) do
    audit_action_event("mcp.response_action.#{decision}", client, params, client.organization_id, %{
      approver_id: approver_context[:user_id] || approver_context["user_id"],
      decision: to_string(decision),
      result: to_string(decision)
    })
  end

  defp audit_action_result(client, params, :success, _error) do
    audit_action_event("mcp.response_action.completed", client, params, client.organization_id, %{
      result: "success"
    })
  end

  defp audit_action_result(client, params, :failure, error) do
    audit_action_event("mcp.response_action.failed", client, params, client.organization_id, %{
      result: "failed",
      error_hash: hash_value(error)
    })
  end

  defp audit_action_event(action_name, client, params, organization_id, extra) do
    attrs = %{
      user_id: client.user && client.user.id,
      user_email: client.user && client.user.email,
      action: action_name,
      action_type: "response",
      resource_type: "agent",
      resource_id: params["agent_id"] || params[:agent_id],
      organization_id: organization_id,
      severity: "high",
      category: "response",
      success: Map.get(extra, :result) in ["requested", "success", "pending_approval", "approved"],
      error_message: Map.get(extra, :error_message),
      details:
        %{
          mcp: true,
          client_id: client.client_id,
          action: params["action"] || params[:action],
          target_hash: hash_value(params["target"] || params[:target]),
          scope: params["scope"] || params[:scope],
          reason_hash: hash_value(params["reason"] || params[:reason])
        }
        |> Map.merge(extra)
        |> sanitize_audit_details()
    }

    case AuditLog.log(attrs) do
      {:ok, _entry} -> :ok
      {:error, reason} -> {:error, {:invalid_params, "Unable to write audit log: #{inspect(reason)}"}}
    end
  rescue
    e ->
      Logger.error("Failed to write MCP durable audit log: #{inspect(e)}")
      {:error, {:invalid_params, "Unable to write audit log"}}
  end

  defp action_request?(%{"method" => "take_action"}), do: true
  defp action_request?(%{"method" => "tools/call", "params" => %{"name" => "take_action"}}), do: true
  defp action_request?(%{"method" => "tools/call", "params" => %{name: "take_action"}}), do: true
  defp action_request?(_), do: false

  defp mcp_permissions_for_user(user) do
    permissions = [:read]

    if user_can_execute_response?(user) do
      [:execute | permissions]
    else
      permissions
    end
  end

  defp user_can_execute_response?(%{role: role}) when role in ["admin", "responder"], do: true

  defp user_can_execute_response?(user) do
    RBAC.can?(user, :response_execute)
  rescue
    _ -> false
  end

  defp normalize_permissions(permissions) when is_list(permissions) do
    Enum.flat_map(permissions, fn
      permission when is_atom(permission) -> [permission]
      permission when is_binary(permission) -> [permission_to_mcp(permission)]
      _ -> []
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp normalize_permissions(_), do: []

  defp permission_to_mcp("read"), do: :read
  defp permission_to_mcp("write"), do: :write
  defp permission_to_mcp("execute"), do: :execute
  defp permission_to_mcp("response_execute"), do: :execute
  defp permission_to_mcp("response:execute"), do: :execute

  defp permission_to_mcp(permission) do
    String.to_existing_atom(permission)
  rescue
    ArgumentError -> nil
  end

  defp normalize_context_opts(opts) when is_map(opts), do: opts
  defp normalize_context_opts(opts) when is_list(opts), do: Map.new(opts)
  defp normalize_context_opts(scope) when is_binary(scope), do: %{scope: scope}
  defp normalize_context_opts(_), do: %{}

  defp request_id(%{} = request), do: request["id"]
  defp request_id(_), do: nil

  defp map_get(%{} = map, key), do: Map.get(map, key)
  defp map_get(_, _key), do: nil

  defp sanitize_audit_details(details) when is_map(details) do
    Map.drop(details, [:api_key, :password, :token, :secret, "api_key", "password", "token", "secret"])
  end

  defp ensure_governance_registration(tools, context_providers) do
    if Process.whereis(MCPGovernance) do
      tools = Map.keys(tools)
      resources = Map.keys(context_providers)

      existing =
        MCPGovernance.list_servers()
        |> Enum.find(&(&1.endpoint_url == @internal_mcp_endpoint))

      case existing do
        %{id: server_id} ->
          MCPGovernance.set_server_state(server_id, :active)
          MCPGovernance.set_permissions(server_id, default_governance_permissions(tools, resources))
          server_id

        nil ->
          case MCPGovernance.register_server(%{
                 name: "Tamandua internal MCP server",
                 endpoint_url: @internal_mcp_endpoint,
                 description: "Internal MCP endpoint exposing Tamandua security tools",
                 owner: "tamandua-server",
                 tools: tools,
                 resources: resources
               }) do
            {:ok, server_id} ->
              server_id

            {:error, reason} ->
              Logger.warning("MCP governance registration failed: #{inspect(reason)}")
              generate_id()
          end
      end
    else
      Logger.warning("MCP governance unavailable at MCPServer startup")
      generate_id()
    end
  rescue
    e ->
      Logger.warning("MCP governance registration error: #{Exception.message(e)}")
      generate_id()
  end

  defp default_governance_permissions(tools, resources) do
    %{
      allowed_tools: tools,
      blocked_tools: [],
      allowed_resources: resources,
      blocked_resources: [],
      max_calls_per_minute: @rate_limit_max_requests,
      max_data_mb_per_hour: 500,
      allowed_callers: []
    }
  end

  defp authorize_governance_tool_call(server_id, tool_name, client) do
    if Process.whereis(MCPGovernance) do
      case MCPGovernance.authorize_tool_call(server_id, tool_name, client.client_id || "anonymous") do
        :ok -> :ok
        {:error, reason} -> {:error, {:governance_denied, reason}}
      end
    else
      Logger.warning("MCP governance unavailable while authorizing #{tool_name}")
      :ok
    end
  end

  defp record_governance_tool_call(server_id, tool_name, client, params, result_status, duration_ms, result) do
    if Process.whereis(MCPGovernance) do
      MCPGovernance.record_tool_call(%{
        server_id: server_id,
        tool_name: tool_name,
        caller_id: client.client_id || "anonymous",
        params: sanitize_params(params),
        result_status: result_status,
        result_size_bytes: encoded_size(result),
        latency_ms: duration_ms
      })
    end

    :ok
  rescue
    e ->
      Logger.warning("Failed to record MCP governance tool call: #{Exception.message(e)}")
      :ok
  end

  defp audit_tool_call(tool_name, client, params, result_status, duration_ms, result) do
    attrs = %{
      user_id: client.user && client.user.id,
      user_email: client.user && client.user.email,
      action: "mcp.tool_call",
      action_type: "mcp",
      resource_type: "mcp_tool",
      resource_id: tool_name,
      organization_id: client.organization_id,
      severity: "info",
      category: "security",
      success: result_status == :success,
      error_message: if(result_status == :error, do: "mcp_tool_call_failed", else: nil),
      details: %{
        mcp: true,
        client_id: client.client_id,
        tool_name: tool_name,
        result_status: to_string(result_status),
        duration_ms: duration_ms,
        error_hash: if(result_status == :error, do: hash_value(inspect_result_error(result)), else: nil),
        params: sanitize_params(params)
      }
    }

    case AuditLog.log(attrs) do
      {:ok, _entry} -> :ok
      {:error, reason} -> Logger.warning("Failed to write MCP tool audit: #{inspect(reason)}")
    end
  rescue
    e ->
      Logger.warning("Failed to write MCP tool audit: #{Exception.message(e)}")
      :ok
  end

  defp approval_to_map(%ApprovalRequest{} = approval) do
    %{
      id: approval.id,
      tool_name: approval.tool_name,
      client_id: approval.client_id,
      organization_id: approval.organization_id,
      action: approval.params["action"] || approval.params[:action],
      agent_id: approval.params["agent_id"] || approval.params[:agent_id],
      scope: approval.scope,
      reason_hash: approval.reason_hash,
      status: approval.status,
      timestamp: DateTime.to_iso8601(approval.timestamp)
    }
  end

  defp filter_approvals(approvals, opts) do
    opts = normalize_context_opts(opts)

    approvals
    |> Enum.filter(&(is_nil(opts[:organization_id]) or &1.organization_id == opts[:organization_id]))
    |> Enum.filter(&(is_nil(opts["organization_id"]) or &1.organization_id == opts["organization_id"]))
  end

  defp encoded_size(value) do
    value
    |> inspect(limit: 20, printable_limit: 200)
    |> byte_size()
  end

  defp inspect_result_error({:error, reason}), do: inspect(reason)
  defp inspect_result_error(_), do: nil

  defp hash_value(nil), do: nil

  defp hash_value(value) do
    value
    |> to_string()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
    |> binary_part(0, 16)
  end

  defp alert_to_map(a), do: %{id: a.id, title: a.title, description: a.description,
    severity: a.severity, status: a.status, agent_id: a.agent_id, created_at: a.inserted_at,
    mitre_tactics: a.mitre_tactics, mitre_techniques: a.mitre_techniques}

  defp audit_entry_to_map(e), do: %{id: e.id, timestamp: DateTime.to_iso8601(e.timestamp),
    client_id: e.client_id, method: e.method, result_status: e.result_status,
    duration_ms: e.duration_ms, ip_address: e.ip_address}

  defp filter_audit_entries(entries, opts) do
    entries
    |> Enum.filter(&(is_nil(opts[:client_id]) or &1.client_id == opts[:client_id]))
    |> Enum.filter(&(is_nil(opts[:method]) or &1.method == opts[:method]))
  end

  defp format_ts(nil), do: nil
  defp format_ts(ms) when is_integer(ms), do: ms |> DateTime.from_unix!(:millisecond) |> DateTime.to_iso8601()
  defp format_ts(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp parse_int(nil), do: nil
  defp parse_int(v) when is_integer(v), do: v
  defp parse_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {i, _} -> i
      _ -> nil
    end
  end

  defp clamp(nil, min, _max), do: min
  defp clamp(value, min, _max) when value < min, do: min
  defp clamp(value, _min, max) when value > max, do: max
  defp clamp(value, _min, _max), do: value

  defp mcp_time_range_start(nil), do: mcp_time_range_start("24h")
  defp mcp_time_range_start("all"), do: ~U[1970-01-01 00:00:00Z]

  defp mcp_time_range_start(range) when is_binary(range) do
    case Regex.run(~r/^(\d+)([mhd])$/, String.trim(range)) do
      [_, amount, unit] ->
        amount = String.to_integer(amount)

        seconds =
          case unit do
            "m" -> amount * 60
            "h" -> amount * 3_600
            "d" -> amount * 86_400
          end

        DateTime.add(DateTime.utc_now(), -seconds, :second)

      _ ->
        DateTime.add(DateTime.utc_now(), -86_400, :second)
    end
  end

  defp mcp_time_range_start(_range), do: mcp_time_range_start("24h")

  defp maybe_filter_org(query, nil), do: query
  defp maybe_filter_org(query, ""), do: query
  defp maybe_filter_org(query, organization_id), do: where(query, [e], e.organization_id == ^organization_id)

  defp maybe_filter_event_type(query, nil), do: query
  defp maybe_filter_event_type(query, ""), do: query
  defp maybe_filter_event_type(query, event_type), do: where(query, [e], e.event_type == ^event_type)

  defp maybe_filter_agent_id(query, nil), do: query
  defp maybe_filter_agent_id(query, ""), do: query
  defp maybe_filter_agent_id(query, agent_id), do: where(query, [e], e.agent_id == ^agent_id)

  defp maybe_filter_severity(query, nil), do: query
  defp maybe_filter_severity(query, ""), do: query
  defp maybe_filter_severity(query, severity), do: where(query, [e], e.severity == ^severity)

  defp maybe_filter_event_query(query, nil), do: query
  defp maybe_filter_event_query(query, ""), do: query

  defp maybe_filter_event_query(query, text) when is_binary(text) do
    pattern = "%#{String.replace(text, "%", "\\%")}%"

    where(query, [e],
      ilike(e.event_type, ^pattern) or
        ilike(e.severity, ^pattern) or
        fragment("?::text ILIKE ?", e.payload, ^pattern) or
        fragment("?::text ILIKE ?", e.enrichment, ^pattern)
    )
  end

  defp maybe_filter_event_query(query, _text), do: query

  defp mcp_event_to_map(%Event{} = event) do
    %{
      id: event.id,
      event_type: event.event_type,
      timestamp: format_ts(event.timestamp),
      severity: event.severity,
      agent_id: event.agent_id,
      organization_id: event.organization_id,
      sha256: event_sha256(event.sha256),
      payload: event.payload || %{},
      enrichment: event.enrichment || %{},
      detections: event.detections || []
    }
  end

  defp event_sha256(nil), do: nil
  defp event_sha256(value) when is_binary(value), do: Base.encode16(value, case: :lower)
  defp event_sha256(value), do: value

  defp generate_id, do: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  defp extract_bearer(nil), do: nil
  defp extract_bearer("Bearer " <> t), do: String.trim(t)
  defp extract_bearer(_), do: nil

  defp sanitize_params(nil), do: nil
  defp sanitize_params(p) when is_map(p) do
    %{}
    |> put_if_present("action", p["action"] || p[:action])
    |> put_if_present("agent_id", p["agent_id"] || p[:agent_id])
    |> put_if_present("severity", p["severity"] || p[:severity])
    |> put_if_present("status", p["status"] || p[:status])
    |> put_if_present("indicator_type", p["indicator_type"] || p[:indicator_type])
    |> put_if_present("indicator_hash", hash_value(p["indicator_value"] || p[:indicator_value]))
    |> put_if_present("target_hash", hash_value(p["target"] || p[:target]))
    |> put_if_present("dry_run", p["dry_run"] || p[:dry_run])
    |> put_if_present("param_keys", Map.keys(p) |> Enum.map(&to_string/1) |> Enum.sort())
  end

  defp put_if_present(map, _key, nil), do: map
  defp put_if_present(map, _key, []), do: map
  defp put_if_present(map, key, value), do: Map.put(map, key, value)

  defp add_audit_entry(state, entry) do
    log = :queue.in(entry, state.audit_log)
    log = if :queue.len(log) > @audit_log_max_entries, do: elem(:queue.out(log), 1), else: log
    %{state | audit_log: log}
  end

  defp update_stats(state, result) do
    s = state.stats
    %{state | stats: %{s | total_requests: s.total_requests + 1,
      successful_requests: s.successful_requests + if(match?({:ok, _}, result), do: 1, else: 0),
      failed_requests: s.failed_requests + if(match?({:error, _}, result), do: 1, else: 0)}}
  end

  defp success_response(id, result), do: %{"jsonrpc" => "2.0", "id" => id, "result" => result}
  defp error_response(id, code, msg), do: %{"jsonrpc" => "2.0", "id" => id, "error" => %{"code" => code, "message" => msg}}

end
