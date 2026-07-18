defmodule TamanduaServer.AISecurity.MCPGovernance do
  @moduledoc """
  MCP (Model Context Protocol) Server Governance.

  GenServer that governs and audits all MCP server connections and tool
  invocations within the Tamandua platform.  Provides:

  - **Server registry**: track registered MCP servers, their allowed
    tools and resources, connection status, and health
  - **Permission model**: fine-grained allowlist/blocklist for which
    MCP servers can access which data and tools
  - **Audit logging**: metadata-only log of every MCP tool call with
    sanitized parameter shape, result size, latency, and caller identity
  - **Anomaly detection**: statistical baselines for tool call frequency
    and data volume, with alerts on deviations
  - **Health monitoring**: periodic heartbeat checks, uptime tracking,
    and automatic disabling of unhealthy servers

  Uses ETS for fast lookup and maintains bounded in-memory state.
  """

  use GenServer
  require Logger

  # ETS tables
  @servers_table :mcp_governance_servers
  @permissions_table :mcp_governance_permissions
  @audit_table :mcp_governance_audit
  @baselines_table :mcp_governance_baselines

  # Limits
  @max_audit_entries 100_000
  @anomaly_z_threshold 3.0
  @default_max_result_bytes 10 * 1_024 * 1_024
  @sensitive_param_keys ~w(prompt body content secret password token api_key api-key
                            authorization credential private_key access_key session cookie)
  @output_scan_metadata_keys ~w(enabled scanner status action injection_detected
                                categories rule_ids confidence scanned_at)
  @secret_read_tool_pattern Regex.compile!(
                              "((secret|credential|password|token|key).*" <>
                                "(read|get|fetch|list)|(read|get|fetch|list).*" <>
                                "(secret|credential|password|token|key)|vault)"
                            )
  @resource_read_tool_pattern ~r/(read|get|fetch|list|query|search|download)/
  @network_tool_pattern ~r/(http|https|network|request|webhook|upload|post|send|curl|fetch_url)/
  @supported_tool_classes ~w(secret_read resource_read sensitive_resource network_access
                             shell_execution code_execution filesystem_write destructive
                             privileged_operation)

  # Intervals
  @health_check_interval :timer.seconds(30)
  @baseline_update_interval :timer.minutes(10)
  @audit_trim_interval :timer.minutes(5)
  @health_timeout_ms 5_000

  # Server states
  @valid_states [:active, :disabled, :unhealthy, :pending_review]

  defstruct [
    :stats,
    :anomaly_alerts
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Register an MCP server for governance.

  Server info map:
  - `:name` (required) - human-readable name
  - `:endpoint_url` (required) - server endpoint URL
  - `:description` - server description
  - `:owner` - responsible team/person
  - `:organization_id` - tenant ID
  - `:tools` - list of tool name strings the server provides
  - `:resources` - list of resource URIs the server provides
  """
  @spec register_server(map()) :: {:ok, String.t()} | {:error, term()}
  def register_server(server_info) do
    GenServer.call(__MODULE__, {:register_server, server_info})
  end

  @doc """
  Unregister an MCP server (removes it from governance).
  """
  @spec unregister_server(String.t()) :: :ok | {:error, :not_found}
  def unregister_server(server_id) do
    GenServer.call(__MODULE__, {:unregister_server, server_id})
  end

  @doc """
  Update the state of an MCP server (active, disabled, etc.).
  """
  @spec set_server_state(String.t(), atom()) :: :ok | {:error, term()}
  def set_server_state(server_id, new_state) when new_state in @valid_states do
    GenServer.call(__MODULE__, {:set_server_state, server_id, new_state})
  end

  @doc """
  List all registered MCP servers with their status.
  """
  @spec list_servers(keyword()) :: [map()]
  def list_servers(opts \\ []) do
    GenServer.call(__MODULE__, {:list_servers, opts})
  end

  @doc """
  Get detailed info about a specific MCP server.
  """
  @spec get_server(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_server(server_id) do
    GenServer.call(__MODULE__, {:get_server, server_id})
  end

  @doc """
  Set permissions for an MCP server.

  Permission map:
  - `:allowed_tools` - list of tool names the server is allowed to expose
  - `:blocked_tools` - list of tool names that are blocked
  - `:allowed_resources` - list of resource URI patterns allowed
  - `:blocked_resources` - list of resource URI patterns blocked
  - `:max_calls_per_minute` - rate limit for tool calls
  - `:max_data_mb_per_hour` - data volume limit in MB
  - `:allowed_callers` - list of user/client IDs allowed to use this server
  - `:high_risk_tool_classes` - classified tool/resource classes to block
    unless the class also requires approval and approval context is supplied.
    Supported classes are `secret_read`, `resource_read`, `sensitive_resource`,
    `network_access`, `shell_execution`, `code_execution`, `filesystem_write`,
    `destructive`, and `privileged_operation` (atoms or strings).
  - `:sensitive_resource_patterns` - glob patterns for secrets and sensitive URIs
  - `:max_result_bytes` - maximum estimated/actual tool result size
  - `:approval_required_classes` - classes which require `approval_granted: true`
  - `:tool_output_injection_scanning` - output scanner policy metadata
  """
  @spec set_permissions(String.t(), map()) :: :ok | {:error, term()}
  def set_permissions(server_id, permissions) do
    GenServer.call(__MODULE__, {:set_permissions, server_id, permissions})
  end

  @doc """
  Get permissions for an MCP server.
  """
  @spec get_permissions(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_permissions(server_id) do
    case :ets.lookup(@permissions_table, server_id) do
      [{^server_id, perms}] -> {:ok, perms}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Authorize a tool call before it is executed.

  The optional context-aware arity also checks resource URIs, classified risk,
  approval state, expected result size, and recent tool-call chains. Supported
  context keys include `:resource_uri`, `:resource_uris`, `:approval_granted`,
  `:expected_result_bytes`, and `:recent_tool_calls`.

  Returns:
  - `:ok` if authorized
  - `{:error, reason}` if denied
  """
  @spec authorize_tool_call(String.t(), String.t(), String.t()) :: :ok | {:error, term()}
  def authorize_tool_call(server_id, tool_name, caller_id) do
    authorize_tool_call(server_id, tool_name, caller_id, %{})
  end

  @spec authorize_tool_call(String.t(), String.t(), String.t(), map() | keyword()) ::
          :ok | {:error, term()}
  def authorize_tool_call(server_id, tool_name, caller_id, context) do
    GenServer.call(
      __MODULE__,
      {:authorize_tool_call, server_id, tool_name, caller_id, normalize_context(context)}
    )
  end

  @doc """
  Enforce result-size and tool-output injection policy using metadata only.

  The result body must not be passed. `metadata` accepts `:result_size_bytes`
  and an `:output_scan` map containing scanner status and detection fields.
  """
  @spec authorize_tool_result(String.t(), String.t(), non_neg_integer(), map()) ::
          {:ok, map()} | {:error, term()}
  @spec authorize_tool_result(String.t(), String.t(), non_neg_integer()) ::
          {:ok, map()} | {:error, term()}
  def authorize_tool_result(server_id, tool_name, result_size_bytes, metadata \\ %{})
      when is_integer(result_size_bytes) and result_size_bytes >= 0 and is_map(metadata) do
    GenServer.call(
      __MODULE__,
      {:authorize_tool_result, server_id, tool_name, result_size_bytes, metadata}
    )
  end

  @doc """
  Record a completed MCP tool call for audit and anomaly tracking.

  Call info:
  - `:server_id` - MCP server ID
  - `:tool_name` - name of the tool called
  - `:caller_id` - who initiated the call
  - `:params` - tool call parameters (sanitized)
  - `:result_status` - :success | :error
  - `:result_size_bytes` - approximate size of the result
  - `:latency_ms` - call latency in milliseconds
  """
  @spec record_tool_call(map()) :: :ok
  def record_tool_call(call_info) do
    GenServer.cast(__MODULE__, {:record_tool_call, call_info})
  end

  @doc """
  Get audit log for MCP tool calls with optional filters.
  """
  @spec get_audit_log(keyword()) :: [map()]
  def get_audit_log(opts \\ []) do
    GenServer.call(__MODULE__, {:get_audit_log, opts})
  end

  @doc """
  Get current anomaly alerts.
  """
  @spec get_anomaly_alerts() :: [map()]
  def get_anomaly_alerts do
    GenServer.call(__MODULE__, :get_anomaly_alerts)
  end

  @doc """
  Get governance statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    :ets.new(@servers_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@permissions_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@audit_table, [:named_table, :ordered_set, :public, read_concurrency: true])
    :ets.new(@baselines_table, [:named_table, :set, :public, read_concurrency: true])

    state = %__MODULE__{
      stats: init_stats(),
      anomaly_alerts: []
    }

    schedule_health_check()
    schedule_baseline_update()
    schedule_audit_trim()

    Logger.info("[MCPGovernance] MCP Server Governance initialized")
    {:ok, state}
  end

  @impl true
  def handle_call({:register_server, info}, _from, state) do
    name = info[:name]
    endpoint_url = info[:endpoint_url]

    if is_nil(name) or is_nil(endpoint_url) do
      {:reply, {:error, :missing_required_fields}, state}
    else
      server_id = "mcp-" <> UUID.uuid4()
      now = DateTime.utc_now()

      entry = %{
        id: server_id,
        name: name,
        endpoint_url: endpoint_url,
        description: info[:description] || "",
        owner: info[:owner],
        organization_id: info[:organization_id] || "default",
        tools: info[:tools] || [],
        resources: info[:resources] || [],
        state: :active,
        health: %{
          status: :unknown,
          last_check: nil,
          uptime_checks: 0,
          uptime_successes: 0,
          last_error: nil
        },
        registered_at: now,
        last_seen_at: now,
        call_count: 0,
        data_volume_bytes: 0
      }

      :ets.insert(@servers_table, {server_id, entry})

      # Set default permissions (allow all registered tools)
      default_perms =
        normalize_permissions(%{
          allowed_tools: info[:tools] || [],
          blocked_tools: [],
          allowed_resources: info[:resources] || [],
          blocked_resources: [],
          max_calls_per_minute: 100,
          max_data_mb_per_hour: 500,
          # empty = all callers allowed
          allowed_callers: []
        })

      :ets.insert(@permissions_table, {server_id, default_perms})

      # Initialize baseline
      :ets.insert(
        @baselines_table,
        {server_id,
         %{
           call_counts: [],
           data_volumes: [],
           tool_distribution: %{},
           updated_at: now
         }}
      )

      new_stats = increment_stat(state.stats, :servers_registered)
      Logger.info("[MCPGovernance] MCP server registered: #{server_id} (#{name})")
      {:reply, {:ok, server_id}, %{state | stats: new_stats}}
    end
  end

  @impl true
  def handle_call({:unregister_server, server_id}, _from, state) do
    case :ets.lookup(@servers_table, server_id) do
      [{^server_id, _}] ->
        :ets.delete(@servers_table, server_id)
        :ets.delete(@permissions_table, server_id)
        :ets.delete(@baselines_table, server_id)
        Logger.info("[MCPGovernance] MCP server unregistered: #{server_id}")
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:set_server_state, server_id, new_state}, _from, state) do
    case :ets.lookup(@servers_table, server_id) do
      [{^server_id, entry}] ->
        updated = %{entry | state: new_state, last_seen_at: DateTime.utc_now()}
        :ets.insert(@servers_table, {server_id, updated})
        Logger.info("[MCPGovernance] Server #{server_id} state -> #{new_state}")
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:list_servers, opts}, _from, state) do
    servers =
      :ets.tab2list(@servers_table)
      |> Enum.map(fn {_id, entry} -> entry end)
      |> filter_servers(opts)
      |> Enum.sort_by(& &1.name)

    {:reply, servers, state}
  end

  @impl true
  def handle_call({:get_server, server_id}, _from, state) do
    case :ets.lookup(@servers_table, server_id) do
      [{^server_id, entry}] ->
        # Enrich with permissions
        perms =
          case :ets.lookup(@permissions_table, server_id) do
            [{^server_id, p}] -> p
            [] -> %{}
          end

        {:reply, {:ok, Map.put(entry, :permissions, perms)}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:set_permissions, server_id, permissions}, _from, state) do
    case :ets.lookup(@servers_table, server_id) do
      [{^server_id, _}] ->
        case validate_permissions(permissions) do
          :ok ->
            :ets.insert(@permissions_table, {server_id, normalize_permissions(permissions)})
            Logger.info("[MCPGovernance] Permissions updated for server: #{server_id}")
            {:reply, :ok, state}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:authorize_tool_call, server_id, tool_name, caller_id, context}, _from, state) do
    result = do_authorize(server_id, tool_name, caller_id, context)

    new_stats =
      case result do
        :ok -> increment_stat(state.stats, :calls_authorized)
        {:error, _} -> increment_stat(state.stats, :calls_denied)
      end

    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call(
        {:authorize_tool_result, server_id, tool_name, result_size_bytes, metadata},
        _from,
        state
      ) do
    result = do_authorize_result(server_id, tool_name, result_size_bytes, metadata)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_audit_log, opts}, _from, state) do
    limit = opts[:limit] || 100
    server_id = opts[:server_id]

    entries =
      :ets.tab2list(@audit_table)
      |> Enum.map(fn {_key, entry} -> entry end)
      |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
      |> then(fn entries ->
        if server_id do
          Enum.filter(entries, fn e -> e.server_id == server_id end)
        else
          entries
        end
      end)
      |> Enum.take(limit)

    {:reply, entries, state}
  end

  @impl true
  def handle_call(:get_anomaly_alerts, _from, state) do
    {:reply, state.anomaly_alerts, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats =
      Map.merge(state.stats, %{
        registered_servers: :ets.info(@servers_table, :size),
        audit_log_size: :ets.info(@audit_table, :size),
        active_anomaly_alerts: length(state.anomaly_alerts)
      })

    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:record_tool_call, call_info}, state) do
    server_id = call_info[:server_id] || "unknown"
    tool_name = call_info[:tool_name] || "unknown"
    result_size_bytes = non_negative_integer(call_info[:result_size_bytes])
    now = DateTime.utc_now()

    entry_key = System.unique_integer([:positive, :monotonic])

    audit_entry = %{
      id: entry_key,
      server_id: server_id,
      tool_name: tool_name,
      caller_id: call_info[:caller_id] || "anonymous",
      params_hash: hash_params(call_info[:params]),
      params_metadata: sanitize_params(call_info[:params]),
      result_status: sanitize_result_status(call_info[:result_status]),
      result_size_bytes: result_size_bytes,
      output_scan: sanitize_output_scan(call_info[:output_scan]),
      latency_ms: call_info[:latency_ms] || 0.0,
      timestamp: now
    }

    :ets.insert(@audit_table, {entry_key, audit_entry})

    # Update server stats
    case :ets.lookup(@servers_table, server_id) do
      [{^server_id, entry}] ->
        updated = %{
          entry
          | call_count: entry.call_count + 1,
            data_volume_bytes: entry.data_volume_bytes + result_size_bytes,
            last_seen_at: now
        }

        :ets.insert(@servers_table, {server_id, updated})

      [] ->
        :ok
    end

    # Update baseline data
    update_baseline(server_id, tool_name, result_size_bytes)

    # Check for anomalies
    anomaly_alerts = check_anomalies(server_id, tool_name, state.anomaly_alerts)

    new_stats = increment_stat(state.stats, :tool_calls_recorded)
    {:noreply, %{state | stats: new_stats, anomaly_alerts: anomaly_alerts}}
  end

  @impl true
  def handle_info(:health_check, state) do
    perform_health_checks()
    schedule_health_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(:baseline_update, state) do
    # Baselines are updated incrementally in record_tool_call
    schedule_baseline_update()
    {:noreply, state}
  end

  @impl true
  def handle_info(:audit_trim, state) do
    trim_audit_table()
    schedule_audit_trim()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp init_stats do
    %{
      servers_registered: 0,
      calls_authorized: 0,
      calls_denied: 0,
      tool_calls_recorded: 0,
      health_checks_performed: 0,
      anomalies_detected: 0,
      started_at: DateTime.utc_now()
    }
  end

  defp increment_stat(stats, key) do
    Map.update(stats, key, 1, &(&1 + 1))
  end

  # --- Authorization ---

  defp do_authorize(server_id, tool_name, caller_id, context) do
    with {:ok, server} <- lookup_server(server_id),
         :ok <- check_server_active(server),
         {:ok, perms} <- lookup_permissions(server_id),
         :ok <- check_tool_allowed(tool_name, perms),
         :ok <- check_resources_allowed(context, perms),
         :ok <- check_caller_allowed(caller_id, perms),
         :ok <- check_call_rate(server_id, perms),
         classes = classify_call(tool_name, context, perms),
         :ok <- check_dangerous_chain(classes, context, perms),
         :ok <- check_risk_policy(classes, context, perms),
         :ok <- check_expected_result_size(context, perms) do
      :ok
    end
  end

  defp do_authorize_result(server_id, tool_name, result_size_bytes, metadata) do
    with {:ok, server} <- lookup_server(server_id),
         :ok <- check_server_active(server),
         {:ok, perms} <- lookup_permissions(server_id),
         :ok <- check_tool_allowed(tool_name, perms),
         :ok <- check_result_size(result_size_bytes, perms),
         scan = sanitize_output_scan(metadata[:output_scan] || metadata["output_scan"]),
         :ok <- check_output_scan(scan, perms) do
      {:ok,
       %{
         tool_name: tool_name,
         result_size_bytes: result_size_bytes,
         output_scan: scan
       }}
    end
  end

  defp lookup_server(server_id) do
    case :ets.lookup(@servers_table, server_id) do
      [{^server_id, entry}] -> {:ok, entry}
      [] -> {:error, :server_not_found}
    end
  end

  defp check_server_active(%{state: :active}), do: :ok
  defp check_server_active(%{state: state}), do: {:error, {:server_not_active, state}}

  defp lookup_permissions(server_id) do
    case :ets.lookup(@permissions_table, server_id) do
      [{^server_id, perms}] -> {:ok, perms}
      # no permissions = default allow
      [] -> {:ok, %{}}
    end
  end

  defp normalize_permissions(permissions) when is_map(permissions) do
    defaults = %{
      allowed_tools: [],
      blocked_tools: [],
      allowed_resources: [],
      blocked_resources: [],
      max_calls_per_minute: 100,
      max_data_mb_per_hour: 500,
      allowed_callers: [],
      high_risk_tool_classes: [],
      sensitive_resource_patterns: [],
      max_result_bytes: @default_max_result_bytes,
      approval_required_classes: [],
      tool_output_injection_scanning: %{
        enabled: true,
        scanner: :external,
        action: :block
      }
    }

    normalized =
      Enum.reduce(permissions, %{}, fn {key, value}, acc ->
        case permission_key(key) do
          nil -> acc
          normalized_key -> Map.put(acc, normalized_key, value)
        end
      end)

    Map.merge(defaults, normalized)
  end

  defp normalize_permissions(_), do: normalize_permissions(%{})

  defp validate_permissions(permissions) when is_map(permissions) do
    configured_classes =
      List.wrap(permissions[:high_risk_tool_classes] || permissions["high_risk_tool_classes"]) ++
        List.wrap(
          permissions[:approval_required_classes] || permissions["approval_required_classes"]
        )

    unsupported =
      configured_classes
      |> Enum.map(&class_name/1)
      |> Enum.reject(&(&1 in @supported_tool_classes))
      |> Enum.uniq()

    max_bytes = permissions[:max_result_bytes] || permissions["max_result_bytes"]

    scan_policy =
      permissions[:tool_output_injection_scanning] ||
        permissions["tool_output_injection_scanning"]

    cond do
      unsupported != [] ->
        {:error, {:unsupported_tool_classes, unsupported}}

      not is_nil(max_bytes) and (not is_integer(max_bytes) or max_bytes < 0) ->
        {:error, :invalid_max_result_bytes}

      not is_nil(scan_policy) and not is_map(scan_policy) ->
        {:error, :invalid_tool_output_injection_scanning}

      true ->
        :ok
    end
  end

  defp validate_permissions(_), do: {:error, :invalid_permissions}

  defp normalize_context(context) when is_map(context), do: context
  defp normalize_context(context) when is_list(context), do: Map.new(context)
  defp normalize_context(_), do: %{}

  defp check_tool_allowed(tool_name, perms) do
    blocked = perms[:blocked_tools] || []
    allowed = perms[:allowed_tools] || []

    cond do
      tool_name in blocked ->
        {:error, {:tool_blocked, tool_name}}

      allowed == [] ->
        # empty allowed list = all tools allowed
        :ok

      tool_name in allowed ->
        :ok

      true ->
        {:error, {:tool_not_allowed, tool_name}}
    end
  end

  defp check_resources_allowed(context, perms) do
    resources = context_resources(context)
    blocked = perms[:blocked_resources] || []
    allowed = perms[:allowed_resources] || []

    cond do
      Enum.any?(resources, &matches_any_pattern?(&1, blocked)) ->
        {:error, :resource_blocked}

      allowed != [] and Enum.any?(resources, &(not matches_any_pattern?(&1, allowed))) ->
        {:error, :resource_not_allowed}

      true ->
        :ok
    end
  end

  defp check_caller_allowed(caller_id, perms) do
    allowed_callers = perms[:allowed_callers] || []

    if allowed_callers == [] or caller_id in allowed_callers do
      :ok
    else
      {:error, {:caller_not_authorized, caller_id}}
    end
  end

  defp check_call_rate(server_id, perms) do
    max_rpm = perms[:max_calls_per_minute] || 100

    # Count recent calls from audit table
    one_minute_ago = DateTime.add(DateTime.utc_now(), -60, :second)

    recent_count =
      :ets.tab2list(@audit_table)
      |> Enum.count(fn {_key, entry} ->
        entry.server_id == server_id and
          DateTime.compare(entry.timestamp, one_minute_ago) == :gt
      end)

    if recent_count < max_rpm do
      :ok
    else
      {:error, :rate_limit_exceeded}
    end
  end

  defp classify_call(tool_name, context, perms) do
    tool = tool_name |> to_string() |> String.downcase()

    explicit_classes =
      (context[:tool_classes] || context["tool_classes"] || [])
      |> normalize_classes()

    classes =
      explicit_classes
      |> maybe_add_class(tool =~ @secret_read_tool_pattern, :secret_read)
      |> maybe_add_class(tool =~ @resource_read_tool_pattern, :resource_read)
      |> maybe_add_class(tool =~ @network_tool_pattern, :network_access)
      |> maybe_add_class(
        tool =~ ~r/(shell|command|exec|terminal|powershell|bash)/,
        :shell_execution
      )
      |> maybe_add_class(
        tool =~ ~r/(eval|execute_code|run_code|python|javascript)/,
        :code_execution
      )
      |> maybe_add_class(tool =~ ~r/(write|save|append|move|copy|create_file)/, :filesystem_write)
      |> maybe_add_class(
        tool =~ ~r/(delete|destroy|drop|wipe|remove|revoke|disable|isolate)/,
        :destructive
      )
      |> maybe_add_class(
        tool =~ ~r/(sudo|privilege|admin|iam|policy_change)/,
        :privileged_operation
      )

    if Enum.any?(context_resources(context), &sensitive_resource?(&1, perms)) do
      [:sensitive_resource, :secret_read | classes] |> Enum.uniq()
    else
      Enum.uniq(classes)
    end
  end

  defp maybe_add_class(classes, true, class), do: [class | classes]
  defp maybe_add_class(classes, false, _class), do: classes

  defp check_risk_policy(classes, context, perms) do
    high_risk = normalize_classes(perms[:high_risk_tool_classes])
    approval_required = normalize_classes(perms[:approval_required_classes])
    approval_granted = truthy?(context[:approval_granted] || context["approval_granted"])
    dry_run = truthy?(context[:dry_run] || context["dry_run"])
    pending_approval = truthy?(context[:pending_approval] || context["pending_approval"])
    non_executing = dry_run or pending_approval

    approval_class = Enum.find(classes, &(&1 in approval_required))

    unapproved_high_risk =
      Enum.find(classes, fn class ->
        class in high_risk and
          not ((approval_granted or non_executing) and class in approval_required)
      end)

    cond do
      approval_class && not approval_granted && not non_executing ->
        {:error, {:approval_required, approval_class}}

      unapproved_high_risk ->
        {:error, {:high_risk_tool_class, unapproved_high_risk}}

      true ->
        :ok
    end
  end

  defp check_dangerous_chain(classes, context, perms) do
    prior_classes = prior_call_classes(context, perms)

    if :network_access in classes and
         Enum.any?(prior_classes, &(&1 in [:secret_read, :sensitive_resource])) do
      {:error, {:dangerous_tool_chain, :sensitive_read_to_network}}
    else
      :ok
    end
  end

  defp prior_call_classes(context, perms) do
    explicit = context[:prior_tool_classes] || context["prior_tool_classes"] || []

    recent =
      context[:recent_tool_calls] || context["recent_tool_calls"] ||
        context[:previous_tool_calls] || context["previous_tool_calls"] || []

    classified =
      Enum.flat_map(List.wrap(recent), fn
        call when is_map(call) ->
          tool = call[:tool_name] || call["tool_name"] || call[:name] || call["name"] || ""
          classify_call(tool, normalize_context(call), perms)

        tool when is_binary(tool) ->
          classify_call(tool, %{}, perms)

        _ ->
          []
      end)

    Enum.uniq(normalize_classes(explicit) ++ classified)
  end

  defp check_expected_result_size(context, perms) do
    case context[:expected_result_bytes] || context["expected_result_bytes"] do
      bytes when is_integer(bytes) and bytes >= 0 -> check_result_size(bytes, perms)
      _ -> :ok
    end
  end

  defp check_result_size(bytes, perms) do
    max_bytes = perms[:max_result_bytes] || @default_max_result_bytes

    if is_integer(max_bytes) and max_bytes >= 0 and bytes > max_bytes do
      {:error, {:max_result_bytes_exceeded, max_bytes}}
    else
      :ok
    end
  end

  defp check_output_scan(scan, perms) do
    policy = perms[:tool_output_injection_scanning] || %{}
    enabled = Map.get(policy, :enabled, Map.get(policy, "enabled", true))
    action = Map.get(policy, :action, Map.get(policy, "action", :block))
    detected = scan[:injection_detected] || scan["injection_detected"]
    status = scan[:status] || scan["status"]

    cond do
      not enabled ->
        :ok

      scan == %{} ->
        {:error, :tool_output_scan_required}

      status in [:error, "error", :skipped, "skipped"] ->
        {:error, :tool_output_scan_failed}

      detected == true and action in [:block, "block"] ->
        {:error, :tool_output_injection_detected}

      true ->
        :ok
    end
  end

  defp context_resources(context) do
    single = context[:resource_uri] || context["resource_uri"]
    many = context[:resource_uris] || context["resource_uris"] || []
    Enum.filter([single | List.wrap(many)], &is_binary/1)
  end

  defp sensitive_resource?(resource, perms) do
    matches_any_pattern?(resource, perms[:sensitive_resource_patterns] || [])
  end

  defp matches_any_pattern?(value, patterns) when is_binary(value) do
    Enum.any?(List.wrap(patterns), fn pattern ->
      pattern = to_string(pattern)

      regex =
        pattern
        |> Regex.escape()
        |> String.replace("\\*", ".*")
        |> then(&Regex.compile!("^#{&1}$", "i"))

      Regex.match?(regex, value)
    end)
  end

  defp matches_any_pattern?(_, _), do: false

  defp normalize_classes(classes) do
    List.wrap(classes)
    |> Enum.map(&class_name/1)
    |> Enum.filter(&(&1 in @supported_tool_classes))
    |> Enum.map(&String.to_existing_atom/1)
  end

  defp class_name(class) when is_atom(class), do: Atom.to_string(class)
  defp class_name(class) when is_binary(class), do: class
  defp class_name(_), do: :invalid_type

  defp truthy?(value), do: value in [true, "true", 1]

  # --- Anomaly detection ---

  defp update_baseline(server_id, tool_name, data_bytes) do
    case :ets.lookup(@baselines_table, server_id) do
      [{^server_id, baseline}] ->
        # Append to call counts (keep last N hours)
        now_hour = DateTime.utc_now() |> DateTime.truncate(:second) |> Map.get(:hour)

        new_call_counts =
          [{now_hour, 1} | baseline.call_counts]
          |> Enum.take(1000)

        new_data_volumes =
          [{now_hour, data_bytes} | baseline.data_volumes]
          |> Enum.take(1000)

        new_tool_dist = Map.update(baseline.tool_distribution, tool_name, 1, &(&1 + 1))

        updated = %{
          baseline
          | call_counts: new_call_counts,
            data_volumes: new_data_volumes,
            tool_distribution: new_tool_dist,
            updated_at: DateTime.utc_now()
        }

        :ets.insert(@baselines_table, {server_id, updated})

      [] ->
        :ok
    end
  end

  defp check_anomalies(server_id, tool_name, existing_alerts) do
    case :ets.lookup(@baselines_table, server_id) do
      [{^server_id, baseline}] ->
        new_alerts = []

        # Check call frequency anomaly
        call_counts = baseline.call_counts |> Enum.map(fn {_h, c} -> c end)

        if length(call_counts) > 20 do
          mean = Enum.sum(call_counts) / length(call_counts)
          stddev = calculate_stddev(call_counts, mean)
          recent_sum = call_counts |> Enum.take(5) |> Enum.sum()

          if stddev > 0 and (recent_sum - mean) / stddev > @anomaly_z_threshold do
            _new_alerts = [
              %{
                type: :call_frequency_spike,
                server_id: server_id,
                tool_name: tool_name,
                description:
                  "Unusual call frequency spike detected (z=#{Float.round((recent_sum - mean) / stddev, 2)})",
                detected_at: DateTime.utc_now(),
                severity: :high
              }
              | new_alerts
            ]
          end
        end

        # Check data volume anomaly
        data_vols = baseline.data_volumes |> Enum.map(fn {_h, v} -> v end)

        if length(data_vols) > 20 do
          mean = Enum.sum(data_vols) / length(data_vols)
          stddev = calculate_stddev(data_vols, mean)
          recent_vol = data_vols |> Enum.take(5) |> Enum.sum()

          if stddev > 0 and (recent_vol - mean) / stddev > @anomaly_z_threshold do
            _new_alerts = [
              %{
                type: :data_volume_spike,
                server_id: server_id,
                description: "Unusual data volume spike detected",
                detected_at: DateTime.utc_now(),
                severity: :high
              }
              | new_alerts
            ]
          end
        end

        # Merge with existing, keep last 1000
        (new_alerts ++ existing_alerts) |> Enum.take(1000)

      [] ->
        existing_alerts
    end
  end

  defp calculate_stddev(values, mean) do
    n = length(values)

    if n < 2 do
      0.0
    else
      variance =
        Enum.reduce(values, 0.0, fn v, acc ->
          acc + :math.pow(v - mean, 2)
        end) / (n - 1)

      :math.sqrt(variance)
    end
  end

  # --- Health checks ---

  defp perform_health_checks do
    :ets.tab2list(@servers_table)
    |> Enum.each(fn {server_id, entry} ->
      if entry.state == :active do
        health_result = ping_server(entry.endpoint_url)
        new_health = update_health(entry.health, health_result)
        new_state = if consecutive_failures(new_health) >= 3, do: :unhealthy, else: entry.state

        updated = %{entry | health: new_health, state: new_state}
        :ets.insert(@servers_table, {server_id, updated})

        if new_state == :unhealthy and entry.state == :active do
          Logger.warning("[MCPGovernance] Server #{server_id} (#{entry.name}) marked unhealthy")
        end
      end
    end)
  end

  defp ping_server("internal://" <> _), do: :ok

  defp ping_server(endpoint_url) do
    # Attempt a lightweight health check
    health_url = "#{endpoint_url}/health"
    request = Finch.build(:get, health_url)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: @health_timeout_ms) do
      {:ok, %Finch.Response{status: status}} when status in 200..299 ->
        :ok

      {:ok, %Finch.Response{status: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp update_health(health, :ok) do
    %{
      health
      | status: :healthy,
        last_check: DateTime.utc_now(),
        uptime_checks: health.uptime_checks + 1,
        uptime_successes: health.uptime_successes + 1,
        last_error: nil
    }
  end

  defp update_health(health, {:error, reason}) do
    %{
      health
      | status: :unhealthy,
        last_check: DateTime.utc_now(),
        uptime_checks: health.uptime_checks + 1,
        last_error: reason
    }
  end

  defp consecutive_failures(health) do
    health.uptime_checks - health.uptime_successes
  end

  # --- Filtering and utility ---

  defp filter_servers(servers, opts) do
    servers
    |> then(fn s ->
      if opts[:state], do: Enum.filter(s, &(&1.state == opts[:state])), else: s
    end)
    |> then(fn s ->
      if opts[:organization_id],
        do: Enum.filter(s, &(&1.organization_id == opts[:organization_id])),
        else: s
    end)
  end

  defp trim_audit_table do
    size = :ets.info(@audit_table, :size)

    if size > @max_audit_entries do
      # Delete oldest entries
      to_delete = size - @max_audit_entries

      :ets.tab2list(@audit_table)
      |> Enum.sort_by(fn {key, _} -> key end)
      |> Enum.take(to_delete)
      |> Enum.each(fn {key, _} -> :ets.delete(@audit_table, key) end)
    end
  end

  # Audit only structural metadata. In particular, do not hash raw values: a
  # hash of a low-entropy token or password can still act as a disclosure oracle.
  defp hash_params(nil), do: nil

  defp hash_params(params) do
    Jason.encode!(sanitize_params(params))
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
    |> binary_part(0, 16)
  end

  defp sanitize_params(nil), do: nil

  defp sanitize_params(params) when is_map(params) do
    fields = Enum.take(params, 100)

    %{
      kind: :map,
      field_count: map_size(params),
      sensitive_field_count:
        Enum.count(fields, fn {key, _value} -> sensitive_param_key?(key) end),
      value_types:
        fields |> Enum.map(fn {_key, value} -> value_type(value) end) |> Enum.frequencies(),
      truncated: map_size(params) > 100
    }
  end

  defp sanitize_params(params) when is_list(params) do
    %{
      kind: :list,
      item_count: length(Enum.take(params, 101)),
      truncated: length(Enum.take(params, 101)) > 100
    }
  end

  defp sanitize_params(params), do: %{kind: value_type(params)}

  defp sensitive_param_key?(key) when is_atom(key) or is_binary(key) do
    normalized = key |> to_string() |> String.downcase()
    Enum.any?(@sensitive_param_keys, &String.contains?(normalized, &1))
  end

  defp sensitive_param_key?(_), do: false

  defp value_type(value) when is_binary(value), do: :string
  defp value_type(value) when is_boolean(value), do: :boolean
  defp value_type(value) when is_integer(value), do: :integer
  defp value_type(value) when is_float(value), do: :float
  defp value_type(value) when is_map(value), do: :map
  defp value_type(value) when is_list(value), do: :list
  defp value_type(value) when is_atom(value), do: :atom
  defp value_type(value) when is_tuple(value), do: :tuple
  defp value_type(_), do: :other

  defp sanitize_output_scan(scan) when is_map(scan) do
    Enum.reduce(scan, %{}, fn {key, value}, acc ->
      normalized_key = output_scan_key_name(key)

      if normalized_key in @output_scan_metadata_keys do
        Map.put(
          acc,
          output_scan_key(normalized_key),
          sanitize_scan_value(normalized_key, value)
        )
      else
        acc
      end
    end)
  end

  defp sanitize_output_scan(_), do: %{}

  defp output_scan_key_name(key) when is_atom(key) or is_binary(key) do
    key |> to_string() |> String.downcase()
  end

  defp output_scan_key_name(_), do: ""

  defp output_scan_key("enabled"), do: :enabled
  defp output_scan_key("scanner"), do: :scanner
  defp output_scan_key("status"), do: :status
  defp output_scan_key("action"), do: :action
  defp output_scan_key("injection_detected"), do: :injection_detected
  defp output_scan_key("categories"), do: :categories
  defp output_scan_key("rule_ids"), do: :rule_ids
  defp output_scan_key("confidence"), do: :confidence
  defp output_scan_key("scanned_at"), do: :scanned_at

  defp sanitize_scan_value("enabled", value), do: value == true
  defp sanitize_scan_value("injection_detected", value), do: value == true

  defp sanitize_scan_value("confidence", value) when is_number(value) do
    value |> max(0) |> min(1)
  end

  defp sanitize_scan_value("categories", value), do: %{count: metadata_item_count(value)}
  defp sanitize_scan_value("rule_ids", value), do: %{count: metadata_item_count(value)}
  defp sanitize_scan_value("scanner", value) when is_atom(value), do: value
  defp sanitize_scan_value("scanner", _value), do: :external

  defp sanitize_scan_value(field, value) when field in ["status", "action"] do
    normalized = value |> to_string() |> String.downcase()

    if normalized in ~w(clean detected error skipped block allow warn),
      do: normalized,
      else: "unknown"
  end

  defp sanitize_scan_value("scanned_at", %DateTime{} = value),
    do: DateTime.truncate(value, :second)

  defp sanitize_scan_value(_field, _value), do: :redacted

  defp metadata_item_count(value) when is_list(value) do
    value |> Enum.take(100) |> length()
  rescue
    _ -> 0
  end

  defp metadata_item_count(nil), do: 0
  defp metadata_item_count(_), do: 1

  defp sanitize_result_status(status) when status in [:success, :error, :blocked], do: status
  defp sanitize_result_status(_), do: :unknown

  defp non_negative_integer(value) when is_integer(value) and value >= 0, do: value
  defp non_negative_integer(_), do: 0

  defp permission_key(key) when is_atom(key) do
    if key in permission_keys(), do: key, else: nil
  end

  defp permission_key(key) when is_binary(key) do
    Enum.find(permission_keys(), &(Atom.to_string(&1) == key))
  end

  defp permission_key(_), do: nil

  defp permission_keys do
    [
      :allowed_tools,
      :blocked_tools,
      :allowed_resources,
      :blocked_resources,
      :max_calls_per_minute,
      :max_data_mb_per_hour,
      :allowed_callers,
      :high_risk_tool_classes,
      :sensitive_resource_patterns,
      :max_result_bytes,
      :approval_required_classes,
      :tool_output_injection_scanning
    ]
  end

  # --- Scheduling ---

  defp schedule_health_check do
    Process.send_after(self(), :health_check, @health_check_interval)
  end

  defp schedule_baseline_update do
    Process.send_after(self(), :baseline_update, @baseline_update_interval)
  end

  defp schedule_audit_trim do
    Process.send_after(self(), :audit_trim, @audit_trim_interval)
  end
end
