defmodule TamanduaServerWeb.API.V1.LiveResponseController do
  @moduledoc """
  Live Response Controller for remote incident response operations.

  Provides REST endpoints for:
  - Session lifecycle management (create, list, show, end)
  - Session history and recording retrieval
  - Remote command execution
  - Process, file, memory, network, registry, and system operations

  ## Session Management Endpoints
  - POST   /api/v1/live-response/sessions          - Create session
  - GET    /api/v1/live-response/sessions           - List active sessions
  - GET    /api/v1/live-response/sessions/:id       - Session details
  - DELETE /api/v1/live-response/sessions/:id       - End session
  - GET    /api/v1/live-response/sessions/:id/history   - Command history
  - GET    /api/v1/live-response/sessions/:id/recording - Session recording

  ## Security
  - All commands are logged with full audit trail
  - Session-based access control
  - Rate limiting on command execution
  - Command allowlist/denylist enforcement
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Registry, as: AgentRegistry
  alias TamanduaServer.Agents.Worker
  alias TamanduaServer.LiveResponse.SessionManager
  alias TamanduaServer.LiveResponse.CommandExecutor
  alias TamanduaServer.LiveResponse.AuditLogger
  alias TamanduaServer.Forensics.Collector

  action_fallback TamanduaServerWeb.FallbackController

  # Command timeout (30 seconds default)
  @default_timeout 30_000

  # Maximum output size (1MB)
  @max_output_size 1_048_576

  @cli_token_max_ttl_minutes 480

  # ============================================================================
  # Session Management Endpoints
  # ============================================================================

  @doc """
  Create a new live response session.

  POST /api/v1/live-response/sessions

  ## Body Parameters
  - agent_id: Target agent ID (required)
  - case_id: Associated case ID (optional)
  - alert_id: Associated alert ID (optional)
  - notes: Session notes (optional)
  - timeout_minutes: Custom idle timeout (optional)

  ## Security
  - Validates agent belongs to user's organization (multi-tenant isolation)
  """
  def create_session(conn, %{"agent_id" => agent_id} = params) do
    user = conn.assigns[:current_user]

    opts =
      []
      |> maybe_add_opt(:case_id, Map.get(params, "case_id"))
      |> maybe_add_opt(:alert_id, Map.get(params, "alert_id"))
      |> maybe_add_opt(:notes, Map.get(params, "notes"))
      |> maybe_add_opt(:timeout_minutes, Map.get(params, "timeout_minutes"))

    # Pass full user struct for tenant validation
    case SessionManager.create_session(agent_id, user, opts) do
      {:ok, session} ->
        conn
        |> put_status(:created)
        |> json(%{
          data: format_session(session),
          message: "Live response session created"
        })

      {:error, :unauthorized} ->
        conn |> put_status(:not_found) |> json(%{error: "Agent not found"})

      {:error, :user_no_organization} ->
        conn |> put_status(:forbidden) |> json(%{error: "User is not associated with any organization"})

      {:error, :agent_not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Agent not found"})

      {:error, :agent_offline} ->
        conn |> put_status(:service_unavailable) |> json(%{error: "Agent is offline"})

      {:error, :agent_session_limit} ->
        conn
        |> put_status(:too_many_requests)
        |> json(%{error: "Maximum concurrent sessions per agent reached"})

      {:error, :user_session_limit} ->
        conn
        |> put_status(:too_many_requests)
        |> json(%{error: "Maximum concurrent sessions per user reached"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Create a short-lived operator token for tamandua-ctl live response.

  POST /api/v1/live-response/:agent_id/cli-token
  """
  def create_cli_token(conn, %{"agent_id" => agent_id} = params) do
    user = conn.assigns[:current_user]
    org_id = get_current_organization_id(conn)
    ttl_minutes = clamp_cli_ttl(params["ttl_minutes"] || params["ttl"] || 15)

    with :ok <- verify_live_response_user(user),
         {:ok, agent} <- Agents.get_agent_for_org(org_id, agent_id),
         {:ok, token, claims} <-
           TamanduaServer.Guardian.encode_and_sign(
             user,
             %{
               "scope" => "dashboard_socket",
               "cli" => true,
               "agent_id" => agent_id,
               "permissions" => ["live_response:shell"]
             },
             ttl: {ttl_minutes, :minute}
           ) do
      Logger.info(
        "CLI live response token issued for user=#{live_response_user_id(user)} agent=#{agent_id} ttl_minutes=#{ttl_minutes}"
      )

      server_url = params["server_url"] || default_server_url(conn)

      json(conn, %{
        token: token,
        token_type: "dashboard_socket_jwt",
        scope: "live_response:shell",
        agent_id: agent_id,
        hostname: agent.hostname,
        server: server_url,
        expires_at: format_unix_exp(claims["exp"]),
        expires_in_seconds: ttl_minutes * 60,
        command:
          "tamandua-ctl remote shell --server #{server_url} --agent-id #{agent_id} --token #{token}"
      })
    else
      {:error, :unauthorized} ->
        conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Agent not found"})

      {:error, reason} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: inspect(reason)})

      nil ->
        conn |> put_status(:not_found) |> json(%{error: "Agent not found"})
    end
  end

  @doc """
  List active live response sessions.

  GET /api/v1/live-response/sessions

  ## Query Parameters
  - agent_id: Filter by agent (optional)
  - user_id: Filter by user (optional)
  - status: Filter by status (optional)
  """
  def list_sessions(conn, params) do
    opts =
      []
      |> maybe_add_opt(:agent_id, Map.get(params, "agent_id"))
      |> maybe_add_opt(:user_id, Map.get(params, "user_id"))
      |> maybe_add_opt(:status, parse_status(Map.get(params, "status")))

    sessions = SessionManager.list_sessions(opts)

    json(conn, %{
      data: Enum.map(sessions, &format_session/1),
      total: length(sessions)
    })
  end

  @doc """
  Get session details.

  GET /api/v1/live-response/sessions/:id
  """
  def show_session(conn, %{"id" => session_id}) do
    case SessionManager.get_session(session_id) do
      {:ok, session} ->
        json(conn, %{data: format_session_detail(session)})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Session not found"})
    end
  end

  @doc """
  End a live response session.

  DELETE /api/v1/live-response/sessions/:id

  ## Body Parameters
  - reason: Why the session is being ended (optional, default: "user_requested")
  """
  def terminate_session(conn, %{"id" => session_id} = params) do
    reason = Map.get(params, "reason", "user_requested")

    case SessionManager.close_session(session_id, reason) do
      {:ok, session} ->
        json(conn, %{
          data: format_session(session),
          message: "Session closed"
        })

      {:error, :session_not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Session not found"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Get command history for a session.

  GET /api/v1/live-response/sessions/:id/history
  """
  def session_command_history(conn, %{"id" => session_id}) do
    case SessionManager.get_session_history(session_id) do
      {:ok, history} ->
        json(conn, %{
          data: %{
            session_id: session_id,
            commands: Enum.map(history, &format_command_entry/1),
            total: length(history)
          }
        })

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Session not found"})
    end
  end

  @doc """
  Get session recording data for replay.

  GET /api/v1/live-response/sessions/:id/recording
  """
  def session_recording(conn, %{"id" => session_id}) do
    case SessionManager.get_session_recording(session_id) do
      {:ok, recording} ->
        json(conn, %{data: format_recording(recording)})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Session not found"})
    end
  end

  # ============================================================================
  # Legacy Endpoints (retained for backward compatibility)
  # ============================================================================

  @doc """
  Start a new live response session (legacy endpoint).

  POST /api/v1/live-response/session
  """
  def start_session(conn, %{"agent_id" => agent_id} = params) do
    create_session(conn, params)
  end

  @doc """
  Execute a command on the remote agent.

  POST /api/v1/live-response/session/:session_id/execute
  """
  def execute(conn, %{"session_id" => session_id, "command" => command} = params) do
    args = Map.get(params, "args", %{})
    timeout = Map.get(params, "timeout", @default_timeout)
    user_role = get_current_user_role(conn)

    case CommandExecutor.execute(session_id, command, args,
           timeout: timeout,
           user_role: user_role
         ) do
      {:ok, result} ->
        json(conn, %{
          data: %{
            session_id: session_id,
            command: command,
            status: result.status,
            output: truncate_output(result.output),
            exit_code: result.exit_code,
            executed_at: format_datetime(result.executed_at),
            duration_ms: result.duration_ms
          }
        })

      {:error, :session_expired} ->
        conn |> put_status(:gone) |> json(%{error: "Session has expired"})

      {:error, :session_closed} ->
        conn |> put_status(:gone) |> json(%{error: "Session has been closed"})

      {:error, :session_not_active} ->
        conn |> put_status(:gone) |> json(%{error: "Session is not active"})

      {:error, :unknown_command} ->
        conn |> put_status(:bad_request) |> json(%{error: "Unknown command: #{command}"})

      {:error, :command_blocked} ->
        conn |> put_status(:forbidden) |> json(%{error: "Command is blocked"})

      {:error, :insufficient_permissions} ->
        conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions for this command"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Session not found"})

      {:error, :timeout} ->
        conn |> put_status(:gateway_timeout) |> json(%{error: "Command timed out"})

      {:error, reason} ->
        conn |> put_status(:internal_server_error) |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  End a live response session (legacy endpoint).

  DELETE /api/v1/live-response/session/:session_id
  """
  def end_session(conn, %{"session_id" => session_id}) do
    terminate_session(conn, %{"id" => session_id})
  end

  @doc """
  Get session history (legacy endpoint).

  GET /api/v1/live-response/session/:session_id/history
  """
  def session_history(conn, %{"session_id" => session_id}) do
    session_command_history(conn, %{"id" => session_id})
  end

  # ============================================================================
  # Direct Agent Operation Endpoints
  # ============================================================================

  @doc """
  List running processes on the remote agent.
  """
  def list_processes(conn, %{"agent_id" => agent_id} = params) do
    filter = Map.get(params, "filter")

    case execute_remote_command(agent_id, "list_processes", %{filter: filter}, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  Kill a process on the remote agent.
  """
  def kill_process(conn, %{"agent_id" => agent_id, "pid" => pid}) do
    case execute_remote_command(agent_id, "kill_process", %{pid: pid}, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  Dump process memory.
  """
  def dump_process_memory(conn, %{"agent_id" => agent_id, "pid" => pid} = params) do
    options = %{
      pid: pid,
      full_dump: Map.get(params, "full_dump", false),
      include_strings: Map.get(params, "include_strings", false)
    }

    case execute_remote_command(agent_id, "dump_process_memory", options, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  Scan process memory with YARA rules.
  """
  def scan_memory(conn, %{"agent_id" => agent_id} = params) do
    scan_options = %{
      pid: Map.get(params, "pid"),
      rules: Map.get(params, "rules", "default"),
      custom_rules: Map.get(params, "custom_rules")
    }

    case execute_remote_command(agent_id, "memory_yara_scan", scan_options, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  Extract strings from process memory.
  """
  def memory_strings(conn, %{"agent_id" => agent_id, "pid" => pid} = params) do
    options = %{
      pid: pid,
      min_length: Map.get(params, "min_length", 4),
      encoding: Map.get(params, "encoding", "all"),
      include_urls: Map.get(params, "include_urls", true),
      include_ips: Map.get(params, "include_ips", true)
    }

    case execute_remote_command(agent_id, "memory_strings", options, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  List files in a directory on the remote agent.
  """
  def list_files(conn, %{"agent_id" => agent_id} = params) do
    path = Map.get(params, "path", "/")

    options = %{
      path: path,
      recursive: Map.get(params, "recursive", false),
      include_hidden: Map.get(params, "include_hidden", true),
      max_depth: Map.get(params, "max_depth", 1)
    }

    case execute_remote_command(agent_id, "list_directory", options, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  Download a file from the remote agent.
  """
  def download_file(conn, %{"agent_id" => agent_id} = params) do
    path = Map.get(params, "path", "")

    case execute_remote_command(agent_id, "download_file", %{path: path}, conn) do
      {:ok, result} ->
        case unwrap_remote_output(result) do
          %{"content" => content} when is_binary(content) ->
            filename = Path.basename(path)
            decoded = decode_file_content(content)

            conn
            |> put_resp_content_type("application/octet-stream")
            |> put_resp_header("content-disposition", "attachment; filename=\"#{filename}\"")
            |> send_resp(200, decoded)

          %{content: content} when is_binary(content) ->
            filename = Path.basename(path)
            decoded = decode_file_content(content)

            conn
            |> put_resp_content_type("application/octet-stream")
            |> put_resp_header("content-disposition", "attachment; filename=\"#{filename}\"")
            |> send_resp(200, decoded)

          output ->
            json(conn, %{data: output})
        end

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  Calculate hash of a file on the remote agent.
  """
  def hash_file(conn, %{"agent_id" => agent_id} = params) do
    path = Map.get(params, "path", "")

    case execute_remote_command(agent_id, "hash_file", %{path: path}, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  Get network connections on the remote agent.
  """
  def network_connections(conn, %{"agent_id" => agent_id} = params) do
    options = %{
      state: Map.get(params, "state"),
      protocol: Map.get(params, "protocol"),
      pid: Map.get(params, "pid")
    }

    case execute_remote_command(agent_id, "list_connections", options, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  Get DNS cache from the remote agent.
  """
  def dns_cache(conn, %{"agent_id" => agent_id}) do
    case execute_remote_command(agent_id, "dns_cache", %{}, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  Query registry on the remote agent (Windows only).
  """
  def registry_query(conn, %{"agent_id" => agent_id} = params) do
    key = Map.get(params, "key", "")

    options = %{
      key: key,
      recursive: Map.get(params, "recursive", false),
      value_name: Map.get(params, "value_name")
    }

    case execute_remote_command(agent_id, "list_keys", options, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  List services on the remote agent.
  """
  def list_services(conn, %{"agent_id" => agent_id} = params) do
    filter = Map.get(params, "filter")
    state = Map.get(params, "state")

    case execute_remote_command(agent_id, "services", %{filter: filter, state: state}, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  Get scheduled tasks on the remote agent.
  """
  def scheduled_tasks(conn, %{"agent_id" => agent_id}) do
    case execute_remote_command(agent_id, "scheduled_tasks", %{}, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  Get startup items on the remote agent.
  """
  def startup_items(conn, %{"agent_id" => agent_id}) do
    case execute_remote_command(agent_id, "autoruns", %{}, conn) do
      {:ok, result} ->
        json(conn, %{data: unwrap_remote_output(result)})

      {:error, reason} ->
        handle_remote_error(conn, reason)
    end
  end

  @doc """
  Execute artifact collection (convenience wrapper for forensics).
  """
  def collect_artifacts(conn, %{"agent_id" => agent_id, "artifacts" => artifacts}) do
    case Collector.create_collection(%{
           agent_id: agent_id,
           organization_id: get_current_organization_id(conn),
           type: "custom",
           paths: [],
           options: %{artifacts: artifacts},
           requested_by: get_current_user_id(conn)
         }) do
      {:ok, collection} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          data: %{
            collection_id: collection.id,
            status: "collecting",
            artifacts: artifacts
          },
          message: "Artifact collection initiated"
        })

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # Private - Remote Command Execution
  # ============================================================================

  defp execute_remote_command(agent_id, command, args, conn) do
    user_role = get_current_user_role(conn)
    org_id = get_current_organization_id(conn)

    # Use tenant-aware execute_direct with org_id validation
    CommandExecutor.execute_direct(agent_id, org_id, command, args,
      timeout: @default_timeout,
      user_role: user_role
    )
  end

  defp get_current_organization_id(conn) do
    # Try multiple sources for organization_id
    conn.assigns[:current_organization_id] ||
      live_response_user_org_id(conn.assigns[:current_user])
  end

  defp verify_live_response_user(nil), do: {:error, :unauthorized}

  defp verify_live_response_user(user) do
    if safe_rbac_can?(user, :live_response_shell) do
      :ok
    else
      role = live_response_user_role(user)

      if role in [:admin, :analyst, :responder, "admin", "analyst", "responder"] do
        :ok
      else
        {:error, :unauthorized}
      end
    end
  end

  defp live_response_user_role(%{role: role}), do: role
  defp live_response_user_role(user) when is_map(user), do: user[:role] || user["role"]
  defp live_response_user_role(_), do: nil

  defp live_response_user_org_id(%{organization_id: organization_id}), do: organization_id

  defp live_response_user_org_id(user) when is_map(user),
    do: user[:organization_id] || user["organization_id"]

  defp live_response_user_org_id(_), do: nil

  defp live_response_user_id(%{id: id}), do: id
  defp live_response_user_id(user) when is_map(user), do: user[:id] || user["id"]
  defp live_response_user_id(_), do: nil

  defp safe_rbac_can?(user, permission) do
    TamanduaServer.Authorization.RBAC.can?(user, permission)
  rescue
    ArgumentError -> false
    UndefinedFunctionError -> false
    FunctionClauseError -> false
  end

  defp clamp_cli_ttl(value) do
    value
    |> parse_int(15)
    |> max(1)
    |> min(@cli_token_max_ttl_minutes)
  end

  defp parse_int(value, _default) when is_integer(value), do: value

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(_, default), do: default

  defp default_server_url(conn) do
    scheme = conn.scheme |> to_string()
    host = conn.host

    cond do
      (scheme == "http" and conn.port == 80) or (scheme == "https" and conn.port == 443) ->
        "#{scheme}://#{host}"

      true ->
        "#{scheme}://#{host}:#{conn.port}"
    end
  end

  defp format_unix_exp(nil), do: nil
  defp format_unix_exp(exp) when is_integer(exp), do: exp |> DateTime.from_unix!() |> DateTime.to_iso8601()
  defp format_unix_exp(_), do: nil

  # ============================================================================
  # Private - Response Formatting
  # ============================================================================

  defp format_session(session) do
    %{
      session_id: session.session_id,
      agent_id: session.agent_id,
      user_id: session.user_id,
      status: to_string(session.status),
      started_at: format_datetime(session.started_at),
      ended_at: format_datetime(session.ended_at),
      last_activity: format_datetime(session.last_activity),
      commands_executed: session.commands_executed,
      timeout_minutes: session[:timeout_minutes]
    }
  end

  defp format_session_detail(session) do
    format_session(session)
    |> Map.merge(%{
      case_id: session[:case_id],
      alert_id: session[:alert_id],
      notes: session[:notes],
      command_count: length(session.command_history),
      recent_commands:
        session.command_history
        |> Enum.take(-10)
        |> Enum.map(&format_command_entry/1)
    })
  end

  defp format_command_entry(entry) do
    %{
      id: entry[:id],
      command: entry[:command],
      args: entry[:args],
      status: entry[:status],
      exit_code: entry[:exit_code],
      duration_ms: entry[:duration_ms],
      executed_at: format_datetime(entry[:executed_at])
    }
  end

  defp format_recording(recording) do
    %{
      session_id: recording.session_id,
      agent_id: recording.agent_id,
      user_id: recording.user_id,
      status: to_string(recording.status),
      started_at: format_datetime(recording.started_at),
      ended_at: format_datetime(recording.ended_at),
      duration_seconds: recording.duration_seconds,
      commands_executed: recording.commands_executed,
      command_history:
        recording.command_history
        |> Enum.map(&format_command_entry/1)
    }
  end

  defp format_datetime(nil), do: nil

  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp format_datetime(other), do: to_string(other)

  # ============================================================================
  # Private - Error Handling
  # ============================================================================

  defp handle_remote_error(conn, :unauthorized) do
    # Return 404 instead of 403 to avoid leaking agent existence info to other tenants
    conn |> put_status(:not_found) |> json(%{error: "Agent not found"})
  end

  defp handle_remote_error(conn, :agent_not_found) do
    conn |> put_status(:not_found) |> json(%{error: "Agent not found"})
  end

  defp handle_remote_error(conn, :agent_offline) do
    conn |> put_status(:service_unavailable) |> json(%{error: "Agent is offline"})
  end

  defp handle_remote_error(conn, :agent_not_connected) do
    conn |> put_status(:service_unavailable) |> json(%{error: "Agent is not connected"})
  end

  defp handle_remote_error(conn, :timeout) do
    conn |> put_status(:gateway_timeout) |> json(%{error: "Command timed out"})
  end

  defp handle_remote_error(conn, :unknown_command) do
    conn |> put_status(:bad_request) |> json(%{error: "Unknown command"})
  end

  defp handle_remote_error(conn, :command_blocked) do
    conn |> put_status(:forbidden) |> json(%{error: "Command is blocked"})
  end

  defp handle_remote_error(conn, :insufficient_permissions) do
    conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions"})
  end

  defp handle_remote_error(conn, reason) do
    conn |> put_status(:internal_server_error) |> json(%{error: to_string(reason)})
  end

  # ============================================================================
  # Private - Utilities
  # ============================================================================

  defp truncate_output(output) when is_binary(output) do
    if byte_size(output) > @max_output_size do
      String.slice(output, 0, @max_output_size) <> "\n... [output truncated]"
    else
      output
    end
  end

  defp truncate_output(output), do: output

  defp unwrap_remote_output(%{output: output}) when not is_nil(output), do: output
  defp unwrap_remote_output(%{"output" => output}) when not is_nil(output), do: output
  defp unwrap_remote_output(result), do: result

  defp decode_file_content(content) do
    case Base.decode64(content) do
      {:ok, decoded} -> decoded
      :error -> content
    end
  end

  defp get_current_user_id(conn) do
    case conn.assigns[:current_user] do
      nil -> nil
      user -> user.id
    end
  end

  defp get_current_user_role(conn) do
    case conn.assigns[:current_user] do
      nil -> :viewer
      user -> user.role || user[:role] || :analyst
    end
  end

  defp maybe_add_opt(opts, _key, nil), do: opts
  defp maybe_add_opt(opts, key, value), do: Keyword.put(opts, key, value)

  defp parse_status(nil), do: nil
  defp parse_status("active"), do: :active
  defp parse_status("idle"), do: :idle
  defp parse_status("closed"), do: :closed
  defp parse_status("expired"), do: :expired
  defp parse_status(_other), do: nil
end
