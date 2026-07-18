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
  alias TamanduaServer.Agents.{Agent, CommandManager, Registry}
  alias TamanduaServer.AuditLog
  alias TamanduaServer.LiveResponse.SessionManager
  alias TamanduaServer.LiveResponse.CommandExecutor

  alias TamanduaServer.LiveResponse.{
    ScreenCapture,
    ScreenCaptureAdmission,
    ScreenCaptureArtifacts,
    ScreenCapturePolicy
  }

  alias TamanduaServer.Mobile.{DeviceV2, MDMCommand}
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Forensics.Collector

  action_fallback(TamanduaServerWeb.FallbackController)

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
    org_id = get_current_organization_id(conn)

    opts =
      []
      |> maybe_add_opt(:case_id, Map.get(params, "case_id"))
      |> maybe_add_opt(:alert_id, Map.get(params, "alert_id"))
      |> maybe_add_opt(:notes, Map.get(params, "notes"))
      |> maybe_add_opt(:timeout_minutes, Map.get(params, "timeout_minutes"))

    case maybe_reject_mobile_live_response(org_id, agent_id) do
      :ok ->
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
            conn
            |> put_status(:forbidden)
            |> json(%{error: "User is not associated with any organization"})

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

      {:error, :mobile_live_response_unsupported} ->
        mobile_live_response_unsupported(conn)
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
         :ok <- reject_mobile_live_response(agent),
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

      {:error, :mobile_live_response_unsupported} ->
        mobile_live_response_unsupported(conn)

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
    organization_id = get_current_organization_id(conn)
    supervise? = supervise_live_response?(conn)

    opts =
      []
      |> maybe_add_opt(:agent_id, Map.get(params, "agent_id"))
      |> maybe_add_opt(
        :user_id,
        if(supervise?, do: Map.get(params, "user_id"), else: get_current_user_id(conn))
      )
      |> maybe_add_opt(:status, parse_status(Map.get(params, "status")))
      |> maybe_add_opt(:organization_id, organization_id)

    sessions =
      if is_nil(organization_id), do: [], else: SessionManager.list_sessions(opts)

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
    case authorize_session_access(conn, session_id) do
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

    case authorize_session_access(conn, session_id) do
      {:ok, _session} ->
        case SessionManager.close_session(session_id, reason) do
          {:ok, session} ->
            json(conn, %{
              data: format_session(session),
              message: "Session closed"
            })

          {:error, :session_not_found} ->
            conn |> put_status(:not_found) |> json(%{error: "Session not found"})

          {:error, close_reason} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: to_string(close_reason)})
        end

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Session not found"})
    end
  end

  @doc """
  Get command history for a session.

  GET /api/v1/live-response/sessions/:id/history
  """
  def session_command_history(conn, %{"id" => session_id}) do
    case authorize_session_access(conn, session_id) do
      {:ok, session} ->
        history = session.command_history

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
    case authorize_session_access(conn, session_id) do
      {:ok, _session} ->
        {:ok, recording} = SessionManager.get_session_recording(session_id)
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
           user_role: user_role,
           organization_id: get_current_organization_id(conn),
           user_id: get_current_user_id(conn),
           supervise: supervise_live_response?(conn)
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
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Insufficient permissions for this command"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Session not found"})

      {:error, :unauthorized} ->
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

  @doc """
  Queue an audited, single-frame endpoint screen capture.

  POST /api/v1/live-response/:agent_id/screen-capture

  Requires `reason`, never returns or logs image bytes, and does not enable
  continuous viewing or remote input.
  """
  def screen_capture(conn, %{"agent_id" => agent_id} = params) do
    user = conn.assigns[:current_user]
    org_id = get_current_organization_id(conn)

    with :ok <- authorize_screen_capture(user),
         {:ok, request} <- ScreenCapture.validate_request(params),
         {:ok, agent} <- Agents.get_agent_for_org(org_id, agent_id),
         policy <- ScreenCapturePolicy.resolve(agent_id),
         policy <- ScreenCapturePolicy.for_command(policy, request.ttl_seconds),
         :ok <- require_screen_capture_policy(policy, request),
         {:ok, delivery} <- screen_capture_delivery(agent, org_id),
         :ok <- ScreenCaptureAdmission.authorize(agent, org_id, delivery, policy),
         capability <- ScreenCapture.capability_state(agent.os_type, delivery.capabilities),
         :ok <- require_screen_capture_capability(capability),
         {:ok, command, artifact} <-
           create_and_queue_screen_capture(
             org_id,
             agent_id,
             request,
             capability,
             policy,
             delivery
           ) do
      audit_screen_capture(conn, command.id, agent_id, request, capability, policy, "queued")

      conn
      |> put_status(:accepted)
      |> json(%{
        data:
          ScreenCapture.response(%{
            command_id: command.id,
            status: "queued",
            capability_state: capability.state,
            consent_required: capability.consent_required,
            consent_model: Map.get(capability, :consent_model),
            capture_coverage: Map.get(capability, :capture_coverage),
            policy_mode: policy.mode,
            notify_timing: policy.notify_timing,
            policy: policy.policy,
            display: request.display,
            scope: request.scope,
            monitor_id: request.monitor_id,
            watermark: request.watermark,
            redaction_count: length(request.redactions),
            expires_at: format_datetime(artifact.expires_at),
            artifact: %{
              id: artifact.id,
              status: artifact.status,
              mime: artifact.mime,
              size: artifact.size,
              sha256: artifact.sha256,
              captured_at: nil,
              display: artifact.display,
              expires_at: format_datetime(artifact.expires_at),
              uploaded_at: nil,
              content_url: nil,
              status_url: "/api/v1/live-response/#{agent_id}/screen-captures/#{artifact.id}"
            }
          })
      })
    else
      {:error, :unauthorized} ->
        conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions"})

      {:error, :reason_required} ->
        invalid_screen_capture_request(conn, "reason is required")

      {:error, :reason_too_long} ->
        invalid_screen_capture_request(conn, "reason must be at most 500 bytes")

      {:error, :invalid_ttl_seconds} ->
        invalid_screen_capture_request(conn, "ttl_seconds must be between 60 and 900")

      {:error, :invalid_display} ->
        invalid_screen_capture_request(
          conn,
          "display must be all for the initial virtual-desktop capture"
        )

      {:error, :invalid_scope} ->
        invalid_screen_capture_request(
          conn,
          "scope must be virtual_desktop, monitor, or active_window"
        )

      {:error, :invalid_monitor_id} ->
        invalid_screen_capture_request(
          conn,
          "monitor_id is required only for monitor scope and must be at most 128 bytes"
        )

      {:error, :invalid_watermark} ->
        invalid_screen_capture_request(conn, "watermark must be a boolean")

      {:error, :invalid_redactions} ->
        invalid_screen_capture_request(
          conn,
          "redactions must contain at most 32 in-bounds basis-point rectangles"
        )

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Agent not found"})

      {:error, :agent_not_found} ->
        conn |> put_status(:service_unavailable) |> json(%{error: "Agent is offline"})

      {:error, :runtime_tenant_mismatch} ->
        conn |> put_status(:not_found) |> json(%{error: "Agent not found"})

      {:error, :mobile_command_device_not_found} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          error: "Mobile command device is not linked",
          detail: "Re-enroll or sync the mobile endpoint before requesting screen capture"
        })

      {:error, {:screen_capture_admission_denied, reason}} ->
        conn
        |> put_status(:conflict)
        |> json(%{
          error: "Screen capture policy hash contract is not negotiated",
          code: "screen_capture_policy_hash_contract_not_negotiated",
          reason: to_string(reason)
        })

      {:error, {:policy_denied, policy}} ->
        audit_screen_capture_policy_denied(
          conn,
          agent_id,
          safe_audit_request(params),
          policy
        )

        conn
        |> put_status(:forbidden)
        |> json(%{
          error: "Screen capture is disabled by effective agent policy",
          data: %{
            status: "policy_denied",
            policy_mode: policy.mode,
            notify_timing: policy.notify_timing,
            policy: policy.policy,
            denial_reason: Map.get(policy, :denial_reason),
            continuous: false,
            input_control: false
          }
        })

      {:error, :unsafe_screen_capture_upload_url} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{
          error:
            "Screen capture upload URL is not safely configured; set an HTTPS TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL"
        })

      {:error, {:unsupported, capability}} ->
        policy = ScreenCapturePolicy.resolve(agent_id)

        audit_screen_capture(
          conn,
          nil,
          agent_id,
          safe_audit_request(params),
          capability,
          policy,
          "unsupported"
        )

        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          data:
            ScreenCapture.response(%{
              status: "unsupported",
              capability_state: capability.state,
              consent_required: capability.consent_required,
              consent_model: Map.get(capability, :consent_model),
              capture_coverage: Map.get(capability, :capture_coverage),
              unsupported_reason: capability.unsupported_reason,
              display: Map.get(params, "display", "all")
            })
        })

      {:error, %Ecto.Changeset{}} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Screen capture command rejected"})

      {:error, reason} ->
        Logger.error(
          "Screen capture command queue failed agent=#{agent_id} reason=#{inspect(reason)}"
        )

        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Unable to queue screen capture"})
    end
  end

  defp authorize_screen_capture(nil), do: {:error, :unauthorized}

  defp authorize_screen_capture(user) do
    if safe_rbac_can?(user, :live_response_screen), do: :ok, else: {:error, :unauthorized}
  end

  defp verify_runtime_tenant(runtime, organization_id) do
    if Registry.same_canonical_organization_id?(runtime[:organization_id], organization_id) do
      :ok
    else
      {:error, :runtime_tenant_mismatch}
    end
  end

  defp require_screen_capture_capability(%{state: "unsupported"} = capability),
    do: {:error, {:unsupported, capability}}

  defp require_screen_capture_capability(_capability), do: :ok

  defp require_screen_capture_policy(%{mode: "disabled"} = policy, _request),
    do: {:error, {:policy_denied, policy}}

  defp require_screen_capture_policy(%{mode: mode} = policy, request)
       when mode in ["silent", "notify", "consent_required"] do
    cond do
      not ScreenCapturePolicy.usable?(policy) ->
        {:error, {:policy_denied, Map.put(policy, :denial_reason, "policy_evidence_unusable")}}

      request.scope not in policy.allowed_scopes ->
        {:error, {:policy_denied, Map.put(policy, :denial_reason, "scope_not_allowed")}}

      policy.redaction_required and request.redactions == [] ->
        {:error, {:policy_denied, Map.put(policy, :denial_reason, "redaction_required")}}

      true ->
        :ok
    end
  end

  defp require_screen_capture_policy(policy, _request),
    do: {:error, {:policy_denied, policy}}

  defp create_and_queue_screen_capture(
         organization_id,
         agent_id,
         request,
         capability,
         policy,
         delivery
       ) do
    with {:ok, upload_base_url} <- ScreenCaptureArtifacts.upload_base_url(),
         {:ok, artifact, upload_token} <-
           ScreenCaptureArtifacts.create(organization_id, agent_id, request.ttl_seconds) do
      upload = %{
        url:
          upload_base_url <>
            "/api/v1/agent-artifacts/screen-captures/#{artifact.id}",
        token: upload_token,
        method: "PUT",
        content_type: ScreenCaptureArtifacts.allowed_mime(),
        max_bytes: ScreenCaptureArtifacts.max_bytes(),
        expires_at: format_datetime(artifact.expires_at)
      }

      case queue_screen_capture(
             agent_id,
             request,
             capability,
             policy,
             artifact.id,
             upload,
             delivery
           ) do
        {:ok, command} ->
          case attach_screen_capture_command(artifact, command, delivery) do
            {:ok, attached_artifact} ->
              {:ok, command, attached_artifact}

            {:error, reason} ->
              cancel_screen_capture_command(command, delivery)

              ScreenCaptureArtifacts.scrub_command_credential(
                artifact.organization_id,
                command.id
              )

              ScreenCaptureArtifacts.mark_failed(artifact, "command_attachment_failed")
              {:error, reason}
          end

        {:error, reason} ->
          ScreenCaptureArtifacts.mark_failed(artifact, "command_queue_failed")
          {:error, reason}
      end
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp queue_screen_capture(
         agent_id,
         request,
         capability,
         policy,
         artifact_id,
         upload,
         delivery
       ) do
    command_params = %{
      schema_version: ScreenCapture.schema_version(),
      reason: request.reason,
      display: request.display,
      scope: request.scope,
      monitor_id: request.monitor_id,
      watermark: request.watermark,
      redactions: request.redactions,
      artifact_id: artifact_id,
      upload: upload,
      expires_at: upload.expires_at,
      nonce: Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
      consent_required: capability.consent_required,
      policy_mode: policy.mode,
      notify_timing: policy.notify_timing,
      policy: policy.policy,
      continuous: false,
      input_control: false,
      result_contract: %{
        schema_version: ScreenCapture.schema_version(),
        status: "completed|failed|unsupported",
        capability_state: "supported|consent_required|unsupported",
        consent_model: "policy|os_permission|portal_prompt|user_prompt|user_initiated",
        capture_coverage: "platform-reported bounded screen coverage",
        captured_at: "RFC3339 timestamp or null",
        display: "all (full virtual desktop)",
        scope: "virtual_desktop|monitor|active_window",
        monitor_id: "stable native display identifier or null",
        watermark: "true when the fixed local product/time watermark was applied",
        redactions: "validated basis-point rectangles applied before upload",
        mime: "image/png",
        sha256: "lowercase hex digest",
        size: "non-negative byte count",
        artifact: %{
          id: artifact_id,
          storage: "server artifact upload only; no filesystem path"
        },
        unsupported_reason: "stable reason code or null",
        continuous: false,
        input_control: false,
        policy: %{
          id: "effective policy evidence id",
          version: "policy evidence version",
          mode: "silent|notify|consent_required|disabled",
          notify_timing: "before_capture|after_capture|null",
          hash: "sha256 of canonical normalized policy",
          hash_algorithm:
            "screen_capture_policy_hash_sha256_lexical_v2 for multi-scope policy evidence",
          issued_at_ms: "unix epoch milliseconds",
          expires_at_ms: "unix epoch milliseconds; no later than command TTL"
        }
      }
    }

    case delivery do
      %{kind: :mobile, device: %DeviceV2{} = device} ->
        MultiTenant.with_organization(device.organization_id, fn ->
          %MDMCommand{}
          |> MDMCommand.changeset(%{
            command_type: "screen_capture",
            device_id: device.id,
            organization_id: device.organization_id,
            requested_by: "live_response:#{agent_id}",
            status: "pending",
            payload: command_params
          })
          |> Repo.insert()
        end)

      _desktop ->
        CommandManager.queue_command(agent_id, :screen_capture, command_params,
          priority: 2,
          timeout: request.ttl_seconds
        )
    end
  end

  defp cancel_screen_capture_command(%MDMCommand{} = command, %{kind: :mobile}) do
    Repo.delete(command)
    :ok
  end

  defp cancel_screen_capture_command(command, _delivery) do
    CommandManager.cancel_command(command.id)
  end

  defp attach_screen_capture_command(artifact, %MDMCommand{} = command, %{kind: :mobile}),
    do: ScreenCaptureArtifacts.attach_mobile_command(artifact, command.id)

  defp attach_screen_capture_command(artifact, command, _delivery),
    do: ScreenCaptureArtifacts.attach_command(artifact, command.id)

  defp screen_capture_delivery(%Agent{} = agent, organization_id) do
    if mobile_os?(agent.os_type) do
      device =
        MultiTenant.with_organization(organization_id, fn ->
          Repo.get_by(DeviceV2,
            organization_id: organization_id,
            device_id: agent.machine_id
          )
        end)

      case device do
        %DeviceV2{} = device ->
          {:ok,
           %{
             kind: :mobile,
             device: device,
             capabilities: mobile_screen_capture_capabilities(agent.config)
           }}

        nil ->
          {:error, :mobile_command_device_not_found}
      end
    else
      with {:ok, runtime} <- Registry.get(agent.id),
           :ok <- verify_runtime_tenant(runtime, organization_id) do
        {:ok,
         %{
           kind: :desktop,
           capabilities: runtime[:capabilities] || [],
           runtime_snapshot: runtime[:runtime_snapshot]
         }}
      end
    end
  end

  defp mobile_os?(os_type) do
    normalized =
      os_type
      |> to_string()
      |> String.downcase()
      |> String.replace(~r/[^a-z0-9]/, "")

    normalized in ["android", "ios", "iphone", "ipad", "ipados"]
  end

  defp mobile_screen_capture_capabilities(config) when is_map(config) do
    capabilities = config["capabilities"] || config[:capabilities] || %{}
    capture = capabilities["screen_capture"] || capabilities[:screen_capture]

    if mobile_capture_available?(capture),
      do: ["screen_capture", "screen_capture_consent_required"],
      else: []
  end

  defp mobile_screen_capture_capabilities(_config), do: []
  defp mobile_capture_available?(true), do: true

  defp mobile_capture_available?(capture) when is_map(capture) do
    capture["available"] == true || capture[:available] == true ||
      capture["native_method_available"] == true || capture[:native_method_available] == true
  end

  defp mobile_capture_available?(_capture), do: false

  defp invalid_screen_capture_request(conn, message) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: message})
  end

  defp safe_audit_request(params) do
    %{
      reason: params["reason"] |> to_string() |> String.slice(0, 500),
      display: Map.get(params, "display", "all"),
      scope: Map.get(params, "scope", "virtual_desktop"),
      monitor_id: Map.get(params, "monitor_id"),
      watermark: Map.get(params, "watermark", false),
      redaction_count:
        if(is_list(Map.get(params, "redactions")),
          do: length(Map.get(params, "redactions")),
          else: 0
        ),
      ttl_seconds: Map.get(params, "ttl_seconds", ScreenCapture.default_ttl_seconds())
    }
  end

  defp audit_screen_capture(conn, command_id, agent_id, request, capability, policy, status) do
    user = conn.assigns[:current_user]

    AuditLog.log(%{
      user_id: user && live_response_user_id(user),
      user_email: user && user.email,
      action: "screen_capture_request",
      action_type: "live_response",
      resource_type: "agent",
      resource_id: agent_id,
      severity: :warning,
      organization_id: get_current_organization_id(conn),
      details: %{
        command_id: command_id,
        status: status,
        reason: request[:reason],
        display: request[:display],
        scope: request[:scope],
        monitor_id: request[:monitor_id],
        watermark: request[:watermark],
        redaction_count: length(request[:redactions] || []),
        ttl_seconds: request[:ttl_seconds],
        capability_state: capability.state,
        consent_required: capability.consent_required,
        unsupported_reason: capability.unsupported_reason,
        policy_mode: policy.mode,
        notify_timing: policy.notify_timing,
        policy: policy.policy,
        continuous: false,
        input_control: false
      }
    })
  end

  defp audit_screen_capture_policy_denied(conn, agent_id, request, policy) do
    user = conn.assigns[:current_user]

    AuditLog.log(%{
      user_id: user && live_response_user_id(user),
      user_email: user && user.email,
      action: "screen_capture_request",
      action_type: "live_response",
      resource_type: "agent",
      resource_id: agent_id,
      severity: :warning,
      organization_id: get_current_organization_id(conn),
      details: %{
        command_id: nil,
        status: "policy_denied",
        reason: request[:reason],
        display: request[:display],
        ttl_seconds: request[:ttl_seconds],
        policy_mode: policy.mode,
        notify_timing: policy.notify_timing,
        policy: policy.policy,
        continuous: false,
        input_control: false
      }
    })
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

  defp authorize_session_access(conn, session_id) do
    case SessionManager.get_session_for_access(
           session_id,
           get_current_organization_id(conn),
           get_current_user_id(conn),
           supervise_live_response?(conn)
         ) do
      {:ok, session} -> {:ok, session}
      {:error, _reason} -> {:error, :not_found}
    end
  end

  defp supervise_live_response?(conn) do
    safe_rbac_can?(conn.assigns[:current_user], :live_response_admin)
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

  defp format_unix_exp(exp) when is_integer(exp),
    do: exp |> DateTime.from_unix!() |> DateTime.to_iso8601()

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

  defp reject_mobile_live_response(%{os_type: os_type}) do
    os = String.downcase(to_string(os_type || ""))

    if String.contains?(os, "android") or String.contains?(os, "ios") or
         String.contains?(os, "iphone") or String.contains?(os, "ipad") do
      {:error, :mobile_live_response_unsupported}
    else
      :ok
    end
  end

  defp maybe_reject_mobile_live_response(nil, _agent_id), do: :ok

  defp maybe_reject_mobile_live_response(org_id, agent_id) do
    case Agents.get_agent_for_org(org_id, agent_id) do
      {:ok, agent} -> reject_mobile_live_response(agent)
      _ -> :ok
    end
  end

  defp mobile_live_response_unsupported(conn) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{
      error: "Live response shell is not available for mobile endpoints",
      platform: "mobile",
      supported_surface: "mobile endpoint commands"
    })
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
