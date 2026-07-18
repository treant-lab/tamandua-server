defmodule TamanduaServerWeb.LiveResponseChannel do
  @moduledoc """
  Phoenix Channel for live response terminal sessions.

  Provides secure, audited terminal access to remote endpoints for incident response.

  ## Features
  - xterm.js based terminal with full PTY support
  - Command history with tab completion
  - Multi-session tabs
  - Session recording (asciinema format)
  - Built-in forensic commands
  - File browser integration

  ## Safety Features
  - Command allowlist/blocklist
  - Full audit logging
  - Session timeout
  - Supervisor approval mode for sensitive commands
  - Dangerous command confirmation
  - Role-based access control

  ## Session Management
  - Active sessions tracking
  - Session sharing (view-only mode)
  - Session export
  - Connection status monitoring
  """

  use TamanduaServerWeb, :channel

  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.LiveResponse.SessionRecording
  alias TamanduaServer.ShellSessions
  alias TamanduaServerWeb.Presence

  require Logger

  # Configuration
  @session_timeout_minutes 30
  @max_sessions_per_user 5
  @max_sessions_per_agent 3
  @command_rate_limit_per_minute 60

  # Global presence topic indexing all live-response sessions. Phoenix.Presence
  # has no topic wildcards ("live_response:*" is treated as a literal topic that
  # nothing tracks), so every session is additionally tracked here to make
  # per-user counting possible. Same remedy as shell_channel.ex (5f167d95).
  @live_response_sessions_topic "live_response_sessions:index"

  # Supervisor approval required for these command patterns
  @supervisor_approval_commands [
    "rm -rf",
    "del /s /q",
    "format",
    "fdisk",
    "dd if=",
    "shutdown",
    "reboot",
    "halt",
    "net user",
    "useradd",
    "userdel",
    "passwd",
    "reg delete",
    "sc delete"
  ]

  # Completely blocked commands
  @blocked_commands [
    ":(){:|:&};:",
    "rm -rf /",
    "rm -rf /*",
    "dd if=/dev/zero of=/dev/sda",
    "mkfs.ext4 /dev/sda",
    "> /dev/sda",
    "mv / /dev/null"
  ]

  @impl true
  def join("live_response:" <> agent_id, payload, socket) do
    user = socket.assigns[:current_user]
    org_id = get_user_org_id(socket)

    with :ok <- verify_permissions(user),
         {:ok, _db_agent} <- verify_agent_ownership(org_id, agent_id),
         {:ok, agent} <- get_online_agent(org_id, agent_id),
         :ok <- check_session_limits(user, agent_id) do
      # Initialize session
      session_id = generate_session_id()
      recording_state = SessionRecording.init(session_id, agent_id, to_string(user.id))

      socket =
        socket
        |> assign(:agent_id, agent_id)
        |> assign(:agent, agent)
        |> assign(:session_id, session_id)
        |> assign(:session_started_at, DateTime.utc_now())
        |> assign(:recording_state, recording_state)
        |> assign(:command_history, [])
        |> assign(:last_activity, DateTime.utc_now())
        |> assign(:command_count, 0)
        |> assign(:bytes_sent, 0)
        |> assign(:bytes_received, 0)
        |> assign(:pending_approvals, %{})
        |> assign(:shell_ready, false)
        |> assign(:shell_start_attempts, 0)
        |> assign(:shell_start_config, nil)
        |> assign(:view_only, Map.get(payload, "view_only", false))
        |> assign(:supervisor_mode, Map.get(payload, "supervisor_mode", false))

      persist_shell_session_start(socket)

      # Presence/audit are best-effort. They must never crash the channel join.
      track_presence(socket, session_id, user, agent, agent_id)

      # Subscribe to supervisor decisions for this session
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "live_response:approvals:#{session_id}")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "shell:#{agent_id}")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "live_response:control:#{agent_id}")

      # Log session start
      audit_log(:session_started, socket)

      # Multiple live-response shells against the same endpoint are legitimate:
      # responders may keep separate sessions for investigation, containment,
      # and long-running commands. Cleanup is handled by explicit tab close,
      # inactivity timeout, and agent disconnect handling instead of replacing
      # older sessions on every new tab.

      # Schedule timeout check
      schedule_timeout_check()

      # Start shell on agent
      send(self(), :start_shell)

      {:ok,
       %{
         session_id: session_id,
         agent_id: agent_id,
         hostname: agent_value(agent, :hostname, "unknown"),
         os: agent_value(agent, :os_type, "unknown"),
         timeout_minutes: @session_timeout_minutes,
         view_only: socket.assigns.view_only,
         supervisor_mode: socket.assigns.supervisor_mode
       }, socket}
    else
      {:error, :unauthorized} ->
        {:error, %{reason: "Insufficient permissions for live response"}}

      {:error, :not_found} ->
        {:error, %{reason: "unauthorized"}}

      {:error, :agent_not_found} ->
        {:error, %{reason: "Agent not found"}}

      {:error, :agent_offline} ->
        {:error, %{reason: "Agent is not online"}}

      {:error, :user_session_limit} ->
        {:error, %{reason: "Maximum sessions per user reached (#{@max_sessions_per_user})"}}

      {:error, :agent_session_limit} ->
        {:error, %{reason: "Maximum sessions per agent reached (#{@max_sessions_per_agent})"}}
    end
  end

  # ============================================================================
  # Handle Info (Internal Messages)
  # ============================================================================

  @impl true
  def handle_info(:start_shell, socket) do
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id
    user = socket.assigns.current_user

    shell_config =
      socket.assigns[:shell_start_config] ||
        %{
          "session_id" => session_id,
          "user_id" => user.id,
          "cols" => 120,
          "rows" => 40,
          "timeout_secs" => @session_timeout_minutes * 60
        }

    attempts = socket.assigns[:shell_start_attempts] || 0

    case send_to_agent(agent_id, "shell:start", shell_config) do
      :ok ->
        Logger.info(
          "Live response shell:start dispatched to #{agent_id} for session #{session_id} attempt=#{attempts + 1}"
        )

        Process.send_after(self(), {:shell_start_retry, session_id}, 25_000)

        socket =
          socket
          |> assign(:shell_start_config, shell_config)
          |> assign(:shell_start_attempts, attempts + 1)

        {:noreply, socket}

      {:error, reason} ->
        push(socket, "error", %{message: reason})
        {:stop, :normal, socket}
    end
  end

  @impl true
  def handle_info({:shell_start_retry, session_id}, socket) do
    cond do
      socket.assigns.session_id != session_id ->
        {:noreply, socket}

      socket.assigns[:shell_ready] ->
        {:noreply, socket}

      (socket.assigns[:shell_start_attempts] || 0) >= 2 ->
        Logger.warning(
          "Live response shell:start did not confirm for #{socket.assigns.agent_id} session #{session_id} after retry"
        )

        {:noreply, socket}

      true ->
        Logger.warning(
          "Retrying live response shell:start for #{socket.assigns.agent_id} session #{session_id}"
        )

        handle_info(:start_shell, socket)
    end
  end

  @impl true
  def handle_info(:check_timeout, socket) do
    last_activity = socket.assigns.last_activity
    now = DateTime.utc_now()
    diff_minutes = DateTime.diff(now, last_activity, :minute)

    if diff_minutes >= @session_timeout_minutes do
      push(socket, "session_timeout", %{
        reason: "Session timed out due to inactivity",
        inactive_minutes: diff_minutes
      })

      socket = terminate_session(socket, "timeout")
      {:stop, :normal, socket}
    else
      schedule_timeout_check()
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:agent_message, message}, socket) do
    if not message_for_current_session?(message, socket) do
      {:noreply, socket}
    else
      Logger.info(
        "LiveResponseChannel: received agent message session=#{message["session_id"] || "none"} type=#{message["type"] || "unknown"}"
      )

      handle_agent_message(message, socket)
    end
  end

  @impl true
  def handle_info({:close_duplicate_user_session, user_id, keep_session_id, reason}, socket) do
    same_user = to_string(user_value(socket.assigns.current_user, :id)) == to_string(user_id)

    if same_user and socket.assigns.session_id != keep_session_id do
      Logger.info(
        "Closing duplicate live response session #{socket.assigns.session_id}; keeping #{keep_session_id}"
      )

      push(socket, "session_ended", %{reason: reason, replacement_session_id: keep_session_id})
      socket = terminate_session(socket, reason)
      {:stop, :normal, socket}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:supervisor_decision, command_id, decision, approver_id}, socket) do
    pending = socket.assigns.pending_approvals

    case Map.get(pending, command_id) do
      nil ->
        {:noreply, socket}

      command_data ->
        socket =
          if decision == :approved do
            # Execute the command
            socket =
              case send_input_to_agent(socket, command_data) do
                {:ok, socket} ->
                  socket

                {:error, reason, socket} ->
                  push(socket, "error", %{message: reason})
                  socket
              end

            audit_log(:supervisor_approved, socket, %{
              command_id: command_id,
              command: command_data,
              approver_id: approver_id
            })

            push(socket, "supervisor_approved", %{command_id: command_id})
            socket
          else
            audit_log(:supervisor_rejected, socket, %{
              command_id: command_id,
              command: command_data,
              approver_id: approver_id
            })

            push(socket, "supervisor_rejected", %{
              command_id: command_id,
              reason: "Command rejected by supervisor"
            })

            socket
          end

        socket = update_in(socket.assigns.pending_approvals, &Map.delete(&1, command_id))
        {:noreply, socket}
    end
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  defp handle_agent_message(message, socket) do
    case message do
      %{"type" => "session_ended"} = payload ->
        push(socket, "session_ended", payload)
        socket = terminate_session(socket, "agent_ended")
        {:stop, :normal, socket}

      _ ->
        handle_agent_message_continue(message, socket)
    end
  end

  defp handle_agent_message_continue(message, socket) do
    socket =
      case message do
        %{"type" => "data", "data" => data} ->
          push(socket, "output", %{data: data})
          record_output(socket, data)

        %{"type" => "session_started"} = payload ->
          push(socket, "session_started", payload)
          assign(socket, :shell_ready, true)

        %{"type" => "builtin_result"} = payload ->
          push(socket, "builtin_result", payload)
          record_builtin_result(socket, payload)

        %{"type" => "dangerous_command_warning"} = payload ->
          push(socket, "dangerous_warning", payload)
          socket

        %{"type" => "error", "message" => error_msg} ->
          push(socket, "error", %{message: error_msg})
          socket

        %{"type" => "pong", "timestamp" => ts} ->
          push(socket, "pong", %{timestamp: ts})
          socket

        %{"type" => "file_list", "files" => files, "path" => path} ->
          push(socket, "file_list", %{files: files, path: path})
          socket

        %{"type" => "file_content"} = payload ->
          push(socket, "file_content", payload)
          socket

        %{"type" => "download_ready"} = payload ->
          push(socket, "download_ready", payload)
          socket

        %{"type" => "completion_suggestions", "suggestions" => suggestions} ->
          push(socket, "completions", %{suggestions: suggestions})
          socket

        _ ->
          Logger.warning("Unknown agent message: #{inspect(message)}")
          socket
      end

    {:noreply, socket}
  end

  # ============================================================================
  # Handle In (Client Messages)
  # ============================================================================

  @impl true
  def handle_in("input", %{"data" => data}, socket) do
    Logger.debug(
      "Live response input received for agent #{socket.assigns.agent_id}, session #{socket.assigns.session_id}, bytes=#{byte_size(data)}, view_only=#{socket.assigns.view_only}"
    )

    if socket.assigns.view_only do
      push(socket, "error", %{message: "Session is view-only"})
      {:reply, {:error, %{reason: "Session is view-only"}}, socket}
    else
      case send_input_to_agent(socket, data) do
        {:ok, socket} ->
          {:reply, {:ok, %{sent: byte_size(data)}}, socket}

        {:error, reason, socket} ->
          {:reply, {:error, %{reason: reason}}, socket}
      end
    end
  end

  @impl true
  def handle_in("resize", %{"cols" => cols, "rows" => rows}, socket) do
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id

    payload = %{
      "session_id" => session_id,
      "type" => "resize",
      "cols" => cols,
      "rows" => rows
    }

    send_to_agent(agent_id, "shell:input", payload)
    {:noreply, socket}
  end

  @impl true
  def handle_in("builtin", %{"command" => command, "args" => args}, socket) do
    if socket.assigns.view_only do
      push(socket, "error", %{message: "Session is view-only"})
      {:noreply, socket}
    else
      socket = assign(socket, :last_activity, DateTime.utc_now())

      # Log the builtin command
      audit_log(:builtin_command, socket, %{command: command, args: args})

      # Add to command history
      add_to_history(socket, %{type: :builtin, command: command, args: args})

      shell_input = builtin_shell_command(command, args, socket.assigns.agent)

      case send_input_to_agent(socket, shell_input) do
        {:ok, socket} ->
          {:reply, {:ok, %{sent: byte_size(shell_input)}}, socket}

        {:error, reason, socket} ->
          {:reply, {:error, %{reason: reason}}, socket}
      end
    end
  end

  @impl true
  def handle_in("confirm_dangerous", %{"command_id" => command_id}, socket) do
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id

    audit_log(:dangerous_confirmed, socket, %{command_id: command_id})

    payload = %{
      "session_id" => session_id,
      "type" => "confirm_dangerous",
      "command_id" => command_id
    }

    send_to_agent(agent_id, "shell:input", payload)
    {:noreply, socket}
  end

  @impl true
  def handle_in("cancel_dangerous", %{"command_id" => command_id}, socket) do
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id

    audit_log(:dangerous_cancelled, socket, %{command_id: command_id})

    payload = %{
      "session_id" => session_id,
      "type" => "cancel_dangerous",
      "command_id" => command_id
    }

    send_to_agent(agent_id, "shell:input", payload)
    {:noreply, socket}
  end

  @impl true
  def handle_in("ping", _payload, socket) do
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id

    payload = %{
      "session_id" => session_id,
      "type" => "ping"
    }

    send_to_agent(agent_id, "shell:input", payload)
    {:noreply, socket}
  end

  @impl true
  def handle_in("terminate", _payload, socket) do
    socket = terminate_session(socket, "user_requested")
    {:stop, :normal, socket}
  end

  @impl true
  def handle_in("get_history", _payload, socket) do
    history =
      socket.assigns.command_history
      |> Enum.take(100)
      |> Enum.map(fn entry ->
        %{
          timestamp: DateTime.to_iso8601(entry.timestamp),
          type: entry.type,
          command: entry[:command] || entry[:data],
          args: entry[:args]
        }
      end)

    push(socket, "history", %{entries: history})
    {:noreply, socket}
  end

  # File browser operations
  @impl true
  def handle_in("list_files", %{"path" => path}, socket) do
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id

    payload = %{
      "session_id" => session_id,
      "type" => "file_list",
      "path" => path,
      "recursive" => false,
      "include_hidden" => true
    }

    send_to_agent(agent_id, "shell:file_op", payload)
    {:noreply, socket}
  end

  @impl true
  def handle_in("preview_file", %{"path" => path, "mode" => mode}, socket) do
    if socket.assigns.view_only and mode != "text" do
      push(socket, "error", %{message: "Session is view-only"})
      {:noreply, socket}
    else
      agent_id = socket.assigns.agent_id
      session_id = socket.assigns.session_id

      # mode: "text" | "hex" | "info"
      payload = %{
        "session_id" => session_id,
        "type" => "file_preview",
        "path" => path,
        "mode" => mode,
        # 64KB preview limit
        "max_size" => 65536
      }

      send_to_agent(agent_id, "shell:file_op", payload)
      audit_log(:file_preview, socket, %{path: path, mode: mode})
      {:noreply, socket}
    end
  end

  @impl true
  def handle_in("download_file", %{"path" => path}, socket) do
    if socket.assigns.view_only do
      push(socket, "error", %{message: "Session is view-only"})
      {:noreply, socket}
    else
      agent_id = socket.assigns.agent_id
      session_id = socket.assigns.session_id

      payload = %{
        "session_id" => session_id,
        "type" => "file_download",
        "path" => path
      }

      send_to_agent(agent_id, "shell:file_op", payload)
      audit_log(:file_download, socket, %{path: path})
      {:noreply, socket}
    end
  end

  @impl true
  def handle_in("hash_file", %{"path" => path}, socket) do
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id

    payload = %{
      "session_id" => session_id,
      "type" => "file_hash",
      "path" => path
    }

    send_to_agent(agent_id, "shell:file_op", payload)
    {:noreply, socket}
  end

  @impl true
  def handle_in("quarantine_file", %{"path" => path}, socket) do
    if socket.assigns.view_only do
      push(socket, "error", %{message: "Session is view-only"})
      {:noreply, socket}
    else
      agent_id = socket.assigns.agent_id
      session_id = socket.assigns.session_id

      payload = %{
        "session_id" => session_id,
        "type" => "file_quarantine",
        "path" => path
      }

      send_to_agent(agent_id, "shell:file_op", payload)
      audit_log(:file_quarantine, socket, %{path: path})
      {:noreply, socket}
    end
  end

  # Tab completion
  @impl true
  def handle_in("request_completion", %{"prefix" => prefix, "context" => context}, socket) do
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id

    payload = %{
      "session_id" => session_id,
      "type" => "tab_completion",
      "prefix" => prefix,
      "context" => context
    }

    send_to_agent(agent_id, "shell:input", payload)
    {:noreply, socket}
  end

  # Session sharing
  @impl true
  def handle_in("share_session", %{"user_id" => target_user_id, "view_only" => view_only}, socket) do
    session_id = socket.assigns.session_id
    user = socket.assigns.current_user

    # Only session owner can share
    if can_share_session?(user, socket) do
      share_token = generate_share_token(session_id, target_user_id, view_only)

      audit_log(:session_shared, socket, %{
        target_user_id: target_user_id,
        view_only: view_only
      })

      push(socket, "share_token", %{
        token: share_token,
        target_user_id: target_user_id,
        view_only: view_only
      })
    else
      push(socket, "error", %{message: "Not authorized to share this session"})
    end

    {:noreply, socket}
  end

  # Export session
  @impl true
  def handle_in("export_session", %{"format" => format}, socket) do
    session_id = socket.assigns.session_id
    recording_state = socket.assigns[:recording_state]
    _recording_path = if recording_state, do: recording_state.path, else: nil

    case format do
      "asciinema" ->
        # Recording is in compressed/encrypted asciinema format
        # Client should use the recording download API endpoint for playback
        push(socket, "export_ready", %{
          format: "asciinema",
          session_id: session_id,
          download_url: "/api/v1/recordings/#{session_id}/download"
        })

      "transcript" ->
        transcript = generate_transcript(socket)

        push(socket, "export_ready", %{
          format: "transcript",
          content: transcript
        })

      "json" ->
        export_data = %{
          session_id: session_id,
          agent_id: socket.assigns.agent_id,
          hostname: agent_value(socket.assigns.agent, :hostname, "unknown"),
          user: user_value(socket.assigns.current_user, :email, "unknown"),
          started_at: DateTime.to_iso8601(socket.assigns.session_started_at),
          command_history: socket.assigns.command_history
        }

        push(socket, "export_ready", %{
          format: "json",
          content: Jason.encode!(export_data)
        })

      _ ->
        push(socket, "error", %{message: "Unsupported export format"})
    end

    {:noreply, socket}
  end

  # List active sessions for this agent
  @impl true
  def handle_in("list_sessions", _payload, socket) do
    agent_id = socket.assigns.agent_id

    sessions =
      TamanduaServerWeb.Presence.list("live_response:#{agent_id}")
      |> Enum.map(fn {session_id, %{metas: [meta | _]}} ->
        %{
          session_id: session_id,
          user_email: meta.user_email,
          view_only: meta.view_only,
          joined_at: DateTime.to_iso8601(meta.joined_at)
        }
      end)

    push(socket, "active_sessions", %{sessions: sessions})
    {:noreply, socket}
  end

  @impl true
  def terminate(_reason, socket) do
    if socket.assigns[:session_id] do
      _socket = terminate_session(socket, "channel_closed")
    end

    :ok
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp get_user_org_id(socket) do
    case socket.assigns[:current_user] do
      %{organization_id: org_id} -> org_id
      user when is_map(user) -> user_value(user, :organization_id)
      _ -> nil
    end
  end

  defp message_for_current_session?(%{"session_id" => session_id}, socket)
       when is_binary(session_id) do
    session_id == socket.assigns[:session_id]
  end

  defp message_for_current_session?(_message, _socket), do: true

  defp verify_agent_ownership(org_id, agent_id) do
    Agents.get_agent_for_org(org_id, agent_id)
  end

  defp verify_permissions(nil), do: {:error, :unauthorized}

  defp verify_permissions(user) do
    # Check RBAC permission or fallback to role-based check
    if safe_rbac_can?(user, :live_response_shell) do
      :ok
    else
      # Fallback: check user role directly
      role = user_value(user, :role)

      if role in [:admin, :analyst, :responder, "admin", "analyst", "responder"] do
        :ok
      else
        {:error, :unauthorized}
      end
    end
  end

  defp safe_rbac_can?(user, permission) do
    TamanduaServer.Authorization.RBAC.can?(user, permission)
  rescue
    ArgumentError ->
      false

    UndefinedFunctionError ->
      false

    FunctionClauseError ->
      false

    KeyError ->
      false
  end

  defp get_online_agent(org_id, agent_id) do
    # Use org-scoped getter for defense in depth (multi-tenant isolation)
    case Agents.get_agent_for_org(org_id, agent_id) do
      {:ok, agent} ->
        worker_pid = Registry.lookup_agent(agent_id)

        cond do
          is_nil(worker_pid) ->
            Logger.warning(
              "Live response rejected for #{agent_id}: no active worker is registered"
            )

            {:error, :agent_offline}

          not Process.alive?(worker_pid) ->
            Logger.warning(
              "Live response rejected for #{agent_id}: registered worker #{inspect(worker_pid)} is not alive"
            )

            {:error, :agent_offline}

          true ->
            {:ok, agent}
        end

      {:error, :not_found} ->
        {:error, :agent_not_found}
    end
  end

  defp check_session_limits(user, agent_id) do
    user_sessions = count_user_sessions(user_value(user, :id))
    agent_sessions = count_agent_sessions(agent_id)
    same_user_agent_sessions = count_agent_sessions(agent_id, user_value(user, :id))
    agent_sessions_for_limit = max(agent_sessions - same_user_agent_sessions, 0)

    cond do
      user_sessions >= @max_sessions_per_user ->
        {:error, :user_session_limit}

      agent_sessions_for_limit >= @max_sessions_per_agent ->
        {:error, :agent_session_limit}

      true ->
        :ok
    end
  end

  defp count_user_sessions(user_id) do
    # Count active live-response sessions for this user across all agents via
    # the global presence index. Phoenix.Presence has no topic wildcards:
    # list("live_response:*") queried the literal topic "live_response:*",
    # which nothing tracks, so this always returned 0 and
    # @max_sessions_per_user was never enforced (fail-open).
    Presence.list(@live_response_sessions_topic)
    |> Enum.count(fn {_session_id, %{metas: metas}} ->
      Enum.any?(metas, &(&1.user_id == user_id))
    end)
  rescue
    _ -> 0
  catch
    # Presence tracker is a GenServer; a dead tracker exits instead of raising.
    :exit, _ -> 0
  end

  defp count_agent_sessions(agent_id) do
    count_agent_sessions(agent_id, nil)
  end

  defp count_agent_sessions(agent_id, user_id) do
    TamanduaServerWeb.Presence.list("live_response:#{agent_id}")
    |> Enum.count(fn {_session_id, %{metas: metas}} ->
      is_nil(user_id) or Enum.any?(metas, &(to_string(&1.user_id) == to_string(user_id)))
    end)
  rescue
    _ -> 0
  catch
    # Presence tracker is a GenServer; a dead tracker exits instead of raising.
    :exit, _ -> 0
  end

  defp close_duplicate_user_sessions(socket) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "live_response:control:#{socket.assigns.agent_id}",
      {:close_duplicate_user_session, user_value(socket.assigns.current_user, :id),
       socket.assigns.session_id, "replaced_by_new_session"}
    )
  end

  defp generate_session_id do
    "lr_" <> Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
  end

  defp generate_command_id do
    "cmd_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end

  defp record_output(socket, data) do
    socket = assign(socket, :bytes_received, socket.assigns[:bytes_received] + byte_size(data))

    case socket.assigns[:recording_state] do
      nil ->
        socket

      recording_state ->
        updated_state = SessionRecording.append_event(recording_state, "o", data)
        assign(socket, :recording_state, updated_state)
    end
  end

  defp record_builtin_result(socket, payload) do
    if recording_state = socket.assigns[:recording_state] do
      output = payload["output"] || Jason.encode!(payload)
      full_output = "\r\n--- Builtin Result ---\r\n" <> output <> "\r\n"
      updated_state = SessionRecording.append_event(recording_state, "o", full_output)

      socket
      |> assign(:bytes_received, socket.assigns[:bytes_received] + byte_size(full_output))
      |> assign(:recording_state, updated_state)
    else
      socket
    end
  end

  defp send_input_to_agent(socket, data) do
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id

    socket = assign(socket, :last_activity, DateTime.utc_now())

    socket = assign(socket, :bytes_sent, socket.assigns[:bytes_sent] + byte_size(data))

    # Record input using the new recording module
    socket =
      if recording_state = socket.assigns[:recording_state] do
        updated_state = SessionRecording.append_event(recording_state, "i", data)
        assign(socket, :recording_state, updated_state)
      else
        socket
      end

    payload = %{
      "session_id" => session_id,
      "type" => "data",
      "data" => data
    }

    case send_to_agent(agent_id, "shell:input", payload) do
      :ok -> {:ok, socket}
      {:error, reason} -> {:error, reason, socket}
    end
  end

  defp send_to_agent(agent_id, event, payload) do
    case Registry.lookup_agent(agent_id) do
      nil ->
        Logger.warning(
          "Live response failed to dispatch #{event} to #{agent_id}: agent worker not connected"
        )

        {:error, "Agent not connected"}

      pid ->
        if event == "shell:input" do
          Logger.debug("Live response dispatch #{event} to #{agent_id} via worker #{inspect(pid)}")
        else
          Logger.info("Live response dispatch #{event} to #{agent_id} via worker #{inspect(pid)}")
        end

        send(pid, {:push_to_agent, event, payload})
        :ok
    end
  end

  defp terminate_session(socket, reason) do
    if socket.assigns[:terminated] do
      socket
    else
      agent_id = socket.assigns.agent_id
      session_id = socket.assigns.session_id

      payload = %{
        "session_id" => session_id,
        "type" => "terminate"
      }

      send_to_agent(agent_id, "shell:input", payload)
      audit_log(:session_ended, socket, %{reason: reason})
      finalize_recording(socket, reason)
    end
  end

  defp finalize_recording(socket, reason) do
    socket = assign(socket, :terminated, true)

    if recording_state = socket.assigns[:recording_state] do
      case SessionRecording.finalize(recording_state) do
        {:ok, metadata} ->
          Logger.info(
            "Live response recording finalized: #{metadata.path} " <>
              "(#{metadata.file_size} bytes, encrypted=#{metadata.encrypted})"
          )

          persist_shell_session_end(socket, reason, metadata)
          assign(socket, :recording_state, nil)

        {:error, reason} ->
          Logger.error("Failed to finalize recording: #{inspect(reason)}")
          persist_shell_session_end(socket, reason, nil)
          socket
      end
    else
      persist_shell_session_end(socket, reason, nil)
      socket
    end
  end

  defp persist_shell_session_start(socket) do
    user = socket.assigns.current_user
    agent = socket.assigns.agent

    attrs = %{
      session_id: socket.assigns.session_id,
      user_id: user_value(user, :id),
      agent_id: socket.assigns.agent_id,
      agent_hostname: agent_value(agent, :hostname, "unknown"),
      agent_os: agent_value(agent, :os_type, "unknown"),
      started_at: socket.assigns.session_started_at,
      status: :active,
      command_count: 0,
      bytes_sent: 0,
      bytes_received: 0,
      has_recording: false,
      client_ip: socket.assigns[:client_ip],
      user_agent: socket.assigns[:user_agent]
    }

    case ShellSessions.create_session(attrs) do
      {:ok, _session} ->
        :ok

      {:error, changeset} ->
        Logger.warning(
          "Failed to persist live response shell session #{socket.assigns.session_id}: " <>
            inspect(changeset.errors)
        )
    end
  rescue
    e ->
      Logger.warning("Failed to persist live response shell session: #{Exception.message(e)}")
  end

  defp persist_shell_session_end(socket, reason, metadata) do
    case ShellSessions.get_session_by_session_id(socket.assigns.session_id) do
      nil ->
        :ok

      session ->
        attrs = %{
          ended_at: DateTime.utc_now(),
          status: :ended,
          end_reason: reason,
          command_count: socket.assigns[:command_count] || 0,
          bytes_sent: socket.assigns[:bytes_sent] || 0,
          bytes_received: socket.assigns[:bytes_received] || 0,
          recording_path: metadata && metadata.path,
          has_recording: not is_nil(metadata)
        }

        case ShellSessions.update_session(session, attrs) do
          {:ok, _session} ->
            :ok

          {:error, changeset} ->
            Logger.warning(
              "Failed to update live response shell session #{socket.assigns.session_id}: " <>
                inspect(changeset.errors)
            )
        end
    end
  rescue
    e ->
      Logger.warning("Failed to update live response shell session: #{Exception.message(e)}")
  end

  defp schedule_timeout_check do
    Process.send_after(self(), :check_timeout, 60_000)
  end

  defp is_blocked_command?(data) do
    data_lower = String.downcase(data)

    Enum.any?(@blocked_commands, fn blocked ->
      String.contains?(data_lower, String.downcase(blocked))
    end)
  end

  defp requires_supervisor_approval?(data) do
    data_lower = String.downcase(data)

    Enum.any?(@supervisor_approval_commands, fn cmd ->
      String.contains?(data_lower, String.downcase(cmd))
    end)
  end

  defp builtin_shell_command("ps", _args, agent) do
    if windows_agent?(agent), do: "tasklist\r\n", else: "ps aux\n"
  end

  defp builtin_shell_command("netstat", _args, agent) do
    if windows_agent?(agent),
      do: "netstat -ano\r\n",
      else: "netstat -anp tcp 2>/dev/null || netstat -an\n"
  end

  defp builtin_shell_command("autoruns", _args, agent) do
    if windows_agent?(agent),
      do: "wmic startup get Caption,Command,Location,User\r\n",
      else:
        "printf 'systemd services:\\n'; systemctl list-unit-files --type=service --no-pager 2>/dev/null | head -100\n"
  end

  defp builtin_shell_command("services", _args, agent) do
    if windows_agent?(agent),
      do: "sc query state= all\r\n",
      else: "systemctl list-units --type=service --no-pager\n"
  end

  defp builtin_shell_command("tasks", _args, agent) do
    if windows_agent?(agent),
      do: "schtasks /query /fo LIST /v\r\n",
      else: "crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null\n"
  end

  defp builtin_shell_command("dns", _args, agent) do
    if windows_agent?(agent),
      do: "ipconfig /displaydns\r\n",
      else: "resolvectl statistics 2>/dev/null; resolvectl query example.com 2>/dev/null\n"
  end

  defp builtin_shell_command("help", _args, _agent) do
    "echo Tamandua live response commands: ps, netstat, autoruns, services, tasks, dns, history\r\n"
  end

  defp builtin_shell_command(command, args, agent) do
    line =
      [command | List.wrap(args)]
      |> Enum.map(&quote_shell_arg(&1, agent))
      |> Enum.join(" ")

    line <> shell_newline(agent)
  end

  defp quote_shell_arg(arg, agent) do
    arg = to_string(arg)

    if arg == "" or shell_quote_required?(arg) do
      if windows_agent?(agent) do
        "\"" <> String.replace(arg, "\"", "\\\"") <> "\""
      else
        "'" <> String.replace(arg, "'", "'\"'\"'") <> "'"
      end
    else
      arg
    end
  end

  defp shell_quote_required?(arg) do
    String.contains?(arg, [" ", "\t", "|", "&", ";", "<", ">", "(", ")", "$", "`", "\"", "'"])
  end

  defp shell_newline(agent) do
    if windows_agent?(agent), do: "\r\n", else: "\n"
  end

  defp windows_agent?(agent) do
    agent
    |> agent_value(:os_type, "")
    |> to_string()
    |> String.downcase()
    |> String.contains?("windows")
  end

  defp check_rate_limit(socket) do
    count = socket.assigns.command_count + 1
    socket = assign(socket, :command_count, count)

    # Reset counter every minute (simplified)
    if count > @command_rate_limit_per_minute do
      push(socket, "rate_limited", %{
        message: "Command rate limit exceeded",
        limit: @command_rate_limit_per_minute
      })
    end

    socket
  end

  defp add_to_history(socket, entry) do
    entry = Map.put(entry, :timestamp, DateTime.utc_now())
    history = [entry | socket.assigns.command_history]
    assign(socket, :command_history, Enum.take(history, 1000))
  end

  defp notify_supervisors(socket, command_id, command) do
    agent_id = socket.assigns.agent_id
    user = socket.assigns.current_user
    agent = socket.assigns.agent

    # Broadcast to supervisor channel
    TamanduaServerWeb.Endpoint.broadcast("supervisors:approvals", "approval_required", %{
      command_id: command_id,
      session_id: socket.assigns.session_id,
      agent_id: agent_id,
      hostname: agent_value(agent, :hostname, "unknown"),
      user_email: user_value(user, :email, "unknown"),
      command: command,
      requested_at: DateTime.utc_now() |> DateTime.to_iso8601()
    })
  end

  defp can_share_session?(user, socket) do
    # Session creator can share
    user_value(user, :id) == user_value(socket.assigns.current_user, :id) ||
      user_value(user, :role) in [:admin, :supervisor, "admin", "supervisor"]
  end

  defp generate_share_token(session_id, target_user_id, view_only) do
    data = "#{session_id}:#{target_user_id}:#{view_only}:#{System.system_time(:second)}"
    signature = :crypto.mac(:hmac, :sha256, get_secret_key(), data) |> Base.url_encode64()
    Base.url_encode64(data) <> "." <> signature
  end

  defp get_secret_key do
    case Application.get_env(:tamandua_server, :secret_key_base) do
      nil ->
        Logger.error(
          "secret_key_base is not configured! " <>
            "HMAC signing is using an insecure fallback. " <>
            "Set :secret_key_base in your application config."
        )

        # Generate a per-boot random key as a safer fallback than a hardcoded string
        :persistent_term.get({__MODULE__, :fallback_secret_key}, nil) ||
          (fn ->
             key = :crypto.strong_rand_bytes(64) |> Base.encode64()
             :persistent_term.put({__MODULE__, :fallback_secret_key}, key)
             key
           end).()

      "" ->
        Logger.error(
          "secret_key_base is empty! Set a proper secret_key_base in your application config."
        )

        :crypto.strong_rand_bytes(64) |> Base.encode64()

      key ->
        key
    end
  end

  defp generate_transcript(socket) do
    lines = [
      "=== Live Response Session Transcript ===",
      "Session ID: #{socket.assigns.session_id}",
      "Agent: #{agent_value(socket.assigns.agent, :hostname, "unknown")} (#{socket.assigns.agent_id})",
      "User: #{user_value(socket.assigns.current_user, :email, "unknown")}",
      "Started: #{DateTime.to_iso8601(socket.assigns.session_started_at)}",
      "Commands Executed: #{length(socket.assigns.command_history)}",
      "",
      "=== Command History ===",
      ""
    ]

    command_lines =
      socket.assigns.command_history
      |> Enum.reverse()
      |> Enum.map(fn entry ->
        time = DateTime.to_iso8601(entry.timestamp)
        cmd = entry[:command] || entry[:data] || "unknown"
        "[#{time}] #{cmd}"
      end)

    Enum.join(lines ++ command_lines, "\n")
  end

  defp audit_log(action, socket, extra \\ %{}) do
    user = socket.assigns.current_user
    agent = socket.assigns.agent
    session_id = socket.assigns.session_id
    user_id = user_value(user, :id)
    user_email = user_value(user, :email, "unknown")
    agent_id = agent_value(agent, :id) || agent_value(agent, :agent_id)
    hostname = agent_value(agent, :hostname, "unknown")

    log_entry = %{
      action: action,
      session_id: session_id,
      user_id: user_id,
      user_email: user_email,
      agent_id: agent_id,
      hostname: hostname,
      timestamp: DateTime.utc_now(),
      extra: extra
    }

    Logger.info("Live Response Audit: #{inspect(log_entry)}")

    TamanduaServer.AuditLog.log(%{
      action: "live_response:#{action}",
      action_type: "live_response",
      user_id: user_id,
      user_email: user_email,
      resource_type: "live_response_session",
      resource_id: session_id,
      severity: :info,
      details: log_entry,
      ip_address: socket.assigns[:client_ip],
      user_agent: socket.assigns[:user_agent],
      organization_id: user_value(user, :organization_id)
    })

    emit_live_response_telemetry(action, log_entry, socket)
  rescue
    e ->
      Logger.error("Failed to write audit log: #{inspect(e)}")
  end

  defp emit_live_response_telemetry(:builtin_command, log_entry, socket) do
    extra = Map.get(log_entry, :extra) || %{}
    command = Map.get(extra, :command) || Map.get(extra, "command") || ""
    args = Map.get(extra, :args) || Map.get(extra, "args") || []
    command_line = builtin_shell_command(command, args, socket.assigns.agent) |> String.trim()
    decoded_command_line = decode_powershell_encoded_command(command_line)

    payload =
      %{
        "session_id" => log_entry.session_id,
        "hostname" => log_entry.hostname,
        "user" => log_entry.user_email,
        "process_name" => command,
        "command" => command,
        "args" => args,
        "command_line" => command_line,
        "source" => "live_response_audit"
      }
      |> put_if_present("decoded_command_line", decoded_command_line)

    TamanduaServer.Telemetry.Ingestor.push_event(%{
      "event_id" => Ecto.UUID.generate(),
      "event_type" => "live_response_command",
      "agent_id" => log_entry.agent_id,
      "organization_id" => user_value(socket.assigns.current_user, :organization_id),
      "hostname" => log_entry.hostname,
      "severity" => "info",
      "timestamp" => DateTime.to_unix(DateTime.utc_now(), :millisecond),
      "payload" => payload,
      "metadata" => %{
        "provider" => "tamandua_server",
        "source" => "live_response_audit"
      }
    })
  rescue
    e ->
      Logger.warning("Failed to emit live response telemetry: #{Exception.message(e)}")
  end

  defp emit_live_response_telemetry(_action, _log_entry, _socket), do: :ok

  defp decode_powershell_encoded_command(command_line) when is_binary(command_line) do
    case Regex.run(~r/(?:^|\s|\/|-)(?:enc|encodedcommand)\s+([A-Za-z0-9+\/=_-]+)/i, command_line) do
      [_, encoded] ->
        encoded
        |> String.replace("-", "+")
        |> String.replace("_", "/")
        |> decode_base64_relaxed()
        |> case do
          {:ok, bytes} -> decode_utf16le(bytes)
          :error -> nil
        end

      _ ->
        nil
    end
  end

  defp decode_powershell_encoded_command(_), do: nil

  defp decode_base64_relaxed(value) do
    case Base.decode64(value) do
      {:ok, _} = ok -> ok
      :error -> Base.decode64(value, padding: false)
    end
  end

  defp decode_utf16le(bytes) when is_binary(bytes) do
    bytes
    |> :unicode.characters_to_binary({:utf16, :little}, :utf8)
    |> case do
      decoded when is_binary(decoded) -> decoded
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp put_if_present(map, _key, nil), do: map
  defp put_if_present(map, _key, ""), do: map
  defp put_if_present(map, key, value), do: Map.put(map, key, value)

  defp track_presence(socket, session_id, user, agent, agent_id) do
    case Presence.track(socket, session_id, %{
           user_id: user_value(user, :id),
           user_email: user_value(user, :email, "unknown"),
           agent_id: agent_id,
           hostname: agent_value(agent, :hostname, "unknown"),
           view_only: socket.assigns.view_only,
           joined_at: DateTime.utc_now()
         }) do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        Logger.warning("Live response presence tracking failed: #{inspect(reason)}")
        :ok
    end

    # Also track on the global session index so count_user_sessions/1 can
    # enforce @max_sessions_per_user across all agents (Presence cannot
    # enumerate "live_response:*"). Entries are removed automatically when
    # this channel process dies.
    case Presence.track(self(), @live_response_sessions_topic, session_id, %{
           user_id: user_value(user, :id),
           agent_id: agent_id
         }) do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        Logger.warning("Live response session-index tracking failed: #{inspect(reason)}")
        :ok
    end
  rescue
    e ->
      Logger.warning("Live response presence tracking crashed: #{Exception.message(e)}")
      :ok
  end

  defp user_value(user, key, default \\ nil), do: safe_value(user, key, default)
  defp agent_value(agent, key, default \\ nil), do: safe_value(agent, key, default)

  defp safe_value(nil, _key, default), do: default

  defp safe_value(map, key, default) when is_map(map) do
    Map.get(map, key) || Map.get(map, to_string(key)) || default
  end

  defp safe_value(_value, _key, default), do: default
end
