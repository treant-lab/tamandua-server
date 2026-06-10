defmodule TamanduaServerWeb.ShellChannel do
  @moduledoc """
  Phoenix Channel for interactive shell sessions.

  Provides live response shell capabilities:
  - Session management with authentication
  - Bidirectional terminal streaming
  - Command audit logging
  - Session recording for playback
  - Terminal resize handling
  - Built-in forensic commands

  Security:
  - Requires authenticated user with shell access permission
  - All commands are logged to audit trail
  - Session timeout handling
  - Dangerous command warnings
  """

  use TamanduaServerWeb, :channel

  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.LiveResponse.SessionRecording
  alias TamanduaServerWeb.Presence

  require Logger

  # Session timeout in minutes
  @session_timeout_minutes 30

  # Maximum sessions per user
  @max_sessions_per_user 5

  @impl true
  def join("shell:" <> agent_id, payload, socket) do
    user = socket.assigns[:current_user]
    org_id = get_user_org_id(socket)

    # Verify user has shell access permission
    unless has_shell_permission?(user) do
      {:error, %{reason: "Insufficient permissions for shell access"}}
    else
      # Validate tenant ownership before allowing join
      case Agents.get_agent_for_org(org_id, agent_id) do
        {:error, :not_found} ->
          {:error, %{reason: "unauthorized"}}

        {:ok, agent} ->
          if agent.status != :online do
            {:error, %{reason: "Agent is not online"}}
          else
            # Check session limit
            if count_user_sessions(user.id) >= @max_sessions_per_user do
              {:error, %{reason: "Maximum number of active sessions reached"}}
            else
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

              # Track presence
              {:ok, _} =
                Presence.track(socket, session_id, %{
                  user_id: user.id,
                  user_email: user.email,
                  agent_id: agent_id,
                  hostname: agent.hostname,
                  joined_at: DateTime.utc_now()
                })

              # Log session start
              audit_log(:session_started, socket)

              # Schedule timeout check
              schedule_timeout_check()

              send(self(), :start_shell)

              # Subscribe to agent_message broadcasts for this agent
              Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "shell:#{agent_id}")

              {:ok,
               %{
                 session_id: session_id,
                 agent_id: agent_id,
                 hostname: agent.hostname,
                 os: agent.os_type,
                 timeout_minutes: @session_timeout_minutes
               }, socket}
            end
          end
      end
    end
  end

  @impl true
  def handle_info(:start_shell, socket) do
    # Request shell start from agent
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id
    user = socket.assigns.current_user

    shell_config = %{
      "session_id" => session_id,
      "user_id" => user.id,
      "cols" => 120,
      "rows" => 40,
      "timeout_secs" => @session_timeout_minutes * 60
    }

    case send_to_agent(agent_id, "shell:start", shell_config) do
      :ok ->
        {:noreply, socket}

      {:error, reason} ->
        push(socket, "session_error", %{error: reason})
        {:stop, :normal, socket}
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

      # End the session
      terminate_session(socket, "timeout")
      {:stop, :normal, socket}
    else
      # Check again later
      schedule_timeout_check()
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:agent_message, message}, socket) do
    # Handle messages from agent via Registry or broadcast
    socket =
      case message do
        %{"type" => "data", "data" => data} ->
          push(socket, "output", %{data: data})
          record_output(socket, data)

        # Also handle PtyOutput format from new PTY bridge
        %{"type" => "data", "session_id" => _sid, "data" => data} ->
          push(socket, "output", %{data: data})
          record_output(socket, data)

        %{"type" => "session_started"} = payload ->
          push(socket, "session_started", payload)
          socket

        %{"type" => "session_ended"} = payload ->
          push(socket, "session_ended", payload)
          terminate_session(socket, "agent_ended")
          socket

        %{"type" => "builtin_result"} = payload ->
          push(socket, "builtin_result", payload)
          record_builtin_result(socket, payload)

        %{"type" => "dangerous_command_warning"} = payload ->
          push(socket, "dangerous_warning", payload)
          socket

        %{"type" => "error", "message" => error_msg} ->
          push(socket, "error", %{message: error_msg})
          socket

        %{"type" => "error", "session_id" => _sid, "message" => error_msg} ->
          push(socket, "error", %{message: error_msg})
          socket

        %{"type" => "pong", "timestamp" => ts} ->
          push(socket, "pong", %{timestamp: ts})
          socket

        %{"type" => "pong", "session_id" => _sid, "timestamp" => ts} ->
          push(socket, "pong", %{timestamp: ts})
          socket

        _ ->
          Logger.warning("Unknown agent message: #{inspect(message)}")
          socket
      end

    {:noreply, socket}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def handle_in("input", %{"data" => data}, socket) do
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id

    # Update last activity
    socket = assign(socket, :last_activity, DateTime.utc_now())

    # Record input using the new recording module
    socket = record_input(socket, data)

    # Send to agent
    payload = %{
      "session_id" => session_id,
      "type" => "data",
      "data" => data
    }

    send_to_agent(agent_id, "shell:input", payload)

    {:noreply, socket}
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
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id
    user = socket.assigns.current_user

    # Update last activity
    socket = assign(socket, :last_activity, DateTime.utc_now())

    # Log the builtin command
    audit_log(:builtin_command, socket, %{command: command, args: args})

    # Add to command history
    history_entry = %{
      timestamp: DateTime.utc_now(),
      type: :builtin,
      command: command,
      args: args
    }

    socket = update_in(socket.assigns.command_history, &[history_entry | &1])

    payload = %{
      "session_id" => session_id,
      "type" => "builtin_command",
      "command" => command,
      "args" => args
    }

    send_to_agent(agent_id, "shell:input", payload)

    {:noreply, socket}
  end

  @impl true
  def handle_in("confirm_dangerous", %{"command_id" => command_id}, socket) do
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id

    # Log the confirmation
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

    # Log the cancellation
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
    terminate_session(socket, "user_requested")
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

  @impl true
  def terminate(_reason, socket) do
    if socket.assigns[:session_id] do
      terminate_session(socket, "channel_closed")
    end

    :ok
  end

  # Private functions

  defp get_user_org_id(socket) do
    case socket.assigns[:current_user] do
      %{organization_id: org_id} -> org_id
      user when is_map(user) -> user[:organization_id]
      _ -> nil
    end
  end

  defp has_shell_permission?(nil), do: false

  defp has_shell_permission?(user) do
    # Check RBAC permission or fallback to role-based check
    if safe_rbac_can?(user, :live_response_shell) do
      true
    else
      # Fallback: check user role directly
      role = user.role || user[:role]
      role in [:admin, :analyst, :responder, "admin", "analyst", "responder"]
    end
  end

  defp safe_rbac_can?(user, permission) do
    TamanduaServer.Authorization.RBAC.can?(user, permission)
  rescue
    ArgumentError ->
      false

    UndefinedFunctionError ->
      false
  end

  defp count_user_sessions(user_id) do
    # Count active shell sessions for this user across all channels
    Phoenix.PubSub.list("shell:*")
    |> Enum.count(fn topic ->
      TamanduaServerWeb.Presence.list(topic)
      |> Enum.any?(fn {_session_id, %{metas: metas}} ->
        Enum.any?(metas, &(&1.user_id == user_id))
      end)
    end)
  rescue
    _ -> 0
  end

  defp generate_session_id do
    "shell_" <> Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
  end

  defp record_input(socket, data) do
    if recording_state = socket.assigns[:recording_state] do
      updated_state = SessionRecording.append_event(recording_state, "i", data)
      assign(socket, :recording_state, updated_state)
    else
      socket
    end
  end

  defp record_output(socket, data) do
    if recording_state = socket.assigns[:recording_state] do
      updated_state = SessionRecording.append_event(recording_state, "o", data)
      assign(socket, :recording_state, updated_state)
    else
      socket
    end
  end

  defp record_builtin_result(socket, payload) do
    if recording_state = socket.assigns[:recording_state] do
      output = payload["output"] || Jason.encode!(payload)
      full_output = "\r\n--- Builtin Result ---\r\n" <> output <> "\r\n"
      updated_state = SessionRecording.append_event(recording_state, "o", full_output)
      assign(socket, :recording_state, updated_state)
    else
      socket
    end
  end

  defp terminate_session(socket, reason) do
    agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id

    # Tell agent to terminate
    payload = %{
      "session_id" => session_id,
      "type" => "terminate"
    }

    send_to_agent(agent_id, "shell:input", payload)

    # Log session end
    audit_log(:session_ended, socket, %{reason: reason})

    # Finalize recording with compression and encryption
    finalize_recording(socket)
  end

  defp finalize_recording(socket) do
    if recording_state = socket.assigns[:recording_state] do
      case SessionRecording.finalize(recording_state) do
        {:ok, metadata} ->
          Logger.info(
            "Shell session recording finalized: #{metadata.path} " <>
              "(#{metadata.file_size} bytes, encrypted=#{metadata.encrypted})"
          )

        {:error, reason} ->
          Logger.error("Failed to finalize shell recording: #{inspect(reason)}")
      end
    end
  end

  defp send_to_agent(agent_id, event, payload) do
    case Registry.lookup_agent(agent_id) do
      nil ->
        {:error, "Agent not connected"}

      pid ->
        send(pid, {:push_to_agent, event, payload})
        :ok
    end
  end

  defp schedule_timeout_check do
    # Check every minute
    Process.send_after(self(), :check_timeout, 60_000)
  end

  defp audit_log(action, socket, extra \\ %{}) do
    user = socket.assigns.current_user
    agent = socket.assigns.agent
    session_id = socket.assigns.session_id

    log_entry = %{
      action: action,
      session_id: session_id,
      user_id: user.id,
      user_email: user.email,
      agent_id: agent.id,
      hostname: agent.hostname,
      timestamp: DateTime.utc_now(),
      extra: extra
    }

    # Log to structured logger
    Logger.info("Shell Audit: #{inspect(log_entry)}")

    # Store in audit log table
    TamanduaServer.AuditLog.log(%{
      action: "shell:#{action}",
      action_type: "shell",
      user_id: user.id,
      user_email: user.email,
      resource_type: "shell_session",
      resource_id: session_id,
      severity: :info,
      details: log_entry,
      ip_address: socket.assigns[:client_ip],
      user_agent: socket.assigns[:user_agent],
      organization_id: user[:organization_id]
    })
  rescue
    e ->
      Logger.error("Failed to write audit log: #{inspect(e)}")
  end
end
