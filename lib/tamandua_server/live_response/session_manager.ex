defmodule TamanduaServer.LiveResponse.SessionManager do
  @moduledoc """
  GenServer for managing live response sessions.

  Provides session lifecycle management including:
  - Session creation, authorization, connection, disconnection, and timeout
  - Per-session state tracking in ETS (session_id, agent_id, user_id, timestamps, commands)
  - Configurable idle session timeout (default 30 minutes)
  - Concurrent session limits per agent and per user
  - Full audit logging of all commands and responses
  - Session recording (command/response pairs for replay)

  ## Architecture

  Session state is stored in two ETS tables:
  - `:live_response_sessions` - Main session state (keyed by session_id)
  - `:live_response_audit` - Audit log entries (keyed by entry_id)

  The GenServer process owns the ETS tables and runs periodic cleanup
  for expired sessions.

  ## Configuration

      config :tamandua_server, TamanduaServer.LiveResponse.SessionManager,
        session_timeout_minutes: 30,
        max_sessions_per_agent: 3,
        max_sessions_per_user: 5,
        cleanup_interval_ms: 60_000

  ## Session States

  - `:active`   - Session is live and accepting commands
  - `:idle`     - Session is connected but no recent activity
  - `:closed`   - Session has been explicitly closed by user or admin
  - `:expired`  - Session was closed due to inactivity timeout
  - `:error`    - Session encountered an unrecoverable error
  """

  use GenServer
  require Logger

  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Registry, as: AgentRegistry

  @sessions_table :live_response_sessions
  @audit_table :live_response_audit

  # Defaults
  @default_session_timeout_minutes 30
  @default_max_sessions_per_agent 3
  @default_max_sessions_per_user 5
  @default_cleanup_interval_ms 60_000

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Create a new live response session with tenant validation.

  ## Parameters
  - `agent_id` - Target agent ID
  - `user` - User struct with `id` and `organization_id` fields (required for tenant validation)
  - `opts` - Optional keyword list:
    - `:case_id` - Associated case investigation ID
    - `:alert_id` - Associated alert ID
    - `:notes` - Freeform notes about the session purpose
    - `:timeout_minutes` - Custom timeout for this session

  ## Returns
  - `{:ok, session}` on success
  - `{:error, :unauthorized}` if agent does not belong to user's organization
  - `{:error, reason}` on other failures
  """
  @spec create_session(String.t(), map(), keyword()) ::
          {:ok, map()} | {:error, atom()}
  def create_session(agent_id, user, opts \\ [])

  def create_session(agent_id, %{id: user_id, organization_id: org_id} = _user, opts)
      when is_binary(org_id) or is_integer(org_id) do
    # Validate agent belongs to user's organization before creating session
    case Agents.get_agent_for_org(org_id, agent_id) do
      {:ok, _agent} ->
        GenServer.call(__MODULE__, {:create_session, agent_id, user_id, org_id, opts})

      {:error, :not_found} ->
        {:error, :unauthorized}
    end
  end

  # Fallback for users without organization_id - reject for security
  def create_session(_agent_id, %{id: _user_id}, _opts) do
    {:error, :user_no_organization}
  end

  @doc """
  Legacy create_session that accepts user_id directly.

  DEPRECATED: This function bypasses tenant validation.
  Only use for system-level operations or when agent has been pre-validated.
  Prefer `create_session/3` with full user struct for tenant safety.
  """
  @spec create_session_unsafe(String.t(), String.t() | integer(), keyword()) ::
          {:ok, map()} | {:error, atom()}
  def create_session_unsafe(agent_id, user_id, opts \\ []) do
    GenServer.call(__MODULE__, {:create_session, agent_id, user_id, nil, opts})
  end

  @doc """
  Authorize a session. Verifies the user has the required permissions
  and the agent is online and available.

  Called internally during session creation and can also be called
  externally to re-verify authorization.
  """
  @spec authorize_session(String.t(), String.t() | integer()) ::
          :ok | {:error, atom()}
  def authorize_session(agent_id, user_id) do
    GenServer.call(__MODULE__, {:authorize_session, agent_id, user_id})
  end

  @doc """
  Mark a session as connected. Called when the WebSocket channel
  successfully starts on the agent side.
  """
  @spec connect_session(String.t()) :: :ok | {:error, atom()}
  def connect_session(session_id) do
    GenServer.call(__MODULE__, {:connect_session, session_id})
  end

  @doc """
  Disconnect a session. Does NOT close it -- the session remains in
  a disconnected state and can be reconnected if within the timeout window.
  """
  @spec disconnect_session(String.t(), String.t()) :: :ok | {:error, atom()}
  def disconnect_session(session_id, reason \\ "user_disconnected") do
    GenServer.call(__MODULE__, {:disconnect_session, session_id, reason})
  end

  @doc """
  Close (end) a session permanently.

  ## Parameters
  - `session_id` - The session to close
  - `reason` - Why the session is being closed (e.g. "user_requested", "admin_terminated")
  """
  @spec close_session(String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def close_session(session_id, reason \\ "user_requested") do
    GenServer.call(__MODULE__, {:close_session, session_id, reason})
  end

  @doc """
  Get session details by ID.
  """
  @spec get_session(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_session(session_id) do
    case ets_lookup(@sessions_table, session_id) do
      {:ok, session} -> {:ok, session}
      :error -> {:error, :not_found}
    end
  end

  @doc "Get a session after enforcing tenant and operator ownership."
  @spec get_session_for_access(String.t(), term(), term(), boolean()) ::
          {:ok, map()} | {:error, :not_found | :unauthorized}
  def get_session_for_access(session_id, organization_id, requester_id, supervise? \\ false) do
    with {:ok, session} <- get_session(session_id),
         :ok <-
           authorize_session_access(
             session,
             organization_id,
             requester_id,
             supervise?
           ) do
      {:ok, session}
    end
  end

  @doc """
  List all active sessions. Optionally filter by agent_id or user_id.

  ## Options
  - `:agent_id` - Filter by agent
  - `:user_id` - Filter by user
  - `:status` - Filter by status (default: all active statuses)
  """
  @spec list_sessions(keyword()) :: [map()]
  def list_sessions(opts \\ []) do
    agent_id = Keyword.get(opts, :agent_id)
    user_id = Keyword.get(opts, :user_id)
    status_filter = Keyword.get(opts, :status)
    organization_id = Keyword.get(opts, :organization_id)

    all_sessions()
    |> maybe_filter_by(:organization_id, organization_id)
    |> maybe_filter_by(:agent_id, agent_id)
    |> maybe_filter_by(:user_id, user_id)
    |> maybe_filter_by(:status, status_filter)
    |> Enum.sort_by(& &1.started_at, {:desc, DateTime})
  end

  @doc """
  List all active (non-closed, non-expired) sessions.
  """
  @spec list_active_sessions() :: [map()]
  def list_active_sessions do
    all_sessions()
    |> Enum.filter(fn s -> s.status in [:active, :idle] end)
    |> Enum.sort_by(& &1.started_at, {:desc, DateTime})
  end

  @doc """
  Record a command execution in a session.

  Stores the command, arguments, and result in the session's command history
  and writes an audit log entry.

  ## Parameters
  - `session_id` - Session ID
  - `command` - Command type string
  - `args` - Command arguments map
  - `result` - Result map with `:status`, `:output`, `:exit_code`, `:duration_ms`
  """
  @spec record_command(String.t(), String.t(), map(), map()) :: :ok | {:error, atom()}
  def record_command(session_id, command, args, result) do
    GenServer.cast(__MODULE__, {:record_command, session_id, command, args, result})
  end

  @doc """
  Touch a session to update its last activity timestamp.
  Prevents idle timeout for active sessions.
  """
  @spec touch_session(String.t()) :: :ok | {:error, :not_found}
  def touch_session(session_id) do
    GenServer.cast(__MODULE__, {:touch_session, session_id})
  end

  @doc """
  Get the full command history for a session.
  """
  @spec get_session_history(String.t()) :: {:ok, [map()]} | {:error, :not_found}
  def get_session_history(session_id) do
    case get_session(session_id) do
      {:ok, session} -> {:ok, session.command_history}
      error -> error
    end
  end

  @doc """
  Get the session recording data (command/response pairs for replay).
  """
  @spec get_session_recording(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_session_recording(session_id) do
    case get_session(session_id) do
      {:ok, session} ->
        recording = %{
          session_id: session.session_id,
          agent_id: session.agent_id,
          user_id: session.user_id,
          started_at: session.started_at,
          ended_at: session.ended_at,
          status: session.status,
          commands_executed: session.commands_executed,
          command_history: session.command_history,
          duration_seconds: calculate_duration(session)
        }

        {:ok, recording}

      error ->
        error
    end
  end

  @doc """
  Get all audit log entries for a session.
  """
  @spec get_audit_entries(String.t()) :: [map()]
  def get_audit_entries(session_id) do
    try do
      @audit_table
      |> :ets.tab2list()
      |> Enum.map(fn {_id, entry} -> entry end)
      |> Enum.filter(&(&1.session_id == session_id))
      |> Enum.sort_by(& &1.timestamp, {:asc, DateTime})
    rescue
      ArgumentError -> []
    end
  end

  @doc """
  Get aggregate statistics about live response sessions.
  """
  @spec stats() :: map()
  def stats do
    sessions = all_sessions()
    active = Enum.count(sessions, &(&1.status in [:active, :idle]))
    closed = Enum.count(sessions, &(&1.status == :closed))
    expired = Enum.count(sessions, &(&1.status == :expired))

    total_commands =
      sessions
      |> Enum.map(& &1.commands_executed)
      |> Enum.sum()

    %{
      total_sessions: length(sessions),
      active_sessions: active,
      closed_sessions: closed,
      expired_sessions: expired,
      total_commands_executed: total_commands,
      unique_agents: sessions |> Enum.map(& &1.agent_id) |> Enum.uniq() |> length(),
      unique_users: sessions |> Enum.map(& &1.user_id) |> Enum.uniq() |> length()
    }
  end

  @doc """
  Count active sessions for a specific agent.
  """
  @spec count_agent_sessions(String.t()) :: non_neg_integer()
  def count_agent_sessions(agent_id) do
    all_sessions()
    |> Enum.count(fn s ->
      s.agent_id == agent_id and s.status in [:active, :idle]
    end)
  end

  @doc """
  Count active sessions for a specific user.
  """
  @spec count_user_sessions(String.t() | integer()) :: non_neg_integer()
  def count_user_sessions(user_id) do
    user_id = to_string(user_id)

    all_sessions()
    |> Enum.count(fn s ->
      to_string(s.user_id) == user_id and s.status in [:active, :idle]
    end)
  end

  @doc """
  Force-expire all sessions for an agent (e.g. when agent goes offline).
  """
  @spec expire_agent_sessions(String.t(), String.t()) :: :ok
  def expire_agent_sessions(agent_id, reason \\ "agent_offline") do
    GenServer.cast(__MODULE__, {:expire_agent_sessions, agent_id, reason})
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables if they don't already exist
    create_ets_table(@sessions_table)
    create_ets_table(@audit_table)

    # Schedule periodic cleanup
    schedule_cleanup()

    # Subscribe to agent status changes to auto-expire sessions
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agents:status")

    Logger.info("[SessionManager] Started with timeout=#{session_timeout_minutes()}m")

    {:ok,
     %{
       started_at: DateTime.utc_now()
     }}
  end

  @impl true
  def handle_call({:create_session, agent_id, user_id, organization_id, opts}, _from, state) do
    result = do_create_session(agent_id, user_id, organization_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:authorize_session, agent_id, user_id}, _from, state) do
    result = do_authorize(agent_id, user_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:connect_session, session_id}, _from, state) do
    result =
      with {:ok, session} <- get_session(session_id) do
        if session.status in [:active, :idle] do
          now = DateTime.utc_now()

          updated =
            session
            |> Map.put(:last_activity, now)
            |> Map.put(:connected_at, now)
            |> Map.put(:status, :active)

          :ets.insert(@sessions_table, {session_id, updated})
          write_audit_entry(session_id, session.agent_id, session.user_id, "session_connected", %{})
          broadcast_session_event(session_id, :connected)
          :ok
        else
          {:error, :session_not_active}
        end
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:disconnect_session, session_id, reason}, _from, state) do
    result =
      with {:ok, session} <- get_session(session_id) do
        if session.status in [:active, :idle] do
          updated = Map.put(session, :status, :idle)
          :ets.insert(@sessions_table, {session_id, updated})

          write_audit_entry(session_id, session.agent_id, session.user_id, "session_disconnected", %{
            reason: reason
          })

          broadcast_session_event(session_id, :disconnected)
          :ok
        else
          {:error, :session_not_active}
        end
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:close_session, session_id, reason}, _from, state) do
    result = do_close_session(session_id, reason)
    {:reply, result, state}
  end

  @impl true
  def handle_cast({:record_command, session_id, command, args, result}, state) do
    case get_session(session_id) do
      {:ok, session} ->
        now = DateTime.utc_now()

        command_entry = %{
          id: generate_id("cmd"),
          command: command,
          args: args,
          status: Map.get(result, :status, "unknown"),
          output: Map.get(result, :output),
          exit_code: Map.get(result, :exit_code),
          duration_ms: Map.get(result, :duration_ms, 0),
          executed_at: now
        }

        history = session.command_history ++ [command_entry]

        updated =
          session
          |> Map.put(:command_history, history)
          |> Map.put(:commands_executed, session.commands_executed + 1)
          |> Map.put(:last_activity, now)
          |> Map.put(:status, :active)

        :ets.insert(@sessions_table, {session_id, updated})

        # Write audit entry
        write_audit_entry(
          session_id,
          session.agent_id,
          session.user_id,
          "command_executed",
          %{
            command: command,
            args: args,
            status: command_entry.status,
            exit_code: command_entry.exit_code,
            duration_ms: command_entry.duration_ms
          }
        )

        # Broadcast for real-time monitoring
        broadcast_session_event(session_id, :command_executed, %{
          command: command,
          status: command_entry.status
        })

      {:error, _} ->
        Logger.warning("[SessionManager] record_command for unknown session #{session_id}")
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast({:touch_session, session_id}, state) do
    case ets_lookup(@sessions_table, session_id) do
      {:ok, session} when session.status in [:active, :idle] ->
        updated =
          session
          |> Map.put(:last_activity, DateTime.utc_now())
          |> Map.put(:status, :active)

        :ets.insert(@sessions_table, {session_id, updated})

      _ ->
        :ok
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast({:expire_agent_sessions, agent_id, reason}, state) do
    all_sessions()
    |> Enum.filter(fn s ->
      s.agent_id == agent_id and s.status in [:active, :idle]
    end)
    |> Enum.each(fn session ->
      do_close_session(session.session_id, reason)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_expired, state) do
    cleanup_expired_sessions()
    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info({:agent_status_changed, agent_id, :offline}, state) do
    # When an agent goes offline, expire all its sessions
    expire_agent_sessions(agent_id, "agent_went_offline")
    {:noreply, state}
  end

  @impl true
  def handle_info({:agent_status_changed, _agent_id, _status}, state) do
    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.debug("[SessionManager] Unhandled message: #{inspect(msg)}")
    {:noreply, state}
  end

  # ============================================================================
  # Private Implementation
  # ============================================================================

  defp do_create_session(agent_id, user_id, organization_id, opts) do
    user_id_str = to_string(user_id)

    with :ok <- do_authorize(agent_id, user_id_str),
         :ok <- check_agent_session_limit(agent_id),
         :ok <- check_user_session_limit(user_id_str) do
      session_id = generate_id("lr_session")
      now = DateTime.utc_now()

      timeout_min =
        Keyword.get(opts, :timeout_minutes, session_timeout_minutes())

      session = %{
        session_id: session_id,
        agent_id: agent_id,
        user_id: user_id_str,
        organization_id: organization_id,
        case_id: Keyword.get(opts, :case_id),
        alert_id: Keyword.get(opts, :alert_id),
        notes: Keyword.get(opts, :notes),
        status: :active,
        started_at: now,
        connected_at: nil,
        ended_at: nil,
        last_activity: now,
        timeout_minutes: timeout_min,
        commands_executed: 0,
        command_history: []
      }

      :ets.insert(@sessions_table, {session_id, session})

      # Write audit entry
      write_audit_entry(session_id, agent_id, user_id_str, "session_created", %{
        case_id: session.case_id,
        alert_id: session.alert_id,
        notes: session.notes,
        timeout_minutes: timeout_min
      })

      broadcast_session_event(session_id, :created)

      Logger.info(
        "[SessionManager] Session #{session_id} created: " <>
          "agent=#{agent_id}, user=#{user_id_str}"
      )

      {:ok, session}
    end
  end

  defp do_authorize(agent_id, _user_id) do
    # Verify agent exists and is online
    case AgentRegistry.get(agent_id) do
      {:ok, agent_entry} ->
        if agent_entry.status in [:online, :isolated] do
          :ok
        else
          {:error, :agent_offline}
        end

      {:error, :not_found} ->
        # Fall back to database lookup
        case TamanduaServer.Agents.get_agent(agent_id) do
          {:ok, _agent} -> {:error, :agent_offline}
          {:error, _} -> {:error, :agent_not_found}
        end
    end
  end

  defp authorize_session_access(session, organization_id, requester_id, supervise?) do
    same_tenant? =
      not is_nil(organization_id) and
        same_identifier?(session[:organization_id], organization_id)

    same_operator? =
      not is_nil(requester_id) and same_identifier?(session.user_id, requester_id)

    if same_tenant? and (same_operator? or supervise?) do
      :ok
    else
      {:error, :unauthorized}
    end
  end

  defp same_identifier?(left, right), do: to_string(left) == to_string(right)

  defp check_agent_session_limit(agent_id) do
    max = max_sessions_per_agent()

    if count_agent_sessions(agent_id) >= max do
      {:error, :agent_session_limit}
    else
      :ok
    end
  end

  defp check_user_session_limit(user_id) do
    max = max_sessions_per_user()

    if count_user_sessions(user_id) >= max do
      {:error, :user_session_limit}
    else
      :ok
    end
  end

  defp do_close_session(session_id, reason) do
    case get_session(session_id) do
      {:ok, session} ->
        now = DateTime.utc_now()

        status =
          case reason do
            "timeout" -> :expired
            "idle_timeout" -> :expired
            _ -> :closed
          end

        updated =
          session
          |> Map.put(:status, status)
          |> Map.put(:ended_at, now)

        :ets.insert(@sessions_table, {session_id, updated})

        write_audit_entry(session_id, session.agent_id, session.user_id, "session_closed", %{
          reason: reason,
          commands_executed: session.commands_executed,
          duration_seconds: calculate_duration(session)
        })

        broadcast_session_event(session_id, :closed, %{reason: reason})

        Logger.info(
          "[SessionManager] Session #{session_id} closed: reason=#{reason}, " <>
            "commands=#{session.commands_executed}"
        )

        {:ok, updated}

      {:error, :not_found} ->
        {:error, :session_not_found}
    end
  end

  defp cleanup_expired_sessions do
    now = DateTime.utc_now()

    expired_count =
      all_sessions()
      |> Enum.filter(fn s ->
        s.status in [:active, :idle] and session_timed_out?(s, now)
      end)
      |> Enum.reduce(0, fn session, count ->
        do_close_session(session.session_id, "idle_timeout")
        count + 1
      end)

    if expired_count > 0 do
      Logger.info("[SessionManager] Expired #{expired_count} idle sessions")
    end
  end

  defp session_timed_out?(session, now) do
    timeout_ms = (session.timeout_minutes || session_timeout_minutes()) * 60 * 1000
    last = session.last_activity || session.started_at
    diff_ms = DateTime.diff(now, last, :millisecond)
    diff_ms >= timeout_ms
  end

  # ============================================================================
  # Audit Logging
  # ============================================================================

  defp write_audit_entry(session_id, agent_id, user_id, action, details) do
    entry_id = generate_id("audit")

    entry = %{
      id: entry_id,
      session_id: session_id,
      agent_id: agent_id,
      user_id: user_id,
      action: action,
      details: details,
      timestamp: DateTime.utc_now()
    }

    :ets.insert(@audit_table, {entry_id, entry})

    # Also publish to PubSub for real-time monitoring
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "live_response:audit",
      {:audit_entry, entry}
    )

    # Write to the persistent audit log as well
    try do
      TamanduaServer.AuditLog.log(%{
        action: "live_response:#{action}",
        action_type: "live_response",
        user_id: user_id,
        resource_type: "live_response_session",
        resource_id: session_id,
        severity: severity_for(action),
        details: Map.merge(details, %{agent_id: agent_id, session_id: session_id})
      })
    rescue
      e ->
        Logger.warning("[SessionManager] Failed to write persistent audit: #{inspect(e)}")
    end
  end

  defp severity_for("command_executed"), do: :info
  defp severity_for("session_created"), do: :info
  defp severity_for("session_connected"), do: :info
  defp severity_for("session_disconnected"), do: :warning
  defp severity_for("session_closed"), do: :info
  defp severity_for(_), do: :info

  # ============================================================================
  # PubSub Broadcasting
  # ============================================================================

  defp broadcast_session_event(session_id, event, extra \\ %{}) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "live_response:sessions",
      {:session_event, session_id, event, extra}
    )
  end

  # ============================================================================
  # ETS Helpers
  # ============================================================================

  defp create_ets_table(name) do
    case :ets.whereis(name) do
      :undefined ->
        :ets.new(name, [:named_table, :set, :public, read_concurrency: true])

      _ref ->
        :ok
    end
  end

  defp ets_lookup(table, key) do
    case :ets.lookup(table, key) do
      [{^key, value}] -> {:ok, value}
      [] -> :error
    end
  rescue
    ArgumentError -> :error
  end

  defp all_sessions do
    try do
      @sessions_table
      |> :ets.tab2list()
      |> Enum.map(fn {_id, session} -> session end)
    rescue
      ArgumentError -> []
    end
  end

  # ============================================================================
  # Filtering Helpers
  # ============================================================================

  defp maybe_filter_by(sessions, _field, nil), do: sessions

  defp maybe_filter_by(sessions, field, value) do
    value_str = to_string(value)

    Enum.filter(sessions, fn s ->
      to_string(Map.get(s, field)) == value_str
    end)
  end

  # ============================================================================
  # Utility Functions
  # ============================================================================

  defp generate_id(prefix) do
    random = Base.encode16(:crypto.strong_rand_bytes(12), case: :lower)
    "#{prefix}_#{random}"
  end

  defp calculate_duration(session) do
    ended = session.ended_at || DateTime.utc_now()
    DateTime.diff(ended, session.started_at, :second)
  end

  defp schedule_cleanup do
    interval = cleanup_interval_ms()
    Process.send_after(self(), :cleanup_expired, interval)
  end

  # ============================================================================
  # Configuration Helpers
  # ============================================================================

  defp config do
    Application.get_env(:tamandua_server, __MODULE__, [])
  end

  defp session_timeout_minutes do
    Keyword.get(config(), :session_timeout_minutes, @default_session_timeout_minutes)
  end

  defp max_sessions_per_agent do
    Keyword.get(config(), :max_sessions_per_agent, @default_max_sessions_per_agent)
  end

  defp max_sessions_per_user do
    Keyword.get(config(), :max_sessions_per_user, @default_max_sessions_per_user)
  end

  defp cleanup_interval_ms do
    Keyword.get(config(), :cleanup_interval_ms, @default_cleanup_interval_ms)
  end
end
