defmodule TamanduaServer.RemoteShell.SessionManager do
  @moduledoc """
  Manages remote shell sessions including:
  - Session creation and lifecycle
  - RBAC enforcement
  - Session timeout management
  - Multiple concurrent sessions per agent
  - Recording session activity
  """

  use GenServer
  require Logger

  alias TamanduaServer.{Repo, Accounts, Agents}
  alias TamanduaServer.ShellSessions
  alias TamanduaServer.RemoteShell.AuditLogger

  @session_check_interval :timer.minutes(1)
  @recording_dir "priv/shell_recordings"

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Creates a new shell session.

  Options:
  - user_id: User requesting the shell
  - agent_id: Target agent
  - client_ip: Client IP address
  - user_agent: Client user agent
  - config: Shell configuration (cols, rows, etc.)
  """
  def create_session(opts) do
    GenServer.call(__MODULE__, {:create_session, opts}, 30_000)
  end

  @doc """
  Gets an active session by session_id.
  """
  def get_session(session_id) do
    GenServer.call(__MODULE__, {:get_session, session_id})
  end

  @doc """
  Terminates a session.
  """
  def terminate_session(session_id, reason \\ "user_requested") do
    GenServer.call(__MODULE__, {:terminate_session, session_id, reason})
  end

  @doc """
  Updates session statistics.
  """
  def update_stats(session_id, stats) do
    GenServer.cast(__MODULE__, {:update_stats, session_id, stats})
  end

  @doc """
  Lists all active sessions.
  """
  def list_active_sessions do
    GenServer.call(__MODULE__, :list_active_sessions)
  end

  @doc """
  Lists sessions for a specific user.
  """
  def list_user_sessions(user_id) do
    GenServer.call(__MODULE__, {:list_user_sessions, user_id})
  end

  @doc """
  Lists sessions for a specific agent.
  """
  def list_agent_sessions(agent_id) do
    GenServer.call(__MODULE__, {:list_agent_sessions, agent_id})
  end

  @doc """
  Checks if user can open a new shell session (RBAC + quota check).
  """
  def can_create_session?(user_id, agent_id) do
    GenServer.call(__MODULE__, {:can_create_session, user_id, agent_id})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Ensure recording directory exists
    File.mkdir_p!(@recording_dir)

    # Schedule periodic cleanup
    schedule_cleanup()

    {:ok, %{
      sessions: %{},
      user_sessions: %{},
      agent_sessions: %{}
    }}
  end

  @impl true
  def handle_call({:create_session, opts}, _from, state) do
    user_id = Keyword.fetch!(opts, :user_id)
    agent_id = Keyword.fetch!(opts, :agent_id)
    client_ip = Keyword.get(opts, :client_ip)
    user_agent = Keyword.get(opts, :user_agent)
    config = Keyword.get(opts, :config, %{})

    case validate_and_create_session(user_id, agent_id, client_ip, user_agent, config, state) do
      {:ok, session, new_state} ->
        {:reply, {:ok, session}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_session, session_id}, _from, state) do
    session = Map.get(state.sessions, session_id)
    {:reply, session, state}
  end

  @impl true
  def handle_call({:terminate_session, session_id, reason}, _from, state) do
    case Map.get(state.sessions, session_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      session ->
        # End session in database
        ShellSessions.end_session(session.session_id, reason)

        # Broadcast termination
        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "shell:#{session_id}",
          {:shell_terminated, reason}
        )

        # Update state
        new_state = remove_session_from_state(session, state)

        {:reply, :ok, new_state}
    end
  end

  @impl true
  def handle_call(:list_active_sessions, _from, state) do
    sessions = Map.values(state.sessions)
    {:reply, sessions, state}
  end

  @impl true
  def handle_call({:list_user_sessions, user_id}, _from, state) do
    session_ids = Map.get(state.user_sessions, user_id, [])
    sessions = Enum.map(session_ids, &Map.get(state.sessions, &1))
              |> Enum.reject(&is_nil/1)
    {:reply, sessions, state}
  end

  @impl true
  def handle_call({:list_agent_sessions, agent_id}, _from, state) do
    session_ids = Map.get(state.agent_sessions, agent_id, [])
    sessions = Enum.map(session_ids, &Map.get(state.sessions, &1))
              |> Enum.reject(&is_nil/1)
    {:reply, sessions, state}
  end

  @impl true
  def handle_call({:can_create_session, user_id, agent_id}, _from, state) do
    result = check_can_create_session(user_id, agent_id, state)
    {:reply, result, state}
  end

  @impl true
  def handle_cast({:update_stats, session_id, stats}, state) do
    case Map.get(state.sessions, session_id) do
      nil ->
        {:noreply, state}

      session ->
        # Update database
        case ShellSessions.get_session_by_session_id(session_id) do
          nil ->
            {:noreply, state}

          db_session ->
            ShellSessions.update_session(db_session, %{
              command_count: Map.get(stats, :command_count, db_session.command_count),
              bytes_sent: Map.get(stats, :bytes_sent, db_session.bytes_sent),
              bytes_received: Map.get(stats, :bytes_received, db_session.bytes_received)
            })

            {:noreply, state}
        end
    end
  end

  @impl true
  def handle_info(:cleanup_sessions, state) do
    new_state = cleanup_expired_sessions(state)
    schedule_cleanup()
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp validate_and_create_session(user_id, agent_id, client_ip, user_agent, config, state) do
    with {:ok, user} <- fetch_user(user_id),
         {:ok, agent} <- fetch_agent(agent_id),
         :ok <- check_permissions(user),
         :ok <- check_quota(user, state),
         {:ok, session} <- create_session_record(user, agent, client_ip, user_agent, config) do

      # Initialize recording file
      recording_path = init_recording(session)

      # Add to state
      new_state = add_session_to_state(session, recording_path, state)

      # Broadcast session created
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agent:#{agent_id}:shells",
        {:shell_created, session}
      )

      Logger.info("Shell session created: #{session.session_id} (user: #{user.email}, agent: #{agent.hostname})")

      {:ok, session, new_state}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp fetch_user(user_id) do
    case Repo.get(Accounts.User, user_id) do
      nil -> {:error, :user_not_found}
      user -> {:ok, Repo.preload(user, :roles)}
    end
  end

  defp fetch_agent(agent_id) do
    case Repo.get(Agents.Agent, agent_id) do
      nil -> {:error, :agent_not_found}
      agent -> {:ok, agent}
    end
  end

  defp check_permissions(user) do
    # Check if user has shell permission via RBAC
    has_permission = Accounts.has_permission?(user, "shell:open")

    if has_permission do
      :ok
    else
      {:error, :permission_denied}
    end
  end

  defp check_quota(user, state) do
    # Get shell permissions for user's role
    permissions = get_shell_permissions(user)
    max_sessions = permissions[:max_concurrent_sessions] || 5

    # Count active sessions for this user
    user_session_count = length(Map.get(state.user_sessions, user.id, []))

    if user_session_count < max_sessions do
      :ok
    else
      {:error, :quota_exceeded}
    end
  end

  defp get_shell_permissions(user) do
    # Get shell permissions from first role (simplified)
    # In production, merge permissions from all roles
    case user.roles do
      [] -> %{max_concurrent_sessions: 1, session_timeout_minutes: 15}
      [role | _] ->
        # Query shell_permissions table
        %{max_concurrent_sessions: 5, session_timeout_minutes: 30}
    end
  end

  defp create_session_record(user, agent, client_ip, user_agent, config) do
    session_id = "shell_#{Ecto.UUID.generate()}"

    attrs = %{
      session_id: session_id,
      user_id: user.id,
      agent_id: agent.id,
      agent_hostname: agent.hostname,
      agent_os: agent.os_type,
      started_at: DateTime.utc_now(),
      client_ip: client_ip,
      user_agent: user_agent,
      read_only: Map.get(config, :read_only, false)
    }

    case ShellSessions.create_session(attrs) do
      {:ok, session} -> {:ok, session}
      {:error, changeset} ->
        Logger.error("Failed to create shell session: #{inspect(changeset)}")
        {:error, :session_creation_failed}
    end
  end

  defp init_recording(session) do
    # Create recording file in asciicast v2 format
    timestamp = DateTime.to_unix(session.started_at)
    filename = "#{String.replace_prefix(session.session_id, "shell_", "")}_#{session.agent_id}_#{session.user_id}.cast"
    path = Path.join(@recording_dir, filename)

    # Write asciicast v2 header
    header = %{
      version: 2,
      width: 120,
      height: 40,
      timestamp: timestamp,
      env: %{
        SHELL: "/bin/sh",
        TERM: "xterm-256color"
      }
    }

    File.write!(path, Jason.encode!(header) <> "\n")

    # Update session with recording path
    if db_session = ShellSessions.get_session_by_session_id(session.session_id) do
      ShellSessions.update_session(db_session, %{
        recording_path: path,
        has_recording: true
      })
    end

    path
  end

  defp add_session_to_state(session, recording_path, state) do
    session_info = %{
      id: session.id,
      session_id: session.session_id,
      user_id: session.user_id,
      agent_id: session.agent_id,
      started_at: session.started_at,
      recording_path: recording_path
    }

    %{state |
      sessions: Map.put(state.sessions, session.session_id, session_info),
      user_sessions: Map.update(state.user_sessions, session.user_id, [session.session_id], fn ids ->
        [session.session_id | ids]
      end),
      agent_sessions: Map.update(state.agent_sessions, session.agent_id, [session.session_id], fn ids ->
        [session.session_id | ids]
      end)
    }
  end

  defp remove_session_from_state(session, state) do
    %{state |
      sessions: Map.delete(state.sessions, session.session_id),
      user_sessions: Map.update(state.user_sessions, session.user_id, [], fn ids ->
        List.delete(ids, session.session_id)
      end),
      agent_sessions: Map.update(state.agent_sessions, session.agent_id, [], fn ids ->
        List.delete(ids, session.session_id)
      end)
    }
  end

  defp check_can_create_session(user_id, agent_id, state) do
    with {:ok, user} <- fetch_user(user_id),
         {:ok, _agent} <- fetch_agent(agent_id),
         :ok <- check_permissions(user),
         :ok <- check_quota(user, state) do
      {:ok, true}
    else
      {:error, reason} -> {:ok, false, reason}
    end
  end

  defp cleanup_expired_sessions(state) do
    # Find sessions that have exceeded timeout
    now = DateTime.utc_now()

    expired = Enum.filter(state.sessions, fn {_session_id, session_info} ->
      timeout_minutes = 30 # TODO: Get from permissions
      timeout_seconds = timeout_minutes * 60

      DateTime.diff(now, session_info.started_at, :second) > timeout_seconds
    end)

    # Terminate expired sessions
    Enum.each(expired, fn {session_id, _} ->
      terminate_session(session_id, "timeout")
    end)

    state
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup_sessions, @session_check_interval)
  end
end
