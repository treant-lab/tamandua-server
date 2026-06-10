defmodule TamanduaServer.LiveResponse.AuditLogger do
  @moduledoc """
  Dedicated audit logger for live response operations.

  Logs every command execution with comprehensive metadata:
  - session_id, user_id, agent_id
  - command type and arguments
  - timestamp (UTC)
  - result status and duration

  ## Storage

  Audit entries are stored in two places:
  1. ETS table (`:live_response_audit`) - Fast, in-memory access for active sessions
  2. Database via `TamanduaServer.AuditLog` - Persistent, compliance-grade storage

  ## Real-time Monitoring

  All audit events are broadcast via Phoenix PubSub on the topic
  `"live_response:audit"`, allowing real-time monitoring of active sessions
  by SOC supervisors.

  ## Configuration

      config :tamandua_server, TamanduaServer.LiveResponse.AuditLogger,
        persist_to_database: true,
        broadcast_events: true
  """

  require Logger

  @audit_table :live_response_audit

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Log a command execution.

  ## Parameters
  - `session_id` - Live response session ID
  - `user_id` - ID of the user who executed the command
  - `agent_id` - Target agent ID
  - `command` - Command type string
  - `args` - Command arguments map
  - `result` - Execution result map with `:status`, `:exit_code`, `:duration_ms`
  """
  @spec log_command(String.t(), String.t() | integer(), String.t(), String.t(), map(), map()) ::
          :ok
  def log_command(session_id, user_id, agent_id, command, args, result) do
    entry = build_entry(
      session_id,
      user_id,
      agent_id,
      "command_executed",
      %{
        command: command,
        args: sanitize_args(args),
        status: Map.get(result, :status, "unknown"),
        exit_code: Map.get(result, :exit_code),
        duration_ms: Map.get(result, :duration_ms, 0),
        output_size: estimate_output_size(Map.get(result, :output))
      }
    )

    store_entry(entry)
    maybe_broadcast(entry)
    maybe_persist(entry)

    :ok
  end

  @doc """
  Log a session lifecycle event (create, connect, disconnect, close, timeout).

  ## Parameters
  - `session_id` - Live response session ID
  - `user_id` - User ID associated with the session
  - `agent_id` - Target agent ID
  - `event` - Event type string (e.g. "session_created", "session_closed")
  - `details` - Additional details map
  """
  @spec log_session_event(String.t(), String.t() | integer(), String.t(), String.t(), map()) ::
          :ok
  def log_session_event(session_id, user_id, agent_id, event, details \\ %{}) do
    entry = build_entry(session_id, user_id, agent_id, event, details)

    store_entry(entry)
    maybe_broadcast(entry)
    maybe_persist(entry)

    :ok
  end

  @doc """
  Log a security-relevant event (blocked command, authorization failure, etc).
  """
  @spec log_security_event(String.t(), String.t() | integer(), String.t(), String.t(), map()) ::
          :ok
  def log_security_event(session_id, user_id, agent_id, event, details \\ %{}) do
    entry =
      build_entry(session_id, user_id, agent_id, event, details)
      |> Map.put(:severity, :warning)

    store_entry(entry)
    maybe_broadcast(entry)
    maybe_persist(entry)

    Logger.warning(
      "[LiveResponse Audit] Security event: #{event} " <>
        "session=#{session_id} user=#{user_id} agent=#{agent_id} " <>
        "details=#{inspect(details)}"
    )

    :ok
  end

  @doc """
  Query audit log entries for a specific session.

  Returns entries sorted by timestamp ascending.
  """
  @spec query_session(String.t()) :: [map()]
  def query_session(session_id) do
    query_entries(fn entry -> entry.session_id == session_id end)
  end

  @doc """
  Query audit log entries for a specific user.
  """
  @spec query_user(String.t() | integer()) :: [map()]
  def query_user(user_id) do
    user_id_str = to_string(user_id)
    query_entries(fn entry -> to_string(entry.user_id) == user_id_str end)
  end

  @doc """
  Query audit log entries for a specific agent.
  """
  @spec query_agent(String.t()) :: [map()]
  def query_agent(agent_id) do
    query_entries(fn entry -> entry.agent_id == agent_id end)
  end

  @doc """
  Query audit log entries within a time range.
  """
  @spec query_time_range(DateTime.t(), DateTime.t()) :: [map()]
  def query_time_range(from, to) do
    query_entries(fn entry ->
      DateTime.compare(entry.timestamp, from) in [:gt, :eq] and
        DateTime.compare(entry.timestamp, to) in [:lt, :eq]
    end)
  end

  @doc """
  Get the most recent N audit entries across all sessions.
  """
  @spec recent_entries(non_neg_integer()) :: [map()]
  def recent_entries(limit \\ 100) do
    all_entries()
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(limit)
  end

  @doc """
  Get aggregate statistics for audit entries.
  """
  @spec stats() :: map()
  def stats do
    entries = all_entries()

    commands =
      entries
      |> Enum.filter(&(&1.action == "command_executed"))

    %{
      total_entries: length(entries),
      total_commands: length(commands),
      unique_sessions: entries |> Enum.map(& &1.session_id) |> Enum.uniq() |> length(),
      unique_users: entries |> Enum.map(& &1.user_id) |> Enum.uniq() |> length(),
      unique_agents: entries |> Enum.map(& &1.agent_id) |> Enum.uniq() |> length(),
      command_breakdown:
        commands
        |> Enum.group_by(&get_in(&1, [:details, :command]))
        |> Enum.map(fn {cmd, list} -> {cmd, length(list)} end)
        |> Enum.into(%{}),
      security_events:
        entries
        |> Enum.count(&(&1.severity == :warning))
    }
  end

  @doc """
  Purge audit entries older than the given DateTime.
  Used for retention management.
  """
  @spec purge_before(DateTime.t()) :: {:ok, non_neg_integer()}
  def purge_before(cutoff) do
    entries = all_entries()

    to_delete =
      entries
      |> Enum.filter(fn entry ->
        DateTime.compare(entry.timestamp, cutoff) == :lt
      end)

    Enum.each(to_delete, fn entry ->
      :ets.delete(@audit_table, entry.id)
    end)

    {:ok, length(to_delete)}
  rescue
    ArgumentError -> {:ok, 0}
  end

  # ============================================================================
  # Private - Entry Construction
  # ============================================================================

  defp build_entry(session_id, user_id, agent_id, action, details) do
    %{
      id: generate_id(),
      session_id: session_id,
      user_id: to_string(user_id),
      agent_id: agent_id,
      action: action,
      details: details,
      severity: :info,
      timestamp: DateTime.utc_now()
    }
  end

  # ============================================================================
  # Private - Storage
  # ============================================================================

  defp store_entry(entry) do
    try do
      :ets.insert(@audit_table, {entry.id, entry})
    rescue
      ArgumentError ->
        # Table may not exist yet if SessionManager hasn't started
        Logger.warning("[AuditLogger] ETS table not available, entry dropped: #{entry.id}")
    end
  end

  defp maybe_broadcast(entry) do
    if config(:broadcast_events, true) do
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "live_response:audit",
        {:audit_entry, entry}
      )
    end
  rescue
    _ -> :ok
  end

  defp maybe_persist(entry) do
    if config(:persist_to_database, true) do
      try do
        TamanduaServer.AuditLog.log(%{
          action: "live_response:#{entry.action}",
          action_type: "live_response",
          user_id: entry.user_id,
          resource_type: "live_response_session",
          resource_id: entry.session_id,
          severity: entry.severity,
          details:
            Map.merge(entry.details, %{
              agent_id: entry.agent_id,
              session_id: entry.session_id
            })
        })
      rescue
        e ->
          Logger.debug("[AuditLogger] Database persist failed: #{inspect(e)}")
      end
    end
  end

  # ============================================================================
  # Private - Query Helpers
  # ============================================================================

  defp query_entries(filter_fn) do
    all_entries()
    |> Enum.filter(filter_fn)
    |> Enum.sort_by(& &1.timestamp, {:asc, DateTime})
  end

  defp all_entries do
    try do
      @audit_table
      |> :ets.tab2list()
      |> Enum.map(fn {_id, entry} -> entry end)
    rescue
      ArgumentError -> []
    end
  end

  # ============================================================================
  # Private - Utilities
  # ============================================================================

  defp generate_id do
    random = Base.encode16(:crypto.strong_rand_bytes(12), case: :lower)
    "lr_audit_#{random}"
  end

  defp sanitize_args(args) when is_map(args) do
    # Remove potentially large binary data from audit logs
    args
    |> Enum.map(fn
      {key, value} when is_binary(value) and byte_size(value) > 1024 ->
        {key, "[#{byte_size(value)} bytes]"}

      pair ->
        pair
    end)
    |> Enum.into(%{})
  end

  defp sanitize_args(args), do: args

  defp estimate_output_size(nil), do: 0
  defp estimate_output_size(output) when is_binary(output), do: byte_size(output)
  defp estimate_output_size(output) when is_map(output), do: output |> inspect() |> byte_size()
  defp estimate_output_size(_), do: 0

  defp config(key, default) do
    Application.get_env(:tamandua_server, __MODULE__, [])
    |> Keyword.get(key, default)
  end
end
