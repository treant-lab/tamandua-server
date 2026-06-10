defmodule TamanduaServer.RemoteShell.AuditLogger do
  @moduledoc """
  Audit logging for shell sessions.

  Logs all commands, outputs, and session events to database and recording files.
  Provides search and filtering capabilities for forensic analysis.
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.ShellSessions

  @recording_dir "priv/shell_recordings"

  defmodule AuditLog do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id

    schema "shell_audit_logs" do
      belongs_to :session, TamanduaServer.ShellSessions.Session
      belongs_to :user, TamanduaServer.Accounts.User

      field :event_type, :string
      field :timestamp, :utc_datetime

      # Command fields
      field :command, :string
      field :exit_code, :integer
      field :blocked, :boolean, default: false
      field :block_reason, :string

      # Output fields
      field :output, :string
      field :output_size, :integer

      # Context
      field :client_ip, :string

      timestamps(updated_at: false)
    end

    @event_types ~w(command output resize error session_start session_end file_upload file_download)

    def changeset(log, attrs) do
      log
      |> cast(attrs, [
        :session_id, :user_id, :event_type, :timestamp,
        :command, :exit_code, :blocked, :block_reason,
        :output, :output_size, :client_ip
      ])
      |> validate_required([:session_id, :event_type, :timestamp])
      |> validate_inclusion(:event_type, @event_types)
      |> foreign_key_constraint(:session_id)
      |> foreign_key_constraint(:user_id)
    end
  end

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Logs a command execution event.
  """
  def log_command(session_id, user_id, command, opts \\ []) do
    attrs = %{
      session_id: session_id,
      user_id: user_id,
      event_type: "command",
      timestamp: DateTime.utc_now(),
      command: command,
      exit_code: Keyword.get(opts, :exit_code),
      blocked: Keyword.get(opts, :blocked, false),
      block_reason: Keyword.get(opts, :block_reason),
      client_ip: Keyword.get(opts, :client_ip)
    }

    case create_audit_log(attrs) do
      {:ok, log} ->
        # Append to recording file
        append_to_recording(session_id, "i", command)
        {:ok, log}

      {:error, reason} ->
        Logger.error("Failed to log command: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Logs command output.
  """
  def log_output(session_id, output, opts \\ []) do
    attrs = %{
      session_id: session_id,
      event_type: "output",
      timestamp: DateTime.utc_now(),
      output: output,
      output_size: byte_size(output),
      user_id: Keyword.get(opts, :user_id)
    }

    case create_audit_log(attrs) do
      {:ok, log} ->
        # Append to recording file
        append_to_recording(session_id, "o", output)
        {:ok, log}

      {:error, reason} ->
        Logger.error("Failed to log output: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Logs a session event (start, end, resize, error).
  """
  def log_event(session_id, event_type, opts \\ []) do
    attrs = %{
      session_id: session_id,
      user_id: Keyword.get(opts, :user_id),
      event_type: event_type,
      timestamp: DateTime.utc_now(),
      command: Keyword.get(opts, :details),
      client_ip: Keyword.get(opts, :client_ip)
    }

    case create_audit_log(attrs) do
      {:ok, log} -> {:ok, log}
      {:error, reason} ->
        Logger.error("Failed to log event: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Searches audit logs with full-text search.
  """
  def search(query_string, opts \\ []) do
    base_query = from(log in AuditLog,
      order_by: [desc: log.timestamp],
      preload: [:session, :user]
    )

    base_query
    |> apply_search(query_string)
    |> apply_filters(opts)
    |> apply_pagination(opts)
    |> Repo.all()
  end

  @doc """
  Gets audit logs for a specific session.
  """
  def get_session_logs(session_id, opts \\ []) do
    from(log in AuditLog,
      where: log.session_id == ^session_id,
      order_by: [asc: log.timestamp],
      preload: [:user]
    )
    |> apply_filters(opts)
    |> apply_pagination(opts)
    |> Repo.all()
  end

  @doc """
  Gets command history for a session.
  """
  def get_command_history(session_id, opts \\ []) do
    from(log in AuditLog,
      where: log.session_id == ^session_id and log.event_type == "command",
      order_by: [asc: log.timestamp],
      select: %{
        timestamp: log.timestamp,
        command: log.command,
        exit_code: log.exit_code,
        blocked: log.blocked
      }
    )
    |> apply_pagination(opts)
    |> Repo.all()
  end

  @doc """
  Gets statistics for audit logs.
  """
  def get_statistics(opts \\ []) do
    from_date = Keyword.get(opts, :from, DateTime.add(DateTime.utc_now(), -30, :day))
    to_date = Keyword.get(opts, :to, DateTime.utc_now())

    # Total events
    total = from(log in AuditLog,
      where: log.timestamp >= ^from_date and log.timestamp <= ^to_date,
      select: count(log.id)
    ) |> Repo.one()

    # By event type
    by_type = from(log in AuditLog,
      where: log.timestamp >= ^from_date and log.timestamp <= ^to_date,
      group_by: log.event_type,
      select: {log.event_type, count(log.id)}
    ) |> Repo.all() |> Enum.into(%{})

    # By user
    by_user = from(log in AuditLog,
      where: log.timestamp >= ^from_date and log.timestamp <= ^to_date and not is_nil(log.user_id),
      group_by: log.user_id,
      select: {log.user_id, count(log.id)}
    ) |> Repo.all() |> Enum.into(%{})

    # Blocked commands
    blocked_count = from(log in AuditLog,
      where: log.timestamp >= ^from_date and log.timestamp <= ^to_date and log.blocked == true,
      select: count(log.id)
    ) |> Repo.one()

    %{
      total: total,
      by_type: by_type,
      by_user: by_user,
      blocked_commands: blocked_count,
      period: %{from: from_date, to: to_date}
    }
  end

  @doc """
  Deletes old audit logs.
  """
  def cleanup_old_logs(days_to_keep \\ 90) do
    cutoff = DateTime.add(DateTime.utc_now(), -days_to_keep, :day)

    {count, _} = from(log in AuditLog,
      where: log.timestamp < ^cutoff
    )
    |> Repo.delete_all()

    Logger.info("Deleted #{count} old audit log entries")
    {:ok, count}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp create_audit_log(attrs) do
    %AuditLog{}
    |> AuditLog.changeset(attrs)
    |> Repo.insert()
  end

  defp apply_search(query, nil), do: query
  defp apply_search(query, ""), do: query
  defp apply_search(query, search_string) do
    # Use PostgreSQL full-text search
    tsquery = String.split(search_string)
              |> Enum.map(&"#{&1}:*")
              |> Enum.join(" & ")

    from(log in query,
      where: fragment("search_vector @@ to_tsquery('english', ?)", ^tsquery)
    )
  end

  defp apply_filters(query, opts) do
    query
    |> filter_by_user(Keyword.get(opts, :user_id))
    |> filter_by_event_type(Keyword.get(opts, :event_type))
    |> filter_by_date_range(Keyword.get(opts, :from), Keyword.get(opts, :to))
    |> filter_by_blocked(Keyword.get(opts, :blocked_only))
  end

  defp filter_by_user(query, nil), do: query
  defp filter_by_user(query, user_id) do
    where(query, [log], log.user_id == ^user_id)
  end

  defp filter_by_event_type(query, nil), do: query
  defp filter_by_event_type(query, event_type) do
    where(query, [log], log.event_type == ^event_type)
  end

  defp filter_by_date_range(query, nil, nil), do: query
  defp filter_by_date_range(query, from, nil) do
    where(query, [log], log.timestamp >= ^from)
  end
  defp filter_by_date_range(query, nil, to) do
    where(query, [log], log.timestamp <= ^to)
  end
  defp filter_by_date_range(query, from, to) do
    where(query, [log], log.timestamp >= ^from and log.timestamp <= ^to)
  end

  defp filter_by_blocked(query, true) do
    where(query, [log], log.blocked == true)
  end
  defp filter_by_blocked(query, _), do: query

  defp apply_pagination(query, opts) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    query
    |> limit(^limit)
    |> offset(^offset)
  end

  defp append_to_recording(session_id, event_type, data) do
    # Get session to find recording path
    case ShellSessions.get_session_by_session_id(session_id) do
      nil ->
        Logger.warn("Session not found for recording: #{session_id}")
        :ok

      session ->
        if session.recording_path do
          # Calculate timestamp relative to session start
          now = DateTime.utc_now()
          timestamp = DateTime.diff(now, session.started_at, :millisecond) / 1000.0

          # Format as asciicast v2 event: [time, type, data]
          event = [timestamp, event_type, data]
          line = Jason.encode!(event) <> "\n"

          # Append to file (async to not block)
          Task.start(fn ->
            File.write(session.recording_path, line, [:append])
          end)
        end

        :ok
    end
  rescue
    e ->
      Logger.error("Failed to append to recording: #{Exception.message(e)}")
      :ok
  end
end
