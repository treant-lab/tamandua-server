defmodule TamanduaServer.ShellSessions do
  @moduledoc """
  Context module for managing shell sessions and recordings.

  Provides:
  - Session persistence and retrieval
  - Recording playback
  - Session search and filtering
  - Session transcript export
  """

  import Ecto.Query
  alias TamanduaServer.LiveResponse.SessionRecording
  alias TamanduaServer.Repo
  alias TamanduaServer.ShellSessions.{Session}

  require Logger

  @recording_dir "priv/shell_recordings"

  # ============================================================================
  # Sessions
  # ============================================================================

  @doc """
  Creates a new shell session record.
  """
  def create_session(attrs) do
    %Session{}
    |> Session.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Gets a session by ID.
  """
  def get_session(id), do: Repo.get(Session, id)

  @doc """
  Gets a session by session_id (external ID).
  """
  def get_session_by_session_id(session_id) do
    Repo.get_by(Session, session_id: session_id)
  end

  @doc """
  Updates a session.
  """
  def update_session(%Session{} = session, attrs) do
    session
    |> Session.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Ends a session by marking it as terminated.
  """
  def end_session(session_id, reason \\ "normal") do
    case get_session_by_session_id(session_id) do
      nil ->
        {:error, :not_found}

      session ->
        update_session(session, %{
          ended_at: DateTime.utc_now(),
          status: :ended,
          end_reason: reason
        })
    end
  end

  @doc """
  Lists sessions with optional filters.

  Options:
  - :agent_id - Filter by agent
  - :agent_ids - Filter by a list of agents
  - :user_id - Filter by user
  - :status - Filter by status (:active, :ended)
  - :from - Start date
  - :to - End date
  - :limit - Maximum results (default 50)
  - :offset - Offset for pagination
  """
  def list_sessions(opts \\ []) do
    query = from(s in Session, order_by: [desc: s.started_at])

    query
    |> filter_by_agent(opts[:agent_id])
    |> filter_by_agents(opts[:agent_ids])
    |> filter_by_user(opts[:user_id])
    |> filter_by_status(opts[:status])
    |> filter_by_date_range(opts[:from], opts[:to])
    |> limit(^(opts[:limit] || 50))
    |> offset(^(opts[:offset] || 0))
    |> Repo.all()
  end

  defp filter_by_agent(query, nil), do: query

  defp filter_by_agent(query, agent_id) do
    where(query, [s], s.agent_id == ^agent_id)
  end

  defp filter_by_agents(query, nil), do: query
  defp filter_by_agents(query, []), do: where(query, false)

  defp filter_by_agents(query, agent_ids) when is_list(agent_ids) do
    where(query, [s], s.agent_id in ^agent_ids)
  end

  defp filter_by_user(query, nil), do: query
  defp filter_by_user(query, user_id) do
    where(query, [s], s.user_id == ^user_id)
  end

  defp filter_by_status(query, nil), do: query
  defp filter_by_status(query, status) do
    where(query, [s], s.status == ^status)
  end

  defp filter_by_date_range(query, nil, nil), do: query
  defp filter_by_date_range(query, from, nil) do
    where(query, [s], s.started_at >= ^from)
  end
  defp filter_by_date_range(query, nil, to) do
    where(query, [s], s.started_at <= ^to)
  end
  defp filter_by_date_range(query, from, to) do
    where(query, [s], s.started_at >= ^from and s.started_at <= ^to)
  end

  @doc """
  Gets active sessions count.
  """
  def count_active_sessions do
    from(s in Session, where: s.status == :active)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Gets session statistics.
  """
  def get_session_stats(opts \\ []) do
    from_date = opts[:from] || DateTime.add(DateTime.utc_now(), -30, :day)
    to_date = opts[:to] || DateTime.utc_now()

    total =
      from(s in Session,
        where: s.started_at >= ^from_date and s.started_at <= ^to_date
      )
      |> Repo.aggregate(:count, :id)

    active =
      from(s in Session, where: s.status == :active)
      |> Repo.aggregate(:count, :id)

    by_user =
      from(s in Session,
        where: s.started_at >= ^from_date and s.started_at <= ^to_date,
        group_by: s.user_id,
        select: {s.user_id, count(s.id)}
      )
      |> Repo.all()
      |> Enum.into(%{})

    by_agent =
      from(s in Session,
        where: s.started_at >= ^from_date and s.started_at <= ^to_date,
        group_by: s.agent_id,
        select: {s.agent_id, count(s.id)}
      )
      |> Repo.all()
      |> Enum.into(%{})

    avg_duration =
      from(s in Session,
        where: s.status == :ended and not is_nil(s.ended_at),
        select: avg(fragment("EXTRACT(EPOCH FROM (? - ?))", s.ended_at, s.started_at))
      )
      |> Repo.one()

    %{
      total: total,
      active: active,
      by_user: by_user,
      by_agent: by_agent,
      average_duration_seconds: avg_duration || 0,
      period: %{from: from_date, to: to_date}
    }
  end

  # ============================================================================
  # Recordings
  # ============================================================================

  @doc """
  Gets the recording file path for a session.
  """
  def get_recording_path(session_id) do
    case get_session_by_session_id(session_id) do
      %Session{recording_path: path} when is_binary(path) and path != "" ->
        {:ok, path}

      _ ->
        case find_recording_file(session_id) do
          nil -> {:error, :not_found}
          path -> {:ok, path}
        end
    end
  end

  @doc """
  Gets the recording content for playback.
  Returns asciicast v2 format content.
  """
  def get_recording(session_id) do
    case get_recording_path(session_id) do
      {:ok, path} ->
        cond do
          String.ends_with?(path, ".cast.gz") or String.ends_with?(path, ".cast.gz.enc") ->
            SessionRecording.read_recording(path)

          true ->
            File.read(path)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Parses an asciicast v2 recording into structured events.
  """
  def parse_recording(content) when is_binary(content) do
    lines = String.split(content, "\n", trim: true)

    case lines do
      [header_line | event_lines] ->
        with {:ok, header} <- Jason.decode(header_line) do
          events =
            event_lines
            |> Enum.map(&parse_event/1)
            |> Enum.reject(&is_nil/1)

          {:ok,
           %{
             header: header,
             events: events,
             duration: get_duration(events),
             event_count: length(events)
           }}
        end

      _ ->
        {:error, :invalid_format}
    end
  end

  defp parse_event(line) do
    case Jason.decode(line) do
      {:ok, [timestamp, type, data]} ->
        %{
          timestamp: timestamp,
          type: type,
          data: data
        }

      _ ->
        nil
    end
  end

  defp get_duration(events) do
    case List.last(events) do
      %{timestamp: ts} -> ts
      _ -> 0
    end
  end

  @doc """
  Generates a text transcript from a recording.
  Only includes output events.
  """
  def generate_transcript(session_id) do
    with {:ok, content} <- get_recording(session_id),
         {:ok, parsed} <- parse_recording(content) do
      transcript =
        parsed.events
        |> Enum.filter(&(&1.type == "o"))
        |> Enum.map(& &1.data)
        |> Enum.join("")
        |> strip_ansi_codes()

      {:ok,
       %{
         session_id: session_id,
         duration: parsed.duration,
         content: transcript
       }}
    end
  end

  defp strip_ansi_codes(text) do
    # Remove ANSI escape sequences
    Regex.replace(~r/\e\[[0-9;]*[a-zA-Z]/, text, "")
  end

  @doc """
  Lists available recordings.
  """
  def list_recordings(opts \\ []) do
    limit = opts[:limit] || 50
    offset = opts[:offset] || 0

    # Get files from recording directory
    @recording_dir
    |> Path.join("**/*.cast")
    |> Path.wildcard()
    |> Enum.sort_by(&File.stat!(&1).mtime, :desc)
    |> Enum.drop(offset)
    |> Enum.take(limit)
    |> Enum.map(&parse_recording_filename/1)
    |> Enum.reject(&is_nil/1)
  end

  defp parse_recording_filename(path) do
    filename = Path.basename(path, ".cast")

    case String.split(filename, "_", parts: 3) do
      [session_id, agent_id, user_id] ->
        stat = File.stat!(path)

        %{
          session_id: "shell_" <> session_id,
          agent_id: agent_id,
          user_id: user_id,
          path: path,
          size: stat.size,
          created_at: stat.mtime |> NaiveDateTime.from_erl!() |> DateTime.from_naive!("Etc/UTC")
        }

      _ ->
        nil
    end
  rescue
    _ -> nil
  end

  @doc """
  Deletes old recordings.
  Keeps recordings for the specified number of days.
  """
  def cleanup_old_recordings(days_to_keep \\ 90) do
    cutoff = DateTime.add(DateTime.utc_now(), -days_to_keep, :day)

    @recording_dir
    |> Path.join("**/*.cast")
    |> Path.wildcard()
    |> Enum.filter(fn path ->
      case File.stat(path) do
        {:ok, stat} ->
          mtime = NaiveDateTime.from_erl!(stat.mtime)
          DateTime.compare(DateTime.from_naive!(mtime, "Etc/UTC"), cutoff) == :lt

        _ ->
          false
      end
    end)
    |> Enum.each(fn path ->
      Logger.info("Deleting old recording: #{path}")
      File.rm(path)
    end)
  end

  # ============================================================================
  # Search
  # ============================================================================

  @doc """
  Searches session recordings for specific content.
  """
  def search_recordings(query, opts \\ []) do
    limit = opts[:limit] || 20

    list_recordings(limit: 100)
    |> Task.async_stream(
      fn recording ->
        case get_recording(recording.session_id) do
          {:ok, content} ->
            if String.contains?(content, query) do
              %{recording | matched: true}
            else
              nil
            end

          _ ->
            nil
        end
      end,
      max_concurrency: 10,
      timeout: 5000,
      on_timeout: :kill_task
    )
    |> Enum.map(fn
      {:ok, result} -> result
      _ -> nil
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.take(limit)
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp find_recording_file(session_id) do
    # Remove "shell_" prefix if present for searching
    search_id = String.replace_prefix(session_id, "shell_", "")

    legacy_match =
      @recording_dir
      |> Path.join("**/#{search_id}*.cast")
      |> Path.wildcard()
      |> List.first()

    legacy_match ||
      "priv/live_response_recordings"
      |> Path.join("**/#{search_id}*.cast.gz*")
      |> Path.wildcard()
      |> List.first()
  end
end
