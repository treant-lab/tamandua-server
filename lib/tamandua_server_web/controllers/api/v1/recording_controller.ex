defmodule TamanduaServerWeb.API.V1.RecordingController do
  @moduledoc """
  API controller for live response session recording management.

  Provides endpoints for:
  - Downloading recordings (decrypted and decompressed on-the-fly)
  - Listing available recordings
  - Purging expired recordings
  - Deleting specific recordings

  All endpoints require authentication and appropriate permissions.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.LiveResponse.SessionRecording
  alias TamanduaServer.Workers.RecordingRetentionWorker

  require Logger

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Download a session recording.

  The recording is decrypted (if encrypted) and decompressed on-the-fly,
  then served as the raw asciicast v2 format suitable for playback in
  asciinema-player or xterm.js.

  ## Parameters
  - session_id: The recording session ID
  - format: "raw" (asciicast v2 text) or "compressed" (gzip as stored)
  """
  def download(conn, %{"session_id" => session_id} = params) do
    format = Map.get(params, "format", "raw")

    case find_recording(session_id) do
      {:ok, path} ->
        case format do
          "raw" ->
            serve_decompressed(conn, path, session_id)

          "compressed" ->
            serve_compressed(conn, path, session_id)

          _ ->
            conn
            |> put_status(:bad_request)
            |> json(%{error: "Invalid format. Use 'raw' or 'compressed'."})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Recording not found for session #{session_id}"})
    end
  end

  @doc """
  List available recordings with metadata.

  ## Parameters
  - page: Page number (default 1)
  - per_page: Items per page (default 20)
  - agent_id: Filter by agent ID (optional)
  """
  def index(conn, params) do
    recordings = SessionRecording.list_recordings()
    agent_filter = Map.get(params, "agent_id")

    entries =
      recordings
      |> maybe_filter_by_agent(agent_filter)
      |> Enum.map(&recording_metadata/1)
      |> Enum.sort_by(& &1.modified_at, {:desc, DateTime})

    page = bounded_page(Map.get(params, "page"))
    per_page = bounded_per_page(Map.get(params, "per_page"), 20, 100)

    paginated =
      entries
      |> Enum.drop((page - 1) * per_page)
      |> Enum.take(per_page)

    json(conn, %{
      data: paginated,
      meta: %{
        total: length(entries),
        page: page,
        per_page: per_page,
        total_pages: ceil(length(entries) / per_page)
      }
    })
  end

  @doc """
  Get metadata about a specific recording.
  """
  def show(conn, %{"session_id" => session_id}) do
    case find_recording(session_id) do
      {:ok, path} ->
        json(conn, %{data: recording_metadata(path)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Recording not found"})
    end
  end

  @doc """
  Delete a specific recording.
  """
  def delete(conn, %{"session_id" => session_id}) do
    case SessionRecording.purge_session(session_id) do
      {:ok, count} when count > 0 ->
        json(conn, %{
          message: "Deleted #{count} recording(s) for session #{session_id}",
          deleted_count: count
        })

      {:ok, 0} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "No recordings found for session #{session_id}"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to delete: #{inspect(reason)}"})
    end
  end

  @doc """
  Trigger a manual purge of expired recordings.

  ## Parameters
  - retention_days: Override retention period (optional, defaults to configured value)
  """
  def purge(conn, params) do
    retention_override = Map.get(params, "retention_days")

    opts =
      if retention_override do
        [retention_days: bounded_retention_days(retention_override)]
      else
        []
      end

    case RecordingRetentionWorker.enqueue_purge(opts) do
      {:ok, job} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          message: "Purge job enqueued",
          job_id: job.id,
          retention_days:
            Keyword.get(opts, :retention_days, SessionRecording.retention_days())
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to enqueue purge: #{inspect(reason)}"})
    end
  end

  @doc """
  Get recording retention configuration and statistics.
  """
  def retention_info(conn, _params) do
    recordings = SessionRecording.list_recordings()

    total_size =
      Enum.reduce(recordings, 0, fn path, acc ->
        case File.stat(path) do
          {:ok, %{size: size}} -> acc + size
          _ -> acc
        end
      end)

    json(conn, %{
      data: %{
        retention_days: SessionRecording.retention_days(),
        recording_dir: SessionRecording.recording_dir(),
        total_recordings: length(recordings),
        total_size_bytes: total_size,
        total_size_human: humanize_bytes(total_size),
        encryption_enabled: System.get_env("TAMANDUA_RECORDING_KEY") != nil
      }
    })
  end

  @doc """
  Get detailed retention statistics (expired vs active breakdown, archive status).
  """
  def retention_stats(conn, _params) do
    stats = RecordingRetentionWorker.retention_stats()

    json(conn, %{
      data: %{
        total_recordings: stats.total_recordings,
        expired_count: stats.expired_count,
        active_count: stats.active_count,
        expired_total_bytes: stats.expired_total_bytes,
        expired_total_human: humanize_bytes(stats.expired_total_bytes),
        active_total_bytes: stats.active_total_bytes,
        active_total_human: humanize_bytes(stats.active_total_bytes),
        global_retention_days: stats.global_retention_days,
        archive_enabled: stats.archive_enabled,
        archive_backend: stats.archive_backend,
        encryption_enabled: System.get_env("TAMANDUA_RECORDING_KEY") != nil
      }
    })
  end

  @doc """
  Trigger a retention purge with advanced options.

  ## Parameters
  - retention_days: Override retention period (optional)
  - session_id: Purge a specific session (optional)
  - dry_run: If true, only report what would be deleted (optional, default false)
  """
  def trigger_retention_purge(conn, params) do
    opts = []

    opts =
      if params["retention_days"] do
        Keyword.put(opts, :retention_days, bounded_retention_days(params["retention_days"]))
      else
        opts
      end

    opts =
      if params["session_id"] do
        Keyword.put(opts, :session_id, params["session_id"])
      else
        opts
      end

    opts =
      if params["dry_run"] do
        Keyword.put(opts, :dry_run, true)
      else
        opts
      end

    case RecordingRetentionWorker.enqueue_purge(opts) do
      {:ok, job} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          message: "Retention purge job enqueued",
          job_id: job.id,
          options: %{
            retention_days: Keyword.get(opts, :retention_days),
            session_id: Keyword.get(opts, :session_id),
            dry_run: Keyword.get(opts, :dry_run, false)
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to enqueue purge: #{inspect(reason)}"})
    end
  end

  # ============================================================================
  # Private
  # ============================================================================

  defp find_recording(session_id) do
    recordings = SessionRecording.list_recordings()

    case Enum.find(recordings, &String.contains?(&1, session_id)) do
      nil -> {:error, :not_found}
      path -> {:ok, path}
    end
  end

  defp serve_decompressed(conn, path, session_id) do
    case SessionRecording.read_recording(path) do
      {:ok, content} ->
        filename = "#{session_id}.cast"

        conn
        |> put_resp_content_type("text/plain")
        |> put_resp_header(
          "content-disposition",
          "attachment; filename=\"#{filename}\""
        )
        |> send_resp(200, content)

      {:error, reason} ->
        Logger.error("Failed to read recording #{path}: #{inspect(reason)}")

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to read recording: #{inspect(reason)}"})
    end
  end

  defp serve_compressed(conn, path, session_id) do
    case File.read(path) do
      {:ok, data} ->
        # If encrypted, decrypt first to get the gzip data
        served_data =
          if String.ends_with?(path, ".enc") do
            case SessionRecording.read_recording(path) do
              {:ok, decompressed} ->
                # Re-compress for download
                :zlib.gzip(decompressed)

              {:error, _} ->
                data
            end
          else
            data
          end

        filename = "#{session_id}.cast.gz"

        conn
        |> put_resp_content_type("application/gzip")
        |> put_resp_header(
          "content-disposition",
          "attachment; filename=\"#{filename}\""
        )
        |> send_resp(200, served_data)

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to read file: #{inspect(reason)}"})
    end
  end

  defp maybe_filter_by_agent(recordings, nil), do: recordings

  defp maybe_filter_by_agent(recordings, agent_id) do
    Enum.filter(recordings, &String.contains?(&1, agent_id))
  end

  defp bounded_page(value), do: value |> parse_int(1) |> max(1)

  defp bounded_per_page(value, default, max_per_page),
    do: value |> parse_int(default) |> max(1) |> min(max_per_page)

  defp bounded_retention_days(value), do: value |> parse_int(SessionRecording.retention_days()) |> max(1) |> min(3650)

  defp parse_int(nil, default), do: default
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(_, default), do: default

  defp recording_metadata(path) do
    filename = Path.basename(path)
    parts = String.split(Path.rootname(Path.rootname(Path.rootname(filename))), "_", parts: 4)

    {session_id, agent_id, user_id} =
      case parts do
        [sid, aid, uid | _] -> {sid, aid, uid}
        [sid, aid] -> {sid, aid, nil}
        [sid] -> {sid, nil, nil}
        _ -> {filename, nil, nil}
      end

    stat =
      case File.stat(path, time: :posix) do
        {:ok, s} -> s
        _ -> %{size: 0, mtime: 0}
      end

    %{
      path: path,
      filename: filename,
      session_id: session_id,
      agent_id: agent_id,
      user_id: user_id,
      size_bytes: stat.size,
      size_human: humanize_bytes(stat.size),
      modified_at: DateTime.from_unix!(stat.mtime),
      encrypted: String.ends_with?(path, ".enc"),
      compressed: true
    }
  end

  defp humanize_bytes(bytes) when bytes < 1024, do: "#{bytes} B"
  defp humanize_bytes(bytes) when bytes < 1_048_576, do: "#{Float.round(bytes / 1024, 1)} KB"

  defp humanize_bytes(bytes) when bytes < 1_073_741_824,
    do: "#{Float.round(bytes / 1_048_576, 1)} MB"

  defp humanize_bytes(bytes), do: "#{Float.round(bytes / 1_073_741_824, 1)} GB"
end
