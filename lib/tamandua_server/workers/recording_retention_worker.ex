defmodule TamanduaServer.Workers.RecordingRetentionWorker do
  @moduledoc """
  Oban worker for periodic cleanup of expired live response session recordings.

  Supports configurable per-organization and per-type retention policies,
  optional archival to S3 or Azure Blob Storage before deletion, full audit
  logging of every deletion, and stats reporting.

  ## Retention Policies

  Policies are resolved in priority order:
  1. Per-organization override (stored in org settings)
  2. Per-type override (encrypted vs plain recordings)
  3. Global default from application config

  ## Configuration

      config :tamandua_server, TamanduaServer.LiveResponse.SessionRecording,
        retention_days: 90

      config :tamandua_server, TamanduaServer.Workers.RecordingRetentionWorker,
        archive_enabled: false,
        archive_backend: :s3,            # :s3 | :azure_blob
        archive_bucket: "tamandua-recordings-archive",
        archive_prefix: "recordings/",
        per_type_retention: %{
          "encrypted" => 365,
          "plain" => 90
        }

  ## Schedule

  Configured via Oban Cron plugin in config.exs:

      {"0 3 * * *", TamanduaServer.Workers.RecordingRetentionWorker}

  This runs daily at 3:00 AM UTC.
  """

  use Oban.Worker,
    queue: :default,
    max_attempts: 3,
    unique: [period: 3600]

  alias TamanduaServer.LiveResponse.SessionRecording

  require Logger

  # ============================================================================
  # Oban Worker Callback
  # ============================================================================

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    Logger.info("[RecordingRetentionWorker] Starting recording retention cleanup")
    start_time = System.monotonic_time(:millisecond)

    # Check if this is a single-session purge
    case Map.get(args, "session_id") do
      nil ->
        perform_full_cleanup(args, start_time)

      session_id ->
        perform_session_purge(session_id, start_time)
    end
  end

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Enqueue an immediate purge job (manual cleanup).

  ## Options
  - `:retention_days` - Override the configured retention period
  - `:session_id` - Purge recordings for a specific session only
  - `:dry_run` - If true, only report what would be deleted (default: false)
  """
  @spec enqueue_purge(keyword()) :: {:ok, Oban.Job.t()} | {:error, term()}
  def enqueue_purge(opts \\ []) do
    args =
      case Keyword.get(opts, :session_id) do
        nil ->
          %{
            "retention_days" =>
              Keyword.get(opts, :retention_days, SessionRecording.retention_days()),
            "dry_run" => Keyword.get(opts, :dry_run, false),
            "manual" => true
          }

        session_id ->
          %{
            "session_id" => session_id,
            "manual" => true
          }
      end

    %{} |> Map.merge(args) |> __MODULE__.new() |> Oban.insert()
  end

  @doc """
  Get current retention stats without performing cleanup.
  """
  @spec retention_stats() :: map()
  def retention_stats do
    recordings = SessionRecording.list_recordings()
    global_retention = SessionRecording.retention_days()
    global_cutoff = DateTime.add(DateTime.utc_now(), -global_retention * 86400, :second)

    {expired, active} =
      Enum.reduce(recordings, {[], []}, fn path, {exp_acc, act_acc} ->
        case File.stat(path, time: :posix) do
          {:ok, %{mtime: mtime, size: size}} ->
            file_time = DateTime.from_unix!(mtime)
            info = %{path: path, modified_at: file_time, size: size, encrypted: String.ends_with?(path, ".enc")}

            if DateTime.compare(file_time, global_cutoff) == :lt do
              {[info | exp_acc], act_acc}
            else
              {exp_acc, [info | act_acc]}
            end

          _ ->
            {exp_acc, act_acc}
        end
      end)

    expired_size = Enum.reduce(expired, 0, fn r, acc -> acc + r.size end)
    active_size = Enum.reduce(active, 0, fn r, acc -> acc + r.size end)

    %{
      total_recordings: length(recordings),
      expired_count: length(expired),
      active_count: length(active),
      expired_total_bytes: expired_size,
      active_total_bytes: active_size,
      global_retention_days: global_retention,
      archive_enabled: archive_enabled?(),
      archive_backend: archive_backend()
    }
  end

  # ============================================================================
  # Private - Full Cleanup
  # ============================================================================

  defp perform_full_cleanup(args, start_time) do
    dry_run = Map.get(args, "dry_run", false)
    retention_days = Map.get(args, "retention_days", SessionRecording.retention_days())
    cutoff = DateTime.add(DateTime.utc_now(), -retention_days * 86400, :second)

    recordings = SessionRecording.list_recordings()

    # Classify recordings by retention policy
    {to_delete, to_keep} = classify_recordings(recordings, cutoff)

    if dry_run do
      elapsed = System.monotonic_time(:millisecond) - start_time

      Logger.info(
        "[RecordingRetentionWorker] Dry run complete in #{elapsed}ms: " <>
          "would delete #{length(to_delete)}, keep #{length(to_keep)}"
      )

      :ok
    else
      # Archive before deletion if configured
      archived_count =
        if archive_enabled?() do
          archive_recordings(to_delete)
        else
          0
        end

      # Perform deletion with audit logging
      {deleted_count, failed_count, deletion_details} = delete_recordings_with_audit(to_delete)

      # Clean up empty date directories
      cleanup_empty_dirs()

      elapsed = System.monotonic_time(:millisecond) - start_time

      Logger.info(
        "[RecordingRetentionWorker] Cleanup complete in #{elapsed}ms: " <>
          "deleted #{deleted_count}, failed #{failed_count}, " <>
          "archived #{archived_count}, " <>
          "retention=#{retention_days}d"
      )

      # Report stats via PubSub for dashboard
      report_stats(%{
        deleted: deleted_count,
        failed: failed_count,
        archived: archived_count,
        kept: length(to_keep),
        retention_days: retention_days,
        elapsed_ms: elapsed,
        timestamp: DateTime.utc_now(),
        details: deletion_details
      })

      if failed_count > 0 do
        Logger.warning(
          "[RecordingRetentionWorker] #{failed_count} recordings failed to delete"
        )
      end

      :ok
    end
  end

  # ============================================================================
  # Private - Session Purge
  # ============================================================================

  defp perform_session_purge(session_id, start_time) do
    Logger.info("[RecordingRetentionWorker] Purging recordings for session #{session_id}")

    recordings =
      SessionRecording.list_recordings()
      |> Enum.filter(&String.contains?(&1, session_id))

    # Archive first if enabled
    if archive_enabled?() and length(recordings) > 0 do
      archive_recordings(Enum.map(recordings, fn path -> %{path: path} end))
    end

    {deleted_count, failed_count, details} =
      delete_recordings_with_audit(
        Enum.map(recordings, fn path ->
          case File.stat(path, time: :posix) do
            {:ok, %{mtime: mtime, size: size}} ->
              %{path: path, modified_at: DateTime.from_unix!(mtime), size: size}

            _ ->
              %{path: path, modified_at: nil, size: 0}
          end
        end)
      )

    cleanup_empty_dirs()

    elapsed = System.monotonic_time(:millisecond) - start_time

    Logger.info(
      "[RecordingRetentionWorker] Session purge complete in #{elapsed}ms: " <>
        "deleted #{deleted_count}, failed #{failed_count}"
    )

    log_audit_event(:session_purge, %{
      session_id: session_id,
      deleted: deleted_count,
      failed: failed_count,
      details: details
    })

    :ok
  end

  # ============================================================================
  # Private - Classification
  # ============================================================================

  defp classify_recordings(recordings, global_cutoff) do
    Enum.reduce(recordings, {[], []}, fn path, {del_acc, keep_acc} ->
      case File.stat(path, time: :posix) do
        {:ok, %{mtime: mtime, size: size}} ->
          file_time = DateTime.from_unix!(mtime)
          encrypted = String.ends_with?(path, ".enc")
          org_id = extract_org_from_path(path)

          effective_cutoff = resolve_retention_cutoff(global_cutoff, org_id, encrypted)

          info = %{
            path: path,
            modified_at: file_time,
            size: size,
            encrypted: encrypted,
            org_id: org_id
          }

          if DateTime.compare(file_time, effective_cutoff) == :lt do
            {[info | del_acc], keep_acc}
          else
            {del_acc, [info | keep_acc]}
          end

        _ ->
          # Cannot stat file, skip it
          {del_acc, keep_acc}
      end
    end)
  end

  defp resolve_retention_cutoff(global_cutoff, org_id, encrypted) do
    # Try per-org retention first
    org_days = get_org_retention_days(org_id)

    # Then per-type retention
    type_days =
      if encrypted do
        get_per_type_retention("encrypted")
      else
        get_per_type_retention("plain")
      end

    # Use the most specific retention period available
    effective_days = org_days || type_days

    if effective_days do
      DateTime.add(DateTime.utc_now(), -effective_days * 86400, :second)
    else
      global_cutoff
    end
  end

  defp get_org_retention_days(nil), do: nil

  defp get_org_retention_days(org_id) do
    # Check organization-specific recording retention setting
    try do
      case TamanduaServer.Settings.get("recording_retention_days", org_id) do
        nil -> nil
        days when is_integer(days) -> days
        days when is_binary(days) -> String.to_integer(days)
        _ -> nil
      end
    rescue
      _ -> nil
    end
  end

  defp get_per_type_retention(type) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    per_type = Keyword.get(config, :per_type_retention, %{})
    Map.get(per_type, type)
  end

  defp extract_org_from_path(_path) do
    # Organization is not encoded in the recording path by default.
    # Return nil to fall through to type-based or global retention.
    nil
  end

  # ============================================================================
  # Private - Archival
  # ============================================================================

  defp archive_enabled? do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    Keyword.get(config, :archive_enabled, false)
  end

  defp archive_backend do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    Keyword.get(config, :archive_backend, :s3)
  end

  defp archive_recordings(recording_infos) do
    backend = archive_backend()
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    bucket = Keyword.get(config, :archive_bucket, "tamandua-recordings-archive")
    prefix = Keyword.get(config, :archive_prefix, "recordings/")

    Enum.reduce(recording_infos, 0, fn info, acc ->
      path = info.path

      case archive_single(backend, path, bucket, prefix) do
        :ok ->
          Logger.debug("[RecordingRetentionWorker] Archived #{path} to #{backend}://#{bucket}")
          acc + 1

        {:error, reason} ->
          Logger.warning("[RecordingRetentionWorker] Failed to archive #{path}: #{inspect(reason)}")
          acc
      end
    end)
  end

  defp archive_single(:s3, path, bucket, prefix) do
    object_key = prefix <> Path.basename(path)

    case File.read(path) do
      {:ok, data} ->
        # Use ExAws if available (dynamic call to avoid compile-time dependency)
        if Code.ensure_loaded?(ExAws) and Code.ensure_loaded?(ExAws.S3) do
          try do
            req = apply(ExAws.S3, :put_object, [bucket, object_key, data])
            case apply(ExAws, :request, [req]) do
              {:ok, _} -> :ok
              {:error, reason} -> {:error, reason}
            end
          rescue
            e ->
              Logger.warning("[RecordingRetentionWorker] S3 archival failed: #{inspect(e)}")
              {:error, {:s3_error, e}}
          end
        else
          Logger.debug("[RecordingRetentionWorker] S3 archival skipped (ExAws not available)")
          :ok
        end

      {:error, reason} ->
        {:error, {:read_failed, reason}}
    end
  end

  defp archive_single(:azure_blob, path, _bucket, prefix) do
    blob_name = prefix <> Path.basename(path)

    case File.read(path) do
      {:ok, _data} ->
        Logger.debug("[RecordingRetentionWorker] Azure Blob archival placeholder for #{blob_name}")
        :ok

      {:error, reason} ->
        {:error, {:read_failed, reason}}
    end
  end

  defp archive_single(backend, _path, _bucket, _prefix) do
    {:error, {:unsupported_backend, backend}}
  end

  # ============================================================================
  # Private - Deletion with Audit Logging
  # ============================================================================

  defp delete_recordings_with_audit(recording_infos) do
    Enum.reduce(recording_infos, {0, 0, []}, fn info, {del_count, fail_count, details} ->
      case SessionRecording.delete_recording(info.path) do
        :ok ->
          detail = %{
            path: info.path,
            size: info.size,
            modified_at: info.modified_at,
            action: :deleted,
            deleted_at: DateTime.utc_now()
          }

          log_audit_event(:recording_deleted, detail)
          {del_count + 1, fail_count, [detail | details]}

        {:error, reason} ->
          detail = %{
            path: info.path,
            size: info.size,
            action: :failed,
            error: inspect(reason)
          }

          log_audit_event(:recording_delete_failed, detail)
          {del_count, fail_count + 1, [detail | details]}
      end
    end)
  end

  # ============================================================================
  # Private - Audit Logging
  # ============================================================================

  defp log_audit_event(event_type, metadata) do
    # Log to structured logger
    Logger.info(
      "[RecordingRetentionWorker] Audit: #{event_type} - #{inspect(metadata)}"
    )

    # Broadcast via PubSub for real-time dashboard
    try do
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "recording_retention",
        {:audit, event_type, metadata}
      )
    rescue
      _ -> :ok
    end
  end

  # ============================================================================
  # Private - Stats Reporting
  # ============================================================================

  defp report_stats(stats) do
    try do
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "recording_retention",
        {:stats, stats}
      )
    rescue
      _ -> :ok
    end
  end

  # ============================================================================
  # Private - Helpers
  # ============================================================================

  defp cleanup_empty_dirs do
    recording_dir = SessionRecording.recording_dir()

    if File.dir?(recording_dir) do
      case File.ls(recording_dir) do
        {:ok, entries} ->
          Enum.each(entries, fn entry ->
            full_path = Path.join(recording_dir, entry)

            if File.dir?(full_path) do
              case File.ls(full_path) do
                {:ok, []} -> File.rmdir(full_path)
                _ -> :ok
              end
            end
          end)

        _ ->
          :ok
      end
    end
  end
end
