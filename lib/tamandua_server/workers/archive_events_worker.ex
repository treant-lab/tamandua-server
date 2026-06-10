defmodule TamanduaServer.Workers.ArchiveEventsWorker do
  @moduledoc """
  Oban worker for archiving and sampling old telemetry events.

  This worker runs daily and performs:
  1. Archives events older than retention period to events_archive table
  2. Applies sampling to low-value events (keeps 10% after 7 days)
  3. Marks events as archived to prevent re-processing
  4. Cleans up fully archived chunks

  ## Retention Strategy

  - **Recent events (0-7 days)**: Keep 100% of all events
  - **Medium-age events (7-30 days)**: Keep 100% of high-value events, sample 10% of low-value
  - **Old events (30+ days)**: Archive to events_archive table, then drop via TimescaleDB retention

  ## High-Value Events

  Events that are always kept regardless of age:
  - process_creation, process_termination
  - network_connection, network_listen
  - file_modification, file_creation, file_deletion
  - registry_modification (Windows)
  - privilege_escalation
  - Any event with detections or alerts

  ## Configuration

      config :tamandua_server, TamanduaServer.Telemetry,
        event_retention_days: 30,
        event_compression_days: 7,
        event_sampling_enabled: true,
        event_sampling_rate: 0.1,  # 10% sampling
        archive_enabled: true,
        archive_batch_size: 5000

  ## Schedule

  Configured via Oban Cron plugin:

      {"0 4 * * *", TamanduaServer.Workers.ArchiveEventsWorker}

  Runs daily at 4:00 AM UTC (staggered 1 hour after RecordingRetentionWorker).
  """

  use Oban.Worker,
    queue: :default,
    max_attempts: 3,
    unique: [period: 3600]

  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Telemetry.EventSampler

  require Logger
  import Ecto.Query

  # ============================================================================
  # Oban Worker Callback
  # ============================================================================

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    Logger.info("[ArchiveEventsWorker] Starting event archival and sampling")
    start_time = System.monotonic_time(:millisecond)

    dry_run = Map.get(args, "dry_run", false)
    retention_days = Map.get(args, "retention_days", retention_days())
    sampling_age_days = Map.get(args, "sampling_age_days", 7)

    stats = %{
      archived: 0,
      sampled: 0,
      deleted: 0,
      kept: 0,
      errors: 0
    }

    stats =
      if archive_enabled?() do
        stats
        |> archive_old_events(retention_days, dry_run)
        |> sample_medium_age_events(sampling_age_days, dry_run)
      else
        Logger.info("[ArchiveEventsWorker] Archiving disabled, skipping")
        stats
      end

    elapsed = System.monotonic_time(:millisecond) - start_time

    Logger.info(
      "[ArchiveEventsWorker] Completed in #{elapsed}ms: " <>
        "archived=#{stats.archived}, sampled=#{stats.sampled}, " <>
        "deleted=#{stats.deleted}, kept=#{stats.kept}, errors=#{stats.errors}, " <>
        "dry_run=#{dry_run}"
    )

    # Report stats for monitoring
    report_stats(Map.put(stats, :elapsed_ms, elapsed))

    :ok
  end

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Manually trigger archival job with custom parameters.

  ## Options
  - `:retention_days` - Archive events older than this (default: 30)
  - `:sampling_age_days` - Start sampling events older than this (default: 7)
  - `:dry_run` - Only report what would be done (default: false)
  """
  @spec enqueue_archival(keyword()) :: {:ok, Oban.Job.t()} | {:error, term()}
  def enqueue_archival(opts \\ []) do
    args = %{
      "retention_days" => Keyword.get(opts, :retention_days, retention_days()),
      "sampling_age_days" => Keyword.get(opts, :sampling_age_days, 7),
      "dry_run" => Keyword.get(opts, :dry_run, false),
      "manual" => true
    }

    __MODULE__.new(args) |> Oban.insert()
  end

  @doc """
  Get archival statistics without performing archival.
  """
  @spec archival_stats() :: map()
  def archival_stats do
    now = DateTime.utc_now()
    retention_cutoff = DateTime.add(now, -retention_days() * 86400, :second)
    sampling_cutoff = DateTime.add(now, -7 * 86400, :second)
    recent_cutoff = DateTime.add(now, -7 * 86400, :second)

    # Count events in each age bracket
    old_count = count_events_older_than(retention_cutoff)
    medium_count = count_events_between(sampling_cutoff, retention_cutoff)
    recent_count = count_events_newer_than(recent_cutoff)
    archived_count = count_archived_events()

    %{
      total_events: old_count + medium_count + recent_count,
      events_to_archive: old_count,
      events_to_sample: medium_count,
      recent_events: recent_count,
      archived_events: archived_count,
      retention_days: retention_days(),
      archive_enabled: archive_enabled?(),
      sampling_enabled: sampling_enabled?(),
      sampling_rate: sampling_rate()
    }
  end

  # ============================================================================
  # Private - Archival
  # ============================================================================

  defp archive_old_events(stats, retention_days, dry_run) do
    cutoff = DateTime.add(DateTime.utc_now(), -retention_days * 86400, :second)

    Logger.info("[ArchiveEventsWorker] Archiving events older than #{retention_days} days (cutoff: #{cutoff})")

    if dry_run do
      count = count_events_older_than(cutoff)
      Logger.info("[ArchiveEventsWorker] Dry run: would archive #{count} events")
      %{stats | archived: count}
    else
      case archive_events_batch(cutoff) do
        {:ok, archived_count} ->
          %{stats | archived: archived_count}

        {:error, reason} ->
          Logger.error("[ArchiveEventsWorker] Archival failed: #{inspect(reason)}")
          %{stats | errors: stats.errors + 1}
      end
    end
  end

  defp archive_events_batch(cutoff) do
    batch_size = archive_batch_size()

    # Process in batches to avoid overwhelming the database
    result =
      Stream.repeatedly(fn -> archive_single_batch(cutoff, batch_size) end)
      |> Enum.take_while(fn count -> count > 0 end)
      |> Enum.sum()

    {:ok, result}
  rescue
    e ->
      {:error, e}
  end

  defp archive_single_batch(cutoff, batch_size) do
    Repo.transaction(fn ->
      # Select batch of events to archive
      events_query =
        from e in Event,
          where: e.timestamp < ^cutoff and e.archived == false,
          limit: ^batch_size,
          select: e

      events = Repo.all(events_query)

      if Enum.empty?(events) do
        0
      else
        # Copy to archive table
        archive_entries =
          Enum.map(events, fn event ->
            %{
              id: event.id,
              agent_id: event.agent_id,
              event_type: event.event_type,
              timestamp: event.timestamp,
              payload: event.payload,
              severity: event.severity,
              sha256: event.sha256,
              enrichment: event.enrichment,
              detections: Map.get(event, :detections, []),
              created_at: event.created_at,
              archived_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
            }
          end)

        case Repo.insert_all("events_archive", archive_entries, on_conflict: :nothing) do
          {inserted_count, _} ->
            # Mark original events as archived
            event_ids = Enum.map(events, & &1.id)

            from(e in Event, where: e.id in ^event_ids)
            |> Repo.update_all(set: [archived: true])

            Logger.debug("[ArchiveEventsWorker] Archived batch of #{inserted_count} events")
            inserted_count

          _ ->
            Logger.warning("[ArchiveEventsWorker] Failed to insert archive batch")
            0
        end
      end
    end)
    |> case do
      {:ok, count} -> count
      {:error, reason} ->
        Logger.error("[ArchiveEventsWorker] Batch archival transaction failed: #{inspect(reason)}")
        0
    end
  end

  # ============================================================================
  # Private - Sampling
  # ============================================================================

  defp sample_medium_age_events(stats, sampling_age_days, dry_run) do
    if sampling_enabled?() do
      cutoff_start = DateTime.add(DateTime.utc_now(), -sampling_age_days * 86400, :second)
      cutoff_end = DateTime.add(DateTime.utc_now(), -retention_days() * 86400, :second)

      Logger.info(
        "[ArchiveEventsWorker] Sampling events between #{sampling_age_days}-#{retention_days()} days old"
      )

      if dry_run do
        count = count_events_between(cutoff_end, cutoff_start)
        sampled_count = round(count * (1 - sampling_rate()))
        Logger.info("[ArchiveEventsWorker] Dry run: would sample #{sampled_count} of #{count} events")
        %{stats | sampled: sampled_count, kept: count - sampled_count}
      else
        case sample_events_batch(cutoff_start, cutoff_end) do
          {:ok, sampled_count, kept_count} ->
            %{stats | sampled: sampled_count, kept: kept_count}

          {:error, reason} ->
            Logger.error("[ArchiveEventsWorker] Sampling failed: #{inspect(reason)}")
            %{stats | errors: stats.errors + 1}
        end
      end
    else
      Logger.info("[ArchiveEventsWorker] Sampling disabled, skipping")
      stats
    end
  end

  defp sample_events_batch(cutoff_start, cutoff_end) do
    batch_size = archive_batch_size()
    sampling_rate = sampling_rate()

    # Process in batches
    {sampled, kept} =
      Stream.repeatedly(fn -> sample_single_batch(cutoff_start, cutoff_end, batch_size, sampling_rate) end)
      |> Enum.take_while(fn {sampled, kept} -> sampled + kept > 0 end)
      |> Enum.reduce({0, 0}, fn {s, k}, {total_s, total_k} -> {total_s + s, total_k + k} end)

    {:ok, sampled, kept}
  rescue
    e -> {:error, e}
  end

  defp sample_single_batch(cutoff_start, cutoff_end, batch_size, sampling_rate) do
    Repo.transaction(fn ->
      # Get batch of medium-age events that haven't been sampled yet
      events_query =
        from e in Event,
          where:
            e.timestamp >= ^cutoff_end and
            e.timestamp < ^cutoff_start and
            e.sampled == false and
            e.archived == false,
          limit: ^batch_size,
          select: e

      events = Repo.all(events_query)

      if Enum.empty?(events) do
        {0, 0}
      else
        # Classify events into high-value (keep) and low-value (sample)
        {high_value, low_value} = Enum.split_with(events, &EventSampler.high_value_event?/1)

        # Keep all high-value events
        high_value_ids = Enum.map(high_value, & &1.id)

        if length(high_value_ids) > 0 do
          from(e in Event, where: e.id in ^high_value_ids)
          |> Repo.update_all(set: [sampled: true])
        end

        # Sample low-value events
        {to_keep, to_drop} = EventSampler.sample_events(low_value, sampling_rate)

        to_keep_ids = Enum.map(to_keep, & &1.id)
        to_drop_ids = Enum.map(to_drop, & &1.id)

        # Mark kept events as sampled
        if length(to_keep_ids) > 0 do
          from(e in Event, where: e.id in ^to_keep_ids)
          |> Repo.update_all(set: [sampled: true])
        end

        # Delete dropped events
        if length(to_drop_ids) > 0 do
          from(e in Event, where: e.id in ^to_drop_ids)
          |> Repo.delete_all()
        end

        sampled_count = length(to_drop)
        kept_count = length(high_value) + length(to_keep)

        Logger.debug(
          "[ArchiveEventsWorker] Sampled batch: kept=#{kept_count}, dropped=#{sampled_count}"
        )

        {sampled_count, kept_count}
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, reason} ->
        Logger.error("[ArchiveEventsWorker] Batch sampling transaction failed: #{inspect(reason)}")
        {0, 0}
    end
  end

  # ============================================================================
  # Private - Helpers
  # ============================================================================

  defp count_events_older_than(cutoff) do
    from(e in Event, where: e.timestamp < ^cutoff and e.archived == false)
    |> Repo.aggregate(:count)
  end

  defp count_events_between(start_time, end_time) do
    from(e in Event,
      where: e.timestamp >= ^start_time and e.timestamp < ^end_time and e.archived == false
    )
    |> Repo.aggregate(:count)
  end

  defp count_events_newer_than(cutoff) do
    from(e in Event, where: e.timestamp >= ^cutoff and e.archived == false)
    |> Repo.aggregate(:count)
  end

  defp count_archived_events do
    Repo.aggregate("events_archive", :count)
  rescue
    _ -> 0
  end

  defp report_stats(stats) do
    try do
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "event_archival",
        {:archival_stats, stats}
      )
    rescue
      _ -> :ok
    end
  end

  # ============================================================================
  # Private - Configuration
  # ============================================================================

  defp retention_days do
    config = Application.get_env(:tamandua_server, TamanduaServer.Telemetry, [])
    Keyword.get(config, :event_retention_days, 30)
  end

  defp archive_enabled? do
    config = Application.get_env(:tamandua_server, TamanduaServer.Telemetry, [])
    Keyword.get(config, :archive_enabled, true)
  end

  defp sampling_enabled? do
    config = Application.get_env(:tamandua_server, TamanduaServer.Telemetry, [])
    Keyword.get(config, :event_sampling_enabled, true)
  end

  defp sampling_rate do
    config = Application.get_env(:tamandua_server, TamanduaServer.Telemetry, [])
    Keyword.get(config, :event_sampling_rate, 0.1)
  end

  defp archive_batch_size do
    config = Application.get_env(:tamandua_server, TamanduaServer.Telemetry, [])
    Keyword.get(config, :archive_batch_size, 5000)
  end
end
