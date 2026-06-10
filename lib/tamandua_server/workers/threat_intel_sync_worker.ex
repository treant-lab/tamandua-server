defmodule TamanduaServer.Workers.ThreatIntelSyncWorker do
  @moduledoc """
  Oban worker that periodically syncs threat intelligence feeds.

  Calls TamanduaServer.Detection.ThreatIntelFeeds.sync_all() on a schedule
  and logs the results (new IOCs ingested, errors per feed).

  ## Schedule

  Configured via Oban Cron plugin in config.exs:

      {"0 */4 * * *", TamanduaServer.Workers.ThreatIntelSyncWorker}

  This runs every 4 hours at the top of the hour.

  ## Retry Policy

  - Max 3 attempts
  - On failure, Oban retries with exponential backoff
  - The unique constraint prevents overlapping sync jobs within a 2-hour window

  ## Manual Trigger

      TamanduaServer.Workers.ThreatIntelSyncWorker.enqueue_sync()
  """

  use Oban.Worker,
    queue: :threat_intel,
    max_attempts: 3,
    unique: [period: 7200]

  alias TamanduaServer.Detection.ThreatIntelFeeds

  require Logger

  @impl Oban.Worker
  def perform(%Oban.Job{args: args, attempt: attempt}) do
    manual = Map.get(args, "manual", false)
    source = if manual, do: "manual trigger", else: "scheduled cron"

    Logger.info("[ThreatIntelSyncWorker] Starting threat intel feed sync (#{source}, attempt #{attempt})")

    try do
      # Trigger the GenServer to sync all feeds
      ThreatIntelFeeds.sync_all()

      # Wait briefly for the async sync to start, then check status
      Process.sleep(2_000)
      status = ThreatIntelFeeds.get_status()

      sync_status = status[:sync_status] || %{}
      total_feeds = map_size(sync_status)

      {ok_feeds, error_feeds} = Enum.split_with(sync_status, fn {_name, info} ->
        info[:status] == :ok
      end)

      ok_count = length(ok_feeds)
      error_count = length(error_feeds)

      total_iocs_ingested = Enum.reduce(ok_feeds, 0, fn {_name, info}, acc ->
        acc + (info[:inserted] || 0)
      end)

      Logger.info(
        "[ThreatIntelSyncWorker] Sync dispatched: " <>
        "#{ok_count}/#{total_feeds} feeds ok, " <>
        "#{error_count} errors, " <>
        "#{total_iocs_ingested} new IOCs from last sync, " <>
        "#{status[:total_iocs] || 0} total IOCs in database"
      )

      # Log individual feed errors for debugging
      Enum.each(error_feeds, fn {name, info} ->
        Logger.warning("[ThreatIntelSyncWorker] Feed #{name} error: #{info[:error]}")
      end)

      :ok
    rescue
      e ->
        Logger.error("[ThreatIntelSyncWorker] Sync failed: #{Exception.message(e)}")

        if attempt < 3 do
          Logger.info("[ThreatIntelSyncWorker] Will retry (attempt #{attempt}/3)")
          {:error, Exception.message(e)}
        else
          Logger.error("[ThreatIntelSyncWorker] All #{attempt} attempts exhausted, giving up")
          :ok
        end
    end
  end

  @doc """
  Enqueue an immediate sync job (manual trigger).

  Returns `{:ok, %Oban.Job{}}` or `{:error, reason}`.
  """
  @spec enqueue_sync() :: {:ok, Oban.Job.t()} | {:error, term()}
  def enqueue_sync do
    %{"manual" => true}
    |> __MODULE__.new()
    |> Oban.insert()
  end
end
