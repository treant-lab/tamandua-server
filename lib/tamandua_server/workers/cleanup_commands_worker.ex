defmodule TamanduaServer.Workers.CleanupCommandsWorker do
  @moduledoc """
  Oban worker for periodic cleanup of expired and old agent commands.

  This job:
  1. Marks expired commands (past expires_at) as failed
  2. Deletes completed/failed commands older than 7 days
  3. Reports statistics on command queue health

  ## Schedule

  Configured via Oban Cron plugin in config.exs:

      {"*/30 * * * *", TamanduaServer.Workers.CleanupCommandsWorker}

  This runs every 30 minutes.
  """

  use Oban.Worker,
    queue: :default,
    max_attempts: 3,
    unique: [period: 1800]  # Prevent duplicate jobs within 30 minutes

  require Logger

  alias TamanduaServer.Agents.AgentCommand
  alias TamanduaServer.Repo

  import Ecto.Query

  @retention_days 7

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    Logger.info("[CleanupCommandsWorker] Starting agent command cleanup")
    start_time = System.monotonic_time(:millisecond)

    retention_days = Map.get(args, "retention_days", @retention_days)

    # Step 1: Mark expired commands as failed
    expired_count = mark_expired_commands()

    # Step 2: Delete old completed/failed commands
    deleted_count = delete_old_commands(retention_days)

    # Step 3: Report queue health statistics
    stats = collect_queue_stats()

    elapsed = System.monotonic_time(:millisecond) - start_time

    Logger.info(
      "[CleanupCommandsWorker] Cleanup complete in #{elapsed}ms: " <>
        "expired #{expired_count}, deleted #{deleted_count}"
    )

    # Broadcast stats via PubSub for monitoring
    report_stats(%{
      expired: expired_count,
      deleted: deleted_count,
      stats: stats,
      elapsed_ms: elapsed,
      timestamp: DateTime.utc_now()
    })

    :ok
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp mark_expired_commands do
    expired_commands = AgentCommand.expired_commands()

    {count, _} =
      Repo.update_all(
        expired_commands,
        set: [
          status: "failed",
          error: "Command expired",
          completed_at: DateTime.utc_now(),
          updated_at: DateTime.utc_now()
        ]
      )

    if count > 0 do
      Logger.info("[CleanupCommandsWorker] Marked #{count} expired commands as failed")
    end

    count
  end

  defp delete_old_commands(retention_days) do
    old_commands = AgentCommand.completed_older_than(retention_days)

    {count, _} = Repo.delete_all(old_commands)

    if count > 0 do
      Logger.info(
        "[CleanupCommandsWorker] Deleted #{count} commands older than #{retention_days} days"
      )
    end

    count
  end

  defp collect_queue_stats do
    # Count commands by status
    status_counts =
      from(c in AgentCommand,
        group_by: c.status,
        select: {c.status, count(c.id)}
      )
      |> Repo.all()
      |> Map.new()

    # Average time from creation to completion for recently completed commands
    avg_completion_time =
      from(c in AgentCommand,
        where: c.status == "completed",
        where: not is_nil(c.completed_at),
        where: c.completed_at > ago(1, "day"),
        select:
          avg(
            fragment(
              "EXTRACT(EPOCH FROM (? - ?))",
              c.completed_at,
              c.inserted_at
            )
          )
      )
      |> Repo.one()

    # Commands stuck in sent/acknowledged for >30 minutes
    stuck_count =
      from(c in AgentCommand,
        where: c.status in ["sent", "acknowledged"],
        where: c.updated_at < ago(30, "minute")
      )
      |> Repo.aggregate(:count)

    %{
      by_status: status_counts,
      avg_completion_seconds: if(avg_completion_time, do: Float.round(avg_completion_time, 2), else: nil),
      stuck_commands: stuck_count
    }
  end

  defp report_stats(stats) do
    try do
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agent_commands",
        {:cleanup_stats, stats}
      )
    rescue
      e ->
        Logger.warning("[CleanupCommandsWorker] Failed to broadcast stats: #{inspect(e)}")
        :ok
    end
  end
end
