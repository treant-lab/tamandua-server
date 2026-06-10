defmodule TamanduaServer.Workers.CleanupWorker do
  @moduledoc """
  Generic maintenance worker used by the default Oban cron configuration.

  Keep this worker conservative: it should not fail application boot if a
  subsystem cleanup is unavailable in a given deployment profile.
  """

  use Oban.Worker,
    queue: :maintenance,
    max_attempts: 1,
    unique: [period: 3600]

  require Logger

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    Logger.info("[CleanupWorker] Starting scheduled maintenance cleanup")

    results = %{
      notifications: cleanup_notifications(),
      commands: cleanup_commands(args)
    }

    Logger.info("[CleanupWorker] Completed scheduled maintenance cleanup: #{inspect(results)}")
    :ok
  end

  defp cleanup_notifications do
    if Code.ensure_loaded?(TamanduaServer.NotificationCenter) and
         function_exported?(TamanduaServer.NotificationCenter, :cleanup_expired_notifications, 0) do
      TamanduaServer.NotificationCenter.cleanup_expired_notifications()
    else
      :skipped
    end
  rescue
    error ->
      Logger.warning("[CleanupWorker] Notification cleanup failed: #{inspect(error)}")
      {:error, error}
  end

  defp cleanup_commands(args) do
    if Code.ensure_loaded?(TamanduaServer.Workers.CleanupCommandsWorker) do
      TamanduaServer.Workers.CleanupCommandsWorker.perform(%Oban.Job{args: args || %{}})
    else
      :skipped
    end
  rescue
    error ->
      Logger.warning("[CleanupWorker] Command cleanup failed: #{inspect(error)}")
      {:error, error}
  end
end
