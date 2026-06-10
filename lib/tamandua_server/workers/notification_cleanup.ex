defmodule TamanduaServer.Workers.NotificationCleanup do
  @moduledoc """
  Oban worker for cleaning up expired notifications.
  Runs daily to remove notifications past their expiry date.
  """
  use Oban.Worker,
    queue: :maintenance,
    max_attempts: 3

  require Logger

  alias TamanduaServer.NotificationCenter

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    Logger.info("[NotificationCleanup] Starting notification cleanup")

    case NotificationCenter.cleanup_expired_notifications() do
      {:ok, count} ->
        Logger.info("[NotificationCleanup] Cleaned up #{count} expired notifications")
        :ok

      {:error, reason} ->
        Logger.error("[NotificationCleanup] Cleanup failed: #{inspect(reason)}")
        {:error, reason}
    end
  end
end
