defmodule TamanduaServer.Workers.CommentDigestWorker do
  @moduledoc """
  Oban worker for sending daily comment digest emails.
  Runs daily at 8 AM local time.
  """

  use Oban.Worker,
    queue: :notifications,
    max_attempts: 3

  alias TamanduaServer.Notifications.CommentNotifier

  require Logger

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    Logger.info("Starting daily comment digest job")

    case CommentNotifier.send_daily_digest() do
      :ok ->
        Logger.info("Daily comment digest sent successfully")
        :ok

      {:error, reason} ->
        Logger.error("Failed to send daily comment digest: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Schedules the daily digest job.
  Should be called from Application.start/2 or a scheduler.
  """
  def schedule_daily_digest do
    # Schedule to run daily at 8 AM
    %{cron: "0 8 * * *"}
    |> Oban.insert()
    |> case do
      {:ok, _job} ->
        Logger.info("Scheduled daily comment digest job")
        :ok

      {:error, reason} ->
        Logger.error("Failed to schedule daily comment digest: #{inspect(reason)}")
        {:error, reason}
    end
  end
end
