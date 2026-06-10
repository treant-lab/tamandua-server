defmodule TamanduaServer.Workers.ShareCleanupWorker do
  @moduledoc """
  Background worker that periodically cleans up expired dashboard shares.
  Runs every hour to deactivate shares that have passed their expiry date.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Dashboard

  @cleanup_interval :timer.hours(1)

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    # Schedule first cleanup
    schedule_cleanup()

    Logger.info("ShareCleanupWorker started")

    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    Logger.debug("Running share cleanup job")

    case Dashboard.cleanup_expired_shares() do
      {count, _} when count > 0 ->
        Logger.info("Deactivated #{count} expired dashboard shares")

      {0, _} ->
        Logger.debug("No expired shares to clean up")

      error ->
        Logger.error("Share cleanup failed: #{inspect(error)}")
    end

    # Schedule next cleanup
    schedule_cleanup()

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  # Public API for manual triggering

  @doc """
  Manually triggers a cleanup run.
  """
  def trigger_cleanup do
    send(__MODULE__, :cleanup)
  end
end
