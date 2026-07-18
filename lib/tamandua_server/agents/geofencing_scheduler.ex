defmodule TamanduaServer.Agents.GeofencingScheduler do
  @moduledoc """
  Scheduled tasks for geofencing maintenance.

  Tasks:
  - Expire old travel requests (daily)
  - Clean up old location history (daily)
  - Refresh GeoIP database (weekly)
  - Generate geofencing reports (daily)
  """
  use GenServer
  require Logger

  alias TamanduaServer.Agents.{TravelManager}

  def start_link(_) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @impl true
  def init(state) do
    # Schedule initial tasks
    schedule_expire_travel()
    schedule_cleanup_locations()
    schedule_daily_report()

    {:ok, state}
  end

  @impl true
  def handle_info(:expire_travel, state) do
    Logger.info("Running scheduled task: expire_travel")

    case TravelManager.expire_old_requests() do
      {:ok, count} ->
        Logger.info("Expired #{count} travel requests")

      {:error, reason} ->
        Logger.error("Failed to expire travel requests: #{inspect(reason)}")
    end

    # Schedule next run (every 24 hours)
    schedule_expire_travel()
    {:noreply, state}
  end

  def handle_info(:cleanup_locations, state) do
    Logger.info("Running scheduled task: cleanup_locations")

    case cleanup_old_locations() do
      {:ok, count} ->
        Logger.info("Cleaned up #{count} old location records")

      {:error, reason} ->
        Logger.error("Failed to cleanup locations: #{inspect(reason)}")
    end

    # Schedule next run (every 24 hours)
    schedule_cleanup_locations()
    {:noreply, state}
  end

  def handle_info(:daily_report, state) do
    Logger.info("Running scheduled task: daily_report")

    case generate_daily_report() do
      {:ok, report} ->
        Logger.info("Generated daily geofencing report: #{inspect(report)}")

      {:error, reason} ->
        Logger.error("Failed to generate daily report: #{inspect(reason)}")
    end

    # Schedule next run (every 24 hours)
    schedule_daily_report()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp schedule_expire_travel do
    # Run every 24 hours
    Process.send_after(self(), :expire_travel, :timer.hours(24))
  end

  defp schedule_cleanup_locations do
    # Run every 24 hours
    Process.send_after(self(), :cleanup_locations, :timer.hours(24))
  end

  defp schedule_daily_report do
    # Run every 24 hours at midnight (roughly)
    Process.send_after(self(), :daily_report, :timer.hours(24))
  end

  defp cleanup_old_locations do
    # This is handled per-agent in LocationTracker
    # Could be enhanced to run globally here
    {:ok, 0}
  end

  defp generate_daily_report do
    # Get statistics for last 24 hours
    # This could be expanded to send email reports, etc.
    {:ok, %{
      generated_at: DateTime.utc_now(),
      stats: "Daily geofencing report"
    }}
  end
end
