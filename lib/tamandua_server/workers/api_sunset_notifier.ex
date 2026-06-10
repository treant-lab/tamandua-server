defmodule TamanduaServer.Workers.APISunsetNotifier do
  @moduledoc """
  Oban worker that sends API sunset notifications to consumers.

  Runs daily to check for upcoming API version sunsets and sends email notifications
  to consumers at specific intervals before the sunset date:

  - 90 days before sunset
  - 60 days before sunset
  - 30 days before sunset
  - 14 days before sunset
  - 7 days before sunset
  - 3 days before sunset
  - 1 day before sunset
  """

  use Oban.Worker,
    queue: :notifications,
    max_attempts: 3

  require Logger

  alias TamanduaServerWeb.API.{VersionNegotiator, DeprecationWarner}
  alias TamanduaServer.Analytics.APIUsageTracker

  @notification_intervals [90, 60, 30, 14, 7, 3, 1]

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"version" => version_str}}) do
    version = String.to_existing_atom(version_str)
    sunset_date = VersionNegotiator.sunset_date(version)

    if sunset_date do
      days_until_sunset = Date.diff(sunset_date, Date.utc_today())

      if days_until_sunset in @notification_intervals do
        Logger.info("Sending sunset notifications for #{version}, #{days_until_sunset} days until sunset")

        case DeprecationWarner.send_sunset_notifications(version, days_until_sunset) do
          {:ok, count} ->
            Logger.info("Sent sunset notifications to #{count} consumers for #{version}")
            {:ok, %{notifications_sent: count}}

          {:error, reason} ->
            Logger.error("Failed to send sunset notifications: #{inspect(reason)}")
            {:error, reason}
        end
      else
        Logger.debug("No sunset notifications needed for #{version} (#{days_until_sunset} days until sunset)")
        {:ok, %{notifications_sent: 0}}
      end
    else
      Logger.warning("No sunset date configured for version #{version}")
      {:ok, %{notifications_sent: 0}}
    end
  end

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"action" => "check_all_versions"}}) do
    # Check all deprecated versions and send notifications
    deprecated_versions = VersionNegotiator.supported_versions()
      |> Enum.filter(&VersionNegotiator.deprecated?/1)

    results = Enum.map(deprecated_versions, fn version ->
      sunset_date = VersionNegotiator.sunset_date(version)
      days_until_sunset = Date.diff(sunset_date, Date.utc_today())

      if days_until_sunset in @notification_intervals do
        case DeprecationWarner.send_sunset_notifications(version, days_until_sunset) do
          {:ok, count} ->
            Logger.info("Sent #{count} sunset notifications for #{version}")
            {version, count}

          {:error, reason} ->
            Logger.error("Failed to send sunset notifications for #{version}: #{inspect(reason)}")
            {version, 0}
        end
      else
        {version, 0}
      end
    end)

    total_sent = Enum.reduce(results, 0, fn {_version, count}, acc -> acc + count end)

    {:ok, %{total_notifications_sent: total_sent, results: results}}
  end

  @doc """
  Schedules sunset notification checks for all deprecated versions.
  Should be called once per day via cron.
  """
  def schedule_daily_check do
    %{action: "check_all_versions"}
    |> __MODULE__.new(schedule_in: {0, :seconds})
    |> Oban.insert()
  end

  @doc """
  Schedules a sunset notification check for a specific version.
  """
  def schedule_version_check(version) when is_atom(version) do
    %{version: Atom.to_string(version)}
    |> __MODULE__.new()
    |> Oban.insert()
  end
end
