defmodule TamanduaServer.Workers.DigestWorker do
  @moduledoc """
  Periodic alert digest worker.

  Runs every 15 minutes (configurable) to:
  1. Collect unnotified alerts
  2. Group by severity and organization
  3. Send digest notifications to users with digest mode enabled
  4. Mark alerts as notified
  """

  use Oban.Worker,
    queue: :notifications,
    max_attempts: 3

  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Notifier
  alias TamanduaServer.Alerts.Notifier.Preferences

  @impl Oban.Worker
  def perform(_job) do
    Logger.info("[DigestWorker] Starting digest processing")

    # Get users with digest enabled
    users = Preferences.get_digest_users()

    if Enum.empty?(users) do
      Logger.debug("[DigestWorker] No users with digest enabled")
      :ok
    else
      # Group users by organization
      users_by_org = Enum.group_by(users, & &1.organization_id)

      results = Enum.map(users_by_org, fn {org_id, org_users} ->
        process_organization_digest(org_id, org_users)
      end)

      success_count = Enum.count(results, &match?({:ok, _}, &1))
      Logger.info("[DigestWorker] Completed: #{success_count}/#{length(results)} organizations")

      :ok
    end
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp process_organization_digest(org_id, users) do
    # Get unnotified alerts from the last digest period
    digest_period_minutes = Application.get_env(:tamandua_server, :digest_period_minutes, 15)
    cutoff = DateTime.utc_now() |> DateTime.add(-digest_period_minutes * 60, :second)

    alerts = get_unnotified_alerts(org_id, cutoff)

    if Enum.empty?(alerts) do
      Logger.debug("[DigestWorker] No unnotified alerts for org #{org_id}")
      {:ok, :no_alerts}
    else
      Logger.info("[DigestWorker] Sending digest for org #{org_id}: #{length(alerts)} alert(s)")

      # Send digest notification
      result = Notifier.send_digest(alerts, users)

      # Mark alerts as notified (prevent re-sending in next digest)
      mark_alerts_notified(alerts)

      result
    end
  end

  defp get_unnotified_alerts(org_id, cutoff) do
    # Query for recent alerts that haven't been notified via digest yet
    # This would ideally use a `notified_at` field on alerts, but we can
    # approximate by checking if they're new/investigating and recent

    Alerts.list_alerts_for_org(org_id,
      status: ["new", "investigating"],
      limit: 100
    )
    |> Enum.filter(fn alert ->
      DateTime.compare(alert.inserted_at, cutoff) in [:gt, :eq]
    end)
    |> Enum.sort_by(& &1.inserted_at, {:desc, DateTime})
  end

  defp mark_alerts_notified(alerts) do
    # In a production system, you'd update a `last_notified_at` field
    # For now, we rely on the NotificationDedup system to track this
    Enum.each(alerts, fn alert ->
      TamanduaServer.Alerts.NotificationDedup.record_notification(alert)
    end)
  end
end
