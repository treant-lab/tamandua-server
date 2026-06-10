defmodule TamanduaServer.Notifications.DeliveryWorker do
  @moduledoc """
  Oban worker for async notification delivery.

  Handles retry logic and error tracking for notification delivery.
  """

  use Oban.Worker,
    queue: :notifications,
    max_attempts: 3,
    unique: [period: 60, fields: [:args], keys: [:integration_id, :alert_id]]

  require Logger

  alias TamanduaServer.Notifications
  alias TamanduaServer.Repo

  @impl Oban.Worker
  def perform(%Oban.Job{args: args, attempt: attempt}) do
    %{
      "integration_id" => integration_id,
      "alert_id" => alert_id,
      "organization_id" => organization_id
    } = args

    Logger.debug("[DeliveryWorker] Processing notification (attempt #{attempt})")

    # Load integration and alert
    with {:ok, integration} <- load_integration(integration_id, organization_id),
         {:ok, alert} <- load_alert(alert_id),
         {:ok, agent} <- load_agent(alert.agent_id) do
      # Send notification
      case Notifications.send_notification_now(integration, alert, agent) do
        {:ok, _} ->
          Logger.info("[DeliveryWorker] Successfully sent notification for alert #{alert_id}")
          :ok

        {:error, :throttled} ->
          Logger.warning("[DeliveryWorker] Notification throttled for alert #{alert_id}")
          :ok  # Don't retry throttled notifications

        {:error, reason} ->
          Logger.error("[DeliveryWorker] Failed to send notification: #{inspect(reason)}")
          {:error, reason}
      end
    else
      {:error, :integration_not_found} ->
        Logger.error("[DeliveryWorker] Integration #{integration_id} not found")
        {:cancel, "Integration not found"}

      {:error, :alert_not_found} ->
        Logger.error("[DeliveryWorker] Alert #{alert_id} not found")
        {:cancel, "Alert not found"}

      {:error, reason} ->
        Logger.error("[DeliveryWorker] Error loading data: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # Private helpers

  defp load_integration(integration_id, organization_id) do
    case Notifications.get_integration!(integration_id, organization_id) do
      nil -> {:error, :integration_not_found}
      integration -> {:ok, integration}
    end
  rescue
    Ecto.NoResultsError -> {:error, :integration_not_found}
  end

  defp load_alert(alert_id) do
    case Repo.get(TamanduaServer.Alerts.Alert, alert_id) do
      nil -> {:error, :alert_not_found}
      alert -> {:ok, alert}
    end
  end

  defp load_agent(nil), do: {:ok, nil}

  defp load_agent(agent_id) do
    case Repo.get(TamanduaServer.Agents.Agent, agent_id) do
      nil -> {:ok, nil}  # Agent might have been deleted
      agent -> {:ok, agent}
    end
  end
end
