defmodule TamanduaServer.NotificationCenter.Channels.SlackWorker do
  @moduledoc """
  Oban worker for sending Slack notifications.
  """
  use Oban.Worker,
    queue: :notifications,
    max_attempts: 3

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.NotificationCenter.{Notification, NotificationDelivery}

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"delivery_id" => delivery_id}}) do
    delivery = Repo.get!(NotificationDelivery, delivery_id) |> Repo.preload(:notification)
    notification = Repo.preload(delivery.notification, :user)

    # Get Slack webhook URL from organization settings or user metadata
    webhook_url =
      get_slack_webhook(notification.organization_id) ||
        get_user_slack_webhook(notification.user)

    case webhook_url do
      nil ->
        delivery
        |> NotificationDelivery.failed_changeset("No Slack webhook configured")
        |> Repo.update()

        {:error, "No Slack webhook"}

      url ->
        send_slack_message(delivery, notification, url)
    end
  end

  defp send_slack_message(delivery, notification, webhook_url) do
    payload = build_slack_payload(notification)

    case HTTPoison.post(webhook_url, Jason.encode!(payload), [
           {"Content-Type", "application/json"}
         ]) do
      {:ok, %{status_code: code}} when code in 200..299 ->
        delivery
        |> NotificationDelivery.sent_changeset(%{status_code: code})
        |> Repo.update()

        Logger.info("[SlackWorker] Slack message sent")
        :ok

      {:ok, %{status_code: code, body: body}} ->
        delivery
        |> NotificationDelivery.failed_changeset("HTTP #{code}: #{body}")
        |> Repo.update()

        Logger.error("[SlackWorker] Failed to send Slack message: HTTP #{code}")
        {:error, "HTTP #{code}"}

      {:error, %{reason: reason}} ->
        delivery
        |> NotificationDelivery.failed_changeset(reason)
        |> Repo.update()

        Logger.error("[SlackWorker] Failed to send Slack message: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp build_slack_payload(notification) do
    color = priority_color(notification.priority)
    alert_url = build_alert_url(notification)

    %{
      text: notification.title,
      attachments: [
        %{
          color: color,
          fields: [
            %{
              title: "Priority",
              value: String.upcase(notification.priority),
              short: true
            },
            %{
              title: "Type",
              value: format_type(notification.type),
              short: true
            },
            %{
              title: "Details",
              value: notification.body || "_No details_",
              short: false
            }
          ],
          actions: [
            %{
              type: "button",
              text: "View in Tamandua",
              url: alert_url
            }
          ],
          footer: "Tamandua EDR",
          ts: DateTime.to_unix(notification.inserted_at)
        }
      ]
    }
  end

  defp priority_color("critical"), do: "#dc2626"
  defp priority_color("high"), do: "#f59e0b"
  defp priority_color("normal"), do: "#3b82f6"
  defp priority_color("low"), do: "#6b7280"

  defp format_type(type) do
    type
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp build_alert_url(%{related_resource_type: "alert", related_resource_id: alert_id}) do
    "#{TamanduaServerWeb.Endpoint.url()}/alerts/#{alert_id}"
  end

  defp build_alert_url(_), do: TamanduaServerWeb.Endpoint.url()

  defp get_slack_webhook(organization_id) do
    # Get from organization settings or notification integrations
    case TamanduaServer.Settings.get_setting("slack_webhook_url", organization_id) do
      {:ok, url} -> url
      _ -> nil
    end
  end

  defp get_user_slack_webhook(user) do
    # Check if user has personal Slack webhook in metadata
    get_in(user.metadata || %{}, ["slack_webhook_url"])
  end
end
