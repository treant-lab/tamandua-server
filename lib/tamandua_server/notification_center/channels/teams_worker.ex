defmodule TamanduaServer.NotificationCenter.Channels.TeamsWorker do
  @moduledoc """
  Oban worker for sending Microsoft Teams notifications.
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

    # Get Teams webhook URL
    webhook_url = get_teams_webhook(notification.organization_id)

    case webhook_url do
      nil ->
        delivery
        |> NotificationDelivery.failed_changeset("No Teams webhook configured")
        |> Repo.update()

        {:error, "No Teams webhook"}

      url ->
        send_teams_message(delivery, notification, url)
    end
  end

  defp send_teams_message(delivery, notification, webhook_url) do
    payload = build_teams_payload(notification)

    case HTTPoison.post(webhook_url, Jason.encode!(payload), [
           {"Content-Type", "application/json"}
         ]) do
      {:ok, %{status_code: code}} when code in 200..299 ->
        delivery
        |> NotificationDelivery.sent_changeset(%{status_code: code})
        |> Repo.update()

        Logger.info("[TeamsWorker] Teams message sent")
        :ok

      {:ok, %{status_code: code, body: body}} ->
        delivery
        |> NotificationDelivery.failed_changeset("HTTP #{code}: #{body}")
        |> Repo.update()

        Logger.error("[TeamsWorker] Failed to send Teams message: HTTP #{code}")
        {:error, "HTTP #{code}"}

      {:error, %{reason: reason}} ->
        delivery
        |> NotificationDelivery.failed_changeset(reason)
        |> Repo.update()

        Logger.error("[TeamsWorker] Failed to send Teams message: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp build_teams_payload(notification) do
    color = priority_color(notification.priority)
    alert_url = build_alert_url(notification)

    # Adaptive Card format for Teams
    %{
      "@type" => "MessageCard",
      "@context" => "https://schema.org/extensions",
      summary: notification.title,
      themeColor: color,
      title: notification.title,
      sections: [
        %{
          facts: [
            %{
              name: "Priority",
              value: String.upcase(notification.priority)
            },
            %{
              name: "Type",
              value: format_type(notification.type)
            },
            %{
              name: "Time",
              value: format_datetime(notification.inserted_at)
            }
          ],
          text: notification.body || "_No details_"
        }
      ],
      potentialAction: [
        %{
          "@type" => "OpenUri",
          name: "View in Tamandua",
          targets: [
            %{
              os: "default",
              uri: alert_url
            }
          ]
        }
      ]
    }
  end

  defp priority_color("critical"), do: "dc2626"
  defp priority_color("high"), do: "f59e0b"
  defp priority_color("normal"), do: "3b82f6"
  defp priority_color("low"), do: "6b7280"

  defp format_type(type) do
    type
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp build_alert_url(%{related_resource_type: "alert", related_resource_id: alert_id}) do
    "#{TamanduaServerWeb.Endpoint.url()}/alerts/#{alert_id}"
  end

  defp build_alert_url(_), do: TamanduaServerWeb.Endpoint.url()

  defp get_teams_webhook(organization_id) do
    case TamanduaServer.Settings.get_setting("teams_webhook_url", organization_id) do
      {:ok, url} -> url
      _ -> nil
    end
  end
end
