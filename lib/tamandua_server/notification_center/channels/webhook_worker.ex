defmodule TamanduaServer.NotificationCenter.Channels.WebhookWorker do
  @moduledoc """
  Oban worker for sending webhook notifications.
  """
  use Oban.Worker,
    queue: :notifications,
    max_attempts: 3

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.NotificationCenter.{
    NotificationDelivery,
    NotificationWebhook
  }

  import Ecto.Query

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"delivery_id" => delivery_id}}) do
    delivery = Repo.get!(NotificationDelivery, delivery_id) |> Repo.preload(:notification)
    notification = Repo.preload(delivery.notification, :user)

    # Get all webhooks that match this notification type
    webhooks = get_matching_webhooks(notification)

    if Enum.empty?(webhooks) do
      delivery
      |> NotificationDelivery.failed_changeset("No webhooks configured for this notification type")
      |> Repo.update()

      {:error, "No webhooks"}
    else
      # Send to all matching webhooks
      results =
        Enum.map(webhooks, fn webhook ->
          send_webhook(webhook, notification)
        end)

      # Update delivery based on results
      if Enum.any?(results, &match?(:ok, &1)) do
        delivery
        |> NotificationDelivery.sent_changeset(%{webhooks: length(webhooks)})
        |> Repo.update()

        :ok
      else
        delivery
        |> NotificationDelivery.failed_changeset("All webhooks failed")
        |> Repo.update()

        {:error, "All webhooks failed"}
      end
    end
  end

  defp get_matching_webhooks(notification) do
    NotificationWebhook
    |> where([w], w.organization_id == ^notification.organization_id)
    |> where([w], w.enabled == true)
    |> Repo.all()
    |> Enum.filter(fn webhook ->
      Enum.empty?(webhook.notification_types) or
        notification.type in webhook.notification_types
    end)
  end

  defp send_webhook(webhook, notification) do
    payload = build_payload(notification)
    headers = build_headers(webhook)

    case HTTPoison.request(
           String.to_atom(String.downcase(webhook.method)),
           webhook.url,
           Jason.encode!(payload),
           headers,
           timeout: 10_000,
           recv_timeout: 10_000
         ) do
      {:ok, %{status_code: code}} when code in 200..299 ->
        Logger.info("[WebhookWorker] Webhook sent to #{webhook.name}: HTTP #{code}")
        :ok

      {:ok, %{status_code: code, body: body}} ->
        Logger.error(
          "[WebhookWorker] Webhook failed for #{webhook.name}: HTTP #{code} - #{body}"
        )

        {:error, "HTTP #{code}"}

      {:error, %{reason: reason}} ->
        Logger.error("[WebhookWorker] Webhook failed for #{webhook.name}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp build_payload(notification) do
    %{
      id: notification.id,
      type: notification.type,
      title: notification.title,
      body: notification.body,
      priority: notification.priority,
      metadata: notification.metadata,
      related_resource_type: notification.related_resource_type,
      related_resource_id: notification.related_resource_id,
      user_id: notification.user_id,
      organization_id: notification.organization_id,
      timestamp: notification.inserted_at,
      alert_url: build_alert_url(notification)
    }
  end

  defp build_headers(webhook) do
    base_headers = [
      {"Content-Type", "application/json"},
      {"User-Agent", "Tamandua-EDR/1.0"}
    ]

    # Add custom headers
    custom_headers = Map.to_list(webhook.headers || %{})

    # Add authentication headers
    auth_headers = build_auth_headers(webhook)

    base_headers ++ custom_headers ++ auth_headers
  end

  defp build_auth_headers(%{auth_type: "basic", auth_config: config}) do
    username = config["username"]
    password = config["password"]
    credentials = Base.encode64("#{username}:#{password}")
    [{"Authorization", "Basic #{credentials}"}]
  end

  defp build_auth_headers(%{auth_type: "bearer", auth_config: config}) do
    token = config["token"]
    [{"Authorization", "Bearer #{token}"}]
  end

  defp build_auth_headers(%{auth_type: "api_key", auth_config: config}) do
    key = config["key"]
    value = config["value"]
    [{key, value}]
  end

  defp build_auth_headers(_), do: []

  defp build_alert_url(%{related_resource_type: "alert", related_resource_id: alert_id}) do
    "#{TamanduaServerWeb.Endpoint.url()}/alerts/#{alert_id}"
  end

  defp build_alert_url(_), do: TamanduaServerWeb.Endpoint.url()
end
