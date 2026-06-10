defmodule TamanduaServer.NotificationCenter.Channels.DiscordWorker do
  @moduledoc """
  Oban worker for sending Discord webhook notifications.

  Sends rich embeds to Discord channels via webhook URLs.
  Follows Discord's webhook API specification for embed formatting.

  ## Discord Webhook Format

  Discord webhooks accept JSON payloads with the following structure:
  - `content` - Text message (optional if embeds provided)
  - `embeds` - Array of embed objects (up to 10)

  ## Embed Structure

  - `title` - Embed title (max 256 chars)
  - `description` - Main content (max 4096 chars)
  - `color` - Decimal color code
  - `fields` - Array of {name, value, inline} objects (max 25)
  - `footer` - Footer text and icon
  - `timestamp` - ISO8601 timestamp
  """

  use Oban.Worker,
    queue: :notifications,
    max_attempts: 3

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.NotificationCenter.{Notification, NotificationDelivery, NotificationWebhook}

  import Ecto.Query

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"delivery_id" => delivery_id}}) do
    delivery = Repo.get!(NotificationDelivery, delivery_id) |> Repo.preload(:notification)
    notification = Repo.preload(delivery.notification, :user)

    # Get Discord webhook URL from organization settings or webhooks table
    case get_discord_webhook(notification.organization_id) do
      nil ->
        delivery
        |> NotificationDelivery.failed_changeset("No Discord webhook configured")
        |> Repo.update()

        {:error, "No Discord webhook"}

      webhook_url ->
        send_discord_message(delivery, notification, webhook_url)
    end
  end

  @doc """
  Send a Discord message directly without using delivery records.
  Used for direct webhook dispatch from Notifier.
  """
  def send_direct(webhook_url, notification_data) when is_binary(webhook_url) do
    payload = build_discord_payload(notification_data)

    case HTTPoison.post(webhook_url, Jason.encode!(payload), [
           {"Content-Type", "application/json"}
         ]) do
      {:ok, %{status_code: code}} when code in 200..299 ->
        Logger.info("[DiscordWorker] Direct Discord message sent")
        :ok

      {:ok, %{status_code: code, body: body}} ->
        Logger.error("[DiscordWorker] Direct send failed: HTTP #{code} - #{body}")
        {:error, "HTTP #{code}"}

      {:error, %{reason: reason}} ->
        Logger.error("[DiscordWorker] Direct send failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # Private Functions

  defp get_discord_webhook(organization_id) do
    # First, try to get from notification_webhooks table
    webhook =
      NotificationWebhook
      |> where([w], w.organization_id == ^organization_id)
      |> where([w], w.enabled == true)
      |> where([w], like(w.url, "%discord.com/api/webhooks%"))
      |> limit(1)
      |> Repo.one()

    case webhook do
      nil ->
        # Fallback: try organization settings
        case TamanduaServer.Settings.get_setting("discord_webhook_url", organization_id) do
          {:ok, url} when is_binary(url) and url != "" -> url
          _ -> nil
        end

      %NotificationWebhook{url: url} ->
        url
    end
  end

  defp send_discord_message(delivery, notification, webhook_url) do
    payload = build_discord_payload(notification)

    case HTTPoison.post(webhook_url, Jason.encode!(payload), [
           {"Content-Type", "application/json"}
         ]) do
      {:ok, %{status_code: code}} when code in 200..299 ->
        delivery
        |> NotificationDelivery.sent_changeset(%{status_code: code, provider: "discord"})
        |> Repo.update()

        Logger.info("[DiscordWorker] Discord message sent")
        :ok

      {:ok, %{status_code: 429, body: body}} ->
        # Rate limited - let Oban retry
        Logger.warning("[DiscordWorker] Rate limited by Discord: #{body}")
        {:error, "rate_limited"}

      {:ok, %{status_code: code, body: body}} ->
        delivery
        |> NotificationDelivery.failed_changeset("HTTP #{code}: #{body}")
        |> Repo.update()

        Logger.error("[DiscordWorker] Failed to send Discord message: HTTP #{code}")
        {:error, "HTTP #{code}"}

      {:error, %{reason: reason}} ->
        delivery
        |> NotificationDelivery.failed_changeset(inspect(reason))
        |> Repo.update()

        Logger.error("[DiscordWorker] Failed to send Discord message: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp build_discord_payload(notification) when is_struct(notification) do
    embed = build_discord_embed(notification)

    %{
      embeds: [embed]
    }
  end

  defp build_discord_payload(notification_data) when is_map(notification_data) do
    embed = build_discord_embed_from_map(notification_data)

    %{
      embeds: [embed]
    }
  end

  defp build_discord_embed(notification) do
    color = priority_to_color(notification.priority)
    timestamp = format_timestamp(notification.inserted_at)

    base_embed = %{
      title: truncate(notification.title, 256),
      description: truncate(notification.body || "", 4096),
      color: color,
      timestamp: timestamp,
      footer: %{
        text: "Tamandua EDR"
      }
    }

    # Add fields
    fields = build_embed_fields(notification)

    Map.put(base_embed, :fields, fields)
  end

  defp build_discord_embed_from_map(data) do
    priority = Map.get(data, :priority, Map.get(data, "priority", "medium"))
    color = priority_to_color(priority)
    timestamp = Map.get(data, :timestamp) || DateTime.utc_now() |> DateTime.to_iso8601()

    base_embed = %{
      title: truncate(Map.get(data, :title, Map.get(data, "title", "")), 256),
      description: truncate(Map.get(data, :body, Map.get(data, "body", "")), 4096),
      color: color,
      timestamp: timestamp,
      footer: %{
        text: "Tamandua EDR"
      }
    }

    # Add fields from metadata
    fields = build_embed_fields_from_map(data)

    Map.put(base_embed, :fields, fields)
  end

  defp build_embed_fields(notification) do
    fields = [
      %{name: "Priority", value: String.upcase(notification.priority || "medium"), inline: true}
    ]

    # Add type field
    fields = [
      %{
        name: "Type",
        value: format_type(notification.type),
        inline: true
      }
      | fields
    ]

    # Add resource link if available
    fields =
      if notification.related_resource_type && notification.related_resource_id do
        [
          %{
            name: "Resource",
            value: "#{notification.related_resource_type}/#{short_id(notification.related_resource_id)}",
            inline: true
          }
          | fields
        ]
      else
        fields
      end

    # Add metadata fields if present (up to 5)
    fields =
      if notification.metadata && is_map(notification.metadata) do
        metadata_fields =
          notification.metadata
          |> Enum.reject(fn {k, _v} -> k in ["workflow_id", "alert_id", "policy_id"] end)
          |> Enum.take(5)
          |> Enum.map(fn {k, v} ->
            %{name: humanize(k), value: truncate(to_string(v), 1024), inline: true}
          end)

        fields ++ metadata_fields
      else
        fields
      end

    Enum.reverse(fields) |> Enum.take(25)
  end

  defp build_embed_fields_from_map(data) do
    fields = []

    # Add priority
    priority = Map.get(data, :priority, Map.get(data, "priority", "medium"))

    fields = [
      %{name: "Priority", value: String.upcase(to_string(priority)), inline: true}
      | fields
    ]

    # Add type if present
    type = Map.get(data, :type, Map.get(data, "type"))

    fields =
      if type do
        [%{name: "Type", value: format_type(type), inline: true} | fields]
      else
        fields
      end

    # Add metadata fields
    metadata = Map.get(data, :metadata, Map.get(data, "metadata", %{})) || %{}

    metadata_fields =
      metadata
      |> Enum.take(8)
      |> Enum.map(fn {k, v} ->
        %{name: humanize(k), value: truncate(to_string(v), 1024), inline: true}
      end)

    Enum.reverse(fields) ++ metadata_fields |> Enum.take(25)
  end

  # Priority to Discord embed color (decimal)
  defp priority_to_color("critical"), do: 15_158_332  # #E74C3C Red
  defp priority_to_color("high"), do: 15_105_570     # #E67E22 Orange
  defp priority_to_color("medium"), do: 15_844_367  # #F1C40F Yellow
  defp priority_to_color("normal"), do: 3_447_003   # #3498DB Blue
  defp priority_to_color("low"), do: 5_763_719      # #2ECC71 Green
  defp priority_to_color(_), do: 9_936_031          # #979C9F Gray

  defp format_type(type) when is_binary(type) do
    type
    |> String.replace("_", " ")
    |> String.split(" ")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_type(_), do: "Notification"

  defp format_timestamp(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_timestamp(_), do: DateTime.utc_now() |> DateTime.to_iso8601()

  defp truncate(string, max_length) when is_binary(string) do
    if String.length(string) > max_length do
      String.slice(string, 0, max_length - 3) <> "..."
    else
      string
    end
  end

  defp truncate(_, _), do: ""

  defp humanize(key) when is_atom(key), do: humanize(Atom.to_string(key))

  defp humanize(key) when is_binary(key) do
    key
    |> String.replace("_", " ")
    |> String.split(" ")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp humanize(_), do: "Field"

  defp short_id(id) when is_binary(id), do: String.slice(id, 0, 8)
  defp short_id(_), do: "unknown"
end
