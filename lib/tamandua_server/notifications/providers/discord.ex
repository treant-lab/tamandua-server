defmodule TamanduaServer.Notifications.Providers.Discord do
  @moduledoc """
  Discord notification provider.

  Uses Discord webhooks to send notifications.
  """

  @behaviour TamanduaServer.Notifications.Providers.Base

  import TamanduaServer.Notifications.Providers.Base

  @impl true
  def send_notification(integration, rendered_title, rendered_body) do
    config = integration.config
    webhook_url = config["webhook_url"] || config[:webhook_url]

    if is_nil(webhook_url) or webhook_url == "" do
      {:error, :missing_webhook_url}
    else
      # Build Discord embed
      payload = %{
        embeds: [
          %{
            title: rendered_title,
            description: rendered_body,
            color: get_color(integration.alert_severity),
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
            footer: %{
              text: "Tamandua EDR"
            }
          }
        ]
      }

      http_post(webhook_url, payload)
    end
  end

  @impl true
  def test_connection(config) do
    webhook_url = config["webhook_url"] || config[:webhook_url]

    if is_nil(webhook_url) or webhook_url == "" do
      {:error, :missing_webhook_url}
    else
      test_payload = %{
        embeds: [
          %{
            title: "Tamandua EDR Test Notification",
            description: "✅ Your Discord integration is configured correctly!",
            color: 5_814_783,  # Green
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
            footer: %{
              text: "Tamandua EDR"
            }
          }
        ]
      }

      case http_post(webhook_url, test_payload) do
        {:ok, _} -> {:ok, "Test notification sent successfully"}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  # Private helpers

  defp get_color(severity) when is_binary(severity) do
    case String.downcase(severity) do
      "critical" -> 15_158_332  # Red
      "high" -> 15_105_570     # Orange
      "medium" -> 16_776_960   # Yellow
      "low" -> 3_447_003       # Blue
      _ -> 9_807_270           # Gray
    end
  end

  defp get_color(_), do: 9_807_270
end
