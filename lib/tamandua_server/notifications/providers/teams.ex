defmodule TamanduaServer.Notifications.Providers.Teams do
  @moduledoc """
  Microsoft Teams notification provider.

  Uses Teams incoming webhooks with adaptive cards.
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
      # Build MessageCard format (legacy) or Adaptive Card (modern)
      payload = build_message_card(rendered_title, rendered_body)

      http_post(webhook_url, payload)
    end
  end

  @impl true
  def test_connection(config) do
    webhook_url = config["webhook_url"] || config[:webhook_url]

    if is_nil(webhook_url) or webhook_url == "" do
      {:error, :missing_webhook_url}
    else
      test_payload = build_message_card(
        "Tamandua EDR Test Notification",
        "✅ Your Microsoft Teams integration is configured correctly!"
      )

      case http_post(webhook_url, test_payload) do
        {:ok, _} -> {:ok, "Test notification sent successfully"}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  # Private helpers

  defp build_message_card(title, text) do
    %{
      "@type" => "MessageCard",
      "@context" => "https://schema.org/extensions",
      summary: title,
      themeColor: "0078D4",
      title: title,
      sections: [
        %{
          activityTitle: "Tamandua EDR Alert",
          text: text
        }
      ]
    }
  end
end
