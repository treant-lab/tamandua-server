defmodule TamanduaServer.Notifications.Providers.Telegram do
  @moduledoc """
  Telegram notification provider.

  Uses Telegram Bot API to send notifications.
  """

  @behaviour TamanduaServer.Notifications.Providers.Base

  import TamanduaServer.Notifications.Providers.Base

  @impl true
  def send_notification(integration, rendered_title, rendered_body) do
    config = integration.config
    bot_token = config["bot_token"] || config[:bot_token]
    chat_id = config["chat_id"] || config[:chat_id]

    if is_nil(bot_token) or bot_token == "" or is_nil(chat_id) or chat_id == "" do
      {:error, :missing_bot_token_or_chat_id}
    else
      url = "https://api.telegram.org/bot#{bot_token}/sendMessage"

      # Combine title and body
      text = "#{rendered_title}\n\n#{rendered_body}"

      payload = %{
        chat_id: chat_id,
        text: text,
        parse_mode: "HTML",
        disable_web_page_preview: true
      }

      http_post(url, payload)
    end
  end

  @impl true
  def test_connection(config) do
    bot_token = config["bot_token"] || config[:bot_token]
    chat_id = config["chat_id"] || config[:chat_id]

    if is_nil(bot_token) or bot_token == "" or is_nil(chat_id) or chat_id == "" do
      {:error, :missing_bot_token_or_chat_id}
    else
      url = "https://api.telegram.org/bot#{bot_token}/sendMessage"

      test_payload = %{
        chat_id: chat_id,
        text: "🚨 <b>Tamandua EDR Test Notification</b>\n\n✅ Your Telegram integration is configured correctly!",
        parse_mode: "HTML"
      }

      case http_post(url, test_payload) do
        {:ok, _} -> {:ok, "Test notification sent successfully"}
        {:error, reason} -> {:error, reason}
      end
    end
  end
end
