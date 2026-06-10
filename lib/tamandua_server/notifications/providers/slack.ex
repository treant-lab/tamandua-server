defmodule TamanduaServer.Notifications.Providers.Slack do
  @moduledoc """
  Slack notification provider.

  Supports both webhook and OAuth-based notifications.
  """

  @behaviour TamanduaServer.Notifications.Providers.Base

  import TamanduaServer.Notifications.Providers.Base

  @impl true
  def send_notification(integration, rendered_title, rendered_body) do
    config = integration.config

    payload = %{
      text: rendered_title,
      blocks: [
        %{
          type: "section",
          text: %{
            type: "mrkdwn",
            text: rendered_body
          }
        }
      ]
    }

    # Add channel if specified
    payload =
      if config["channel"] || config[:channel] do
        Map.put(payload, :channel, config["channel"] || config[:channel])
      else
        payload
      end

    # Send via webhook or API
    cond do
      config["webhook_url"] || config[:webhook_url] ->
        send_webhook(config["webhook_url"] || config[:webhook_url], payload)

      config["oauth_token"] || config[:oauth_token] ->
        send_api(config["oauth_token"] || config[:oauth_token], payload)

      true ->
        {:error, "No webhook_url or oauth_token configured"}
    end
  end

  @impl true
  def test_connection(config) do
    test_payload = %{
      text: "Test notification from Tamandua EDR",
      blocks: [
        %{
          type: "section",
          text: %{
            type: "mrkdwn",
            text: ":white_check_mark: *Tamandua EDR Test Notification*\n\nYour Slack integration is configured correctly!"
          }
        }
      ]
    }

    cond do
      config["webhook_url"] || config[:webhook_url] ->
        case send_webhook(config["webhook_url"] || config[:webhook_url], test_payload) do
          {:ok, _} -> {:ok, "Test notification sent successfully"}
          {:error, reason} -> {:error, reason}
        end

      config["oauth_token"] || config[:oauth_token] ->
        case send_api(config["oauth_token"] || config[:oauth_token], test_payload) do
          {:ok, _} -> {:ok, "Test notification sent successfully"}
          {:error, reason} -> {:error, reason}
        end

      true ->
        {:error, "No webhook_url or oauth_token configured"}
    end
  end

  # Private helpers

  defp send_webhook(webhook_url, payload) do
    http_post(webhook_url, payload)
  end

  defp send_api(oauth_token, payload) do
    url = "https://slack.com/api/chat.postMessage"
    headers = [{"Authorization", "Bearer #{oauth_token}"}]

    http_post(url, payload, headers)
  end
end
