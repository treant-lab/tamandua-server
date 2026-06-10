defmodule TamanduaServer.Notifications.Providers.PagerDuty do
  @moduledoc """
  PagerDuty notification provider.

  Uses PagerDuty Events API v2 for incident creation.
  """

  @behaviour TamanduaServer.Notifications.Providers.Base

  import TamanduaServer.Notifications.Providers.Base

  @events_api_url "https://events.pagerduty.com/v2/enqueue"

  @impl true
  def send_notification(integration, rendered_title, rendered_body) do
    config = integration.config
    integration_key = config["integration_key"] || config[:integration_key]

    if is_nil(integration_key) or integration_key == "" do
      {:error, :missing_integration_key}
    else
      # Build Events API v2 payload
      payload = %{
        routing_key: integration_key,
        event_action: "trigger",
        payload: %{
          summary: rendered_title,
          severity: map_severity(integration.alert_severity),
          source: "Tamandua EDR",
          custom_details: %{
            description: rendered_body
          }
        }
      }

      http_post(@events_api_url, payload)
    end
  end

  @impl true
  def test_connection(config) do
    integration_key = config["integration_key"] || config[:integration_key]

    if is_nil(integration_key) or integration_key == "" do
      {:error, :missing_integration_key}
    else
      test_payload = %{
        routing_key: integration_key,
        event_action: "trigger",
        payload: %{
          summary: "Tamandua EDR Test Notification",
          severity: "info",
          source: "Tamandua EDR",
          custom_details: %{
            description: "✅ Your PagerDuty integration is configured correctly!"
          }
        }
      }

      case http_post(@events_api_url, test_payload) do
        {:ok, _} -> {:ok, "Test notification sent successfully"}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  # Private helpers

  defp map_severity(severity) when is_binary(severity) do
    case String.downcase(severity) do
      "critical" -> "critical"
      "high" -> "error"
      "medium" -> "warning"
      "low" -> "info"
      _ -> "info"
    end
  end

  defp map_severity(_), do: "info"
end
