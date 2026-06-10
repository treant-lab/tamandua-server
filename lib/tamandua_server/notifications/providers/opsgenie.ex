defmodule TamanduaServer.Notifications.Providers.OpsGenie do
  @moduledoc """
  OpsGenie notification provider.

  Uses OpsGenie REST API to create alerts.
  """

  @behaviour TamanduaServer.Notifications.Providers.Base

  import TamanduaServer.Notifications.Providers.Base

  @impl true
  def send_notification(integration, rendered_title, rendered_body) do
    config = integration.config
    api_key = config["api_key"] || config[:api_key]
    region = config["region"] || config[:region] || "us"

    if is_nil(api_key) or api_key == "" do
      {:error, :missing_api_key}
    else
      url = get_api_url(region)

      payload = %{
        message: rendered_title,
        description: rendered_body,
        priority: map_priority(integration.alert_severity),
        source: "Tamandua EDR"
      }

      headers = [{"Authorization", "GenieKey #{api_key}"}]

      http_post(url, payload, headers)
    end
  end

  @impl true
  def test_connection(config) do
    api_key = config["api_key"] || config[:api_key]
    region = config["region"] || config[:region] || "us"

    if is_nil(api_key) or api_key == "" do
      {:error, :missing_api_key}
    else
      url = get_api_url(region)

      test_payload = %{
        message: "Tamandua EDR Test Notification",
        description: "✅ Your OpsGenie integration is configured correctly!",
        priority: "P5",
        source: "Tamandua EDR"
      }

      headers = [{"Authorization", "GenieKey #{api_key}"}]

      case http_post(url, test_payload, headers) do
        {:ok, _} -> {:ok, "Test notification sent successfully"}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  # Private helpers

  defp get_api_url("eu"), do: "https://api.eu.opsgenie.com/v2/alerts"
  defp get_api_url(_), do: "https://api.opsgenie.com/v2/alerts"

  defp map_priority(severity) when is_binary(severity) do
    case String.downcase(severity) do
      "critical" -> "P1"
      "high" -> "P2"
      "medium" -> "P3"
      "low" -> "P4"
      _ -> "P5"
    end
  end

  defp map_priority(_), do: "P5"
end
