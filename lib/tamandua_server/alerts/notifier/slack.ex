defmodule TamanduaServer.Alerts.Notifier.Slack do
  @moduledoc """
  Slack notification delivery via incoming webhooks.

  Sends rich formatted alert notifications to Slack channels with
  interactive buttons and color-coded attachments.
  """

  require Logger

  @doc """
  Send an alert notification to Slack.

  ## Examples

      iex> send_alert_slack(alert, "https://hooks.slack.com/services/...")
      {:ok, :sent}
  """
  def send_alert_slack(alert, webhook_url) when is_binary(webhook_url) do
    payload = build_alert_payload(alert)

    case send_webhook(webhook_url, payload) do
      {:ok, _} ->
        Logger.info("[Slack] Sent alert #{alert.id} to webhook")
        {:ok, :sent}

      {:error, reason} = error ->
        Logger.error("[Slack] Failed to send alert #{alert.id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Send a digest notification to Slack.
  """
  def send_digest(alerts, webhook_urls) when is_list(alerts) and is_list(webhook_urls) do
    payload = build_digest_payload(alerts)

    results = Enum.map(webhook_urls, fn webhook ->
      send_webhook(webhook, payload)
    end)

    {:ok, results}
  end

  @doc """
  Send a test notification to verify Slack webhook.
  """
  def send_test(webhook_url) do
    payload = %{
      text: ":white_check_mark: Tamandua EDR Test Notification",
      attachments: [
        %{
          color: "#22c55e",
          text: "Your Slack notifications are configured correctly!",
          footer: "Tamandua EDR",
          ts: DateTime.utc_now() |> DateTime.to_unix()
        }
      ]
    }

    send_webhook(webhook_url, payload)
  end

  # ===========================================================================
  # Payload Building
  # ===========================================================================

  defp build_alert_payload(alert) do
    %{
      text: "#{severity_emoji(alert.severity)} *#{alert.severity |> to_string() |> String.upcase()} Alert*: #{alert.title}",
      attachments: [
        %{
          color: severity_color(alert.severity),
          fields: build_alert_fields(alert),
          actions: build_alert_actions(alert),
          footer: "Tamandua EDR",
          footer_icon: "https://tamandua.local/icon.png",
          ts: extract_timestamp(alert.inserted_at)
        }
      ]
    }
  end

  defp build_digest_payload(alerts) do
    total = length(alerts)
    severity_counts = Enum.frequencies_by(alerts, & &1.severity)

    critical = Map.get(severity_counts, "critical", 0)
    high = Map.get(severity_counts, "high", 0)
    medium = Map.get(severity_counts, "medium", 0)
    low = Map.get(severity_counts, "low", 0)

    summary = []
    summary = if critical > 0, do: ["#{critical} Critical" | summary], else: summary
    summary = if high > 0, do: ["#{high} High" | summary], else: summary
    summary = if medium > 0, do: ["#{medium} Medium" | summary], else: summary
    summary = if low > 0, do: ["#{low} Low" | summary], else: summary

    summary_text = Enum.join(summary, ", ")

    # Show top 5 alerts in digest
    top_alerts = alerts
    |> Enum.sort_by(&severity_rank(&1.severity))
    |> Enum.take(5)

    alert_text = top_alerts
    |> Enum.map(fn a ->
      "#{severity_emoji(a.severity)} *#{a.severity |> to_string() |> String.upcase()}*: #{a.title}"
    end)
    |> Enum.join("\n")

    more = if total > 5, do: "\n\n_...and #{total - 5} more_", else: ""

    %{
      text: ":bell: *Alert Digest* - #{total} new alert(s)",
      attachments: [
        %{
          color: "#3b82f6",
          fields: [
            %{
              title: "Summary",
              value: summary_text,
              short: false
            },
            %{
              title: "Recent Alerts",
              value: alert_text <> more,
              short: false
            }
          ],
          actions: [
            %{
              type: "button",
              text: "View All Alerts",
              url: dashboard_url(),
              style: "primary"
            }
          ],
          footer: "Tamandua EDR",
          ts: DateTime.utc_now() |> DateTime.to_unix()
        }
      ]
    }
  end

  defp build_alert_fields(alert) do
    base_fields = [
      %{
        title: "Agent",
        value: alert.agent_id,
        short: true
      },
      %{
        title: "Severity",
        value: alert.severity |> to_string() |> String.upcase(),
        short: true
      }
    ]

    # Add threat score if available
    base_fields = if alert.threat_score do
      base_fields ++ [
        %{
          title: "Threat Score",
          value: "#{round(alert.threat_score * 100)}/100",
          short: true
        }
      ]
    else
      base_fields
    end

    # Add MITRE techniques if available
    base_fields = if alert.mitre_techniques && !Enum.empty?(alert.mitre_techniques) do
      techniques = alert.mitre_techniques
      |> Enum.take(5)
      |> Enum.map(&"`#{&1}`")
      |> Enum.join(", ")

      base_fields ++ [
        %{
          title: "MITRE ATT&CK Techniques",
          value: techniques,
          short: false
        }
      ]
    else
      base_fields
    end

    # Add description if present
    if alert.description && String.length(alert.description) > 0 do
      base_fields ++ [
        %{
          title: "Description",
          value: String.slice(alert.description, 0, 300),
          short: false
        }
      ]
    else
      base_fields
    end
  end

  defp build_alert_actions(alert) do
    [
      %{
        type: "button",
        text: "View Alert",
        url: alert_url(alert),
        style: "primary"
      },
      %{
        type: "button",
        text: "Investigate",
        url: investigate_url(alert)
      },
      %{
        type: "button",
        text: "Mark False Positive",
        url: alert_url(alert) <> "/false-positive",
        style: "danger"
      }
    ]
  end

  # ===========================================================================
  # HTTP Request
  # ===========================================================================

  defp send_webhook(webhook_url, payload) do
    try do
      body = Jason.encode!(payload)
      headers = [{"Content-Type", "application/json"}]

      case HTTPoison.post(webhook_url, body, headers, timeout: 10_000) do
        {:ok, %{status_code: 200}} ->
          {:ok, :sent}

        {:ok, %{status_code: status, body: error_body}} ->
          Logger.error("[Slack] Webhook returned #{status}: #{error_body}")
          {:error, {:webhook_error, status, error_body}}

        {:error, %{reason: reason}} ->
          Logger.error("[Slack] HTTP error: #{inspect(reason)}")
          {:error, {:http_error, reason}}
      end
    rescue
      e ->
        Logger.error("[Slack] Exception sending webhook: #{inspect(e)}")
        {:error, {:exception, e}}
    end
  end

  # ===========================================================================
  # Helpers
  # ===========================================================================

  defp severity_emoji("critical"), do: ":rotating_light:"
  defp severity_emoji("high"), do: ":red_circle:"
  defp severity_emoji("medium"), do: ":large_orange_diamond:"
  defp severity_emoji("low"), do: ":large_blue_circle:"
  defp severity_emoji("info"), do: ":information_source:"
  defp severity_emoji(_), do: ":grey_question:"

  defp severity_color("critical"), do: "#dc2626"
  defp severity_color("high"), do: "#f97316"
  defp severity_color("medium"), do: "#eab308"
  defp severity_color("low"), do: "#3b82f6"
  defp severity_color("info"), do: "#6b7280"
  defp severity_color(_), do: "#9ca3af"

  defp severity_rank("critical"), do: 0
  defp severity_rank("high"), do: 1
  defp severity_rank("medium"), do: 2
  defp severity_rank("low"), do: 3
  defp severity_rank("info"), do: 4
  defp severity_rank(_), do: 5

  defp extract_timestamp(%DateTime{} = dt), do: DateTime.to_unix(dt)
  defp extract_timestamp(%NaiveDateTime{} = ndt) do
    ndt
    |> DateTime.from_naive!("Etc/UTC")
    |> DateTime.to_unix()
  end
  defp extract_timestamp(_), do: DateTime.utc_now() |> DateTime.to_unix()

  defp alert_url(alert) do
    base_url = Application.get_env(:tamandua_server, :base_url, "http://localhost:4000")
    "#{base_url}/alerts/#{alert.id}"
  end

  defp investigate_url(alert) do
    base_url = Application.get_env(:tamandua_server, :base_url, "http://localhost:4000")
    "#{base_url}/investigate?alert_id=#{alert.id}"
  end

  defp dashboard_url do
    base_url = Application.get_env(:tamandua_server, :base_url, "http://localhost:4000")
    "#{base_url}/alerts"
  end
end
