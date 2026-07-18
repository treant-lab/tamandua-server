defmodule TamanduaServer.Integrations do
  @moduledoc """
  Context module for external integrations.

  Handles:
  - Threat intelligence feeds (MISP, OTX, VirusTotal)
  - Notification services (Slack, PagerDuty, Teams)
  - IOC ingestion from external sources
  """

  require Logger

  alias TamanduaServer.Detection.{IOCReload, IOCs}
  alias TamanduaServer.Alerts.Alert

  # ======================= Threat Intelligence Feeds =======================

  @doc """
  Process MISP feed data and ingest IOCs.

  MISP event format:
  ```
  {
    "Event": {
      "uuid": "...",
      "info": "...",
      "Attribute": [
        {"type": "ip-src", "value": "1.2.3.4", "to_ids": true},
        {"type": "md5", "value": "abc123...", "to_ids": true}
      ]
    }
  }
  ```
  """
  def process_misp_feed(params) do
    Logger.info("Processing MISP feed")

    event = params["Event"] || params["event"] || params

    attributes = event["Attribute"] || event["attributes"] || []

    results =
      Enum.map(attributes, fn attr ->
        if attr["to_ids"] == true or attr["to_ids"] == "true" do
          ioc_attrs = %{
            type: misp_type_to_ioc_type(attr["type"]),
            value: attr["value"],
            description: attr["comment"] || event["info"],
            source: "misp",
            severity: misp_threat_level_to_severity(event["threat_level_id"]),
            tags: extract_misp_tags(event),
            enabled: true
          }

          case IOCs.add_global(ioc_attrs) do
            {:ok, ioc} -> {:ok, ioc.id}
            {:error, reason} -> {:error, reason}
          end
        else
          {:skipped, :not_to_ids}
        end
      end)

    created =
      Enum.count(results, fn
        {:ok, _} -> true
        _ -> false
      end)

    if created > 0, do: schedule_ioc_reload()

    Logger.info("MISP feed processed: #{created} IOCs created")
    {:ok, %{created: created, total: length(attributes)}}
  end

  @doc """
  Process AlienVault OTX pulse data and ingest IOCs.

  OTX pulse format:
  ```
  {
    "id": "...",
    "name": "...",
    "indicators": [
      {"type": "IPv4", "indicator": "1.2.3.4"},
      {"type": "FileHash-MD5", "indicator": "abc123..."}
    ]
  }
  ```
  """
  def process_otx_feed(params) do
    Logger.info("Processing OTX feed")

    indicators = params["indicators"] || []
    pulse_name = params["name"] || "OTX Pulse"

    results =
      Enum.map(indicators, fn indicator ->
        ioc_attrs = %{
          type: otx_type_to_ioc_type(indicator["type"]),
          value: indicator["indicator"],
          description: pulse_name,
          source: "otx",
          severity: "medium",
          tags: params["tags"] || [],
          enabled: true
        }

        case IOCs.add_global(ioc_attrs) do
          {:ok, ioc} -> {:ok, ioc.id}
          {:error, reason} -> {:error, reason}
        end
      end)

    created =
      Enum.count(results, fn
        {:ok, _} -> true
        _ -> false
      end)

    if created > 0, do: schedule_ioc_reload()

    Logger.info("OTX feed processed: #{created} IOCs created")
    {:ok, %{created: created, total: length(indicators)}}
  end

  @doc """
  Process VirusTotal API response data and ingest IOCs.

  VT format:
  ```
  {
    "data": {
      "type": "file",
      "id": "sha256hash",
      "attributes": {
        "sha256": "...",
        "md5": "...",
        "last_analysis_stats": {"malicious": 50}
      }
    }
  }
  ```
  """
  def process_virustotal_feed(params) do
    Logger.info("Processing VirusTotal feed")

    data = params["data"]

    if data do
      attrs = data["attributes"] || %{}
      stats = attrs["last_analysis_stats"] || %{}
      malicious_count = stats["malicious"] || 0

      # Only ingest if detected as malicious
      if malicious_count > 5 do
        iocs = []

        # SHA256
        iocs =
          if attrs["sha256"] do
            [
              %{
                type: "hash_sha256",
                value: attrs["sha256"],
                description: "VirusTotal detection: #{malicious_count} engines",
                source: "virustotal",
                severity: vt_malicious_to_severity(malicious_count),
                tags: ["malware"],
                enabled: true
              }
              | iocs
            ]
          else
            iocs
          end

        # MD5
        iocs =
          if attrs["md5"] do
            [
              %{
                type: "hash_md5",
                value: attrs["md5"],
                description: "VirusTotal detection: #{malicious_count} engines",
                source: "virustotal",
                severity: vt_malicious_to_severity(malicious_count),
                tags: ["malware"],
                enabled: true
              }
              | iocs
            ]
          else
            iocs
          end

        results =
          Enum.map(iocs, fn ioc_attrs ->
            case IOCs.add_global(ioc_attrs) do
              {:ok, ioc} -> {:ok, ioc.id}
              {:error, reason} -> {:error, reason}
            end
          end)

        created =
          Enum.count(results, fn
            {:ok, _} -> true
            _ -> false
          end)

        if created > 0, do: schedule_ioc_reload()

        {:ok, %{created: created, total: length(iocs)}}
      else
        {:ok, %{created: 0, total: 0, skipped: "Not malicious enough"}}
      end
    else
      {:error, "Invalid VirusTotal data format"}
    end
  end

  # ======================= Notification Services =======================

  defp schedule_ioc_reload do
    IOCReload.schedule()
  end

  @doc """
  Send alert notification to Slack.
  """
  def notify_slack(%Alert{} = alert, webhook_url) when is_binary(webhook_url) do
    payload = build_slack_payload(alert)

    case post_webhook(webhook_url, payload) do
      {:ok, _} ->
        Logger.info("Slack notification sent for alert #{alert.id}")
        :ok

      {:error, reason} ->
        Logger.error("Failed to send Slack notification: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Send alert notification to PagerDuty.
  """
  def notify_pagerduty(%Alert{} = alert, routing_key) when is_binary(routing_key) do
    payload = build_pagerduty_payload(alert, routing_key)
    url = "https://events.pagerduty.com/v2/enqueue"

    case post_webhook(url, payload) do
      {:ok, _} ->
        Logger.info("PagerDuty notification sent for alert #{alert.id}")
        :ok

      {:error, reason} ->
        Logger.error("Failed to send PagerDuty notification: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Send alert notification to Microsoft Teams.
  """
  def notify_teams(%Alert{} = alert, webhook_url) when is_binary(webhook_url) do
    payload = build_teams_payload(alert)

    case post_webhook(webhook_url, payload) do
      {:ok, _} ->
        Logger.info("Teams notification sent for alert #{alert.id}")
        :ok

      {:error, reason} ->
        Logger.error("Failed to send Teams notification: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Process incoming Slack interactive message (button clicks, etc).
  """
  def process_slack_action(params) do
    # Handle Slack interactive components
    case params["type"] do
      "block_actions" ->
        process_slack_block_actions(params)

      "view_submission" ->
        # Handle modal submissions
        :ok

      _ ->
        Logger.warning("Unknown Slack action type: #{params["type"]}")
        :ok
    end
  end

  @doc """
  Process incoming PagerDuty webhook (acknowledgments, etc).
  """
  def process_pagerduty_webhook(params) do
    messages = params["messages"] || []

    Enum.each(messages, fn message ->
      event_type = message["event"]
      incident = message["incident"] || %{}

      case event_type do
        "incident.acknowledge" ->
          Logger.info("PagerDuty incident acknowledged: #{incident["id"]}")

        # Could update alert status here

        "incident.resolve" ->
          Logger.info("PagerDuty incident resolved: #{incident["id"]}")

        # Could close alert here

        _ ->
          Logger.debug("PagerDuty event: #{event_type}")
      end
    end)

    :ok
  end

  @doc """
  Process incoming Teams webhook.
  """
  def process_teams_webhook(params) do
    # Teams webhooks are typically outbound only
    # But we can handle incoming messages if configured as a bot
    Logger.debug("Teams webhook received: #{inspect(params)}")
    :ok
  end

  # ======================= Private Functions =======================

  # Type conversions

  defp misp_type_to_ioc_type(type) do
    case type do
      "ip-src" -> "ip"
      "ip-dst" -> "ip"
      "ip" -> "ip"
      "domain" -> "domain"
      "hostname" -> "domain"
      "url" -> "url"
      "md5" -> "hash_md5"
      "sha1" -> "hash_sha1"
      "sha256" -> "hash_sha256"
      "filename" -> "filename"
      "email" -> "email"
      "email-src" -> "email"
      "email-dst" -> "email"
      _ -> "unknown"
    end
  end

  defp otx_type_to_ioc_type(type) do
    case type do
      "IPv4" -> "ip"
      "IPv6" -> "ip"
      "domain" -> "domain"
      "hostname" -> "domain"
      "URL" -> "url"
      "FileHash-MD5" -> "hash_md5"
      "FileHash-SHA1" -> "hash_sha1"
      "FileHash-SHA256" -> "hash_sha256"
      "email" -> "email"
      _ -> "unknown"
    end
  end

  defp misp_threat_level_to_severity(level) do
    case level do
      "1" -> "critical"
      "2" -> "high"
      "3" -> "medium"
      "4" -> "low"
      1 -> "critical"
      2 -> "high"
      3 -> "medium"
      4 -> "low"
      _ -> "medium"
    end
  end

  defp vt_malicious_to_severity(count) when count >= 30, do: "critical"
  defp vt_malicious_to_severity(count) when count >= 15, do: "high"
  defp vt_malicious_to_severity(count) when count >= 5, do: "medium"
  defp vt_malicious_to_severity(_), do: "low"

  defp extract_misp_tags(event) do
    tags = event["Tag"] || event["tags"] || []

    Enum.map(tags, fn
      %{"name" => name} -> name
      name when is_binary(name) -> name
      _ -> nil
    end)
    |> Enum.filter(&(&1 != nil))
  end

  # Slack payload builder

  defp build_slack_payload(%Alert{} = alert) do
    color = severity_to_color(alert.severity)

    %{
      "attachments" => [
        %{
          "color" => color,
          "blocks" => [
            %{
              "type" => "header",
              "text" => %{
                "type" => "plain_text",
                "text" => "🚨 Tamandua EDR Alert"
              }
            },
            %{
              "type" => "section",
              "fields" => [
                %{
                  "type" => "mrkdwn",
                  "text" => "*Title:*\n#{alert.title}"
                },
                %{
                  "type" => "mrkdwn",
                  "text" => "*Severity:*\n#{String.upcase(to_string(alert.severity))}"
                },
                %{
                  "type" => "mrkdwn",
                  "text" => "*Agent:*\n#{alert.agent_id || "N/A"}"
                },
                %{
                  "type" => "mrkdwn",
                  "text" => "*Status:*\n#{alert.status}"
                }
              ]
            },
            %{
              "type" => "section",
              "text" => %{
                "type" => "mrkdwn",
                "text" => "*Description:*\n#{alert.description || "No description"}"
              }
            },
            %{
              "type" => "actions",
              "elements" => [
                %{
                  "type" => "button",
                  "text" => %{"type" => "plain_text", "text" => "View Alert"},
                  "url" => "#{get_base_url()}/app/alerts/#{alert.id}",
                  "style" => "primary"
                },
                %{
                  "type" => "button",
                  "text" => %{"type" => "plain_text", "text" => "Acknowledge"},
                  "action_id" => "acknowledge_alert",
                  "value" => alert.id
                }
              ]
            }
          ]
        }
      ]
    }
  end

  # PagerDuty payload builder

  defp build_pagerduty_payload(%Alert{} = alert, routing_key) do
    severity =
      case alert.severity do
        :critical -> "critical"
        :high -> "error"
        :medium -> "warning"
        _ -> "info"
      end

    %{
      "routing_key" => routing_key,
      "event_action" => "trigger",
      "dedup_key" => "tamandua-alert-#{alert.id}",
      "payload" => %{
        "summary" => "[Tamandua EDR] #{alert.title}",
        "severity" => severity,
        "source" => alert.agent_id || "tamandua-server",
        "custom_details" => %{
          "alert_id" => alert.id,
          "description" => alert.description,
          "mitre_tactics" => alert.mitre_tactics || [],
          "mitre_techniques" => alert.mitre_techniques || []
        }
      },
      "links" => [
        %{
          "href" => "#{get_base_url()}/app/alerts/#{alert.id}",
          "text" => "View in Tamandua"
        }
      ]
    }
  end

  # Teams payload builder (Adaptive Card format)

  defp build_teams_payload(%Alert{} = alert) do
    color = severity_to_color(alert.severity)

    %{
      "@type" => "MessageCard",
      "@context" => "http://schema.org/extensions",
      "themeColor" => String.replace(color, "#", ""),
      "summary" => "Tamandua EDR Alert: #{alert.title}",
      "sections" => [
        %{
          "activityTitle" => "🚨 Tamandua EDR Alert",
          "activitySubtitle" => DateTime.utc_now() |> DateTime.to_iso8601(),
          "facts" => [
            %{"name" => "Title", "value" => alert.title},
            %{"name" => "Severity", "value" => String.upcase(to_string(alert.severity))},
            %{"name" => "Agent", "value" => alert.agent_id || "N/A"},
            %{"name" => "Status", "value" => to_string(alert.status)}
          ],
          "text" => alert.description || "No description"
        }
      ],
      "potentialAction" => [
        %{
          "@type" => "OpenUri",
          "name" => "View Alert",
          "targets" => [
            %{"os" => "default", "uri" => "#{get_base_url()}/app/alerts/#{alert.id}"}
          ]
        }
      ]
    }
  end

  defp severity_to_color(:critical), do: "#dc3545"
  defp severity_to_color(:high), do: "#fd7e14"
  defp severity_to_color(:medium), do: "#ffc107"
  defp severity_to_color(:low), do: "#28a745"
  defp severity_to_color(_), do: "#6c757d"

  defp process_slack_block_actions(params) do
    actions = params["actions"] || []

    Enum.each(actions, fn action ->
      case action["action_id"] do
        "acknowledge_alert" ->
          alert_id = action["value"]
          Logger.info("Slack: acknowledging alert #{alert_id}")

        # TamanduaServer.Alerts.update_status(alert_id, :acknowledged)

        _ ->
          Logger.debug("Unknown Slack action: #{action["action_id"]}")
      end
    end)

    :ok
  end

  defp post_webhook(url, payload) do
    case Req.post(url, json: payload, receive_timeout: 10_000) do
      {:ok, %Req.Response{status: status}} when status in 200..299 ->
        {:ok, status}

      {:ok, %Req.Response{status: status, body: body}} ->
        {:error, "HTTP #{status}: #{inspect(body)}"}

      {:error, exception} ->
        {:error, Exception.message(exception)}
    end
  end

  defp get_base_url do
    Application.get_env(:tamandua_server, TamanduaServerWeb.Endpoint)[:url][:host] ||
      "http://localhost:4000"
  end
end
