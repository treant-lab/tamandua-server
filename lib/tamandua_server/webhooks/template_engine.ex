defmodule TamanduaServer.Webhooks.TemplateEngine do
  @moduledoc """
  Liquid template engine for webhook payloads.

  Supports template variables like {{ alert.id }}, {{ alert.severity }}, etc.
  Provides pre-built templates for popular integrations (Slack, Teams, generic JSON).
  """

  require Logger

  @doc """
  Renders a webhook payload template with the provided data.

  ## Examples

      iex> render(template, %{alert: alert_data})
      {:ok, rendered_payload}

  """
  def render(nil, data), do: {:ok, data}
  def render("", data), do: {:ok, data}

  def render(template, data) when is_binary(template) do
    try do
      rendered = Solid.render!(template, data)
      {:ok, rendered}
    rescue
      error ->
        Logger.error("[TemplateEngine] Failed to render template: #{inspect(error)}")
        {:error, "Template rendering failed: #{Exception.message(error)}"}
    end
  end

  @doc """
  Validates a template for syntax errors.
  """
  def validate_template(nil), do: :ok
  def validate_template(""), do: :ok

  def validate_template(template) when is_binary(template) do
    try do
      Solid.parse(template)
      :ok
    rescue
      error ->
        {:error, "Invalid template syntax: #{Exception.message(error)}"}
    end
  end

  @doc """
  Returns pre-built templates for popular integrations.
  """
  def builtin_templates do
    %{
      "slack" => slack_template(),
      "microsoft_teams" => teams_template(),
      "generic_json" => generic_json_template(),
      "pagerduty" => pagerduty_template(),
      "opsgenie" => opsgenie_template(),
      "jira" => jira_template(),
      "servicenow" => servicenow_template()
    }
  end

  @doc """
  Returns a template by name.
  """
  def get_builtin_template(name) do
    Map.get(builtin_templates(), name)
  end

  # Pre-built Templates

  defp slack_template do
    """
    {
      "text": "{{ event }} - {{ data.alert.severity | upcase }}",
      "blocks": [
        {
          "type": "header",
          "text": {
            "type": "plain_text",
            "text": "🚨 {{ data.alert.title }}"
          }
        },
        {
          "type": "section",
          "fields": [
            {
              "type": "mrkdwn",
              "text": "*Alert ID:*\\n{{ data.alert.id }}"
            },
            {
              "type": "mrkdwn",
              "text": "*Severity:*\\n{{ data.alert.severity }}"
            },
            {
              "type": "mrkdwn",
              "text": "*Agent:*\\n{{ data.alert.agent_id }}"
            },
            {
              "type": "mrkdwn",
              "text": "*Time:*\\n{{ timestamp }}"
            }
          ]
        },
        {
          "type": "section",
          "text": {
            "type": "mrkdwn",
            "text": "*Description:*\\n{{ data.alert.description }}"
          }
        },
        {
          "type": "actions",
          "elements": [
            {
              "type": "button",
              "text": {
                "type": "plain_text",
                "text": "View Alert"
              },
              "url": "{{ data.alert.url }}",
              "style": "primary"
            }
          ]
        }
      ]
    }
    """
  end

  defp teams_template do
    """
    {
      "@type": "MessageCard",
      "@context": "https://schema.org/extensions",
      "summary": "{{ data.alert.title }}",
      "themeColor": "{% if data.alert.severity == 'critical' %}dc3545{% elsif data.alert.severity == 'high' %}fd7e14{% elsif data.alert.severity == 'medium' %}ffc107{% else %}17a2b8{% endif %}",
      "title": "🚨 {{ data.alert.title }}",
      "sections": [
        {
          "activityTitle": "**Alert Details**",
          "facts": [
            {
              "name": "Alert ID",
              "value": "{{ data.alert.id }}"
            },
            {
              "name": "Severity",
              "value": "{{ data.alert.severity | upcase }}"
            },
            {
              "name": "Agent",
              "value": "{{ data.alert.agent_id }}"
            },
            {
              "name": "Timestamp",
              "value": "{{ timestamp }}"
            }
          ],
          "text": "{{ data.alert.description }}"
        }
      ],
      "potentialAction": [
        {
          "@type": "OpenUri",
          "name": "View Alert",
          "targets": [
            {
              "os": "default",
              "uri": "{{ data.alert.url }}"
            }
          ]
        }
      ]
    }
    """
  end

  defp generic_json_template do
    """
    {
      "event_type": "{{ event }}",
      "event_id": "{{ event_id }}",
      "timestamp": "{{ timestamp }}",
      "alert": {
        "id": "{{ data.alert.id }}",
        "title": "{{ data.alert.title }}",
        "description": "{{ data.alert.description }}",
        "severity": "{{ data.alert.severity }}",
        "status": "{{ data.alert.status }}",
        "agent_id": "{{ data.alert.agent_id }}",
        "detection_rule": "{{ data.alert.detection_rule }}",
        "mitre_tactics": {{ data.alert.mitre_tactics | json }},
        "evidence": {{ data.alert.evidence | json }}
      }
    }
    """
  end

  defp pagerduty_template do
    """
    {
      "routing_key": "YOUR_INTEGRATION_KEY",
      "event_action": "trigger",
      "payload": {
        "summary": "{{ data.alert.title }}",
        "severity": "{% if data.alert.severity == 'critical' %}critical{% elsif data.alert.severity == 'high' %}error{% elsif data.alert.severity == 'medium' %}warning{% else %}info{% endif %}",
        "source": "Tamandua EDR",
        "custom_details": {
          "alert_id": "{{ data.alert.id }}",
          "agent_id": "{{ data.alert.agent_id }}",
          "detection_rule": "{{ data.alert.detection_rule }}",
          "description": "{{ data.alert.description }}"
        }
      },
      "links": [
        {
          "href": "{{ data.alert.url }}",
          "text": "View in Tamandua EDR"
        }
      ]
    }
    """
  end

  defp opsgenie_template do
    """
    {
      "message": "{{ data.alert.title }}",
      "description": "{{ data.alert.description }}",
      "priority": "{% if data.alert.severity == 'critical' %}P1{% elsif data.alert.severity == 'high' %}P2{% elsif data.alert.severity == 'medium' %}P3{% else %}P4{% endif %}",
      "alias": "tamandua-{{ data.alert.id }}",
      "tags": ["tamandua", "edr", "{{ data.alert.severity }}"],
      "details": {
        "alert_id": "{{ data.alert.id }}",
        "agent_id": "{{ data.alert.agent_id }}",
        "detection_rule": "{{ data.alert.detection_rule }}",
        "timestamp": "{{ timestamp }}"
      }
    }
    """
  end

  defp jira_template do
    """
    {
      "fields": {
        "project": {
          "key": "SEC"
        },
        "summary": "{{ data.alert.title }}",
        "description": "{{ data.alert.description }}\\n\\n*Alert ID:* {{ data.alert.id }}\\n*Severity:* {{ data.alert.severity }}\\n*Agent:* {{ data.alert.agent_id }}\\n*Timestamp:* {{ timestamp }}",
        "issuetype": {
          "name": "Bug"
        },
        "priority": {
          "name": "{% if data.alert.severity == 'critical' %}Highest{% elsif data.alert.severity == 'high' %}High{% elsif data.alert.severity == 'medium' %}Medium{% else %}Low{% endif %}"
        },
        "labels": ["tamandua", "edr", "security", "{{ data.alert.severity }}"]
      }
    }
    """
  end

  defp servicenow_template do
    """
    {
      "short_description": "{{ data.alert.title }}",
      "description": "{{ data.alert.description }}",
      "category": "security",
      "subcategory": "malware",
      "urgency": "{% if data.alert.severity == 'critical' %}1{% elsif data.alert.severity == 'high' %}2{% elsif data.alert.severity == 'medium' %}3{% else %}4{% endif %}",
      "impact": "{% if data.alert.severity == 'critical' %}1{% elsif data.alert.severity == 'high' %}2{% elsif data.alert.severity == 'medium' %}3{% else %}4{% endif %}",
      "comments": "Alert ID: {{ data.alert.id }}\\nAgent ID: {{ data.alert.agent_id }}\\nDetection Rule: {{ data.alert.detection_rule }}\\nTimestamp: {{ timestamp }}"
    }
    """
  end

  @doc """
  Extracts template variables from a template string.
  """
  def extract_variables(template) when is_binary(template) do
    Regex.scan(~r/\{\{\s*([a-zA-Z0-9_.]+)\s*(?:\|[^}]+)?\}\}/, template)
    |> Enum.map(fn [_, var] -> var end)
    |> Enum.uniq()
  end

  def extract_variables(_), do: []

  @doc """
  Returns available template variables for webhook events.
  """
  def available_variables do
    %{
      "alert.created" => [
        "event",
        "event_id",
        "timestamp",
        "data.alert.id",
        "data.alert.title",
        "data.alert.description",
        "data.alert.severity",
        "data.alert.status",
        "data.alert.agent_id",
        "data.alert.agent_hostname",
        "data.alert.detection_rule",
        "data.alert.mitre_tactics",
        "data.alert.mitre_techniques",
        "data.alert.evidence",
        "data.alert.url"
      ],
      "agent.connected" => [
        "event",
        "event_id",
        "timestamp",
        "data.agent.id",
        "data.agent.hostname",
        "data.agent.ip_address",
        "data.agent.os_type",
        "data.agent.os_version",
        "data.agent.version"
      ],
      "agent.disconnected" => [
        "event",
        "event_id",
        "timestamp",
        "data.agent.id",
        "data.agent.hostname",
        "data.agent.last_seen"
      ],
      "detection.triggered" => [
        "event",
        "event_id",
        "timestamp",
        "data.detection.rule_name",
        "data.detection.rule_type",
        "data.detection.severity",
        "data.detection.agent_id",
        "data.detection.matched_content"
      ],
      "response.executed" => [
        "event",
        "event_id",
        "timestamp",
        "data.response.action",
        "data.response.target",
        "data.response.agent_id",
        "data.response.status",
        "data.response.result"
      ]
    }
  end
end
