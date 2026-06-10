defmodule TamanduaServer.Integrations.WebhookParsers.PagerDuty do
  @moduledoc """
  Parser for PagerDuty webhook events (v3 webhook format).

  Handles:
  - Incident triggered
  - Incident acknowledged
  - Incident resolved
  - Incident escalated
  """

  @behaviour TamanduaServer.Integrations.WebhookParsers.Behaviour

  @impl true
  def parse(payload, _opts) do
    # PagerDuty v3 webhook format
    event = payload["event"] || payload
    incident = event["data"] || event["incident"] || event

    action_type = determine_action(event["event_type"] || payload["type"])
    alert_reference = extract_alert_reference(incident)

    parsed = %{
      action_type: action_type,
      alert_reference: alert_reference,
      external_id: incident["id"],
      external_status: incident["status"],
      external_url: incident["html_url"],
      user: extract_user(event),
      comment: extract_notes(incident),
      enrichment_data: extract_enrichment(incident, event),
      metadata: %{
        urgency: incident["urgency"],
        service_id: get_in(incident, ["service", "id"]),
        service_name: get_in(incident, ["service", "summary"]),
        escalation_policy: get_in(incident, ["escalation_policy", "summary"])
      },
      raw_payload: payload
    }

    {:ok, parsed}
  end

  defp determine_action("incident.triggered"), do: :incident_sync
  defp determine_action("incident.acknowledged"), do: :alert_status_update
  defp determine_action("incident.resolved"), do: :alert_status_update
  defp determine_action("incident.escalated"), do: :incident_sync
  defp determine_action("incident.annotated"), do: :alert_comment
  defp determine_action(_), do: :incident_sync

  defp extract_alert_reference(incident) do
    # Look for Tamandua alert ID in incident body or title
    body = incident["body"] || %{}
    details = body["details"] || ""
    title = incident["title"] || incident["summary"] || ""
    alert_id = extract_alert_id_from_text(details <> " " <> title)

    # Also check custom_details
    alert_id = alert_id || get_in(incident, ["body", "details", "tamandua_alert_id"])

    %{
      external_id: incident["id"],
      title: incident["title"] || incident["summary"],
      alert_id: alert_id
    }
  end

  defp extract_alert_id_from_text(text) when is_binary(text) do
    case Regex.run(~r/Tamandua Alert ID: ([a-f0-9-]{36})/i, text) do
      [_, id] -> id
      _ -> nil
    end
  end
  defp extract_alert_id_from_text(_), do: nil

  defp extract_user(event) do
    cond do
      agent = get_in(event, ["agent", "summary"]) -> agent
      user = get_in(event, ["user", "summary"]) -> user
      true -> "PagerDuty System"
    end
  end

  defp extract_notes(incident) do
    # Extract first note if available
    case incident["first_trigger_log_entry"] do
      %{"summary" => summary} -> summary
      _ -> nil
    end
  end

  defp extract_enrichment(incident, event) do
    %{
      pagerduty_incident_id: incident["id"],
      pagerduty_incident_number: incident["incident_number"],
      pagerduty_status: incident["status"],
      pagerduty_urgency: incident["urgency"],
      pagerduty_service: get_in(incident, ["service", "summary"]),
      pagerduty_assignees: extract_assignees(incident),
      pagerduty_event_type: event["event_type"]
    }
  end

  defp extract_assignees(incident) do
    case incident["assignments"] do
      assignments when is_list(assignments) ->
        Enum.map(assignments, fn assignment ->
          get_in(assignment, ["assignee", "summary"])
        end)
        |> Enum.reject(&is_nil/1)

      _ ->
        []
    end
  end
end
