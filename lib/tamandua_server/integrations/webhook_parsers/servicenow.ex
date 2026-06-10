defmodule TamanduaServer.Integrations.WebhookParsers.ServiceNow do
  @moduledoc """
  Parser for ServiceNow incident/ticket webhooks.

  Handles:
  - Incident resolved
  - Incident closed
  - Incident work notes added
  """

  @behaviour TamanduaServer.Integrations.WebhookParsers.Behaviour

  @impl true
  def parse(payload, _opts) do
    # ServiceNow sends business rule webhook with current and previous record
    current = payload["current"] || payload
    previous = payload["previous"] || %{}

    action_type = determine_action(current, previous)
    alert_reference = extract_alert_reference(current)

    parsed = %{
      action_type: action_type,
      alert_reference: alert_reference,
      external_id: current["sys_id"] || current["number"],
      external_status: current["state"] || current["incident_state"],
      external_url: build_servicenow_url(current),
      user: current["sys_updated_by"] || current["assigned_to"],
      comment: current["work_notes"] || current["comments"],
      resolution_notes: build_resolution_notes(current),
      enrichment_data: extract_enrichment(current),
      metadata: %{
        incident_number: current["number"],
        priority: current["priority"],
        category: current["category"],
        impact: current["impact"]
      },
      raw_payload: payload
    }

    {:ok, parsed}
  end

  defp determine_action(%{"state" => "6"}, %{"state" => prev}) when prev != "6" do
    :alert_status_update # Resolved
  end
  defp determine_action(%{"state" => "7"}, %{"state" => prev}) when prev != "7" do
    :alert_status_update # Closed
  end
  defp determine_action(%{"work_notes" => notes}, _) when notes not in [nil, ""] do
    :alert_comment
  end
  defp determine_action(_, _), do: :incident_sync

  defp extract_alert_reference(record) do
    # Look for Tamandua alert ID in description or work notes
    description = record["description"] || ""
    short_description = record["short_description"] || ""
    alert_id = extract_alert_id_from_text(description <> " " <> short_description)

    %{
      external_id: record["sys_id"] || record["number"],
      title: record["short_description"],
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

  defp build_resolution_notes(record) do
    parts = []

    parts = if record["close_notes"], do: ["Close Notes: #{record["close_notes"]}" | parts], else: parts
    parts = if record["resolution_code"], do: ["Resolution Code: #{record["resolution_code"]}" | parts], else: parts

    if length(parts) > 0 do
      Enum.join(parts, "\n")
    else
      nil
    end
  end

  defp extract_enrichment(record) do
    %{
      servicenow_number: record["number"],
      servicenow_sys_id: record["sys_id"],
      servicenow_state: record["state"],
      servicenow_priority: record["priority"],
      servicenow_assigned_to: record["assigned_to"],
      servicenow_assignment_group: record["assignment_group"]
    }
  end

  defp build_servicenow_url(%{"sys_id" => sys_id, "instance" => instance}) do
    "https://#{instance}.service-now.com/nav_to.do?uri=incident.do?sys_id=#{sys_id}"
  end
  defp build_servicenow_url(%{"number" => number, "instance" => instance}) do
    "https://#{instance}.service-now.com/incident.do?sysparm_query=number=#{number}"
  end
  defp build_servicenow_url(_), do: nil
end
