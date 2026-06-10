defmodule TamanduaServer.Integrations.WebhookParsers.Sentinel do
  @moduledoc """
  Parser for Microsoft Sentinel (Azure Sentinel) incident webhooks.

  Handles:
  - Incident created
  - Incident status changed
  - Incident closed
  """

  @behaviour TamanduaServer.Integrations.WebhookParsers.Behaviour

  @impl true
  def parse(payload, _opts) do
    # Sentinel Logic App sends incident data
    properties = payload["properties"] || payload
    incident = properties["Incident"] || properties

    action_type = determine_action(incident)
    alert_reference = extract_alert_reference(incident)

    parsed = %{
      action_type: action_type,
      alert_reference: alert_reference,
      external_id: incident["IncidentNumber"] || incident["name"],
      external_status: incident["Status"] || incident["status"],
      external_url: incident["IncidentUrl"] || build_sentinel_url(incident),
      user: get_in(incident, ["Owner", "userPrincipalName"]) || incident["ModifiedBy"],
      comment: incident["Comments"] || extract_comments(incident),
      resolution_notes: build_resolution_notes(incident),
      enrichment_data: extract_enrichment(incident),
      metadata: %{
        incident_number: incident["IncidentNumber"],
        severity: incident["Severity"],
        classification: incident["Classification"],
        classification_comment: incident["ClassificationComment"]
      },
      raw_payload: payload
    }

    {:ok, parsed}
  end

  defp determine_action(%{"Status" => "Closed"}), do: :alert_status_update
  defp determine_action(%{"Status" => "Active"}), do: :incident_sync
  defp determine_action(%{"Classification" => classification}) when classification != nil do
    :alert_status_update
  end
  defp determine_action(_), do: :incident_sync

  defp extract_alert_reference(incident) do
    # Look for Tamandua alert ID in title or description
    title = incident["Title"] || incident["title"] || ""
    description = incident["Description"] || incident["description"] || ""
    alert_id = extract_alert_id_from_text(title <> " " <> description)

    %{
      external_id: incident["IncidentNumber"] || incident["name"],
      title: incident["Title"] || incident["title"],
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

  defp build_resolution_notes(incident) do
    parts = []

    parts = if incident["Classification"], do: ["Classification: #{incident["Classification"]}" | parts], else: parts
    parts = if incident["ClassificationComment"], do: ["Comment: #{incident["ClassificationComment"]}" | parts], else: parts
    parts = if incident["ClassificationReason"], do: ["Reason: #{incident["ClassificationReason"]}" | parts], else: parts

    if length(parts) > 0 do
      Enum.join(parts, "\n")
    else
      nil
    end
  end

  defp extract_comments(incident) do
    case incident["Comments"] do
      comments when is_list(comments) ->
        comments
        |> Enum.map(fn comment -> comment["message"] || comment end)
        |> Enum.join("\n")

      comment when is_binary(comment) ->
        comment

      _ ->
        nil
    end
  end

  defp extract_enrichment(incident) do
    %{
      sentinel_incident_number: incident["IncidentNumber"],
      sentinel_severity: incident["Severity"],
      sentinel_status: incident["Status"],
      sentinel_classification: incident["Classification"],
      sentinel_tactics: incident["AdditionalData"]["tactics"] || [],
      sentinel_alerts_count: incident["AlertsCount"]
    }
  end

  defp build_sentinel_url(incident) do
    # Build Azure portal URL for incident
    case incident do
      %{"WorkspaceId" => workspace_id, "IncidentNumber" => number} ->
        "https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights/IncidentBlade/incidentId/#{number}/workspaceId/#{workspace_id}"

      _ ->
        nil
    end
  end
end
