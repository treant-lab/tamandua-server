defmodule TamanduaServer.Integrations.WebhookParsers.QRadar do
  @moduledoc """
  Parser for IBM QRadar offense webhooks.

  Handles:
  - Offense created
  - Offense updated
  - Offense closed
  """

  @behaviour TamanduaServer.Integrations.WebhookParsers.Behaviour

  @impl true
  def parse(payload, _opts) do
    # QRadar sends offense data
    offense = payload["offense"] || payload

    action_type = determine_action(offense)
    alert_reference = extract_alert_reference(offense)

    parsed = %{
      action_type: action_type,
      alert_reference: alert_reference,
      external_id: to_string(offense["id"]),
      external_status: offense["status"] || "OPEN",
      external_url: build_qradar_url(offense),
      user: offense["assigned_to"] || offense["username_count"],
      comment: offense["closing_reason_id"] |> map_closing_reason(),
      resolution_notes: build_resolution_notes(offense),
      enrichment_data: extract_enrichment(offense),
      metadata: %{
        offense_id: offense["id"],
        magnitude: offense["magnitude"],
        credibility: offense["credibility"],
        relevance: offense["relevance"],
        event_count: offense["event_count"]
      },
      raw_payload: payload
    }

    {:ok, parsed}
  end

  defp determine_action(%{"status" => "CLOSED"}), do: :alert_status_update
  defp determine_action(%{"status" => "HIDDEN"}), do: :alert_status_update
  defp determine_action(%{"follow_up" => true}), do: :incident_sync
  defp determine_action(_), do: :incident_sync

  defp extract_alert_reference(offense) do
    # Look for Tamandua alert ID in description
    description = offense["description"] || ""
    alert_id = extract_alert_id_from_text(description)

    %{
      external_id: to_string(offense["id"]),
      title: description,
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

  defp build_resolution_notes(offense) do
    parts = []

    parts = if offense["closing_reason_id"], do: ["Closing Reason: #{map_closing_reason(offense["closing_reason_id"])}" | parts], else: parts
    parts = if offense["closing_user"], do: ["Closed By: #{offense["closing_user"]}" | parts], else: parts

    if length(parts) > 0 do
      Enum.join(parts, "\n")
    else
      nil
    end
  end

  defp extract_enrichment(offense) do
    %{
      qradar_offense_id: offense["id"],
      qradar_status: offense["status"],
      qradar_magnitude: offense["magnitude"],
      qradar_credibility: offense["credibility"],
      qradar_relevance: offense["relevance"],
      qradar_categories: offense["categories"] || [],
      qradar_source_ips: extract_source_ips(offense),
      qradar_destination_ips: extract_destination_ips(offense)
    }
  end

  defp extract_source_ips(offense) do
    case offense["source_address_ids"] do
      ids when is_list(ids) -> ids
      _ -> []
    end
  end

  defp extract_destination_ips(offense) do
    case offense["local_destination_address_ids"] do
      ids when is_list(ids) -> ids
      _ -> []
    end
  end

  defp build_qradar_url(%{"id" => id, "console_url" => console_url}) do
    "#{console_url}/console/qradar/jsp/QRadar.jsp?appName=Sem&pageId=OffenseSummary&summaryId=#{id}"
  end
  defp build_qradar_url(_), do: nil

  # Map QRadar closing reason IDs to human-readable text
  defp map_closing_reason(1), do: "False Positive"
  defp map_closing_reason(2), do: "Resolved"
  defp map_closing_reason(3), do: "Not an Issue"
  defp map_closing_reason(54), do: "Non-Issue"
  defp map_closing_reason(id) when is_integer(id), do: "Reason ID: #{id}"
  defp map_closing_reason(_), do: nil
end
