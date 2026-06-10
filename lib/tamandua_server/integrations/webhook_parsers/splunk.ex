defmodule TamanduaServer.Integrations.WebhookParsers.Splunk do
  @moduledoc """
  Parser for Splunk alert webhooks.

  Handles:
  - Notable event closed/resolved
  - Alert suppressed
  - SOAR investigation updated
  """

  @behaviour TamanduaServer.Integrations.WebhookParsers.Behaviour

  @impl true
  def parse(payload, _opts) do
    result = payload["result"] || payload

    # Extract action type
    action_type = determine_action(result)

    # Extract alert reference
    alert_reference = extract_alert_reference(result)

    # Extract status
    external_status = result["status"] || result["urgency"] || "5"

    # Build normalized response
    parsed = %{
      action_type: action_type,
      alert_reference: alert_reference,
      external_id: result["event_id"] || result["sid"],
      external_status: external_status,
      external_url: build_splunk_url(result),
      user: result["owner"] || result["user"],
      comment: result["comment"] || result["description"],
      resolution_notes: result["description"],
      enrichment_data: extract_enrichment(result),
      metadata: %{
        search_name: result["search_name"],
        app: result["app"],
        severity: result["severity"]
      },
      raw_payload: payload
    }

    {:ok, parsed}
  end

  defp determine_action(%{"status" => "5"}), do: :alert_status_update # Closed
  defp determine_action(%{"status" => "4"}), do: :alert_status_update # False Positive
  defp determine_action(%{"comment" => _}), do: :alert_comment
  defp determine_action(_), do: :incident_sync

  defp extract_alert_reference(result) do
    %{
      external_id: result["event_id"] || result["sid"],
      title: result["search_name"] || result["name"],
      alert_id: result["tamandua_alert_id"]
    }
  end

  defp extract_enrichment(result) do
    %{
      splunk_search_id: result["sid"],
      splunk_app: result["app"],
      splunk_severity: result["severity"],
      splunk_owner: result["owner"]
    }
  end

  defp build_splunk_url(%{"sid" => sid, "splunk_server" => server}) do
    "#{server}/app/search/search?sid=#{sid}"
  end
  defp build_splunk_url(_), do: nil
end
