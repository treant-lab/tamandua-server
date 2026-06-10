defmodule TamanduaServer.Integrations.WebhookParsers.Generic do
  @moduledoc """
  Generic webhook parser for custom integrations.

  Provides basic parsing for webhooks that follow a standard format.
  """

  @behaviour TamanduaServer.Integrations.WebhookParsers.Behaviour

  @impl true
  def parse(payload, _opts) do
    # Generic parser expects a standard format
    action_type = determine_action(payload)
    alert_reference = extract_alert_reference(payload)

    parsed = %{
      action_type: action_type,
      alert_reference: alert_reference,
      external_id: payload["id"] || payload["external_id"] || payload["ticket_id"],
      external_status: payload["status"] || payload["state"],
      external_url: payload["url"] || payload["link"],
      user: payload["user"] || payload["updated_by"],
      comment: payload["comment"] || payload["notes"] || payload["message"],
      resolution_notes: payload["resolution"] || payload["resolution_notes"],
      enrichment_data: payload["enrichment"] || %{},
      metadata: payload["metadata"] || %{},
      raw_payload: payload
    }

    {:ok, parsed}
  end

  defp determine_action(%{"action" => "status_update"}), do: :alert_status_update
  defp determine_action(%{"action" => "comment"}), do: :alert_comment
  defp determine_action(%{"action" => "enrich"}), do: :alert_enrichment
  defp determine_action(%{"action" => "sync"}), do: :incident_sync
  defp determine_action(%{"status" => status}) when status in ["resolved", "closed", "done"] do
    :alert_status_update
  end
  defp determine_action(_), do: :incident_sync

  defp extract_alert_reference(payload) do
    %{
      alert_id: payload["alert_id"] || payload["tamandua_alert_id"],
      external_id: payload["id"] || payload["external_id"],
      title: payload["title"] || payload["subject"]
    }
  end
end
