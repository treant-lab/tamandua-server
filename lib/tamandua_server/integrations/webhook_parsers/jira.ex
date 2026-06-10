defmodule TamanduaServer.Integrations.WebhookParsers.Jira do
  @moduledoc """
  Parser for Jira webhook events.

  Handles:
  - Issue status changed (Done, Resolved, Closed)
  - Issue commented
  - Issue updated
  """

  @behaviour TamanduaServer.Integrations.WebhookParsers.Behaviour

  @impl true
  def parse(payload, _opts) do
    webhook_event = payload["webhookEvent"]
    issue = payload["issue"] || %{}
    fields = issue["fields"] || %{}
    changelog = payload["changelog"]

    action_type = determine_action(webhook_event, changelog)
    alert_reference = extract_alert_reference(issue, fields)

    parsed = %{
      action_type: action_type,
      alert_reference: alert_reference,
      external_id: issue["key"],
      external_status: get_in(fields, ["status", "name"]) || "Open",
      external_url: get_in(issue, ["self"]) |> jira_browse_url(),
      user: get_in(payload, ["user", "displayName"]) || get_in(payload, ["user", "name"]),
      comment: extract_comment(payload),
      resolution_notes: extract_resolution(fields),
      enrichment_data: extract_enrichment(issue, fields),
      metadata: %{
        issue_type: get_in(fields, ["issuetype", "name"]),
        priority: get_in(fields, ["priority", "name"]),
        assignee: get_in(fields, ["assignee", "displayName"]),
        project_key: get_in(fields, ["project", "key"])
      },
      raw_payload: payload
    }

    {:ok, parsed}
  end

  defp determine_action("jira:issue_updated", %{"items" => items}) do
    status_changed? = Enum.any?(items, fn item ->
      item["field"] == "status"
    end)

    if status_changed?, do: :alert_status_update, else: :incident_sync
  end
  defp determine_action("comment_created", _), do: :alert_comment
  defp determine_action("comment_updated", _), do: :alert_comment
  defp determine_action(_, _), do: :incident_sync

  defp extract_alert_reference(issue, fields) do
    # Look for Tamandua alert ID in description or custom field
    description = fields["description"] || ""
    alert_id = extract_alert_id_from_text(description)

    %{
      external_id: issue["key"],
      title: fields["summary"],
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

  defp extract_comment(payload) do
    case payload["comment"] do
      %{"body" => body} -> body
      _ -> nil
    end
  end

  defp extract_resolution(fields) do
    case fields["resolution"] do
      %{"name" => name, "description" => desc} -> "#{name}: #{desc}"
      %{"name" => name} -> name
      _ -> nil
    end
  end

  defp extract_enrichment(issue, fields) do
    %{
      jira_issue_key: issue["key"],
      jira_status: get_in(fields, ["status", "name"]),
      jira_priority: get_in(fields, ["priority", "name"]),
      jira_assignee: get_in(fields, ["assignee", "displayName"]),
      jira_reporter: get_in(fields, ["reporter", "displayName"]),
      jira_labels: fields["labels"] || []
    }
  end

  defp jira_browse_url(api_url) when is_binary(api_url) do
    # Convert /rest/api/2/issue/KEY to /browse/KEY
    case Regex.run(~r{/rest/api/\d+/issue/([A-Z]+-\d+)}, api_url) do
      [_, key] ->
        base_url = String.replace(api_url, ~r{/rest/api.*}, "")
        "#{base_url}/browse/#{key}"
      _ ->
        api_url
    end
  end
  defp jira_browse_url(_), do: nil
end
