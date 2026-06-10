defmodule TamanduaServer.Integrations.WebhookParsers.Slack do
  @moduledoc """
  Parser for Slack interactive message webhooks.

  Handles:
  - Button clicks (action responses)
  - Slash commands
  - Block kit interactions
  """

  @behaviour TamanduaServer.Integrations.WebhookParsers.Behaviour

  @impl true
  def parse(payload, _opts) do
    # Slack sends URL-encoded payload parameter
    payload = decode_slack_payload(payload)

    action_type = determine_action(payload)
    alert_reference = extract_alert_reference(payload)

    # Extract the action that was taken
    action_info = extract_action_info(payload)

    parsed = %{
      action_type: action_type,
      alert_reference: alert_reference,
      external_id: payload["message_ts"] || payload["trigger_id"],
      external_status: action_info.status,
      user: get_in(payload, ["user", "name"]) || get_in(payload, ["user", "username"]),
      comment: action_info.comment,
      enrichment_data: %{
        slack_channel: get_in(payload, ["channel", "name"]),
        slack_user: get_in(payload, ["user", "name"]),
        slack_action: action_info.action_name
      },
      metadata: %{
        channel_id: get_in(payload, ["channel", "id"]),
        response_url: payload["response_url"],
        action_value: action_info.value
      },
      raw_payload: payload
    }

    {:ok, parsed}
  end

  defp decode_slack_payload(%{"payload" => encoded_payload}) when is_binary(encoded_payload) do
    case Jason.decode(URI.decode_www_form(encoded_payload)) do
      {:ok, decoded} -> decoded
      {:error, _} -> %{"error" => "Invalid JSON in Slack payload"}
    end
  end
  defp decode_slack_payload(payload), do: payload

  defp determine_action(%{"type" => "block_actions"}), do: :interactive_response
  defp determine_action(%{"type" => "interactive_message"}), do: :interactive_response
  defp determine_action(%{"command" => _}), do: :interactive_response
  defp determine_action(_), do: :alert_comment

  defp extract_alert_reference(payload) do
    # Extract alert ID from callback_id or message text
    callback_id = payload["callback_id"] || ""
    message_text = get_in(payload, ["message", "text"]) || ""

    alert_id = extract_alert_id_from_text(callback_id <> " " <> message_text)

    %{
      alert_id: alert_id,
      external_id: payload["message_ts"]
    }
  end

  defp extract_alert_id_from_text(text) when is_binary(text) do
    case Regex.run(~r/alert[_-]([a-f0-9-]{36})/i, text) do
      [_, id] -> id
      _ -> nil
    end
  end
  defp extract_alert_id_from_text(_), do: nil

  defp extract_action_info(payload) do
    actions = payload["actions"] || []

    case List.first(actions) do
      %{"name" => name, "value" => value, "text" => text} ->
        %{
          action_name: name,
          value: value,
          status: map_action_to_status(name, value),
          comment: extract_comment_from_action(text, name)
        }

      _ ->
        %{
          action_name: "unknown",
          value: nil,
          status: nil,
          comment: payload["text"]
        }
    end
  end

  defp map_action_to_status("resolve" <> _, _), do: "resolved"
  defp map_action_to_status("close" <> _, _), do: "resolved"
  defp map_action_to_status("investigate" <> _, _), do: "investigating"
  defp map_action_to_status("false_positive" <> _, _), do: "false_positive"
  defp map_action_to_status("dismiss" <> _, _), do: "false_positive"
  defp map_action_to_status(_, "resolved"), do: "resolved"
  defp map_action_to_status(_, "investigating"), do: "investigating"
  defp map_action_to_status(_, "false_positive"), do: "false_positive"
  defp map_action_to_status(_, _), do: nil

  defp extract_comment_from_action(%{"text" => text}, action_name) do
    "Action: #{action_name} - #{text}"
  end
  defp extract_comment_from_action(text, action_name) when is_binary(text) do
    "Action: #{action_name} - #{text}"
  end
  defp extract_comment_from_action(_, action_name) do
    "Action: #{action_name}"
  end
end
