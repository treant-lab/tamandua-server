defmodule TamanduaServer.Alerts.Exporters.JSONExporter do
  @moduledoc """
  Generates JSON exports of alerts.

  Produces structured JSON with configurable fields and nested data.
  """

  alias TamanduaServer.Alerts.Alert

  @doc """
  Generates JSON data from alerts.

  ## Parameters
  - `alerts` - List of Alert structs (preloaded with associations)
  - `columns` - List of column names to include

  ## Returns
  Pretty-printed JSON string.
  """
  def generate(alerts, columns) when is_list(alerts) and is_list(columns) do
    data = %{
      metadata: %{
        exported_at: DateTime.utc_now() |> DateTime.to_iso8601(),
        total_count: length(alerts),
        columns: columns
      },
      alerts: Enum.map(alerts, &alert_to_json(&1, columns))
    }

    Jason.encode!(data, pretty: true)
  end

  defp alert_to_json(alert, columns) do
    columns
    |> Enum.reduce(%{}, fn column, acc ->
      value = extract_value(alert, column)
      Map.put(acc, column, value)
    end)
  end

  # Extract value from alert based on column name
  defp extract_value(alert, "id"), do: alert.id
  defp extract_value(alert, "severity"), do: alert.severity
  defp extract_value(alert, "title"), do: alert.title
  defp extract_value(alert, "description"), do: alert.description
  defp extract_value(alert, "status"), do: alert.status
  defp extract_value(alert, "verdict"), do: alert.verdict
  defp extract_value(alert, "threat_score"), do: alert.threat_score

  defp extract_value(%{agent: agent} = _alert, "agent_hostname") when not is_nil(agent) do
    agent.hostname
  end

  defp extract_value(%{agent: agent} = _alert, "agent_os") when not is_nil(agent) do
    agent.os_type
  end

  defp extract_value(%{assigned_to: user} = _alert, "assigned_to_name") when not is_nil(user) do
    user.name
  end

  defp extract_value(alert, "mitre_tactics"), do: alert.mitre_tactics
  defp extract_value(alert, "mitre_techniques"), do: alert.mitre_techniques
  defp extract_value(alert, "attributed_actors"), do: alert.attributed_actors
  defp extract_value(alert, "campaign_id"), do: alert.campaign_id
  defp extract_value(alert, "occurrence_count"), do: alert.occurrence_count
  defp extract_value(alert, "workflow_state"), do: alert.workflow_state
  defp extract_value(alert, "escalation_level"), do: alert.escalation_level
  defp extract_value(alert, "sla_acknowledge_breached"), do: alert.sla_acknowledge_breached
  defp extract_value(alert, "sla_resolve_breached"), do: alert.sla_resolve_breached

  defp extract_value(alert, "inserted_at") do
    if alert.inserted_at, do: DateTime.to_iso8601(alert.inserted_at), else: nil
  end

  defp extract_value(alert, "acknowledged_at") do
    if alert.acknowledged_at, do: DateTime.to_iso8601(alert.acknowledged_at), else: nil
  end

  defp extract_value(alert, "resolved_at") do
    if alert.resolved_at, do: DateTime.to_iso8601(alert.resolved_at), else: nil
  end

  defp extract_value(alert, "last_seen_at") do
    if alert.last_seen_at, do: DateTime.to_iso8601(alert.last_seen_at), else: nil
  end

  defp extract_value(_alert, _column), do: nil
end
