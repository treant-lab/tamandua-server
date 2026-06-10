defmodule TamanduaServer.Alerts.Exporters.CSVExporter do
  @moduledoc """
  Generates CSV exports of alerts.

  Uses NimbleCSV for efficient CSV generation with Excel compatibility.
  """

  alias TamanduaServer.Alerts.Alert

  # Define CSV module with Excel-compatible settings
  NimbleCSV.define(ExcelCSV, separator: ",", escape: "\"", moduledoc: false)

  @doc """
  Generates CSV data from alerts.

  ## Parameters
  - `alerts` - List of Alert structs (preloaded with associations)
  - `columns` - List of column names to include

  ## Returns
  CSV string ready to be written to file or downloaded.
  """
  def generate(alerts, columns) when is_list(alerts) and is_list(columns) do
    # Generate header row
    headers = Enum.map(columns, &column_to_header/1)

    # Generate data rows
    rows = Enum.map(alerts, fn alert ->
      Enum.map(columns, fn column ->
        extract_value(alert, column)
        |> format_value()
      end)
    end)

    # Encode to CSV
    ExcelCSV.dump_to_iodata([headers | rows])
    |> IO.iodata_to_binary()
  end

  # Column name to human-readable header
  defp column_to_header("id"), do: "ID"
  defp column_to_header("severity"), do: "Severity"
  defp column_to_header("title"), do: "Title"
  defp column_to_header("description"), do: "Description"
  defp column_to_header("status"), do: "Status"
  defp column_to_header("verdict"), do: "Verdict"
  defp column_to_header("threat_score"), do: "Threat Score"
  defp column_to_header("agent_hostname"), do: "Agent Hostname"
  defp column_to_header("agent_os"), do: "Agent OS"
  defp column_to_header("assigned_to_name"), do: "Assigned To"
  defp column_to_header("mitre_tactics"), do: "MITRE Tactics"
  defp column_to_header("mitre_techniques"), do: "MITRE Techniques"
  defp column_to_header("attributed_actors"), do: "Attributed Actors"
  defp column_to_header("campaign_id"), do: "Campaign ID"
  defp column_to_header("occurrence_count"), do: "Occurrence Count"
  defp column_to_header("workflow_state"), do: "Workflow State"
  defp column_to_header("escalation_level"), do: "Escalation Level"
  defp column_to_header("sla_acknowledge_breached"), do: "SLA Acknowledge Breached"
  defp column_to_header("sla_resolve_breached"), do: "SLA Resolve Breached"
  defp column_to_header("inserted_at"), do: "Created At"
  defp column_to_header("acknowledged_at"), do: "Acknowledged At"
  defp column_to_header("resolved_at"), do: "Resolved At"
  defp column_to_header("last_seen_at"), do: "Last Seen At"
  defp column_to_header(column), do: String.replace(column, "_", " ") |> String.capitalize()

  # Extract value from alert based on column name
  defp extract_value(alert, "id"), do: alert.id
  defp extract_value(alert, "severity"), do: alert.severity
  defp extract_value(alert, "title"), do: alert.title
  defp extract_value(alert, "description"), do: alert.description
  defp extract_value(alert, "status"), do: alert.status
  defp extract_value(alert, "verdict"), do: alert.verdict
  defp extract_value(alert, "threat_score"), do: alert.threat_score
  defp extract_value(%{agent: agent} = _alert, "agent_hostname") when not is_nil(agent), do: agent.hostname
  defp extract_value(%{agent: agent} = _alert, "agent_os") when not is_nil(agent), do: agent.os_type
  defp extract_value(%{assigned_to: user} = _alert, "assigned_to_name") when not is_nil(user), do: user.name
  defp extract_value(alert, "mitre_tactics"), do: alert.mitre_tactics
  defp extract_value(alert, "mitre_techniques"), do: alert.mitre_techniques
  defp extract_value(alert, "attributed_actors"), do: alert.attributed_actors
  defp extract_value(alert, "campaign_id"), do: alert.campaign_id
  defp extract_value(alert, "occurrence_count"), do: alert.occurrence_count
  defp extract_value(alert, "workflow_state"), do: alert.workflow_state
  defp extract_value(alert, "escalation_level"), do: alert.escalation_level
  defp extract_value(alert, "sla_acknowledge_breached"), do: alert.sla_acknowledge_breached
  defp extract_value(alert, "sla_resolve_breached"), do: alert.sla_resolve_breached
  defp extract_value(alert, "inserted_at"), do: alert.inserted_at
  defp extract_value(alert, "acknowledged_at"), do: alert.acknowledged_at
  defp extract_value(alert, "resolved_at"), do: alert.resolved_at
  defp extract_value(alert, "last_seen_at"), do: alert.last_seen_at
  defp extract_value(_alert, _column), do: nil

  # Format value for CSV output
  defp format_value(nil), do: ""
  defp format_value(true), do: "Yes"
  defp format_value(false), do: "No"
  defp format_value(value) when is_list(value), do: Enum.join(value, "; ")
  defp format_value(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  defp format_value(value) when is_number(value), do: to_string(value)
  defp format_value(value) when is_binary(value), do: value
  defp format_value(value), do: inspect(value)
end
