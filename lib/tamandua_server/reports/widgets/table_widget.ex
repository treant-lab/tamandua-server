defmodule TamanduaServer.Reports.Widgets.TableWidget do
  @moduledoc """
  Table widget for displaying tabular data in reports.

  Supports:
  - Multiple data sources
  - Column customization
  - Sorting and filtering
  - Pagination
  - Export to CSV
  """

  use TamanduaServer.Reports.Widgets.BaseWidget

  alias TamanduaServer.{Alerts, Agents, Detection}

  @impl true
  def widget_type, do: "table"

  @impl true
  def widget_name, do: "Data Table"

  @impl true
  def widget_description, do: "Display tabular data with sorting and filtering"

  @impl true
  def widget_icon, do: "table"

  @impl true
  def default_params do
    %{
      "data_source" => "recent_alerts",
      "columns" => [],
      "max_rows" => 10,
      "show_headers" => true,
      "striped" => true,
      "compact" => false
    }
  end

  @impl true
  def param_schema do
    [
      %{name: "data_source", type: {:enum, ["recent_alerts", "critical_alerts", "agent_list",
                                             "offline_agents", "top_threats", "recent_detections"]},
         default: "recent_alerts"},
      %{name: "max_rows", type: {:range, 1, 100}, default: 10},
      %{name: "show_headers", type: :boolean, default: true},
      %{name: "striped", type: :boolean, default: true},
      %{name: "compact", type: :boolean, default: false}
    ]
  end

  @impl true
  def render(widget_config, context) do
    params = widget_config.params
    data_source = params["data_source"]
    max_rows = params["max_rows"]

    {headers, rows} = fetch_table_data(data_source, context, max_rows)

    {:ok, %{
      "type" => "table",
      "title" => widget_config.title,
      "content" => %{
        "headers" => headers,
        "rows" => rows,
        "options" => %{
          "showHeaders" => params["show_headers"],
          "striped" => params["striped"],
          "compact" => params["compact"]
        }
      }
    }}
  end

  defp fetch_table_data("recent_alerts", context, max_rows) do
    headers = ["Date", "Title", "Severity", "Status", "Agent"]

    rows = safe_call(fn ->
      Alerts.list_alerts_in_range(context.date_from, context.date_to)
      |> Enum.take(max_rows)
      |> Enum.map(fn alert ->
        [
          format_datetime(alert.inserted_at),
          alert.title || "Untitled",
          to_string(alert.severity),
          to_string(alert.status),
          alert.agent_id || "N/A"
        ]
      end)
    end, [])

    {headers, rows}
  end

  defp fetch_table_data("critical_alerts", context, max_rows) do
    headers = ["Date", "Title", "MITRE Technique", "Status"]

    rows = safe_call(fn ->
      Alerts.list_alerts_in_range(context.date_from, context.date_to)
      |> Enum.filter(&(&1.severity in [:critical, "critical"]))
      |> Enum.take(max_rows)
      |> Enum.map(fn alert ->
        techniques = List.first(alert.mitre_techniques || []) || "N/A"
        [
          format_datetime(alert.inserted_at),
          alert.title || "Untitled",
          techniques,
          to_string(alert.status)
        ]
      end)
    end, [])

    {headers, rows}
  end

  defp fetch_table_data("agent_list", _context, max_rows) do
    headers = ["Hostname", "IP Address", "OS", "Version", "Status", "Last Seen"]

    rows = safe_call(fn ->
      Agents.list_all()
      |> Enum.take(max_rows)
      |> Enum.map(fn agent ->
        [
          agent[:hostname] || agent.hostname || "Unknown",
          agent[:ip_address] || Map.get(agent, :ip_address, "") || "",
          to_string(agent[:os_type] || Map.get(agent, :os_type, "")),
          agent[:agent_version] || Map.get(agent, :agent_version, "") || "",
          to_string(agent[:status] || Map.get(agent, :status, :unknown)),
          format_datetime(agent[:last_seen_at] || Map.get(agent, :last_seen_at))
        ]
      end)
    end, [])

    {headers, rows}
  end

  defp fetch_table_data("offline_agents", _context, max_rows) do
    headers = ["Hostname", "IP Address", "Last Seen", "Days Offline"]

    rows = safe_call(fn ->
      Agents.list_all()
      |> Enum.filter(fn agent ->
        status = agent[:status] || Map.get(agent, :status)
        status == :offline or status == "offline"
      end)
      |> Enum.take(max_rows)
      |> Enum.map(fn agent ->
        last_seen = agent[:last_seen_at] || Map.get(agent, :last_seen_at)
        days_offline = calculate_days_offline(last_seen)

        [
          agent[:hostname] || agent.hostname || "Unknown",
          agent[:ip_address] || Map.get(agent, :ip_address, "") || "",
          format_datetime(last_seen),
          to_string(days_offline)
        ]
      end)
    end, [])

    {headers, rows}
  end

  defp fetch_table_data("top_threats", _context, max_rows) do
    headers = ["Threat Name", "MITRE ID", "Tactic", "Count"]

    rows = safe_call(fn ->
      Detection.get_top_techniques(limit: max_rows)
      |> Enum.map(fn {tech_id, name, count} ->
        tactic = get_technique_tactic(tech_id)
        [name, tech_id, tactic, to_string(count)]
      end)
    end, [])

    {headers, rows}
  end

  defp fetch_table_data("recent_detections", context, max_rows) do
    headers = ["Date", "Detection", "Severity", "Agent", "Rule"]

    rows = safe_call(fn ->
      Detection.list_detections_in_range(context.date_from, context.date_to)
      |> Enum.take(max_rows)
      |> Enum.map(fn detection ->
        [
          format_datetime(detection.detected_at),
          detection.name || "Unnamed Detection",
          to_string(detection.severity || "medium"),
          detection.agent_id || "N/A",
          detection.rule_name || "N/A"
        ]
      end)
    end, [])

    {headers, rows}
  end

  defp fetch_table_data(_unknown, _context, _max_rows) do
    {["No data"], [["No data available"]]}
  end

  defp format_datetime(nil), do: "Never"
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_datetime(_), do: "Unknown"

  defp calculate_days_offline(nil), do: "Unknown"
  defp calculate_days_offline(last_seen) do
    now = DateTime.utc_now()
    last_seen_dt = case last_seen do
      %NaiveDateTime{} = ndt -> DateTime.from_naive!(ndt, "Etc/UTC")
      %DateTime{} = dt -> dt
      _ -> now
    end
    DateTime.diff(now, last_seen_dt, :day)
  end

  defp get_technique_tactic(technique_id) do
    case TamanduaServer.Detection.Mitre.get_technique(technique_id) do
      nil -> "Unknown"
      technique -> List.first(technique.tactics) || "Unknown"
    end
  rescue
    _ -> "Unknown"
  end

  defp safe_call(fun, default) do
    try do
      fun.()
    rescue
      _ -> default
    catch
      _, _ -> default
    end
  end
end
