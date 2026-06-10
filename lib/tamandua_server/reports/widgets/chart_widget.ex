defmodule TamanduaServer.Reports.Widgets.ChartWidget do
  @moduledoc """
  Chart widget for visualizing data in reports.

  Supports:
  - Bar charts
  - Line charts
  - Pie charts
  - Area charts
  - Multiple data sources (alerts, agents, events, detections)
  """

  use TamanduaServer.Reports.Widgets.BaseWidget

  alias TamanduaServer.{Alerts, Agents, Telemetry, Detection}

  @impl true
  def widget_type, do: "chart"

  @impl true
  def widget_name, do: "Chart"

  @impl true
  def widget_description, do: "Visualize data with bar, line, pie, or area charts"

  @impl true
  def widget_icon, do: "chart-bar"

  @impl true
  def default_params do
    %{
      "chart_type" => "bar",
      "data_source" => "alerts_by_severity",
      "color_scheme" => "default",
      "show_legend" => true,
      "show_values" => true,
      "height" => 300
    }
  end

  @impl true
  def param_schema do
    [
      %{name: "chart_type", type: {:enum, ["bar", "line", "pie", "area"]}, default: "bar"},
      %{name: "data_source", type: {:enum, ["alerts_by_severity", "alerts_by_status", "agents_by_os",
                                             "agents_by_status", "top_threats", "events_timeline"]}, default: "alerts_by_severity"},
      %{name: "color_scheme", type: {:enum, ["default", "security", "status", "custom"]}, default: "default"},
      %{name: "show_legend", type: :boolean, default: true},
      %{name: "show_values", type: :boolean, default: true},
      %{name: "height", type: {:range, 200, 600}, default: 300}
    ]
  end

  @impl true
  def render(widget_config, context) do
    params = widget_config.params
    data_source = params["data_source"]

    {labels, data} = fetch_data(data_source, context)
    colors = get_color_scheme(params["color_scheme"], length(data))

    {:ok, %{
      "type" => "chart",
      "title" => widget_config.title,
      "content" => %{
        "chart_type" => params["chart_type"],
        "labels" => labels,
        "data" => data,
        "colors" => colors,
        "options" => %{
          "showLegend" => params["show_legend"],
          "showValues" => params["show_values"],
          "height" => params["height"]
        }
      }
    }}
  end

  defp fetch_data("alerts_by_severity", _context) do
    severities = ["critical", "high", "medium", "low", "info"]
    counts = Enum.map(severities, fn sev ->
      safe_call(fn -> Alerts.count_by_severity(String.to_atom(sev)) end, 0)
    end)
    {Enum.map(severities, &String.capitalize/1), counts}
  end

  defp fetch_data("alerts_by_status", _context) do
    statuses = ["open", "investigating", "resolved", "false_positive"]
    counts = Enum.map(statuses, fn status ->
      safe_call(fn -> Alerts.count_by_status(status) end, 0)
    end)
    {Enum.map(statuses, &format_status/1), counts}
  end

  defp fetch_data("agents_by_os", _context) do
    os_dist = safe_call(fn -> Agents.count_by_os() end, %{})
    labels = Map.keys(os_dist)
    data = Map.values(os_dist)
    {labels, data}
  end

  defp fetch_data("agents_by_status", _context) do
    online = safe_call(fn -> Agents.count_online() end, 0)
    total = safe_call(fn -> Agents.count_all() end, 0)
    offline = max(total - online, 0)
    {["Online", "Offline"], [online, offline]}
  end

  defp fetch_data("top_threats", _context) do
    threats = safe_call(fn ->
      Detection.get_top_techniques(limit: 10)
      |> Enum.map(fn {_id, name, count} -> {name, count} end)
    end, [])

    if length(threats) > 0 do
      {labels, data} = Enum.unzip(threats)
      {labels, data}
    else
      {["No threats"], [0]}
    end
  end

  defp fetch_data("events_timeline", context) do
    # Generate daily event counts for the period
    days = safe_call(fn ->
      Telemetry.get_daily_event_counts(context.date_from, context.date_to)
    end, %{})

    labels = Map.keys(days) |> Enum.sort()
    data = Enum.map(labels, &Map.get(days, &1, 0))
    {labels, data}
  end

  defp fetch_data(_unknown, _context) do
    {["No data"], [0]}
  end

  defp get_color_scheme("security", count) do
    base_colors = ["#dc3545", "#fd7e14", "#ffc107", "#28a745", "#17a2b8"]
    List.duplicate(base_colors, ceil(count / length(base_colors))) |> Enum.take(count)
  end

  defp get_color_scheme("status", count) do
    base_colors = ["#0066cc", "#28a745", "#ffc107", "#dc3545"]
    List.duplicate(base_colors, ceil(count / length(base_colors))) |> Enum.take(count)
  end

  defp get_color_scheme(_default, count) do
    base_colors = ["#0066cc", "#00d4aa", "#6366f1", "#ec4899", "#f59e0b", "#10b981"]
    List.duplicate(base_colors, ceil(count / length(base_colors))) |> Enum.take(count)
  end

  defp format_status("open"), do: "Open"
  defp format_status("investigating"), do: "Investigating"
  defp format_status("resolved"), do: "Resolved"
  defp format_status("false_positive"), do: "False Positive"
  defp format_status(status), do: String.capitalize(status)

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
