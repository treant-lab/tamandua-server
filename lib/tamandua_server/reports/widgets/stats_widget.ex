defmodule TamanduaServer.Reports.Widgets.StatsWidget do
  @moduledoc """
  Stats card widget for displaying key metrics in reports.

  Supports:
  - Single or multiple stat cards
  - Automatic icon/color based on metric type
  - Trend indicators
  - Comparison with previous period
  """

  use TamanduaServer.Reports.Widgets.BaseWidget

  alias TamanduaServer.{Alerts, Agents, Telemetry, Detection}

  @impl true
  def widget_type, do: "stats"

  @impl true
  def widget_name, do: "Statistics Cards"

  @impl true
  def widget_description, do: "Display key metrics in card format"

  @impl true
  def widget_icon, do: "chart-square-bar"

  @impl true
  def default_params do
    %{
      "metrics" => ["total_agents", "open_alerts", "critical_alerts"],
      "show_change" => true,
      "layout" => "grid"
    }
  end

  @impl true
  def param_schema do
    [
      %{name: "show_change", type: :boolean, default: true},
      %{name: "layout", type: {:enum, ["grid", "horizontal", "vertical"]}, default: "grid"}
    ]
  end

  @impl true
  def render(widget_config, context) do
    params = widget_config.params
    metrics = params["metrics"] || default_params()["metrics"]

    stats = Enum.map(metrics, &fetch_metric(&1, context, params["show_change"]))

    {:ok, %{
      "type" => "stats",
      "title" => widget_config.title,
      "content" => stats,
      "layout" => params["layout"]
    }}
  end

  defp fetch_metric("total_agents", _context, _show_change) do
    %{
      "label" => "Total Agents",
      "value" => safe_call(fn -> Agents.count_all() end, 0),
      "icon" => "desktop-computer",
      "color" => "blue"
    }
  end

  defp fetch_metric("online_agents", _context, _show_change) do
    online = safe_call(fn -> Agents.count_online() end, 0)
    total = safe_call(fn -> Agents.count_all() end, 0)
    percentage = if total > 0, do: Float.round(online / total * 100, 1), else: 0

    %{
      "label" => "Online Agents",
      "value" => online,
      "subtitle" => "#{percentage}% coverage",
      "icon" => "status-online",
      "color" => "green"
    }
  end

  defp fetch_metric("open_alerts", _context, show_change) do
    open = safe_call(fn -> Alerts.count_open() end, 0)

    stat = %{
      "label" => "Open Alerts",
      "value" => open,
      "icon" => "bell",
      "color" => if(open > 10, do: "yellow", else: "blue")
    }

    if show_change do
      Map.put(stat, "change", "+#{open}")
    else
      stat
    end
  end

  defp fetch_metric("critical_alerts", _context, show_change) do
    critical = safe_call(fn -> Alerts.count_by_severity(:critical) end, 0)

    stat = %{
      "label" => "Critical Alerts",
      "value" => critical,
      "icon" => "exclamation",
      "color" => if(critical > 0, do: "red", else: "green")
    }

    if show_change and critical > 0 do
      Map.put(stat, "change", "+#{critical}")
    else
      stat
    end
  end

  defp fetch_metric("high_alerts", _context, _show_change) do
    high = safe_call(fn -> Alerts.count_by_severity(:high) end, 0)

    %{
      "label" => "High Severity Alerts",
      "value" => high,
      "icon" => "exclamation-circle",
      "color" => if(high > 0, do: "orange", else: "green")
    }
  end

  defp fetch_metric("events_today", _context, _show_change) do
    events = safe_call(fn -> Telemetry.count_events_today() end, 0)

    %{
      "label" => "Events Today",
      "value" => format_large_number(events),
      "icon" => "database",
      "color" => "blue"
    }
  end

  defp fetch_metric("detections_today", _context, _show_change) do
    detections = safe_call(fn -> Detection.count_detections_today() end, 0)

    %{
      "label" => "Detections Today",
      "value" => detections,
      "icon" => "shield-exclamation",
      "color" => if(detections > 0, do: "yellow", else: "green")
    }
  end

  defp fetch_metric("security_score", _context, _show_change) do
    # Calculate simple security score
    total_agents = safe_call(fn -> Agents.count_all() end, 0)
    online_agents = safe_call(fn -> Agents.count_online() end, 0)
    critical_alerts = safe_call(fn -> Alerts.count_by_severity(:critical) end, 0)
    high_alerts = safe_call(fn -> Alerts.count_by_severity(:high) end, 0)

    score = calculate_security_score(total_agents, online_agents, critical_alerts, high_alerts)
    color = cond do
      score >= 80 -> "green"
      score >= 60 -> "yellow"
      true -> "red"
    end

    %{
      "label" => "Security Score",
      "value" => "#{score}/100",
      "icon" => "shield-check",
      "color" => color
    }
  end

  defp fetch_metric(_unknown, _context, _show_change) do
    %{
      "label" => "Unknown Metric",
      "value" => "N/A",
      "icon" => "question-mark-circle",
      "color" => "gray"
    }
  end

  defp calculate_security_score(total_agents, online_agents, critical_alerts, high_alerts) do
    base_score = 100

    agent_penalty = if total_agents > 0 do
      offline_ratio = (total_agents - online_agents) / total_agents
      round(offline_ratio * 20)
    else
      20
    end

    critical_penalty = min(critical_alerts * 10, 30)
    high_penalty = min(high_alerts * 3, 15)

    max(0, base_score - agent_penalty - critical_penalty - high_penalty)
  end

  defp format_large_number(n) when n >= 1_000_000, do: "#{Float.round(n / 1_000_000, 1)}M"
  defp format_large_number(n) when n >= 1_000, do: "#{Float.round(n / 1_000, 1)}K"
  defp format_large_number(n), do: "#{n}"

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
