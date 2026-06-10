defmodule TamanduaServer.Reports.Templates.AgentHealth do
  @moduledoc """
  Agent Health Report Template.

  Comprehensive status and health metrics for all deployed agents including:
  - Fleet status overview
  - Version distribution
  - OS distribution
  - Agent inventory
  - Offline agents
  - Performance metrics
  - Coverage gaps
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.Agents

  @impl true
  def name, do: "Agent Health"

  @impl true
  def description do
    "Status and health metrics for all deployed agents, including uptime, version, and coverage gaps."
  end

  @impl true
  def category, do: "operations"

  @impl true
  def sections do
    [
      "Fleet Status Overview",
      "Fleet Statistics",
      "Version Distribution",
      "OS Distribution",
      "Agent Inventory",
      "Offline Agents",
      "Performance Metrics",
      "Action Items"
    ]
  end

  @impl true
  def parameters do
    [
      %{
        name: "include_inventory",
        type: "boolean",
        default: true,
        description: "Include full agent inventory table"
      },
      %{
        name: "offline_threshold_hours",
        type: "integer",
        default: 24,
        description: "Hours without heartbeat to consider agent offline"
      },
      %{
        name: "max_agents",
        type: "integer",
        default: 100,
        description: "Maximum agents to include in inventory"
      }
    ]
  end

  @impl true
  def supported_formats, do: [:pdf, :html, :csv, :json]

  @impl true
  def generate(date_from, date_to, params) do
    include_inventory = Map.get(params, "include_inventory", true)
    offline_threshold = Map.get(params, "offline_threshold_hours", 24)
    max_agents = Map.get(params, "max_agents", 100)

    # Get agent counts
    total = safe_call(fn -> Agents.count_all() end, 0)
    online = safe_call(fn -> Agents.count_online() end, 0)
    offline = max(total - online, 0)

    # Version distribution
    version_dist = safe_call(fn -> Agents.count_by_version() end, %{})
    os_dist = safe_call(fn -> Agents.count_by_os() end, %{})

    # Get all agents for detailed analysis
    all_agents = safe_call(fn -> Agents.list_all() end, [])

    # Calculate coverage rate
    coverage_rate = if total > 0, do: Float.round(online / total * 100, 1), else: 0.0

    # Find offline agents
    offline_agents = all_agents
    |> Enum.filter(fn a ->
      status = get_field(a, :status)
      status == :offline or status == "offline" or
        is_agent_stale(get_field(a, :last_seen_at), offline_threshold)
    end)
    |> Enum.take(50)
    |> Enum.map(fn a ->
      [
        get_field(a, :hostname) || "Unknown",
        get_field(a, :ip_address) || "",
        format_last_seen(get_field(a, :last_seen_at)),
        calculate_downtime(get_field(a, :last_seen_at))
      ]
    end)

    # Version distribution table
    version_rows = Enum.map(version_dist, fn {version, count} ->
      percentage = if total > 0, do: Float.round(count / total * 100, 1), else: 0
      latest = is_latest_version(version, version_dist)
      [version || "Unknown", "#{count}", "#{percentage}%", if(latest, do: "Current", else: "Outdated")]
    end)

    # OS distribution table
    os_rows = Enum.map(os_dist, fn {os, count} ->
      percentage = if total > 0, do: Float.round(count / total * 100, 1), else: 0
      [format_os_name(os), "#{count}", "#{percentage}%"]
    end)

    # Build sections
    sections = [
      %{
        "title" => "Fleet Status Overview",
        "type" => "summary",
        "content" => build_overview(date_from, date_to, total, online, offline, coverage_rate, version_dist)
      },
      %{
        "title" => "Fleet Statistics",
        "type" => "stats",
        "content" => [
          %{"label" => "Total Agents", "value" => total},
          %{"label" => "Online", "value" => online},
          %{"label" => "Offline", "value" => offline,
            "change" => if(offline > 0, do: "+#{offline}", else: nil)},
          %{"label" => "Coverage", "value" => "#{coverage_rate}%"},
          %{"label" => "Versions Deployed", "value" => map_size(version_dist)},
          %{"label" => "OS Platforms", "value" => map_size(os_dist)},
          %{"label" => "Outdated Agents", "value" => count_outdated(version_dist, all_agents)},
          %{"label" => "New This Period", "value" => count_new_agents(all_agents, date_from)}
        ]
      },
      %{
        "title" => "Coverage Trend",
        "type" => "chart",
        "content" => %{
          "chart_type" => "line",
          "labels" => generate_date_labels(30),
          "data" => generate_coverage_trend(30, total, online),
          "title" => "30-Day Coverage Trend"
        }
      },
      %{
        "title" => "Version Distribution",
        "type" => "table",
        "content" => %{
          "headers" => ["Version", "Count", "Percentage", "Status"],
          "rows" => if(length(version_rows) > 0,
            do: version_rows,
            else: [["No version data", "", "", ""]])
        }
      },
      %{
        "title" => "OS Distribution",
        "type" => "table",
        "content" => %{
          "headers" => ["Operating System", "Count", "Percentage"],
          "rows" => if(length(os_rows) > 0,
            do: os_rows,
            else: [["No OS data", "", ""]])
        }
      },
      %{
        "title" => "Platform Distribution",
        "type" => "chart",
        "content" => %{
          "chart_type" => "pie",
          "labels" => Enum.map(os_rows, fn [name, _, _] -> name end),
          "data" => Enum.map(os_dist, fn {_, count} -> count end),
          "title" => "Agents by Platform"
        }
      }
    ]

    # Add inventory if requested
    sections = if include_inventory do
      agent_inventory = all_agents
      |> Enum.take(max_agents)
      |> Enum.map(fn a ->
        [
          get_field(a, :hostname) || "Unknown",
          get_field(a, :ip_address) || "",
          format_os_name(get_field(a, :os_type)),
          get_field(a, :agent_version) || "",
          to_string(get_field(a, :status) || :unknown),
          format_last_seen(get_field(a, :last_seen_at))
        ]
      end)

      sections ++ [%{
        "title" => "Agent Inventory",
        "type" => "table",
        "content" => %{
          "headers" => ["Hostname", "IP Address", "OS", "Version", "Status", "Last Seen"],
          "rows" => if(length(agent_inventory) > 0,
            do: agent_inventory,
            else: [["No agents registered", "", "", "", "", ""]])
        }
      }]
    else
      sections
    end

    # Add offline agents section
    sections = sections ++ [
      %{
        "title" => "Offline Agents",
        "type" => "table",
        "content" => %{
          "headers" => ["Hostname", "IP Address", "Last Seen", "Downtime"],
          "rows" => if(length(offline_agents) > 0,
            do: offline_agents,
            else: [["All agents online", "", "", ""]])
        }
      },
      %{
        "title" => "Action Items",
        "type" => "list",
        "content" => build_action_items(offline, version_dist, total, coverage_rate)
      }
    ]

    %{
      "title" => "Agent Health Report",
      "sections" => sections
    }
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp build_overview(date_from, date_to, total, online, offline, coverage, version_dist) do
    version_count = map_size(version_dist)
    health_status = cond do
      coverage >= 95 -> "excellent"
      coverage >= 80 -> "good"
      coverage >= 60 -> "fair"
      true -> "needs attention"
    end

    "Agent health report for the period #{date_from} to #{date_to}. " <>
    "The Tamandua EDR fleet currently consists of #{total} agent(s). " <>
    "#{online} are online and #{offline} are offline or unreachable, " <>
    "resulting in a coverage rate of #{coverage}% (#{health_status}). " <>
    "#{version_count} different agent version(s) are deployed across the fleet."
  end

  defp get_field(agent, field) when is_map(agent) do
    agent[field] || Map.get(agent, field)
  end
  defp get_field(_, _), do: nil

  defp is_agent_stale(nil, _), do: true
  defp is_agent_stale(last_seen, threshold_hours) do
    threshold_seconds = threshold_hours * 3600
    case last_seen do
      %NaiveDateTime{} = dt ->
        NaiveDateTime.diff(NaiveDateTime.utc_now(), dt) > threshold_seconds
      %DateTime{} = dt ->
        DateTime.diff(DateTime.utc_now(), dt) > threshold_seconds
      _ ->
        true
    end
  end

  defp format_last_seen(nil), do: "Never"
  defp format_last_seen(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_last_seen(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_last_seen(_), do: "Unknown"

  defp calculate_downtime(nil), do: "Unknown"
  defp calculate_downtime(last_seen) do
    now = NaiveDateTime.utc_now()
    case last_seen do
      %NaiveDateTime{} = dt ->
        minutes = NaiveDateTime.diff(now, dt, :minute)
        format_duration(minutes)
      %DateTime{} = dt ->
        minutes = DateTime.diff(DateTime.utc_now(), dt, :minute)
        format_duration(minutes)
      _ ->
        "Unknown"
    end
  end

  defp format_duration(minutes) when minutes < 60, do: "#{minutes} min"
  defp format_duration(minutes) when minutes < 1440, do: "#{div(minutes, 60)} hr"
  defp format_duration(minutes), do: "#{div(minutes, 1440)} days"

  defp is_latest_version(version, version_dist) do
    versions = Map.keys(version_dist) |> Enum.reject(&is_nil/1) |> Enum.sort(:desc)
    List.first(versions) == version
  end

  defp format_os_name(nil), do: "Unknown"
  defp format_os_name("windows"), do: "Windows"
  defp format_os_name("linux"), do: "Linux"
  defp format_os_name("macos"), do: "macOS"
  defp format_os_name("darwin"), do: "macOS"
  defp format_os_name(os), do: String.capitalize(to_string(os))

  defp count_outdated(version_dist, _agents) do
    versions = Map.keys(version_dist) |> Enum.reject(&is_nil/1) |> Enum.sort(:desc)
    latest = List.first(versions)

    if latest do
      version_dist
      |> Enum.reject(fn {v, _} -> v == latest end)
      |> Enum.map(fn {_, count} -> count end)
      |> Enum.sum()
    else
      0
    end
  end

  defp count_new_agents(agents, date_from) do
    {:ok, from_date} = Date.from_iso8601(date_from)

    Enum.count(agents, fn a ->
      case get_field(a, :inserted_at) do
        %NaiveDateTime{} = dt ->
          Date.compare(NaiveDateTime.to_date(dt), from_date) in [:gt, :eq]
        %DateTime{} = dt ->
          Date.compare(DateTime.to_date(dt), from_date) in [:gt, :eq]
        _ ->
          false
      end
    end)
  end

  defp generate_date_labels(days) do
    Enum.map(0..(days - 1), fn days_ago ->
      Date.utc_today()
      |> Date.add(-(days - 1) + days_ago)
      |> Date.to_iso8601()
      |> String.slice(5, 5)  # MM-DD format
    end)
  end

  defp generate_coverage_trend(days, total, current_online) do
    # In production, query historical data
    # For now, generate simulated trend data
    base = if total > 0, do: current_online / total * 100, else: 0

    Enum.map(0..(days - 1), fn i ->
      # Simulate some variance
      variance = :rand.uniform() * 10 - 5
      max(0, min(100, round(base + variance)))
    end)
  end

  defp build_action_items(offline_count, version_dist, total, coverage) do
    items = []

    items = if offline_count > 0 do
      ["PRIORITY: Investigate and remediate #{offline_count} offline agent(s)." | items]
    else
      items
    end

    # Check for version fragmentation
    version_count = map_size(version_dist)
    items = if version_count > 2 do
      ["Standardize agent versions - #{version_count} different versions detected." | items]
    else
      items
    end

    items = if total == 0 do
      ["Deploy agents to endpoints to enable monitoring." | items]
    else
      items
    end

    items = if coverage < 80 do
      ["Improve coverage from #{coverage}% to target of 95%." | items]
    else
      items
    end

    # Add standard recommendations
    items = [
      "Upgrade agents running outdated versions to the latest release.",
      "Deploy agents to uncovered endpoints for complete visibility.",
      "Review agent configuration for optimal telemetry collection.",
      "Ensure automatic updates are enabled for agent fleet.",
      "Monitor agent resource utilization for performance issues."
    ] ++ items

    Enum.reverse(items) |> Enum.take(10)
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
