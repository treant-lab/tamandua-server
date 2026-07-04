defmodule TamanduaServer.Reports.Templates.AlertDetailReport do
  @moduledoc """
  Alert Detail Report Template.

  Comprehensive breakdown of all alerts in a time period including:
  - Alert timeline
  - Severity distribution
  - Status breakdown
  - Affected hosts
  - MITRE ATT&CK mapping
  - Response actions taken
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.{Alerts, Agents}
  alias TamanduaServer.Detection.Mitre

  @impl true
  def name, do: "Alert Detail Report"

  @impl true
  def description do
    "Detailed breakdown of all security alerts, including timeline, affected assets, and response actions"
  end

  @impl true
  def category, do: "security"

  @impl true
  def sections do
    [
      "Alert Summary",
      "Severity Distribution",
      "Alert Timeline",
      "Affected Hosts",
      "MITRE ATT&CK Coverage",
      "Response Actions",
      "Resolution Statistics"
    ]
  end

  @impl true
  def parameters do
    [
      %{
        name: "include_resolved",
        type: "boolean",
        default: true,
        description: "Include resolved alerts in the report"
      },
      %{
        name: "include_false_positives",
        type: "boolean",
        default: false,
        description: "Include alerts marked as false positives"
      },
      %{
        name: "min_severity",
        type: "string",
        default: "low",
        description: "Minimum severity level to include (low, medium, high, critical)"
      },
      %{
        name: "max_alerts",
        type: "integer",
        default: 100,
        description: "Maximum number of alerts to include in detail view"
      }
    ]
  end

  @impl true
  def supported_formats, do: [:pdf, :html, :csv, :json]

  @impl true
  def generate(date_from, date_to, params) do
    include_resolved = Map.get(params, "include_resolved", true)
    include_fps = Map.get(params, "include_false_positives", false)
    max_alerts = Map.get(params, "max_alerts", 100)

    # Fetch alerts in range (tenant-scoped; fails closed to [] when no
    # organization is provided to avoid cross-tenant leakage)
    organization_id = params["organization_id"] || params[:organization_id]

    alerts =
      if organization_id do
        safe_call(fn ->
          Alerts.list_alerts_in_range_for_org(organization_id, date_from, date_to)
          |> filter_alerts(include_resolved, include_fps)
          |> Enum.take(max_alerts)
        end, [])
      else
        []
      end

    total_alerts = length(alerts)

    # Group by severity
    by_severity = Enum.group_by(alerts, & &1.severity)
    critical_count = length(Map.get(by_severity, :critical, []) ++ Map.get(by_severity, "critical", []))
    high_count = length(Map.get(by_severity, :high, []) ++ Map.get(by_severity, "high", []))
    medium_count = length(Map.get(by_severity, :medium, []) ++ Map.get(by_severity, "medium", []))
    low_count = length(Map.get(by_severity, :low, []) ++ Map.get(by_severity, "low", []))

    # Group by status
    by_status = Enum.group_by(alerts, & &1.status)
    open_count = length(Map.get(by_status, "open", []))
    investigating_count = length(Map.get(by_status, "investigating", []))
    resolved_count = length(Map.get(by_status, "resolved", []))
    fp_count = length(Map.get(by_status, "false_positive", []))

    # Affected hosts
    affected_hosts = alerts
      |> Enum.map(& &1.agent_id)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    # MITRE techniques
    mitre_techniques = alerts
      |> Enum.flat_map(& &1.mitre_techniques || [])
      |> Enum.frequencies()
      |> Enum.sort_by(fn {_, count} -> -count end)
      |> Enum.take(15)

    # Response times
    avg_response_time = calculate_avg_response_time(alerts)
    median_response_time = calculate_median_response_time(alerts)

    # Build sections
    sections = [
      %{
        "title" => "Alert Summary",
        "type" => "summary",
        "content" => build_summary(date_from, date_to, total_alerts, affected_hosts, critical_count)
      },
      %{
        "title" => "Key Metrics",
        "type" => "stats",
        "content" => [
          %{"label" => "Total Alerts", "value" => total_alerts},
          %{"label" => "Critical", "value" => critical_count},
          %{"label" => "High", "value" => high_count},
          %{"label" => "Affected Hosts", "value" => length(affected_hosts)},
          %{"label" => "Avg Response Time", "value" => avg_response_time},
          %{"label" => "Resolution Rate", "value" => "#{calculate_resolution_rate(resolved_count, total_alerts)}%"}
        ]
      },
      %{
        "title" => "Severity Distribution",
        "type" => "chart",
        "content" => %{
          "chart_type" => "pie",
          "labels" => ["Critical", "High", "Medium", "Low"],
          "data" => [critical_count, high_count, medium_count, low_count],
          "title" => "Alerts by Severity"
        }
      },
      %{
        "title" => "Status Breakdown",
        "type" => "chart",
        "content" => %{
          "chart_type" => "bar",
          "labels" => ["Open", "Investigating", "Resolved", "False Positive"],
          "data" => [open_count, investigating_count, resolved_count, fp_count],
          "title" => "Alerts by Status"
        }
      },
      %{
        "title" => "Alert Timeline",
        "type" => "table",
        "content" => %{
          "headers" => ["Timestamp", "Title", "Severity", "Status", "Agent", "MITRE Technique"],
          "rows" => Enum.map(alerts, fn alert ->
            technique = List.first(alert.mitre_techniques || []) || "N/A"
            [
              format_datetime(alert.inserted_at),
              alert.title || "Untitled",
              to_string(alert.severity),
              to_string(alert.status),
              alert.agent_id || "N/A",
              technique
            ]
          end)
        }
      },
      %{
        "title" => "MITRE ATT&CK Mapping",
        "type" => "table",
        "content" => %{
          "headers" => ["Technique ID", "Technique Name", "Tactic", "Occurrence Count"],
          "rows" => Enum.map(mitre_techniques, fn {tech_id, count} ->
            technique_name = get_technique_name(tech_id)
            tactic = get_technique_tactic(tech_id)
            [tech_id, technique_name, tactic, to_string(count)]
          end)
        }
      },
      %{
        "title" => "Affected Hosts",
        "type" => "table",
        "content" => %{
          "headers" => ["Agent ID", "Hostname", "Alert Count", "Highest Severity"],
          "rows" => build_affected_hosts_table(alerts, affected_hosts)
        }
      },
      %{
        "title" => "Resolution Statistics",
        "type" => "table",
        "content" => %{
          "headers" => ["Metric", "Value"],
          "rows" => [
            ["Average Response Time", avg_response_time],
            ["Median Response Time", median_response_time],
            ["Resolution Rate", "#{calculate_resolution_rate(resolved_count, total_alerts)}%"],
            ["False Positive Rate", "#{calculate_fp_rate(fp_count, total_alerts)}%"],
            ["Open Alerts", to_string(open_count)],
            ["Critical Alerts Unresolved", to_string(count_unresolved_critical(alerts))]
          ]
        }
      }
    ]

    %{
      "title" => "Alert Detail Report",
      "sections" => sections
    }
  end

  # Helper functions

  defp filter_alerts(alerts, include_resolved, include_fps) do
    alerts
    |> then(fn a ->
      if include_resolved, do: a, else: Enum.reject(a, &(&1.status == "resolved"))
    end)
    |> then(fn a ->
      if include_fps, do: a, else: Enum.reject(a, &(&1.status == "false_positive"))
    end)
  end

  defp build_summary(date_from, date_to, total, affected_hosts, critical) do
    "This report covers all security alerts detected during #{date_from} to #{date_to}. " <>
    "A total of #{total} alert(s) were generated during this period, affecting #{length(affected_hosts)} unique host(s). " <>
    "#{critical} of these alerts were classified as critical severity and require immediate attention."
  end

  defp calculate_avg_response_time(alerts) do
    resolved = Enum.filter(alerts, &(&1.status in ["resolved", "false_positive"]))

    if length(resolved) == 0 do
      "N/A"
    else
      total_minutes = Enum.reduce(resolved, 0, fn alert, acc ->
        case {alert.inserted_at, alert.updated_at} do
          {nil, _} -> acc
          {_, nil} -> acc
          {created, updated} -> acc + NaiveDateTime.diff(updated, created, :minute)
        end
      end)

      avg = div(total_minutes, length(resolved))
      format_duration(avg)
    end
  end

  defp calculate_median_response_time(alerts) do
    resolved = Enum.filter(alerts, &(&1.status in ["resolved", "false_positive"]))

    if length(resolved) == 0 do
      "N/A"
    else
      times = Enum.map(resolved, fn alert ->
        case {alert.inserted_at, alert.updated_at} do
          {nil, _} -> 0
          {_, nil} -> 0
          {created, updated} -> NaiveDateTime.diff(updated, created, :minute)
        end
      end) |> Enum.sort()

      median_idx = div(length(times), 2)
      median = Enum.at(times, median_idx, 0)
      format_duration(median)
    end
  end

  defp calculate_resolution_rate(resolved, total) when total > 0 do
    Float.round(resolved / total * 100, 1)
  end
  defp calculate_resolution_rate(_, _), do: 0.0

  defp calculate_fp_rate(fps, total) when total > 0 do
    Float.round(fps / total * 100, 1)
  end
  defp calculate_fp_rate(_, _), do: 0.0

  defp count_unresolved_critical(alerts) do
    Enum.count(alerts, fn alert ->
      (alert.severity in [:critical, "critical"]) and alert.status != "resolved"
    end)
  end

  defp build_affected_hosts_table(alerts, agent_ids) do
    Enum.map(agent_ids, fn agent_id ->
      agent_alerts = Enum.filter(alerts, &(&1.agent_id == agent_id))
      alert_count = length(agent_alerts)

      highest_severity = agent_alerts
        |> Enum.map(& severity_to_number(&1.severity))
        |> Enum.max(fn -> 0 end)
        |> number_to_severity()

      hostname = get_hostname(agent_id)

      [agent_id, hostname, to_string(alert_count), highest_severity]
    end)
  end

  defp severity_to_number(:critical), do: 4
  defp severity_to_number("critical"), do: 4
  defp severity_to_number(:high), do: 3
  defp severity_to_number("high"), do: 3
  defp severity_to_number(:medium), do: 2
  defp severity_to_number("medium"), do: 2
  defp severity_to_number(:low), do: 1
  defp severity_to_number("low"), do: 1
  defp severity_to_number(_), do: 0

  defp number_to_severity(4), do: "Critical"
  defp number_to_severity(3), do: "High"
  defp number_to_severity(2), do: "Medium"
  defp number_to_severity(1), do: "Low"
  defp number_to_severity(_), do: "Info"

  defp get_hostname(agent_id) do
    case safe_call(fn -> Agents.get_agent(agent_id) end, nil) do
      nil -> "Unknown"
      agent -> agent.hostname || agent_id
    end
  end

  defp get_technique_name(tech_id) do
    case Mitre.get_technique(tech_id) do
      nil -> tech_id
      technique -> technique.name
    end
  rescue
    _ -> tech_id
  end

  defp get_technique_tactic(tech_id) do
    case Mitre.get_technique(tech_id) do
      nil -> "Unknown"
      technique -> List.first(technique.tactics) || "Unknown"
    end
  rescue
    _ -> "Unknown"
  end

  defp format_datetime(nil), do: "N/A"
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(_), do: "Unknown"

  defp format_duration(minutes) when minutes < 60, do: "#{minutes} min"
  defp format_duration(minutes) when minutes < 1440, do: "#{div(minutes, 60)} hr #{rem(minutes, 60)} min"
  defp format_duration(minutes), do: "#{div(minutes, 1440)} days"

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
