defmodule TamanduaServer.Reports.Templates.IncidentReport do
  @moduledoc """
  Incident Report Template.

  Detailed breakdown of security incidents including:
  - Incident summary and timeline
  - Affected assets
  - MITRE ATT&CK mapping
  - Response actions taken
  - Remediation status
  - Lessons learned
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.{Agents, Alerts}

  @impl true
  def name, do: "Incident Report"

  @impl true
  def description do
    "Detailed breakdown of security incidents, response actions taken, and resolution timeline."
  end

  @impl true
  def category, do: "security"

  @impl true
  def sections do
    [
      "Incident Summary",
      "Incident Statistics",
      "Incident Timeline",
      "Affected Assets",
      "MITRE ATT&CK Mapping",
      "Response Actions",
      "Resolution Status",
      "Lessons Learned"
    ]
  end

  @impl true
  def parameters do
    [
      %{
        name: "severity_filter",
        type: "select",
        options: ["all", "critical", "high", "medium", "low"],
        default: "all",
        description: "Filter incidents by severity"
      },
      %{
        name: "max_incidents",
        type: "integer",
        default: 50,
        description: "Maximum number of incidents to include"
      },
      %{
        name: "include_resolved",
        type: "boolean",
        default: true,
        description: "Include resolved incidents"
      }
    ]
  end

  @impl true
  def supported_formats, do: [:pdf, :html, :csv, :json]

  @impl true
  def generate(date_from, date_to, params) do
    severity_filter = Map.get(params, "severity_filter", "all")
    max_incidents = Map.get(params, "max_incidents", 50)
    include_resolved = Map.get(params, "include_resolved", true)

    # Tenant scoping: alert data must be limited to the caller's
    # organization. When no organization is provided we fail closed
    # (empty list) instead of returning cross-tenant data.
    organization_id = params["organization_id"] || params[:organization_id]

    # Get alerts in range (tenant-scoped)
    alerts_in_range =
      if organization_id do
        safe_call(fn ->
          Alerts.list_alerts_in_range_for_org(organization_id, date_from, date_to)
        end, [])
      else
        []
      end

    # Apply filters
    filtered_alerts = alerts_in_range
    |> filter_by_severity(severity_filter)
    |> filter_by_status(include_resolved)
    |> Enum.take(max_incidents)

    total_incidents = length(filtered_alerts)

    # Calculate statistics
    open_count = count_by_status(filtered_alerts, "open")
    investigating_count = count_by_status(filtered_alerts, "investigating")
    resolved_count = count_by_status(filtered_alerts, "resolved")
    false_positive_count = count_by_status(filtered_alerts, "false_positive")

    critical_count = count_by_severity(filtered_alerts, "critical")
    high_count = count_by_severity(filtered_alerts, "high")
    medium_count = count_by_severity(filtered_alerts, "medium")
    low_count = count_by_severity(filtered_alerts, "low")

    # Calculate response metrics
    avg_response_time = calculate_avg_response_time(filtered_alerts)
    resolution_rate = if total_incidents > 0 do
      Float.round((resolved_count + false_positive_count) / total_incidents * 100, 1)
    else
      0.0
    end

    # Get affected hosts
    affected_agents = filtered_alerts
    |> Enum.map(& &1.agent_id)
    |> Enum.uniq()
    |> Enum.reject(&is_nil/1)

    affected_hosts = safe_call(fn ->
      Enum.map(affected_agents, fn agent_id ->
        case Agents.get(agent_id) do
          nil -> [agent_id, "Unknown", "Unknown", 0]
          agent ->
            incident_count = Enum.count(filtered_alerts, & &1.agent_id == agent_id)
            [agent.hostname || agent_id, agent.ip_address || "", agent.os_type || "", incident_count]
        end
      end)
    end, [])

    # Build incident timeline
    incident_timeline = filtered_alerts
    |> Enum.sort_by(& &1.inserted_at, {:desc, NaiveDateTime})
    |> Enum.take(20)
    |> Enum.map(fn a ->
      [
        format_datetime(a.inserted_at),
        a.title || "Untitled",
        to_string(a.severity),
        to_string(a.status),
        get_assigned_user(a)
      ]
    end)

    # MITRE mapping from alerts
    mitre_techniques = safe_call(fn ->
      filtered_alerts
      |> Enum.flat_map(fn a -> a.mitre_techniques || [] end)
      |> Enum.frequencies()
      |> Enum.sort_by(fn {_, count} -> -count end)
      |> Enum.take(15)
      |> Enum.map(fn {tech, count} ->
        [tech, get_technique_name(tech), "#{count}"]
      end)
    end, [])

    # Build sections
    sections = [
      %{
        "title" => "Incident Summary",
        "type" => "summary",
        "content" => build_summary(date_from, date_to, total_incidents, open_count,
                                   investigating_count, resolved_count, false_positive_count,
                                   length(affected_agents))
      },
      %{
        "title" => "Incident Statistics",
        "type" => "stats",
        "content" => [
          %{"label" => "Total Incidents", "value" => total_incidents},
          %{"label" => "Critical", "value" => critical_count,
            "change" => if(critical_count > 0, do: "+#{critical_count}", else: nil)},
          %{"label" => "High", "value" => high_count},
          %{"label" => "Medium", "value" => medium_count},
          %{"label" => "Low", "value" => low_count},
          %{"label" => "Open", "value" => open_count},
          %{"label" => "Investigating", "value" => investigating_count},
          %{"label" => "Resolved", "value" => resolved_count},
          %{"label" => "Avg Response Time", "value" => avg_response_time},
          %{"label" => "Resolution Rate", "value" => "#{resolution_rate}%"}
        ]
      },
      %{
        "title" => "Severity Distribution",
        "type" => "chart",
        "content" => %{
          "chart_type" => "pie",
          "labels" => ["Critical", "High", "Medium", "Low"],
          "data" => [critical_count, high_count, medium_count, low_count],
          "title" => "Incidents by Severity"
        }
      },
      %{
        "title" => "Incident Timeline",
        "type" => "table",
        "content" => %{
          "headers" => ["Date", "Incident", "Severity", "Status", "Assignee"],
          "rows" => if(length(incident_timeline) > 0,
            do: incident_timeline,
            else: [["No incidents in this period", "", "", "", ""]])
        }
      },
      %{
        "title" => "Affected Assets",
        "type" => "table",
        "content" => %{
          "headers" => ["Hostname", "IP Address", "OS", "Incident Count"],
          "rows" => if(length(affected_hosts) > 0,
            do: affected_hosts,
            else: [["No affected assets", "", "", ""]])
        }
      },
      %{
        "title" => "MITRE ATT&CK Mapping",
        "type" => "table",
        "content" => %{
          "headers" => ["Technique ID", "Technique Name", "Count"],
          "rows" => if(length(mitre_techniques) > 0,
            do: mitre_techniques,
            else: [["No MITRE techniques mapped", "", ""]])
        }
      },
      %{
        "title" => "Response Actions",
        "type" => "list",
        "content" => build_response_actions(filtered_alerts)
      },
      %{
        "title" => "Lessons Learned",
        "type" => "list",
        "content" => build_lessons_learned(filtered_alerts, critical_count, false_positive_count)
      }
    ]

    %{
      "title" => "Incident Report",
      "sections" => sections
    }
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp build_summary(date_from, date_to, total, open, investigating, resolved, fps, affected_hosts) do
    "This report covers security incidents detected during #{date_from} to #{date_to}. " <>
    "A total of #{total} incident(s) occurred during this period. " <>
    "Currently #{open} alert(s) are open, #{investigating} are under investigation, " <>
    "#{resolved} have been resolved, and #{fps} were marked as false positives. " <>
    "#{affected_hosts} unique host(s) were affected by these incidents."
  end

  defp filter_by_severity(alerts, "all"), do: alerts
  defp filter_by_severity(alerts, severity) do
    Enum.filter(alerts, fn a ->
      to_string(a.severity) == severity
    end)
  end

  defp filter_by_status(alerts, true), do: alerts
  defp filter_by_status(alerts, false) do
    Enum.reject(alerts, fn a ->
      to_string(a.status) in ["resolved", "false_positive"]
    end)
  end

  defp count_by_status(alerts, status) do
    Enum.count(alerts, fn a -> to_string(a.status) == status end)
  end

  defp count_by_severity(alerts, severity) do
    Enum.count(alerts, fn a -> to_string(a.severity) == severity end)
  end

  defp calculate_avg_response_time([]), do: "N/A"
  defp calculate_avg_response_time(alerts) do
    resolved_alerts = Enum.filter(alerts, fn a ->
      to_string(a.status) in ["resolved", "false_positive"]
    end)

    if length(resolved_alerts) == 0 do
      "N/A"
    else
      total_minutes = resolved_alerts
      |> Enum.map(fn alert ->
        case {alert.inserted_at, alert.updated_at} do
          {nil, _} -> 0
          {_, nil} -> 0
          {created, updated} ->
            NaiveDateTime.diff(updated, created, :minute)
        end
      end)
      |> Enum.sum()

      avg_minutes = div(total_minutes, length(resolved_alerts))

      cond do
        avg_minutes < 60 -> "#{avg_minutes} min"
        avg_minutes < 1440 -> "#{div(avg_minutes, 60)} hr"
        true -> "#{div(avg_minutes, 1440)} days"
      end
    end
  end

  defp get_assigned_user(%{assigned_to: nil}), do: "Unassigned"
  defp get_assigned_user(%{assigned_to: user}) when is_map(user) do
    user[:name] || user[:email] || user.name || user.email || "Unknown"
  end
  defp get_assigned_user(%{assigned_to_id: nil}), do: "Unassigned"
  defp get_assigned_user(_), do: "Unassigned"

  defp get_technique_name(technique_id) do
    # In production, query from MITRE module
    technique_id
  end

  defp build_response_actions(alerts) do
    actions = []

    # Count response actions taken
    # Alert schema has no :response_actions field today; Map.get/2 returns
    # nil (instead of raising KeyError) so the section degrades gracefully.
    response_counts = alerts
    |> Enum.flat_map(fn a -> Map.get(a, :response_actions) || [] end)
    |> Enum.frequencies()

    actions = if map_size(response_counts) > 0 do
      Enum.map(response_counts, fn {action, count} ->
        "#{action}: #{count} time(s)"
      end) ++ actions
    else
      actions
    end

    # Add general response recommendations
    actions = [
      "Automated quarantine triggered for suspicious files detected by YARA rules.",
      "Network isolation recommended for hosts with confirmed malware.",
      "Credential rotation recommended for accounts involved in lateral movement.",
      "Memory forensics collection initiated for process injection incidents."
    ] ++ actions

    Enum.take(actions, 10)
  end

  defp build_lessons_learned(alerts, critical_count, fp_count) do
    lessons = [
      "Automate common response actions to reduce mean time to respond.",
      "Improve detection coverage for credential access techniques.",
      "Implement network segmentation recommendations from previous incidents."
    ]

    lessons = if critical_count > 5 do
      ["Review detection thresholds - #{critical_count} critical alerts may indicate over-alerting." | lessons]
    else
      lessons
    end

    lessons = if fp_count > 3 do
      ["Tune detection rules to reduce false positives (#{fp_count} FPs detected)." | lessons]
    else
      lessons
    end

    Enum.reverse(lessons)
  end

  defp format_datetime(nil), do: "N/A"
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_datetime(_), do: "N/A"

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
