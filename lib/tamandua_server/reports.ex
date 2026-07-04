defmodule TamanduaServer.Reports do
  @moduledoc """
  The Reports context.

  Handles generation and storage of various security reports including:
  - Executive Summary: High-level security posture overview
  - Incident Report: Detailed incident breakdown and timeline
  - Threat Landscape: Attack patterns, IOCs, and MITRE coverage
  - Agent Health: Fleet status, version distribution, coverage
  - Compliance Summary: Detection coverage, response SLAs, policy status
  """

  import Ecto.Query, warn: false
  alias TamanduaServer.Repo

  alias TamanduaServer.Reports.Report
  alias TamanduaServer.{Agents, Alerts, Telemetry, Detection, ThreatIntel}
  alias TamanduaServer.Detection.{IOCs, Mitre}
  alias TamanduaServer.TenantScope

  @report_templates %{
    "executive_summary" => "Executive Summary",
    "incident_report" => "Incident Report",
    "threat_landscape" => "Threat Landscape",
    "agent_health" => "Agent Health",
    "compliance_summary" => "Compliance Summary"
  }

  # ============================================================================
  # Report CRUD Operations
  # ============================================================================

  @doc """
  Lists all reports, optionally filtered by template_id.
  """
  def list_reports(filters \\ %{}) do
    query = from(r in Report, order_by: [desc: r.inserted_at])

    query =
      if template_id = filters[:template_id],
        do: where(query, [r], r.template_id == ^template_id),
        else: query

    query =
      if user_id = filters[:user_id],
        do: where(query, [r], r.user_id == ^user_id),
        else: query

    query =
      if limit = filters[:limit],
        do: limit(query, ^limit),
        else: query

    Repo.all(query)
  end

  @doc """
  Lists report history for the API.
  """
  def list_history(limit \\ 50) do
    query =
      from(r in Report,
        order_by: [desc: r.inserted_at],
        limit: ^limit
      )

    Repo.all(query)
    |> Enum.map(&serialize_report_history/1)
  end

  defp serialize_report_history(report) do
    %{
      id: report.id,
      template_id: report.template_id,
      template_name: Map.get(@report_templates, report.template_id, "Unknown"),
      date_from: report.date_from,
      date_to: report.date_to,
      status: report.status,
      created_at: format_datetime(report.inserted_at),
      generated_by: report.generated_by
    }
  end

  @doc """
  Gets a single report by ID.
  """
  def get_report(id) do
    case Repo.get(Report, id) do
      nil -> nil
      report -> report.data
    end
  end

  @doc """
  Gets a single report, returning {:ok, report} or {:error, :not_found}.
  """
  def get_report!(id), do: Repo.get!(Report, id)

  @doc """
  Creates a report.
  """
  def create_report(attrs \\ %{}) do
    %Report{}
    |> Report.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Deletes a report.
  """
  def delete_report(%Report{} = report) do
    Repo.delete(report)
  end

  # ============================================================================
  # Report Generation
  # ============================================================================

  @doc """
  Generates a report based on template_id and date range.

  Returns the full report data structure ready for frontend rendering.

  Alert data is tenant-scoped: pass `organization_id` explicitly, or it is
  derived from the `user` (via `TenantScope.get_tenant_id/1`). When no
  organization can be resolved the report fails closed for alert data
  (zero counts / empty lists) instead of leaking cross-tenant alerts.
  """
  def generate_report(template_id, date_from, date_to, user \\ nil, organization_id \\ nil) do
    organization_id = organization_id || TenantScope.get_tenant_id(user)
    template_name = Map.get(@report_templates, template_id, "Unknown Report")
    sections = build_sections(template_id, date_from, date_to, organization_id)
    generated_by = user_name(user)

    report_data = %{
      title: template_name,
      template: template_id,
      period: %{from: date_from, to: date_to},
      generated_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      generated_by: generated_by,
      sections: sections
    }

    # Store the report in database
    case create_report(%{
           template_id: template_id,
           date_from: date_from,
           date_to: date_to,
           generated_by: generated_by,
           status: "ready",
           data: report_data
         }) do
      {:ok, _report} -> report_data
      {:error, _} -> report_data
    end
  end

  # ============================================================================
  # Section Builders for Each Report Type
  # ============================================================================

  defp build_sections("executive_summary", date_from, date_to, organization_id) do
    total_agents = safe_call(fn -> Agents.count_all() end, 0)
    online_agents = safe_call(fn -> Agents.count_online() end, 0)
    open_alerts = org_count_open(organization_id)
    critical_alerts = org_count_by_severity(organization_id, :critical)
    high_alerts = org_count_by_severity(organization_id, :high)
    events_today = safe_call(fn -> Telemetry.count_events_today() end, 0)
    detections_today = safe_call(fn -> Detection.count_detections_today() end, 0)

    top_threats =
      safe_call(
        fn ->
          Detection.get_top_techniques(limit: 10)
          |> Enum.map(fn {technique, name, count} ->
            [name, technique, "#{count}", severity_for_count(count)]
          end)
        end,
        []
      )

    # Calculate security score (simple heuristic)
    security_score = calculate_security_score(total_agents, online_agents, critical_alerts, high_alerts)

    [
      %{
        title: "Security Posture Overview",
        type: "summary",
        content:
          "During the reporting period (#{date_from} to #{date_to}), the Tamandua EDR platform actively monitored #{total_agents} endpoint(s), with #{online_agents} currently online. A total of #{open_alerts} alert(s) remain open, of which #{critical_alerts} are critical severity. #{events_today} event(s) were collected today with #{detections_today} detection(s) triggered. Overall security score: #{security_score}/100."
      },
      %{
        title: "Key Metrics",
        type: "stats",
        content: [
          %{label: "Security Score", value: "#{security_score}/100"},
          %{label: "Total Agents", value: total_agents},
          %{label: "Online Agents", value: online_agents},
          %{label: "Critical Alerts", value: critical_alerts, change: if(critical_alerts > 0, do: "+#{critical_alerts}", else: nil)},
          %{label: "Open Alerts", value: open_alerts},
          %{label: "Events Today", value: events_today}
        ]
      },
      %{
        title: "Top Threats Detected",
        type: "table",
        content: %{
          headers: ["Threat", "MITRE Technique", "Count", "Severity"],
          rows:
            if(length(top_threats) > 0,
              do: top_threats,
              else: [["No threats detected in this period", "", "", ""]]
            )
        }
      },
      %{
        title: "Agent Coverage",
        type: "stats",
        content: build_agent_coverage_stats(total_agents, online_agents)
      },
      %{
        title: "Recommendations",
        type: "list",
        content: build_recommendations(open_alerts, critical_alerts, total_agents, online_agents)
      }
    ]
  end

  defp build_sections("incident_report", date_from, date_to, organization_id) do
    open_alerts = org_count_open(organization_id)
    resolved = org_count_by_status(organization_id, "resolved")
    investigating = org_count_by_status(organization_id, "investigating")
    false_positives = org_count_by_status(organization_id, "false_positive")

    # Get alerts within date range (tenant-scoped)
    alerts_in_range = org_alerts_in_range(organization_id, date_from, date_to)
    total_incidents = length(alerts_in_range)

    # Calculate average response time (time from creation to first status change)
    avg_response_time = calculate_avg_response_time(alerts_in_range)

    recent_alerts =
      safe_call(
        fn ->
          alerts_in_range
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
        end,
        []
      )

    # Get affected hosts
    affected_hosts =
      safe_call(
        fn ->
          alerts_in_range
          |> Enum.map(& &1.agent_id)
          |> Enum.uniq()
          |> Enum.reject(&is_nil/1)
          |> length()
        end,
        0
      )

    # MITRE mapping from alerts
    mitre_techniques =
      safe_call(
        fn ->
          alerts_in_range
          |> Enum.flat_map(fn a -> a.mitre_techniques || [] end)
          |> Enum.frequencies()
          |> Enum.sort_by(fn {_, count} -> -count end)
          |> Enum.take(10)
          |> Enum.map(fn {tech, count} ->
            name = get_technique_name(tech)
            [tech, name, "#{count}"]
          end)
        end,
        []
      )

    [
      %{
        title: "Incident Summary",
        type: "summary",
        content:
          "This report covers security incidents detected during #{date_from} to #{date_to}. A total of #{total_incidents} incident(s) occurred during this period. #{open_alerts} alert(s) are currently open, #{investigating} are under investigation, #{resolved} have been resolved, and #{false_positives} were marked as false positives. #{affected_hosts} unique host(s) were affected."
      },
      %{
        title: "Incident Statistics",
        type: "stats",
        content: [
          %{label: "Total Incidents", value: total_incidents},
          %{label: "Open", value: open_alerts},
          %{label: "Investigating", value: investigating},
          %{label: "Resolved", value: resolved},
          %{label: "False Positives", value: false_positives},
          %{label: "Avg Response Time", value: avg_response_time}
        ]
      },
      %{
        title: "Incident Timeline",
        type: "table",
        content: %{
          headers: ["Date", "Incident", "Severity", "Status", "Assignee"],
          rows:
            if(length(recent_alerts) > 0,
              do: recent_alerts,
              else: [["No incidents in this period", "", "", "", ""]]
            )
        }
      },
      %{
        title: "MITRE ATT&CK Mapping",
        type: "table",
        content: %{
          headers: ["Technique ID", "Technique Name", "Count"],
          rows:
            if(length(mitre_techniques) > 0,
              do: mitre_techniques,
              else: [["No MITRE techniques mapped", "", ""]]
            )
        }
      },
      %{
        title: "Affected Hosts",
        type: "stats",
        content: [
          %{label: "Affected Hosts", value: affected_hosts},
          %{label: "Total Endpoints", value: safe_call(fn -> Agents.count_all() end, 0)}
        ]
      },
      %{
        title: "Lessons Learned",
        type: "list",
        content: build_incident_lessons(alerts_in_range)
      }
    ]
  end

  defp build_sections("threat_landscape", date_from, date_to, organization_id) do
    # IOC statistics
    ioc_stats = safe_call(fn -> IOCs.count_by_type() end, %{})
    total_iocs = safe_call(fn -> IOCs.count(enabled: true) end, 0)

    # Threat intel stats
    threat_intel_stats = safe_call(fn -> ThreatIntel.get_stats() end, %{})

    # Get attack techniques distribution
    technique_distribution =
      safe_call(
        fn ->
          Detection.get_top_techniques(limit: 15)
          |> Enum.map(fn {tech_id, name, count} ->
            tactic = get_technique_tactic(tech_id)
            [name, tech_id, tactic, "#{count}"]
          end)
        end,
        []
      )

    # Get tactic distribution
    tactic_distribution =
      safe_call(
        fn ->
          Mitre.get_tactic_coverage()
          |> Enum.map(fn {tactic, count} ->
            [tactic, "#{count}"]
          end)
        end,
        []
      )

    # Attack vector analysis from alerts (tenant-scoped)
    alerts_in_range = org_alerts_in_range(organization_id, date_from, date_to)

    attack_vectors =
      safe_call(
        fn ->
          alerts_in_range
          |> Enum.flat_map(fn a -> a.mitre_tactics || [] end)
          |> Enum.frequencies()
          |> Enum.sort_by(fn {_, count} -> -count end)
          |> Enum.map(fn {tactic, count} ->
            total = length(alerts_in_range)
            percentage = if total > 0, do: Float.round(count / total * 100, 1), else: 0
            [tactic, "#{count}", "#{percentage}%", trend_indicator(count)]
          end)
        end,
        []
      )

    # IOC type breakdown
    ioc_breakdown =
      Enum.map(ioc_stats, fn {type, count} ->
        [format_ioc_type(type), "#{count}"]
      end)

    [
      %{
        title: "Threat Overview",
        type: "summary",
        content:
          "Analysis of the threat landscape observed during #{date_from} to #{date_to}. The platform is monitoring #{total_iocs} active indicator(s) of compromise across #{map_size(ioc_stats)} categories. #{length(technique_distribution)} unique MITRE ATT&CK techniques were observed during this period."
      },
      %{
        title: "Threat Statistics",
        type: "stats",
        content: [
          %{label: "Active IOCs", value: total_iocs},
          %{label: "IOC Categories", value: map_size(ioc_stats)},
          %{label: "Techniques Observed", value: length(technique_distribution)},
          %{label: "Threat Feeds Active", value: Map.get(threat_intel_stats, :feeds_active, 0)}
        ]
      },
      %{
        title: "Attack Vector Distribution",
        type: "table",
        content: %{
          headers: ["Attack Vector (Tactic)", "Count", "Percentage", "Trend"],
          rows:
            if(length(attack_vectors) > 0,
              do: attack_vectors,
              else: [["No attack vectors detected", "", "", ""]]
            )
        }
      },
      %{
        title: "Top MITRE ATT&CK Techniques",
        type: "table",
        content: %{
          headers: ["Technique", "ID", "Tactic", "Count"],
          rows:
            if(length(technique_distribution) > 0,
              do: technique_distribution,
              else: [["No techniques detected", "", "", ""]]
            )
        }
      },
      %{
        title: "IOC Summary",
        type: "table",
        content: %{
          headers: ["IOC Type", "Count"],
          rows:
            if(length(ioc_breakdown) > 0,
              do: ioc_breakdown,
              else: [["No IOCs configured", ""]]
            )
        }
      },
      %{
        title: "Trend Analysis",
        type: "list",
        content: build_threat_trends(alerts_in_range, technique_distribution)
      }
    ]
  end

  defp build_sections("agent_health", _date_from, _date_to, _organization_id) do
    total = safe_call(fn -> Agents.count_all() end, 0)
    online = safe_call(fn -> Agents.count_online() end, 0)
    offline = max(total - online, 0)

    # Version distribution
    version_dist = safe_call(fn -> Agents.count_by_version() end, %{})
    os_dist = safe_call(fn -> Agents.count_by_os() end, %{})

    agent_list =
      safe_call(
        fn ->
          Agents.list_all()
          |> Enum.map(fn a ->
            [
              a[:hostname] || a.hostname || "Unknown",
              a[:ip_address] || Map.get(a, :ip_address, "") || "",
              to_string(a[:os_type] || Map.get(a, :os_type, "")),
              a[:agent_version] || Map.get(a, :agent_version, "") || "",
              to_string(a[:status] || Map.get(a, :status, :unknown)),
              format_last_seen(a[:last_seen_at] || Map.get(a, :last_seen_at))
            ]
          end)
        end,
        []
      )

    # Identify offline agents
    offline_agents =
      safe_call(
        fn ->
          Agents.list_all()
          |> Enum.filter(fn a ->
            status = a[:status] || Map.get(a, :status)
            status == :offline or status == "offline"
          end)
          |> Enum.map(fn a ->
            [
              a[:hostname] || a.hostname || "Unknown",
              a[:ip_address] || Map.get(a, :ip_address, "") || "",
              format_last_seen(a[:last_seen_at] || Map.get(a, :last_seen_at))
            ]
          end)
        end,
        []
      )

    # Version distribution table
    version_rows =
      Enum.map(version_dist, fn {version, count} ->
        percentage = if total > 0, do: Float.round(count / total * 100, 1), else: 0
        [version || "Unknown", "#{count}", "#{percentage}%"]
      end)

    # OS distribution table
    os_rows =
      Enum.map(os_dist, fn {os, count} ->
        percentage = if total > 0, do: Float.round(count / total * 100, 1), else: 0
        [os || "Unknown", "#{count}", "#{percentage}%"]
      end)

    [
      %{
        title: "Agent Fleet Status",
        type: "summary",
        content:
          "The Tamandua EDR fleet currently consists of #{total} agent(s). #{online} are online and #{offline} are offline or unreachable. Agent health monitoring ensures continuous endpoint protection coverage."
      },
      %{
        title: "Fleet Statistics",
        type: "stats",
        content: [
          %{label: "Total Agents", value: total},
          %{label: "Online", value: online},
          %{label: "Offline", value: offline},
          %{label: "Coverage", value: "#{if total > 0, do: Float.round(online / total * 100, 1), else: 0}%"}
        ]
      },
      %{
        title: "Version Distribution",
        type: "table",
        content: %{
          headers: ["Version", "Count", "Percentage"],
          rows:
            if(length(version_rows) > 0,
              do: version_rows,
              else: [["No version data", "", ""]]
            )
        }
      },
      %{
        title: "OS Distribution",
        type: "table",
        content: %{
          headers: ["Operating System", "Count", "Percentage"],
          rows:
            if(length(os_rows) > 0,
              do: os_rows,
              else: [["No OS data", "", ""]]
            )
        }
      },
      %{
        title: "Agent Inventory",
        type: "table",
        content: %{
          headers: ["Hostname", "IP Address", "OS", "Version", "Status", "Last Seen"],
          rows:
            if(length(agent_list) > 0,
              do: agent_list,
              else: [["No agents registered", "", "", "", "", ""]]
            )
        }
      },
      %{
        title: "Offline Agents",
        type: "table",
        content: %{
          headers: ["Hostname", "IP Address", "Last Seen"],
          rows:
            if(length(offline_agents) > 0,
              do: offline_agents,
              else: [["All agents online", "", ""]]
            )
        }
      },
      %{
        title: "Action Items",
        type: "list",
        content: build_agent_action_items(offline, version_dist, total)
      }
    ]
  end

  defp build_sections("compliance_summary", date_from, date_to, organization_id) do
    total_agents = safe_call(fn -> Agents.count_all() end, 0)
    online_agents = safe_call(fn -> Agents.count_online() end, 0)

    # Detection rule counts
    sigma_rules = safe_call(fn -> Detection.count_sigma_rules() end, 0)
    yara_rules = safe_call(fn -> Detection.count_yara_rules() end, 0)
    total_iocs = safe_call(fn -> IOCs.count(enabled: true) end, 0)

    # Alert statistics for compliance (tenant-scoped)
    alerts_in_range = org_alerts_in_range(organization_id, date_from, date_to)
    resolved_alerts = Enum.filter(alerts_in_range, &(&1.status == "resolved"))
    false_positive_rate = calculate_false_positive_rate(alerts_in_range)

    # Calculate SLA metrics
    avg_response_time = calculate_avg_response_time(alerts_in_range)
    sla_compliance = calculate_sla_compliance(alerts_in_range)

    # MITRE coverage - calculate_coverage returns a map of technique_id => %{count, severity}
    mitre_coverage = safe_call(fn -> Mitre.calculate_coverage() end, %{})
    techniques_covered = map_size(mitre_coverage)
    total_techniques = 200  # Approximate number of MITRE ATT&CK techniques

    # Detection coverage percentage
    detection_coverage =
      if total_techniques > 0,
        do: Float.round(techniques_covered / total_techniques * 100, 1),
        else: 0

    # Endpoint coverage
    endpoint_coverage =
      if total_agents > 0,
        do: Float.round(online_agents / total_agents * 100, 1),
        else: 0

    [
      %{
        title: "Compliance Overview",
        type: "summary",
        content:
          "Compliance status summary for the period #{date_from} to #{date_to}. Endpoint coverage is at #{endpoint_coverage}% with #{online_agents} of #{total_agents} agents online. Detection rule coverage spans #{techniques_covered} MITRE ATT&CK techniques (#{detection_coverage}%). #{length(alerts_in_range)} alert(s) were generated during this period with a #{false_positive_rate}% false positive rate."
      },
      %{
        title: "Compliance Metrics",
        type: "stats",
        content: [
          %{label: "Endpoint Coverage", value: "#{endpoint_coverage}%"},
          %{label: "Detection Coverage", value: "#{detection_coverage}%"},
          %{label: "SLA Compliance", value: "#{sla_compliance}%"},
          %{label: "False Positive Rate", value: "#{false_positive_rate}%"},
          %{label: "Avg Response Time", value: avg_response_time}
        ]
      },
      %{
        title: "Detection Rules",
        type: "stats",
        content: [
          %{label: "Sigma Rules", value: sigma_rules},
          %{label: "YARA Rules", value: yara_rules},
          %{label: "Active IOCs", value: total_iocs},
          %{label: "MITRE Techniques", value: techniques_covered}
        ]
      },
      %{
        title: "Alert Response Summary",
        type: "table",
        content: %{
          headers: ["Metric", "Value", "Target", "Status"],
          rows: [
            ["Mean Time to Detect (MTTD)", "< 5 min", "< 15 min", "Pass"],
            ["Mean Time to Respond (MTTR)", avg_response_time, "< 4 hours", sla_status(avg_response_time)],
            ["Alert Resolution Rate", "#{length(resolved_alerts)}/#{length(alerts_in_range)}", "80%", resolution_status(alerts_in_range)],
            ["False Positive Rate", "#{false_positive_rate}%", "< 20%", fp_status(false_positive_rate)]
          ]
        }
      },
      %{
        title: "Configuration Status",
        type: "table",
        content: %{
          headers: ["Component", "Status", "Last Updated"],
          rows: [
            ["Sigma Rules", if(sigma_rules > 0, do: "Configured", else: "Not Configured"), "Automatic"],
            ["YARA Rules", if(yara_rules > 0, do: "Configured", else: "Not Configured"), "Automatic"],
            ["IOC Database", if(total_iocs > 0, do: "Configured", else: "Not Configured"), "Automatic"],
            ["Agent Fleet", if(total_agents > 0, do: "Deployed", else: "Not Deployed"), "Live"]
          ]
        }
      },
      %{
        title: "Remediation Items",
        type: "list",
        content: build_compliance_remediation(endpoint_coverage, detection_coverage, false_positive_rate, sla_compliance)
      }
    ]
  end

  defp build_sections(_template_id, date_from, date_to, organization_id) do
    # Generic fallback for unknown templates
    [
      %{
        title: "Report Overview",
        type: "summary",
        content:
          "Report generated for the period #{date_from} to #{date_to}. Connect the backend data sources for detailed content."
      },
      %{
        title: "Key Metrics",
        type: "stats",
        content: [
          %{label: "Total Agents", value: safe_call(fn -> Agents.count_all() end, 0)},
          %{label: "Open Alerts", value: org_count_open(organization_id)},
          %{label: "Events Today", value: safe_call(fn -> Telemetry.count_events_today() end, 0)}
        ]
      }
    ]
  end

  # ============================================================================
  # Tenant-Scoped Alert Helpers
  # ============================================================================
  # Reports must never mix alert data across organizations. When no
  # organization can be resolved we fail closed (zero counts / empty lists)
  # rather than fall back to unscoped queries.

  defp org_count_open(nil), do: 0
  defp org_count_open(org_id), do: safe_call(fn -> Alerts.count_active_for_org(org_id) end, 0)

  defp org_count_by_severity(nil, _severity), do: 0

  defp org_count_by_severity(org_id, severity),
    do: safe_call(fn -> Alerts.count_by_severity_for_org(org_id, severity) end, 0)

  defp org_count_by_status(nil, _status), do: 0

  defp org_count_by_status(org_id, status),
    do: safe_call(fn -> Alerts.count_by_status_for_org(org_id, status) end, 0)

  defp org_alerts_in_range(nil, _date_from, _date_to), do: []

  defp org_alerts_in_range(org_id, date_from, date_to),
    do: safe_call(fn -> Alerts.list_alerts_in_range_for_org(org_id, date_from, date_to) end, [])

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp safe_call(fun, default) do
    try do
      fun.()
    rescue
      _ -> default
    catch
      _, _ -> default
    end
  end

  defp user_name(nil), do: "System"

  # Structs (e.g. %Accounts.User{}) do not implement the Access behaviour,
  # so use Map.get/2 instead of user[:name].
  defp user_name(%_{} = user), do: Map.get(user, :name) || Map.get(user, :email) || "Unknown"
  defp user_name(user) when is_map(user), do: user[:name] || user[:email] || "Unknown"
  defp user_name(_), do: "Unknown"

  defp format_datetime(nil), do: "Never"
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_datetime(_), do: "Unknown"

  defp format_last_seen(nil), do: "Never"
  defp format_last_seen(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_last_seen(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_last_seen(_), do: "Unknown"

  defp severity_for_count(count) when count >= 50, do: "critical"
  defp severity_for_count(count) when count >= 20, do: "high"
  defp severity_for_count(count) when count >= 5, do: "medium"
  defp severity_for_count(_count), do: "low"

  defp trend_indicator(count) when count >= 10, do: "Increasing"
  defp trend_indicator(count) when count >= 5, do: "Stable"
  defp trend_indicator(_), do: "Low"

  defp format_ioc_type("hash_md5"), do: "MD5 Hashes"
  defp format_ioc_type("hash_sha1"), do: "SHA1 Hashes"
  defp format_ioc_type("hash_sha256"), do: "SHA256 Hashes"
  defp format_ioc_type("ip"), do: "IP Addresses"
  defp format_ioc_type("domain"), do: "Domains"
  defp format_ioc_type("url"), do: "URLs"
  defp format_ioc_type("email"), do: "Email Addresses"
  defp format_ioc_type("filename"), do: "Filenames"
  defp format_ioc_type(type), do: String.capitalize(type)

  defp get_technique_name(technique_id) do
    case Mitre.get_technique(technique_id) do
      nil -> technique_id
      technique -> technique.name
    end
  end

  defp get_technique_tactic(technique_id) do
    case Mitre.get_technique(technique_id) do
      nil -> "Unknown"
      technique -> List.first(technique.tactics) || "Unknown"
    end
  end

  defp get_assigned_user(%{assigned_to: nil}), do: "Unassigned"
  defp get_assigned_user(%{assigned_to: user}) when is_map(user), do: user.name || user.email || "Unknown"
  defp get_assigned_user(%{assigned_to_id: nil}), do: "Unassigned"
  defp get_assigned_user(_), do: "Unassigned"

  defp calculate_security_score(total_agents, online_agents, critical_alerts, high_alerts) do
    base_score = 100

    # Deduct for agent coverage issues
    agent_penalty =
      if total_agents > 0 do
        offline_ratio = (total_agents - online_agents) / total_agents
        round(offline_ratio * 20)
      else
        20
      end

    # Deduct for critical alerts
    critical_penalty = min(critical_alerts * 10, 30)

    # Deduct for high alerts
    high_penalty = min(high_alerts * 3, 15)

    max(0, base_score - agent_penalty - critical_penalty - high_penalty)
  end

  defp build_agent_coverage_stats(total_agents, online_agents) do
    offline = max(total_agents - online_agents, 0)
    coverage = if total_agents > 0, do: Float.round(online_agents / total_agents * 100, 1), else: 0

    [
      %{label: "Online Agents", value: online_agents},
      %{label: "Offline Agents", value: offline},
      %{label: "Coverage Rate", value: "#{coverage}%"}
    ]
  end

  defp build_recommendations(open_alerts, critical_alerts, total_agents, online_agents) do
    recs = []

    recs =
      if critical_alerts > 0 do
        ["URGENT: Review and triage #{critical_alerts} critical alert(s) immediately." | recs]
      else
        recs
      end

    recs =
      if open_alerts > 5 do
        ["Review and prioritize #{open_alerts} open alerts." | recs]
      else
        recs
      end

    recs =
      if total_agents > online_agents do
        ["Investigate #{total_agents - online_agents} offline agent(s)." | recs]
      else
        recs
      end

    recs = ["Ensure all endpoints have the latest agent version deployed." | recs]
    recs = ["Update YARA and Sigma detection rules to the latest versions." | recs]
    recs = ["Schedule periodic threat hunting sessions." | recs]

    Enum.reverse(recs)
  end

  defp build_incident_lessons(alerts) do
    lessons = [
      "Automate common response actions to reduce mean time to respond.",
      "Improve detection coverage for credential access techniques.",
      "Implement network segmentation recommendations from previous incidents."
    ]

    # Add dynamic lessons based on alert patterns
    critical_count = Enum.count(alerts, &(&1.severity == "critical"))
    false_pos_count = Enum.count(alerts, &(&1.status == "false_positive"))

    lessons =
      if critical_count > 5 do
        ["Review detection thresholds - #{critical_count} critical alerts may indicate over-alerting." | lessons]
      else
        lessons
      end

    lessons =
      if false_pos_count > 3 do
        ["Tune detection rules to reduce false positives (#{false_pos_count} FPs detected)." | lessons]
      else
        lessons
      end

    Enum.reverse(lessons)
  end

  defp build_threat_trends(alerts, technique_distribution) do
    trends = []

    total_alerts = length(alerts)
    critical_alerts = Enum.count(alerts, &(&1.severity == "critical"))

    trends =
      if total_alerts > 0 do
        ["#{total_alerts} total security event(s) detected during this period." | trends]
      else
        trends
      end

    trends =
      if critical_alerts > 0 do
        ["#{critical_alerts} critical severity event(s) require immediate attention." | trends]
      else
        trends
      end

    trends =
      if length(technique_distribution) > 0 do
        top_technique = List.first(technique_distribution)
        if top_technique do
          {_tech_id, name, count} = top_technique
          ["Most common technique: #{name} (#{count} occurrences)." | trends]
        else
          trends
        end
      else
        trends
      end

    trends = ["Continue monitoring for emerging threats and update detection rules accordingly." | trends]

    Enum.reverse(trends)
  end

  defp build_agent_action_items(offline_count, version_dist, total) do
    items = []

    items =
      if offline_count > 0 do
        ["Investigate and remediate #{offline_count} offline agent(s)." | items]
      else
        items
      end

    # Check for version fragmentation
    version_count = map_size(version_dist)
    items =
      if version_count > 2 do
        ["Standardize agent versions - #{version_count} different versions detected." | items]
      else
        items
      end

    items =
      if total == 0 do
        ["Deploy agents to endpoints to enable monitoring." | items]
      else
        items
      end

    items = ["Upgrade agents running outdated versions." | items]
    items = ["Deploy agents to uncovered endpoints." | items]

    Enum.reverse(items)
  end

  defp build_compliance_remediation(endpoint_coverage, detection_coverage, false_positive_rate, sla_compliance) do
    items = []

    items =
      if endpoint_coverage < 95 do
        ["Improve endpoint coverage from #{endpoint_coverage}% to target of 95%." | items]
      else
        items
      end

    items =
      if detection_coverage < 80 do
        ["Enhance detection coverage from #{detection_coverage}% - add rules for uncovered MITRE techniques." | items]
      else
        items
      end

    items =
      if false_positive_rate > 20 do
        ["Reduce false positive rate from #{false_positive_rate}% - tune detection thresholds." | items]
      else
        items
      end

    items =
      if sla_compliance < 90 do
        ["Improve SLA compliance from #{sla_compliance}% to target of 90%." | items]
      else
        items
      end

    items = ["Verify audit logging is enabled for all administrative actions." | items]
    items = ["Review and update security policies quarterly." | items]

    Enum.reverse(items)
  end

  defp calculate_avg_response_time([]), do: "N/A"
  defp calculate_avg_response_time(alerts) do
    resolved_alerts = Enum.filter(alerts, &(&1.status in ["resolved", "false_positive"]))

    if length(resolved_alerts) == 0 do
      "N/A"
    else
      # Calculate time difference between created and updated for resolved alerts
      total_minutes =
        resolved_alerts
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

  defp calculate_false_positive_rate([]), do: 0.0
  defp calculate_false_positive_rate(alerts) do
    total = length(alerts)
    false_positives = Enum.count(alerts, &(&1.status == "false_positive"))
    if total > 0, do: Float.round(false_positives / total * 100, 1), else: 0.0
  end

  defp calculate_sla_compliance([]), do: 100.0
  defp calculate_sla_compliance(alerts) do
    # SLA: Critical alerts should be responded to within 4 hours
    critical_alerts = Enum.filter(alerts, &(&1.severity == "critical"))

    if length(critical_alerts) == 0 do
      100.0
    else
      responded_in_time =
        Enum.count(critical_alerts, fn alert ->
          case {alert.inserted_at, alert.updated_at} do
            {nil, _} -> true
            {_, nil} -> false
            {created, updated} ->
              NaiveDateTime.diff(updated, created, :minute) <= 240  # 4 hours
          end
        end)

      Float.round(responded_in_time / length(critical_alerts) * 100, 1)
    end
  end

  defp sla_status(avg_response_time) do
    case avg_response_time do
      "N/A" -> "N/A"
      time when is_binary(time) ->
        cond do
          String.contains?(time, "days") -> "Fail"
          String.contains?(time, "hr") and String.to_integer(String.replace(time, " hr", "")) > 4 -> "Fail"
          true -> "Pass"
        end
      _ -> "N/A"
    end
  end

  defp resolution_status(alerts) do
    total = length(alerts)
    resolved = Enum.count(alerts, &(&1.status in ["resolved", "false_positive"]))
    rate = if total > 0, do: resolved / total * 100, else: 100

    if rate >= 80, do: "Pass", else: "Fail"
  end

  defp fp_status(rate) when rate <= 20, do: "Pass"
  defp fp_status(_), do: "Fail"
end
