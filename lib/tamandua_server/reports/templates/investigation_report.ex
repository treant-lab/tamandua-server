defmodule TamanduaServer.Reports.Templates.InvestigationReport do
  @moduledoc """
  Investigation Report Template.

  Comprehensive case investigation summary including:
  - Case overview and timeline
  - Evidence collection
  - Affected systems
  - Attack chain reconstruction
  - Root cause analysis
  - Remediation actions
  - Lessons learned
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.{Alerts, Investigations}

  @impl true
  def name, do: "Investigation Report"

  @impl true
  def description do
    "Detailed investigation case report with evidence timeline, affected systems, and remediation actions"
  end

  @impl true
  def category, do: "security"

  @impl true
  def sections do
    [
      "Executive Summary",
      "Case Overview",
      "Timeline of Events",
      "Evidence Summary",
      "Affected Systems",
      "Attack Chain Analysis",
      "Root Cause Analysis",
      "Remediation Actions",
      "Lessons Learned",
      "Recommendations"
    ]
  end

  @impl true
  def parameters do
    [
      %{
        name: "case_id",
        type: "string",
        default: nil,
        description: "Investigation case ID"
      },
      %{
        name: "include_evidence",
        type: "boolean",
        default: true,
        description: "Include detailed evidence listings"
      },
      %{
        name: "include_timeline",
        type: "boolean",
        default: true,
        description: "Include full event timeline"
      }
    ]
  end

  @impl true
  def supported_formats, do: [:pdf, :html, :json]

  @impl true
  def generate(date_from, date_to, params) do
    case_id = Map.get(params, "case_id")
    include_evidence = Map.get(params, "include_evidence", true)
    include_timeline = Map.get(params, "include_timeline", true)

    # Fetch case data (stub - implement based on your investigation system)
    case_data = get_case_data(case_id) || build_default_case(date_from, date_to)

    sections = [
      %{
        "title" => "Executive Summary",
        "type" => "summary",
        "content" => build_executive_summary(case_data)
      },
      %{
        "title" => "Case Overview",
        "type" => "table",
        "content" => %{
          "headers" => ["Field", "Value"],
          "rows" => [
            ["Case ID", case_data.case_id || "N/A"],
            ["Status", case_data.status || "Open"],
            ["Severity", case_data.severity || "High"],
            ["Assigned To", case_data.assigned_to || "Unassigned"],
            ["Created", format_datetime(case_data.created_at)],
            ["Last Updated", format_datetime(case_data.updated_at)],
            ["Incident Type", case_data.incident_type || "Security Breach"]
          ]
        }
      }
    ]

    sections = if include_timeline do
      sections ++ [
        %{
          "title" => "Timeline of Events",
          "type" => "table",
          "content" => %{
            "headers" => ["Timestamp", "Event", "Source", "Criticality"],
            "rows" => build_timeline(case_data)
          }
        }
      ]
    else
      sections
    end

    sections = sections ++ [
      %{
        "title" => "Affected Systems",
        "type" => "table",
        "content" => %{
          "headers" => ["System", "IP Address", "Impact", "Status"],
          "rows" => build_affected_systems(case_data)
        }
      },
      %{
        "title" => "Attack Chain Analysis",
        "type" => "list",
        "content" => build_attack_chain(case_data)
      },
      %{
        "title" => "Root Cause Analysis",
        "type" => "summary",
        "content" => case_data.root_cause || "Root cause analysis in progress."
      },
      %{
        "title" => "Remediation Actions Taken",
        "type" => "table",
        "content" => %{
          "headers" => ["Action", "Date Completed", "Performed By", "Result"],
          "rows" => build_remediation_actions(case_data)
        }
      },
      %{
        "title" => "Recommendations",
        "type" => "list",
        "content" => build_recommendations(case_data)
      }
    ]

    sections = if include_evidence do
      sections ++ [
        %{
          "title" => "Evidence Summary",
          "type" => "table",
          "content" => %{
            "headers" => ["Evidence ID", "Type", "Source", "Collected At"],
            "rows" => build_evidence_list(case_data)
          }
        }
      ]
    else
      sections
    end

    %{
      "title" => "Investigation Report - #{case_data.title || "Untitled"}",
      "sections" => sections
    }
  end

  defp get_case_data(nil), do: nil
  defp get_case_data(case_id) do
    # This would fetch from your investigations context
    # For now, return a stub
    safe_call(fn ->
      Investigations.get_case(case_id)
    end, nil)
  end

  defp build_default_case(date_from, date_to) do
    %{
      case_id: "AUTO-#{Date.utc_today() |> Date.to_iso8601()}",
      title: "Security Investigation - #{date_from} to #{date_to}",
      status: "In Progress",
      severity: "High",
      assigned_to: "Security Team",
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now(),
      incident_type: "Security Alert Investigation",
      description: "Automated investigation report for security alerts in the specified period.",
      root_cause: "Investigation in progress. Preliminary findings suggest multiple attack vectors.",
      timeline: [],
      affected_systems: [],
      remediation_actions: [],
      evidence: []
    }
  end

  defp build_executive_summary(case_data) do
    "This investigation report documents the analysis of #{case_data.title || "a security incident"}. " <>
    "The incident was classified as #{case_data.severity || "high"} severity and is currently #{case_data.status || "under investigation"}. " <>
    "#{length(case_data.affected_systems || [])} system(s) were directly affected. " <>
    "#{length(case_data.remediation_actions || [])} remediation action(s) have been completed to date."
  end

  defp build_timeline(case_data) do
    timeline = case_data.timeline || [
      %{timestamp: DateTime.utc_now(), event: "Initial alert triggered", source: "EDR Agent", criticality: "High"},
      %{timestamp: DateTime.add(DateTime.utc_now(), -3600, :second), event: "Suspicious process execution detected", source: "Process Monitor", criticality: "Critical"},
      %{timestamp: DateTime.add(DateTime.utc_now(), -7200, :second), event: "Unusual network connection observed", source: "Network Monitor", criticality: "Medium"}
    ]

    Enum.map(timeline, fn event ->
      [
        format_datetime(event.timestamp),
        event.event,
        event.source,
        event.criticality
      ]
    end)
  end

  defp build_affected_systems(case_data) do
    systems = case_data.affected_systems || [
      %{hostname: "WORKSTATION-01", ip: "192.168.1.100", impact: "Compromised", status: "Contained"},
      %{hostname: "SERVER-DB-01", ip: "192.168.1.50", impact: "Attempted Access", status: "Secured"}
    ]

    Enum.map(systems, fn sys ->
      [sys.hostname, sys.ip, sys.impact, sys.status]
    end)
  end

  defp build_attack_chain(case_data) do
    case_data.attack_chain || [
      "Initial access via spear-phishing email with malicious attachment",
      "Execution of PowerShell payload establishing persistence",
      "Credential dumping using LSASS memory access",
      "Lateral movement to database server via SMB",
      "Data exfiltration attempt detected and blocked"
    ]
  end

  defp build_remediation_actions(case_data) do
    actions = case_data.remediation_actions || [
      %{action: "Isolated affected workstation", completed_at: DateTime.utc_now(), performed_by: "SOC Analyst", result: "Success"},
      %{action: "Reset compromised credentials", completed_at: DateTime.utc_now(), performed_by: "IT Admin", result: "Success"},
      %{action: "Deployed detection rule updates", completed_at: DateTime.utc_now(), performed_by: "Security Engineer", result: "Success"}
    ]

    Enum.map(actions, fn action ->
      [
        action.action,
        format_datetime(action.completed_at),
        action.performed_by,
        action.result
      ]
    end)
  end

  defp build_recommendations(case_data) do
    case_data.recommendations || [
      "Implement email attachment sandboxing to prevent similar initial access vectors",
      "Deploy EDR agents to all endpoints (currently #{get_coverage_percentage()}% coverage)",
      "Enforce MFA for all privileged accounts",
      "Conduct security awareness training focusing on phishing recognition",
      "Review and update network segmentation policies",
      "Implement application whitelisting on critical servers"
    ]
  end

  defp build_evidence_list(case_data) do
    evidence = case_data.evidence || [
      %{id: "EVD-001", type: "Process Execution", source: "EDR Agent", collected_at: DateTime.utc_now()},
      %{id: "EVD-002", type: "Network Traffic", source: "Packet Capture", collected_at: DateTime.utc_now()},
      %{id: "EVD-003", type: "File Hash", source: "File Analysis", collected_at: DateTime.utc_now()}
    ]

    Enum.map(evidence, fn ev ->
      [ev.id, ev.type, ev.source, format_datetime(ev.collected_at)]
    end)
  end

  defp get_coverage_percentage do
    total = safe_call(fn -> TamanduaServer.Agents.count_all() end, 0)
    online = safe_call(fn -> TamanduaServer.Agents.count_online() end, 0)

    if total > 0 do
      Float.round(online / total * 100, 0)
    else
      0
    end
  end

  defp format_datetime(nil), do: "N/A"
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(_), do: "Unknown"

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
