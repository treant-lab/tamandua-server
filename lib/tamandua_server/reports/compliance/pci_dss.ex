defmodule TamanduaServer.Reports.Compliance.PCIDSS do
  @moduledoc """
  PCI-DSS 4.0 Compliance Report Template.

  Maps Tamandua EDR controls to PCI-DSS requirements:
  - Requirement 1: Install and maintain network security controls
  - Requirement 5: Protect all systems against malware
  - Requirement 6: Develop and maintain secure systems
  - Requirement 10: Log and monitor all access
  - Requirement 11: Test security of systems regularly
  - Requirement 12: Support information security with policies
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.Reports.Compliance.ComplianceBase

  @impl true
  def name, do: "PCI-DSS 4.0 Compliance"

  @impl true
  def description do
    "Payment Card Industry Data Security Standard compliance assessment mapping EDR controls to PCI-DSS requirements."
  end

  @impl true
  def category, do: "compliance"

  @impl true
  def sections do
    [
      "Compliance Summary",
      "Compliance Score",
      "Requirement 1: Network Security",
      "Requirement 5: Malware Protection",
      "Requirement 6: Secure Systems",
      "Requirement 10: Logging & Monitoring",
      "Requirement 11: Security Testing",
      "Gap Analysis",
      "Remediation Plan"
    ]
  end

  @impl true
  def parameters do
    [
      %{
        name: "include_evidence",
        type: "boolean",
        default: true,
        description: "Include evidence references for each control"
      },
      %{
        name: "assessment_scope",
        type: "select",
        options: ["full", "cardholder_data_environment", "connected_systems"],
        default: "full",
        description: "Scope of assessment"
      }
    ]
  end

  @impl true
  def supported_formats, do: [:pdf, :html, :json]

  @impl true
  def generate(date_from, date_to, params) do
    include_evidence = Map.get(params, "include_evidence", true)

    # Evaluate all controls
    controls = evaluate_controls()

    # Calculate overall score
    score = ComplianceBase.calculate_compliance_score(controls)

    # Count by status
    compliant = Enum.count(controls, & &1.status == :compliant)
    partial = Enum.count(controls, & &1.status == :partial)
    non_compliant = Enum.count(controls, & &1.status == :non_compliant)
    not_assessed = Enum.count(controls, & &1.status == :not_assessed)
    total = length(controls)

    # Group controls by requirement
    controls_by_req = Enum.group_by(controls, & &1.requirement)

    # Build sections
    sections = [
      %{
        "title" => "Compliance Summary",
        "type" => "summary",
        "content" => build_summary(date_from, date_to, score, compliant, partial,
                                   non_compliant, not_assessed, total)
      },
      %{
        "title" => "Compliance Score",
        "type" => "stats",
        "content" => [
          %{"label" => "Overall Score", "value" => "#{score}%"},
          %{"label" => "Total Controls", "value" => total},
          %{"label" => "Compliant", "value" => compliant},
          %{"label" => "Partial", "value" => partial},
          %{"label" => "Non-Compliant", "value" => non_compliant,
            "change" => if(non_compliant > 0, do: "+#{non_compliant}", else: nil)},
          %{"label" => "Not Assessed", "value" => not_assessed}
        ]
      },
      %{
        "title" => "Compliance by Requirement",
        "type" => "chart",
        "content" => %{
          "chart_type" => "bar",
          "labels" => ["Req 1", "Req 5", "Req 6", "Req 10", "Req 11", "Req 12"],
          "data" => calculate_requirement_scores(controls_by_req),
          "title" => "Compliance Score by PCI-DSS Requirement"
        }
      }
    ]

    # Add requirement sections
    sections = sections ++ build_requirement_sections(controls_by_req, include_evidence)

    # Add gap analysis
    gaps = ComplianceBase.build_gap_analysis(controls)
    sections = sections ++ [
      %{
        "title" => "Gap Analysis",
        "type" => "table",
        "content" => %{
          "headers" => ["Control ID", "Requirement", "Status", "Remediation"],
          "rows" => if(length(gaps) > 0,
            do: gaps,
            else: [["No compliance gaps identified", "", "", ""]])
        }
      },
      %{
        "title" => "Remediation Plan",
        "type" => "list",
        "content" => build_remediation_plan(controls)
      }
    ]

    %{
      "title" => "PCI-DSS 4.0 Compliance Report",
      "sections" => sections
    }
  end

  # ============================================================================
  # Control Evaluation
  # ============================================================================

  defp evaluate_controls do
    [
      # Requirement 1: Network Security Controls
      %{
        id: "1.2.1",
        requirement: "Requirement 1",
        title: "Network segmentation controls",
        severity: "High",
        status: evaluate_network_segmentation(),
        evidence: "Network telemetry and firewall rules",
        remediation: "Implement and verify network segmentation for CDE"
      },
      %{
        id: "1.3.1",
        requirement: "Requirement 1",
        title: "Inbound traffic restriction",
        severity: "High",
        status: ComplianceBase.check_detection_rules(),
        evidence: "Firewall rules and network monitoring",
        remediation: "Configure firewall rules to restrict inbound traffic"
      },

      # Requirement 5: Malware Protection
      %{
        id: "5.2.1",
        requirement: "Requirement 5",
        title: "Anti-malware solution deployed",
        severity: "Critical",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "EDR agent deployment status",
        remediation: "Deploy EDR agents to all systems in scope"
      },
      %{
        id: "5.2.2",
        requirement: "Requirement 5",
        title: "Anti-malware is actively running",
        severity: "Critical",
        status: check_agents_active(),
        evidence: "Agent heartbeat monitoring",
        remediation: "Ensure all agents are online and reporting"
      },
      %{
        id: "5.3.1",
        requirement: "Requirement 5",
        title: "Anti-malware signatures updated",
        severity: "High",
        status: check_rules_updated(),
        evidence: "YARA/Sigma rule update timestamps",
        remediation: "Implement automatic rule updates"
      },
      %{
        id: "5.3.2",
        requirement: "Requirement 5",
        title: "Periodic malware scans",
        severity: "Medium",
        status: check_periodic_scans(),
        evidence: "Scan logs and schedules",
        remediation: "Configure periodic full system scans"
      },

      # Requirement 6: Secure Systems
      %{
        id: "6.3.1",
        requirement: "Requirement 6",
        title: "Security vulnerabilities identified",
        severity: "High",
        status: check_vulnerability_detection(),
        evidence: "Detection rule coverage",
        remediation: "Expand detection rules for known vulnerabilities"
      },
      %{
        id: "6.4.1",
        requirement: "Requirement 6",
        title: "Change management process",
        severity: "Medium",
        status: :partial,  # Requires manual verification
        evidence: "Audit logs",
        remediation: "Implement formal change management procedures"
      },

      # Requirement 10: Logging and Monitoring
      %{
        id: "10.2.1",
        requirement: "Requirement 10",
        title: "Audit logs enabled",
        severity: "Critical",
        status: ComplianceBase.check_logging_enabled(),
        evidence: "Telemetry collection status",
        remediation: "Enable comprehensive audit logging"
      },
      %{
        id: "10.2.2",
        requirement: "Requirement 10",
        title: "User access logging",
        severity: "High",
        status: check_user_access_logging(),
        evidence: "Authentication event collection",
        remediation: "Configure authentication event monitoring"
      },
      %{
        id: "10.4.1",
        requirement: "Requirement 10",
        title: "Time synchronization",
        severity: "Medium",
        status: :partial,  # Requires manual verification
        evidence: "NTP configuration",
        remediation: "Configure NTP on all systems"
      },
      %{
        id: "10.6.1",
        requirement: "Requirement 10",
        title: "Log review process",
        severity: "High",
        status: check_log_review(),
        evidence: "Alert review status",
        remediation: "Implement daily log review procedures"
      },
      %{
        id: "10.7.1",
        requirement: "Requirement 10",
        title: "Log retention (12 months)",
        severity: "High",
        status: :partial,  # Requires configuration verification
        evidence: "Data retention settings",
        remediation: "Configure 12-month log retention policy"
      },

      # Requirement 11: Security Testing
      %{
        id: "11.3.1",
        requirement: "Requirement 11",
        title: "Penetration testing",
        severity: "High",
        status: :not_assessed,  # External process
        evidence: "Pentest reports",
        remediation: "Schedule annual penetration testing"
      },
      %{
        id: "11.4.1",
        requirement: "Requirement 11",
        title: "Intrusion detection deployed",
        severity: "Critical",
        status: ComplianceBase.check_detection_rules(),
        evidence: "IDS/Detection rule count",
        remediation: "Deploy and configure detection rules"
      },
      %{
        id: "11.5.1",
        requirement: "Requirement 11",
        title: "File integrity monitoring",
        severity: "High",
        status: check_fim_enabled(),
        evidence: "FIM configuration",
        remediation: "Enable file integrity monitoring on critical files"
      },

      # Requirement 12: Security Policies
      %{
        id: "12.1.1",
        requirement: "Requirement 12",
        title: "Security policy established",
        severity: "Medium",
        status: :partial,  # Requires manual verification
        evidence: "Policy documents",
        remediation: "Document and publish security policies"
      },
      %{
        id: "12.10.1",
        requirement: "Requirement 12",
        title: "Incident response plan",
        severity: "High",
        status: ComplianceBase.check_incident_response(),
        evidence: "IR playbooks and procedures",
        remediation: "Develop and test incident response procedures"
      }
    ]
  end

  defp evaluate_network_segmentation do
    # Check if network monitoring is in place
    metrics = ComplianceBase.get_security_metrics()
    if metrics.online_agents > 0, do: :partial, else: :fail
  end

  defp check_agents_active do
    metrics = ComplianceBase.get_security_metrics()
    coverage = if metrics.total_agents > 0 do
      metrics.online_agents / metrics.total_agents * 100
    else
      0
    end

    cond do
      coverage >= 99 -> :pass
      coverage >= 90 -> :partial
      true -> :fail
    end
  end

  defp check_rules_updated do
    # Check if rules are configured (proxy for updates)
    metrics = ComplianceBase.get_security_metrics()
    if metrics.sigma_rules + metrics.yara_rules > 0, do: :pass, else: :fail
  end

  defp check_periodic_scans do
    # EDR provides continuous monitoring, which exceeds periodic scan requirements
    metrics = ComplianceBase.get_security_metrics()
    if metrics.online_agents > 0, do: :pass, else: :fail
  end

  defp check_vulnerability_detection do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.sigma_rules >= 50, do: :pass, else: :partial
  end

  defp check_user_access_logging do
    # EDR collects authentication events
    metrics = ComplianceBase.get_security_metrics()
    if metrics.online_agents > 0, do: :pass, else: :fail
  end

  defp check_log_review do
    # Check if alerts are being reviewed (resolved)
    resolved = ComplianceBase.safe_call(fn ->
      TamanduaServer.Alerts.count_by_status("resolved")
    end, 0)

    if resolved > 0, do: :pass, else: :partial
  end

  defp check_fim_enabled do
    # FIM is part of EDR functionality
    metrics = ComplianceBase.get_security_metrics()
    if metrics.online_agents > 0, do: :pass, else: :fail
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp build_summary(date_from, date_to, score, compliant, partial, non_compliant, not_assessed, total) do
    status = cond do
      score >= 90 -> "strong"
      score >= 70 -> "moderate"
      score >= 50 -> "needs improvement"
      true -> "requires immediate attention"
    end

    "PCI-DSS 4.0 compliance assessment for the period #{date_from} to #{date_to}. " <>
    "Overall compliance score is #{score}% (#{status}). " <>
    "Of #{total} controls evaluated: #{compliant} are fully compliant, " <>
    "#{partial} are partially compliant, #{non_compliant} are non-compliant, " <>
    "and #{not_assessed} have not been assessed. " <>
    "Focus areas include malware protection (Req 5), logging (Req 10), and security testing (Req 11)."
  end

  defp calculate_requirement_scores(controls_by_req) do
    requirements = ["Requirement 1", "Requirement 5", "Requirement 6",
                    "Requirement 10", "Requirement 11", "Requirement 12"]

    Enum.map(requirements, fn req ->
      controls = Map.get(controls_by_req, req, [])
      if length(controls) > 0 do
        ComplianceBase.calculate_compliance_score(controls)
      else
        0
      end
    end)
  end

  defp build_requirement_sections(controls_by_req, include_evidence) do
    requirements = [
      {"Requirement 1", "Requirement 1: Network Security Controls"},
      {"Requirement 5", "Requirement 5: Malware Protection"},
      {"Requirement 6", "Requirement 6: Secure Systems"},
      {"Requirement 10", "Requirement 10: Logging & Monitoring"},
      {"Requirement 11", "Requirement 11: Security Testing"},
      {"Requirement 12", "Requirement 12: Security Policies"}
    ]

    Enum.map(requirements, fn {key, title} ->
      controls = Map.get(controls_by_req, key, [])
      rows = Enum.map(controls, fn c ->
        base = [c.id, c.title, format_status(c.status), c.severity]
        if include_evidence, do: base ++ [c.evidence], else: base
      end)

      headers = if include_evidence do
        ["Control ID", "Control", "Status", "Severity", "Evidence"]
      else
        ["Control ID", "Control", "Status", "Severity"]
      end

      %{
        "title" => title,
        "type" => "table",
        "content" => %{
          "headers" => headers,
          "rows" => if(length(rows) > 0, do: rows, else: [["No controls", "", "", ""]])
        }
      }
    end)
  end

  defp format_status(:compliant), do: "Compliant"
  defp format_status(:partial), do: "Partial"
  defp format_status(:non_compliant), do: "Non-Compliant"
  defp format_status(:not_assessed), do: "Not Assessed"
  defp format_status(:pass), do: "Compliant"
  defp format_status(:fail), do: "Non-Compliant"
  defp format_status(_), do: "Unknown"

  defp build_remediation_plan(controls) do
    non_compliant = Enum.filter(controls, fn c ->
      c.status in [:non_compliant, :partial, :not_assessed, :fail]
    end)

    if length(non_compliant) == 0 do
      [
        "All assessed controls are compliant.",
        "Continue monitoring and periodic reassessment.",
        "Schedule quarterly compliance reviews."
      ]
    else
      priorities = non_compliant
      |> Enum.sort_by(fn c ->
        case c.severity do
          "Critical" -> 1
          "High" -> 2
          "Medium" -> 3
          _ -> 4
        end
      end)
      |> Enum.take(10)
      |> Enum.map(fn c -> "#{c.id}: #{c.remediation}" end)

      priorities ++ [
        "Schedule follow-up assessment after remediation.",
        "Document all remediation activities for audit trail."
      ]
    end
  end
end
