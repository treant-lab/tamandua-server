defmodule TamanduaServer.Reports.Compliance.SOC2 do
  @moduledoc """
  SOC 2 Type II Compliance Report Template.

  Maps Tamandua EDR controls to SOC 2 Trust Service Criteria:
  - CC: Common Criteria (Security)
  - A: Availability
  - C: Confidentiality
  - PI: Processing Integrity
  - P: Privacy
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.Reports.Compliance.ComplianceBase

  @impl true
  def name, do: "SOC 2 Type II Compliance"

  @impl true
  def description do
    "SOC 2 Type II compliance assessment mapping EDR controls to Trust Service Criteria."
  end

  @impl true
  def category, do: "compliance"

  @impl true
  def sections do
    [
      "Compliance Summary",
      "Trust Criteria Overview",
      "CC: Security (Common Criteria)",
      "A: Availability",
      "C: Confidentiality",
      "Gap Analysis",
      "Remediation Plan"
    ]
  end

  @impl true
  def parameters do
    [
      %{name: "include_evidence", type: "boolean", default: true, description: "Include evidence"}
    ]
  end

  @impl true
  def supported_formats, do: [:pdf, :html, :json]

  @impl true
  def generate(date_from, date_to, params) do
    include_evidence = Map.get(params, "include_evidence", true)

    controls = evaluate_controls()
    score = ComplianceBase.calculate_compliance_score(controls)

    compliant = Enum.count(controls, & &1.status == :compliant)
    partial = Enum.count(controls, & &1.status == :partial)
    non_compliant = Enum.count(controls, & &1.status == :non_compliant)
    not_assessed = Enum.count(controls, & &1.status == :not_assessed)
    total = length(controls)

    controls_by_criteria = Enum.group_by(controls, & &1.criteria)

    sections = [
      %{
        "title" => "Compliance Summary",
        "type" => "summary",
        "content" => build_summary(date_from, date_to, score, compliant, partial,
                                   non_compliant, not_assessed, total)
      },
      %{
        "title" => "Trust Criteria Overview",
        "type" => "stats",
        "content" => [
          %{"label" => "Overall Score", "value" => "#{score}%"},
          %{"label" => "Security (CC)", "value" => "#{criteria_score(controls_by_criteria, "CC")}%"},
          %{"label" => "Availability (A)", "value" => "#{criteria_score(controls_by_criteria, "A")}%"},
          %{"label" => "Confidentiality (C)", "value" => "#{criteria_score(controls_by_criteria, "C")}%"},
          %{"label" => "Total Controls", "value" => total},
          %{"label" => "Compliant", "value" => compliant},
          %{"label" => "Partial", "value" => partial},
          %{"label" => "Non-Compliant", "value" => non_compliant}
        ]
      },
      %{
        "title" => "Compliance by Trust Criteria",
        "type" => "chart",
        "content" => %{
          "chart_type" => "bar",
          "labels" => ["Security (CC)", "Availability (A)", "Confidentiality (C)"],
          "data" => [
            criteria_score(controls_by_criteria, "CC"),
            criteria_score(controls_by_criteria, "A"),
            criteria_score(controls_by_criteria, "C")
          ],
          "title" => "SOC 2 Trust Criteria Compliance"
        }
      }
    ]

    # Add criteria sections
    sections = sections ++ build_criteria_sections(controls_by_criteria, include_evidence)

    # Add gap analysis
    gaps = ComplianceBase.build_gap_analysis(controls)
    sections = sections ++ [
      %{
        "title" => "Gap Analysis",
        "type" => "table",
        "content" => %{
          "headers" => ["Control ID", "Requirement", "Status", "Remediation"],
          "rows" => if(length(gaps) > 0, do: gaps, else: [["No gaps", "", "", ""]])
        }
      },
      %{
        "title" => "Remediation Plan",
        "type" => "list",
        "content" => build_remediation_plan(controls)
      }
    ]

    %{
      "title" => "SOC 2 Type II Compliance Report",
      "sections" => sections
    }
  end

  defp evaluate_controls do
    [
      # CC: Security (Common Criteria)
      %{
        id: "CC1.1",
        criteria: "CC",
        title: "COSO Principle 1: Integrity and ethical values",
        severity: "Medium",
        status: :partial,
        evidence: "Security policies",
        remediation: "Document integrity and ethics policies"
      },
      %{
        id: "CC2.1",
        criteria: "CC",
        title: "Internal and external communication of security objectives",
        severity: "Medium",
        status: :partial,
        evidence: "Security communications",
        remediation: "Implement security communication program"
      },
      %{
        id: "CC3.1",
        criteria: "CC",
        title: "Security-related objectives specified",
        severity: "High",
        status: ComplianceBase.check_detection_rules(),
        evidence: "Detection rule configuration",
        remediation: "Document security objectives and controls"
      },
      %{
        id: "CC4.1",
        criteria: "CC",
        title: "Monitoring activities - Security monitoring",
        severity: "Critical",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "EDR agent deployment",
        remediation: "Deploy security monitoring across all systems"
      },
      %{
        id: "CC5.1",
        criteria: "CC",
        title: "Control activities designed and implemented",
        severity: "High",
        status: ComplianceBase.check_detection_rules(),
        evidence: "Detection and response rules",
        remediation: "Implement security control activities"
      },
      %{
        id: "CC6.1",
        criteria: "CC",
        title: "Logical access security software and infrastructure",
        severity: "Critical",
        status: check_access_controls(),
        evidence: "Access control logs",
        remediation: "Implement logical access controls"
      },
      %{
        id: "CC6.2",
        criteria: "CC",
        title: "Prior to access, identity verified",
        severity: "High",
        status: :partial,
        evidence: "Authentication logs",
        remediation: "Implement identity verification"
      },
      %{
        id: "CC6.3",
        criteria: "CC",
        title: "Access granted based on authorization",
        severity: "High",
        status: :partial,
        evidence: "Authorization logs",
        remediation: "Implement role-based access control"
      },
      %{
        id: "CC6.6",
        criteria: "CC",
        title: "Security threat detection",
        severity: "Critical",
        status: ComplianceBase.check_detection_rules(),
        evidence: "Detection rule count and alerts",
        remediation: "Configure threat detection rules"
      },
      %{
        id: "CC6.7",
        criteria: "CC",
        title: "Transmission protected from unauthorized access",
        severity: "High",
        status: :partial,
        evidence: "Encryption configuration",
        remediation: "Implement transmission encryption"
      },
      %{
        id: "CC6.8",
        criteria: "CC",
        title: "Unauthorized software detected and prevented",
        severity: "High",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "Malware detection",
        remediation: "Deploy anti-malware protection"
      },
      %{
        id: "CC7.1",
        criteria: "CC",
        title: "Detect security events using detection processes",
        severity: "Critical",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "Security event detection",
        remediation: "Implement security event detection"
      },
      %{
        id: "CC7.2",
        criteria: "CC",
        title: "Monitor for anomalies indicating security events",
        severity: "High",
        status: check_anomaly_detection(),
        evidence: "Behavioral analytics",
        remediation: "Enable anomaly detection"
      },
      %{
        id: "CC7.3",
        criteria: "CC",
        title: "Evaluate security events",
        severity: "High",
        status: ComplianceBase.check_incident_response(),
        evidence: "Alert triage process",
        remediation: "Implement alert evaluation procedures"
      },
      %{
        id: "CC7.4",
        criteria: "CC",
        title: "Respond to security incidents",
        severity: "Critical",
        status: ComplianceBase.check_incident_response(),
        evidence: "Incident response procedures",
        remediation: "Implement incident response plan"
      },
      %{
        id: "CC7.5",
        criteria: "CC",
        title: "Recover from security incidents",
        severity: "High",
        status: :partial,
        evidence: "Recovery procedures",
        remediation: "Document recovery procedures"
      },

      # A: Availability
      %{
        id: "A1.1",
        criteria: "A",
        title: "System availability objectives defined",
        severity: "Medium",
        status: :partial,
        evidence: "SLA documentation",
        remediation: "Define availability SLAs"
      },
      %{
        id: "A1.2",
        criteria: "A",
        title: "System components monitored for availability",
        severity: "High",
        status: check_availability_monitoring(),
        evidence: "Agent health monitoring",
        remediation: "Implement system availability monitoring"
      },
      %{
        id: "A1.3",
        criteria: "A",
        title: "Recovery procedures support availability",
        severity: "High",
        status: :partial,
        evidence: "Backup and recovery procedures",
        remediation: "Implement and test recovery procedures"
      },

      # C: Confidentiality
      %{
        id: "C1.1",
        criteria: "C",
        title: "Confidential information identified",
        severity: "High",
        status: :partial,
        evidence: "Data classification",
        remediation: "Implement data classification"
      },
      %{
        id: "C1.2",
        criteria: "C",
        title: "Confidential information protected from access",
        severity: "Critical",
        status: check_data_protection(),
        evidence: "Access controls and monitoring",
        remediation: "Implement data access controls"
      }
    ]
  end

  defp check_access_controls do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.online_agents > 0, do: :pass, else: :fail
  end

  defp check_anomaly_detection do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.sigma_rules >= 50, do: :pass, else: :partial
  end

  defp check_availability_monitoring do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.online_agents > 0, do: :pass, else: :fail
  end

  defp check_data_protection do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.online_agents > 0 and metrics.sigma_rules > 0, do: :pass, else: :partial
  end

  defp criteria_score(controls_by_criteria, criteria) do
    controls = Map.get(controls_by_criteria, criteria, [])
    if length(controls) > 0 do
      ComplianceBase.calculate_compliance_score(controls)
    else
      0
    end
  end

  defp build_summary(date_from, date_to, score, compliant, partial, non_compliant, not_assessed, total) do
    status = if score >= 80, do: "strong", else: "needs improvement"

    "SOC 2 Type II compliance assessment for #{date_from} to #{date_to}. " <>
    "Overall compliance score: #{score}% (#{status}). " <>
    "Of #{total} controls: #{compliant} compliant, #{partial} partial, " <>
    "#{non_compliant} non-compliant, #{not_assessed} not assessed."
  end

  defp build_criteria_sections(controls_by_criteria, include_evidence) do
    [
      {"CC", "CC: Security (Common Criteria)"},
      {"A", "A: Availability"},
      {"C", "C: Confidentiality"}
    ]
    |> Enum.map(fn {key, title} ->
      controls = Map.get(controls_by_criteria, key, [])
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
    non_compliant = Enum.filter(controls, & &1.status in [:non_compliant, :partial, :not_assessed, :fail])

    if length(non_compliant) == 0 do
      ["All controls compliant."]
    else
      non_compliant
      |> Enum.sort_by(& if(&1.severity == "Critical", do: 1, else: 2))
      |> Enum.take(10)
      |> Enum.map(& "#{&1.id}: #{&1.remediation}")
    end
  end
end
