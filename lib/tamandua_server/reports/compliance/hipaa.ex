defmodule TamanduaServer.Reports.Compliance.HIPAA do
  @moduledoc """
  HIPAA Security Rule Compliance Report Template.

  Maps Tamandua EDR controls to HIPAA Security Rule requirements:
  - Administrative Safeguards (164.308)
  - Physical Safeguards (164.310)
  - Technical Safeguards (164.312)
  - Organizational Requirements (164.314)
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.Reports.Compliance.ComplianceBase

  @impl true
  def name, do: "HIPAA Security Rule Compliance"

  @impl true
  def description do
    "HIPAA Security Rule compliance assessment mapping EDR controls to PHI protection requirements."
  end

  @impl true
  def category, do: "compliance"

  @impl true
  def sections do
    [
      "Compliance Summary",
      "Compliance Score",
      "Administrative Safeguards",
      "Physical Safeguards",
      "Technical Safeguards",
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
        description: "Include evidence references"
      }
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

    controls_by_category = Enum.group_by(controls, & &1.category)

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
          %{"label" => "Non-Compliant", "value" => non_compliant},
          %{"label" => "Not Assessed", "value" => not_assessed}
        ]
      },
      %{
        "title" => "Safeguard Compliance",
        "type" => "chart",
        "content" => %{
          "chart_type" => "bar",
          "labels" => ["Administrative", "Physical", "Technical"],
          "data" => calculate_category_scores(controls_by_category),
          "title" => "Compliance by Safeguard Type"
        }
      }
    ]

    # Add category sections
    sections = sections ++ build_category_sections(controls_by_category, include_evidence)

    # Add gap analysis and remediation
    gaps = ComplianceBase.build_gap_analysis(controls)
    sections = sections ++ [
      %{
        "title" => "Gap Analysis",
        "type" => "table",
        "content" => %{
          "headers" => ["Control ID", "Requirement", "Status", "Remediation"],
          "rows" => if(length(gaps) > 0, do: gaps, else: [["No gaps identified", "", "", ""]])
        }
      },
      %{
        "title" => "Remediation Plan",
        "type" => "list",
        "content" => build_remediation_plan(controls)
      }
    ]

    %{
      "title" => "HIPAA Security Rule Compliance Report",
      "sections" => sections
    }
  end

  defp evaluate_controls do
    [
      # Administrative Safeguards (164.308)
      %{
        id: "164.308(a)(1)",
        category: "Administrative",
        title: "Security Management Process - Risk Analysis",
        severity: "Critical",
        status: :partial,
        evidence: "Threat detection and alerting",
        remediation: "Document formal risk analysis procedures"
      },
      %{
        id: "164.308(a)(1)(ii)(B)",
        category: "Administrative",
        title: "Risk Management - Implement security measures",
        severity: "High",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "EDR deployment status",
        remediation: "Deploy security controls to all systems with PHI access"
      },
      %{
        id: "164.308(a)(3)",
        category: "Administrative",
        title: "Workforce Security - Authorization procedures",
        severity: "High",
        status: :partial,
        evidence: "Access control logs",
        remediation: "Implement workforce authorization procedures"
      },
      %{
        id: "164.308(a)(4)",
        category: "Administrative",
        title: "Information Access Management",
        severity: "High",
        status: check_access_monitoring(),
        evidence: "Access monitoring logs",
        remediation: "Implement access management procedures"
      },
      %{
        id: "164.308(a)(5)",
        category: "Administrative",
        title: "Security Awareness Training",
        severity: "Medium",
        status: :not_assessed,
        evidence: "Training records",
        remediation: "Implement security awareness training program"
      },
      %{
        id: "164.308(a)(6)",
        category: "Administrative",
        title: "Security Incident Procedures",
        severity: "Critical",
        status: ComplianceBase.check_incident_response(),
        evidence: "Incident response procedures",
        remediation: "Document and test incident response procedures"
      },
      %{
        id: "164.308(a)(7)",
        category: "Administrative",
        title: "Contingency Plan",
        severity: "High",
        status: :partial,
        evidence: "Backup and recovery procedures",
        remediation: "Develop and test contingency plan"
      },

      # Physical Safeguards (164.310)
      %{
        id: "164.310(a)(1)",
        category: "Physical",
        title: "Facility Access Controls",
        severity: "High",
        status: :not_assessed,
        evidence: "Physical access logs",
        remediation: "Implement facility access controls"
      },
      %{
        id: "164.310(b)",
        category: "Physical",
        title: "Workstation Use",
        severity: "Medium",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "Workstation monitoring",
        remediation: "Define and enforce workstation use policies"
      },
      %{
        id: "164.310(c)",
        category: "Physical",
        title: "Workstation Security",
        severity: "High",
        status: check_workstation_security(),
        evidence: "Endpoint security status",
        remediation: "Implement workstation security controls"
      },
      %{
        id: "164.310(d)(1)",
        category: "Physical",
        title: "Device and Media Controls",
        severity: "High",
        status: :partial,
        evidence: "USB and media monitoring",
        remediation: "Implement device control policies"
      },

      # Technical Safeguards (164.312)
      %{
        id: "164.312(a)(1)",
        category: "Technical",
        title: "Access Control - Unique User ID",
        severity: "Critical",
        status: check_user_identification(),
        evidence: "User identification in logs",
        remediation: "Ensure unique user identification for all access"
      },
      %{
        id: "164.312(a)(2)(i)",
        category: "Technical",
        title: "Emergency Access Procedure",
        severity: "High",
        status: :partial,
        evidence: "Emergency access procedures",
        remediation: "Document emergency access procedures"
      },
      %{
        id: "164.312(a)(2)(ii)",
        category: "Technical",
        title: "Automatic Logoff",
        severity: "Medium",
        status: :partial,
        evidence: "Session timeout policies",
        remediation: "Implement automatic session timeout"
      },
      %{
        id: "164.312(b)",
        category: "Technical",
        title: "Audit Controls",
        severity: "Critical",
        status: ComplianceBase.check_logging_enabled(),
        evidence: "Audit logging configuration",
        remediation: "Enable comprehensive audit logging"
      },
      %{
        id: "164.312(c)(1)",
        category: "Technical",
        title: "Integrity Controls",
        severity: "High",
        status: check_integrity_monitoring(),
        evidence: "File integrity monitoring",
        remediation: "Implement integrity monitoring for PHI"
      },
      %{
        id: "164.312(d)",
        category: "Technical",
        title: "Person or Entity Authentication",
        severity: "Critical",
        status: check_authentication(),
        evidence: "Authentication logs",
        remediation: "Implement strong authentication controls"
      },
      %{
        id: "164.312(e)(1)",
        category: "Technical",
        title: "Transmission Security",
        severity: "High",
        status: :partial,
        evidence: "Network encryption status",
        remediation: "Implement encryption for PHI transmission"
      }
    ]
  end

  defp check_access_monitoring do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.online_agents > 0, do: :pass, else: :fail
  end

  defp check_workstation_security do
    metrics = ComplianceBase.get_security_metrics()
    coverage = if metrics.total_agents > 0 do
      metrics.online_agents / metrics.total_agents * 100
    else
      0
    end
    if coverage >= 90, do: :pass, else: :partial
  end

  defp check_user_identification do
    # EDR tracks user context for processes
    metrics = ComplianceBase.get_security_metrics()
    if metrics.online_agents > 0, do: :pass, else: :fail
  end

  defp check_integrity_monitoring do
    # FIM is part of EDR
    metrics = ComplianceBase.get_security_metrics()
    if metrics.online_agents > 0, do: :pass, else: :fail
  end

  defp check_authentication do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.online_agents > 0, do: :partial, else: :fail
  end

  defp build_summary(date_from, date_to, score, compliant, partial, non_compliant, not_assessed, total) do
    status = if score >= 80, do: "strong", else: "needs improvement"

    "HIPAA Security Rule compliance assessment for #{date_from} to #{date_to}. " <>
    "Overall compliance score: #{score}% (#{status}). " <>
    "Of #{total} controls: #{compliant} compliant, #{partial} partial, " <>
    "#{non_compliant} non-compliant, #{not_assessed} not assessed. " <>
    "Focus areas: Technical safeguards and audit controls."
  end

  defp calculate_category_scores(controls_by_category) do
    categories = ["Administrative", "Physical", "Technical"]
    Enum.map(categories, fn cat ->
      controls = Map.get(controls_by_category, cat, [])
      if length(controls) > 0 do
        ComplianceBase.calculate_compliance_score(controls)
      else
        0
      end
    end)
  end

  defp build_category_sections(controls_by_category, include_evidence) do
    [
      {"Administrative", "Administrative Safeguards (164.308)"},
      {"Physical", "Physical Safeguards (164.310)"},
      {"Technical", "Technical Safeguards (164.312)"}
    ]
    |> Enum.map(fn {key, title} ->
      controls = Map.get(controls_by_category, key, [])
      rows = Enum.map(controls, fn c ->
        base = [c.id, c.title, format_status(c.status), c.severity]
        if include_evidence, do: base ++ [c.evidence], else: base
      end)

      headers = if include_evidence do
        ["Section", "Requirement", "Status", "Severity", "Evidence"]
      else
        ["Section", "Requirement", "Status", "Severity"]
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
      ["All controls compliant. Continue monitoring."]
    else
      non_compliant
      |> Enum.sort_by(& if(&1.severity == "Critical", do: 1, else: 2))
      |> Enum.take(10)
      |> Enum.map(& "#{&1.id}: #{&1.remediation}")
    end
  end
end
