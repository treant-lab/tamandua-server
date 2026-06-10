defmodule TamanduaServer.Reports.Compliance.GDPR do
  @moduledoc """
  GDPR Article 32 Compliance Report Template.

  Maps Tamandua EDR controls to GDPR Security of Processing requirements:
  - Article 32: Security of processing
  - Article 33: Breach notification
  - Article 34: Communication to data subjects
  - Article 35: Data protection impact assessment
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.Reports.Compliance.ComplianceBase

  @impl true
  def name, do: "GDPR Security Compliance"

  @impl true
  def description do
    "GDPR Article 32 compliance assessment for security of processing requirements."
  end

  @impl true
  def category, do: "compliance"

  @impl true
  def sections do
    [
      "Compliance Summary",
      "Compliance Score",
      "Article 32: Security of Processing",
      "Article 33: Breach Notification",
      "Technical Measures",
      "Organizational Measures",
      "Gap Analysis",
      "Remediation Plan"
    ]
  end

  @impl true
  def parameters do
    [%{name: "include_evidence", type: "boolean", default: true, description: "Include evidence"}]
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

    controls_by_article = Enum.group_by(controls, & &1.article)

    sections = [
      %{
        "title" => "Compliance Summary",
        "type" => "summary",
        "content" => build_summary(date_from, date_to, score, total)
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
      }
    ]

    # Add article sections
    sections = sections ++ build_article_sections(controls_by_article, include_evidence)

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
      "title" => "GDPR Security Compliance Report",
      "sections" => sections
    }
  end

  defp evaluate_controls do
    [
      # Article 32: Security of Processing
      %{
        id: "Art32.1.a",
        article: "Article 32",
        title: "Pseudonymization and encryption of personal data",
        severity: "High",
        status: :partial,
        evidence: "Encryption status monitoring",
        remediation: "Implement data encryption at rest and in transit"
      },
      %{
        id: "Art32.1.b.1",
        article: "Article 32",
        title: "Confidentiality of processing systems",
        severity: "Critical",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "EDR deployment and access controls",
        remediation: "Deploy endpoint protection on all systems"
      },
      %{
        id: "Art32.1.b.2",
        article: "Article 32",
        title: "Integrity of processing systems",
        severity: "Critical",
        status: check_integrity_controls(),
        evidence: "File integrity monitoring",
        remediation: "Enable integrity monitoring"
      },
      %{
        id: "Art32.1.b.3",
        article: "Article 32",
        title: "Availability of processing systems",
        severity: "High",
        status: check_availability(),
        evidence: "System availability metrics",
        remediation: "Implement availability monitoring"
      },
      %{
        id: "Art32.1.b.4",
        article: "Article 32",
        title: "Resilience of processing systems",
        severity: "High",
        status: :partial,
        evidence: "Backup and recovery procedures",
        remediation: "Implement and test recovery procedures"
      },
      %{
        id: "Art32.1.c",
        article: "Article 32",
        title: "Restore availability after incident",
        severity: "High",
        status: :partial,
        evidence: "Disaster recovery procedures",
        remediation: "Document and test DR procedures"
      },
      %{
        id: "Art32.1.d",
        article: "Article 32",
        title: "Regular testing of security measures",
        severity: "Medium",
        status: ComplianceBase.check_detection_rules(),
        evidence: "Security testing records",
        remediation: "Implement regular security testing"
      },

      # Article 33: Breach Notification
      %{
        id: "Art33.1",
        article: "Article 33",
        title: "Breach detection capability",
        severity: "Critical",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "Breach detection monitoring",
        remediation: "Implement breach detection controls"
      },
      %{
        id: "Art33.2",
        article: "Article 33",
        title: "72-hour notification capability",
        severity: "Critical",
        status: ComplianceBase.check_incident_response(),
        evidence: "Incident response procedures",
        remediation: "Establish 72-hour breach notification process"
      },
      %{
        id: "Art33.3",
        article: "Article 33",
        title: "Breach documentation",
        severity: "High",
        status: ComplianceBase.check_logging_enabled(),
        evidence: "Incident logging",
        remediation: "Enable comprehensive incident logging"
      },

      # Technical Measures
      %{
        id: "Tech.1",
        article: "Technical",
        title: "Access control mechanisms",
        severity: "Critical",
        status: :partial,
        evidence: "Access control logs",
        remediation: "Implement role-based access control"
      },
      %{
        id: "Tech.2",
        article: "Technical",
        title: "Audit logging enabled",
        severity: "Critical",
        status: ComplianceBase.check_logging_enabled(),
        evidence: "Audit log configuration",
        remediation: "Enable comprehensive audit logging"
      },
      %{
        id: "Tech.3",
        article: "Technical",
        title: "Malware protection",
        severity: "Critical",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "Anti-malware deployment",
        remediation: "Deploy anti-malware on all systems"
      },
      %{
        id: "Tech.4",
        article: "Technical",
        title: "Network security monitoring",
        severity: "High",
        status: ComplianceBase.check_detection_rules(),
        evidence: "Network monitoring rules",
        remediation: "Configure network security monitoring"
      },

      # Organizational Measures
      %{
        id: "Org.1",
        article: "Organizational",
        title: "Security policies documented",
        severity: "High",
        status: :partial,
        evidence: "Policy documentation",
        remediation: "Document security policies"
      },
      %{
        id: "Org.2",
        article: "Organizational",
        title: "Staff security training",
        severity: "Medium",
        status: :not_assessed,
        evidence: "Training records",
        remediation: "Implement security awareness training"
      },
      %{
        id: "Org.3",
        article: "Organizational",
        title: "Incident response procedures",
        severity: "Critical",
        status: ComplianceBase.check_incident_response(),
        evidence: "IR procedures",
        remediation: "Document and test IR procedures"
      }
    ]
  end

  defp check_integrity_controls do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.online_agents > 0, do: :pass, else: :fail
  end

  defp check_availability do
    metrics = ComplianceBase.get_security_metrics()
    coverage = if metrics.total_agents > 0 do
      metrics.online_agents / metrics.total_agents * 100
    else
      0
    end
    if coverage >= 90, do: :pass, else: :partial
  end

  defp build_summary(date_from, date_to, score, total) do
    status = if score >= 80, do: "strong", else: "needs improvement"

    "GDPR Article 32 security compliance assessment for #{date_from} to #{date_to}. " <>
    "Overall compliance score: #{score}% (#{status}) across #{total} controls. " <>
    "Focus areas: breach detection, notification capabilities, and technical security measures."
  end

  defp build_article_sections(controls_by_article, include_evidence) do
    [
      {"Article 32", "Article 32: Security of Processing"},
      {"Article 33", "Article 33: Breach Notification"},
      {"Technical", "Technical Measures"},
      {"Organizational", "Organizational Measures"}
    ]
    |> Enum.map(fn {key, title} ->
      controls = Map.get(controls_by_article, key, [])
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
