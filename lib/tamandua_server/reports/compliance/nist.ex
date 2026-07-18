defmodule TamanduaServer.Reports.Compliance.NIST do
  @moduledoc """
  NIST Cybersecurity Framework (CSF) Compliance Report Template.

  Maps Tamandua EDR controls to NIST CSF categories:
  - Identify (ID)
  - Protect (PR)
  - Detect (DE)
  - Respond (RS)
  - Recover (RC)
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.Reports.Compliance.ComplianceBase

  @impl true
  def name, do: "NIST CSF Compliance"

  @impl true
  def description do
    "NIST Cybersecurity Framework compliance assessment mapping EDR controls to CSF categories."
  end

  @impl true
  def category, do: "compliance"

  @impl true
  def sections do
    [
      "Compliance Summary",
      "Framework Overview",
      "ID: Identify",
      "PR: Protect",
      "DE: Detect",
      "RS: Respond",
      "RC: Recover",
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
    _partial = Enum.count(controls, & &1.status == :partial)
    non_compliant = Enum.count(controls, & &1.status == :non_compliant)
    _not_assessed = Enum.count(controls, & &1.status == :not_assessed)
    total = length(controls)

    controls_by_function = Enum.group_by(controls, & &1.function)

    sections = [
      %{
        "title" => "Compliance Summary",
        "type" => "summary",
        "content" => build_summary(date_from, date_to, score, total)
      },
      %{
        "title" => "Framework Overview",
        "type" => "stats",
        "content" => [
          %{"label" => "Overall Score", "value" => "#{score}%"},
          %{"label" => "Identify (ID)", "value" => "#{function_score(controls_by_function, "ID")}%"},
          %{"label" => "Protect (PR)", "value" => "#{function_score(controls_by_function, "PR")}%"},
          %{"label" => "Detect (DE)", "value" => "#{function_score(controls_by_function, "DE")}%"},
          %{"label" => "Respond (RS)", "value" => "#{function_score(controls_by_function, "RS")}%"},
          %{"label" => "Recover (RC)", "value" => "#{function_score(controls_by_function, "RC")}%"},
          %{"label" => "Compliant", "value" => compliant},
          %{"label" => "Non-Compliant", "value" => non_compliant}
        ]
      },
      %{
        "title" => "NIST CSF Function Coverage",
        "type" => "chart",
        "content" => %{
          "chart_type" => "radar",
          "labels" => ["Identify", "Protect", "Detect", "Respond", "Recover"],
          "data" => [
            function_score(controls_by_function, "ID"),
            function_score(controls_by_function, "PR"),
            function_score(controls_by_function, "DE"),
            function_score(controls_by_function, "RS"),
            function_score(controls_by_function, "RC")
          ],
          "title" => "NIST CSF Maturity"
        }
      }
    ]

    # Add function sections
    sections = sections ++ build_function_sections(controls_by_function, include_evidence)

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
      "title" => "NIST CSF Compliance Report",
      "sections" => sections
    }
  end

  defp evaluate_controls do
    [
      # Identify (ID)
      %{
        id: "ID.AM-1",
        function: "ID",
        title: "Physical devices and systems inventoried",
        severity: "High",
        status: check_asset_inventory(),
        evidence: "Agent inventory",
        remediation: "Complete asset inventory"
      },
      %{
        id: "ID.AM-2",
        function: "ID",
        title: "Software platforms inventoried",
        severity: "High",
        status: :partial,
        evidence: "Software inventory",
        remediation: "Deploy software inventory tools"
      },
      %{
        id: "ID.AM-5",
        function: "ID",
        title: "Resources prioritized based on classification",
        severity: "Medium",
        status: :partial,
        evidence: "Asset classification",
        remediation: "Implement asset classification"
      },
      %{
        id: "ID.RA-1",
        function: "ID",
        title: "Asset vulnerabilities identified",
        severity: "High",
        status: ComplianceBase.check_detection_rules(),
        evidence: "Vulnerability detection",
        remediation: "Implement vulnerability scanning"
      },
      %{
        id: "ID.RA-2",
        function: "ID",
        title: "Threat intelligence received",
        severity: "Medium",
        status: check_threat_intel(),
        evidence: "Threat intel feeds",
        remediation: "Configure threat intel feeds"
      },

      # Protect (PR)
      %{
        id: "PR.AC-1",
        function: "PR",
        title: "Identities and credentials managed",
        severity: "Critical",
        status: :partial,
        evidence: "Identity management",
        remediation: "Implement identity management"
      },
      %{
        id: "PR.AC-3",
        function: "PR",
        title: "Remote access managed",
        severity: "High",
        status: :partial,
        evidence: "Remote access monitoring",
        remediation: "Configure remote access controls"
      },
      %{
        id: "PR.AC-4",
        function: "PR",
        title: "Access permissions managed",
        severity: "High",
        status: :partial,
        evidence: "Access control logs",
        remediation: "Implement RBAC"
      },
      %{
        id: "PR.DS-1",
        function: "PR",
        title: "Data at rest protected",
        severity: "High",
        status: :partial,
        evidence: "Encryption status",
        remediation: "Implement data encryption"
      },
      %{
        id: "PR.DS-5",
        function: "PR",
        title: "Protections against data leaks",
        severity: "High",
        status: ComplianceBase.check_detection_rules(),
        evidence: "DLP monitoring",
        remediation: "Configure DLP rules"
      },
      %{
        id: "PR.IP-1",
        function: "PR",
        title: "Configuration baselines established",
        severity: "Medium",
        status: :partial,
        evidence: "Configuration management",
        remediation: "Establish configuration baselines"
      },
      %{
        id: "PR.IP-12",
        function: "PR",
        title: "Vulnerability management plan",
        severity: "High",
        status: ComplianceBase.check_detection_rules(),
        evidence: "Vulnerability management",
        remediation: "Implement vulnerability management"
      },
      %{
        id: "PR.PT-1",
        function: "PR",
        title: "Audit records determined and documented",
        severity: "Critical",
        status: ComplianceBase.check_logging_enabled(),
        evidence: "Audit logging",
        remediation: "Configure comprehensive logging"
      },

      # Detect (DE)
      %{
        id: "DE.AE-1",
        function: "DE",
        title: "Baseline of network operations established",
        severity: "High",
        status: :partial,
        evidence: "Network baselines",
        remediation: "Establish network baselines"
      },
      %{
        id: "DE.AE-2",
        function: "DE",
        title: "Detected events analyzed",
        severity: "Critical",
        status: ComplianceBase.check_incident_response(),
        evidence: "Event analysis procedures",
        remediation: "Implement event analysis"
      },
      %{
        id: "DE.AE-3",
        function: "DE",
        title: "Event data aggregated and correlated",
        severity: "High",
        status: ComplianceBase.check_logging_enabled(),
        evidence: "SIEM correlation",
        remediation: "Configure event correlation"
      },
      %{
        id: "DE.CM-1",
        function: "DE",
        title: "Network monitored for security events",
        severity: "Critical",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "Network monitoring",
        remediation: "Deploy network monitoring"
      },
      %{
        id: "DE.CM-4",
        function: "DE",
        title: "Malicious code detected",
        severity: "Critical",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "Malware detection",
        remediation: "Deploy anti-malware"
      },
      %{
        id: "DE.CM-7",
        function: "DE",
        title: "Unauthorized personnel/connections monitored",
        severity: "High",
        status: ComplianceBase.check_detection_rules(),
        evidence: "Unauthorized access detection",
        remediation: "Configure unauthorized access detection"
      },
      %{
        id: "DE.DP-4",
        function: "DE",
        title: "Event detection information communicated",
        severity: "Medium",
        status: ComplianceBase.check_incident_response(),
        evidence: "Alert notifications",
        remediation: "Configure alert notifications"
      },

      # Respond (RS)
      %{
        id: "RS.RP-1",
        function: "RS",
        title: "Response plan executed",
        severity: "Critical",
        status: ComplianceBase.check_incident_response(),
        evidence: "IR procedures",
        remediation: "Implement IR procedures"
      },
      %{
        id: "RS.CO-2",
        function: "RS",
        title: "Events reported consistent with criteria",
        severity: "High",
        status: :partial,
        evidence: "Reporting procedures",
        remediation: "Establish reporting procedures"
      },
      %{
        id: "RS.AN-1",
        function: "RS",
        title: "Notifications from detection systems investigated",
        severity: "Critical",
        status: ComplianceBase.check_incident_response(),
        evidence: "Investigation procedures",
        remediation: "Implement investigation procedures"
      },
      %{
        id: "RS.MI-1",
        function: "RS",
        title: "Incidents contained",
        severity: "Critical",
        status: :partial,
        evidence: "Containment capabilities",
        remediation: "Implement containment procedures"
      },
      %{
        id: "RS.MI-2",
        function: "RS",
        title: "Incidents mitigated",
        severity: "Critical",
        status: :partial,
        evidence: "Mitigation procedures",
        remediation: "Implement mitigation procedures"
      },

      # Recover (RC)
      %{
        id: "RC.RP-1",
        function: "RC",
        title: "Recovery plan executed",
        severity: "High",
        status: :partial,
        evidence: "Recovery procedures",
        remediation: "Document recovery procedures"
      },
      %{
        id: "RC.IM-1",
        function: "RC",
        title: "Recovery plans incorporate lessons learned",
        severity: "Medium",
        status: :partial,
        evidence: "Post-incident reviews",
        remediation: "Implement post-incident reviews"
      },
      %{
        id: "RC.CO-3",
        function: "RC",
        title: "Recovery activities communicated",
        severity: "Medium",
        status: :partial,
        evidence: "Communication procedures",
        remediation: "Establish recovery communications"
      }
    ]
  end

  defp check_asset_inventory do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.total_agents > 0, do: :pass, else: :fail
  end

  defp check_threat_intel do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.total_iocs > 0, do: :pass, else: :partial
  end

  defp function_score(controls_by_function, function) do
    controls = Map.get(controls_by_function, function, [])
    if length(controls) > 0 do
      ComplianceBase.calculate_compliance_score(controls)
    else
      0
    end
  end

  defp build_summary(date_from, date_to, score, total) do
    maturity = cond do
      score >= 80 -> "Tier 3: Repeatable"
      score >= 60 -> "Tier 2: Risk Informed"
      score >= 40 -> "Tier 1: Partial"
      true -> "Tier 0: Initial"
    end

    "NIST Cybersecurity Framework assessment for #{date_from} to #{date_to}. " <>
    "Overall maturity score: #{score}% (#{maturity}) across #{total} controls. " <>
    "Focus areas: Detect and Respond functions for EDR capabilities."
  end

  defp build_function_sections(controls_by_function, include_evidence) do
    [
      {"ID", "ID: Identify"},
      {"PR", "PR: Protect"},
      {"DE", "DE: Detect"},
      {"RS", "RS: Respond"},
      {"RC", "RC: Recover"}
    ]
    |> Enum.map(fn {key, title} ->
      controls = Map.get(controls_by_function, key, [])
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
