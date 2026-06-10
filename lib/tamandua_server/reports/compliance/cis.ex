defmodule TamanduaServer.Reports.Compliance.CIS do
  @moduledoc """
  CIS Controls v8 Compliance Report Template.

  Maps Tamandua EDR controls to CIS Critical Security Controls:
  - IG1: Basic Cyber Hygiene (Essential)
  - IG2: Intermediate (Foundational)
  - IG3: Advanced (Organizational)
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.Reports.Compliance.ComplianceBase

  @impl true
  def name, do: "CIS Controls v8 Compliance"

  @impl true
  def description do
    "CIS Critical Security Controls v8 compliance assessment with Implementation Group mapping."
  end

  @impl true
  def category, do: "compliance"

  @impl true
  def sections do
    [
      "Compliance Summary",
      "Implementation Group Overview",
      "CIS Control 1: Asset Inventory",
      "CIS Control 2: Software Inventory",
      "CIS Control 3: Data Protection",
      "CIS Control 4: Secure Configuration",
      "CIS Control 7: Vulnerability Management",
      "CIS Control 8: Audit Log Management",
      "CIS Control 10: Malware Defenses",
      "CIS Control 13: Network Monitoring",
      "CIS Control 17: Incident Response",
      "Gap Analysis",
      "Remediation Plan"
    ]
  end

  @impl true
  def parameters do
    [
      %{
        name: "implementation_group",
        type: "select",
        options: ["IG1", "IG2", "IG3"],
        default: "IG1",
        description: "Target Implementation Group"
      },
      %{name: "include_evidence", type: "boolean", default: true, description: "Include evidence"}
    ]
  end

  @impl true
  def supported_formats, do: [:pdf, :html, :json]

  @impl true
  def generate(date_from, date_to, params) do
    ig = Map.get(params, "implementation_group", "IG1")
    include_evidence = Map.get(params, "include_evidence", true)

    controls = evaluate_controls(ig)
    score = ComplianceBase.calculate_compliance_score(controls)

    compliant = Enum.count(controls, & &1.status == :compliant)
    partial = Enum.count(controls, & &1.status == :partial)
    non_compliant = Enum.count(controls, & &1.status == :non_compliant)
    not_assessed = Enum.count(controls, & &1.status == :not_assessed)
    total = length(controls)

    controls_by_cis = Enum.group_by(controls, & &1.cis_control)

    sections = [
      %{
        "title" => "Compliance Summary",
        "type" => "summary",
        "content" => build_summary(date_from, date_to, score, ig, total)
      },
      %{
        "title" => "Implementation Group Overview",
        "type" => "stats",
        "content" => [
          %{"label" => "Target IG", "value" => ig},
          %{"label" => "Overall Score", "value" => "#{score}%"},
          %{"label" => "Total Controls", "value" => total},
          %{"label" => "Compliant", "value" => compliant},
          %{"label" => "Partial", "value" => partial},
          %{"label" => "Non-Compliant", "value" => non_compliant},
          %{"label" => "Not Assessed", "value" => not_assessed}
        ]
      },
      %{
        "title" => "CIS Control Coverage",
        "type" => "chart",
        "content" => %{
          "chart_type" => "bar",
          "labels" => ["Asset", "Software", "Data", "Config", "Vuln", "Audit", "Malware", "Network", "IR"],
          "data" => [
            control_score(controls_by_cis, "CIS 1"),
            control_score(controls_by_cis, "CIS 2"),
            control_score(controls_by_cis, "CIS 3"),
            control_score(controls_by_cis, "CIS 4"),
            control_score(controls_by_cis, "CIS 7"),
            control_score(controls_by_cis, "CIS 8"),
            control_score(controls_by_cis, "CIS 10"),
            control_score(controls_by_cis, "CIS 13"),
            control_score(controls_by_cis, "CIS 17")
          ],
          "title" => "Compliance by CIS Control"
        }
      }
    ]

    # Add CIS control sections
    sections = sections ++ build_control_sections(controls_by_cis, include_evidence)

    # Add gap analysis
    gaps = ComplianceBase.build_gap_analysis(controls)
    sections = sections ++ [
      %{
        "title" => "Gap Analysis",
        "type" => "table",
        "content" => %{
          "headers" => ["Safeguard", "Requirement", "Status", "Remediation"],
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
      "title" => "CIS Controls v8 Compliance Report (#{ig})",
      "sections" => sections
    }
  end

  defp evaluate_controls(ig) do
    base_controls = [
      # CIS Control 1: Inventory and Control of Enterprise Assets
      %{
        id: "1.1",
        cis_control: "CIS 1",
        title: "Establish and maintain detailed enterprise asset inventory",
        ig: "IG1",
        severity: "High",
        status: check_asset_inventory(),
        evidence: "Agent inventory",
        remediation: "Deploy agents to all enterprise assets"
      },
      %{
        id: "1.2",
        cis_control: "CIS 1",
        title: "Address unauthorized assets",
        ig: "IG1",
        severity: "High",
        status: :partial,
        evidence: "Asset discovery",
        remediation: "Implement rogue device detection"
      },

      # CIS Control 2: Inventory and Control of Software Assets
      %{
        id: "2.1",
        cis_control: "CIS 2",
        title: "Establish and maintain software inventory",
        ig: "IG1",
        severity: "High",
        status: :partial,
        evidence: "Software inventory",
        remediation: "Enable software inventory collection"
      },
      %{
        id: "2.3",
        cis_control: "CIS 2",
        title: "Address unauthorized software",
        ig: "IG1",
        severity: "High",
        status: ComplianceBase.check_detection_rules(),
        evidence: "Unauthorized software detection",
        remediation: "Configure unauthorized software detection"
      },

      # CIS Control 3: Data Protection
      %{
        id: "3.3",
        cis_control: "CIS 3",
        title: "Configure data access control lists",
        ig: "IG1",
        severity: "High",
        status: :partial,
        evidence: "Access controls",
        remediation: "Implement access control monitoring"
      },
      %{
        id: "3.4",
        cis_control: "CIS 3",
        title: "Enforce data retention",
        ig: "IG1",
        severity: "Medium",
        status: :partial,
        evidence: "Data retention policies",
        remediation: "Configure data retention"
      },

      # CIS Control 4: Secure Configuration
      %{
        id: "4.1",
        cis_control: "CIS 4",
        title: "Establish secure configuration process",
        ig: "IG1",
        severity: "High",
        status: :partial,
        evidence: "Configuration baselines",
        remediation: "Establish configuration baselines"
      },
      %{
        id: "4.4",
        cis_control: "CIS 4",
        title: "Implement and manage firewall on endpoints",
        ig: "IG1",
        severity: "High",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "Endpoint firewall status",
        remediation: "Enable endpoint firewall"
      },

      # CIS Control 7: Continuous Vulnerability Management
      %{
        id: "7.1",
        cis_control: "CIS 7",
        title: "Establish vulnerability management process",
        ig: "IG1",
        severity: "High",
        status: ComplianceBase.check_detection_rules(),
        evidence: "Vulnerability detection",
        remediation: "Implement vulnerability management"
      },
      %{
        id: "7.4",
        cis_control: "CIS 7",
        title: "Perform automated application patch management",
        ig: "IG1",
        severity: "High",
        status: :partial,
        evidence: "Patch management",
        remediation: "Implement automated patching"
      },

      # CIS Control 8: Audit Log Management
      %{
        id: "8.2",
        cis_control: "CIS 8",
        title: "Collect audit logs",
        ig: "IG1",
        severity: "Critical",
        status: ComplianceBase.check_logging_enabled(),
        evidence: "Audit log collection",
        remediation: "Enable comprehensive logging"
      },
      %{
        id: "8.3",
        cis_control: "CIS 8",
        title: "Ensure adequate audit log storage",
        ig: "IG1",
        severity: "High",
        status: :partial,
        evidence: "Log storage capacity",
        remediation: "Configure log retention"
      },
      %{
        id: "8.5",
        cis_control: "CIS 8",
        title: "Collect detailed audit logs",
        ig: "IG2",
        severity: "High",
        status: ComplianceBase.check_logging_enabled(),
        evidence: "Detailed logging",
        remediation: "Enable detailed audit logging"
      },

      # CIS Control 10: Malware Defenses
      %{
        id: "10.1",
        cis_control: "CIS 10",
        title: "Deploy and maintain anti-malware software",
        ig: "IG1",
        severity: "Critical",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "Anti-malware deployment",
        remediation: "Deploy EDR to all endpoints"
      },
      %{
        id: "10.2",
        cis_control: "CIS 10",
        title: "Configure automatic anti-malware signature updates",
        ig: "IG1",
        severity: "Critical",
        status: check_signature_updates(),
        evidence: "Rule update status",
        remediation: "Enable automatic rule updates"
      },
      %{
        id: "10.4",
        cis_control: "CIS 10",
        title: "Configure automatic anti-malware scanning",
        ig: "IG1",
        severity: "High",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "Real-time scanning",
        remediation: "Enable real-time scanning"
      },
      %{
        id: "10.5",
        cis_control: "CIS 10",
        title: "Enable anti-exploitation features",
        ig: "IG2",
        severity: "High",
        status: :partial,
        evidence: "Exploit protection",
        remediation: "Enable exploit protection"
      },
      %{
        id: "10.7",
        cis_control: "CIS 10",
        title: "Use behavior-based anti-malware software",
        ig: "IG2",
        severity: "High",
        status: check_behavioral_detection(),
        evidence: "Behavioral detection",
        remediation: "Enable behavioral detection"
      },

      # CIS Control 13: Network Monitoring and Defense
      %{
        id: "13.1",
        cis_control: "CIS 13",
        title: "Centralize security event alerting",
        ig: "IG1",
        severity: "High",
        status: ComplianceBase.check_endpoint_protection(),
        evidence: "Centralized alerting",
        remediation: "Centralize security alerts"
      },
      %{
        id: "13.3",
        cis_control: "CIS 13",
        title: "Deploy network intrusion detection solution",
        ig: "IG2",
        severity: "High",
        status: ComplianceBase.check_detection_rules(),
        evidence: "IDS deployment",
        remediation: "Deploy network detection"
      },
      %{
        id: "13.6",
        cis_control: "CIS 13",
        title: "Collect network traffic flow logs",
        ig: "IG2",
        severity: "Medium",
        status: :partial,
        evidence: "Network flow logs",
        remediation: "Enable network flow collection"
      },

      # CIS Control 17: Incident Response Management
      %{
        id: "17.1",
        cis_control: "CIS 17",
        title: "Designate personnel to manage incident handling",
        ig: "IG1",
        severity: "High",
        status: :partial,
        evidence: "IR team assignment",
        remediation: "Assign incident handlers"
      },
      %{
        id: "17.2",
        cis_control: "CIS 17",
        title: "Establish incident handling process",
        ig: "IG1",
        severity: "High",
        status: ComplianceBase.check_incident_response(),
        evidence: "IR procedures",
        remediation: "Document IR procedures"
      },
      %{
        id: "17.4",
        cis_control: "CIS 17",
        title: "Establish and maintain incident response process",
        ig: "IG2",
        severity: "High",
        status: ComplianceBase.check_incident_response(),
        evidence: "IR process",
        remediation: "Implement IR process"
      },
      %{
        id: "17.6",
        cis_control: "CIS 17",
        title: "Define incident response mechanisms",
        ig: "IG2",
        severity: "Medium",
        status: :partial,
        evidence: "Response mechanisms",
        remediation: "Define response playbooks"
      }
    ]

    # Filter by implementation group
    filter_by_ig(base_controls, ig)
  end

  defp filter_by_ig(controls, "IG1") do
    Enum.filter(controls, & &1.ig == "IG1")
  end
  defp filter_by_ig(controls, "IG2") do
    Enum.filter(controls, & &1.ig in ["IG1", "IG2"])
  end
  defp filter_by_ig(controls, "IG3") do
    controls  # All controls
  end
  defp filter_by_ig(controls, _), do: controls

  defp check_asset_inventory do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.total_agents > 0, do: :pass, else: :fail
  end

  defp check_signature_updates do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.sigma_rules + metrics.yara_rules > 0, do: :pass, else: :fail
  end

  defp check_behavioral_detection do
    metrics = ComplianceBase.get_security_metrics()
    if metrics.sigma_rules >= 50, do: :pass, else: :partial
  end

  defp control_score(controls_by_cis, cis_control) do
    controls = Map.get(controls_by_cis, cis_control, [])
    if length(controls) > 0 do
      ComplianceBase.calculate_compliance_score(controls)
    else
      0
    end
  end

  defp build_summary(date_from, date_to, score, ig, total) do
    maturity = cond do
      score >= 80 -> "mature"
      score >= 60 -> "developing"
      true -> "initial"
    end

    "CIS Controls v8 compliance assessment (#{ig}) for #{date_from} to #{date_to}. " <>
    "Overall compliance score: #{score}% (#{maturity}) across #{total} safeguards. " <>
    "Focus on essential hygiene controls for strong security posture."
  end

  defp build_control_sections(controls_by_cis, include_evidence) do
    [
      {"CIS 1", "CIS Control 1: Asset Inventory"},
      {"CIS 2", "CIS Control 2: Software Inventory"},
      {"CIS 3", "CIS Control 3: Data Protection"},
      {"CIS 4", "CIS Control 4: Secure Configuration"},
      {"CIS 7", "CIS Control 7: Vulnerability Management"},
      {"CIS 8", "CIS Control 8: Audit Log Management"},
      {"CIS 10", "CIS Control 10: Malware Defenses"},
      {"CIS 13", "CIS Control 13: Network Monitoring"},
      {"CIS 17", "CIS Control 17: Incident Response"}
    ]
    |> Enum.map(fn {key, title} ->
      controls = Map.get(controls_by_cis, key, [])
      rows = Enum.map(controls, fn c ->
        base = [c.id, c.title, c.ig, format_status(c.status), c.severity]
        if include_evidence, do: base ++ [c.evidence], else: base
      end)

      headers = if include_evidence do
        ["Safeguard", "Title", "IG", "Status", "Severity", "Evidence"]
      else
        ["Safeguard", "Title", "IG", "Status", "Severity"]
      end

      %{
        "title" => title,
        "type" => "table",
        "content" => %{
          "headers" => headers,
          "rows" => if(length(rows) > 0, do: rows, else: [["No safeguards", "", "", "", ""]])
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
      ["All safeguards compliant."]
    else
      non_compliant
      |> Enum.sort_by(& if(&1.severity == "Critical", do: 1, else: 2))
      |> Enum.take(10)
      |> Enum.map(& "#{&1.id}: #{&1.remediation}")
    end
  end
end
