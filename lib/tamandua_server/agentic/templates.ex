defmodule TamanduaServer.Agentic.Templates do
  @moduledoc """
  Agent Template Library

  Pre-built agent templates that customers can deploy immediately. Each template
  is a fully-specified AgentDefinition with appropriate triggers, reasoning chains,
  actions, and guardrails.

  ## Available Templates

  - `ransomware_responder` - Detect ransomware -> snapshot -> isolate -> kill -> rollback -> report
  - `phishing_investigator` - Email alert -> analyze links -> check reputation -> scan -> verdict -> quarantine
  - `insider_threat_hunter` - DLP alert -> user timeline -> access patterns -> risk score -> escalate
  - `vulnerability_prioritizer` - New CVE -> check exposure -> correlate TI -> prioritize -> assign patch
  - `lateral_movement_tracker` - Remote login -> map path -> check creds -> blast radius -> contain
  - `compliance_auditor` - Scheduled -> collect evidence -> evaluate controls -> generate report -> notify

  ## Usage

      # List all templates
      Templates.list_templates()

      # Get a specific template
      Templates.get_template(:ransomware_responder)

      # Deploy a template to an org
      Templates.deploy_template(:ransomware_responder, org_id)
  """

  require Logger

  alias TamanduaServer.Agentic.AgentBuilder
  alias TamanduaServer.Agentic.AgentBuilder.{AgentDefinition, Trigger, ReasoningStep, Guardrails}

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  List all available agent templates with their metadata.
  """
  @spec list_templates() :: [map()]
  def list_templates do
    [
      template_metadata(:ransomware_responder),
      template_metadata(:phishing_investigator),
      template_metadata(:insider_threat_hunter),
      template_metadata(:vulnerability_prioritizer),
      template_metadata(:lateral_movement_tracker),
      template_metadata(:compliance_auditor)
    ]
  end

  @doc """
  Get a specific template definition.
  """
  @spec get_template(atom()) :: {:ok, map()} | {:error, :not_found}
  def get_template(template_name) do
    case build_template(template_name) do
      nil -> {:error, :not_found}
      template -> {:ok, template}
    end
  end

  @doc """
  Deploy a template as a real agent for an organization.

  Creates the agent via AgentBuilder with the template's configuration.
  The agent is created in disabled state so the customer can review before enabling.
  """
  @spec deploy_template(atom(), String.t(), keyword()) ::
          {:ok, AgentDefinition.t()} | {:error, term()}
  def deploy_template(template_name, org_id, opts \\ []) do
    case build_template(template_name) do
      nil ->
        {:error, :template_not_found}

      template ->
        created_by = Keyword.get(opts, :created_by)
        enabled = Keyword.get(opts, :enabled, false)

        agent_attrs = %{
          name: template.name,
          description: template.description,
          org_id: org_id,
          created_by: created_by,
          triggers: template.triggers,
          data_sources: template.data_sources,
          reasoning_chain: template.reasoning_chain,
          allowed_actions: template.allowed_actions,
          guardrails: template.guardrails,
          schedule: template.schedule,
          enabled: enabled,
          tags: template.tags
        }

        AgentBuilder.create_agent(agent_attrs)
    end
  end

  @doc """
  Deploy all templates for a new organization (onboarding).
  """
  @spec deploy_all_templates(String.t(), keyword()) :: [{atom(), {:ok, AgentDefinition.t()} | {:error, term()}}]
  def deploy_all_templates(org_id, opts \\ []) do
    templates = [:ransomware_responder, :phishing_investigator, :insider_threat_hunter,
                 :vulnerability_prioritizer, :lateral_movement_tracker, :compliance_auditor]

    Enum.map(templates, fn name ->
      {name, deploy_template(name, org_id, opts)}
    end)
  end

  # ============================================================================
  # Template Metadata
  # ============================================================================

  defp template_metadata(:ransomware_responder) do
    %{
      id: :ransomware_responder,
      name: "Ransomware Responder",
      description: "Automatically detects ransomware activity and responds with immediate containment: " <>
                   "snapshot, isolate, kill malicious processes, and generate incident report.",
      category: :incident_response,
      severity_levels: [:critical, :high],
      mitre_tactics: ["impact", "execution"],
      estimated_response_time: "< 30 seconds",
      actions: [:collect_evidence, :isolate_host, :kill_process, :quarantine_file, :notify, :generate_report],
      risk_level: :high,
      requires_customization: false
    }
  end

  defp template_metadata(:phishing_investigator) do
    %{
      id: :phishing_investigator,
      name: "Phishing Investigator",
      description: "Investigates phishing alerts: analyzes URLs and attachments, checks reputation, " <>
                   "scans for malware, renders verdict, and quarantines if malicious.",
      category: :investigation,
      severity_levels: [:medium, :high, :critical],
      mitre_tactics: ["initial-access"],
      estimated_response_time: "< 2 minutes",
      actions: [:enrich_context, :threat_intel_lookup, :enrich_hash, :quarantine_file, :notify],
      risk_level: :medium,
      requires_customization: false
    }
  end

  defp template_metadata(:insider_threat_hunter) do
    %{
      id: :insider_threat_hunter,
      name: "Insider Threat Hunter",
      description: "Monitors for insider threat indicators: DLP alerts trigger user activity " <>
                   "timeline analysis, access pattern review, risk scoring, and escalation.",
      category: :threat_hunting,
      severity_levels: [:medium, :high],
      mitre_tactics: ["exfiltration", "collection"],
      estimated_response_time: "< 5 minutes",
      actions: [:enrich_context, :threat_intel_lookup, :notify, :generate_report],
      risk_level: :medium,
      requires_customization: true
    }
  end

  defp template_metadata(:vulnerability_prioritizer) do
    %{
      id: :vulnerability_prioritizer,
      name: "Vulnerability Prioritizer",
      description: "When new CVEs are published, checks asset exposure, correlates with threat " <>
                   "intelligence, prioritizes by risk, and assigns patch tickets.",
      category: :vulnerability_management,
      severity_levels: [:low, :medium, :high, :critical],
      mitre_tactics: [],
      estimated_response_time: "< 10 minutes",
      actions: [:enrich_context, :threat_intel_lookup, :notify, :generate_report],
      risk_level: :low,
      requires_customization: true
    }
  end

  defp template_metadata(:lateral_movement_tracker) do
    %{
      id: :lateral_movement_tracker,
      name: "Lateral Movement Tracker",
      description: "Detects remote login attempts and lateral movement: maps attack path, " <>
                   "checks credential usage, assesses blast radius, and contains the threat.",
      category: :incident_response,
      severity_levels: [:high, :critical],
      mitre_tactics: ["lateral-movement", "credential-access"],
      estimated_response_time: "< 1 minute",
      actions: [:enrich_context, :threat_intel_lookup, :isolate_host, :kill_process, :notify, :generate_report],
      risk_level: :high,
      requires_customization: false
    }
  end

  defp template_metadata(:compliance_auditor) do
    %{
      id: :compliance_auditor,
      name: "Compliance Auditor",
      description: "Scheduled compliance auditor: collects control evidence, evaluates against " <>
                   "framework requirements, generates compliance report, and notifies stakeholders.",
      category: :compliance,
      severity_levels: [:low, :medium, :high, :critical],
      mitre_tactics: [],
      estimated_response_time: "< 30 minutes",
      actions: [:enrich_context, :notify, :generate_report],
      risk_level: :low,
      requires_customization: true
    }
  end

  # ============================================================================
  # Template Definitions
  # ============================================================================

  defp build_template(:ransomware_responder) do
    %{
      name: "Ransomware Responder",
      description: "Automatically detects ransomware activity and responds with immediate " <>
                   "containment: memory snapshot, host isolation, process kill, file quarantine, " <>
                   "and incident report generation.",
      triggers: [
        %Trigger{type: :alert, conditions: %{detection_type: "ransomware", severity: :critical}},
        %Trigger{type: :alert, conditions: %{detection_type: "ransomware", severity: :high}},
        %Trigger{type: :alert, conditions: %{mitre_tactic: "impact", tags: ["encryption"]}}
      ],
      data_sources: [:alerts, :telemetry, :processes, :files, :network],
      reasoning_chain: [
        %ReasoningStep{
          id: "assess",
          action: :enrich_context,
          params: %{type: :ransomware_assessment},
          timeout_ms: 15_000,
          on_success: "snapshot"
        },
        %ReasoningStep{
          id: "snapshot",
          action: :collect_evidence,
          params: %{type: :memory_dump, include_process_list: true},
          timeout_ms: 120_000,
          on_success: "isolate"
        },
        %ReasoningStep{
          id: "isolate",
          action: :isolate_host,
          params: %{},
          timeout_ms: 30_000,
          on_success: "kill"
        },
        %ReasoningStep{
          id: "kill",
          action: :kill_process,
          params: %{force: true},
          timeout_ms: 15_000,
          on_success: "quarantine"
        },
        %ReasoningStep{
          id: "quarantine",
          action: :quarantine_file,
          params: %{},
          timeout_ms: 30_000,
          on_success: "report"
        },
        %ReasoningStep{
          id: "report",
          action: :generate_report,
          params: %{type: :ransomware_incident},
          timeout_ms: 60_000,
          on_success: "notify"
        },
        %ReasoningStep{
          id: "notify",
          action: :notify,
          params: %{channel: "#security-ops", severity: :critical},
          timeout_ms: 10_000
        }
      ],
      allowed_actions: [
        :enrich_context, :collect_evidence, :isolate_host, :kill_process,
        :quarantine_file, :generate_report, :notify
      ],
      guardrails: %Guardrails{
        max_actions_per_hour: 20,
        require_approval_for: [],  # No approval needed -- speed is critical for ransomware
        max_concurrent_executions: 10,
        cooldown_seconds: 0,
        allowed_severity_levels: [:high, :critical],
        max_blast_radius: :single_host
      },
      schedule: nil,
      tags: ["ransomware", "critical", "automated", "incident-response"]
    }
  end

  defp build_template(:phishing_investigator) do
    %{
      name: "Phishing Investigator",
      description: "Investigates phishing alerts by analyzing email content, URLs, and " <>
                   "attachments. Checks reputation, scans for malware, renders a verdict, " <>
                   "and quarantines malicious messages.",
      triggers: [
        %Trigger{type: :alert, conditions: %{detection_type: "phishing"}},
        %Trigger{type: :alert, conditions: %{detection_type: "suspicious_email"}},
        %Trigger{type: :alert, conditions: %{mitre_tactic: "initial-access", tags: ["email"]}}
      ],
      data_sources: [:alerts, :email_logs, :threat_intel, :files],
      reasoning_chain: [
        %ReasoningStep{
          id: "analyze_email",
          action: :enrich_context,
          params: %{type: :email_analysis, check_headers: true, check_body: true},
          timeout_ms: 30_000,
          on_success: "check_urls"
        },
        %ReasoningStep{
          id: "check_urls",
          action: :threat_intel_lookup,
          params: %{indicator_type: :url},
          timeout_ms: 30_000,
          on_success: "check_attachments"
        },
        %ReasoningStep{
          id: "check_attachments",
          action: :enrich_hash,
          params: %{providers: [:virustotal, :hybrid_analysis]},
          timeout_ms: 30_000,
          on_success: "verdict",
          on_failure: "verdict"
        },
        %ReasoningStep{
          id: "verdict",
          action: :enrich_context,
          params: %{type: :phishing_verdict},
          timeout_ms: 15_000,
          on_success: "quarantine"
        },
        %ReasoningStep{
          id: "quarantine",
          action: :quarantine_file,
          params: %{},
          condition: %{field: "verdict", operator: "equals", value: "malicious"},
          timeout_ms: 30_000,
          on_success: "notify"
        },
        %ReasoningStep{
          id: "notify",
          action: :notify,
          params: %{channel: "#security-ops"},
          timeout_ms: 10_000
        }
      ],
      allowed_actions: [
        :enrich_context, :threat_intel_lookup, :enrich_hash,
        :quarantine_file, :notify, :generate_report
      ],
      guardrails: %Guardrails{
        max_actions_per_hour: 100,
        require_approval_for: [],
        max_concurrent_executions: 20,
        cooldown_seconds: 0,
        allowed_severity_levels: [:low, :medium, :high, :critical],
        max_blast_radius: :single_host
      },
      schedule: nil,
      tags: ["phishing", "email", "investigation"]
    }
  end

  defp build_template(:insider_threat_hunter) do
    %{
      name: "Insider Threat Hunter",
      description: "Monitors for insider threat indicators triggered by DLP alerts. " <>
                   "Builds user activity timeline, analyzes access patterns, calculates " <>
                   "risk score, and escalates to SOC when threshold exceeded.",
      triggers: [
        %Trigger{type: :alert, conditions: %{detection_type: "dlp_violation"}},
        %Trigger{type: :alert, conditions: %{detection_type: "insider_threat"}},
        %Trigger{type: :alert, conditions: %{mitre_tactic: "exfiltration"}},
        %Trigger{type: :alert, conditions: %{mitre_tactic: "collection"}}
      ],
      data_sources: [:alerts, :telemetry, :user_activity, :identity_logs, :files, :network],
      reasoning_chain: [
        %ReasoningStep{
          id: "build_timeline",
          action: :enrich_context,
          params: %{type: :user_activity_timeline, lookback_hours: 72},
          timeout_ms: 60_000,
          on_success: "analyze_access"
        },
        %ReasoningStep{
          id: "analyze_access",
          action: :enrich_context,
          params: %{type: :access_pattern_analysis},
          timeout_ms: 30_000,
          on_success: "score_risk"
        },
        %ReasoningStep{
          id: "score_risk",
          action: :enrich_context,
          params: %{type: :insider_risk_scoring},
          timeout_ms: 15_000,
          on_success: "decide"
        },
        %ReasoningStep{
          id: "decide",
          action: :enrich_context,
          params: %{type: :escalation_decision},
          timeout_ms: 10_000,
          on_success: "report"
        },
        %ReasoningStep{
          id: "report",
          action: :generate_report,
          params: %{type: :insider_threat_assessment},
          timeout_ms: 60_000,
          on_success: "notify"
        },
        %ReasoningStep{
          id: "notify",
          action: :notify,
          params: %{channel: "#insider-threats", priority: :high},
          timeout_ms: 10_000
        }
      ],
      allowed_actions: [:enrich_context, :threat_intel_lookup, :notify, :generate_report],
      guardrails: %Guardrails{
        max_actions_per_hour: 30,
        require_approval_for: [],
        max_concurrent_executions: 5,
        cooldown_seconds: 60,
        allowed_severity_levels: [:medium, :high, :critical],
        max_blast_radius: :single_host
      },
      schedule: nil,
      tags: ["insider-threat", "dlp", "user-behavior"]
    }
  end

  defp build_template(:vulnerability_prioritizer) do
    %{
      name: "Vulnerability Prioritizer",
      description: "When new CVEs are detected, checks asset exposure, correlates with active " <>
                   "threat intelligence, calculates risk priority, and creates patch tickets.",
      triggers: [
        %Trigger{type: :alert, conditions: %{detection_type: "new_vulnerability"}},
        %Trigger{type: :alert, conditions: %{detection_type: "cve_detected"}},
        %Trigger{type: :schedule, conditions: %{}}
      ],
      data_sources: [:alerts, :vulnerabilities, :threat_intel, :cloud_logs],
      reasoning_chain: [
        %ReasoningStep{
          id: "check_exposure",
          action: :enrich_context,
          params: %{type: :asset_exposure_check},
          timeout_ms: 60_000,
          on_success: "correlate_ti"
        },
        %ReasoningStep{
          id: "correlate_ti",
          action: :threat_intel_lookup,
          params: %{indicator_type: :cve},
          timeout_ms: 30_000,
          on_success: "prioritize"
        },
        %ReasoningStep{
          id: "prioritize",
          action: :enrich_context,
          params: %{type: :vulnerability_prioritization, factors: [:epss, :kev, :asset_criticality]},
          timeout_ms: 15_000,
          on_success: "assign"
        },
        %ReasoningStep{
          id: "assign",
          action: :notify,
          params: %{type: :patch_ticket, channel: "#vulnerability-mgmt"},
          timeout_ms: 30_000,
          on_success: "report"
        },
        %ReasoningStep{
          id: "report",
          action: :generate_report,
          params: %{type: :vulnerability_assessment},
          timeout_ms: 60_000
        }
      ],
      allowed_actions: [:enrich_context, :threat_intel_lookup, :notify, :generate_report],
      guardrails: %Guardrails{
        max_actions_per_hour: 200,
        require_approval_for: [],
        max_concurrent_executions: 10,
        cooldown_seconds: 0,
        allowed_severity_levels: [:low, :medium, :high, :critical],
        max_blast_radius: :org_wide
      },
      schedule: "0 6 * * *",  # Daily at 6 AM
      tags: ["vulnerability", "cve", "patch-management"]
    }
  end

  defp build_template(:lateral_movement_tracker) do
    %{
      name: "Lateral Movement Tracker",
      description: "Detects lateral movement activity: maps the attack path, checks credential " <>
                   "usage across hosts, assesses blast radius, and contains the threat.",
      triggers: [
        %Trigger{type: :alert, conditions: %{mitre_tactic: "lateral-movement"}},
        %Trigger{type: :alert, conditions: %{detection_type: "remote_execution"}},
        %Trigger{type: :alert, conditions: %{detection_type: "suspicious_login", severity: :high}}
      ],
      data_sources: [:alerts, :telemetry, :identity_logs, :network, :processes],
      reasoning_chain: [
        %ReasoningStep{
          id: "map_path",
          action: :enrich_context,
          params: %{type: :lateral_movement_path_analysis},
          timeout_ms: 30_000,
          on_success: "check_creds"
        },
        %ReasoningStep{
          id: "check_creds",
          action: :enrich_context,
          params: %{type: :credential_usage_analysis},
          timeout_ms: 30_000,
          on_success: "assess_blast"
        },
        %ReasoningStep{
          id: "assess_blast",
          action: :enrich_context,
          params: %{type: :blast_radius_assessment},
          timeout_ms: 15_000,
          on_success: "contain"
        },
        %ReasoningStep{
          id: "contain",
          action: :isolate_host,
          params: %{},
          timeout_ms: 30_000,
          on_success: "kill_remote"
        },
        %ReasoningStep{
          id: "kill_remote",
          action: :kill_process,
          params: %{force: true},
          timeout_ms: 15_000,
          on_success: "report"
        },
        %ReasoningStep{
          id: "report",
          action: :generate_report,
          params: %{type: :lateral_movement_incident},
          timeout_ms: 60_000,
          on_success: "notify"
        },
        %ReasoningStep{
          id: "notify",
          action: :notify,
          params: %{channel: "#security-ops", severity: :high},
          timeout_ms: 10_000
        }
      ],
      allowed_actions: [
        :enrich_context, :threat_intel_lookup, :isolate_host, :kill_process,
        :notify, :generate_report
      ],
      guardrails: %Guardrails{
        max_actions_per_hour: 30,
        require_approval_for: [:isolate_host],
        max_concurrent_executions: 5,
        cooldown_seconds: 30,
        allowed_severity_levels: [:high, :critical],
        max_blast_radius: :subnet
      },
      schedule: nil,
      tags: ["lateral-movement", "incident-response", "containment"]
    }
  end

  defp build_template(:compliance_auditor) do
    %{
      name: "Compliance Auditor",
      description: "Scheduled compliance auditor: collects control evidence from endpoints, " <>
                   "evaluates against framework requirements (SOC2, HIPAA, PCI-DSS), generates " <>
                   "compliance reports, and notifies stakeholders.",
      triggers: [
        %Trigger{type: :schedule, conditions: %{cron: "0 0 * * 1"}},
        %Trigger{type: :manual, conditions: %{}}
      ],
      data_sources: [:alerts, :telemetry, :cloud_logs, :vulnerabilities, :identity_logs],
      reasoning_chain: [
        %ReasoningStep{
          id: "collect_evidence",
          action: :enrich_context,
          params: %{type: :compliance_evidence_collection, frameworks: [:soc2, :hipaa, :pci_dss]},
          timeout_ms: 300_000,
          on_success: "evaluate"
        },
        %ReasoningStep{
          id: "evaluate",
          action: :enrich_context,
          params: %{type: :control_evaluation},
          timeout_ms: 120_000,
          on_success: "report"
        },
        %ReasoningStep{
          id: "report",
          action: :generate_report,
          params: %{type: :compliance_report, include_gaps: true, include_remediation: true},
          timeout_ms: 120_000,
          on_success: "notify"
        },
        %ReasoningStep{
          id: "notify",
          action: :notify,
          params: %{channel: "#compliance", include_summary: true},
          timeout_ms: 10_000
        }
      ],
      allowed_actions: [:enrich_context, :notify, :generate_report],
      guardrails: %Guardrails{
        max_actions_per_hour: 10,
        require_approval_for: [],
        max_concurrent_executions: 1,
        cooldown_seconds: 3600,
        allowed_severity_levels: [:low, :medium, :high, :critical],
        max_blast_radius: :org_wide
      },
      schedule: "0 0 * * 1",  # Weekly on Monday
      tags: ["compliance", "audit", "scheduled", "soc2", "hipaa"]
    }
  end

  defp build_template(_), do: nil
end
