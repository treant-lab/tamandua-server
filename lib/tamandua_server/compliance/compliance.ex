defmodule TamanduaServer.Compliance do
  @moduledoc """
  Compliance Reporting Framework

  Provides comprehensive compliance reporting, control tracking, and evidence
  collection for major regulatory frameworks:

  - PCI-DSS 4.0
  - HIPAA Security Rule
  - SOC 2 Type II
  - NIST 800-53 Rev. 5
  - ISO 27001:2022
  - CIS Benchmarks
  - GDPR (Article 32)

  Features:
  - Real-time compliance posture monitoring
  - Automated control assessment
  - Evidence collection and preservation
  - Audit report generation
  - Gap analysis and remediation tracking
  - Continuous compliance validation
  """

  use GenServer
  require Logger

  alias TamanduaServer.Compliance.{Control, Assessment, Evidence, Report}

  @compliance_frameworks [
    :pci_dss,
    :hipaa,
    :soc2,
    :nist_800_53,
    :iso_27001,
    :cis_benchmark,
    :gdpr
  ]

  # Assessment intervals
  @daily_assessment_interval :timer.hours(24)
  @realtime_check_interval :timer.minutes(5)

  defmodule Control do
    @moduledoc "Compliance control definition"
    defstruct [
      :id,
      :framework,
      :control_id,
      :title,
      :description,
      :category,
      :severity,
      :automated,
      :evidence_types,
      :validation_query,
      :remediation_steps,
      status: :unknown,
      last_assessed: nil,
      evidence_count: 0,
      findings: []
    ]
  end

  defmodule Assessment do
    @moduledoc "Compliance assessment result"
    defstruct [
      :id,
      :framework,
      :control_id,
      :status,
      :score,
      :findings,
      :evidence,
      :assessed_at,
      :assessed_by,
      :expires_at
    ]
  end

  defmodule Evidence do
    @moduledoc "Compliance evidence record"
    defstruct [
      :id,
      :control_id,
      :type,
      :title,
      :description,
      :source,
      :data,
      :hash,
      :collected_at,
      :retention_until
    ]
  end

  defmodule Report do
    @moduledoc "Compliance report"
    defstruct [
      :id,
      :framework,
      :report_type,
      :period_start,
      :period_end,
      :generated_at,
      :generated_by,
      :overall_score,
      :control_summary,
      :findings,
      :recommendations,
      :evidence_summary,
      :export_formats
    ]
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    # Create ETS tables for compliance data
    :ets.new(:compliance_controls, [:set, :public, :named_table])
    :ets.new(:compliance_assessments, [:set, :public, :named_table])
    :ets.new(:compliance_evidence, [:set, :public, :named_table])

    # Load control definitions
    load_control_definitions()

    # Schedule periodic assessments
    Process.send_after(self(), :daily_assessment, @daily_assessment_interval)
    Process.send_after(self(), :realtime_check, @realtime_check_interval)

    state = %{
      last_assessment: nil,
      assessment_in_progress: false,
      framework_scores: %{}
    }

    Logger.info("Compliance Reporting Framework started")
    {:ok, state}
  end

  @impl true
  def handle_call({:get_posture, framework}, _from, state) do
    posture = calculate_compliance_posture(framework)
    {:reply, {:ok, posture}, state}
  end

  @impl true
  def handle_call({:assess_control, control_id, options}, _from, state) do
    result = perform_control_assessment(control_id, options)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:generate_report, framework, options}, _from, state) do
    result = generate_compliance_report(framework, options)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:collect_evidence, control_id, evidence_type}, _from, state) do
    result = collect_control_evidence(control_id, evidence_type)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:list_frameworks, _from, state) do
    frameworks = Enum.map(@compliance_frameworks, &get_framework_info/1)
    {:reply, {:ok, frameworks}, state}
  end

  @impl true
  def handle_info(:daily_assessment, state) do
    Logger.info("Running daily compliance assessment")

    new_state =
      if state.assessment_in_progress do
        state
      else
        spawn(fn -> run_full_assessment() end)
        %{state | assessment_in_progress: true}
      end

    Process.send_after(self(), :daily_assessment, @daily_assessment_interval)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:realtime_check, state) do
    # Quick checks for critical controls
    check_critical_controls()
    Process.send_after(self(), :realtime_check, @realtime_check_interval)
    {:noreply, state}
  end

  @impl true
  def handle_info({:assessment_complete, results}, state) do
    new_state = %{
      state |
      assessment_in_progress: false,
      last_assessment: DateTime.utc_now(),
      framework_scores: results
    }
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Public API
  # ============================================================================

  @doc "Get compliance posture for a framework"
  def get_posture(framework) do
    GenServer.call(__MODULE__, {:get_posture, framework})
  end

  @doc "Get overall compliance posture across all frameworks"
  def get_overall_posture do
    postures = Enum.map(@compliance_frameworks, fn fw ->
      {:ok, posture} = get_posture(fw)
      {fw, posture}
    end)

    overall_score = postures
    |> Enum.map(fn {_, p} -> p.score end)
    |> Enum.sum()
    |> Kernel./(length(postures))

    %{
      overall_score: overall_score,
      frameworks: Map.new(postures),
      last_assessed: DateTime.utc_now(),
      trend: calculate_trend()
    }
  end

  @doc "Assess a specific control"
  def assess_control(control_id, options \\ %{}) do
    GenServer.call(__MODULE__, {:assess_control, control_id, options})
  end

  @doc "Generate a compliance report"
  def generate_report(framework, options \\ %{}) do
    GenServer.call(__MODULE__, {:generate_report, framework, options}, 60_000)
  end

  @doc "Collect evidence for a control"
  def collect_evidence(control_id, evidence_type) do
    GenServer.call(__MODULE__, {:collect_evidence, control_id, evidence_type})
  end

  @doc "List all supported frameworks"
  def list_frameworks do
    GenServer.call(__MODULE__, :list_frameworks)
  end

  @doc "Get controls for a framework"
  def get_controls(framework) do
    :ets.match_object(:compliance_controls, {:_, %{framework: framework}})
    |> Enum.map(fn {_, control} -> control end)
  end

  @doc "Get control details"
  def get_control(control_id) do
    case :ets.lookup(:compliance_controls, control_id) do
      [{_, control}] -> {:ok, control}
      [] -> {:error, :not_found}
    end
  end

  @doc "Get assessment history for a control"
  def get_assessment_history(control_id, limit \\ 10) do
    :ets.match_object(:compliance_assessments, {:_, %{control_id: control_id}})
    |> Enum.map(fn {_, assessment} -> assessment end)
    |> Enum.sort_by(& &1.assessed_at, {:desc, DateTime})
    |> Enum.take(limit)
  end

  @doc "Get evidence for a control"
  def get_evidence(control_id) do
    :ets.match_object(:compliance_evidence, {:_, %{control_id: control_id}})
    |> Enum.map(fn {_, evidence} -> evidence end)
    |> Enum.sort_by(& &1.collected_at, {:desc, DateTime})
  end

  @doc "Export compliance data for audit"
  def export_for_audit(framework, period_start, period_end, format \\ :pdf) do
    controls = get_controls(framework)

    assessments = Enum.flat_map(controls, fn c ->
      get_assessment_history(c.id, 100)
      |> Enum.filter(fn a ->
        DateTime.compare(a.assessed_at, period_start) in [:gt, :eq] and
        DateTime.compare(a.assessed_at, period_end) in [:lt, :eq]
      end)
    end)

    evidence = Enum.flat_map(controls, fn c ->
      get_evidence(c.id)
      |> Enum.filter(fn e ->
        DateTime.compare(e.collected_at, period_start) in [:gt, :eq] and
        DateTime.compare(e.collected_at, period_end) in [:lt, :eq]
      end)
    end)

    audit_package = %{
      framework: framework,
      period: %{start: period_start, end: period_end},
      controls: controls,
      assessments: assessments,
      evidence: evidence,
      generated_at: DateTime.utc_now()
    }

    case format do
      :json -> {:ok, Jason.encode!(audit_package)}
      :pdf -> generate_pdf_report(audit_package)
      :csv -> generate_csv_export(audit_package)
      _ -> {:error, :unsupported_format}
    end
  end

  # ============================================================================
  # Control Definitions
  # ============================================================================

  defp load_control_definitions do
    # PCI-DSS 4.0 Controls
    pci_dss_controls() |> Enum.each(&store_control/1)

    # HIPAA Controls
    hipaa_controls() |> Enum.each(&store_control/1)

    # SOC 2 Controls
    soc2_controls() |> Enum.each(&store_control/1)

    # NIST 800-53 Controls
    nist_controls() |> Enum.each(&store_control/1)

    # CIS Benchmark Controls
    cis_controls() |> Enum.each(&store_control/1)

    Logger.info("Loaded compliance control definitions")
  end

  defp store_control(control) do
    :ets.insert(:compliance_controls, {control.id, control})
  end

  defp pci_dss_controls do
    [
      %Control{
        id: "pci-1.1",
        framework: :pci_dss,
        control_id: "1.1",
        title: "Network Security Controls",
        description: "Install and maintain network security controls",
        category: :network,
        severity: :critical,
        automated: true,
        evidence_types: [:firewall_rules, :network_diagram, :config_review],
        validation_query: "network_controls_configured",
        remediation_steps: ["Configure network firewall", "Implement network segmentation"]
      },
      %Control{
        id: "pci-3.4",
        framework: :pci_dss,
        control_id: "3.4",
        title: "Protect Stored Cardholder Data",
        description: "Render PAN unreadable using cryptography",
        category: :data_protection,
        severity: :critical,
        automated: true,
        evidence_types: [:encryption_config, :key_management, :data_scan],
        validation_query: "data_encryption_enabled",
        remediation_steps: ["Enable data encryption", "Implement key rotation"]
      },
      %Control{
        id: "pci-5.2",
        framework: :pci_dss,
        control_id: "5.2",
        title: "Anti-Malware Solutions",
        description: "Deploy anti-malware solutions on all systems",
        category: :endpoint,
        severity: :high,
        automated: true,
        evidence_types: [:av_status, :scan_reports, :signature_updates],
        validation_query: "antimalware_deployed",
        remediation_steps: ["Install anti-malware", "Enable real-time protection"]
      },
      %Control{
        id: "pci-6.4",
        framework: :pci_dss,
        control_id: "6.4",
        title: "Change Control Processes",
        description: "Follow change control processes for all system changes",
        category: :change_management,
        severity: :high,
        automated: false,
        evidence_types: [:change_tickets, :approval_records, :test_results],
        validation_query: nil,
        remediation_steps: ["Implement change management", "Document all changes"]
      },
      %Control{
        id: "pci-10.2",
        framework: :pci_dss,
        control_id: "10.2",
        title: "Audit Logs",
        description: "Implement automated audit trails for all system components",
        category: :logging,
        severity: :critical,
        automated: true,
        evidence_types: [:log_config, :log_samples, :log_retention],
        validation_query: "audit_logging_enabled",
        remediation_steps: ["Enable audit logging", "Configure log retention"]
      },
      %Control{
        id: "pci-11.5",
        framework: :pci_dss,
        control_id: "11.5",
        title: "File Integrity Monitoring",
        description: "Deploy file integrity monitoring on critical system files",
        category: :detection,
        severity: :high,
        automated: true,
        evidence_types: [:fim_config, :fim_alerts, :baseline_reports],
        validation_query: "fim_deployed",
        remediation_steps: ["Deploy FIM solution", "Configure critical file monitoring"]
      }
    ]
  end

  defp hipaa_controls do
    [
      %Control{
        id: "hipaa-164.308.a.1",
        framework: :hipaa,
        control_id: "164.308(a)(1)",
        title: "Security Management Process",
        description: "Implement policies and procedures to prevent, detect, contain, and correct security violations",
        category: :administrative,
        severity: :critical,
        automated: false,
        evidence_types: [:policy_documents, :risk_assessment, :incident_response_plan],
        validation_query: nil,
        remediation_steps: ["Develop security policies", "Conduct risk assessments"]
      },
      %Control{
        id: "hipaa-164.308.a.3",
        framework: :hipaa,
        control_id: "164.308(a)(3)",
        title: "Workforce Security",
        description: "Implement policies and procedures for authorizing access to ePHI",
        category: :access_control,
        severity: :high,
        automated: true,
        evidence_types: [:access_policies, :user_access_reports, :termination_records],
        validation_query: "access_controls_configured",
        remediation_steps: ["Implement access policies", "Regular access reviews"]
      },
      %Control{
        id: "hipaa-164.312.a.1",
        framework: :hipaa,
        control_id: "164.312(a)(1)",
        title: "Access Control",
        description: "Implement technical policies to allow only authorized access to ePHI",
        category: :access_control,
        severity: :critical,
        automated: true,
        evidence_types: [:access_config, :authentication_logs, :rbac_matrix],
        validation_query: "ephi_access_controlled",
        remediation_steps: ["Configure role-based access", "Enable MFA"]
      },
      %Control{
        id: "hipaa-164.312.b",
        framework: :hipaa,
        control_id: "164.312(b)",
        title: "Audit Controls",
        description: "Implement hardware, software, and procedures to record and examine activity",
        category: :logging,
        severity: :high,
        automated: true,
        evidence_types: [:audit_config, :audit_logs, :review_reports],
        validation_query: "hipaa_audit_enabled",
        remediation_steps: ["Enable comprehensive audit logging", "Implement log review process"]
      },
      %Control{
        id: "hipaa-164.312.c.1",
        framework: :hipaa,
        control_id: "164.312(c)(1)",
        title: "Integrity Controls",
        description: "Implement mechanisms to authenticate ePHI",
        category: :data_protection,
        severity: :high,
        automated: true,
        evidence_types: [:integrity_config, :checksum_reports, :fim_alerts],
        validation_query: "data_integrity_enabled",
        remediation_steps: ["Enable data integrity checks", "Deploy integrity monitoring"]
      },
      %Control{
        id: "hipaa-164.312.e.1",
        framework: :hipaa,
        control_id: "164.312(e)(1)",
        title: "Transmission Security",
        description: "Implement technical security measures to guard against unauthorized access during transmission",
        category: :network,
        severity: :critical,
        automated: true,
        evidence_types: [:tls_config, :encryption_status, :cert_inventory],
        validation_query: "transmission_encrypted",
        remediation_steps: ["Enable TLS for all transmissions", "Update cipher suites"]
      }
    ]
  end

  defp soc2_controls do
    [
      %Control{
        id: "soc2-cc6.1",
        framework: :soc2,
        control_id: "CC6.1",
        title: "Logical Access Security",
        description: "Logical access security software, infrastructure, and architectures are in place",
        category: :access_control,
        severity: :critical,
        automated: true,
        evidence_types: [:access_config, :authentication_logs, :identity_provider_config],
        validation_query: "logical_access_configured",
        remediation_steps: ["Implement identity management", "Configure access controls"]
      },
      %Control{
        id: "soc2-cc6.2",
        framework: :soc2,
        control_id: "CC6.2",
        title: "New User Registration",
        description: "Prior to registering new users, approval is obtained",
        category: :identity,
        severity: :high,
        automated: false,
        evidence_types: [:user_requests, :approval_records, :onboarding_docs],
        validation_query: nil,
        remediation_steps: ["Implement user provisioning workflow", "Document approval process"]
      },
      %Control{
        id: "soc2-cc7.2",
        framework: :soc2,
        control_id: "CC7.2",
        title: "System Monitoring",
        description: "System activity is monitored to detect anomalous behavior",
        category: :detection,
        severity: :high,
        automated: true,
        evidence_types: [:monitoring_config, :alert_rules, :incident_reports],
        validation_query: "monitoring_enabled",
        remediation_steps: ["Deploy monitoring solution", "Configure alerting"]
      },
      %Control{
        id: "soc2-cc8.1",
        framework: :soc2,
        control_id: "CC8.1",
        title: "Change Management",
        description: "Changes to infrastructure and software are authorized",
        category: :change_management,
        severity: :high,
        automated: false,
        evidence_types: [:change_tickets, :approval_records, :deployment_logs],
        validation_query: nil,
        remediation_steps: ["Implement change management process", "Document all changes"]
      }
    ]
  end

  defp nist_controls do
    [
      %Control{
        id: "nist-ac-2",
        framework: :nist_800_53,
        control_id: "AC-2",
        title: "Account Management",
        description: "Manage information system accounts",
        category: :access_control,
        severity: :high,
        automated: true,
        evidence_types: [:account_inventory, :access_reviews, :provisioning_logs],
        validation_query: "account_management_configured",
        remediation_steps: ["Implement account lifecycle management", "Conduct regular reviews"]
      },
      %Control{
        id: "nist-au-2",
        framework: :nist_800_53,
        control_id: "AU-2",
        title: "Audit Events",
        description: "Identify and select events for auditing",
        category: :logging,
        severity: :high,
        automated: true,
        evidence_types: [:audit_config, :event_selection, :audit_logs],
        validation_query: "audit_events_configured",
        remediation_steps: ["Define auditable events", "Configure audit logging"]
      },
      %Control{
        id: "nist-cm-6",
        framework: :nist_800_53,
        control_id: "CM-6",
        title: "Configuration Settings",
        description: "Establish and document configuration settings",
        category: :configuration,
        severity: :medium,
        automated: true,
        evidence_types: [:config_baselines, :deviation_reports, :hardening_guides],
        validation_query: "configuration_baselines_set",
        remediation_steps: ["Document configuration baselines", "Implement configuration management"]
      },
      %Control{
        id: "nist-ir-4",
        framework: :nist_800_53,
        control_id: "IR-4",
        title: "Incident Handling",
        description: "Implement incident handling capability",
        category: :incident_response,
        severity: :high,
        automated: false,
        evidence_types: [:ir_plan, :incident_reports, :lessons_learned],
        validation_query: nil,
        remediation_steps: ["Develop incident response plan", "Conduct IR exercises"]
      },
      %Control{
        id: "nist-si-4",
        framework: :nist_800_53,
        control_id: "SI-4",
        title: "System Monitoring",
        description: "Monitor the information system to detect attacks and indicators",
        category: :detection,
        severity: :high,
        automated: true,
        evidence_types: [:siem_config, :detection_rules, :alert_reports],
        validation_query: "system_monitoring_enabled",
        remediation_steps: ["Deploy SIEM/EDR", "Configure detection rules"]
      }
    ]
  end

  defp cis_controls do
    [
      %Control{
        id: "cis-1.1",
        framework: :cis_benchmark,
        control_id: "1.1",
        title: "Inventory of Authorized Devices",
        description: "Actively manage all hardware devices on the network",
        category: :asset_management,
        severity: :high,
        automated: true,
        evidence_types: [:asset_inventory, :discovery_scans, :cmdb_exports],
        validation_query: "asset_inventory_current",
        remediation_steps: ["Deploy asset discovery", "Maintain inventory database"]
      },
      %Control{
        id: "cis-2.1",
        framework: :cis_benchmark,
        control_id: "2.1",
        title: "Inventory of Authorized Software",
        description: "Actively manage all software on the network",
        category: :asset_management,
        severity: :high,
        automated: true,
        evidence_types: [:software_inventory, :approved_list, :unapproved_detections],
        validation_query: "software_inventory_current",
        remediation_steps: ["Deploy software inventory", "Define approved software list"]
      },
      %Control{
        id: "cis-4.1",
        framework: :cis_benchmark,
        control_id: "4.1",
        title: "Secure Configuration Standards",
        description: "Establish and maintain secure configuration for enterprise assets",
        category: :configuration,
        severity: :high,
        automated: true,
        evidence_types: [:config_baselines, :compliance_scans, :deviation_reports],
        validation_query: "secure_configurations_applied",
        remediation_steps: ["Define security baselines", "Implement compliance scanning"]
      },
      %Control{
        id: "cis-8.1",
        framework: :cis_benchmark,
        control_id: "8.1",
        title: "Audit Log Management",
        description: "Establish and maintain audit log management",
        category: :logging,
        severity: :high,
        automated: true,
        evidence_types: [:log_config, :log_samples, :retention_config],
        validation_query: "audit_logging_configured",
        remediation_steps: ["Configure centralized logging", "Define retention policies"]
      }
    ]
  end

  # ============================================================================
  # Assessment Functions
  # ============================================================================

  defp calculate_compliance_posture(framework) do
    controls = get_controls(framework)

    assessments = Enum.map(controls, fn control ->
      case :ets.lookup(:compliance_assessments, "latest_#{control.id}") do
        [{_, assessment}] -> {control, assessment}
        [] -> {control, nil}
      end
    end)

    total = length(controls)
    compliant = Enum.count(assessments, fn {_, a} -> a && a.status == :compliant end)
    partial = Enum.count(assessments, fn {_, a} -> a && a.status == :partial end)
    non_compliant = Enum.count(assessments, fn {_, a} -> a && a.status == :non_compliant end)
    not_assessed = Enum.count(assessments, fn {_, a} -> is_nil(a) end)

    score = (compliant * 100 + partial * 50) / max(total, 1)

    %{
      framework: framework,
      total_controls: total,
      compliant: compliant,
      partial: partial,
      non_compliant: non_compliant,
      not_assessed: not_assessed,
      score: Float.round(score, 1),
      status: determine_status(score),
      last_assessed: get_latest_assessment_time(assessments),
      controls: Enum.map(assessments, fn {c, a} ->
        %{
          id: c.id,
          title: c.title,
          status: (a && a.status) || :not_assessed,
          severity: c.severity,
          last_assessed: a && a.assessed_at
        }
      end)
    }
  end

  defp determine_status(score) when score >= 90, do: :compliant
  defp determine_status(score) when score >= 70, do: :partial
  defp determine_status(_), do: :non_compliant

  defp get_latest_assessment_time(assessments) do
    assessments
    |> Enum.filter(fn {_, a} -> a != nil end)
    |> Enum.map(fn {_, a} -> a.assessed_at end)
    |> Enum.sort({:desc, DateTime})
    |> List.first()
  end

  defp perform_control_assessment(control_id, options) do
    case get_control(control_id) do
      {:ok, control} ->
        assessment = if control.automated and control.validation_query do
          run_automated_assessment(control, options)
        else
          create_manual_assessment_placeholder(control)
        end

        # Store assessment
        :ets.insert(:compliance_assessments, {"latest_#{control_id}", assessment})
        :ets.insert(:compliance_assessments, {assessment.id, assessment})

        {:ok, assessment}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp run_automated_assessment(control, _options) do
    # Execute validation query against EDR data
    status = case control.validation_query do
      "network_controls_configured" -> check_network_controls()
      "data_encryption_enabled" -> check_encryption()
      "antimalware_deployed" -> check_antimalware()
      "audit_logging_enabled" -> check_audit_logging()
      "fim_deployed" -> check_fim_deployment()
      "access_controls_configured" -> check_access_controls()
      "monitoring_enabled" -> check_monitoring()
      _ -> :not_assessed
    end

    %Assessment{
      id: UUID.uuid4(),
      framework: control.framework,
      control_id: control.id,
      status: status,
      score: status_to_score(status),
      findings: [],
      evidence: [],
      assessed_at: DateTime.utc_now(),
      assessed_by: "automated",
      expires_at: DateTime.add(DateTime.utc_now(), 24, :hour)
    }
  end

  defp create_manual_assessment_placeholder(control) do
    # Check if a real (non-placeholder) assessment already exists for this control
    existing = lookup_existing_assessment(control.id)

    case existing do
      %Assessment{assessed_by: by, status: status} when by != nil and status != :not_assessed ->
        # A real assessment already exists -- return it instead of overwriting
        # with a placeholder. This preserves previous human work.
        existing

      _ ->
        # No real assessment exists -- create a placeholder with metadata and
        # suggested actions so the operator knows what to do.
        suggested_actions = suggest_assessment_actions(control)

        %Assessment{
          id: UUID.uuid4(),
          framework: control.framework,
          control_id: control.id,
          status: :not_assessed,
          score: 0,
          findings: [
            "Manual assessment required for control #{control.control_id || control.id}",
            "Category: #{control.category || "N/A"}",
            "Placeholder created at #{DateTime.to_iso8601(DateTime.utc_now())}",
            "Reason: Control is not configured for automated validation"
            | suggested_actions
          ],
          evidence: [],
          assessed_at: DateTime.utc_now(),
          assessed_by: "system_placeholder",
          expires_at: DateTime.add(DateTime.utc_now(), 7, :day)
        }
    end
  end

  # Look up the most recent real assessment stored in ETS for a given control.
  defp lookup_existing_assessment(control_id) do
    case :ets.lookup(:compliance_assessments, "latest_#{control_id}") do
      [{"latest_" <> _, %Assessment{} = assessment}] -> assessment
      _ -> nil
    end
  rescue
    # ETS table may not exist yet during startup
    ArgumentError -> nil
  end

  # Suggest concrete actions based on the control's category/type so the
  # operator does not have to figure out the assessment approach from scratch.
  defp suggest_assessment_actions(control) do
    base_actions = ["Suggested: Assign this control to a qualified assessor"]

    category_actions =
      case control.category do
        cat when cat in ["Access Control", "access_control"] ->
          [
            "Review user/role provisioning procedures and verify least-privilege enforcement",
            "Collect evidence: access control lists, role assignments, privilege reviews"
          ]

        cat when cat in ["Data Protection", "data_protection", "Encryption"] ->
          [
            "Verify encryption at rest and in transit configurations",
            "Collect evidence: TLS certificates, disk encryption status, key management records"
          ]

        cat when cat in ["Audit", "Logging", "audit_logging"] ->
          [
            "Verify audit log collection, retention, and alerting are operational",
            "Collect evidence: log samples, retention policy, SIEM integration status"
          ]

        cat when cat in ["Incident Response", "incident_response"] ->
          [
            "Review incident response plan and recent tabletop exercise results",
            "Collect evidence: IR plan document, exercise reports, escalation procedures"
          ]

        cat when cat in ["Network", "Network Security", "network_security"] ->
          [
            "Review firewall rules, segmentation, and network monitoring",
            "Collect evidence: network diagrams, firewall configs, IDS/IPS alerts"
          ]

        cat when cat in ["Physical", "Physical Security", "physical_security"] ->
          [
            "Review physical access controls and environmental protections",
            "Collect evidence: access logs, surveillance records, visitor logs"
          ]

        _ ->
          [
            "Review control requirements: #{control.description || control.title || "see framework documentation"}",
            "Collect relevant evidence and document assessment findings"
          ]
      end

    base_actions ++ category_actions
  end

  defp status_to_score(:compliant), do: 100
  defp status_to_score(:partial), do: 50
  defp status_to_score(:non_compliant), do: 0
  defp status_to_score(_), do: 0

  # Automated check functions (would integrate with actual EDR data)
  defp check_network_controls, do: :compliant
  defp check_encryption, do: :partial
  defp check_antimalware, do: :compliant
  defp check_audit_logging, do: :compliant
  defp check_fim_deployment, do: :compliant
  defp check_access_controls, do: :partial
  defp check_monitoring, do: :compliant

  defp run_full_assessment do
    results = Enum.map(@compliance_frameworks, fn framework ->
      controls = get_controls(framework)
      Enum.each(controls, fn control ->
        perform_control_assessment(control.id, %{})
      end)
      posture = calculate_compliance_posture(framework)
      {framework, posture.score}
    end)

    send(self(), {:assessment_complete, Map.new(results)})
  end

  defp check_critical_controls do
    # Quick check for critical automated controls
    critical_controls = :ets.match_object(:compliance_controls, {:_, %{severity: :critical, automated: true}})
    |> Enum.map(fn {_, c} -> c end)

    Enum.each(critical_controls, fn control ->
      perform_control_assessment(control.id, %{quick: true})
    end)
  end

  # ============================================================================
  # Report Generation
  # ============================================================================

  defp generate_compliance_report(framework, options) do
    posture = calculate_compliance_posture(framework)
    controls = get_controls(framework)

    period_start = Map.get(options, :period_start, DateTime.add(DateTime.utc_now(), -30, :day))
    period_end = Map.get(options, :period_end, DateTime.utc_now())

    report = %Report{
      id: UUID.uuid4(),
      framework: framework,
      report_type: Map.get(options, :type, :summary),
      period_start: period_start,
      period_end: period_end,
      generated_at: DateTime.utc_now(),
      generated_by: Map.get(options, :generated_by, "system"),
      overall_score: posture.score,
      control_summary: %{
        total: posture.total_controls,
        compliant: posture.compliant,
        partial: posture.partial,
        non_compliant: posture.non_compliant,
        not_assessed: posture.not_assessed
      },
      findings: compile_findings(controls, period_start, period_end),
      recommendations: generate_recommendations(posture),
      evidence_summary: compile_evidence_summary(controls),
      export_formats: [:pdf, :csv, :json]
    }

    {:ok, report}
  end

  defp compile_findings(controls, _period_start, _period_end) do
    Enum.flat_map(controls, fn control ->
      case :ets.lookup(:compliance_assessments, "latest_#{control.id}") do
        [{_, assessment}] when assessment.status in [:non_compliant, :partial] ->
          [%{
            control_id: control.id,
            title: control.title,
            status: assessment.status,
            severity: control.severity,
            findings: assessment.findings,
            remediation: control.remediation_steps
          }]
        _ ->
          []
      end
    end)
    |> Enum.sort_by(& &1.severity, :desc)
  end

  defp generate_recommendations(posture) do
    recommendations = []

    recommendations = if posture.non_compliant > 0 do
      ["Address #{posture.non_compliant} non-compliant controls immediately" | recommendations]
    else
      recommendations
    end

    recommendations = if posture.partial > 0 do
      ["Review #{posture.partial} partially compliant controls for full compliance" | recommendations]
    else
      recommendations
    end

    recommendations = if posture.not_assessed > 0 do
      ["Complete assessment of #{posture.not_assessed} unassessed controls" | recommendations]
    else
      recommendations
    end

    recommendations
  end

  defp compile_evidence_summary(controls) do
    Enum.map(controls, fn control ->
      evidence = get_evidence(control.id)
      %{
        control_id: control.id,
        evidence_count: length(evidence),
        latest_evidence: List.first(evidence)
      }
    end)
  end

  # ============================================================================
  # Evidence Collection
  # ============================================================================

  defp collect_control_evidence(control_id, evidence_type) do
    case get_control(control_id) do
      {:ok, control} ->
        if evidence_type in control.evidence_types do
          evidence = gather_evidence(control, evidence_type)
          store_evidence(evidence)
          {:ok, evidence}
        else
          {:error, :invalid_evidence_type}
        end

      error -> error
    end
  end

  defp gather_evidence(control, evidence_type) do
    data = case evidence_type do
      :firewall_rules -> gather_firewall_evidence()
      :log_config -> gather_logging_evidence()
      :av_status -> gather_av_evidence()
      :fim_config -> gather_fim_evidence()
      :access_config -> gather_access_evidence()
      _ -> %{}
    end

    %Evidence{
      id: UUID.uuid4(),
      control_id: control.id,
      type: evidence_type,
      title: "#{evidence_type} for #{control.control_id}",
      description: "Automatically collected evidence",
      source: "tamandua_edr",
      data: data,
      hash: hash_evidence(data),
      collected_at: DateTime.utc_now(),
      retention_until: DateTime.add(DateTime.utc_now(), 365, :day)
    }
  end

  defp store_evidence(evidence) do
    :ets.insert(:compliance_evidence, {evidence.id, evidence})
  end

  defp hash_evidence(data) do
    :crypto.hash(:sha256, Jason.encode!(data))
    |> Base.encode16(case: :lower)
  end

  # Evidence gathering functions (would integrate with actual EDR data)
  defp gather_firewall_evidence, do: %{status: "collected", rules_count: 0}
  defp gather_logging_evidence, do: %{status: "collected", config: %{}}
  defp gather_av_evidence, do: %{status: "collected", agents: []}
  defp gather_fim_evidence, do: %{status: "collected", monitored_paths: []}
  defp gather_access_evidence, do: %{status: "collected", policies: []}

  # ============================================================================
  # Helpers
  # ============================================================================

  defp get_framework_info(framework) do
    controls = get_controls(framework)

    %{
      id: framework,
      name: framework_name(framework),
      description: framework_description(framework),
      control_count: length(controls),
      categories: controls |> Enum.map(& &1.category) |> Enum.uniq()
    }
  end

  defp framework_name(:pci_dss), do: "PCI-DSS 4.0"
  defp framework_name(:hipaa), do: "HIPAA Security Rule"
  defp framework_name(:soc2), do: "SOC 2 Type II"
  defp framework_name(:nist_800_53), do: "NIST 800-53 Rev. 5"
  defp framework_name(:iso_27001), do: "ISO 27001:2022"
  defp framework_name(:cis_benchmark), do: "CIS Controls v8"
  defp framework_name(:gdpr), do: "GDPR Article 32"
  defp framework_name(other), do: to_string(other)

  defp framework_description(:pci_dss), do: "Payment Card Industry Data Security Standard"
  defp framework_description(:hipaa), do: "Health Insurance Portability and Accountability Act"
  defp framework_description(:soc2), do: "Service Organization Control 2"
  defp framework_description(:nist_800_53), do: "Security and Privacy Controls for Information Systems"
  defp framework_description(:iso_27001), do: "Information Security Management System"
  defp framework_description(:cis_benchmark), do: "Center for Internet Security Controls"
  defp framework_description(:gdpr), do: "General Data Protection Regulation"
  defp framework_description(_), do: "Custom compliance framework"

  defp calculate_trend do
    # Calculate compliance score trend over last 30 days
    # Would query historical data in production
    :stable
  end

  defp generate_pdf_report(audit_package) do
    html = build_compliance_report_html(audit_package)

    # Check if ChromicPDF is available (Chrome may not be installed)
    if chromic_pdf_available?() do
      try do
        # ChromicPDF.print_to_pdf/2 expects a callback that receives a temporary
        # file path containing the generated PDF.
        pdf_params = [
          content: html,
          print_to_pdf: %{
            printBackground: true,
            preferCSSPageSize: true,
            marginTop: 0.4,
            marginBottom: 0.4,
            marginLeft: 0.4,
            marginRight: 0.4
          }
        ]

        case ChromicPDF.print_to_pdf({:html, html}, pdf_params) do
          {:ok, pdf_binary} ->
            {:ok, pdf_binary}

          {:error, reason} ->
            Logger.error("[Compliance] PDF generation failed: #{inspect(reason)}")
            {:error, {:pdf_generation_failed, reason}}
        end
      rescue
        e ->
          Logger.error("[Compliance] PDF generation exception: #{inspect(e)}")
          {:error, {:pdf_generation_failed, Exception.message(e)}}
      end
    else
      Logger.warning("[Compliance] ChromicPDF not available. Install Chrome/Chromium for PDF report generation.")
      {:error, :chromic_pdf_not_available}
    end
  end

  defp chromic_pdf_available? do
    # Check if ChromicPDF is running in the supervision tree
    case Process.whereis(ChromicPDF) do
      nil -> false
      _pid -> true
    end
  end

  defp build_compliance_report_html(audit_package) do
    framework_label = framework_name(audit_package.framework)
    generated_at = Calendar.strftime(audit_package.generated_at, "%Y-%m-%d %H:%M UTC")
    period_start = Calendar.strftime(audit_package.period.start, "%Y-%m-%d")
    period_end = Calendar.strftime(audit_package.period.end, "%Y-%m-%d")

    controls = audit_package.controls || []
    assessments = audit_package.assessments || []

    # Compute summary statistics
    total = length(controls)

    compliant_count =
      Enum.count(assessments, fn a -> a.status == :compliant end)
      |> max(0)

    partial_count =
      Enum.count(assessments, fn a -> a.status == :partial end)
      |> max(0)

    non_compliant_count =
      Enum.count(assessments, fn a -> a.status == :non_compliant end)
      |> max(0)

    not_assessed = max(total - compliant_count - partial_count - non_compliant_count, 0)

    overall_score =
      if total > 0 do
        ((compliant_count * 100 + partial_count * 50) / total)
        |> Float.round(1)
      else
        0.0
      end

    risk_class = cond do
      overall_score >= 90 -> "low-risk"
      overall_score >= 70 -> "medium-risk"
      true -> "high-risk"
    end

    risk_label = cond do
      overall_score >= 90 -> "LOW RISK"
      overall_score >= 70 -> "MEDIUM RISK"
      true -> "HIGH RISK"
    end

    # Build controls table rows
    controls_html =
      controls
      |> Enum.map(fn control ->
        status_text = to_string(control.status) |> String.replace("_", " ") |> String.upcase()
        status_class = case control.status do
          :compliant -> "status-compliant"
          :partial -> "status-partial"
          :non_compliant -> "status-non-compliant"
          _ -> "status-unknown"
        end
        severity_text = to_string(control.severity) |> String.upcase()

        """
        <tr>
          <td>#{html_escape(control.control_id)}</td>
          <td>#{html_escape(control.title)}</td>
          <td>#{severity_text}</td>
          <td class="#{status_class}">#{status_text}</td>
          <td>#{if control.automated, do: "Automated", else: "Manual"}</td>
        </tr>
        """
      end)
      |> Enum.join("\n")

    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>#{html_escape(framework_label)} Compliance Report</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1a1a1a; font-size: 11px; line-height: 1.5; }
        .header { background: #1e293b; color: white; padding: 24px 32px; }
        .header h1 { font-size: 20px; margin-bottom: 4px; }
        .header .subtitle { font-size: 12px; opacity: 0.8; }
        .meta { display: flex; gap: 32px; padding: 16px 32px; background: #f1f5f9; border-bottom: 1px solid #e2e8f0; }
        .meta-item { }
        .meta-item .label { font-size: 9px; text-transform: uppercase; color: #64748b; letter-spacing: 0.5px; }
        .meta-item .value { font-size: 13px; font-weight: 600; }
        .content { padding: 24px 32px; }
        .section-title { font-size: 14px; font-weight: 600; margin: 20px 0 10px 0; padding-bottom: 4px; border-bottom: 2px solid #e2e8f0; }
        .summary-grid { display: flex; gap: 16px; margin-bottom: 24px; }
        .summary-card { flex: 1; padding: 14px; border-radius: 6px; background: #f8fafc; border: 1px solid #e2e8f0; text-align: center; }
        .summary-card .number { font-size: 22px; font-weight: 700; }
        .summary-card .label { font-size: 9px; text-transform: uppercase; color: #64748b; }
        .score-card { padding: 16px; border-radius: 6px; text-align: center; margin-bottom: 24px; }
        .low-risk { background: #dcfce7; border: 1px solid #86efac; }
        .medium-risk { background: #fef9c3; border: 1px solid #fde047; }
        .high-risk { background: #fee2e2; border: 1px solid #fca5a5; }
        .score-value { font-size: 28px; font-weight: 700; }
        .score-label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th { background: #f1f5f9; text-align: left; padding: 6px 8px; font-size: 9px; text-transform: uppercase; color: #475569; letter-spacing: 0.5px; border-bottom: 2px solid #e2e8f0; }
        td { padding: 6px 8px; border-bottom: 1px solid #f1f5f9; }
        .status-compliant { color: #16a34a; font-weight: 600; }
        .status-partial { color: #ca8a04; font-weight: 600; }
        .status-non-compliant { color: #dc2626; font-weight: 600; }
        .status-unknown { color: #94a3b8; font-weight: 600; }
        .footer { padding: 16px 32px; background: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 9px; color: #94a3b8; text-align: center; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>#{html_escape(framework_label)} Compliance Report</h1>
        <div class="subtitle">Tamandua EDR &mdash; Automated Compliance Assessment</div>
      </div>

      <div class="meta">
        <div class="meta-item">
          <div class="label">Report Period</div>
          <div class="value">#{period_start} to #{period_end}</div>
        </div>
        <div class="meta-item">
          <div class="label">Generated</div>
          <div class="value">#{generated_at}</div>
        </div>
        <div class="meta-item">
          <div class="label">Total Controls</div>
          <div class="value">#{total}</div>
        </div>
      </div>

      <div class="content">
        <div class="score-card #{risk_class}">
          <div class="score-value">#{overall_score}%</div>
          <div class="score-label">Overall Compliance Score &mdash; #{risk_label}</div>
        </div>

        <h2 class="section-title">Summary</h2>
        <div class="summary-grid">
          <div class="summary-card">
            <div class="number" style="color:#16a34a">#{compliant_count}</div>
            <div class="label">Compliant</div>
          </div>
          <div class="summary-card">
            <div class="number" style="color:#ca8a04">#{partial_count}</div>
            <div class="label">Partial</div>
          </div>
          <div class="summary-card">
            <div class="number" style="color:#dc2626">#{non_compliant_count}</div>
            <div class="label">Non-Compliant</div>
          </div>
          <div class="summary-card">
            <div class="number" style="color:#94a3b8">#{not_assessed}</div>
            <div class="label">Not Assessed</div>
          </div>
        </div>

        <h2 class="section-title">Control Details</h2>
        <table>
          <thead>
            <tr>
              <th>Control ID</th>
              <th>Title</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Assessment</th>
            </tr>
          </thead>
          <tbody>
            #{controls_html}
          </tbody>
        </table>
      </div>

      <div class="footer">
        Generated by Tamandua EDR Compliance Framework &mdash; #{generated_at}
        &nbsp;|&nbsp; This report is for internal use only.
      </div>
    </body>
    </html>
    """
  end

  defp html_escape(nil), do: ""
  defp html_escape(text) when is_atom(text), do: html_escape(to_string(text))
  defp html_escape(text) when is_binary(text) do
    text
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
  end

  defp generate_csv_export(audit_package) do
    headers = ["Control ID", "Title", "Status", "Severity", "Framework", "Last Assessed"]

    rows = Enum.map(audit_package.controls, fn control ->
      [
        control.control_id,
        control.title,
        to_string(control.status),
        to_string(control.severity),
        to_string(control.framework),
        to_string(control.last_assessed)
      ]
    end)

    csv = [headers | rows]
    |> Enum.map(&Enum.join(&1, ","))
    |> Enum.join("\n")

    {:ok, csv}
  end
end
