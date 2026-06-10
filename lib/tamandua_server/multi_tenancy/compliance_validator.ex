defmodule TamanduaServer.MultiTenancy.ComplianceValidator do
  @moduledoc """
  Validates compliance with data sovereignty and privacy regulations.

  This module enforces compliance requirements for various regulatory frameworks:
  - GDPR (General Data Protection Regulation) - EU
  - CCPA (California Consumer Privacy Act) - California, USA
  - SOX (Sarbanes-Oxley Act) - Financial data
  - HIPAA (Health Insurance Portability and Accountability Act) - Healthcare
  - PCI-DSS (Payment Card Industry Data Security Standard) - Payment data
  - SOC 2 - Security, availability, processing integrity, confidentiality, privacy

  ## Features

  - Data residency validation
  - Cross-border transfer checks
  - Encryption requirement validation
  - Audit log retention validation
  - Access control validation
  - Data retention policy validation
  - Breach notification requirements
  - Compliance violation alerts

  ## Usage

      # Validate GDPR compliance
      ComplianceValidator.validate(tenant_id, :gdpr)

      # Run full compliance audit
      ComplianceValidator.audit_compliance(tenant_id)

      # Generate compliance report
      ComplianceValidator.generate_report(tenant_id, :gdpr)
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.MultiTenancy.DataResidency
  alias TamanduaServer.Audit

  require Logger

  @supported_frameworks [:gdpr, :ccpa, :sox, :hipaa, :pci_dss, :soc2]

  # GDPR requirements
  @gdpr_regions [:eu, :uk]
  @gdpr_max_retention_days 2555  # 7 years
  @gdpr_breach_notification_hours 72

  # CCPA requirements
  @ccpa_regions [:us, :ca]
  @ccpa_max_retention_days 365 * 2  # 2 years for consumer data

  # SOX requirements (financial data)
  @sox_min_retention_years 7
  @sox_audit_log_retention_years 7

  # HIPAA requirements (healthcare)
  @hipaa_min_retention_years 6
  @hipaa_encryption_required true

  # PCI-DSS requirements (payment data)
  @pci_dss_encryption_required true
  @pci_dss_audit_retention_years 1

  # ===========================================================================
  # Public API
  # ===========================================================================

  @doc """
  Validates compliance for a tenant against a specific framework.

  ## Parameters

  - `tenant_id` - Organization UUID
  - `framework` - Compliance framework atom (:gdpr, :ccpa, :sox, :hipaa, :pci_dss, :soc2)

  ## Returns

  - `{:ok, %{compliant: true, checks: [...]}}` - All checks passed
  - `{:ok, %{compliant: false, violations: [...], checks: [...]}}` - Violations found
  - `{:error, reason}` - Validation failed

  ## Examples

      iex> ComplianceValidator.validate(tenant_id, :gdpr)
      {:ok, %{
        compliant: false,
        violations: [
          %{check: "data_residency", severity: "critical", message: "EU data stored in US region"},
          %{check: "encryption", severity: "high", message: "Encryption not enabled"}
        ],
        checks: [
          %{check: "data_residency", passed: false},
          %{check: "encryption", passed: false},
          %{check: "audit_logging", passed: true},
          %{check: "access_controls", passed: true}
        ]
      }}
  """
  def validate(tenant_id, framework) when framework in @supported_frameworks do
    with {:ok, org} <- get_organization(tenant_id) do
      checks = run_compliance_checks(org, framework)
      violations = get_violations(checks)

      result = %{
        compliant: Enum.empty?(violations),
        framework: framework,
        violations: violations,
        checks: checks,
        validated_at: DateTime.utc_now()
      }

      # Log compliance validation
      log_compliance_validation(tenant_id, framework, result)

      {:ok, result}
    end
  end

  def validate(_tenant_id, framework) do
    {:error, {:unsupported_framework, framework}}
  end

  @doc """
  Runs a full compliance audit across all applicable frameworks for a tenant.

  ## Returns

      %{
        gdpr: %{compliant: true, violations: []},
        ccpa: %{compliant: false, violations: [...]},
        sox: %{compliant: true, violations: []},
        overall_compliant: false
      }
  """
  def audit_compliance(tenant_id) do
    with {:ok, org} <- get_organization(tenant_id) do
      frameworks = get_applicable_frameworks(org)

      results =
        Enum.reduce(frameworks, %{}, fn framework, acc ->
          {:ok, validation} = validate(tenant_id, framework)
          Map.put(acc, framework, validation)
        end)

      overall_compliant = Enum.all?(Map.values(results), & &1.compliant)

      %{
        results: results,
        frameworks: frameworks,
        overall_compliant: overall_compliant,
        audited_at: DateTime.utc_now()
      }
    end
  end

  @doc """
  Generates a compliance report for a tenant.

  ## Options

  - `:format` - Output format (:json, :pdf, :html, default: :json)
  - `:include_evidence` - Include supporting evidence (default: false)
  - `:period` - Reporting period in days (default: 30)

  ## Returns

      %{
        organization: %{id: "...", name: "ACME Corp"},
        framework: :gdpr,
        report_period: {~D[2024-01-20], ~D[2024-02-20]},
        compliance_status: :compliant,
        violations: [],
        recommendations: [
          "Enable automated backup to secondary region",
          "Implement data retention policy"
        ],
        evidence: [...]
      }
  """
  def generate_report(tenant_id, framework, opts \\ []) do
    with {:ok, org} <- get_organization(tenant_id),
         {:ok, validation} <- validate(tenant_id, framework) do

      period = Keyword.get(opts, :period, 30)
      include_evidence = Keyword.get(opts, :include_evidence, false)

      report = %{
        organization: %{
          id: org.id,
          name: org.name,
          region: org.region
        },
        framework: framework,
        report_period: build_period(period),
        compliance_status: if(validation.compliant, do: :compliant, else: :non_compliant),
        violations: validation.violations,
        checks: validation.checks,
        recommendations: generate_recommendations(validation),
        generated_at: DateTime.utc_now()
      }

      report =
        if include_evidence do
          Map.put(report, :evidence, collect_evidence(tenant_id, framework, period))
        else
          report
        end

      format = Keyword.get(opts, :format, :json)
      format_report(report, format)
    end
  end

  @doc """
  Checks if a specific data location violates compliance requirements.

  ## Examples

      iex> ComplianceValidator.check_data_location_compliance(tenant_id, :us)
      {:ok, :compliant}

      iex> ComplianceValidator.check_data_location_compliance(eu_gdpr_tenant_id, :us)
      {:error, :gdpr_violation}
  """
  def check_data_location_compliance(tenant_id, data_region) do
    with {:ok, org} <- get_organization(tenant_id) do
      frameworks = get_compliance_frameworks(org)

      violations =
        Enum.filter(frameworks, fn framework ->
          violates_data_residency?(framework, org.region, data_region)
        end)

      if Enum.empty?(violations) do
        {:ok, :compliant}
      else
        {:error, {:compliance_violation, violations}}
      end
    end
  end

  @doc """
  Validates encryption configuration meets compliance requirements.

  ## Examples

      iex> ComplianceValidator.validate_encryption(tenant_id)
      {:ok, %{compliant: true, encryption_enabled: true, algorithm: "AES-256"}}
  """
  def validate_encryption(tenant_id) do
    with {:ok, org} <- get_organization(tenant_id),
         {:ok, config} <- DataResidency.get_storage_config(tenant_id) do

      frameworks = get_compliance_frameworks(org)

      # Check if encryption is required by any framework
      encryption_required = Enum.any?(frameworks, &requires_encryption?/1)

      # Check if encryption is actually enabled
      encryption_enabled = is_encryption_enabled?(config)

      result = %{
        compliant: !encryption_required || encryption_enabled,
        encryption_enabled: encryption_enabled,
        encryption_required: encryption_required,
        frameworks_requiring_encryption: Enum.filter(frameworks, &requires_encryption?/1)
      }

      {:ok, result}
    end
  end

  @doc """
  Validates audit log retention meets compliance requirements.

  ## Examples

      iex> ComplianceValidator.validate_audit_retention(tenant_id)
      {:ok, %{compliant: true, retention_days: 2555, required_days: 2555}}
  """
  def validate_audit_retention(tenant_id) do
    with {:ok, org} <- get_organization(tenant_id) do
      frameworks = get_compliance_frameworks(org)

      required_retention = calculate_required_retention(frameworks)
      current_retention = get_current_retention(org)

      result = %{
        compliant: current_retention >= required_retention,
        retention_days: current_retention,
        required_days: required_retention,
        frameworks: frameworks
      }

      {:ok, result}
    end
  end

  @doc """
  Returns list of supported compliance frameworks.
  """
  def supported_frameworks, do: @supported_frameworks

  # ===========================================================================
  # Private Functions - Compliance Checks
  # ===========================================================================

  defp run_compliance_checks(org, :gdpr) do
    [
      check_gdpr_data_residency(org),
      check_gdpr_encryption(org),
      check_gdpr_audit_logging(org),
      check_gdpr_access_controls(org),
      check_gdpr_retention_policy(org),
      check_gdpr_breach_notification(org),
      check_gdpr_data_processing_agreements(org),
      check_gdpr_right_to_erasure(org)
    ]
  end

  defp run_compliance_checks(org, :ccpa) do
    [
      check_ccpa_data_residency(org),
      check_ccpa_privacy_notice(org),
      check_ccpa_opt_out(org),
      check_ccpa_data_retention(org),
      check_ccpa_access_controls(org)
    ]
  end

  defp run_compliance_checks(org, :sox) do
    [
      check_sox_audit_trail(org),
      check_sox_access_controls(org),
      check_sox_change_management(org),
      check_sox_retention_policy(org),
      check_sox_separation_of_duties(org)
    ]
  end

  defp run_compliance_checks(org, :hipaa) do
    [
      check_hipaa_encryption(org),
      check_hipaa_access_controls(org),
      check_hipaa_audit_logging(org),
      check_hipaa_retention_policy(org),
      check_hipaa_breach_notification(org)
    ]
  end

  defp run_compliance_checks(org, :pci_dss) do
    [
      check_pci_encryption(org),
      check_pci_access_controls(org),
      check_pci_network_security(org),
      check_pci_audit_logging(org),
      check_pci_vulnerability_management(org)
    ]
  end

  defp run_compliance_checks(org, :soc2) do
    [
      check_soc2_security(org),
      check_soc2_availability(org),
      check_soc2_processing_integrity(org),
      check_soc2_confidentiality(org),
      check_soc2_privacy(org)
    ]
  end

  # GDPR Checks
  defp check_gdpr_data_residency(org) do
    frameworks = get_compliance_frameworks(org)

    if :gdpr in frameworks do
      # GDPR requires EU data to stay in EU/UK
      passed = org.region in @gdpr_regions

      %{
        check: "gdpr_data_residency",
        passed: passed,
        severity: "critical",
        message: if(passed, do: "Data correctly stored in GDPR region", else: "GDPR data stored outside EU/UK"),
        details: %{region: org.region, required_regions: @gdpr_regions}
      }
    else
      %{check: "gdpr_data_residency", passed: true, severity: "info", message: "GDPR not applicable"}
    end
  end

  defp check_gdpr_encryption(org) do
    encryption_enabled = Map.get(org.settings, "encryption_enabled", false)

    %{
      check: "gdpr_encryption",
      passed: encryption_enabled,
      severity: "high",
      message: if(encryption_enabled, do: "Encryption enabled", else: "Encryption not enabled (GDPR Article 32)"),
      details: %{encryption_enabled: encryption_enabled}
    }
  end

  defp check_gdpr_audit_logging(org) do
    audit_enabled = Map.get(org.settings, "audit_logging_enabled", true)

    %{
      check: "gdpr_audit_logging",
      passed: audit_enabled,
      severity: "medium",
      message: if(audit_enabled, do: "Audit logging enabled", else: "Audit logging not enabled"),
      details: %{audit_enabled: audit_enabled}
    }
  end

  defp check_gdpr_access_controls(org) do
    rbac_enabled = Map.get(org.settings, "rbac_enabled", true)

    %{
      check: "gdpr_access_controls",
      passed: rbac_enabled,
      severity: "high",
      message: if(rbac_enabled, do: "RBAC enabled", else: "RBAC not properly configured"),
      details: %{rbac_enabled: rbac_enabled}
    }
  end

  defp check_gdpr_retention_policy(org) do
    retention_days = Map.get(org.settings, "data_retention_days", 0)
    passed = retention_days > 0 && retention_days <= @gdpr_max_retention_days

    %{
      check: "gdpr_retention_policy",
      passed: passed,
      severity: "medium",
      message: if(passed, do: "Retention policy compliant", else: "Retention policy not configured or exceeds limits"),
      details: %{retention_days: retention_days, max_days: @gdpr_max_retention_days}
    }
  end

  defp check_gdpr_breach_notification(org) do
    notification_configured = Map.get(org.settings, "breach_notification_enabled", false)

    %{
      check: "gdpr_breach_notification",
      passed: notification_configured,
      severity: "high",
      message: if(notification_configured, do: "Breach notification configured (72h)", else: "Breach notification not configured"),
      details: %{notification_hours: @gdpr_breach_notification_hours}
    }
  end

  defp check_gdpr_data_processing_agreements(org) do
    dpa_signed = Map.get(org.settings, "dpa_signed", false)

    %{
      check: "gdpr_data_processing_agreements",
      passed: dpa_signed,
      severity: "medium",
      message: if(dpa_signed, do: "DPA on file", else: "Data Processing Agreement not signed"),
      details: %{dpa_signed: dpa_signed}
    }
  end

  defp check_gdpr_right_to_erasure(org) do
    erasure_enabled = Map.get(org.settings, "right_to_erasure_enabled", false)

    %{
      check: "gdpr_right_to_erasure",
      passed: erasure_enabled,
      severity: "high",
      message: if(erasure_enabled, do: "Right to erasure implemented", else: "Right to erasure not implemented (GDPR Article 17)"),
      details: %{erasure_enabled: erasure_enabled}
    }
  end

  # CCPA Checks
  defp check_ccpa_data_residency(org) do
    passed = org.region in @ccpa_regions

    %{
      check: "ccpa_data_residency",
      passed: passed,
      severity: "medium",
      message: if(passed, do: "Data in CCPA jurisdiction", else: "Data outside CCPA jurisdiction"),
      details: %{region: org.region}
    }
  end

  defp check_ccpa_privacy_notice(org) do
    privacy_notice = Map.get(org.settings, "privacy_notice_enabled", false)

    %{
      check: "ccpa_privacy_notice",
      passed: privacy_notice,
      severity: "high",
      message: if(privacy_notice, do: "Privacy notice published", else: "Privacy notice not published"),
      details: %{privacy_notice: privacy_notice}
    }
  end

  defp check_ccpa_opt_out(org) do
    opt_out_enabled = Map.get(org.settings, "ccpa_opt_out_enabled", false)

    %{
      check: "ccpa_opt_out",
      passed: opt_out_enabled,
      severity: "high",
      message: if(opt_out_enabled, do: "Opt-out mechanism enabled", else: "Opt-out mechanism not enabled"),
      details: %{opt_out_enabled: opt_out_enabled}
    }
  end

  defp check_ccpa_data_retention(org) do
    retention_days = Map.get(org.settings, "data_retention_days", 0)
    passed = retention_days > 0 && retention_days <= @ccpa_max_retention_days

    %{
      check: "ccpa_data_retention",
      passed: passed,
      severity: "medium",
      message: if(passed, do: "Data retention compliant", else: "Data retention exceeds CCPA limits"),
      details: %{retention_days: retention_days, max_days: @ccpa_max_retention_days}
    }
  end

  defp check_ccpa_access_controls(org) do
    access_controls = Map.get(org.settings, "rbac_enabled", true)

    %{
      check: "ccpa_access_controls",
      passed: access_controls,
      severity: "medium",
      message: if(access_controls, do: "Access controls enabled", else: "Access controls not configured"),
      details: %{access_controls: access_controls}
    }
  end

  # SOX Checks
  defp check_sox_audit_trail(org) do
    audit_enabled = Map.get(org.settings, "audit_logging_enabled", true)
    retention_years = Map.get(org.settings, "audit_retention_years", 0)
    passed = audit_enabled && retention_years >= @sox_audit_log_retention_years

    %{
      check: "sox_audit_trail",
      passed: passed,
      severity: "critical",
      message: if(passed, do: "Audit trail compliant (7 years)", else: "Audit trail not compliant"),
      details: %{retention_years: retention_years, required_years: @sox_audit_log_retention_years}
    }
  end

  defp check_sox_access_controls(org) do
    rbac_enabled = Map.get(org.settings, "rbac_enabled", true)
    mfa_enabled = Map.get(org.settings, "mfa_required", false)
    passed = rbac_enabled && mfa_enabled

    %{
      check: "sox_access_controls",
      passed: passed,
      severity: "critical",
      message: if(passed, do: "Strong access controls", else: "Access controls insufficient (MFA required)"),
      details: %{rbac_enabled: rbac_enabled, mfa_enabled: mfa_enabled}
    }
  end

  defp check_sox_change_management(org) do
    change_mgmt = Map.get(org.settings, "change_management_enabled", false)

    %{
      check: "sox_change_management",
      passed: change_mgmt,
      severity: "high",
      message: if(change_mgmt, do: "Change management process enabled", else: "Change management not configured"),
      details: %{change_management: change_mgmt}
    }
  end

  defp check_sox_retention_policy(org) do
    retention_years = Map.get(org.settings, "data_retention_years", 0)
    passed = retention_years >= @sox_min_retention_years

    %{
      check: "sox_retention_policy",
      passed: passed,
      severity: "critical",
      message: if(passed, do: "Retention policy compliant (7 years)", else: "Retention policy does not meet SOX requirements"),
      details: %{retention_years: retention_years, required_years: @sox_min_retention_years}
    }
  end

  defp check_sox_separation_of_duties(org) do
    sod_enabled = Map.get(org.settings, "separation_of_duties", false)

    %{
      check: "sox_separation_of_duties",
      passed: sod_enabled,
      severity: "high",
      message: if(sod_enabled, do: "Separation of duties enforced", else: "Separation of duties not enforced"),
      details: %{sod_enabled: sod_enabled}
    }
  end

  # HIPAA Checks
  defp check_hipaa_encryption(org) do
    encryption = Map.get(org.settings, "encryption_enabled", false)

    %{
      check: "hipaa_encryption",
      passed: encryption,
      severity: "critical",
      message: if(encryption, do: "PHI encryption enabled", else: "PHI encryption not enabled (HIPAA Security Rule)"),
      details: %{encryption_required: @hipaa_encryption_required}
    }
  end

  defp check_hipaa_access_controls(org) do
    rbac = Map.get(org.settings, "rbac_enabled", true)
    audit = Map.get(org.settings, "audit_logging_enabled", true)
    passed = rbac && audit

    %{
      check: "hipaa_access_controls",
      passed: passed,
      severity: "critical",
      message: if(passed, do: "PHI access controls compliant", else: "PHI access controls insufficient"),
      details: %{rbac: rbac, audit: audit}
    }
  end

  defp check_hipaa_audit_logging(org) do
    audit_enabled = Map.get(org.settings, "audit_logging_enabled", true)

    %{
      check: "hipaa_audit_logging",
      passed: audit_enabled,
      severity: "critical",
      message: if(audit_enabled, do: "HIPAA audit logging enabled", else: "HIPAA audit logging not enabled"),
      details: %{audit_enabled: audit_enabled}
    }
  end

  defp check_hipaa_retention_policy(org) do
    retention_years = Map.get(org.settings, "data_retention_years", 0)
    passed = retention_years >= @hipaa_min_retention_years

    %{
      check: "hipaa_retention_policy",
      passed: passed,
      severity: "high",
      message: if(passed, do: "Retention policy compliant (6 years)", else: "Retention policy does not meet HIPAA requirements"),
      details: %{retention_years: retention_years, required_years: @hipaa_min_retention_years}
    }
  end

  defp check_hipaa_breach_notification(org) do
    notification = Map.get(org.settings, "breach_notification_enabled", false)

    %{
      check: "hipaa_breach_notification",
      passed: notification,
      severity: "critical",
      message: if(notification, do: "Breach notification configured", else: "Breach notification not configured (60 days)"),
      details: %{notification_days: 60}
    }
  end

  # PCI-DSS Checks
  defp check_pci_encryption(org) do
    encryption = Map.get(org.settings, "encryption_enabled", false)

    %{
      check: "pci_encryption",
      passed: encryption,
      severity: "critical",
      message: if(encryption, do: "Card data encryption enabled", else: "Card data encryption not enabled"),
      details: %{encryption_required: @pci_dss_encryption_required}
    }
  end

  defp check_pci_access_controls(org) do
    rbac = Map.get(org.settings, "rbac_enabled", true)

    %{
      check: "pci_access_controls",
      passed: rbac,
      severity: "critical",
      message: if(rbac, do: "Access controls enabled", else: "Access controls not configured"),
      details: %{rbac: rbac}
    }
  end

  defp check_pci_network_security(org) do
    firewall = Map.get(org.settings, "firewall_enabled", false)

    %{
      check: "pci_network_security",
      passed: firewall,
      severity: "critical",
      message: if(firewall, do: "Network security configured", else: "Network security not configured"),
      details: %{firewall: firewall}
    }
  end

  defp check_pci_audit_logging(org) do
    audit = Map.get(org.settings, "audit_logging_enabled", true)
    retention_years = Map.get(org.settings, "audit_retention_years", 0)
    passed = audit && retention_years >= @pci_dss_audit_retention_years

    %{
      check: "pci_audit_logging",
      passed: passed,
      severity: "critical",
      message: if(passed, do: "Audit logging compliant (1 year)", else: "Audit logging not compliant"),
      details: %{retention_years: retention_years, required_years: @pci_dss_audit_retention_years}
    }
  end

  defp check_pci_vulnerability_management(org) do
    vuln_scan = Map.get(org.settings, "vulnerability_scanning_enabled", false)

    %{
      check: "pci_vulnerability_management",
      passed: vuln_scan,
      severity: "high",
      message: if(vuln_scan, do: "Vulnerability scanning enabled", else: "Vulnerability scanning not enabled"),
      details: %{vuln_scan: vuln_scan}
    }
  end

  # SOC 2 Checks
  defp check_soc2_security(org), do: check_gdpr_encryption(org)
  defp check_soc2_availability(org) do
    replication = Map.get(org.settings, "replication_enabled", false)

    %{
      check: "soc2_availability",
      passed: replication,
      severity: "medium",
      message: if(replication, do: "Replication enabled for availability", else: "Replication not enabled"),
      details: %{replication: replication}
    }
  end

  defp check_soc2_processing_integrity(org) do
    integrity_checks = Map.get(org.settings, "data_integrity_checks", false)

    %{
      check: "soc2_processing_integrity",
      passed: integrity_checks,
      severity: "medium",
      message: if(integrity_checks, do: "Data integrity checks enabled", else: "Data integrity checks not enabled"),
      details: %{integrity_checks: integrity_checks}
    }
  end

  defp check_soc2_confidentiality(org), do: check_gdpr_encryption(org)
  defp check_soc2_privacy(org), do: check_gdpr_access_controls(org)

  # ===========================================================================
  # Helper Functions
  # ===========================================================================

  defp get_organization(tenant_id) do
    case Repo.get(Organization, tenant_id) do
      nil -> {:error, :tenant_not_found}
      org -> {:ok, org}
    end
  end

  defp get_violations(checks) do
    checks
    |> Enum.reject(& &1.passed)
    |> Enum.map(fn check ->
      %{
        check: check.check,
        severity: check.severity,
        message: check.message,
        details: check.details
      }
    end)
  end

  defp get_compliance_frameworks(%Organization{settings: settings}) do
    Map.get(settings, "compliance_frameworks", [])
    |> Enum.map(&String.to_existing_atom/1)
  rescue
    _ -> []
  end

  defp get_applicable_frameworks(org) do
    configured = get_compliance_frameworks(org)

    # Add auto-detected frameworks based on region
    auto_detected =
      cond do
        org.region in @gdpr_regions -> [:gdpr]
        org.region in @ccpa_regions -> [:ccpa]
        true -> []
      end

    Enum.uniq(configured ++ auto_detected)
  end

  defp violates_data_residency?(:gdpr, org_region, data_region) do
    org_region in @gdpr_regions && data_region not in @gdpr_regions
  end
  defp violates_data_residency?(_framework, _org_region, _data_region), do: false

  defp requires_encryption?(:hipaa), do: true
  defp requires_encryption?(:pci_dss), do: true
  defp requires_encryption?(_), do: false

  defp is_encryption_enabled?(config) do
    Map.get(config, :encryption_enabled, false)
  end

  defp calculate_required_retention(frameworks) do
    retention_requirements = %{
      gdpr: @gdpr_max_retention_days,
      sox: @sox_min_retention_years * 365,
      hipaa: @hipaa_min_retention_years * 365,
      pci_dss: @pci_dss_audit_retention_years * 365
    }

    frameworks
    |> Enum.map(&Map.get(retention_requirements, &1, 0))
    |> Enum.max(fn -> 0 end)
  end

  defp get_current_retention(%Organization{settings: settings}) do
    Map.get(settings, "data_retention_days", 0)
  end

  defp build_period(days) do
    end_date = Date.utc_today()
    start_date = Date.add(end_date, -days)
    {start_date, end_date}
  end

  defp generate_recommendations(validation) do
    validation.violations
    |> Enum.map(&generate_recommendation/1)
    |> Enum.reject(&is_nil/1)
  end

  defp generate_recommendation(%{check: "gdpr_encryption"}), do: "Enable encryption at rest and in transit for GDPR compliance"
  defp generate_recommendation(%{check: "gdpr_data_residency"}), do: "Migrate data to EU/UK region for GDPR compliance"
  defp generate_recommendation(%{check: "sox_access_controls"}), do: "Enable MFA for all users to meet SOX requirements"
  defp generate_recommendation(%{check: "hipaa_encryption"}), do: "Enable PHI encryption to comply with HIPAA Security Rule"
  defp generate_recommendation(_), do: nil

  defp collect_evidence(_tenant_id, _framework, _period) do
    # This would collect actual evidence like:
    # - Audit log samples
    # - Access control configurations
    # - Encryption settings
    # - Backup schedules
    []
  end

  defp format_report(report, :json), do: {:ok, report}
  defp format_report(_report, format), do: {:error, {:unsupported_format, format}}

  defp log_compliance_validation(tenant_id, framework, result) do
    Audit.log_event(%{
      organization_id: tenant_id,
      action: "compliance.validation",
      resource_type: "organization",
      resource_id: tenant_id,
      metadata: %{
        framework: framework,
        compliant: result.compliant,
        violations_count: length(result.violations)
      },
      severity: if(result.compliant, do: "info", else: "high")
    })
  rescue
    error ->
      Logger.error("Failed to log compliance validation: #{inspect(error)}")
      :ok
  end
end
