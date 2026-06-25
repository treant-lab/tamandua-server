defmodule TamanduaServerWeb.API.V1.ComplianceController do
  @moduledoc """
  Compliance Reporting API Controller

  Provides endpoints for compliance posture monitoring, control assessment,
  evidence collection, and report generation.

  ## Supported Frameworks
  - PCI-DSS 4.0
  - HIPAA Security Rule
  - SOC 2 Type II
  - NIST 800-53 Rev. 5
  - ISO 27001:2022
  - CIS Benchmarks v8
  - GDPR Article 32
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Compliance

  action_fallback TamanduaServerWeb.FallbackController

  @allowed_frameworks ~w(pci_dss hipaa soc2 nist_800_53 iso_27001 cis_benchmark gdpr)
  @allowed_evidence_types ~w(log_review access_control_test encryption_check network_scan vulnerability_scan configuration_audit policy_review)

  @doc """
  Get overall compliance posture across all frameworks.

  Returns aggregate scores and status for each framework.
  """
  def overview(conn, _params) do
    posture = Compliance.get_overall_posture()

    json(conn, %{
      data: %{
        overall_score: posture.overall_score,
        trend: posture.trend,
        frameworks: Enum.map(posture.frameworks, fn {fw, p} ->
          %{
            framework: fw,
            name: framework_name(fw),
            score: p.score,
            status: p.status,
            compliant: p.compliant,
            non_compliant: p.non_compliant,
            not_assessed: p.not_assessed
          }
        end),
        last_assessed: posture.last_assessed
      }
    })
  end

  @doc """
  List all supported compliance frameworks.
  """
  def list_frameworks(conn, _params) do
    case Compliance.list_frameworks() do
      {:ok, frameworks} ->
        json(conn, %{data: frameworks})

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Get compliance posture for a specific framework.

  ## Path Parameters
  - framework: Framework identifier (pci_dss, hipaa, soc2, nist_800_53, cis_benchmark, gdpr)
  """
  def framework_posture(conn, %{"framework" => framework_str}) do
    case compliance_safe_to_existing_atom(framework_str, @allowed_frameworks) do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid framework: #{framework_str}"})

      framework ->
        case Compliance.get_posture(framework) do
          {:ok, posture} ->
            json(conn, %{
              data: %{
                framework: framework,
                name: framework_name(framework),
                score: posture.score,
                status: posture.status,
                total_controls: posture.total_controls,
                compliant: posture.compliant,
                partial: posture.partial,
                non_compliant: posture.non_compliant,
                not_assessed: posture.not_assessed,
                last_assessed: posture.last_assessed,
                controls: Enum.map(posture.controls, fn c ->
                  %{
                    id: c.id,
                    title: c.title,
                    status: c.status,
                    severity: c.severity,
                    last_assessed: c.last_assessed
                  }
                end)
              }
            })

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  @doc """
  List controls for a framework.

  ## Path Parameters
  - framework: Framework identifier

  ## Query Parameters
  - status: Filter by status (compliant, partial, non_compliant, not_assessed)
  - severity: Filter by severity (critical, high, medium, low)
  - category: Filter by category
  """
  def list_controls(conn, %{"framework" => framework_str} = params) do
    case compliance_safe_to_existing_atom(framework_str, @allowed_frameworks) do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid framework"})

      framework ->
        controls = Compliance.get_controls(framework)

        # Apply filters
        filtered = controls
        |> maybe_filter_status(params["status"])
        |> maybe_filter_severity(params["severity"])
        |> maybe_filter_category(params["category"])

        json(conn, %{
          data: Enum.map(filtered, &serialize_control/1),
          meta: %{
            framework: framework,
            total: length(filtered)
          }
        })
    end
  end

  @doc """
  Get control details.

  ## Path Parameters
  - control_id: Control identifier
  """
  def control_detail(conn, %{"control_id" => control_id}) do
    case Compliance.get_control(control_id) do
      {:ok, control} ->
        assessments = Compliance.get_assessment_history(control_id, 5)
        evidence = Compliance.get_evidence(control_id)

        json(conn, %{
          data: %{
            control: serialize_control(control),
            assessment_history: Enum.map(assessments, &serialize_assessment/1),
            evidence: Enum.map(evidence, &serialize_evidence/1)
          }
        })

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Trigger assessment for a specific control.

  ## Path Parameters
  - control_id: Control identifier

  ## Body Parameters
  - manual_result: Manual assessment result (for non-automated controls)
  - findings: Assessment findings
  - evidence: Evidence references
  """
  def assess_control(conn, %{"control_id" => control_id} = params) do
    options = %{
      manual_result: params["manual_result"],
      findings: params["findings"],
      evidence: params["evidence"],
      assessed_by: get_current_user_id(conn)
    }

    case Compliance.assess_control(control_id, options) do
      {:ok, assessment} ->
        json(conn, %{
          data: serialize_assessment(assessment),
          message: "Assessment completed"
        })

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Collect evidence for a control.

  ## Path Parameters
  - control_id: Control identifier

  ## Body Parameters
  - evidence_type: Type of evidence to collect
  """
  def collect_evidence(conn, %{"control_id" => control_id, "evidence_type" => evidence_type}) do
    case compliance_safe_to_existing_atom(evidence_type, @allowed_evidence_types) do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid evidence type"})

      evidence_type_atom ->
        case Compliance.collect_evidence(control_id, evidence_type_atom) do
          {:ok, evidence} ->
            json(conn, %{
              data: serialize_evidence(evidence),
              message: "Evidence collected"
            })

          {:error, :invalid_evidence_type} ->
            conn
            |> put_status(:bad_request)
            |> json(%{error: "Invalid evidence type for this control"})

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  @doc """
  Generate a compliance report.

  ## Path Parameters
  - framework: Framework identifier

  ## Body Parameters
  - type: Report type (summary, detailed, audit)
  - period_start: Report period start (ISO8601)
  - period_end: Report period end (ISO8601)
  - format: Export format (json, pdf, csv)
  """
  def generate_report(conn, %{"framework" => framework_str} = params) do
    case compliance_safe_to_existing_atom(framework_str, @allowed_frameworks) do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid framework"})

      framework ->
        options = %{
          type:
            (params["type"] &&
               compliance_safe_to_existing_atom(params["type"], ~w(summary detailed audit))) ||
              :summary,
          period_start: parse_datetime(params["period_start"]) || DateTime.add(DateTime.utc_now(), -30, :day),
          period_end: parse_datetime(params["period_end"]) || DateTime.utc_now(),
          generated_by: get_current_user_id(conn)
        }

        case Compliance.generate_report(framework, options) do
          {:ok, report} ->
            json(conn, %{
              data: serialize_report(report),
              message: "Report generated"
            })

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  @doc """
  Export compliance data for audit.

  ## Path Parameters
  - framework: Framework identifier

  ## Query Parameters
  - period_start: Export period start
  - period_end: Export period end
  - format: Export format (json, pdf, csv)
  """
  def export_audit(conn, %{"framework" => framework_str} = params) do
    case compliance_safe_to_existing_atom(framework_str, @allowed_frameworks) do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid framework"})

      framework ->
        period_start = parse_datetime(params["period_start"]) || DateTime.add(DateTime.utc_now(), -365, :day)
        period_end = parse_datetime(params["period_end"]) || DateTime.utc_now()
        format =
          (params["format"] && compliance_safe_to_existing_atom(params["format"], ~w(json pdf csv))) ||
            :json

        case Compliance.export_for_audit(framework, period_start, period_end, format) do
          {:ok, data} ->
            content_type = case format do
              :json -> "application/json"
              :csv -> "text/csv"
              :pdf -> "application/pdf"
            end

            filename = "compliance_audit_#{framework}_#{Date.utc_today()}.#{format}"

            conn
            |> put_resp_content_type(content_type)
            |> put_resp_header("content-disposition", "attachment; filename=\"#{filename}\"")
            |> send_resp(200, data)

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  @doc """
  Get gap analysis for a framework.

  Returns non-compliant and partially compliant controls with remediation steps.
  """
  def gap_analysis(conn, %{"framework" => framework_str}) do
    case compliance_safe_to_existing_atom(framework_str, @allowed_frameworks) do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid framework"})

      framework ->
        controls = Compliance.get_controls(framework)

        gaps = Enum.filter(controls, fn c ->
          case :ets.lookup(:compliance_assessments, "latest_#{c.id}") do
            [{_, a}] -> a.status in [:non_compliant, :partial]
            [] -> true  # Not assessed = gap
          end
        end)

        json(conn, %{
          data: %{
            framework: framework,
            gap_count: length(gaps),
            gaps: Enum.map(gaps, fn control ->
              assessment = case :ets.lookup(:compliance_assessments, "latest_#{control.id}") do
                [{_, a}] -> a
                [] -> nil
              end

              %{
                control: serialize_control(control),
                current_status: (assessment && assessment.status) || :not_assessed,
                findings: (assessment && assessment.findings) || [],
                remediation_steps: control.remediation_steps,
                priority: priority_score(control.severity, assessment && assessment.status),
                effort_estimate: estimate_effort(control)
              }
            end)
            |> Enum.sort_by(& &1.priority, :desc)
          }
        })
    end
  end

  @doc """
  Get compliance dashboard statistics.
  """
  def dashboard(conn, _params) do
    posture = Compliance.get_overall_posture()

    # Calculate statistics
    frameworks_data = posture.frameworks
    |> Enum.map(fn {fw, p} ->
      %{
        framework: fw,
        name: framework_name(fw),
        score: p.score,
        status: p.status,
        critical_gaps: count_critical_gaps(fw)
      }
    end)

    json(conn, %{
      data: %{
        overall_score: posture.overall_score,
        trend: posture.trend,
        frameworks: frameworks_data,
        top_risks: get_top_risks(),
        recent_assessments: get_recent_assessments(10),
        upcoming_audits: get_upcoming_audits(),
        remediation_progress: get_remediation_progress()
      }
    })
  end

  # Private functions

  defp serialize_control(control) do
    %{
      id: control.id,
      framework: control.framework,
      control_id: control.control_id,
      title: control.title,
      description: control.description,
      category: control.category,
      severity: control.severity,
      automated: control.automated,
      evidence_types: control.evidence_types,
      remediation_steps: control.remediation_steps,
      status: control.status,
      last_assessed: control.last_assessed
    }
  end

  defp serialize_assessment(assessment) do
    %{
      id: assessment.id,
      control_id: assessment.control_id,
      status: assessment.status,
      score: assessment.score,
      findings: assessment.findings,
      assessed_at: assessment.assessed_at,
      assessed_by: assessment.assessed_by,
      expires_at: assessment.expires_at
    }
  end

  defp serialize_evidence(evidence) do
    %{
      id: evidence.id,
      control_id: evidence.control_id,
      type: evidence.type,
      title: evidence.title,
      description: evidence.description,
      source: evidence.source,
      hash: evidence.hash,
      collected_at: evidence.collected_at,
      retention_until: evidence.retention_until
    }
  end

  defp serialize_report(report) do
    %{
      id: report.id,
      framework: report.framework,
      report_type: report.report_type,
      period_start: report.period_start,
      period_end: report.period_end,
      generated_at: report.generated_at,
      generated_by: report.generated_by,
      overall_score: report.overall_score,
      control_summary: report.control_summary,
      findings: report.findings,
      recommendations: report.recommendations,
      evidence_summary: report.evidence_summary,
      export_formats: report.export_formats
    }
  end

  @valid_control_statuses ~w(compliant non_compliant partial unknown not_applicable)
  @valid_control_severities ~w(low medium high critical)
  @valid_control_categories ~w(access_control audit_logging encryption network data_protection identity monitoring incident_response)

  defp compliance_safe_to_existing_atom(value, allowed) when is_binary(value) do
    if value in allowed, do: allowed_atom(value), else: nil
  end
  defp compliance_safe_to_existing_atom(_, _), do: nil

  defp allowed_atom("pci_dss"), do: :pci_dss
  defp allowed_atom("hipaa"), do: :hipaa
  defp allowed_atom("soc2"), do: :soc2
  defp allowed_atom("nist_800_53"), do: :nist_800_53
  defp allowed_atom("iso_27001"), do: :iso_27001
  defp allowed_atom("cis_benchmark"), do: :cis_benchmark
  defp allowed_atom("gdpr"), do: :gdpr
  defp allowed_atom("log_review"), do: :log_review
  defp allowed_atom("access_control_test"), do: :access_control_test
  defp allowed_atom("encryption_check"), do: :encryption_check
  defp allowed_atom("network_scan"), do: :network_scan
  defp allowed_atom("vulnerability_scan"), do: :vulnerability_scan
  defp allowed_atom("configuration_audit"), do: :configuration_audit
  defp allowed_atom("policy_review"), do: :policy_review
  defp allowed_atom("summary"), do: :summary
  defp allowed_atom("detailed"), do: :detailed
  defp allowed_atom("audit"), do: :audit
  defp allowed_atom("json"), do: :json
  defp allowed_atom("pdf"), do: :pdf
  defp allowed_atom("csv"), do: :csv
  defp allowed_atom("compliant"), do: :compliant
  defp allowed_atom("non_compliant"), do: :non_compliant
  defp allowed_atom("partial"), do: :partial
  defp allowed_atom("unknown"), do: :unknown
  defp allowed_atom("not_applicable"), do: :not_applicable
  defp allowed_atom("low"), do: :low
  defp allowed_atom("medium"), do: :medium
  defp allowed_atom("high"), do: :high
  defp allowed_atom("critical"), do: :critical
  defp allowed_atom("access_control"), do: :access_control
  defp allowed_atom("audit_logging"), do: :audit_logging
  defp allowed_atom("encryption"), do: :encryption
  defp allowed_atom("network"), do: :network
  defp allowed_atom("data_protection"), do: :data_protection
  defp allowed_atom("identity"), do: :identity
  defp allowed_atom("monitoring"), do: :monitoring
  defp allowed_atom("incident_response"), do: :incident_response

  defp maybe_filter_status(controls, nil), do: controls
  defp maybe_filter_status(controls, status) do
    case compliance_safe_to_existing_atom(status, @valid_control_statuses) do
      nil -> controls
      status_atom -> Enum.filter(controls, & &1.status == status_atom)
    end
  end

  defp maybe_filter_severity(controls, nil), do: controls
  defp maybe_filter_severity(controls, severity) do
    case compliance_safe_to_existing_atom(severity, @valid_control_severities) do
      nil -> controls
      severity_atom -> Enum.filter(controls, & &1.severity == severity_atom)
    end
  end

  defp maybe_filter_category(controls, nil), do: controls
  defp maybe_filter_category(controls, category) do
    case compliance_safe_to_existing_atom(category, @valid_control_categories) do
      nil -> controls
      category_atom -> Enum.filter(controls, & &1.category == category_atom)
    end
  end

  defp parse_datetime(nil), do: nil
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp priority_score(severity, status) do
    severity_weight = case severity do
      :critical -> 100
      :high -> 75
      :medium -> 50
      :low -> 25
    end

    status_weight = case status do
      :non_compliant -> 1.0
      :partial -> 0.7
      :not_assessed -> 0.5
      _ -> 0.0
    end

    round(severity_weight * status_weight)
  end

  defp estimate_effort(control) do
    if control.automated do
      "Low - Automated remediation available"
    else
      case control.severity do
        :critical -> "High - Manual review required"
        :high -> "Medium - Policy/process changes needed"
        _ -> "Low - Minor adjustments"
      end
    end
  end

  defp count_critical_gaps(framework) do
    controls = Compliance.get_controls(framework)

    Enum.count(controls, fn c ->
      c.severity == :critical and c.status in [:non_compliant, :partial, :unknown]
    end)
  end

  defp get_top_risks do
    # Get highest priority compliance gaps
    []
  end

  defp get_recent_assessments(limit) do
    # Get recent assessment activities
    []
    |> Enum.take(limit)
  end

  defp get_upcoming_audits do
    # Get scheduled audits
    []
  end

  defp get_remediation_progress do
    %{
      in_progress: 0,
      completed_30d: 0,
      pending: 0
    }
  end

  defp framework_name(:pci_dss), do: "PCI-DSS 4.0"
  defp framework_name(:hipaa), do: "HIPAA Security Rule"
  defp framework_name(:soc2), do: "SOC 2 Type II"
  defp framework_name(:nist_800_53), do: "NIST 800-53"
  defp framework_name(:iso_27001), do: "ISO 27001"
  defp framework_name(:cis_benchmark), do: "CIS Controls"
  defp framework_name(:gdpr), do: "GDPR"
  defp framework_name(other), do: to_string(other)

  defp get_current_user_id(conn) do
    case conn.assigns[:current_user] do
      nil -> nil
      user -> user.id
    end
  end
end
