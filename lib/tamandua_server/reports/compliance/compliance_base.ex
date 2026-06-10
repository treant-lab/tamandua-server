defmodule TamanduaServer.Reports.Compliance.ComplianceBase do
  @moduledoc """
  Base module for compliance report templates.

  Provides common functionality for all compliance frameworks including:
  - Control status evaluation
  - Evidence collection
  - Gap analysis
  - Score calculation
  """

  alias TamanduaServer.{Agents, Alerts, Detection}
  alias TamanduaServer.Detection.IOCs

  @doc """
  Evaluates the status of a control based on available evidence.

  Returns one of: :compliant, :partial, :non_compliant, :not_assessed
  """
  def evaluate_control_status(control_id, evidence_checks) do
    results = Enum.map(evidence_checks, fn check ->
      check.()
    end)

    passed = Enum.count(results, & &1 == :pass)
    failed = Enum.count(results, & &1 == :fail)
    total = length(results)

    cond do
      total == 0 -> :not_assessed
      passed == total -> :compliant
      passed > 0 -> :partial
      true -> :non_compliant
    end
  end

  @doc """
  Calculates overall compliance score for a framework.
  """
  def calculate_compliance_score(controls) do
    total = length(controls)
    if total == 0 do
      0
    else
      compliant = Enum.count(controls, & &1.status == :compliant)
      partial = Enum.count(controls, & &1.status == :partial)

      # Full points for compliant, half for partial
      score = (compliant * 100 + partial * 50) / total
      Float.round(score, 1)
    end
  end

  @doc """
  Gets common security metrics used across compliance frameworks.
  """
  def get_security_metrics do
    %{
      total_agents: safe_call(fn -> Agents.count_all() end, 0),
      online_agents: safe_call(fn -> Agents.count_online() end, 0),
      total_alerts: safe_call(fn -> Alerts.count_open() end, 0),
      critical_alerts: safe_call(fn -> Alerts.count_by_severity(:critical) end, 0),
      sigma_rules: safe_call(fn -> Detection.count_sigma_rules() end, 0),
      yara_rules: safe_call(fn -> Detection.count_yara_rules() end, 0),
      total_iocs: safe_call(fn -> IOCs.count(enabled: true) end, 0)
    }
  end

  @doc """
  Checks if endpoint protection is deployed (common compliance requirement).
  """
  def check_endpoint_protection do
    metrics = get_security_metrics()
    coverage = if metrics.total_agents > 0 do
      metrics.online_agents / metrics.total_agents * 100
    else
      0
    end

    cond do
      coverage >= 95 -> :pass
      coverage >= 80 -> :partial
      true -> :fail
    end
  end

  @doc """
  Checks if detection rules are configured.
  """
  def check_detection_rules do
    metrics = get_security_metrics()
    total_rules = metrics.sigma_rules + metrics.yara_rules

    cond do
      total_rules >= 100 -> :pass
      total_rules >= 50 -> :partial
      true -> :fail
    end
  end

  @doc """
  Checks if logging is enabled (assumes logging is enabled if agents report).
  """
  def check_logging_enabled do
    metrics = get_security_metrics()
    if metrics.online_agents > 0, do: :pass, else: :fail
  end

  @doc """
  Checks if incident response process is in place.
  """
  def check_incident_response do
    # Check if alerts are being processed
    metrics = get_security_metrics()
    resolved = safe_call(fn -> Alerts.count_by_status("resolved") end, 0)

    cond do
      resolved > 0 -> :pass
      metrics.total_alerts == 0 -> :pass
      true -> :partial
    end
  end

  @doc """
  Formats a control for report output.
  """
  def format_control(control) do
    status_label = case control.status do
      :compliant -> "Compliant"
      :partial -> "Partial"
      :non_compliant -> "Non-Compliant"
      :not_assessed -> "Not Assessed"
      _ -> "Unknown"
    end

    [
      control.id,
      control.title,
      status_label,
      control.severity || "Medium",
      control.evidence || "N/A"
    ]
  end

  @doc """
  Builds gap analysis for non-compliant controls.
  """
  def build_gap_analysis(controls) do
    controls
    |> Enum.filter(fn c -> c.status in [:non_compliant, :partial, :not_assessed] end)
    |> Enum.sort_by(fn c ->
      priority = case c.severity do
        "Critical" -> 1
        "High" -> 2
        "Medium" -> 3
        "Low" -> 4
        _ -> 5
      end
      {priority, c.id}
    end)
    |> Enum.map(fn c ->
      [
        c.id,
        c.title,
        format_status(c.status),
        c.remediation || "Review and implement control requirements"
      ]
    end)
  end

  defp format_status(:compliant), do: "Compliant"
  defp format_status(:partial), do: "Partial"
  defp format_status(:non_compliant), do: "Non-Compliant"
  defp format_status(:not_assessed), do: "Not Assessed"
  defp format_status(_), do: "Unknown"

  @doc """
  Safe function call with default fallback.
  """
  def safe_call(fun, default) do
    try do
      fun.()
    rescue
      _ -> default
    catch
      _, _ -> default
    end
  end
end
