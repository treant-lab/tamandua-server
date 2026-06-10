defmodule TamanduaServerWeb.API.V1.ReportController do
  @moduledoc """
  Controller for report generation and management.

  Supports the following report types:
  - Executive Summary: High-level security posture overview
  - Incident Report: Detailed incident breakdown and timeline
  - Threat Report: Detailed threat analysis
  - Agent Health: Fleet status, version distribution, coverage
  - Detection Efficacy: Detection rule performance and coverage
  - Compliance Reports: PCI-DSS, HIPAA, SOC2, GDPR, NIST, CIS

  Also supports:
  - Report scheduling (daily, weekly, monthly)
  - Multiple output formats (PDF, HTML, CSV, JSON)
  - Email delivery
  """

  use TamanduaServerWeb, :controller

  require Logger

  alias TamanduaServer.Reports
  alias TamanduaServer.Reports.{Engine, Scheduler}

  action_fallback TamanduaServerWeb.FallbackController

  @report_templates %{
    "executive_summary" => "Executive Summary",
    "incident_report" => "Incident Report",
    "threat_report" => "Threat Report",
    "threat_landscape" => "Threat Landscape",
    "agent_health" => "Agent Health",
    "detection_efficacy" => "Detection Efficacy",
    "compliance_summary" => "Compliance Summary",
    "compliance_pci_dss" => "PCI-DSS 4.0 Compliance",
    "compliance_hipaa" => "HIPAA Security Rule",
    "compliance_soc2" => "SOC 2 Type II",
    "compliance_gdpr" => "GDPR Security",
    "compliance_nist" => "NIST CSF",
    "compliance_cis" => "CIS Controls v8",
    "custom" => "Custom Report"
  }

  @doc """
  Generate a report based on template and date range.

  ## Parameters
    - template_id: One of executive_summary, incident_report, threat_landscape, agent_health, compliance_summary
    - date_from: Start date in YYYY-MM-DD format
    - date_to: End date in YYYY-MM-DD format
  """
  def generate(conn, params) do
    template_id = params["template_id"]
    date_from = params["date_from"]
    date_to = params["date_to"]
    user = get_current_user(conn)

    # Validate template
    unless Map.has_key?(@report_templates, template_id) do
      conn
      |> put_status(:bad_request)
      |> json(%{error: "Invalid template_id. Must be one of: #{Map.keys(@report_templates) |> Enum.join(", ")}"})
    else
      # Validate dates
      with {:ok, _} <- Date.from_iso8601(date_from),
           {:ok, _} <- Date.from_iso8601(date_to) do
        report_data = Reports.generate_report(template_id, date_from, date_to, user)
        json(conn, %{data: report_data})
      else
        _ ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: "Invalid date format. Use YYYY-MM-DD."})
      end
    end
  end

  @doc """
  List report generation history.
  """
  def history(conn, params) do
    limit = Map.get(params, "limit", "50") |> parse_int(50)

    reports =
      try do
        Reports.list_history(limit)
      rescue
        e ->
          Logger.warning("[ReportController] history failed: #{Exception.message(e)}")
          []
      catch
        kind, reason ->
          Logger.warning("[ReportController] history caught #{inspect(kind)}: #{inspect(reason)}")
          []
      end

    json(conn, %{data: reports})
  end

  @doc """
  Alias for history - matches frontend API call.
  """
  def list(conn, params), do: history(conn, params)

  @doc """
  Get a specific report by ID.
  """
  def show(conn, %{"id" => id}) do
    report =
      try do
        Reports.get_report(id)
      rescue
        e ->
          Logger.warning("[ReportController] show failed: #{Exception.message(e)}")
          nil
      catch
        kind, reason ->
          Logger.warning("[ReportController] show caught #{inspect(kind)}: #{inspect(reason)}")
          nil
      end

    case report do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Report not found"})

      report ->
        json(conn, %{data: report})
    end
  end

  @doc """
  Download a report in the specified format.

  ## Parameters
    - id: Report ID
    - format: "pdf" or "csv" (default: "pdf")
  """
  def download(conn, %{"id" => id} = params) do
    format = Map.get(params, "format", "pdf")

    report =
      try do
        Reports.get_report(id)
      rescue
        e ->
          Logger.warning("[ReportController] download failed: #{Exception.message(e)}")
          nil
      catch
        kind, reason ->
          Logger.warning("[ReportController] download caught #{inspect(kind)}: #{inspect(reason)}")
          nil
      end

    case report do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Report not found"})

      report ->
        case format do
          "csv" ->
            csv_content = generate_csv(report)

            conn
            |> put_resp_content_type("text/csv")
            |> put_resp_header(
              "content-disposition",
              "attachment; filename=\"#{sanitize_filename(report["title"] || "report")}_#{Date.utc_today()}.csv\""
            )
            |> send_resp(200, csv_content)

          _ ->
            # For PDF, we return the report data and let the frontend handle PDF generation
            # (using browser print/PDF functionality)
            # In a production system, you'd use a PDF library here
            json(conn, %{
              data: report,
              message: "Use browser print functionality to save as PDF"
            })
        end
    end
  end

  @doc """
  List available report templates.
  """
  def templates(conn, _params) do
    # Try to get from Engine first for full details
    templates = try do
      Engine.list_templates()
    rescue
      e ->
        Logger.warning("[ReportController] templates failed: #{Exception.message(e)}")
        # Fallback to static list
        @report_templates
        |> Enum.map(fn {id, name} ->
          %{
            id: id,
            name: name,
            description: get_template_description(id),
            sections: get_template_sections(id),
            category: get_template_category(id),
            formats: [:pdf, :html, :csv, :json]
          }
        end)
    end

    json(conn, %{data: templates})
  end

  @doc """
  List all reports (alias for index).
  """
  def index(conn, params) do
    limit = Map.get(params, "limit", "50") |> parse_int(50)
    template_id = params["template_id"]

    filters = %{}
    |> maybe_add_filter(:template_id, template_id)
    |> maybe_add_filter(:limit, limit)

    reports = Reports.list_reports(filters)
    |> Enum.map(&serialize_report/1)

    json(conn, %{data: reports})
  end

  # ============================================================================
  # Scheduled Reports
  # ============================================================================

  @doc """
  List all scheduled reports.
  """
  def list_scheduled(conn, _params) do
    schedules = try do
      Scheduler.list_schedules()
      |> Enum.map(&serialize_schedule/1)
    rescue
      e ->
        Logger.warning("[ReportController] list_scheduled failed: #{Exception.message(e)}")
        []
    end

    json(conn, %{data: schedules})
  end

  @doc """
  Create a new scheduled report.
  """
  def create_schedule(conn, params) do
    opts = [
      name: params["name"],
      template_id: params["template_id"],
      schedule: params["schedule"],
      recipients: params["recipients"] || [],
      format: params["format"] || "pdf",
      params: params["params"] || %{},
      enabled: Map.get(params, "enabled", true),
      created_by: get_current_user_name(conn)
    ]

    case Scheduler.create_schedule(opts) do
      {:ok, schedule} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_schedule(schedule), message: "Schedule created"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to create schedule", details: format_errors(changeset)})
    end
  end

  @doc """
  Update a scheduled report.
  """
  def update_schedule(conn, %{"id" => id} = params) do
    opts = params
    |> Map.take(["name", "template_id", "schedule", "recipients", "format", "params", "enabled"])
    |> Enum.map(fn {k, v} ->
      key = try do
        String.to_existing_atom(k)
      rescue
        ArgumentError -> k
      end
      {key, v}
    end)
    |> Enum.into(%{})

    case Scheduler.update_schedule(id, opts) do
      {:ok, schedule} ->
        json(conn, %{data: serialize_schedule(schedule), message: "Schedule updated"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Schedule not found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to update schedule", details: format_errors(changeset)})
    end
  end

  @doc """
  Delete a scheduled report.
  """
  def delete_schedule(conn, %{"id" => id}) do
    case Scheduler.delete_schedule(id) do
      {:ok, _} ->
        json(conn, %{message: "Schedule deleted"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Schedule not found"})
    end
  end

  @doc """
  Get a scheduled report by ID.
  """
  def show_schedule(conn, %{"id" => id}) do
    case Scheduler.get_scheduled_report(id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Schedule not found"})

      schedule ->
        json(conn, %{data: serialize_schedule(schedule)})
    end
  end

  @doc """
  Run a scheduled report immediately.
  """
  def run_schedule(conn, %{"id" => id}) do
    case Scheduler.run_now(id) do
      :ok ->
        json(conn, %{message: "Report generation started"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Schedule not found"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to run report", details: inspect(reason)})
    end
  end

  @doc """
  Pause a scheduled report.
  """
  def pause_schedule(conn, %{"id" => id}) do
    case Scheduler.pause_schedule(id) do
      {:ok, schedule} ->
        json(conn, %{data: serialize_schedule(schedule), message: "Schedule paused"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Schedule not found"})
    end
  end

  @doc """
  Resume a paused scheduled report.
  """
  def resume_schedule(conn, %{"id" => id}) do
    case Scheduler.resume_schedule(id) do
      {:ok, schedule} ->
        json(conn, %{data: serialize_schedule(schedule), message: "Schedule resumed"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Schedule not found"})
    end
  end

  @doc """
  Get execution history for a scheduled report.
  """
  def schedule_history(conn, %{"id" => id} = params) do
    limit = Map.get(params, "limit", "20") |> parse_int(20)

    reports = Scheduler.get_history(id, limit)
    |> Enum.map(&serialize_report/1)

    json(conn, %{data: reports})
  end

  # ============================================================================
  # Advanced Generation
  # ============================================================================

  @doc """
  Generate a report using the Report Engine with format support.
  """
  def generate_advanced(conn, params) do
    template_id = params["template_id"]
    date_from = params["date_from"]
    date_to = params["date_to"]
    format = safe_to_existing_atom(params["format"] || "json", ~w(json pdf csv html)) || :json
    user = get_current_user(conn)

    opts = [
      date_from: date_from,
      date_to: date_to,
      format: format,
      user: user,
      params: params["params"] || %{}
    ]

    case Engine.generate(template_id, opts) do
      {:ok, result} ->
        case format do
          :json ->
            json(conn, %{data: result.data})

          :csv ->
            conn
            |> put_resp_content_type("text/csv")
            |> put_resp_header("content-disposition",
               "attachment; filename=\"#{sanitize_filename(result.data["title"])}_#{Date.utc_today()}.csv\"")
            |> send_resp(200, result.content)

          :html ->
            conn
            |> put_resp_content_type("text/html")
            |> send_resp(200, result.content)

          :pdf ->
            conn
            |> put_resp_content_type("application/pdf")
            |> put_resp_header("content-disposition",
               "attachment; filename=\"#{sanitize_filename(result.data["title"])}_#{Date.utc_today()}.pdf\"")
            |> send_resp(200, result.content)

          _ ->
            json(conn, %{data: result.data})
        end

      {:error, :unknown_template} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Unknown template: #{template_id}"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Report generation failed", details: inspect(reason)})
    end
  end

  # ---------------------------------------------------------------------------
  # Private Functions
  # ---------------------------------------------------------------------------

  defp get_current_user(conn) do
    conn.assigns[:current_user]
  end

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {num, _} -> num
      :error -> default
    end
  end

  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(_, default), do: default

  defp sanitize_filename(name) do
    name
    |> String.replace(~r/[^\w\s-]/, "")
    |> String.replace(~r/\s+/, "_")
    |> String.downcase()
  end

  defp generate_csv(report) do
    # Generate CSV from report sections
    lines = ["Tamandua EDR Report"]
    lines = lines ++ ["Title,#{report["title"] || "Report"}"]
    lines = lines ++ ["Generated,#{report["generated_at"] || DateTime.utc_now() |> DateTime.to_iso8601()}"]
    lines = lines ++ ["Period,#{get_in(report, ["period", "from"])} to #{get_in(report, ["period", "to"])}"]
    lines = lines ++ [""]

    sections = report["sections"] || []

    csv_lines =
      Enum.flat_map(sections, fn section ->
        section_lines = ["## #{section["title"]}"]

        content_lines =
          case section["type"] do
            "summary" ->
              [section["content"] || ""]

            "stats" ->
              stats = section["content"] || []

              stats
              |> Enum.map(fn stat ->
                "#{stat["label"]},#{stat["value"]}"
              end)

            "table" ->
              table = section["content"] || %{}
              headers = table["headers"] || []
              rows = table["rows"] || []

              [Enum.join(headers, ",")] ++
                Enum.map(rows, fn row -> Enum.join(row, ",") end)

            "list" ->
              items = section["content"] || []
              Enum.map(items, fn item -> "- #{item}" end)

            _ ->
              [inspect(section["content"])]
          end

        section_lines ++ content_lines ++ [""]
      end)

    (lines ++ csv_lines)
    |> Enum.join("\n")
  end

  defp get_template_description("executive_summary"),
    do:
      "High-level overview of security posture, key metrics, and critical incidents for leadership review."

  defp get_template_description("incident_report"),
    do:
      "Detailed breakdown of security incidents, response actions taken, and resolution timeline."

  defp get_template_description("threat_landscape"),
    do:
      "Analysis of detected threats, attack patterns, and threat actor activity observed in the environment."

  defp get_template_description("agent_health"),
    do:
      "Status and health metrics for all deployed agents, including uptime, version, and coverage gaps."

  defp get_template_description("compliance_summary"),
    do: "Compliance status against security policies, detection coverage, and audit trail summary."

  defp get_template_description("threat_report"),
    do: "Detailed threat analysis including attack patterns, IOCs, and MITRE ATT&CK mapping."

  defp get_template_description("detection_efficacy"),
    do: "Analysis of detection rule performance, coverage statistics, and false positive rates."

  defp get_template_description("compliance_pci_dss"),
    do: "PCI-DSS 4.0 compliance assessment mapping EDR controls to payment security requirements."

  defp get_template_description("compliance_hipaa"),
    do: "HIPAA Security Rule compliance assessment for PHI protection requirements."

  defp get_template_description("compliance_soc2"),
    do: "SOC 2 Type II compliance assessment for Trust Service Criteria."

  defp get_template_description("compliance_gdpr"),
    do: "GDPR Article 32 compliance assessment for security of processing."

  defp get_template_description("compliance_nist"),
    do: "NIST Cybersecurity Framework compliance assessment."

  defp get_template_description("compliance_cis"),
    do: "CIS Controls v8 compliance assessment with Implementation Group mapping."

  defp get_template_description(_), do: "Custom report template."

  defp get_template_sections("executive_summary"),
    do: ["Security Score", "Critical Incidents", "Agent Coverage", "Top Threats", "Recommendations"]

  defp get_template_sections("incident_report"),
    do: ["Incident Timeline", "Affected Assets", "MITRE ATT&CK Mapping", "Response Actions", "Lessons Learned"]

  defp get_template_sections("threat_report"),
    do: ["Threat Overview", "Attack Vectors", "MITRE Techniques", "IOC Summary", "Trend Analysis"]

  defp get_template_sections("threat_landscape"),
    do: ["Threat Overview", "Attack Vectors", "IOC Summary", "Threat Actor Activity", "Trend Analysis"]

  defp get_template_sections("agent_health"),
    do: ["Agent Status", "Version Distribution", "Coverage Gaps", "Performance Metrics", "Offline Agents"]

  defp get_template_sections("detection_efficacy"),
    do: ["Detection Statistics", "Rule Performance", "MITRE Coverage", "False Positives", "Recommendations"]

  defp get_template_sections("compliance_summary"),
    do: ["Policy Compliance", "Detection Coverage", "Audit Events", "Configuration Status", "Remediation Items"]

  defp get_template_sections("compliance_pci_dss"),
    do: ["Req 1: Network", "Req 5: Malware", "Req 10: Logging", "Req 11: Testing", "Gap Analysis"]

  defp get_template_sections("compliance_hipaa"),
    do: ["Administrative Safeguards", "Physical Safeguards", "Technical Safeguards", "Gap Analysis"]

  defp get_template_sections("compliance_soc2"),
    do: ["Security (CC)", "Availability (A)", "Confidentiality (C)", "Gap Analysis"]

  defp get_template_sections("compliance_gdpr"),
    do: ["Article 32", "Article 33", "Technical Measures", "Organizational Measures", "Gap Analysis"]

  defp get_template_sections("compliance_nist"),
    do: ["Identify", "Protect", "Detect", "Respond", "Recover", "Gap Analysis"]

  defp get_template_sections("compliance_cis"),
    do: ["Asset Inventory", "Malware Defenses", "Audit Logs", "Incident Response", "Gap Analysis"]

  defp get_template_sections("custom"),
    do: ["Executive Summary", "Alert Statistics", "Threat Overview", "Agent Health", "Detection Coverage", "Compliance Status", "Timeline", "Recommendations"]

  defp get_template_sections(_), do: []

  defp get_template_category("custom"), do: "custom"
  defp get_template_category("compliance_" <> _), do: "compliance"
  defp get_template_category("executive_summary"), do: "security"
  defp get_template_category("incident_report"), do: "security"
  defp get_template_category("threat_report"), do: "security"
  defp get_template_category("threat_landscape"), do: "security"
  defp get_template_category("detection_efficacy"), do: "security"
  defp get_template_category("agent_health"), do: "operations"
  defp get_template_category(_), do: "other"

  defp maybe_add_filter(filters, _key, nil), do: filters
  defp maybe_add_filter(filters, key, value), do: Map.put(filters, key, value)

  defp get_current_user_name(conn) do
    case conn.assigns[:current_user] do
      nil -> "System"
      user -> user.name || user.email || "Unknown"
    end
  end

  defp serialize_report(report) do
    %{
      id: report.id,
      template_id: report.template_id,
      template_name: @report_templates[report.template_id] || report.template_id,
      date_from: report.date_from,
      date_to: report.date_to,
      status: report.status,
      generated_by: report.generated_by,
      created_at: report.inserted_at,
      data: report.data
    }
  end

  defp serialize_schedule(schedule) do
    %{
      id: schedule.id,
      name: schedule.name,
      template_id: schedule.template_id,
      template_name: @report_templates[schedule.template_id] || schedule.template_id,
      schedule: schedule.schedule,
      schedule_description: describe_schedule(schedule.schedule),
      recipients: schedule.recipients,
      format: schedule.format,
      params: schedule.params,
      enabled: schedule.enabled,
      last_run_at: schedule.last_run_at,
      next_run_at: schedule.next_run_at,
      created_by: schedule.created_by,
      created_at: schedule.inserted_at
    }
  end

  defp describe_schedule("0 6 * * *"), do: "Daily at 6:00 AM"
  defp describe_schedule("0 6 * * 1"), do: "Weekly on Monday at 6:00 AM"
  defp describe_schedule("0 6 1 * *"), do: "Monthly on the 1st at 6:00 AM"
  defp describe_schedule(cron), do: "Cron: #{cron}"

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
  defp format_errors(error), do: inspect(error)

end
