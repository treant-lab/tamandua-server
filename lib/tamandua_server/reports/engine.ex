defmodule TamanduaServer.Reports.Engine do
  @moduledoc """
  Report Generation Engine for Tamandua EDR.

  Provides template-based report generation with support for multiple output formats:
  - PDF (via ChromicPDF)
  - HTML (styled, print-ready)
  - CSV (tabular data export)
  - JSON (machine-readable)

  Features:
  - Template-based generation with pluggable templates
  - Scheduled report execution (daily, weekly, monthly)
  - Email delivery via Swoosh
  - Report history and storage
  - Chart generation for visual reports
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Reports
  alias TamanduaServer.Reports.{Report, Scheduler}
  alias TamanduaServer.Mailer

  import Swoosh.Email

  @templates %{
    # Standard reports
    "executive_summary" => TamanduaServer.Reports.Templates.ExecutiveSummary,
    "threat_report" => TamanduaServer.Reports.Templates.ThreatReport,
    "incident_report" => TamanduaServer.Reports.Templates.IncidentReport,
    "agent_health" => TamanduaServer.Reports.Templates.AgentHealth,
    "detection_efficacy" => TamanduaServer.Reports.Templates.DetectionEfficacy,

    # Compliance reports
    "compliance_pci_dss" => TamanduaServer.Reports.Compliance.PCIDSS,
    "compliance_hipaa" => TamanduaServer.Reports.Compliance.HIPAA,
    "compliance_soc2" => TamanduaServer.Reports.Compliance.SOC2,
    "compliance_gdpr" => TamanduaServer.Reports.Compliance.GDPR,
    "compliance_nist" => TamanduaServer.Reports.Compliance.NIST,
    "compliance_cis" => TamanduaServer.Reports.Compliance.CIS,

    # Custom reports
    "custom" => TamanduaServer.Reports.Templates.Custom
  }

  @supported_formats [:pdf, :html, :csv, :json]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Generate a report from a template.

  ## Options
  - `:date_from` - Start date (required)
  - `:date_to` - End date (required)
  - `:format` - Output format (:pdf, :html, :csv, :json). Default: :json
  - `:user` - User generating the report
  - `:organization_id` - Organization scope
  - `:params` - Additional template-specific parameters
  """
  def generate(template_id, opts \\ []) do
    with {:ok, template} <- get_template(template_id),
         :ok <- validate_options(opts) do
      GenServer.call(__MODULE__, {:generate, template_id, template, opts}, 120_000)
    end
  end

  @doc """
  Generate a report asynchronously.
  Returns {:ok, job_id} for tracking.
  """
  def generate_async(template_id, opts \\ []) do
    GenServer.call(__MODULE__, {:generate_async, template_id, opts})
  end

  @doc """
  Get the status of an async report generation job.
  """
  def get_job_status(job_id) do
    GenServer.call(__MODULE__, {:job_status, job_id})
  end

  @doc """
  List all available report templates.
  """
  def list_templates do
    @templates
    |> Enum.map(fn {id, module} ->
      %{
        id: id,
        name: module.name(),
        description: module.description(),
        category: module.category(),
        sections: module.sections(),
        parameters: module.parameters(),
        formats: module.supported_formats()
      }
    end)
    |> Enum.sort_by(& &1.category)
  end

  @doc """
  Get a specific template's metadata.
  """
  def get_template_info(template_id) do
    case get_template(template_id) do
      {:ok, module} ->
        {:ok, %{
          id: template_id,
          name: module.name(),
          description: module.description(),
          category: module.category(),
          sections: module.sections(),
          parameters: module.parameters(),
          formats: module.supported_formats()
        }}
      error -> error
    end
  end

  @doc """
  Convert a report to a specific format.
  """
  def convert_to_format(report_data, format) when format in @supported_formats do
    case format do
      :json -> {:ok, Jason.encode!(report_data, pretty: true)}
      :csv -> {:ok, convert_to_csv(report_data)}
      :html -> {:ok, convert_to_html(report_data)}
      :pdf -> convert_to_pdf(report_data)
    end
  end

  @doc """
  Send a report via email.
  """
  def email_report(report_data, recipients, opts \\ []) do
    GenServer.call(__MODULE__, {:email_report, report_data, recipients, opts})
  end

  @doc """
  Get supported output formats.
  """
  def supported_formats, do: @supported_formats

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Initialize ETS table for job tracking
    :ets.new(:report_jobs, [:named_table, :public, read_concurrency: true])

    {:ok, %{jobs: %{}}}
  end

  @impl true
  def handle_call({:generate, template_id, template, opts}, _from, state) do
    result = do_generate(template_id, template, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:generate_async, template_id, opts}, _from, state) do
    job_id = generate_job_id()

    # Store initial job status
    :ets.insert(:report_jobs, {job_id, %{
      status: :pending,
      template_id: template_id,
      started_at: DateTime.utc_now(),
      progress: 0,
      report_id: nil,
      error: nil
    }})

    # Spawn async task
    Task.start(fn ->
      case get_template(template_id) do
        {:ok, template} ->
          :ets.update_element(:report_jobs, job_id, {2, %{
            status: :running,
            template_id: template_id,
            started_at: DateTime.utc_now(),
            progress: 10,
            report_id: nil,
            error: nil
          }})

          case do_generate(template_id, template, opts) do
            {:ok, report} ->
              :ets.update_element(:report_jobs, job_id, {2, %{
                status: :completed,
                template_id: template_id,
                started_at: DateTime.utc_now(),
                progress: 100,
                report_id: report.id,
                error: nil
              }})

            {:error, reason} ->
              :ets.update_element(:report_jobs, job_id, {2, %{
                status: :failed,
                template_id: template_id,
                started_at: DateTime.utc_now(),
                progress: 0,
                report_id: nil,
                error: inspect(reason)
              }})
          end

        {:error, reason} ->
          :ets.update_element(:report_jobs, job_id, {2, %{
            status: :failed,
            template_id: template_id,
            started_at: DateTime.utc_now(),
            progress: 0,
            report_id: nil,
            error: inspect(reason)
          }})
      end
    end)

    {:reply, {:ok, job_id}, state}
  end

  @impl true
  def handle_call({:job_status, job_id}, _from, state) do
    result = case :ets.lookup(:report_jobs, job_id) do
      [{^job_id, status}] -> {:ok, status}
      [] -> {:error, :not_found}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:email_report, report_data, recipients, opts}, _from, state) do
    result = do_email_report(report_data, recipients, opts)
    {:reply, result, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp get_template(template_id) do
    case Map.get(@templates, template_id) do
      nil -> {:error, :unknown_template}
      module -> {:ok, module}
    end
  end

  defp validate_options(opts) do
    with {:ok, _} <- validate_date(opts[:date_from]),
         {:ok, _} <- validate_date(opts[:date_to]) do
      :ok
    end
  end

  defp validate_date(nil), do: {:error, :missing_date}
  defp validate_date(date) when is_binary(date) do
    case Date.from_iso8601(date) do
      {:ok, _} -> {:ok, date}
      _ -> {:error, :invalid_date_format}
    end
  end
  defp validate_date(%Date{} = date), do: {:ok, Date.to_iso8601(date)}
  defp validate_date(_), do: {:error, :invalid_date}

  defp do_generate(template_id, template_module, opts) do
    date_from = opts[:date_from]
    date_to = opts[:date_to]
    format = opts[:format] || :json
    user = opts[:user]
    params = opts[:params] || %{}

    Logger.info("Generating report: #{template_id} (#{date_from} to #{date_to})")

    try do
      # Generate report data using template
      report_data = template_module.generate(date_from, date_to, params)

      # Add metadata
      report_data = Map.merge(report_data, %{
        "id" => Ecto.UUID.generate(),
        "template_id" => template_id,
        "template_name" => template_module.name(),
        "generated_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
        "generated_by" => user_name(user),
        "period" => %{"from" => date_from, "to" => date_to},
        "format" => to_string(format)
      })

      # Convert to requested format
      {:ok, formatted_content} = convert_to_format(report_data, format)

      # Store in database
      {:ok, stored_report} = store_report(template_id, date_from, date_to, user, report_data)

      {:ok, %{
        id: stored_report.id,
        template_id: template_id,
        format: format,
        data: report_data,
        content: formatted_content,
        generated_at: DateTime.utc_now()
      }}
    rescue
      e ->
        Logger.error("Report generation failed: #{inspect(e)}")
        {:error, :generation_failed}
    end
  end

  defp store_report(template_id, date_from, date_to, user, data) do
    Reports.create_report(%{
      template_id: template_id,
      date_from: date_from,
      date_to: date_to,
      generated_by: user_name(user),
      user_id: user && user.id,
      status: "ready",
      data: data
    })
  end

  defp user_name(nil), do: "System"
  defp user_name(user) when is_map(user), do: user[:name] || user[:email] || user.name || user.email || "Unknown"
  defp user_name(_), do: "Unknown"

  defp generate_job_id do
    "job_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end

  # ============================================================================
  # Format Converters
  # ============================================================================

  defp convert_to_csv(report_data) do
    lines = ["# #{report_data["title"] || "Tamandua EDR Report"}"]
    lines = lines ++ ["# Generated: #{report_data["generated_at"]}"]
    lines = lines ++ ["# Period: #{get_in(report_data, ["period", "from"])} to #{get_in(report_data, ["period", "to"])}"]
    lines = lines ++ [""]

    sections = report_data["sections"] || []

    csv_lines = Enum.flat_map(sections, fn section ->
      section_header = ["## #{section["title"]}"]

      content_lines = case section["type"] do
        "summary" ->
          [section["content"] || ""]

        "stats" ->
          stats = section["content"] || []
          header = ["Label", "Value"]
          rows = Enum.map(stats, fn stat ->
            [stat["label"] || "", to_string(stat["value"] || "")]
          end)
          [Enum.join(header, ",")] ++ Enum.map(rows, &Enum.join(&1, ","))

        "table" ->
          table = section["content"] || %{}
          headers = table["headers"] || []
          rows = table["rows"] || []
          [Enum.join(headers, ",")] ++
            Enum.map(rows, fn row ->
              row
              |> Enum.map(&escape_csv_field/1)
              |> Enum.join(",")
            end)

        "list" ->
          items = section["content"] || []
          Enum.map(items, fn item -> "- #{item}" end)

        "chart" ->
          chart = section["content"] || %{}
          data = chart["data"] || []
          labels = chart["labels"] || []
          [Enum.join(["Label", "Value"], ",")] ++
            Enum.zip(labels, data)
            |> Enum.map(fn {label, value} -> "#{label},#{value}" end)

        _ ->
          [inspect(section["content"])]
      end

      section_header ++ content_lines ++ [""]
    end)

    (lines ++ csv_lines) |> Enum.join("\n")
  end

  defp escape_csv_field(nil), do: ""
  defp escape_csv_field(field) when is_binary(field) do
    if String.contains?(field, [",", "\"", "\n"]) do
      "\"#{String.replace(field, "\"", "\"\"")}\""
    else
      field
    end
  end
  defp escape_csv_field(field), do: to_string(field)

  defp convert_to_html(report_data) do
    title = report_data["title"] || "Tamandua EDR Report"
    generated_at = report_data["generated_at"]
    period = report_data["period"] || %{}
    sections = report_data["sections"] || []

    sections_html = Enum.map(sections, &render_section_html/1) |> Enum.join("\n")

    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>#{title}</title>
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
          line-height: 1.6;
          color: #1a1a2e;
          background: #f8f9fa;
          padding: 2rem;
        }
        .report {
          max-width: 1000px;
          margin: 0 auto;
          background: white;
          padding: 3rem;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
          border-bottom: 2px solid #0066cc;
          padding-bottom: 1.5rem;
          margin-bottom: 2rem;
        }
        .logo {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          margin-bottom: 1rem;
        }
        .logo svg { width: 32px; height: 32px; fill: #0066cc; }
        .logo span { font-size: 1.5rem; font-weight: 700; color: #1a1a2e; }
        h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        .meta { color: #666; font-size: 0.9rem; }
        .meta span { margin-right: 1.5rem; }
        .section { margin-bottom: 2rem; }
        h2 {
          font-size: 1.25rem;
          border-bottom: 1px solid #eee;
          padding-bottom: 0.5rem;
          margin-bottom: 1rem;
          color: #1a1a2e;
        }
        .summary { color: #444; line-height: 1.8; }
        .stats {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 1rem;
        }
        .stat {
          background: #f8f9fa;
          padding: 1rem;
          border-radius: 6px;
          border-left: 3px solid #0066cc;
        }
        .stat-value { font-size: 1.75rem; font-weight: 700; color: #1a1a2e; }
        .stat-label { font-size: 0.85rem; color: #666; margin-top: 0.25rem; }
        .stat-change { font-size: 0.75rem; margin-top: 0.25rem; }
        .stat-change.positive { color: #28a745; }
        .stat-change.negative { color: #dc3545; }
        table {
          width: 100%;
          border-collapse: collapse;
          font-size: 0.9rem;
        }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; color: #1a1a2e; }
        tr:hover { background: #fafafa; }
        .list { padding-left: 1.5rem; }
        .list li { margin-bottom: 0.5rem; color: #444; }
        .chart-container { padding: 1rem; background: #f8f9fa; border-radius: 6px; }
        .footer {
          border-top: 1px solid #eee;
          padding-top: 1.5rem;
          margin-top: 2rem;
          font-size: 0.8rem;
          color: #999;
        }
        @media print {
          body { background: white; padding: 0; }
          .report { box-shadow: none; padding: 0; }
        }
      </style>
    </head>
    <body>
      <div class="report">
        <div class="header">
          <div class="logo">
            <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
            <span>Tamandua EDR</span>
          </div>
          <h1>#{title}</h1>
          <div class="meta">
            <span>Period: #{period["from"]} to #{period["to"]}</span>
            <span>Generated: #{format_datetime_html(generated_at)}</span>
            #{if report_data["generated_by"], do: "<span>By: #{report_data["generated_by"]}</span>", else: ""}
          </div>
        </div>

        #{sections_html}

        <div class="footer">
          <p>This report was generated by Tamandua EDR. Confidential - Do not distribute without authorization.</p>
          <p>Report ID: #{report_data["id"]} | Template: #{report_data["template_id"]}</p>
        </div>
      </div>
    </body>
    </html>
    """
  end

  defp render_section_html(%{"type" => "summary", "title" => title, "content" => content}) do
    """
    <div class="section">
      <h2>#{title}</h2>
      <p class="summary">#{content}</p>
    </div>
    """
  end

  defp render_section_html(%{"type" => "stats", "title" => title, "content" => stats}) do
    stats_html = Enum.map(stats, fn stat ->
      change_html = if stat["change"] do
        class = if String.starts_with?(to_string(stat["change"]), "+"), do: "negative", else: "positive"
        ~s(<div class="stat-change #{class}">#{stat["change"]} from previous period</div>)
      else
        ""
      end

      """
      <div class="stat">
        <div class="stat-value">#{stat["value"]}</div>
        <div class="stat-label">#{stat["label"]}</div>
        #{change_html}
      </div>
      """
    end) |> Enum.join("\n")

    """
    <div class="section">
      <h2>#{title}</h2>
      <div class="stats">#{stats_html}</div>
    </div>
    """
  end

  defp render_section_html(%{"type" => "table", "title" => title, "content" => table}) do
    headers = table["headers"] || []
    rows = table["rows"] || []

    headers_html = Enum.map(headers, &"<th>#{&1}</th>") |> Enum.join("")
    rows_html = Enum.map(rows, fn row ->
      cells = Enum.map(row, &"<td>#{&1}</td>") |> Enum.join("")
      "<tr>#{cells}</tr>"
    end) |> Enum.join("\n")

    """
    <div class="section">
      <h2>#{title}</h2>
      <table>
        <thead><tr>#{headers_html}</tr></thead>
        <tbody>#{rows_html}</tbody>
      </table>
    </div>
    """
  end

  defp render_section_html(%{"type" => "list", "title" => title, "content" => items}) do
    items_html = Enum.map(items, &"<li>#{&1}</li>") |> Enum.join("\n")

    """
    <div class="section">
      <h2>#{title}</h2>
      <ul class="list">#{items_html}</ul>
    </div>
    """
  end

  defp render_section_html(%{"type" => "chart", "title" => title, "content" => chart}) do
    # For HTML, we render chart data as a simple bar representation
    # In PDF, this would be rendered as actual charts
    data = chart["data"] || []
    labels = chart["labels"] || []
    max_val = Enum.max(data, fn -> 1 end)

    bars_html = Enum.zip(labels, data)
    |> Enum.map(fn {label, value} ->
      width = if max_val > 0, do: round(value / max_val * 100), else: 0
      """
      <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
        <div style="width: 120px; font-size: 0.85rem;">#{label}</div>
        <div style="flex: 1; background: #eee; border-radius: 4px; height: 20px; margin: 0 1rem;">
          <div style="background: #0066cc; width: #{width}%; height: 100%; border-radius: 4px;"></div>
        </div>
        <div style="width: 50px; text-align: right; font-size: 0.85rem;">#{value}</div>
      </div>
      """
    end) |> Enum.join("\n")

    """
    <div class="section">
      <h2>#{title}</h2>
      <div class="chart-container">#{bars_html}</div>
    </div>
    """
  end

  defp render_section_html(%{"title" => title, "content" => content}) do
    """
    <div class="section">
      <h2>#{title}</h2>
      <p class="summary">#{inspect(content)}</p>
    </div>
    """
  end

  defp format_datetime_html(nil), do: "N/A"
  defp format_datetime_html(datetime_str) when is_binary(datetime_str) do
    case DateTime.from_iso8601(datetime_str) do
      {:ok, dt, _} -> Calendar.strftime(dt, "%B %d, %Y at %H:%M UTC")
      _ -> datetime_str
    end
  end
  defp format_datetime_html(_), do: "N/A"

  defp convert_to_pdf(report_data) do
    # Use the dedicated PDFGenerator for professional reports
    alias TamanduaServer.Reports.PDFGenerator

    case PDFGenerator.generate(report_data, format: :executive) do
      {:ok, pdf_binary} ->
        {:ok, pdf_binary}

      {:error, reason} ->
        # Fallback to basic HTML-to-PDF conversion
        Logger.warning("PDFGenerator failed, falling back to basic conversion: #{inspect(reason)}")
        html = convert_to_html(report_data)

        case ChromicPDF.print_to_pdf({:html, html}, [
          print_to_pdf: %{
            preferCSSPageSize: true,
            printBackground: true,
            marginTop: "1cm",
            marginBottom: "1cm",
            marginLeft: "1cm",
            marginRight: "1cm"
          }
        ]) do
          {:ok, pdf_binary} -> {:ok, pdf_binary}
          {:error, err} -> {:error, {:pdf_generation_failed, err}}
        end
    end
  end

  # ============================================================================
  # Email Functions
  # ============================================================================

  defp do_email_report(report_data, recipients, opts) do
    subject = opts[:subject] || "Tamandua EDR Report: #{report_data["title"]}"
    format = opts[:format] || :pdf

    # Generate attachment
    {:ok, attachment_content} = convert_to_format(report_data, format)

    filename = "#{sanitize_filename(report_data["title"] || "report")}_#{Date.utc_today()}.#{format}"
    content_type = case format do
      :pdf -> "application/pdf"
      :html -> "text/html"
      :csv -> "text/csv"
      :json -> "application/json"
    end

    # Build email
    email = new()
    |> to(recipients)
    |> from({"Tamandua EDR", "noreply@tamandua.local"})
    |> subject(subject)
    |> html_body(email_body_html(report_data))
    |> text_body(email_body_text(report_data))
    |> attachment(
      Swoosh.Attachment.new(
        {:data, attachment_content},
        filename: filename,
        content_type: content_type
      )
    )

    # Send email
    case Mailer.deliver(email) do
      {:ok, _} ->
        Logger.info("Report email sent to #{length(List.wrap(recipients))} recipient(s)")
        {:ok, :sent}

      {:error, reason} ->
        Logger.error("Failed to send report email: #{inspect(reason)}")
        {:error, {:email_failed, reason}}
    end
  end

  defp email_body_html(report_data) do
    """
    <html>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #333;">
      <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #0066cc;">#{report_data["title"]}</h2>
        <p>A new report has been generated from Tamandua EDR.</p>

        <table style="width: 100%; margin: 20px 0; border-collapse: collapse;">
          <tr>
            <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Report Type:</strong></td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">#{report_data["template_name"]}</td>
          </tr>
          <tr>
            <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Period:</strong></td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">#{get_in(report_data, ["period", "from"])} to #{get_in(report_data, ["period", "to"])}</td>
          </tr>
          <tr>
            <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Generated:</strong></td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">#{report_data["generated_at"]}</td>
          </tr>
          <tr>
            <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Generated By:</strong></td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">#{report_data["generated_by"]}</td>
          </tr>
        </table>

        <p>The full report is attached to this email.</p>

        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="font-size: 12px; color: #999;">
          This is an automated message from Tamandua EDR.<br>
          Do not reply to this email.
        </p>
      </div>
    </body>
    </html>
    """
  end

  defp email_body_text(report_data) do
    """
    #{report_data["title"]}

    A new report has been generated from Tamandua EDR.

    Report Type: #{report_data["template_name"]}
    Period: #{get_in(report_data, ["period", "from"])} to #{get_in(report_data, ["period", "to"])}
    Generated: #{report_data["generated_at"]}
    Generated By: #{report_data["generated_by"]}

    The full report is attached to this email.

    --
    This is an automated message from Tamandua EDR.
    Do not reply to this email.
    """
  end

  defp sanitize_filename(name) do
    name
    |> String.replace(~r/[^\w\s-]/, "")
    |> String.replace(~r/\s+/, "_")
    |> String.downcase()
  end
end
