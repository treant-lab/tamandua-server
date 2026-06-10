defmodule TamanduaServer.Reports.PDFRenderer do
  @moduledoc """
  PDF Renderer for Tamandua EDR Reports.

  Uses ChromicPDF (headless Chrome) to render HTML reports to PDF with:
  - Professional styling and branding
  - Charts and visualizations
  - Page headers/footers
  - Table of contents
  - Configurable paper size and orientation
  """

  require Logger

  @default_options %{
    paper_size: :a4,
    orientation: :portrait,
    margin_top: "20mm",
    margin_bottom: "20mm",
    margin_left: "15mm",
    margin_right: "15mm",
    print_background: true,
    display_header_footer: true
  }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Renders a report to PDF.

  ## Options
  - `:paper_size` - :a4, :letter, :legal (default: :a4)
  - `:orientation` - :portrait, :landscape (default: :portrait)
  - `:include_toc` - Include table of contents (default: false)
  - `:margin_top` - Top margin (default: "20mm")
  - `:margin_bottom` - Bottom margin (default: "20mm")
  - `:margin_left` - Left margin (default: "15mm")
  - `:margin_right` - Right margin (default: "15mm")

  ## Returns
  - `{:ok, pdf_binary}` - PDF content as binary
  - `{:error, reason}` - Error with reason
  """
  def render(report_data, opts \\ []) do
    options = Map.merge(@default_options, Map.new(opts))

    with {:ok, html} <- generate_html(report_data, options),
         {:ok, pdf} <- html_to_pdf(html, options) do
      {:ok, pdf}
    else
      {:error, reason} ->
        Logger.error("PDF rendering failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Renders a report to PDF and saves to file.
  """
  def render_to_file(report_data, file_path, opts \\ []) do
    case render(report_data, opts) do
      {:ok, pdf_binary} ->
        File.write(file_path, pdf_binary)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Renders HTML string directly to PDF.
  """
  def render_html_to_pdf(html, opts \\ []) do
    options = Map.merge(@default_options, Map.new(opts))
    html_to_pdf(html, options)
  end

  # ============================================================================
  # HTML Generation
  # ============================================================================

  defp generate_html(report_data, options) do
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>#{escape_html(report_data.title)}</title>
      #{stylesheet()}
    </head>
    <body>
      #{cover_page(report_data)}
      #{if options[:include_toc], do: table_of_contents(report_data), else: ""}
      #{render_sections(report_data.sections)}
      #{footer_page(report_data)}
    </body>
    </html>
    """

    {:ok, html}
  end

  defp stylesheet do
    """
    <style>
      @page {
        size: A4;
        margin: 20mm 15mm;
      }

      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

      body {
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
        font-size: 11pt;
        line-height: 1.6;
        color: #1a1a2e;
        background: #ffffff;
      }

      /* Cover Page */
      .cover-page {
        page-break-after: always;
        height: 100vh;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        text-align: center;
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        color: #ffffff;
        padding: 60px;
      }

      .cover-logo {
        width: 120px;
        height: 120px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 40px;
        font-size: 48px;
      }

      .cover-title {
        font-size: 36pt;
        font-weight: 700;
        margin-bottom: 16px;
        color: #ffffff;
      }

      .cover-subtitle {
        font-size: 14pt;
        color: rgba(255, 255, 255, 0.8);
        margin-bottom: 60px;
      }

      .cover-meta {
        font-size: 11pt;
        color: rgba(255, 255, 255, 0.6);
      }

      .cover-meta p {
        margin: 8px 0;
      }

      /* Table of Contents */
      .toc {
        page-break-after: always;
        padding: 40px 0;
      }

      .toc h2 {
        font-size: 24pt;
        margin-bottom: 30px;
        color: #1a1a2e;
        border-bottom: 2px solid #e94560;
        padding-bottom: 10px;
      }

      .toc-item {
        display: flex;
        justify-content: space-between;
        padding: 12px 0;
        border-bottom: 1px dotted #ddd;
      }

      .toc-item span:first-child {
        font-weight: 500;
      }

      /* Sections */
      .section {
        margin-bottom: 40px;
        page-break-inside: avoid;
      }

      .section-title {
        font-size: 18pt;
        font-weight: 600;
        color: #1a1a2e;
        margin-bottom: 16px;
        padding-bottom: 8px;
        border-bottom: 2px solid #e94560;
      }

      .section-content {
        color: #333;
      }

      /* Summary Section */
      .summary-text {
        font-size: 11pt;
        line-height: 1.8;
        color: #444;
        text-align: justify;
      }

      /* Stats Grid */
      .stats-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 16px;
        margin-top: 20px;
      }

      .stat-card {
        background: #f8f9fa;
        border-radius: 8px;
        padding: 20px;
        text-align: center;
        border-left: 4px solid #e94560;
      }

      .stat-value {
        font-size: 28pt;
        font-weight: 700;
        color: #1a1a2e;
      }

      .stat-label {
        font-size: 10pt;
        color: #666;
        margin-top: 4px;
      }

      .stat-change {
        font-size: 9pt;
        margin-top: 8px;
      }

      .stat-change.positive {
        color: #28a745;
      }

      .stat-change.negative {
        color: #dc3545;
      }

      /* Tables */
      .data-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 20px;
        font-size: 10pt;
      }

      .data-table thead {
        background: #1a1a2e;
        color: #ffffff;
      }

      .data-table th {
        padding: 12px 16px;
        text-align: left;
        font-weight: 600;
      }

      .data-table td {
        padding: 10px 16px;
        border-bottom: 1px solid #eee;
      }

      .data-table tbody tr:nth-child(even) {
        background: #f8f9fa;
      }

      .data-table tbody tr:hover {
        background: #e9ecef;
      }

      /* Lists */
      .item-list {
        list-style: none;
        margin-top: 16px;
      }

      .item-list li {
        display: flex;
        align-items: flex-start;
        padding: 12px 0;
        border-bottom: 1px solid #eee;
      }

      .item-list li::before {
        content: '';
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #e94560;
        margin-right: 12px;
        margin-top: 6px;
        flex-shrink: 0;
      }

      /* Compliance Specific */
      .compliance-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 30px;
        padding: 20px;
        background: #f8f9fa;
        border-radius: 8px;
      }

      .compliance-score {
        text-align: center;
      }

      .compliance-score .score {
        font-size: 48pt;
        font-weight: 700;
        color: #1a1a2e;
      }

      .compliance-score .label {
        font-size: 12pt;
        color: #666;
      }

      .status-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 9pt;
        font-weight: 600;
      }

      .status-implemented {
        background: #d4edda;
        color: #155724;
      }

      .status-partial {
        background: #fff3cd;
        color: #856404;
      }

      .status-gap {
        background: #f8d7da;
        color: #721c24;
      }

      .status-na {
        background: #e9ecef;
        color: #495057;
      }

      /* Charts placeholder */
      .chart-placeholder {
        background: #f8f9fa;
        border: 2px dashed #ddd;
        border-radius: 8px;
        padding: 40px;
        text-align: center;
        color: #999;
        margin-top: 20px;
      }

      /* Footer Page */
      .footer-page {
        page-break-before: always;
        padding: 40px 0;
      }

      .footer-content {
        text-align: center;
        padding: 60px 40px;
        background: #f8f9fa;
        border-radius: 8px;
      }

      .footer-content h3 {
        font-size: 14pt;
        color: #1a1a2e;
        margin-bottom: 16px;
      }

      .footer-content p {
        font-size: 10pt;
        color: #666;
        margin: 8px 0;
      }

      .confidential-notice {
        margin-top: 40px;
        padding: 20px;
        background: #fff3cd;
        border-radius: 8px;
        font-size: 10pt;
        color: #856404;
      }

      /* Print-specific */
      @media print {
        .cover-page {
          -webkit-print-color-adjust: exact;
          print-color-adjust: exact;
        }

        .stat-card {
          -webkit-print-color-adjust: exact;
          print-color-adjust: exact;
        }

        .data-table thead {
          -webkit-print-color-adjust: exact;
          print-color-adjust: exact;
        }
      }
    </style>
    """
  end

  defp cover_page(report_data) do
    """
    <div class="cover-page">
      <div class="cover-logo">
        #{shield_icon()}
      </div>
      <h1 class="cover-title">#{escape_html(report_data.title)}</h1>
      <p class="cover-subtitle">Tamandua Endpoint Detection and Response</p>
      <div class="cover-meta">
        <p>Report Period: #{escape_html(report_data.period.from)} to #{escape_html(report_data.period.to)}</p>
        <p>Generated: #{format_datetime(report_data.generated_at)}</p>
        #{if report_data[:generated_by], do: "<p>Generated By: #{escape_html(report_data.generated_by)}</p>", else: ""}
        <p>Template: #{escape_html(report_data.template)}</p>
      </div>
    </div>
    """
  end

  defp table_of_contents(report_data) do
    items =
      report_data.sections
      |> Enum.with_index(1)
      |> Enum.map(fn {section, idx} ->
        """
        <div class="toc-item">
          <span>#{idx}. #{escape_html(section.title)}</span>
          <span>#{idx}</span>
        </div>
        """
      end)
      |> Enum.join("\n")

    """
    <div class="toc">
      <h2>Table of Contents</h2>
      #{items}
    </div>
    """
  end

  defp render_sections(sections) do
    sections
    |> Enum.with_index(1)
    |> Enum.map(fn {section, _idx} -> render_section(section) end)
    |> Enum.join("\n")
  end

  defp render_section(%{title: title, type: type, content: content}) do
    """
    <div class="section">
      <h2 class="section-title">#{escape_html(title)}</h2>
      <div class="section-content">
        #{render_section_content(type, content)}
      </div>
    </div>
    """
  end

  defp render_section_content("summary", content) when is_binary(content) do
    """
    <p class="summary-text">#{escape_html(content)}</p>
    """
  end

  defp render_section_content("stats", content) when is_list(content) do
    cards =
      content
      |> Enum.map(fn stat ->
        change_html = if stat[:change] do
          change_class = if String.starts_with?(to_string(stat.change), "-"), do: "positive", else: "negative"
          "<p class=\"stat-change #{change_class}\">#{escape_html(to_string(stat.change))} from previous period</p>"
        else
          ""
        end

        """
        <div class="stat-card">
          <div class="stat-value">#{escape_html(to_string(stat.value))}</div>
          <div class="stat-label">#{escape_html(stat.label)}</div>
          #{change_html}
        </div>
        """
      end)
      |> Enum.join("\n")

    """
    <div class="stats-grid">
      #{cards}
    </div>
    """
  end

  defp render_section_content("table", %{headers: headers, rows: rows}) do
    header_cells =
      headers
      |> Enum.map(fn h -> "<th>#{escape_html(h)}</th>" end)
      |> Enum.join("\n")

    row_html =
      rows
      |> Enum.map(fn row ->
        cells = row
                |> Enum.map(fn cell -> "<td>#{escape_html(to_string(cell))}</td>" end)
                |> Enum.join("\n")
        "<tr>#{cells}</tr>"
      end)
      |> Enum.join("\n")

    """
    <table class="data-table">
      <thead>
        <tr>#{header_cells}</tr>
      </thead>
      <tbody>
        #{row_html}
      </tbody>
    </table>
    """
  end

  defp render_section_content("list", content) when is_list(content) do
    items =
      content
      |> Enum.map(fn item -> "<li>#{escape_html(to_string(item))}</li>" end)
      |> Enum.join("\n")

    """
    <ul class="item-list">
      #{items}
    </ul>
    """
  end

  defp render_section_content("chart", content) do
    # Placeholder for charts - would need chart.js or similar
    """
    <div class="chart-placeholder">
      <p>Chart: #{escape_html(content[:chart_type] || "visualization")}</p>
      <p>Data visualization would be rendered here</p>
    </div>
    """
  end

  defp render_section_content("compliance_controls", content) when is_list(content) do
    rows =
      content
      |> Enum.map(fn control ->
        status_class = case control[:status] do
          "implemented" -> "status-implemented"
          "partial" -> "status-partial"
          "gap" -> "status-gap"
          _ -> "status-na"
        end

        """
        <tr>
          <td>#{escape_html(control[:id] || "")}</td>
          <td>#{escape_html(control[:name] || "")}</td>
          <td><span class="status-badge #{status_class}">#{escape_html(control[:status] || "N/A")}</span></td>
          <td>#{escape_html(control[:evidence] || "")}</td>
          <td>#{escape_html(control[:priority] || "")}</td>
        </tr>
        """
      end)
      |> Enum.join("\n")

    """
    <table class="data-table">
      <thead>
        <tr>
          <th>Control ID</th>
          <th>Control Name</th>
          <th>Status</th>
          <th>Evidence</th>
          <th>Priority</th>
        </tr>
      </thead>
      <tbody>
        #{rows}
      </tbody>
    </table>
    """
  end

  defp render_section_content(_type, content) when is_binary(content) do
    """
    <p class="summary-text">#{escape_html(content)}</p>
    """
  end

  defp render_section_content(_type, content) do
    """
    <pre>#{escape_html(Jason.encode!(content, pretty: true))}</pre>
    """
  end

  defp footer_page(report_data) do
    """
    <div class="footer-page">
      <div class="footer-content">
        <h3>End of Report</h3>
        <p>Report: #{escape_html(report_data.title)}</p>
        <p>Template: #{escape_html(report_data.template)}</p>
        <p>Period: #{escape_html(report_data.period.from)} to #{escape_html(report_data.period.to)}</p>
        <p>Generated: #{format_datetime(report_data.generated_at)}</p>
      </div>
      <div class="confidential-notice">
        <strong>CONFIDENTIAL</strong> - This report contains sensitive security information.
        Do not distribute without proper authorization.
        Generated by Tamandua Endpoint Detection and Response Platform.
      </div>
    </div>
    """
  end

  defp shield_icon do
    """
    <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/>
    </svg>
    """
  end

  # ============================================================================
  # PDF Generation via ChromicPDF
  # ============================================================================

  defp html_to_pdf(html, options) do
    pdf_options = build_chromic_options(options)

    case ChromicPDF.print_to_pdf({:html, html}, pdf_options) do
      {:ok, pdf_binary} ->
        {:ok, pdf_binary}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("ChromicPDF error: #{inspect(e)}")
      {:error, "PDF generation failed: #{inspect(e)}"}
  end

  defp build_chromic_options(options) do
    [
      print_to_pdf: %{
        preferCSSPageSize: true,
        printBackground: options[:print_background],
        displayHeaderFooter: options[:display_header_footer],
        marginTop: options[:margin_top] || 0.79,
        marginBottom: options[:margin_bottom] || 0.79,
        marginLeft: options[:margin_left] || 0.59,
        marginRight: options[:margin_right] || 0.59,
        headerTemplate: header_template(),
        footerTemplate: footer_template()
      }
    ]
    |> maybe_add_paper_size(options[:paper_size])
    |> maybe_add_orientation(options[:orientation])
  end

  defp maybe_add_paper_size(opts, :a4), do: put_in(opts, [:print_to_pdf, :paperWidth], 8.27) |> put_in([:print_to_pdf, :paperHeight], 11.69)
  defp maybe_add_paper_size(opts, :letter), do: put_in(opts, [:print_to_pdf, :paperWidth], 8.5) |> put_in([:print_to_pdf, :paperHeight], 11.0)
  defp maybe_add_paper_size(opts, :legal), do: put_in(opts, [:print_to_pdf, :paperWidth], 8.5) |> put_in([:print_to_pdf, :paperHeight], 14.0)
  defp maybe_add_paper_size(opts, _), do: opts

  defp maybe_add_orientation(opts, :landscape), do: put_in(opts, [:print_to_pdf, :landscape], true)
  defp maybe_add_orientation(opts, _), do: opts

  defp header_template do
    """
    <div style="font-size: 9px; color: #999; width: 100%; text-align: center; margin: 0 auto; padding-top: 5px;">
      <span>Tamandua EDR - Confidential</span>
    </div>
    """
  end

  defp footer_template do
    """
    <div style="font-size: 9px; color: #999; width: 100%; text-align: center; padding-bottom: 5px;">
      <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
    </div>
    """
  end

  # ============================================================================
  # Utilities
  # ============================================================================

  defp escape_html(nil), do: ""
  defp escape_html(text) when is_binary(text) do
    text
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&#39;")
  end
  defp escape_html(other), do: escape_html(to_string(other))

  defp format_datetime(nil), do: ""
  defp format_datetime(datetime) when is_binary(datetime) do
    case DateTime.from_iso8601(datetime) do
      {:ok, dt, _} -> Calendar.strftime(dt, "%B %d, %Y at %H:%M UTC")
      _ -> datetime
    end
  end
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%B %d, %Y at %H:%M UTC")
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%B %d, %Y at %H:%M")
  defp format_datetime(other), do: to_string(other)
end
