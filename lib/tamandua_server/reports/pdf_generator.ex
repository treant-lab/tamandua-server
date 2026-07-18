defmodule TamanduaServer.Reports.PDFGenerator do
  @moduledoc """
  Professional PDF Report Generator for Tamandua EDR.

  Uses ChromicPDF to generate high-quality, CrowdStrike-style executive reports with:
  - Professional branding and layout
  - Interactive charts rendered as SVG
  - Data tables with pagination
  - Executive summaries and recommendations
  - Multi-page support with headers/footers
  - Compliance-ready formatting

  ## Usage

      {:ok, pdf_binary} = PDFGenerator.generate(report_data)
      {:ok, pdf_binary} = PDFGenerator.generate(report_data, format: :executive)
  """

  require Logger

  @branding_colors %{
    primary: "#0066cc",
    primary_dark: "#004d99",
    secondary: "#1a1a2e",
    accent: "#00d4aa",
    success: "#28a745",
    warning: "#ffc107",
    danger: "#dc3545",
    info: "#17a2b8",
    light: "#f8f9fa",
    dark: "#1a1a2e"
  }

  @severity_colors %{
    "critical" => "#dc3545",
    "high" => "#fd7e14",
    "medium" => "#ffc107",
    "low" => "#28a745",
    "info" => "#17a2b8"
  }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Generate a PDF from report data.

  ## Options
  - `:format` - Report format (:executive, :detailed, :compliance). Default: :executive
  - `:include_toc` - Include table of contents. Default: true
  - `:include_charts` - Include SVG charts. Default: true
  - `:page_size` - Page size (A4, Letter). Default: A4
  - `:orientation` - Page orientation (portrait, landscape). Default: portrait

  ## Returns
  - `{:ok, pdf_binary}` on success
  - `{:error, reason}` on failure
  """
  def generate(report_data, opts \\ []) do
    format = Keyword.get(opts, :format, :executive)

    # Build HTML from report data
    html = build_html(report_data, format, opts)

    # Generate PDF using ChromicPDF
    pdf_opts = build_pdf_options(opts)

    case ChromicPDF.print_to_pdf({:html, html}, pdf_opts) do
      {:ok, pdf_binary} ->
        Logger.info("PDF generated successfully: #{byte_size(pdf_binary)} bytes")
        {:ok, pdf_binary}

      {:error, reason} ->
        Logger.error("PDF generation failed: #{inspect(reason)}")
        {:error, {:pdf_generation_failed, reason}}
    end
  end

  @doc """
  Generate PDF and save to file.
  """
  def generate_to_file(report_data, file_path, opts \\ []) do
    case generate(report_data, opts) do
      {:ok, pdf_binary} ->
        case File.write(file_path, pdf_binary) do
          :ok -> {:ok, file_path}
          {:error, reason} -> {:error, {:file_write_failed, reason}}
        end

      error -> error
    end
  end

  @doc """
  Check if ChromicPDF is available and functioning.
  """
  def health_check do
    html = "<html><body><p>Test</p></body></html>"

    case ChromicPDF.print_to_pdf({:html, html}) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    e -> {:error, {:exception, inspect(e)}}
  end

  # ============================================================================
  # HTML Building
  # ============================================================================

  defp build_html(report_data, format, opts) do
    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>#{escape_html(report_data["title"] || "Tamandua EDR Report")}</title>
      #{build_styles(format)}
    </head>
    <body>
      #{build_cover_page(report_data, format)}
      #{if Keyword.get(opts, :include_toc, true), do: build_table_of_contents(report_data), else: ""}
      #{build_executive_summary(report_data, format)}
      #{build_sections(report_data, format, opts)}
      #{build_footer(report_data)}
    </body>
    </html>
    """
  end

  defp build_styles(_format) do
    """
    <style>
      @page {
        size: A4;
        margin: 1.5cm 1.5cm 2cm 1.5cm;

        @bottom-center {
          content: "Page " counter(page) " of " counter(pages);
          font-size: 9pt;
          color: #666;
        }

        @bottom-right {
          content: "Confidential - Tamandua EDR";
          font-size: 9pt;
          color: #999;
        }
      }

      @page :first {
        margin: 0;

        @bottom-center { content: none; }
        @bottom-right { content: none; }
      }

      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }

      body {
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif;
        font-size: 10pt;
        line-height: 1.5;
        color: #{@branding_colors.secondary};
        background: white;
      }

      /* Cover Page */
      .cover-page {
        page-break-after: always;
        height: 100vh;
        display: flex;
        flex-direction: column;
        background: linear-gradient(135deg, #{@branding_colors.secondary} 0%, #2d2d4a 100%);
        color: white;
        padding: 3cm;
      }

      .cover-header {
        display: flex;
        align-items: center;
        gap: 1rem;
        margin-bottom: 3cm;
      }

      .cover-logo {
        width: 48px;
        height: 48px;
        background: #{@branding_colors.primary};
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .cover-logo svg {
        width: 32px;
        height: 32px;
        fill: white;
      }

      .cover-brand {
        font-size: 24pt;
        font-weight: 700;
      }

      .cover-brand-tag {
        background: #{@branding_colors.primary};
        padding: 0.25em 0.75em;
        border-radius: 4px;
        font-size: 10pt;
        font-weight: 600;
        margin-left: 0.5rem;
      }

      .cover-title {
        font-size: 36pt;
        font-weight: 700;
        margin-bottom: 1rem;
        line-height: 1.2;
      }

      .cover-subtitle {
        font-size: 14pt;
        color: rgba(255,255,255,0.8);
        margin-bottom: 2cm;
      }

      .cover-meta {
        margin-top: auto;
        font-size: 11pt;
      }

      .cover-meta-row {
        display: flex;
        margin-bottom: 0.5rem;
      }

      .cover-meta-label {
        width: 120px;
        color: rgba(255,255,255,0.6);
      }

      .cover-meta-value {
        font-weight: 500;
      }

      .cover-classification {
        position: absolute;
        bottom: 1.5cm;
        left: 50%;
        transform: translateX(-50%);
        background: #{@branding_colors.danger};
        padding: 0.5em 2em;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 9pt;
        border-radius: 4px;
      }

      /* Table of Contents */
      .toc {
        page-break-after: always;
        padding: 2cm;
      }

      .toc h2 {
        font-size: 18pt;
        color: #{@branding_colors.primary};
        margin-bottom: 1.5rem;
        border-bottom: 2px solid #{@branding_colors.primary};
        padding-bottom: 0.5rem;
      }

      .toc-item {
        display: flex;
        align-items: baseline;
        margin-bottom: 0.75rem;
        font-size: 11pt;
      }

      .toc-number {
        width: 2rem;
        color: #{@branding_colors.primary};
        font-weight: 600;
      }

      .toc-title {
        flex: 1;
      }

      .toc-dots {
        flex: 1;
        border-bottom: 1px dotted #ccc;
        margin: 0 0.5rem;
        height: 0.5em;
      }

      .toc-page {
        color: #666;
      }

      /* Content Sections */
      .section {
        margin-bottom: 1.5cm;
      }

      .section-header {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 1rem;
        border-bottom: 2px solid #{@branding_colors.primary};
        padding-bottom: 0.5rem;
      }

      .section-number {
        background: #{@branding_colors.primary};
        color: white;
        width: 28px;
        height: 28px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 600;
        font-size: 12pt;
      }

      h2 {
        font-size: 16pt;
        color: #{@branding_colors.secondary};
        font-weight: 600;
      }

      h3 {
        font-size: 12pt;
        color: #{@branding_colors.primary};
        margin: 1rem 0 0.5rem 0;
        font-weight: 600;
      }

      /* Summary/Paragraph */
      .summary-text {
        color: #444;
        line-height: 1.7;
        text-align: justify;
        margin-bottom: 1rem;
      }

      /* Stats Cards */
      .stats-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1rem;
        margin: 1rem 0;
      }

      .stat-card {
        background: #{@branding_colors.light};
        border-left: 4px solid #{@branding_colors.primary};
        padding: 1rem;
        border-radius: 0 6px 6px 0;
      }

      .stat-card.critical {
        border-left-color: #{@severity_colors["critical"]};
      }

      .stat-card.high {
        border-left-color: #{@severity_colors["high"]};
      }

      .stat-card.warning {
        border-left-color: #{@branding_colors.warning};
      }

      .stat-card.success {
        border-left-color: #{@branding_colors.success};
      }

      .stat-value {
        font-size: 24pt;
        font-weight: 700;
        color: #{@branding_colors.secondary};
        line-height: 1;
      }

      .stat-label {
        font-size: 9pt;
        color: #666;
        margin-top: 0.25rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }

      .stat-change {
        font-size: 9pt;
        margin-top: 0.25rem;
      }

      .stat-change.positive { color: #{@branding_colors.success}; }
      .stat-change.negative { color: #{@branding_colors.danger}; }

      /* Tables */
      table {
        width: 100%;
        border-collapse: collapse;
        font-size: 9pt;
        margin: 1rem 0;
      }

      th {
        background: #{@branding_colors.secondary};
        color: white;
        padding: 0.75rem;
        text-align: left;
        font-weight: 600;
        font-size: 9pt;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }

      td {
        padding: 0.6rem 0.75rem;
        border-bottom: 1px solid #eee;
        vertical-align: top;
      }

      tr:nth-child(even) {
        background: #fafafa;
      }

      tr:hover {
        background: #f0f7ff;
      }

      /* Severity badges */
      .severity-badge {
        display: inline-block;
        padding: 0.2em 0.6em;
        border-radius: 4px;
        font-size: 8pt;
        font-weight: 600;
        text-transform: uppercase;
      }

      .severity-critical { background: #{@severity_colors["critical"]}; color: white; }
      .severity-high { background: #{@severity_colors["high"]}; color: white; }
      .severity-medium { background: #{@severity_colors["medium"]}; color: #333; }
      .severity-low { background: #{@severity_colors["low"]}; color: white; }
      .severity-info { background: #{@severity_colors["info"]}; color: white; }

      /* Lists */
      .recommendation-list {
        margin: 1rem 0;
        padding-left: 0;
        list-style: none;
      }

      .recommendation-list li {
        padding: 0.75rem 1rem;
        background: #f8f9fa;
        border-left: 3px solid #{@branding_colors.primary};
        margin-bottom: 0.5rem;
        border-radius: 0 4px 4px 0;
      }

      .recommendation-list li::before {
        content: "\\2713";
        color: #{@branding_colors.primary};
        font-weight: bold;
        margin-right: 0.5rem;
      }

      /* Charts */
      .chart-container {
        background: #f8f9fa;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1rem 0;
      }

      .chart-title {
        font-size: 11pt;
        font-weight: 600;
        margin-bottom: 1rem;
        color: #{@branding_colors.secondary};
      }

      .bar-chart {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
      }

      .bar-row {
        display: flex;
        align-items: center;
        gap: 0.5rem;
      }

      .bar-label {
        width: 100px;
        font-size: 9pt;
        text-align: right;
      }

      .bar-track {
        flex: 1;
        background: #e9ecef;
        height: 20px;
        border-radius: 4px;
        overflow: hidden;
      }

      .bar-fill {
        height: 100%;
        background: #{@branding_colors.primary};
        border-radius: 4px;
        transition: width 0.3s;
      }

      .bar-value {
        width: 50px;
        font-size: 9pt;
        font-weight: 600;
        text-align: right;
      }

      /* Footer */
      .report-footer {
        margin-top: 2cm;
        padding-top: 1rem;
        border-top: 1px solid #ddd;
        font-size: 8pt;
        color: #999;
      }

      .report-footer p {
        margin-bottom: 0.25rem;
      }

      /* Page breaks */
      .page-break {
        page-break-before: always;
      }

      /* Compliance specific styles */
      .compliance-status {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.25rem 0.75rem;
        border-radius: 4px;
        font-size: 9pt;
        font-weight: 600;
      }

      .compliance-pass { background: #d4edda; color: #155724; }
      .compliance-fail { background: #f8d7da; color: #721c24; }
      .compliance-partial { background: #fff3cd; color: #856404; }

      /* Executive Summary Box */
      .executive-box {
        background: linear-gradient(135deg, #{@branding_colors.primary} 0%, #{@branding_colors.primary_dark} 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 8px;
        margin: 1rem 0;
      }

      .executive-box h3 {
        color: white;
        font-size: 14pt;
        margin-bottom: 0.75rem;
      }

      .executive-box p {
        line-height: 1.7;
        opacity: 0.95;
      }

      .executive-score {
        display: flex;
        align-items: center;
        gap: 1rem;
        margin-top: 1rem;
        padding-top: 1rem;
        border-top: 1px solid rgba(255,255,255,0.2);
      }

      .score-circle {
        width: 60px;
        height: 60px;
        border-radius: 50%;
        background: white;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
      }

      .score-value {
        font-size: 20pt;
        font-weight: 700;
        color: #{@branding_colors.primary};
        line-height: 1;
      }

      .score-label {
        font-size: 8pt;
        color: #666;
      }

      .score-description {
        flex: 1;
        font-size: 10pt;
      }

      /* Print-specific */
      @media print {
        body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .no-print { display: none; }
      }
    </style>
    """
  end

  defp build_cover_page(report_data, _format) do
    title = report_data["title"] || "Security Report"
    period = report_data["period"] || %{}
    generated_at = report_data["generated_at"]
    generated_by = report_data["generated_by"] || "System"
    template_name = report_data["template_name"] || report_data["template_id"] || "Standard"

    """
    <div class="cover-page">
      <div class="cover-header">
        <div class="cover-logo">
          <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
        </div>
        <span class="cover-brand">Tamandua</span>
        <span class="cover-brand-tag">EDR</span>
      </div>

      <h1 class="cover-title">#{escape_html(title)}</h1>
      <p class="cover-subtitle">#{escape_html(template_name)} - Endpoint Detection and Response</p>

      <div class="cover-meta">
        <div class="cover-meta-row">
          <span class="cover-meta-label">Report Period:</span>
          <span class="cover-meta-value">#{escape_html(period["from"] || "N/A")} to #{escape_html(period["to"] || "N/A")}</span>
        </div>
        <div class="cover-meta-row">
          <span class="cover-meta-label">Generated:</span>
          <span class="cover-meta-value">#{format_datetime(generated_at)}</span>
        </div>
        <div class="cover-meta-row">
          <span class="cover-meta-label">Prepared By:</span>
          <span class="cover-meta-value">#{escape_html(generated_by)}</span>
        </div>
        <div class="cover-meta-row">
          <span class="cover-meta-label">Classification:</span>
          <span class="cover-meta-value">Confidential</span>
        </div>
      </div>

      <div class="cover-classification">Confidential</div>
    </div>
    """
  end

  defp build_table_of_contents(report_data) do
    sections = report_data["sections"] || []

    toc_items = sections
    |> Enum.with_index(1)
    |> Enum.map(fn {section, idx} ->
      """
      <div class="toc-item">
        <span class="toc-number">#{idx}</span>
        <span class="toc-title">#{escape_html(section["title"] || "Section #{idx}")}</span>
        <span class="toc-dots"></span>
        <span class="toc-page">#{idx + 2}</span>
      </div>
      """
    end)
    |> Enum.join("\n")

    """
    <div class="toc">
      <h2>Table of Contents</h2>
      #{toc_items}
    </div>
    """
  end

  defp build_executive_summary(report_data, _format) do
    sections = report_data["sections"] || []

    # Find summary section if exists
    summary_section = Enum.find(sections, fn s ->
      s["type"] == "summary" || String.contains?(String.downcase(s["title"] || ""), "overview")
    end)

    summary_text = if summary_section do
      summary_section["content"] || ""
    else
      "This report provides a comprehensive analysis of the security posture during the specified period."
    end

    # Find security score if exists
    stats_section = Enum.find(sections, fn s -> s["type"] == "stats" end)

    security_score = if stats_section do
      stats = stats_section["content"] || []
      score_stat = Enum.find(stats, fn s ->
        label = s["label"] || ""
        String.contains?(String.downcase(label), "score")
      end)
      if score_stat, do: score_stat["value"], else: nil
    end

    score_html = if security_score do
      score_num = extract_numeric_score(security_score)
      _score_class = cond do
        score_num >= 80 -> "success"
        score_num >= 60 -> "warning"
        true -> "danger"
      end

      """
      <div class="executive-score">
        <div class="score-circle">
          <span class="score-value">#{score_num}</span>
          <span class="score-label">/100</span>
        </div>
        <div class="score-description">
          <strong>Security Score:</strong> #{score_description(score_num)}
        </div>
      </div>
      """
    else
      ""
    end

    """
    <div class="section">
      <div class="executive-box">
        <h3>Executive Summary</h3>
        <p>#{escape_html(summary_text)}</p>
        #{score_html}
      </div>
    </div>
    """
  end

  defp build_sections(report_data, _format, opts) do
    sections = report_data["sections"] || []
    include_charts = Keyword.get(opts, :include_charts, true)

    sections
    |> Enum.with_index(1)
    |> Enum.map(fn {section, idx} ->
      # Skip first summary section as it's in executive summary
      if idx == 1 && (section["type"] == "summary" || String.contains?(String.downcase(section["title"] || ""), "overview")) do
        ""
      else
        render_section(section, idx, include_charts)
      end
    end)
    |> Enum.join("\n")
  end

  defp render_section(section, idx, include_charts) do
    title = section["title"] || "Section #{idx}"
    type = section["type"] || "summary"
    content = section["content"]

    content_html = case type do
      "summary" -> render_summary(content)
      "stats" -> render_stats(content)
      "table" -> render_table(content)
      "list" -> render_list(content)
      "chart" when include_charts -> render_chart(content)
      "chart" -> render_chart_fallback(content)
      _ -> render_unknown(content)
    end

    """
    <div class="section">
      <div class="section-header">
        <div class="section-number">#{idx}</div>
        <h2>#{escape_html(title)}</h2>
      </div>
      #{content_html}
    </div>
    """
  end

  defp render_summary(content) when is_binary(content) do
    """
    <p class="summary-text">#{escape_html(content)}</p>
    """
  end
  defp render_summary(_), do: ""

  defp render_stats(content) when is_list(content) do
    cards = content
    |> Enum.map(fn stat ->
      label = stat["label"] || ""
      value = stat["value"] || "N/A"
      change = stat["change"]

      card_class = cond do
        String.contains?(String.downcase(label), "critical") -> "critical"
        String.contains?(String.downcase(label), "high") -> "high"
        String.contains?(String.downcase(label), "score") -> "success"
        true -> ""
      end

      change_html = if change do
        change_class = if String.starts_with?(to_string(change), "+"), do: "negative", else: "positive"
        ~s(<div class="stat-change #{change_class}">#{escape_html(to_string(change))}</div>)
      else
        ""
      end

      """
      <div class="stat-card #{card_class}">
        <div class="stat-value">#{escape_html(to_string(value))}</div>
        <div class="stat-label">#{escape_html(label)}</div>
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
  defp render_stats(_), do: ""

  defp render_table(content) when is_map(content) do
    headers = content["headers"] || []
    rows = content["rows"] || []

    headers_html = headers
    |> Enum.map(&"<th>#{escape_html(to_string(&1))}</th>")
    |> Enum.join("")

    rows_html = rows
    |> Enum.map(fn row ->
      cells = row
      |> Enum.map(&render_table_cell/1)
      |> Enum.join("")
      "<tr>#{cells}</tr>"
    end)
    |> Enum.join("\n")

    """
    <table>
      <thead><tr>#{headers_html}</tr></thead>
      <tbody>#{rows_html}</tbody>
    </table>
    """
  end
  defp render_table(_), do: ""

  defp render_table_cell(cell) do
    cell_str = to_string(cell)

    # Check if it's a severity indicator
    severity = String.downcase(cell_str)
    if severity in ~w(critical high medium low info pass fail) do
      badge_class = case severity do
        "pass" -> "severity-low"
        "fail" -> "severity-critical"
        sev -> "severity-#{sev}"
      end
      ~s(<td><span class="severity-badge #{badge_class}">#{escape_html(cell_str)}</span></td>)
    else
      ~s(<td>#{escape_html(cell_str)}</td>)
    end
  end

  defp render_list(content) when is_list(content) do
    items = content
    |> Enum.map(&"<li>#{escape_html(to_string(&1))}</li>")
    |> Enum.join("\n")

    """
    <ul class="recommendation-list">
      #{items}
    </ul>
    """
  end
  defp render_list(_), do: ""

  defp render_chart(content) when is_map(content) do
    chart_type = content["type"] || "bar"
    chart_title = content["title"] || "Chart"
    data = content["data"] || []
    labels = content["labels"] || []

    case chart_type do
      "bar" -> render_bar_chart(chart_title, labels, data)
      "pie" -> render_pie_chart_fallback(chart_title, labels, data)
      _ -> render_bar_chart(chart_title, labels, data)
    end
  end
  defp render_chart(_), do: ""

  defp render_bar_chart(title, labels, data) do
    max_val = Enum.max(data, fn -> 1 end) |> max(1)

    bars = Enum.zip(labels, data)
    |> Enum.map(fn {label, value} ->
      width = round(value / max_val * 100)
      """
      <div class="bar-row">
        <span class="bar-label">#{escape_html(to_string(label))}</span>
        <div class="bar-track">
          <div class="bar-fill" style="width: #{width}%;"></div>
        </div>
        <span class="bar-value">#{value}</span>
      </div>
      """
    end)
    |> Enum.join("\n")

    """
    <div class="chart-container">
      <div class="chart-title">#{escape_html(title)}</div>
      <div class="bar-chart">
        #{bars}
      </div>
    </div>
    """
  end

  defp render_pie_chart_fallback(title, labels, data) do
    # For PDF, render pie chart as a table since SVG pie charts are complex
    total = Enum.sum(data) |> max(1)

    rows = Enum.zip(labels, data)
    |> Enum.map(fn {label, value} ->
      pct = Float.round(value / total * 100, 1)
      "<tr><td>#{escape_html(to_string(label))}</td><td>#{value}</td><td>#{pct}%</td></tr>"
    end)
    |> Enum.join("\n")

    """
    <div class="chart-container">
      <div class="chart-title">#{escape_html(title)}</div>
      <table>
        <thead><tr><th>Category</th><th>Count</th><th>Percentage</th></tr></thead>
        <tbody>#{rows}</tbody>
      </table>
    </div>
    """
  end

  defp render_chart_fallback(content) when is_map(content) do
    # Render chart data as table when charts disabled
    labels = content["labels"] || []
    data = content["data"] || []

    rows = Enum.zip(labels, data)
    |> Enum.map(fn {label, value} ->
      "<tr><td>#{escape_html(to_string(label))}</td><td>#{value}</td></tr>"
    end)
    |> Enum.join("\n")

    """
    <table>
      <thead><tr><th>Item</th><th>Value</th></tr></thead>
      <tbody>#{rows}</tbody>
    </table>
    """
  end
  defp render_chart_fallback(_), do: ""

  defp render_unknown(content) do
    """
    <p class="summary-text">#{escape_html(inspect(content))}</p>
    """
  end

  defp build_footer(report_data) do
    report_id = report_data["id"] || "N/A"
    template_id = report_data["template_id"] || "N/A"

    """
    <div class="report-footer">
      <p>This report was automatically generated by Tamandua EDR.</p>
      <p>Report ID: #{escape_html(report_id)} | Template: #{escape_html(template_id)}</p>
      <p>Classification: Confidential - Do not distribute without authorization.</p>
    </div>
    """
  end

  # ============================================================================
  # PDF Options
  # ============================================================================

  defp build_pdf_options(opts) do
    _page_size = Keyword.get(opts, :page_size, "A4")
    _orientation = Keyword.get(opts, :orientation, :portrait)

    [
      print_to_pdf: %{
        preferCSSPageSize: true,
        printBackground: true,
        displayHeaderFooter: false,
        marginTop: "0",
        marginBottom: "0",
        marginLeft: "0",
        marginRight: "0"
      },
      evaluate: %{
        expression: """
        // Wait for fonts to load
        document.fonts.ready
        """
      }
    ]
  end

  # ============================================================================
  # Helpers
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

  defp format_datetime(nil), do: "N/A"
  defp format_datetime(datetime_str) when is_binary(datetime_str) do
    case DateTime.from_iso8601(datetime_str) do
      {:ok, dt, _} -> Calendar.strftime(dt, "%B %d, %Y at %H:%M UTC")
      _ -> datetime_str
    end
  end
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%B %d, %Y at %H:%M UTC")
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%B %d, %Y at %H:%M UTC")
  defp format_datetime(_), do: "N/A"

  defp extract_numeric_score(value) when is_integer(value), do: value
  defp extract_numeric_score(value) when is_binary(value) do
    case Integer.parse(String.replace(value, ~r/[^\d]/, "")) do
      {num, _} -> min(num, 100)
      :error -> 0
    end
  end
  defp extract_numeric_score(_), do: 0

  defp score_description(score) when score >= 90 do
    "Excellent security posture. Continue monitoring and maintaining current practices."
  end
  defp score_description(score) when score >= 75 do
    "Good security posture with minor areas for improvement identified."
  end
  defp score_description(score) when score >= 60 do
    "Moderate security posture. Several areas require attention and remediation."
  end
  defp score_description(score) when score >= 40 do
    "Below average security posture. Immediate action recommended on critical findings."
  end
  defp score_description(_) do
    "Critical security gaps identified. Immediate remediation required."
  end
end
