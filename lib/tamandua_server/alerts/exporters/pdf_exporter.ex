defmodule TamanduaServer.Alerts.Exporters.PDFExporter do
  @moduledoc """
  Generates PDF exports of alerts with charts and formatting.

  Uses ChromicPDF for PDF generation with custom HTML templates.
  """

  alias TamanduaServer.Alerts.Alert

  @doc """
  Generates PDF data from alerts.

  ## Parameters
  - `alerts` - List of Alert structs (preloaded with associations)
  - `columns` - List of column names to include

  ## Returns
  {:ok, binary} with PDF data or {:error, reason}
  """
  def generate(alerts, columns) when is_list(alerts) and is_list(columns) do
    html = generate_html(alerts, columns)

    # Generate PDF using ChromicPDF
    ChromicPDF.print_to_pdf({:html, html}, print_to_pdf_opts())
  end

  defp generate_html(alerts, columns) do
    stats = calculate_statistics(alerts)

    """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Alert Export Report</title>
      <style>
        #{pdf_styles()}
      </style>
    </head>
    <body>
      <div class="header">
        <h1>Alert Export Report</h1>
        <p class="export-date">Generated: #{format_datetime(DateTime.utc_now())}</p>
      </div>

      <div class="summary">
        <h2>Summary Statistics</h2>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-label">Total Alerts</div>
            <div class="stat-value">#{stats.total}</div>
          </div>
          <div class="stat-card critical">
            <div class="stat-label">Critical</div>
            <div class="stat-value">#{stats.critical}</div>
          </div>
          <div class="stat-card high">
            <div class="stat-label">High</div>
            <div class="stat-value">#{stats.high}</div>
          </div>
          <div class="stat-card medium">
            <div class="stat-label">Medium</div>
            <div class="stat-value">#{stats.medium}</div>
          </div>
          <div class="stat-card low">
            <div class="stat-label">Low</div>
            <div class="stat-value">#{stats.low}</div>
          </div>
        </div>

        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-label">New</div>
            <div class="stat-value">#{stats.new}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Investigating</div>
            <div class="stat-value">#{stats.investigating}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Resolved</div>
            <div class="stat-value">#{stats.resolved}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">False Positive</div>
            <div class="stat-value">#{stats.false_positive}</div>
          </div>
        </div>
      </div>

      <div class="alerts-table">
        <h2>Alert Details</h2>
        <table>
          <thead>
            <tr>
              #{generate_table_headers(columns)}
            </tr>
          </thead>
          <tbody>
            #{generate_table_rows(alerts, columns)}
          </tbody>
        </table>
      </div>

      <div class="footer">
        <p>Tamandua EDR - Alert Export Report</p>
        <p>Page <span class="pageNumber"></span> of <span class="totalPages"></span></p>
      </div>
    </body>
    </html>
    """
  end

  defp pdf_styles do
    """
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      margin: 0;
      padding: 20px;
      color: #1f2937;
    }

    .header {
      text-align: center;
      margin-bottom: 30px;
      padding-bottom: 20px;
      border-bottom: 2px solid #e5e7eb;
    }

    .header h1 {
      margin: 0;
      font-size: 28px;
      color: #111827;
    }

    .export-date {
      margin: 10px 0 0 0;
      color: #6b7280;
      font-size: 14px;
    }

    .summary {
      margin-bottom: 30px;
    }

    .summary h2 {
      font-size: 20px;
      margin-bottom: 15px;
      color: #374151;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 15px;
      margin-bottom: 15px;
    }

    .stat-card {
      background: #f9fafb;
      padding: 15px;
      border-radius: 8px;
      border: 1px solid #e5e7eb;
      text-align: center;
    }

    .stat-card.critical { background: #fef2f2; border-color: #fecaca; }
    .stat-card.high { background: #fff7ed; border-color: #fed7aa; }
    .stat-card.medium { background: #fffbeb; border-color: #fde68a; }
    .stat-card.low { background: #eff6ff; border-color: #bfdbfe; }

    .stat-label {
      font-size: 12px;
      color: #6b7280;
      margin-bottom: 5px;
    }

    .stat-value {
      font-size: 24px;
      font-weight: bold;
      color: #111827;
    }

    .alerts-table {
      margin-bottom: 30px;
    }

    .alerts-table h2 {
      font-size: 20px;
      margin-bottom: 15px;
      color: #374151;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }

    thead {
      background: #f9fafb;
    }

    th {
      padding: 12px 8px;
      text-align: left;
      font-weight: 600;
      color: #374151;
      border-bottom: 2px solid #e5e7eb;
    }

    td {
      padding: 10px 8px;
      border-bottom: 1px solid #f3f4f6;
    }

    tbody tr:hover {
      background: #f9fafb;
    }

    .severity {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }

    .severity-critical { background: #fef2f2; color: #991b1b; }
    .severity-high { background: #fff7ed; color: #9a3412; }
    .severity-medium { background: #fffbeb; color: #92400e; }
    .severity-low { background: #eff6ff; color: #1e40af; }
    .severity-info { background: #f3f4f6; color: #374151; }

    .footer {
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #e5e7eb;
      text-align: center;
      font-size: 11px;
      color: #6b7280;
    }

    @media print {
      .footer {
        position: fixed;
        bottom: 0;
        width: 100%;
      }
    }
    """
  end

  defp generate_table_headers(columns) do
    columns
    |> Enum.map(&column_to_header/1)
    |> Enum.map(&"<th>#{&1}</th>")
    |> Enum.join("\n")
  end

  defp generate_table_rows(alerts, columns) do
    alerts
    |> Enum.map(&generate_table_row(&1, columns))
    |> Enum.join("\n")
  end

  defp generate_table_row(alert, columns) do
    cells = columns
    |> Enum.map(fn column ->
      value = extract_value(alert, column)
      formatted = format_cell_value(column, value)
      "<td>#{formatted}</td>"
    end)
    |> Enum.join("\n")

    "<tr>#{cells}</tr>"
  end

  defp column_to_header("id"), do: "ID"
  defp column_to_header("severity"), do: "Severity"
  defp column_to_header("title"), do: "Title"
  defp column_to_header("description"), do: "Description"
  defp column_to_header("status"), do: "Status"
  defp column_to_header("threat_score"), do: "Threat Score"
  defp column_to_header("agent_hostname"), do: "Agent"
  defp column_to_header("mitre_tactics"), do: "MITRE Tactics"
  defp column_to_header("inserted_at"), do: "Created"
  defp column_to_header(column), do: String.replace(column, "_", " ") |> String.capitalize()

  defp extract_value(alert, "id"), do: String.slice(alert.id, 0, 8)
  defp extract_value(alert, "severity"), do: alert.severity
  defp extract_value(alert, "title"), do: alert.title
  defp extract_value(alert, "description"), do: alert.description
  defp extract_value(alert, "status"), do: alert.status
  defp extract_value(alert, "threat_score"), do: alert.threat_score
  defp extract_value(%{agent: agent} = _alert, "agent_hostname") when not is_nil(agent), do: agent.hostname
  defp extract_value(alert, "mitre_tactics"), do: alert.mitre_tactics
  defp extract_value(alert, "inserted_at"), do: alert.inserted_at
  defp extract_value(_alert, _column), do: nil

  defp format_cell_value("severity", value) when is_binary(value) do
    "<span class=\"severity severity-#{value}\">#{String.upcase(value)}</span>"
  end

  defp format_cell_value("mitre_tactics", tactics) when is_list(tactics) do
    Enum.join(tactics, ", ")
  end

  defp format_cell_value("inserted_at", %DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  end

  defp format_cell_value("threat_score", score) when is_number(score) do
    Float.round(score, 2)
  end

  defp format_cell_value(_column, nil), do: "-"
  defp format_cell_value(_column, value) when is_list(value), do: Enum.join(value, ", ")
  defp format_cell_value(_column, value) when is_binary(value) do
    # Escape HTML and truncate long text
    value
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> truncate(100)
  end
  defp format_cell_value(_column, value), do: to_string(value)

  defp truncate(string, max_length) do
    if String.length(string) > max_length do
      String.slice(string, 0, max_length) <> "..."
    else
      string
    end
  end

  defp calculate_statistics(alerts) do
    %{
      total: length(alerts),
      critical: Enum.count(alerts, &(&1.severity == "critical")),
      high: Enum.count(alerts, &(&1.severity == "high")),
      medium: Enum.count(alerts, &(&1.severity == "medium")),
      low: Enum.count(alerts, &(&1.severity == "low")),
      new: Enum.count(alerts, &(&1.status == "new")),
      investigating: Enum.count(alerts, &(&1.status == "investigating")),
      resolved: Enum.count(alerts, &(&1.status == "resolved")),
      false_positive: Enum.count(alerts, &(&1.status == "false_positive"))
    }
  end

  defp format_datetime(dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp print_to_pdf_opts do
    [
      print_to_pdf: %{
        preferCSSPageSize: true,
        printBackground: true,
        displayHeaderFooter: true,
        marginTop: "1cm",
        marginBottom: "1cm",
        marginLeft: "1cm",
        marginRight: "1cm"
      }
    ]
  end
end
