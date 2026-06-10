# Alert Exporters

Format-specific exporters for alert data.

## Quick Start

```elixir
# CSV Export
csv_data = TamanduaServer.Alerts.Exporters.CSVExporter.generate(
  alerts,
  ["severity", "title", "status"]
)
File.write!("alerts.csv", csv_data)

# JSON Export
json_data = TamanduaServer.Alerts.Exporters.JSONExporter.generate(
  alerts,
  ["severity", "title", "status"]
)
File.write!("alerts.json", json_data)

# PDF Export
{:ok, pdf_data} = TamanduaServer.Alerts.Exporters.PDFExporter.generate(
  alerts,
  ["severity", "title", "status"]
)
File.write!("alerts.pdf", pdf_data)
```

## Exporters

### CSVExporter

Generates Excel-compatible CSV files using NimbleCSV.

**Features:**
- RFC 4180 compliant
- Proper quote escaping
- Excel-compatible encoding
- Array fields joined with semicolons

**Example Output:**
```csv
Severity,Title,Status
critical,"Malware Detected: TrojanSpy.Win32.Agent",new
high,"Suspicious PowerShell Execution",investigating
```

### JSONExporter

Generates structured JSON with metadata.

**Features:**
- Pretty-printed output
- Metadata section with export info
- ISO 8601 timestamps
- Configurable column selection

**Example Output:**
```json
{
  "metadata": {
    "exported_at": "2026-02-20T12:00:00Z",
    "total_count": 2,
    "columns": ["severity", "title", "status"]
  },
  "alerts": [
    {
      "severity": "critical",
      "title": "Malware Detected",
      "status": "new"
    }
  ]
}
```

### PDFExporter

Generates formatted PDF reports with ChromicPDF.

**Features:**
- Summary statistics with charts
- Severity distribution
- Status breakdown
- Formatted table with color-coded severities
- Responsive layout
- Header and footer

**Requires:**
- Chrome or Chromium installed
- ChromicPDF supervision tree running

## Column Formatting

Each exporter handles column formatting differently:

### Timestamps
- CSV: `2026-02-20 12:00:00 UTC`
- JSON: `2026-02-20T12:00:00Z` (ISO 8601)
- PDF: `2026-02-20 12:00` (short format)

### Arrays
- CSV: Joined with `; ` (semicolon space)
- JSON: Native JSON arrays
- PDF: Joined with `, ` (comma space)

### Booleans
- CSV: `Yes` / `No`
- JSON: `true` / `false`
- PDF: `Yes` / `No`

### Null Values
- CSV: Empty string `""`
- JSON: `null`
- PDF: `-`

## Adding Custom Columns

To add a new column:

1. Add column name to `ExportTemplate.available_columns/0`
2. Add extraction logic in each exporter:

```elixir
# In csv_exporter.ex, json_exporter.ex, pdf_exporter.ex
defp extract_value(alert, "my_new_field"), do: alert.my_new_field

# In csv_exporter.ex
defp column_to_header("my_new_field"), do: "My New Field"
```

## Performance Notes

### CSV
- **Fastest** - Simple string concatenation
- Memory efficient with streaming
- Suitable for millions of records

### JSON
- **Medium** - JSON encoding overhead
- Pretty-printing adds size
- Good for programmatic consumption

### PDF
- **Slowest** - Chrome rendering overhead
- Memory intensive for large datasets
- Limited to ~10,000 records per export
- Recommended to use filters for large datasets

## Testing

```elixir
# Run tests
mix test test/tamandua_server/alerts/exporters/

# Test specific exporter
mix test test/tamandua_server/alerts/exporters/csv_exporter_test.exs
```

## Dependencies

- `nimble_csv` - CSV generation
- `jason` - JSON encoding
- `chromic_pdf` - PDF generation (optional)
