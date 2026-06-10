# Alert Export System

Comprehensive alert export functionality for Tamandua EDR with support for multiple formats, scheduled exports, and flexible delivery options.

## Features

### Export Formats

1. **CSV** - Excel-compatible CSV files with configurable columns
2. **JSON** - Structured JSON exports with metadata
3. **PDF** - Formatted PDF reports with charts and summary statistics

### Export Options

- **Filter Selection** - Export only filtered results from current search
- **Column Selection** - Choose which fields to include in export
- **Date Range** - Filter alerts by date range
- **Max Records Limit** - Prevent excessively large exports

### Scheduled Exports

- **Cron Scheduling** - Define custom schedules using cron expressions
- **Daily/Weekly/Monthly** - Common schedule presets
- **Email Delivery** - Automatic email delivery to recipients
- **S3/SFTP Upload** - Upload exports to cloud storage or SFTP servers
- **Retention Policies** - Auto-cleanup of old exports

### Export Templates

- **Saved Configurations** - Save column selections and filters as templates
- **Shared Templates** - Share templates across organization
- **Template Scheduling** - Schedule recurring exports from templates

## Architecture

```
┌─────────────┐
│   User UI   │ (AlertExportLive)
└──────┬──────┘
       │
       v
┌─────────────────┐
│    Exporter     │ (Orchestrator)
│  create_export  │
└──────┬──────────┘
       │
       v
┌─────────────────┐
│  ExportWorker   │ (Oban Background Job)
│   - Generate    │
│   - Deliver     │
└──────┬──────────┘
       │
       ├─────────> CSVExporter  (NimbleCSV)
       ├─────────> JSONExporter (Jason)
       └─────────> PDFExporter  (ChromicPDF)
```

## Usage

### Manual Export

```elixir
# Create a one-time export
{:ok, job} = TamanduaServer.Alerts.Exporter.create_export(
  organization_id,
  user_id,
  format: "csv",
  columns: ["severity", "title", "status", "threat_score"],
  filter_json: %{
    "logic" => "AND",
    "conditions" => [
      %{"field" => "severity", "operator" => "in", "value" => ["critical", "high"]}
    ]
  },
  delivery_method: "download"
)

# Check job status
{:ok, job} = Exporter.get_export_job(job.id)
IO.inspect(job.status) # "pending" | "processing" | "completed" | "failed"
IO.inspect(job.progress) # 0-100

# Download URL (available when status is "completed")
IO.inspect(job.download_url) # URL expires in 24 hours
```

### Email Delivery

```elixir
{:ok, job} = Exporter.create_export(
  org_id,
  user_id,
  format: "pdf",
  columns: ["severity", "title", "agent_hostname", "inserted_at"],
  delivery_method: "email",
  delivery_config: %{
    "recipients" => ["analyst@company.com", "manager@company.com"],
    "subject" => "Daily Alert Report",
    "message" => "Attached is your daily alert report."
  }
)
```

### S3 Upload

```elixir
{:ok, job} = Exporter.create_export(
  org_id,
  user_id,
  format: "json",
  columns: ExportTemplate.default_columns(),
  delivery_method: "s3",
  delivery_config: %{
    "bucket" => "company-security-reports",
    "key" => "alerts/daily-export-#{Date.utc_today()}.json",
    "region" => "us-east-1"
  }
)
```

### Scheduled Exports

```elixir
# Create a template with schedule
{:ok, template} = Exporter.create_template(%{
  name: "Daily Critical Alerts",
  description: "Critical alerts from the last 24 hours",
  format: "pdf",
  columns: ["severity", "title", "description", "agent_hostname", "mitre_tactics"],
  filter_json: %{
    "logic" => "AND",
    "conditions" => [
      %{"field" => "severity", "operator" => "eq", "value" => "critical"},
      %{"field" => "inserted_at", "operator" => "gte", "value" => "1d"}
    ]
  },
  scheduled: true,
  schedule_type: "daily",
  schedule_cron: "0 9 * * *",  # Every day at 9 AM
  schedule_timezone: "America/New_York",
  delivery_method: "email",
  delivery_config: %{
    "recipients" => ["soc@company.com"]
  },
  organization_id: org_id,
  created_by_id: user_id
})
```

## Column Reference

### Available Columns

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Alert ID |
| `severity` | String | critical, high, medium, low, info |
| `title` | String | Alert title |
| `description` | Text | Detailed description |
| `status` | String | new, investigating, resolved, false_positive |
| `verdict` | String | unconfirmed, true_positive, false_positive, benign, suspicious |
| `threat_score` | Float | 0.0 - 1.0 |
| `agent_hostname` | String | Hostname of affected agent |
| `agent_os` | String | Operating system |
| `assigned_to_name` | String | Assigned analyst |
| `mitre_tactics` | Array | MITRE ATT&CK tactics |
| `mitre_techniques` | Array | MITRE ATT&CK techniques |
| `attributed_actors` | Array | Threat actors |
| `campaign_id` | String | Campaign identifier |
| `occurrence_count` | Integer | Deduplication count |
| `workflow_state` | String | Current workflow state |
| `escalation_level` | Integer | 0-3 |
| `sla_acknowledge_breached` | Boolean | SLA acknowledgement breach |
| `sla_resolve_breached` | Boolean | SLA resolution breach |
| `inserted_at` | DateTime | Alert creation time |
| `acknowledged_at` | DateTime | Acknowledgement time |
| `resolved_at` | DateTime | Resolution time |
| `last_seen_at` | DateTime | Last occurrence time |

## Cron Schedule Examples

```
# Every hour
0 * * * *

# Every day at 9 AM
0 9 * * *

# Every Monday at 9 AM
0 9 * * 1

# Every weekday at 6 PM
0 18 * * 1-5

# First day of month at midnight
0 0 1 * *

# Every 15 minutes
*/15 * * * *
```

## API Endpoints

### REST API

```
POST   /api/v1/alerts/exports           Create export job
GET    /api/v1/alerts/exports           List export jobs
GET    /api/v1/alerts/exports/:id       Get export job
DELETE /api/v1/alerts/exports/:id       Cancel export job

POST   /api/v1/alerts/export-templates  Create template
GET    /api/v1/alerts/export-templates  List templates
GET    /api/v1/alerts/export-templates/:id  Get template
PUT    /api/v1/alerts/export-templates/:id  Update template
DELETE /api/v1/alerts/export-templates/:id  Delete template
```

### GraphQL

```graphql
mutation CreateExport {
  createAlertExport(
    input: {
      format: CSV
      columns: ["severity", "title", "status"]
      deliveryMethod: DOWNLOAD
    }
  ) {
    exportJob {
      id
      status
      progress
      downloadUrl
    }
  }
}

query ListExports {
  alertExports(first: 20) {
    edges {
      node {
        id
        format
        status
        progress
        totalRecords
        insertedAt
        downloadUrl
      }
    }
  }
}
```

## Database Schema

### alert_export_templates

```sql
CREATE TABLE alert_export_templates (
  id UUID PRIMARY KEY,
  name VARCHAR NOT NULL,
  description TEXT,
  format VARCHAR NOT NULL,  -- csv, json, pdf
  columns TEXT[] DEFAULT '{}',
  filter_json JSONB DEFAULT '{}',
  scheduled BOOLEAN DEFAULT FALSE,
  schedule_type VARCHAR,  -- daily, weekly, monthly
  schedule_cron VARCHAR,
  delivery_method VARCHAR,  -- download, email, s3, sftp
  delivery_config JSONB DEFAULT '{}',
  retention_days INTEGER DEFAULT 7,
  is_shared BOOLEAN DEFAULT FALSE,
  last_run_at TIMESTAMP,
  organization_id UUID NOT NULL REFERENCES organizations(id),
  created_by_id UUID REFERENCES users(id),
  inserted_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);
```

### alert_export_jobs

```sql
CREATE TABLE alert_export_jobs (
  id UUID PRIMARY KEY,
  status VARCHAR NOT NULL DEFAULT 'pending',
  format VARCHAR NOT NULL,
  filter_json JSONB DEFAULT '{}',
  columns TEXT[] DEFAULT '{}',
  progress INTEGER DEFAULT 0,
  total_records INTEGER,
  processed_records INTEGER DEFAULT 0,
  message VARCHAR,
  file_path VARCHAR,
  file_size BIGINT,
  download_url VARCHAR,
  url_expires_at TIMESTAMP,
  triggered_by VARCHAR,  -- manual, scheduled
  delivery_method VARCHAR,
  delivery_status VARCHAR,
  delivery_error TEXT,
  error_message TEXT,
  error_details JSONB,
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  organization_id UUID NOT NULL REFERENCES organizations(id),
  user_id UUID REFERENCES users(id),
  template_id UUID REFERENCES alert_export_templates(id),
  inserted_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);
```

## Background Jobs

### Export Worker

```elixir
# Queue: :exports
# Priority: 2
# Max Attempts: 3

# Job args:
%{
  "export_job_id" => "uuid",
  "delivery_config" => %{...}
}
```

### Scheduled Export Worker

```elixir
# Queue: :scheduled
# Cron: "0 * * * *" (every hour)

# Checks for due templates and triggers exports
```

### Cleanup Worker

```elixir
# Queue: :scheduled
# Cron: "0 2 * * *" (2 AM daily)

# Cleans up expired export files
```

## Configuration

### Environment Variables

```bash
# Export file storage directory
EXPORT_UPLOAD_DIR=priv/static/exports

# URL expiry (hours)
EXPORT_URL_EXPIRY_HOURS=24

# S3 configuration (for S3 delivery)
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1

# SMTP configuration (for email delivery)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=...
SMTP_PASSWORD=...
```

### Oban Configuration

```elixir
# config/config.exs
config :tamandua_server, Oban,
  queues: [
    exports: 5,      # 5 concurrent export workers
    scheduled: 1     # 1 scheduled task worker
  ]
```

## Performance Considerations

### Large Exports

- **Chunk Processing** - Exports are processed in chunks to avoid memory issues
- **Progress Tracking** - Real-time progress updates via job.progress
- **Background Processing** - All exports run in background via Oban
- **Timeout Protection** - 10-minute timeout for export generation

### Limits

- **Max Records** - Default 100,000 records per export
- **File Size** - PDF generation limited by ChromicPDF memory
- **Concurrent Exports** - 5 concurrent exports per organization

### Optimization Tips

```elixir
# Use column selection to reduce data size
columns: ["id", "severity", "title"]  # Only essential fields

# Apply filters to reduce record count
filter_json: %{
  "logic" => "AND",
  "conditions" => [
    %{"field" => "inserted_at", "operator" => "gte", "value" => "7d"}
  ]
}

# Use CSV for large exports (faster than PDF)
format: "csv"
```

## Security

### Access Control

- **Organization Scoping** - Users can only export alerts from their organization
- **Template Sharing** - Templates can be private or shared within organization
- **Download URLs** - Presigned URLs expire after 24 hours
- **RBAC Integration** - Export permissions enforced via RBAC system

### Data Protection

- **Sensitive Data** - Consider excluding sensitive columns from exports
- **Encryption** - S3 uploads use server-side encryption
- **Audit Trail** - All exports logged in export_jobs table
- **Email Security** - TLS required for SMTP delivery

## Monitoring

### Metrics

```elixir
# Export job success/failure rates
TelemetryMetrics.counter("export.jobs.completed")
TelemetryMetrics.counter("export.jobs.failed")

# Export duration
TelemetryMetrics.distribution("export.duration", unit: {:native, :millisecond})

# Delivery success rates
TelemetryMetrics.counter("export.delivery.success")
TelemetryMetrics.counter("export.delivery.failed")
```

### Alerts

- Failed export jobs after 3 retries
- Scheduled export failures
- Delivery failures (email, S3, SFTP)
- Disk space usage for export files

## Troubleshooting

### Export Fails with "Failed to generate PDF"

**Solution**: Ensure Chrome/Chromium is installed:
```bash
# Ubuntu/Debian
apt-get install chromium-browser

# macOS
brew install chromium

# Check if ChromicPDF is running
ps aux | grep chrome
```

### Email Delivery Fails

**Solution**: Check SMTP configuration and credentials:
```elixir
# Test SMTP connection
TamanduaServer.Mailer.deliver_export_email(
  ["test@example.com"],
  "Test",
  "Test message",
  "/path/to/test.pdf"
)
```

### S3 Upload Fails

**Solution**: Verify AWS credentials and bucket permissions:
```bash
# Test AWS credentials
aws s3 ls s3://your-bucket --profile default

# Check IAM permissions (requires s3:PutObject)
```

### Export Job Stuck in "Processing"

**Solution**: Check Oban queue:
```elixir
# Check worker status
Oban.check_queue(queue: :exports)

# Cancel stuck job
Exporter.cancel_export_job(job_id)

# Restart Oban
Supervisor.restart_child(TamanduaServer.Supervisor, Oban)
```

## Future Enhancements

- [ ] Excel (.xlsx) export format
- [ ] Custom PDF templates with branding
- [ ] Webhook delivery method
- [ ] Export compression (ZIP archives)
- [ ] Incremental exports (delta from last export)
- [ ] Export versioning and comparison
- [ ] Custom chart generation for PDFs
- [ ] Multi-language PDF reports
- [ ] Export annotations and comments
- [ ] Collaborative export templates
