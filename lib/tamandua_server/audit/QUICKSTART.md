# Activity Feed & Audit Search - Quickstart Guide

## 1. Run Migrations

```bash
cd apps/tamandua_server
mix ecto.migrate
```

## 2. Add Routes

Edit `apps/tamandua_server_web/lib/tamandua_server_web/router.ex`:

```elixir
scope "/", TamanduaServerWeb do
  pipe_through [:browser, :require_authenticated_user]

  live "/activity", ActivityFeedLive, :index
  live "/audit/search", AuditSearchLive, :index
end
```

## 3. Basic Usage

### Log Activities in Your Controllers

```elixir
defmodule TamanduaServerWeb.AlertController do
  alias TamanduaServer.Audit.ActivityLogger

  def update(conn, %{"id" => id, "alert" => alert_params}) do
    alert = Alerts.get_alert!(id)
    
    case Alerts.update_alert(alert, alert_params) do
      {:ok, updated_alert} ->
        # Log the activity
        ActivityLogger.log_alert_status_change(
          updated_alert,
          alert.status,
          updated_alert.status,
          conn.assigns.current_user.id,
          get_ip(conn)
        )
        
        json(conn, updated_alert)
      
      {:error, changeset} ->
        json(conn, %{errors: changeset.errors})
    end
  end
  
  defp get_ip(conn) do
    conn.remote_ip
    |> Tuple.to_list()
    |> Enum.join(".")
  end
end
```

### Subscribe to Activity Feed

```elixir
# In your LiveView
Phoenix.PubSub.subscribe(
  TamanduaServer.PubSub,
  "activity:org:#{organization_id}"
)

# Handle broadcasts
def handle_info({:new_activity, activity}, socket) do
  # Update UI with new activity
  {:noreply, update(socket, :activities, fn acts -> [activity | acts] end)}
end
```

## 4. Configure Forwarders

### Splunk HEC

```elixir
alias TamanduaServer.Audit.AuditForwarder

Repo.insert!(%AuditForwarder{
  name: "Production Splunk",
  forwarder_type: "splunk",
  organization_id: org.id,
  config: %{
    "hec_url" => "https://splunk.example.com:8088/services/collector",
    "hec_token" => System.get_env("SPLUNK_HEC_TOKEN"),
    "index" => "tamandua_audit"
  },
  forward_all: true,
  is_active: true,
  batch_size: 100,
  batch_timeout_ms: 5000
})
```

### AWS S3

```elixir
Repo.insert!(%AuditForwarder{
  name: "S3 Archive",
  forwarder_type: "s3",
  organization_id: org.id,
  config: %{
    "bucket" => "tamandua-audit-logs",
    "region" => "us-east-1",
    "prefix" => "production/audit-logs"
  },
  filter_severity: ["critical", "high"],
  is_active: true
})
```

## 5. Search & Export

### Programmatic Search

```elixir
alias TamanduaServer.Audit.ActivityLogger

# Get failed logins from last 24 hours
failed_logins = ActivityLogger.search_paginated(
  organization_id,
  %{
    action: "auth.login_failed",
    from_date: DateTime.add(DateTime.utc_now(), -86400, :second)
  },
  1,
  50
)

# Full-text search
results = ActivityLogger.full_text_search(
  organization_id,
  "quarantine failed",
  %{category: "response"},
  1,
  50
)
```

### Export to CSV

```elixir
alias TamanduaServer.Audit.ActivityExporter

{:ok, export} = ActivityExporter.create_export(%{
  organization_id: org.id,
  user_id: user.id,
  export_type: "csv",
  filters: %{
    "from_date" => "2024-01-01",
    "to_date" => "2024-12-31",
    "category" => "response"
  }
})

# Check status later
export = Repo.get!(AuditExport, export.id)
export.status  # "completed"
export.file_path  # "/tmp/tamandua_exports/abc-123.csv"
```

## 6. Suspicious Activity Monitoring

### Get Suspicious Activity Summary

```elixir
alias TamanduaServer.Audit.SuspiciousActivityDetector

summary = SuspiciousActivityDetector.get_suspicious_summary(org.id, 7)

summary.total_count  # Total suspicious activities in last 7 days
summary.by_reason  # Grouped by reason
summary.high_risk  # Activities with risk_score >= 70
```

### Subscribe to Suspicious Activity Alerts

```elixir
Phoenix.PubSub.subscribe(
  TamanduaServer.PubSub,
  "suspicious_activity:org:#{organization_id}"
)

def handle_info({:suspicious_activity, activity}, socket) do
  # Show alert notification
  {:noreply, put_flash(socket, :error, "Suspicious activity detected!")}
end
```

## 7. Testing

```bash
# Run all audit tests
mix test test/tamandua_server/audit/

# Test specific module
mix test test/tamandua_server/audit/activity_logger_test.exs

# Test with coverage
mix test --cover
```

## Common Actions Reference

```elixir
# Authentication
ActivityLogger.log_login(user_id, org_id, ip, user_agent)
ActivityLogger.log_login_failure(email, org_id, ip, reason)

# Alert management
ActivityLogger.log_alert_status_change(alert, old_status, new_status, user_id, ip)

# Configuration
ActivityLogger.log_config_change(type, id, changes, user_id, org_id, ip)

# Response actions
ActivityLogger.log_response_action(action_type, agent_id, user_id, org_id, metadata)

# Data access (for compliance)
ActivityLogger.log_data_access(action, resource_type, user_id, org_id, metadata)

# Generic logging
ActivityLogger.log(%{
  action: "custom.action",
  resource_type: "custom",
  resource_id: id,
  user_id: user_id,
  organization_id: org_id,
  metadata: %{...},
  severity: "medium",
  category: "custom"
})
```

## Environment Variables

```bash
# Splunk
SPLUNK_HEC_URL=https://splunk.example.com:8088/services/collector
SPLUNK_HEC_TOKEN=your-token-here

# AWS S3
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
AWS_REGION=us-east-1

# Syslog
SYSLOG_HOST=syslog.example.com
SYSLOG_PORT=514

# Azure Sentinel
AZURE_WORKSPACE_ID=your-workspace-id
AZURE_SHARED_KEY=your-shared-key
```

## Troubleshooting

### Activities not appearing in feed
- Check PubSub is running: `Phoenix.PubSub.node_name(TamanduaServer.PubSub)`
- Verify LiveView is connected: `connected?(socket)` should be true
- Check organization_id matches

### Forwarder failing
- Check forwarder health: `Repo.get!(AuditForwarder, id).health_status`
- View last error: `forwarder.last_error_message`
- Verify credentials are correct

### Suspicious detection not working
- Check `SuspiciousActivityDetector.analyze/1` is being called
- Verify thresholds are configured correctly
- Review detection logic for your use case

## Performance Tips

1. Use indexes: All common query paths are indexed
2. Partition tables: For >10M records, partition by inserted_at
3. Archive old data: Move logs >90 days to S3
4. Batch forwarders: Use larger batch sizes for high volume
5. Use saved searches: Cache common queries

## Next Steps

- Create custom compliance report templates
- Set up retention policies
- Configure scheduled exports
- Add custom suspicious activity detectors
- Integrate with alerting system
