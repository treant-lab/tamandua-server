# Notification Integrations

The Tamandua EDR notification system provides robust, multi-channel alert delivery with routing rules, throttling, and delivery tracking.

## Features

- **7 Providers**: Slack, Microsoft Teams, Email, PagerDuty, OpsGenie, Discord, Telegram
- **Routing Rules**: Filter alerts by severity, type, MITRE technique, or custom tags
- **Throttling**: Prevent notification spam with per-integration rate limits
- **Delivery Logs**: Track sent, failed, and throttled notifications
- **Template Engine**: Customize notification content with Liquid/Mustache-style templates
- **Test Notifications**: Verify configuration before going live
- **Async Delivery**: Oban-powered background jobs with retry logic

## Architecture

```
Alert Created
    |
    v
Notifications.notify_alert/2
    |
    v
Router.route_alert/2 (applies routing rules)
    |
    v
DeliveryWorker (Oban job, queued)
    |
    v
Throttler.throttled?/1 (check rate limit)
    |
    v
Provider.send_notification/3
    |
    v
DeliveryLog (record result)
```

## Usage

### Creating an Integration

```elixir
{:ok, integration} = Notifications.create_integration(%{
  name: "Security Team Slack",
  provider: "slack",
  organization_id: org_id,
  config: %{
    webhook_url: "https://hooks.slack.com/services/...",
    channel: "#security-alerts"
  },
  template_title: "*{{ alert.severity | upcase }}*: {{ alert.title }}",
  template_body: """
  :warning: Alert from Tamandua EDR

  *Agent:* {{ agent.hostname }}
  *MITRE:* {{ alert.mitre_technique }}
  *Time:* {{ alert.inserted_at }}

  {{ alert.description }}
  """,
  routing_rules: %{
    severity: ["critical", "high"],
    mitre_techniques: ["T1059", "T1055"]
  },
  throttle_enabled: true,
  throttle_max_per_hour: 30
})
```

### Sending Notifications

Notifications are automatically sent when alerts are created. To manually trigger:

```elixir
# Async (via Oban)
{:ok, integrations} = Notifications.notify_alert(alert, organization_id)

# Synchronous (for testing)
{:ok, response} = Notifications.send_notification_now(integration, alert, agent)
```

### Testing an Integration

```elixir
case Notifications.test_integration(integration) do
  {:ok, message} -> IO.puts("Test passed: #{message}")
  {:error, reason} -> IO.puts("Test failed: #{reason}")
end
```

### Viewing Delivery Logs

```elixir
# Logs for a specific integration
logs = Notifications.list_delivery_logs(integration_id, limit: 50)

# Logs for a specific alert
logs = Notifications.list_alert_delivery_logs(alert_id)

# Delivery statistics
stats = Notifications.get_delivery_stats(integration_id)
# %{total: 100, sent: 95, failed: 3, throttled: 2}
```

## Providers

### Slack

**Configuration:**
- `webhook_url` (required) OR `oauth_token` (required)
- `channel` (optional) - Override default channel

**Features:**
- Rich formatting with Slack's Block Kit
- Thread support
- @ mentions

### Microsoft Teams

**Configuration:**
- `webhook_url` (required)

**Features:**
- MessageCard and Adaptive Card formats
- Action buttons

### Email (SMTP)

**Configuration:**
- `smtp_host` (required)
- `smtp_port` (required, default: 587)
- `username` (required)
- `password` (required)
- `from` (required)
- `to` (optional)

**Features:**
- HTML and plain text
- TLS encryption

### PagerDuty

**Configuration:**
- `integration_key` (required) - Events API v2 integration key

**Features:**
- Automatic incident creation
- Severity mapping (critical → critical, high → error, etc.)

### OpsGenie

**Configuration:**
- `api_key` (required)
- `region` (optional: "us" or "eu", default: "us")

**Features:**
- Priority mapping (critical → P1, high → P2, etc.)
- Team routing

### Discord

**Configuration:**
- `webhook_url` (required)

**Features:**
- Rich embeds with color-coded severity
- Timestamp and footer

### Telegram

**Configuration:**
- `bot_token` (required)
- `chat_id` (required) - Can be user, group, or channel

**Features:**
- HTML formatting
- Inline links

## Routing Rules

Routing rules filter which alerts trigger a notification. Rules are ANDed together.

```elixir
routing_rules: %{
  # Only alerts with these severities
  severity: ["critical", "high"],

  # Only specific alert types
  alert_types: ["malware", "ransomware"],

  # Only specific MITRE techniques (supports prefixes)
  mitre_techniques: ["T1059", "T1055"],

  # Only alerts with these tags
  tags: ["production", "critical-asset"]
}
```

**Empty rules = match all alerts.**

### Alert Type Detection

Alert types are extracted from:
1. `alert.alert_type` field (if present)
2. `alert.type` field (if present)
3. Keywords in `alert.title` (malware, ransomware, phishing, c2, etc.)

### MITRE Technique Matching

- Exact match: `"T1059.001"` matches `"T1059.001"`
- Prefix match: `"T1059"` matches `"T1059.001"`, `"T1059.003"`, etc.

## Throttling

Prevent notification spam by limiting the number of notifications per hour.

```elixir
throttle_enabled: true
throttle_max_per_hour: 30  # Max 30 notifications/hour
```

Throttled notifications are logged but not sent. The throttle window is a sliding 1-hour window.

## Template Variables

Available variables for templates:

| Variable | Description |
|----------|-------------|
| `alert.id` | Alert UUID |
| `alert.title` | Alert title |
| `alert.severity` | critical, high, medium, low, info |
| `alert.description` | Full alert description |
| `alert.inserted_at` | Alert creation time |
| `alert.mitre_technique` | MITRE ATT&CK technique ID |
| `agent.id` | Agent UUID |
| `agent.hostname` | Agent hostname |
| `agent.os_type` | windows, linux, macos |
| `agent.os_version` | OS version string |
| `dashboard_url` | Dashboard base URL |

### Filters (Liquid-style)

Basic filters are supported:

```liquid
{{ alert.severity | upcase }}            → CRITICAL
{{ alert.title | downcase }}             → malware detected
{{ alert.inserted_at | date: "%Y-%m-%d" }} → 2026-02-20
```

## Database Schema

### notification_integrations

| Column | Type | Description |
|--------|------|-------------|
| id | uuid | Primary key |
| organization_id | uuid | Foreign key |
| name | string | Integration display name |
| provider | string | slack, teams, email, etc. |
| enabled | boolean | Active status |
| config | jsonb | Provider-specific config |
| template_title | text | Title template |
| template_body | text | Body template |
| routing_rules | jsonb | Routing filters |
| throttle_enabled | boolean | Enable rate limiting |
| throttle_max_per_hour | integer | Max notifications/hour |
| last_success_at | timestamp | Last successful delivery |
| last_failure_at | timestamp | Last failed delivery |
| failure_count | integer | Consecutive failures |
| total_sent | integer | Total successful deliveries |
| total_failed | integer | Total failed deliveries |

### notification_delivery_logs

| Column | Type | Description |
|--------|------|-------------|
| id | uuid | Primary key |
| integration_id | uuid | Foreign key |
| organization_id | uuid | Foreign key |
| alert_id | uuid | Foreign key (nullable) |
| status | string | sent, failed, retry, throttled |
| provider | string | Provider name |
| recipient | string | Channel, email, etc. |
| rendered_title | text | Rendered title |
| rendered_body | text | Rendered body |
| error_message | text | Error details (if failed) |
| response_code | integer | HTTP status code |
| response_body | text | Provider response |
| delivered_at | timestamp | Delivery timestamp |
| retry_count | integer | Number of retries |
| next_retry_at | timestamp | Next retry time |

## Configuration

### Environment Variables

```bash
# Dashboard URL (for alert links)
export DASHBOARD_URL=https://tamandua.example.com

# Enable email notifications (requires SMTP config)
export EMAIL_ENABLED=true
```

### Oban Queue

The `notifications` queue processes notification delivery jobs:

```elixir
config :tamandua_server, Oban,
  queues: [
    notifications: 10  # 10 concurrent workers
  ]
```

### Supervision Tree

The `Notifications.Throttler` GenServer must be started:

```elixir
children = [
  # ...
  TamanduaServer.Notifications.Throttler,
  # ...
]
```

## Testing

### Unit Tests

```bash
mix test test/tamandua_server/notifications_test.exs
```

### Manual Testing

```elixir
# Create test integration
{:ok, integration} = Notifications.create_integration(%{
  name: "Test Slack",
  provider: "slack",
  organization_id: org_id,
  config: %{webhook_url: "https://hooks.slack.com/..."}
})

# Send test notification
Notifications.test_integration(integration)

# Create test alert and notify
alert = insert(:alert, organization_id: org_id, severity: "critical")
{:ok, integrations} = Notifications.notify_alert(alert, org_id)
```

## Troubleshooting

### Notifications Not Sending

1. Check integration is enabled: `integration.enabled == true`
2. Check routing rules: `Router.route_alert(alert, org_id)`
3. Check throttling: `Throttler.get_stats(integration.id)`
4. Check delivery logs: `Notifications.list_delivery_logs(integration_id)`

### Provider Errors

Check delivery logs for error messages:

```elixir
logs = Notifications.list_delivery_logs(integration_id, limit: 10)
Enum.each(logs, fn log ->
  if log.status == "failed" do
    IO.puts("Error: #{log.error_message}")
  end
end)
```

### Test Connection Failures

```elixir
case Notifications.test_integration(integration) do
  {:error, reason} ->
    IO.puts("Test failed: #{reason}")
    # Common issues:
    # - Invalid webhook URL
    # - Expired API key
    # - Network connectivity
    # - SMTP authentication failure
end
```

## Future Enhancements

- [ ] Template preview UI
- [ ] Solid (Liquid parser) for advanced templating
- [ ] Webhook provider (generic HTTP POST)
- [ ] SMS provider (Twilio)
- [ ] Jira integration
- [ ] ServiceNow integration
- [ ] Custom field mapping
- [ ] Notification aggregation/digests
- [ ] A/B testing for templates
