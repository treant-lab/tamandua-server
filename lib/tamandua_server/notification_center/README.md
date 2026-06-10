# Notification Center

Comprehensive notification system for Tamandua EDR with multi-channel delivery, escalation policies, and user preferences.

## Features

### 1. Notification Types
- **Alert Notifications**: New alert, status change, assignment, escalation
- **Comment Notifications**: Mentions, replies
- **System Notifications**: Agent offline, integration failure, policy violation
- **SLA Notifications**: Breach warnings, deadline alerts

### 2. Delivery Channels
- **In-App**: Real-time notification center with dropdown and full page view
- **Email**: HTML email notifications with templates
- **SMS**: Twilio integration for critical alerts
- **Slack**: Webhook integration with rich formatting
- **Microsoft Teams**: Adaptive card notifications
- **PagerDuty**: Incident creation for critical alerts
- **Webhook**: Custom webhook notifications with configurable auth

### 3. User Preferences
- **Global Settings**: Enable/disable notifications, frequency (immediate, digest)
- **Quiet Hours**: Do Not Disturb with timezone support
- **Severity Threshold**: Only notify for high/critical alerts
- **Per-Type Channel Selection**: Configure channels per notification type
- **Critical Override**: Always notify for critical alerts

### 4. Escalation Policies
- **Escalation Chains**: Multi-level escalation with delays
- **Auto-Escalation**: Automatic escalation if not acknowledged
- **On-Call Schedules**: Support for rotation schedules
- **Acknowledgment**: Stop escalation when acknowledged

### 5. Notification Features
- **Grouping**: Group similar notifications (e.g., "5 new alerts")
- **Expiry**: Auto-delete old notifications (default 7 days)
- **Read/Unread Tracking**: Mark as read, mark all as read
- **Archive**: Archive old notifications
- **Filtering**: Filter by type, read status, date
- **Real-time Updates**: Live updates via Phoenix PubSub

## Architecture

```
┌─────────────────┐
│   Alert/Event   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Dispatcher    │ ← Check preferences, quiet hours, severity
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Notification   │ ← Create notification record
│     Record      │   Group if applicable
└────────┬────────┘
         │
         ├──────────────┬──────────────┬────────────┬──────────┐
         ▼              ▼              ▼            ▼          ▼
    ┌────────┐    ┌────────┐    ┌────────┐   ┌─────────┐  ┌────────┐
    │ In-App │    │ Email  │    │  SMS   │   │  Slack  │  │Webhook │
    └────────┘    └────────┘    └────────┘   └─────────┘  └────────┘
         │              │              │            │          │
         ▼              ▼              ▼            ▼          ▼
    PubSub        Oban Worker    Oban Worker  Oban Worker Oban Worker
                  (async)        (async)      (async)     (async)
```

## Usage

### Dispatching Notifications

```elixir
# Simple notification
TamanduaServer.NotificationCenter.dispatch(
  "alert_new",
  "New Critical Alert",
  "Malware detected on DESKTOP-01",
  %{
    organization_id: org_id,
    users: [user_id],
    priority: "critical",
    related_resource_type: "alert",
    related_resource_id: alert_id
  }
)

# With grouping
TamanduaServer.NotificationCenter.dispatch(
  "agent_offline",
  "Agents Offline",
  "Multiple agents went offline",
  %{
    organization_id: org_id,
    users: [admin_id],
    group_key: "agents_offline_#{Date.utc_today()}"
  }
)

# With escalation policy
TamanduaServer.NotificationCenter.dispatch(
  "sla_breach",
  "SLA Breach: #{alert.title}",
  "Alert not resolved within SLA",
  %{
    organization_id: org_id,
    escalation_policy_id: policy_id,
    related_resource_type: "alert",
    related_resource_id: alert_id
  }
)
```

### Integration with Alert System

Add to your alert creation/update logic:

```elixir
# In TamanduaServer.Alerts context

def create_alert(attrs) do
  Multi.new()
  |> Multi.insert(:alert, Alert.changeset(%Alert{}, attrs))
  |> Multi.run(:notify, fn _repo, %{alert: alert} ->
    NotificationCenter.dispatch(
      "alert_new",
      "New Alert: #{alert.title}",
      alert.description,
      %{
        organization_id: alert.organization_id,
        priority: severity_to_priority(alert.severity),
        related_resource_type: "alert",
        related_resource_id: alert.id,
        users: get_alert_recipients(alert)
      }
    )
  end)
  |> Repo.transaction()
end

def assign_alert(alert, user_id) do
  Multi.new()
  |> Multi.update(:alert, Alert.changeset(alert, %{assigned_to_id: user_id}))
  |> Multi.run(:notify, fn _repo, %{alert: alert} ->
    NotificationCenter.dispatch(
      "alert_assigned",
      "Alert Assigned: #{alert.title}",
      "This alert has been assigned to you",
      %{
        organization_id: alert.organization_id,
        users: [user_id],
        related_resource_type: "alert",
        related_resource_id: alert.id
      }
    )
  end)
  |> Repo.transaction()
end
```

### Escalation Policies

```elixir
# Create escalation policy
{:ok, policy} = NotificationCenter.create_escalation_policy(%{
  organization_id: org_id,
  name: "Critical Alert Escalation",
  description: "Escalation for critical alerts",
  escalation_chain: [
    %{"user_id" => analyst_id, "delay_minutes" => 15},
    %{"user_id" => senior_analyst_id, "delay_minutes" => 30},
    %{"user_id" => manager_id, "delay_minutes" => 60}
  ],
  trigger_conditions: %{
    severity: ["critical"],
    alert_types: ["malware", "ransomware"]
  }
})

# Start escalation
NotificationCenter.start_escalation(alert_id, policy.id)

# Acknowledge (stops escalation)
NotificationCenter.acknowledge_escalation(instance_id, user_id)
```

## Configuration

### Environment Variables

```bash
# Twilio (SMS)
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_FROM_NUMBER=+1234567890

# Email
NOTIFICATION_FROM_EMAIL=noreply@treantlab.org
NOTIFICATION_FROM_NAME="Tamandua EDR"

# PagerDuty
PAGERDUTY_API_KEY=your_api_key
PAGERDUTY_SERVICE_ID=your_service_id
PAGERDUTY_FROM_EMAIL=admin@example.com
```

### Organization Settings

Store in `settings` table:
- `slack_webhook_url`
- `teams_webhook_url`
- `pagerduty_api_key`
- `pagerduty_service_id`

### Template System

Custom notification templates support EEx templating:

```elixir
# Create custom email template
NotificationCenter.create_template(%{
  organization_id: org_id,
  type: "alert_new",
  channel: "email",
  name: "Custom Alert Email",
  subject_template: "[URGENT] <%= notification.title %>",
  body_template: """
  Alert Details:
  - Title: <%= notification.title %>
  - Severity: <%= alert.severity %>
  - Agent: <%= alert.agent.hostname %>

  View: <%= alert_url %>
  """
})
```

### Webhooks

```elixir
# Create webhook
NotificationCenter.create_webhook(%{
  organization_id: org_id,
  name: "My Webhook",
  url: "https://api.example.com/webhooks/tamandua",
  method: "POST",
  auth_type: "bearer",
  auth_config: %{"token" => "your_token"},
  notification_types: ["alert_new", "alert_escalated"]
})
```

## Database Schema

### Notifications Table
```sql
- id (uuid)
- organization_id (uuid)
- user_id (uuid)
- type (enum)
- title (string)
- body (text)
- priority (string)
- metadata (jsonb)
- related_resource_type (string)
- related_resource_id (uuid)
- read_at (timestamp)
- acknowledged_at (timestamp)
- archived_at (timestamp)
- expires_at (timestamp)
- group_key (string)
- group_count (integer)
- inserted_at (timestamp)
- updated_at (timestamp)
```

### User Preferences Table
```sql
- id (uuid)
- user_id (uuid)
- organization_id (uuid)
- enabled (boolean)
- frequency (string) - immediate, digest_15min, digest_hourly, digest_daily
- quiet_hours_enabled (boolean)
- quiet_hours_start (time)
- quiet_hours_end (time)
- quiet_hours_timezone (string)
- min_severity (string)
- channel_preferences (jsonb) - per-type channel selection
- critical_override (boolean)
```

### Escalation Policies Table
```sql
- id (uuid)
- organization_id (uuid)
- name (string)
- description (text)
- enabled (boolean)
- escalation_chain (jsonb) - array of {user_id, delay_minutes}
- trigger_conditions (jsonb)
- schedule_enabled (boolean)
- schedule (jsonb)
```

## UI Components

### Notification Dropdown (Top Nav)
```heex
<.live_component
  module={TamanduaServerWeb.Components.NotificationDropdown}
  id="notification-dropdown"
  user_id={@current_user.id}
/>
```

### Full Notification Center
Navigate to: `/notifications`

### Preferences Page
Navigate to: `/notifications/preferences`

## Background Jobs

All channel deliveries run as Oban workers in the `:notifications` queue:
- `EmailWorker` - Email delivery
- `SmsWorker` - SMS via Twilio
- `SlackWorker` - Slack webhook
- `TeamsWorker` - Teams webhook
- `PagerDutyWorker` - PagerDuty incident creation
- `WebhookWorker` - Custom webhooks

## Periodic Tasks

Add to your application supervision tree:

```elixir
# Escalation manager
{TamanduaServer.NotificationCenter.EscalationManager, []}

# Cleanup cron (in Oban config)
%{
  cleanup_notifications: [
    schedule: "0 2 * * *",  # Daily at 2 AM
    worker: TamanduaServer.Workers.NotificationCleanup
  ]
}
```

## Testing

```bash
# Run tests
mix test test/tamandua_server/notification_center_test.exs

# Test specific channel
iex> NotificationCenter.dispatch("alert_new", "Test", "Body", %{
  organization_id: org_id,
  users: [user_id],
  priority: "critical"
})
```

## Monitoring

Key metrics to monitor:
- Notification delivery rate
- Channel failure rate
- Escalation response time
- Unread notification count per user
- Notification queue depth

## Troubleshooting

### Notifications not received
1. Check user preferences (`UserPreference`)
2. Verify quiet hours settings
3. Check severity threshold
4. Verify channel configuration (API keys, webhooks)
5. Check Oban queue status

### Email not sending
- Verify SMTP settings in config
- Check `notification_deliveries` table for errors
- Review Oban job failures

### SMS not sending
- Verify Twilio credentials
- Check user has `phone` field set
- Review Twilio API logs

### Escalation not working
- Verify `EscalationManager` is running
- Check escalation instance state
- Verify escalation chain user IDs are valid

## Security

- User preferences are scoped to user + organization
- Webhook auth supports: none, basic, bearer, api_key
- Email templates are sandboxed EEx (no code execution)
- All delivery logs retained for audit trail
- Rate limiting on notification creation (TODO)

## Future Enhancements

- [ ] Push notifications (mobile)
- [ ] Voice calls for critical alerts
- [ ] Machine learning for notification prioritization
- [ ] Smart grouping (ML-based)
- [ ] Notification analytics dashboard
- [ ] A/B testing for notification copy
- [ ] Rich media attachments
- [ ] Interactive notifications (buttons, quick actions)
