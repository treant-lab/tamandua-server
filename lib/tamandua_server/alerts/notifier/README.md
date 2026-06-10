# Alert Notification System

Complete alert notification delivery system for Tamandua EDR with multi-channel support, escalation, and digest mode.

## Features

- **Multi-channel delivery**: Email, SMS (Twilio), Slack
- **User preferences**: Per-user severity filters, quiet hours, digest mode
- **Deduplication**: Prevents notification spam
- **Alert storm detection**: Automatic digest mode when >10 alerts in 5 minutes
- **Escalation rules**: Multi-tier escalation with delays
- **Business hours**: Respect business hours for escalations
- **Digest mode**: Batch low-priority alerts into periodic summaries

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Alert Created                       │
└────────────────────┬────────────────────────────────────┘
                     │
                     v
          ┌──────────────────────┐
          │  Notifier.notify_alert │
          └──────────┬─────────────┘
                     │
       ┌─────────────┴─────────────┐
       │  Check Deduplication      │
       │  (NotificationDedup)      │
       └─────────────┬─────────────┘
                     │
       ┌─────────────┴─────────────┐
       │  Get Users to Notify      │
       │  + Apply Preferences      │
       │  + Check Quiet Hours      │
       └─────────────┬─────────────┘
                     │
       ┌─────────────┴─────────────┐
       │  Send to Channels         │
       │  - Email (Swoosh)         │
       │  - SMS (Twilio)           │
       │  - Slack (Webhook)        │
       └─────────────┬─────────────┘
                     │
       ┌─────────────┴─────────────┐
       │  Schedule Escalation      │
       │  (if rules match)         │
       └───────────────────────────┘
```

## Modules

### Core

- **`TamanduaServer.Alerts.Notifier`**: Main notification dispatcher
- **`TamanduaServer.Alerts.NotificationDedup`**: Deduplication and storm detection (GenServer + ETS)
- **`TamanduaServer.Alerts.EscalationRules`**: Escalation rule management

### Channels

- **`TamanduaServer.Alerts.Notifier.Email`**: HTML email via Swoosh/SMTP
- **`TamanduaServer.Alerts.Notifier.SMS`**: SMS via Twilio API
- **`TamanduaServer.Alerts.Notifier.Slack`**: Rich notifications via webhooks

### Preferences

- **`TamanduaServer.Alerts.Notifier.Preferences`**: User preference management
- **`TamanduaServer.Alerts.NotificationPreference`**: Ecto schema

### Workers

- **`TamanduaServer.Workers.DigestWorker`**: Periodic digest (runs every 15min via Oban)
- **`TamanduaServer.Workers.EscalationWorker`**: Delayed escalation execution

## Configuration

### Environment Variables

```bash
# Base URL for notification links
TAMANDUA_BASE_URL=https://tamandua.example.com

# Email
EMAIL_ENABLED=true
NOTIFICATION_FROM_EMAIL=alerts@example.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=user@gmail.com
SMTP_PASSWORD=app-password
SMTP_SSL=false

# SMS (Twilio)
TWILIO_ENABLED=true
TWILIO_ACCOUNT_SID=ACxxxxx
TWILIO_AUTH_TOKEN=token
TWILIO_PHONE_NUMBER=+15551234567

# Slack
SLACK_ENABLED=true
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Behavior
NOTIFICATION_DEDUP_MINUTES=15
DIGEST_PERIOD_MINUTES=15
ALERT_DEDUP_WINDOW_SECONDS=300
```

### Database Tables

**notification_preferences**
```sql
CREATE TABLE notification_preferences (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  enabled BOOLEAN DEFAULT TRUE,
  email_enabled BOOLEAN DEFAULT TRUE,
  sms_enabled BOOLEAN DEFAULT FALSE,
  slack_enabled BOOLEAN DEFAULT FALSE,
  phone_number VARCHAR,
  slack_webhook_url VARCHAR,
  severity_filter TEXT[] DEFAULT '{}',
  quiet_hours_start TIME,
  quiet_hours_end TIME,
  digest_enabled BOOLEAN DEFAULT FALSE,
  inserted_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

**escalation_rules**
```sql
CREATE TABLE escalation_rules (
  id UUID PRIMARY KEY,
  name VARCHAR NOT NULL,
  description TEXT,
  enabled BOOLEAN DEFAULT TRUE,
  severity_filter TEXT[] DEFAULT '{}',
  mitre_techniques TEXT[] DEFAULT '{}',
  mitre_tactics TEXT[] DEFAULT '{}',
  agent_ids UUID[] DEFAULT '{}',
  escalation_delay_minutes INTEGER DEFAULT 30,
  escalate_to UUID[] DEFAULT '{}',
  escalation_channels TEXT[] DEFAULT '{email}',
  tiers JSONB[] DEFAULT '{}',
  business_hours_only BOOLEAN DEFAULT FALSE,
  business_hours_start TIME,
  business_hours_end TIME,
  business_days INTEGER[] DEFAULT '{1,2,3,4,5}',
  organization_id UUID REFERENCES organizations(id),
  created_by_id UUID REFERENCES users(id),
  inserted_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

## Usage

### Send Notification

```elixir
# Automatically called when alert is created
{:ok, alert} = Alerts.create_alert(%{
  severity: "critical",
  title: "Ransomware Detected",
  agent_id: agent_id
})
# Notifier.notify_alert/1 is called automatically in create_alert/1

# Manual notification
Notifier.notify_alert(alert)

# Force notification (bypass dedup and quiet hours)
Notifier.notify_alert(alert, force: true)

# Specific channels only
Notifier.notify_alert(alert, channels: [:email, :slack])
```

### User Preferences

```elixir
# Get preferences
prefs = Preferences.get_preferences(user_id)

# Set severity filter (only critical/high)
Preferences.set_severity_filter(user_id, ["critical", "high"])

# Set quiet hours (10 PM - 6 AM)
Preferences.set_quiet_hours(user_id, ~T[22:00:00], ~T[06:00:00])

# Enable digest mode
Preferences.enable_digest(user_id)

# Configure SMS
Preferences.set_phone_number(user_id, "+15551234567")

# Configure Slack
Preferences.set_slack_webhook(user_id, "https://hooks.slack.com/...")
```

### Escalation Rules

```elixir
# Create simple escalation rule
{:ok, rule} = EscalationRules.create_rule(%{
  name: "Critical Alert Escalation",
  severity_filter: ["critical", "high"],
  escalation_delay_minutes: 30,
  escalate_to: [manager_user_id],
  escalation_channels: ["email", "sms"]
})

# Multi-tier escalation
{:ok, rule} = EscalationRules.create_rule(%{
  name: "Multi-Tier Escalation",
  severity_filter: ["critical"],
  tiers: [
    %{tier: 1, delay_minutes: 15, escalate_to: [l1_user_id], channels: ["email"]},
    %{tier: 2, delay_minutes: 30, escalate_to: [l2_user_id], channels: ["email", "sms"]},
    %{tier: 3, delay_minutes: 60, escalate_to: [manager_user_id], channels: ["email", "sms", "slack"]}
  ],
  business_hours_only: true,
  business_hours_start: ~T[09:00:00],
  business_hours_end: ~T[17:00:00],
  business_days: [1, 2, 3, 4, 5]  # Mon-Fri
})
```

### Digest Mode

```elixir
# Digest worker runs automatically every 15 minutes via Oban cron
# To run manually:
Oban.insert(DigestWorker.new(%{}))

# Get digest users
users = Preferences.get_digest_users()

# Send digest manually
alerts = Alerts.list_alerts_for_org(org_id, limit: 50)
Notifier.send_digest(alerts, users)
```

### Testing

```elixir
# Send test notification
Notifier.send_test_notification(user, :email)
Notifier.send_test_notification(user, :sms)
Notifier.send_test_notification(user, :slack)

# Check dedup stats
NotificationDedup.get_stats()
# => %{total_tracked: 42, recent_notifications: 5, ...}

# Check for alert storm
NotificationDedup.check_storm()
# => :normal | {:storm, 15}
```

## Email Templates

Email notifications include:

- **HTML formatting** with severity-based colors
- **Alert details**: ID, agent, timestamp, threat score
- **Evidence** extracted from the alert
- **MITRE ATT&CK** techniques/tactics
- **Recommended actions** based on severity
- **Action buttons**: "View Alert", "Investigate"

## SMS Format

SMS messages are concise (under 160 chars when possible):

```
[Tamandua] CRITICAL Alert
Ransomware Detected on DESKTOP-ABC123
Agent: a1b2c3d4
https://edr.example.com/a/a1b2c3d4
```

## Slack Format

Slack notifications use rich formatting:

- **Color-coded** by severity
- **Emoji indicators** (🚨 critical, 🔴 high, etc.)
- **Structured fields**: Agent, severity, threat score, MITRE techniques
- **Interactive buttons**: View Alert, Investigate, Mark False Positive

## Deduplication

### Alert Deduplication
- Groups similar alerts within 5 minutes (configurable)
- Based on: rule ID + agent ID + primary entity (process/file/IP)
- Increments occurrence count instead of creating duplicate

### Notification Deduplication
- Prevents sending multiple notifications for same alert within 15 minutes
- ETS-based in-memory tracking
- Auto-cleanup of old entries every 5 minutes

### Alert Storm Detection
- Detects >10 alerts in 5 minutes
- Automatically switches to digest mode
- Returns `:storm` status to prevent spam

## Escalation

### Simple Escalation
1. Alert created and matches escalation rule
2. Wait `escalation_delay_minutes`
3. If alert still unresolved and unassigned → send notification to escalation contacts

### Multi-Tier Escalation
1. Alert created and matches rule
2. Wait tier 1 delay → escalate to tier 1 contacts
3. If still unresolved, wait tier 2 delay → escalate to tier 2 contacts
4. Continue through all tiers until resolved or tiers exhausted

### Business Hours
- Escalations can be restricted to business hours
- Configurable start/end time and days of week
- Outside business hours = no escalation scheduled

## Performance

- **ETS-backed deduplication**: O(1) lookups
- **Async sending**: Email/SMS/Slack sent in parallel
- **Batched digests**: Reduces notification volume by 90%+
- **Circuit breaker**: Twilio/SMTP failures don't block alert creation

## Security

- **Webhook validation**: Slack webhooks must match `hooks.slack.com` pattern
- **Phone validation**: SMS requires valid phone number format
- **Secrets**: SMTP/Twilio credentials from env vars, never logged
- **HTTPS only**: All external API calls use HTTPS
- **No PII in logs**: User emails/phones not logged

## Monitoring

```elixir
# Check notification stats
NotificationDedup.get_stats()

# Check escalation rules
EscalationRules.list_rules(enabled_only: true)

# Check digest users
Preferences.get_digest_users() |> length()

# Oban jobs
Oban.check_queue(queue: :notifications)
Oban.check_queue(queue: :escalations)
```

## Troubleshooting

### Notifications not sending

1. Check configuration:
   ```elixir
   Application.get_env(:tamandua_server, :email_enabled)
   Application.get_env(:tamandua_server, :twilio_enabled)
   ```

2. Check user preferences:
   ```elixir
   Preferences.get_preferences(user_id)
   ```

3. Check deduplication:
   ```elixir
   NotificationDedup.check_recent(alert)
   ```

4. Check quiet hours:
   ```elixir
   Preferences.can_notify_now?(user_id)
   ```

### Email delivery fails

- Verify SMTP credentials
- Check SMTP server allows connections
- Check firewall rules (port 587/465)
- Test with `Notifier.send_test_notification(user, :email)`

### SMS delivery fails

- Verify Twilio credentials
- Check Twilio account balance
- Verify phone number format (+country code)
- Check Twilio logs in dashboard

### Escalations not triggering

- Check escalation rule is enabled
- Verify rule matches alert (severity, MITRE, etc.)
- Check business hours settings
- Check Oban jobs: `Oban.check_queue(queue: :escalations)`

## Future Enhancements

- [ ] PagerDuty integration
- [ ] Microsoft Teams webhook support
- [ ] Custom webhook support
- [ ] Voice call escalation
- [ ] Mobile push notifications
- [ ] Notification analytics dashboard
- [ ] A/B testing for notification content
- [ ] Machine learning for optimal notification timing
