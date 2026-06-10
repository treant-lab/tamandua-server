# Insider Threat Detection - Quick Start Guide

## Setup

### 1. Run Migrations
```bash
cd apps/tamandua_server
mix ecto.migrate
```

### 2. Start Scheduler
Add to your application supervisor (`lib/tamandua_server/application.ex`):

```elixir
children = [
  # ... existing children
  TamanduaServer.InsiderThreat.Scheduler
]
```

### 3. Create Peer Groups

Auto-create role-based peer groups:
```elixir
{:ok, peer_groups} = TamanduaServer.InsiderThreat.auto_create_role_based_peer_groups(org_id)
```

Or create manually:
```elixir
{:ok, peer_group} = TamanduaServer.InsiderThreat.create_peer_group(%{
  name: "Software Engineers",
  description: "Engineering team",
  group_type: "role",
  organization_id: org_id
})

# Add members
TamanduaServer.InsiderThreat.add_peer_group_member(peer_group.id, user1_id)
TamanduaServer.InsiderThreat.add_peer_group_member(peer_group.id, user2_id)
```

### 4. Calculate Initial Baselines
```elixir
# Calculate baselines for last 30 days
end_time = DateTime.utc_now()
start_time = DateTime.add(end_time, -30 * 24 * 3600, :second)

{:ok, baseline} = TamanduaServer.InsiderThreat.calculate_peer_group_baseline(
  peer_group.id,
  start_time,
  end_time
)
```

## Basic Usage

### Analyze User Activity
```elixir
alias TamanduaServer.InsiderThreat

# Analyze last 24 hours
end_time = DateTime.utc_now()
start_time = DateTime.add(end_time, -24 * 3600, :second)

{:ok, result} = InsiderThreat.analyze_user(user_id, start_time, end_time)

IO.inspect(result.risk_score)
# %{
#   total: 75.0,
#   severity: :critical,
#   components: %{indicators: 65.0, peer_group: 10.0},
#   indicators: [...],
#   trend: :increasing,
#   threshold_exceeded: true
# }
```

### View Alerts
```elixir
# Get top risky users
top_users = InsiderThreat.top_users_by_risk(org_id, 10)

Enum.each(top_users, fn user ->
  IO.puts "User: #{user.user.email}, Risk: #{user.risk_score}"
end)

# Get recent alerts
recent = InsiderThreat.recent_alerts(org_id, 24)

# Get all open alerts
open_alerts = InsiderThreat.list_alerts(org_id, %{status: "open"})
```

### Start Investigation
```elixir
alert = InsiderThreat.get_alert(alert_id)

# Start investigating
{:ok, alert} = InsiderThreat.start_investigation(alert, investigator_id)

# Create investigation case
{:ok, investigation} = InsiderThreat.create_investigation(%{
  title: "Data exfiltration investigation",
  description: "User accessed 1000 customer records and uploaded to cloud storage",
  subject_user_id: alert.user_id,
  organization_id: org_id,
  lead_investigator_id: investigator_id,
  priority: "critical"
})

# Link alert to investigation
InsiderThreat.Alert.link_investigation(alert, investigation.id)
```

### Collect Evidence
```elixir
# Get user activity timeline
timeline = InsiderThreat.get_user_timeline(
  user_id,
  investigation.investigation_started_at,
  DateTime.utc_now()
)

# Get access log
access_log = InsiderThreat.get_user_access_log(
  user_id,
  investigation.investigation_started_at,
  DateTime.utc_now()
)

# Get network activity
network = InsiderThreat.get_user_network_activity(
  user_id,
  investigation.investigation_started_at,
  DateTime.utc_now()
)

# Add to investigation
InsiderThreat.add_evidence(investigation, %{
  type: "timeline",
  description: "User activity timeline",
  data: timeline,
  collected_by: investigator_id
})

InsiderThreat.add_evidence(investigation, %{
  type: "access_log",
  description: "Data access log",
  data: access_log,
  collected_by: investigator_id
})
```

### Resolve Alert
```elixir
# True positive - malicious activity
{:ok, alert} = InsiderThreat.resolve_alert(
  alert,
  resolver_id,
  "Confirmed data exfiltration. User account disabled, legal action initiated.",
  false
)

# False positive - legitimate activity
{:ok, alert} = InsiderThreat.resolve_alert(
  alert,
  resolver_id,
  "Legitimate data export for approved project. User had proper authorization.",
  true
)
```

### Close Investigation
```elixir
{:ok, investigation} = InsiderThreat.close_investigation(
  investigation,
  "Malicious insider activity confirmed",
  "User terminated, credentials revoked, legal proceedings initiated"
)

# Export for legal hold
{:ok, export} = InsiderThreat.export_for_legal_hold(investigation)

# Save export to file system for legal team
File.write!(
  "/tmp/investigation_#{investigation.id}.json",
  Jason.encode!(export, pretty: true)
)
```

## Dashboard Integration

### Get Dashboard Data
```elixir
dashboard = InsiderThreat.get_dashboard_data(org_id)

# Returns complete dashboard metrics:
# - Top 10 users by risk score
# - Risk distribution (critical/high/medium/low)
# - Recent alerts (last 24 hours)
# - Statistics (total, open, investigating, resolved)
# - Open investigations count
# - Peer groups count
```

### Get User Risk Profile
```elixir
profile = InsiderThreat.get_user_risk_profile(user_id)

# Returns:
# - Current risk score
# - Severity level
# - Total alerts
# - Recent alerts
# - Open investigations
# - Alert history
```

## Event Integration

To enable insider threat detection on your events, ensure events include `user_id`:

```elixir
# Example: File access event
%Event{
  event_type: "file_access",
  user_id: user_id,
  agent_id: agent_id,
  payload: %{
    "file_path" => "/share/confidential/financial_records.xlsx",
    "file_size" => 5_000_000,
    "classification" => "confidential",
    "operation" => "read",
    "bytes_read" => 5_000_000
  }
}

# Example: Network connection event
%Event{
  event_type: "network_connection",
  user_id: user_id,
  agent_id: agent_id,
  payload: %{
    "remote_ip" => "1.2.3.4",
    "remote_host" => "dropbox.com",
    "remote_port" => 443,
    "protocol" => "https",
    "bytes_sent" => 50_000_000,
    "bytes_received" => 1_000
  }
}

# Example: Authentication event
%Event{
  event_type: "authentication_success",
  user_id: user_id,
  agent_id: agent_id,
  payload: %{
    "source_ip" => "10.0.1.50",
    "location" => "San Francisco, CA",
    "auth_method" => "password",
    "device_type" => "laptop"
  }
}
```

## Testing

### Manual Analysis
```elixir
# Analyze specific user
alias TamanduaServer.InsiderThreat

end_time = DateTime.utc_now()
start_time = DateTime.add(end_time, -1 * 3600, :second)  # Last hour

{:ok, result} = InsiderThreat.analyze_user(user_id, start_time, end_time)

IO.puts "Risk Score: #{result.risk_score.total}"
IO.puts "Severity: #{result.risk_score.severity}"
IO.puts "Indicators: #{length(result.indicators)}"

Enum.each(result.indicators, fn indicator ->
  IO.puts "  - #{indicator.type}: #{indicator.description} (weight: #{indicator.weight})"
end)
```

### Trigger Scheduled Analysis
```elixir
# Trigger immediate analysis for organization
TamanduaServer.InsiderThreat.Scheduler.trigger_analysis(org_id)

# Trigger baseline recalculation
TamanduaServer.InsiderThreat.Scheduler.trigger_baseline_calculation(org_id)
```

## Common Workflows

### 1. New User Onboarding
```elixir
# Add user to appropriate peer group
peer_group = InsiderThreat.list_peer_groups(org_id)
  |> Enum.find(&(&1.name == "Software Engineers"))

InsiderThreat.add_peer_group_member(peer_group.id, new_user_id)
```

### 2. User Role Change
```elixir
# Remove from old peer group
InsiderThreat.remove_peer_group_member(old_peer_group_id, user_id)

# Add to new peer group
InsiderThreat.add_peer_group_member(new_peer_group_id, user_id)
```

### 3. Weekly Review
```elixir
# Get weekly statistics
end_time = DateTime.utc_now()
start_time = DateTime.add(end_time, -7 * 24 * 3600, :second)

stats = InsiderThreat.alert_statistics(org_id, start_time, end_time)

IO.puts """
Weekly Insider Threat Report
============================
Total Alerts: #{stats.total}
Open: #{stats.open}
Investigating: #{stats.investigating}
Resolved: #{stats.resolved}
False Positives: #{stats.false_positives}
Avg Risk Score: #{stats.avg_risk_score}

By Severity:
  Critical: #{stats.by_severity["critical"] || 0}
  High: #{stats.by_severity["high"] || 0}
  Medium: #{stats.by_severity["medium"] || 0}
  Low: #{stats.by_severity["low"] || 0}
"""
```

### 4. High-Risk User Audit
```elixir
# Get all high-risk users
top_users = InsiderThreat.top_users_by_risk(org_id, 20)

high_risk_users = Enum.filter(top_users, &(&1.risk_score >= 70))

Enum.each(high_risk_users, fn user_data ->
  profile = InsiderThreat.get_user_risk_profile(user_data.user_id)

  IO.puts """
  User: #{user_data.user.email}
  Risk Score: #{profile.current_risk_score}
  Severity: #{profile.severity}
  Total Alerts: #{profile.total_alerts}
  Recent Alerts: #{profile.recent_alerts}
  Open Investigations: #{profile.open_investigations}
  """
end)
```

## Troubleshooting

### No alerts being generated
1. Check that events have `user_id` field populated
2. Verify peer groups are created and users are members
3. Check baselines are calculated: `peer_group.baseline != %{}`
4. Ensure scheduler is running: `Process.whereis(TamanduaServer.InsiderThreat.Scheduler)`

### False positives
1. Review and adjust risk thresholds in config
2. Update peer group baselines more frequently
3. Mark alerts as false positive to improve future detection
4. Create exclusion rules for known benign patterns

### Low detection rate
1. Verify all relevant event types are being collected
2. Check peer group baseline coverage (need 30+ days of data)
3. Review detection rules in `priv/insider_threat_rules/detection_rules.yml`
4. Lower risk thresholds for more sensitive detection

### Performance issues
1. Ensure database indexes are created (check migration)
2. Increase analysis interval if too frequent
3. Use batch analysis for historical data
4. Archive old alerts and investigations
