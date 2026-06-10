# Insider Threat Detection System

Comprehensive insider threat detection for Tamandua EDR with risk scoring, peer group analysis, and investigation workflows.

## Overview

The insider threat detection system identifies malicious or negligent behavior by authorized users through:

- **Real-time detection** of 16 different threat indicators
- **Peer group comparison** to identify outliers
- **Risk scoring** with weighted indicators (0-100 scale)
- **Automated investigations** with evidence collection
- **Compliance reporting** for SOX, GDPR, HIPAA

## Architecture

```
┌─────────────────┐
│ Event Ingestion │
└────────┬────────┘
         │
         v
┌─────────────────┐
│    Detector     │ ← Analyzes events for indicators
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Risk Scorer    │ ← Calculates risk score
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Alert Creation  │ ← Creates alerts if threshold exceeded
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Investigation   │ ← Manual investigation workflow
└─────────────────┘
```

## Threat Indicators

### Critical Severity (Weight: 35-40)
- **Data Exfiltration** - Large data transfers to external systems
- **Bulk Download** - Downloading >1GB in short time
- **Credential Misuse** - Shared credentials, credential stuffing

### High Severity (Weight: 25-30)
- **Privilege Escalation** - Unauthorized privilege elevation attempts
- **USB Write** - Writing sensitive data to USB devices
- **Cloud Upload** - Uploading data to cloud storage
- **Lateral Movement** - Connecting to internal systems via RDP/SSH/SMB
- **Sensitive Data Access** - Accessing classified/confidential data

### Medium Severity (Weight: 15-20)
- **Off-Hours Activity** - System access during 10pm-6am
- **Failed Auth Spike** - Multiple failed authentication attempts
- **Unusual Location** - Authentication from new location
- **Unusual Access** - Accessing resources outside normal pattern
- **Policy Violation** - DLP or acceptable use policy violation

### Low Severity (Weight: 10-15)
- **Peer Group Outlier** - Behavior significantly different from peers
- **File Share Access** - Accessing unusual file shares
- **Application Anomaly** - Using unusual applications

## Risk Scoring

Risk score is calculated as:

```elixir
risk_score =
  (indicator_weights_sum) +
  (peer_group_outlier_score)
  |> min(100.0)
```

### Thresholds
- **Critical** (≥70): Automatic investigation required
- **High** (≥40): Alert analyst for review
- **Medium** (≥20): Monitor for escalation
- **Low** (<20): Log for baseline

### Trend Analysis
- **Increasing**: Risk score rising over last 7 days
- **Stable**: Risk score consistent
- **Decreasing**: Risk score falling

## Peer Groups

Peer groups establish behavioral baselines for role-based comparison.

### Group Types
- **Role-based**: Software Engineers, Analysts, Admins
- **Department-based**: Engineering, Sales, Finance
- **Location-based**: US-East, EU-West
- **Manual**: Custom groupings

### Baseline Metrics
```elixir
%{
  data_access: %{mean: 500.0, std_dev: 100.0},  # MB/day
  access_hours: [9, 10, 11, 12, 13, 14, 15, 16, 17],
  file_shares: ["/share/eng", "/share/repos"],
  applications: ["vscode", "chrome", "slack"],
  authentication: %{mean_auths_per_day: 5.0},
  network: %{mean_bytes_per_day: 1_000_000}
}
```

### Outlier Detection
User is considered an outlier if their metric deviates >2σ from peer group mean.

## Detection Rules

Rules are defined in `priv/insider_threat_rules/detection_rules.yml`:

```yaml
- id: "IT-001"
  name: "Off-Hours Sensitive Data Access"
  severity: high
  conditions:
    - event_type: "file_access"
    - time_range: ["22:00", "06:00"]
    - file_classification: ["confidential", "secret"]
  actions:
    - type: "alert"
      risk_score: 25
```

### Available Rules
- IT-001: Off-Hours Sensitive Data Access
- IT-002: Bulk Data Download
- IT-003: Multiple Privilege Escalation Attempts
- IT-004: Unusual File Share Access
- IT-005: Authentication from Unusual Location
- IT-006: Failed Authentication Spike
- IT-007: Large USB Write
- IT-008: Cloud Storage Upload
- IT-009: Lateral Movement Detection
- IT-010: DLP Policy Violation
- IT-011: Failed Logins Followed by Success
- IT-012: After-Hours VPN Access
- IT-013: Excessive Peer Group Deviation
- IT-014: Credential Sharing Indicator
- IT-015: Database Query Anomaly

## Investigation Workflows

### Investigation Lifecycle
1. **Alert Created** - Risk threshold exceeded
2. **Investigation Started** - Assigned to analyst
3. **Evidence Collection** - Gather timeline, access logs, network activity
4. **Analysis** - Review user behavior patterns
5. **Resolution** - Close with outcome and action taken
6. **Legal Hold** - Export data for compliance

### Evidence Collection
- **User Timeline**: All events for user in time period
- **Access Log**: Files/data accessed
- **Network Activity**: Connections, transfers
- **Authentication Log**: Logins, failures, locations

### Outcomes
- **True Positive**: Malicious insider activity confirmed
- **False Positive**: Legitimate activity misidentified
- **Benign**: Suspicious but not malicious
- **Unconfirmed**: Insufficient evidence

## API Usage

### Analyze User Activity
```elixir
# Analyze last 24 hours for a user
end_time = DateTime.utc_now()
start_time = DateTime.add(end_time, -24 * 3600, :second)

{:ok, result} = InsiderThreat.analyze_user(user_id, start_time, end_time)

# result = %{
#   indicators: [%Indicator{}, ...],
#   risk_score: %{total: 75.0, severity: :critical, ...},
#   user_metrics: %{data_access: 5_000_000, ...}
# }
```

### Create Peer Group
```elixir
{:ok, peer_group} = InsiderThreat.create_peer_group(%{
  name: "Software Engineers",
  group_type: "role",
  organization_id: org_id
})

# Add members
InsiderThreat.add_peer_group_member(peer_group.id, user1_id)
InsiderThreat.add_peer_group_member(peer_group.id, user2_id)

# Calculate baseline (last 30 days)
end_time = DateTime.utc_now()
start_time = DateTime.add(end_time, -30 * 24 * 3600, :second)

{:ok, baseline} = InsiderThreat.calculate_peer_group_baseline(
  peer_group.id,
  start_time,
  end_time
)
```

### Manage Alerts
```elixir
# Get top risky users
top_users = InsiderThreat.top_users_by_risk(org_id, 10)

# Start investigation
alert = InsiderThreat.get_alert(alert_id)
{:ok, alert} = InsiderThreat.start_investigation(alert, investigator_id)

# Resolve alert
{:ok, alert} = InsiderThreat.resolve_alert(
  alert,
  resolver_id,
  "User was working on approved project",
  false  # not false positive
)
```

### Investigation Workflows
```elixir
# Create investigation
{:ok, investigation} = InsiderThreat.create_investigation(%{
  title: "Suspicious data access by John Doe",
  description: "Multiple off-hours access to financial data",
  subject_user_id: user_id,
  organization_id: org_id,
  lead_investigator_id: investigator_id,
  priority: "high"
})

# Get activity logs
timeline = InsiderThreat.get_user_timeline(user_id, start_time, end_time)
access_log = InsiderThreat.get_user_access_log(user_id, start_time, end_time)
network_activity = InsiderThreat.get_user_network_activity(user_id, start_time, end_time)

# Add evidence
InsiderThreat.add_evidence(investigation, %{
  type: "access_log",
  description: "Accessed 50 customer records",
  data: access_log,
  collected_by: investigator_id
})

# Close investigation
{:ok, investigation} = InsiderThreat.close_investigation(
  investigation,
  "Employee terminated for data theft",
  "Account disabled, legal action initiated"
)

# Export for legal hold
{:ok, export} = InsiderThreat.export_for_legal_hold(investigation)
```

## Scheduled Tasks

The `InsiderThreat.Scheduler` runs automated tasks:

### Hourly Analysis
Analyzes all users in all organizations for the last hour.

```elixir
# Triggered automatically every hour
InsiderThreat.run_scheduled_analysis(org_id)
```

### Daily Baseline Calculation
Recalculates peer group baselines every 24 hours.

```elixir
# Triggered automatically every 24 hours
InsiderThreat.auto_calculate_baselines(org_id)
```

### Cleanup
Removes old resolved alerts (>90 days) and closed investigations (>1 year).

### Manual Triggers
```elixir
# Trigger immediate analysis
InsiderThreat.Scheduler.trigger_analysis(org_id)

# Trigger baseline recalculation
InsiderThreat.Scheduler.trigger_baseline_calculation(org_id)
```

## Dashboard Integration

### Dashboard Data
```elixir
dashboard = InsiderThreat.get_dashboard_data(org_id)

# Returns:
# %{
#   top_users: [%{user_id: ..., risk_score: 85.0, ...}, ...],
#   risk_distribution: %{"critical" => 5, "high" => 12, ...},
#   recent_alerts: [...],
#   statistics: %{total: 50, open: 10, ...},
#   open_investigations: 3,
#   peer_groups: 5
# }
```

### User Risk Profile
```elixir
profile = InsiderThreat.get_user_risk_profile(user_id)

# Returns:
# %{
#   user_id: ...,
#   current_risk_score: 65.0,
#   severity: :high,
#   total_alerts: 15,
#   recent_alerts: 3,
#   open_investigations: 1,
#   alert_history: [...]
# }
```

## Database Schema

### Tables
- `insider_threat_peer_groups` - Peer group definitions
- `insider_threat_peer_group_members` - User membership
- `insider_threat_alerts` - Risk-based alerts
- `insider_threat_investigations` - Investigation cases

### Indexes
Optimized for:
- Alert queries by organization, status, severity
- User risk lookups
- Investigation searches
- Temporal queries (time-based analysis)

## Compliance & Audit

### Audit Logging
All actions are logged:
- Alert creation/resolution
- Investigation activities
- Evidence collection
- Status changes

### Legal Hold Export
Export investigation data in compliance-ready format:
```elixir
{:ok, export} = InsiderThreat.export_for_legal_hold(investigation)

# Includes:
# - Investigation details
# - Subject user information
# - Complete activity timeline
# - All evidence collected
# - Alert history
# - Timestamps and metadata
```

### Compliance Reports
- **SOX**: Financial data access auditing
- **GDPR**: Personal data access tracking
- **HIPAA**: Protected health information monitoring

## Configuration

Add to `config/config.exs`:

```elixir
config :tamandua_server, TamanduaServer.InsiderThreat,
  # Analysis frequency (default: 1 hour)
  analysis_interval: :timer.hours(1),

  # Baseline recalculation (default: 24 hours)
  baseline_interval: :timer.hours(24),

  # Risk thresholds
  high_risk_threshold: 70.0,
  medium_risk_threshold: 40.0,

  # Peer group settings
  baseline_lookback_days: 30,
  minimum_data_points: 50,
  outlier_std_dev_threshold: 2.0,

  # Alert settings
  auto_investigate_threshold: 70.0,
  suppress_duplicates_hours: 24
```

## Performance Considerations

- **Batch Analysis**: Use `analyze_organization/3` for bulk processing
- **Async Processing**: Analysis runs in background tasks
- **Caching**: Peer group baselines cached, recalculated daily
- **Indexing**: Optimized database indexes for temporal queries
- **Cleanup**: Automatic removal of old data

## Testing

Run tests:
```bash
mix test test/tamandua_server/insider_threat/
```

Test coverage includes:
- Indicator creation and weighting
- Risk score calculation
- Peer group baseline calculation
- Outlier detection
- Alert lifecycle
- Investigation workflows

## Future Enhancements

### Machine Learning (Optional)
- **Unsupervised Learning**: Cluster users by behavior
- **Anomaly Detection**: Isolation Forest, One-Class SVM
- **Behavioral Modeling**: LSTM for sequence prediction
- **Model Training**: Train on historical user activity

### Advanced Features
- **UEBA Integration**: User and Entity Behavior Analytics
- **Threat Intelligence**: Enrich with external threat feeds
- **Automated Response**: Auto-disable high-risk accounts
- **Graph Analysis**: User relationship and access patterns
