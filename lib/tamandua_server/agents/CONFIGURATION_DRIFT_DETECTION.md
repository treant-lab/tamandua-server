# Agent Configuration Drift Detection

## Overview

The Configuration Drift Detection system monitors agent configurations and detects unauthorized or unexpected changes. It provides comprehensive drift detection, reporting, and auto-remediation capabilities for maintaining compliance and security posture.

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Drift Detection System                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────┐      ┌────────────────────┐           │
│  │ Configuration   │      │  Drift Detector    │           │
│  │   Baseline      │─────▶│   (Comparison)     │           │
│  │                 │      │                    │           │
│  │  - Collectors   │      │  - Scan Agents     │           │
│  │  - Response     │      │  - Detect Changes  │           │
│  │  - Network      │      │  - Calculate Score │           │
│  │  - Features     │      │  - Broadcast Event │           │
│  └─────────────────┘      └────────────────────┘           │
│           │                         │                        │
│           │                         ▼                        │
│           │              ┌────────────────────┐             │
│           │              │ Configuration      │             │
│           │              │     Drift          │             │
│           │              │  (Detected)        │             │
│           │              └────────────────────┘             │
│           │                         │                        │
│           │                         ▼                        │
│           │              ┌────────────────────┐             │
│           └─────────────▶│  Drift Remediator  │             │
│                          │                    │             │
│                          │  - Push Config     │             │
│                          │  - Quarantine      │             │
│                          │  - Alert Admin     │             │
│                          └────────────────────┘             │
│                                   │                          │
│                                   ▼                          │
│                          ┌────────────────────┐             │
│                          │ Compliance Status  │             │
│                          │                    │             │
│                          │  - Score           │             │
│                          │  - Last Scan       │             │
│                          │  - Drift Count     │             │
│                          └────────────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

## Database Schema

### agent_configuration_baselines

Stores the expected configuration state for each agent.

```elixir
schema "agent_configuration_baselines" do
  field :agent_id, :binary_id
  field :organization_id, :binary_id

  # Configuration categories
  field :collector_settings, :map
  field :response_permissions, :map
  field :network_settings, :map
  field :file_paths, :map
  field :resource_limits, :map
  field :enabled_features, :map
  field :rule_versions, :map

  # Metadata
  field :baseline_hash, :string
  field :baseline_version, :integer
  field :is_active, :boolean
  field :approved_at, :utc_datetime
end
```

### agent_configuration_drifts

Stores detected configuration drift events.

```elixir
schema "agent_configuration_drifts" do
  field :agent_id, :binary_id
  field :baseline_id, :binary_id

  field :drift_type, :string          # collector_disabled, feature_toggled, etc.
  field :category, :string            # collectors, response, network, etc.
  field :severity, :string            # critical, high, medium, low
  field :status, :string              # detected, acknowledged, resolved

  field :field_path, :string
  field :expected_value, :map
  field :actual_value, :map

  field :remediation_status, :string
  field :detected_at, :utc_datetime
  field :resolved_at, :utc_datetime
end
```

### agent_compliance_status

Tracks overall compliance status for each agent.

```elixir
schema "agent_compliance_status" do
  field :agent_id, :binary_id
  field :is_compliant, :boolean
  field :drift_count, :integer
  field :compliance_score, :float     # 0-100

  field :critical_drifts, :integer
  field :high_drifts, :integer
  field :medium_drifts, :integer
  field :low_drifts, :integer

  field :last_scan_at, :utc_datetime
  field :last_compliant_at, :utc_datetime
end
```

## Drift Detection

### Drift Types

1. **Collector Changes**
   - `collector_disabled` - Collector was disabled
   - `collector_enabled` - Collector was enabled
   - `collector_settings_changed` - Interval or buffer size changed

2. **Response Changes**
   - `response_permission_changed` - Allowed actions modified
   - Auto-response enabled/disabled

3. **Network Changes**
   - `network_config_changed` - Server URL, proxy, or TLS settings modified

4. **Path Changes**
   - `file_path_changed` - Quarantine, log, or config directory changed

5. **Resource Changes**
   - `resource_limit_changed` - CPU, memory, or disk limits modified

6. **Feature Changes**
   - `feature_toggled` - YARA, Sigma, ML, or other features toggled

7. **Rule Changes**
   - `rules_outdated` - YARA or Sigma rule versions outdated

### Severity Levels

Severity is automatically assigned based on drift type and security impact:

- **Critical**: Security features disabled, network URL changed, auto-response enabled
- **High**: Collectors disabled, response permissions modified, critical paths changed
- **Medium**: Settings modifications, non-critical path changes, resource limit increases
- **Low**: Minor configuration adjustments, non-security features

### Compliance Scoring

Compliance score (0-100) is calculated based on drift severity:

```
Score = 100 - (Critical × 25) - (High × 10) - (Medium × 5) - (Low × 2)
```

Minimum score is 0. Agents with score ≥ 90 are considered compliant.

## Usage

### Creating a Baseline

Create a baseline from an agent's current configuration:

```elixir
# From agent configuration
{:ok, agent} = Agents.get_agent(agent_id)

baseline_attrs = %{
  agent_id: agent.id,
  organization_id: agent.organization_id,
  # Configuration will be extracted automatically
  created_by_id: user_id,
  notes: "Initial baseline capture"
}

{:ok, baseline} =
  %ConfigurationBaseline{}
  |> ConfigurationBaseline.from_agent_config(agent, agent.config)
  |> Repo.insert()
```

### Scanning for Drift

#### Single Agent

```elixir
# On-demand scan
{:ok, result} = DriftDetector.scan_agent(agent_id,
  scan_type: "manual",
  triggered_by_id: user_id
)

# Result contains:
%{
  scan: %ConfigurationScan{},
  drifts: [%{drift_type: "collector_disabled", ...}],
  severity_counts: %{critical: 0, high: 1, medium: 2, low: 0},
  compliance_score: 85.0
}
```

#### Organization-Wide

```elixir
# Scan all agents in organization
{:ok, result} = DriftDetector.scan_organization(organization_id,
  scan_type: "scheduled"
)

# Result contains:
%{
  total: 50,
  scanned: 48,
  failed: 2,
  results: [...]
}
```

#### Scheduled Scans

Add to your Oban worker or scheduler:

```elixir
defmodule TamanduaServer.Workers.DriftScanWorker do
  use Oban.Worker, queue: :scheduled

  @impl Oban.Worker
  def perform(_job) do
    DriftRemediator.schedule_drift_scans()
    :ok
  end
end

# Schedule hourly
%{scheduled_at: ~U[2024-01-01 00:00:00Z]}
|> DriftScanWorker.new()
|> Oban.insert()
```

### Remediating Drift

#### Single Drift

```elixir
# Remediate specific drift (requires approval)
{:ok, :remediated} = DriftRemediator.remediate_drift(drift_id,
  require_approval: true,
  approved_by_id: admin_user_id
)
```

#### All Agent Drifts

```elixir
# Push full baseline configuration
{:ok, result} = DriftRemediator.remediate_agent(agent_id,
  approved_by_id: admin_user_id
)

# Result: %{drifts_remediated: 5}
```

#### Quarantine Drifted Agent

```elixir
# Quarantine agent with critical drift
{:ok, :quarantined} = DriftRemediator.quarantine_drifted_agent(
  agent_id,
  "Critical network configuration drift detected",
  quarantined_by_id: admin_user_id
)
```

### Querying Drift Data

#### Get Agent Drifts

```elixir
# Get active drifts
drifts = DriftDetector.get_agent_drifts(agent_id,
  status: "detected",
  severity: "critical"
)

# Get drift history
history = DriftDetector.get_agent_drifts(agent_id,
  status: "resolved",
  limit: 50
)
```

#### Compliance Summary

```elixir
summary = DriftDetector.get_compliance_summary(organization_id)

%{
  total_agents: 100,
  compliant: 85,
  non_compliant: 15,
  avg_compliance_score: 92.5,
  total_critical_drifts: 2,
  total_high_drifts: 8,
  total_medium_drifts: 15,
  total_low_drifts: 5
}
```

#### Remediation Recommendations

```elixir
{:ok, recommendation} = DriftRemediator.get_remediation_recommendation(drift_id)

%{
  action: "immediate_remediation",
  description: "Critical security feature disabled...",
  auto_approve: false,
  notify_admin: true
}
```

## Real-Time Events

Subscribe to drift events via Phoenix PubSub:

```elixir
# In LiveView or GenServer
Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agents:drift")

# Handle events
def handle_info({:drift_detected, event}, state) do
  # event: %{
  #   agent_id: "...",
  #   hostname: "web-01",
  #   drift_count: 3,
  #   critical_count: 1,
  #   timestamp: ~U[...]
  # }
end

def handle_info({:drift_remediated, event}, state) do
  # event: %{
  #   agent_id: "...",
  #   drift_id: "...",
  #   drift_type: "collector_disabled",
  #   status: "success"
  # }
end

def handle_info({:agent_remediated, event}, state) do
  # event: %{
  #   agent_id: "...",
  #   drifts_remediated: 5
  # }
end
```

## Dashboard UI

### Drift Dashboard

Access at: `/agents/drift`

Features:
- Organization-wide compliance summary
- Severity breakdown (Critical, High, Medium, Low)
- List of non-compliant agents
- Recent drift detections
- Drift timeline chart
- Filters by severity and status
- One-click remediation

### Agent Drift Detail

Access at: `/agents/drift/:agent_id`

Features:
- Agent information and compliance score
- Active drifts with details
- Drift history
- Configuration comparison (baseline vs current)
- Per-drift remediation
- Bulk remediation
- Drift acknowledgment and ignoring

## Best Practices

### 1. Baseline Management

- Create baselines after initial agent deployment
- Update baselines when making intentional configuration changes
- Version baselines for change tracking
- Approve baselines before activation

### 2. Scan Frequency

- **Hourly**: Scheduled scans for all agents
- **On-Reconnect**: Scan when agent reconnects
- **On-Demand**: Manual scans for investigations
- **Post-Deployment**: Scan after configuration updates

### 3. Remediation Workflow

For **Critical** drifts:
1. Immediate notification to security team
2. Quarantine agent if network configuration changed
3. Require manual approval for remediation
4. Audit log all actions

For **High** drifts:
1. Alert administrator
2. Schedule remediation within 24 hours
3. Require approval for production agents

For **Medium/Low** drifts:
1. Log for review
2. Auto-remediate if approved
3. Weekly review of patterns

### 4. Compliance Reporting

Generate regular compliance reports:
- Daily: Critical/High drift summary
- Weekly: Compliance trends and agent status
- Monthly: Full compliance audit

### 5. Alert Integration

Integrate with alerting systems:

```elixir
# Send alert on critical drift
def handle_info({:drift_detected, %{critical_count: c}}, _) when c > 0 do
  Alerts.create_alert(%{
    type: "configuration_drift",
    severity: "critical",
    title: "Critical configuration drift detected",
    ...
  })
end
```

## Security Considerations

### 1. Baseline Protection

- Require elevated privileges to modify baselines
- Audit all baseline changes
- Protect baseline storage with encryption
- Implement baseline integrity checks

### 2. Remediation Controls

- Require multi-factor authentication for remediation
- Implement approval workflows
- Rate-limit remediation actions
- Validate configuration before pushing

### 3. Drift Response

Critical drifts that require immediate action:
- Network URL changes → Quarantine agent
- TLS verification disabled → Quarantine agent
- Self-defense disabled → Alert and investigate
- Auto-response enabled → Review and approve

### 4. Audit Logging

Log all drift-related events:
- Baseline creation/modification
- Drift detection
- Remediation attempts
- Approval/rejection decisions
- Quarantine actions

## Troubleshooting

### Issue: False Positives

**Problem**: Legitimate configuration changes detected as drift

**Solution**:
1. Update baseline after approved changes
2. Use drift acknowledgment for known issues
3. Adjust severity thresholds
4. Implement change windows

### Issue: Remediation Failures

**Problem**: Agent doesn't accept configuration updates

**Solution**:
1. Check agent connectivity
2. Verify agent version compatibility
3. Review agent logs for errors
4. Manually intervene if needed

### Issue: Scan Performance

**Problem**: Scans taking too long

**Solution**:
1. Implement batching for organization scans
2. Use Task.async for parallel scanning
3. Cache baseline data
4. Optimize query performance

## Metrics and Monitoring

Track these metrics:

- **Compliance Rate**: % of agents compliant
- **Mean Time to Detect (MTTD)**: Time between drift and detection
- **Mean Time to Remediate (MTTR)**: Time between detection and remediation
- **Drift Frequency**: # of drifts per agent per day
- **Remediation Success Rate**: % of successful remediations
- **False Positive Rate**: % of acknowledged/ignored drifts

## API Reference

See module documentation:
- `TamanduaServer.Agents.DriftDetector`
- `TamanduaServer.Agents.DriftRemediator`
- `TamanduaServer.Agents.ConfigurationBaseline`
- `TamanduaServer.Agents.ConfigurationDrift`

## Future Enhancements

1. **ML-Based Drift Prediction**
   - Predict drift likelihood based on patterns
   - Anomaly detection for unusual configurations

2. **Configuration Templates**
   - Predefined baseline templates
   - Role-based configuration profiles

3. **Change Management Integration**
   - Link to change tickets
   - Approval workflows via ServiceNow/Jira

4. **Drift Correlation**
   - Correlate drift across multiple agents
   - Identify attack patterns

5. **Auto-Rollback**
   - Automatic rollback on detection
   - Safe mode activation
