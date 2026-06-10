# Breadcrumb Access Monitoring and Alerting

## Overview

The Breadcrumb Monitoring system provides real-time detection and response capabilities for honeypot file access. When an adversary accesses a deployed breadcrumb, the system immediately detects the access, creates a high-severity alert, logs the event, and can execute automated response actions.

This implementation is comparable to enterprise deception platforms like Attivo Networks, SentinelOne Singularity Hologram, or Illusive Networks.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Agent FIM Collector                             │
│  (Monitors file system for breadcrumb access)                       │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ File Access Event
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│                   BreadcrumbMonitor GenServer                        │
│  • Matches events against deployed breadcrumbs                       │
│  • Detects tampering (modifications, deletions)                      │
│  • Tracks access statistics                                          │
└───────────────────┬──────────────┬──────────────┬───────────────────┘
                    │              │              │
         ┌──────────┴────┐  ┌──────┴─────┐  ┌────┴──────┐
         │ Access Log    │  │   Alert    │  │ Response  │
         │ (Database)    │  │  Creation  │  │ Actions   │
         └───────────────┘  └────────────┘  └───────────┘
                                   │              │
                            ┌──────┴──────┐  ┌───┴──────┐
                            │ High-Sev    │  │ Isolate  │
                            │ Alert       │  │ Kill PID │
                            │ T1083       │  │ Snapshot │
                            └─────────────┘  └──────────┘
```

## Components

### 1. BreadcrumbMonitor GenServer

**Location:** `apps/tamandua_server/lib/tamandua_server/deception/breadcrumb_monitor.ex`

**Responsibilities:**
- Receives file access events from agents
- Matches events against deployed breadcrumbs (via in-memory cache)
- Detects tampering (modifications, moves, deletions)
- Creates high-severity alerts
- Logs access events to database
- Triggers automated response actions
- Tracks effectiveness statistics

**Key Functions:**
- `handle_file_access/1` - Process file access event from FIM collector
- `handle_breadcrumb_access/1` - Process direct canary token access
- `configure_response/1` - Update automated response configuration
- `get_statistics/0` - Get access statistics
- `get_effectiveness_report/0` - Generate effectiveness metrics

### 2. Database Schema

**Tables:**

#### breadcrumb_deployments
Tracks deployed honeypot files:
- `id` - UUID
- `agent_id` - Target agent
- `type` - Breadcrumb type (ssh_key, api_token, credential, etc.)
- `path` - File path on agent
- `content_hash` - Original file hash
- `canary_token` - Unique canary token
- `deployed_at` - Deployment timestamp
- `status` - active, accessed, rotated, removed
- `access_count` - Number of accesses
- `metadata` - Additional metadata

#### breadcrumb_access_log
Tracks each access event:
- `id` - UUID
- `breadcrumb_id` - Reference to deployment
- `agent_id` - Agent where access occurred
- `accessed_at` - Access timestamp
- `process_name` - Accessing process
- `pid` - Process ID
- `user` - User context
- `access_type` - read, write, delete, execute, etc.
- `alert_id` - Generated alert
- `tamper_detected` - Boolean flag
- `original_hash` - Original file hash
- `new_hash` - Modified file hash (if applicable)

### 3. Alert Generation

**Alert Attributes:**
- **Title:** "Honeyfile Accessed: [Breadcrumb Type]" or "Honeyfile Tampered With: [Type]"
- **Severity:** High
- **MITRE Techniques:** T1083 (File and Directory Discovery)
- **Evidence:**
  - File path
  - Process name and PID
  - User context
  - Access type
  - Breadcrumb type
  - Tamper detection status
  - Hash comparison

**Alert Description:**
Provides comprehensive context including:
- Breadcrumb details (type, path, deployment time)
- Access details (process, PID, user, timestamp)
- Tamper information (if applicable)
- Access count

### 4. Tamper Detection

The system detects the following tamper scenarios:

1. **File Deletion** - `access_type: "delete"`
2. **File Modification** - `access_type: "write"` or hash mismatch
3. **File Rename/Move** - `access_type: "rename"` or `"move"`
4. **Content Changes** - New hash differs from original

### 5. Automated Response

**Configurable Actions:**

```elixir
# Configure response behavior
BreadcrumbMonitor.configure_response(%{
  isolate_agent: true,          # Isolate agent immediately
  kill_process: true,            # Kill accessing process
  create_snapshot: true,         # Create forensic snapshot
  escalate_to_soc: true,         # Send SOC notification
  trigger_playbook_id: "pb_xyz" # Execute playbook
})
```

**Response Actions:**
- **Isolate Agent** - Immediately isolate agent from network
- **Kill Process** - Terminate the accessing process
- **Forensic Snapshot** - Collect process list, network connections, event logs
- **Playbook Execution** - Trigger automated response playbook
- **SOC Escalation** - Notify security operations center

All response actions execute asynchronously to avoid blocking the monitor.

### 6. Access Analytics

**Statistics Tracked:**
- Total access count
- Accesses by breadcrumb type
- Accesses by agent
- Time-to-detection (deployment → first access)
- Average time-to-detection
- Most accessed breadcrumb types

**Effectiveness Metrics:**
- Deployment count by type
- Access count by type
- Effectiveness rate (% of breadcrumbs accessed)
- Effectiveness status (high/medium/low)

```elixir
# Get effectiveness report
{:ok, report} = BreadcrumbMonitor.get_effectiveness_report()

# Example output:
%{
  total_deployed: 50,
  total_accessed: 8,
  overall_effectiveness: 16.0,
  by_type: [
    %{type: "ssh_key", deployed: 10, accessed: 5, effectiveness_rate: 50.0, status: "high"},
    %{type: "api_token", deployed: 15, accessed: 2, effectiveness_rate: 13.3, status: "medium"},
    %{type: "credential", deployed: 25, accessed: 1, effectiveness_rate: 4.0, status: "low"}
  ]
}
```

## Integration Points

### 1. Agent FIM Collector

The agent's File Integrity Monitoring (FIM) collector monitors breadcrumb files and sends access events:

```rust
// In agent: apps/tamandua_agent/src/deception/mod.rs
pub fn on_file_access(path: &str, process: &ProcessInfo) {
    // Check if path matches a deployed breadcrumb
    if let Some(breadcrumb) = breadcrumbs.get(path) {
        send_access_event(breadcrumb, process);
    }
}
```

### 2. Breadcrumbs Module

The Breadcrumbs deployment module integrates with the monitor:

```elixir
# When a canary token is accessed
def record_access(agent_id, canary_token, access_info) do
  # Forward to monitor for alerting
  BreadcrumbMonitor.handle_breadcrumb_access(%{
    canary_token: canary_token,
    agent_id: agent_id,
    process_name: access_info.process_name,
    # ...
  })
end
```

### 3. Playbook Engine

Breadcrumb access can trigger automated playbooks:

```elixir
# Example playbook for breadcrumb access
Playbook.create_playbook(%{
  name: "Breadcrumb Access Response",
  trigger_type: "alert",
  trigger_conditions: %{
    "detection_type" => "honeypot",
    "severity" => "high"
  },
  steps: [
    %{action: "isolate_host"},
    %{action: "kill_process"},
    %{action: "collect_forensics"},
    %{action: "create_ticket", params: %{priority: "critical"}}
  ]
})
```

## Usage Examples

### Deploy and Monitor Breadcrumbs

```elixir
# 1. Deploy breadcrumbs to an agent
{:ok, count} = Breadcrumbs.deploy_to_agent("agent-001",
  types: [:ssh_key, :api_token, :credential],
  density: :medium
)

# 2. Configure automated response
{:ok, _config} = BreadcrumbMonitor.configure_response(%{
  isolate_agent: true,
  kill_process: true,
  escalate_to_soc: true
})

# 3. When an access occurs, the system automatically:
#    - Logs the access
#    - Creates a high-severity alert
#    - Executes response actions
#    - Updates statistics

# 4. View access history
{:ok, history} = BreadcrumbMonitor.get_access_history(breadcrumb_id)

# 5. Get effectiveness report
{:ok, report} = BreadcrumbMonitor.get_effectiveness_report()
```

### Manual Access Simulation (Testing)

```elixir
# Simulate a file access event
BreadcrumbMonitor.handle_file_access(%{
  file_path: "/home/user/.ssh/id_rsa_fake",
  agent_id: "agent-001",
  process_name: "mimikatz.exe",
  pid: 1234,
  user: "SYSTEM",
  access_type: "read",
  timestamp: DateTime.utc_now(),
  file_hash: "abc123"
})
```

## Alert Investigation Workflow

When a breadcrumb alert is triggered:

1. **Review Alert Details**
   - Check the accessing process and user
   - Examine the breadcrumb type and location
   - Review tamper detection status

2. **Analyze Evidence**
   - Process chain and parent process
   - Network connections from the process
   - Recent authentication events
   - Lateral movement indicators

3. **Investigate Timeline**
   - Time from deployment to access (time-to-detection)
   - Correlation with other alerts on the same agent
   - Sequence of file accesses

4. **Response Actions**
   - Automated response already executed (if configured)
   - Manual investigation required
   - Threat hunting across other endpoints

5. **Threat Intelligence**
   - Extract IOCs (process hashes, network connections)
   - Add to threat intel feeds
   - Create YARA/Sigma rules

## Performance Considerations

1. **In-Memory Caching**
   - Breadcrumbs cached in GenServer state
   - Cache refreshed every 5 minutes
   - O(1) lookup by path and canary token

2. **Async Processing**
   - Alert creation runs asynchronously
   - Response actions execute in separate processes
   - Database writes don't block monitoring

3. **Batch Operations**
   - Multiple deployments persisted in batch
   - Statistics computed efficiently with ETS

## Security Best Practices

1. **Breadcrumb Placement**
   - Deploy in high-value directories
   - Use realistic filenames and content
   - Rotate regularly to prevent adversary adaptation

2. **Alert Tuning**
   - All breadcrumb access is high-severity by default
   - Consider context when triaging
   - Track false positives (legitimate admin access)

3. **Response Calibration**
   - Test automated responses in staging
   - Consider process kill impact
   - Use playbooks for complex workflows

4. **Monitoring**
   - Track effectiveness metrics
   - Adjust deployment strategies based on data
   - Review access patterns for campaign detection

## Testing

Run the test suite:

```bash
cd apps/tamandua_server
mix test test/tamandua_server/deception/breadcrumb_monitor_test.exs
```

Test coverage includes:
- File access detection
- Tamper detection (modifications, deletions)
- Alert creation
- Access logging
- Statistics tracking
- Effectiveness reporting
- Response configuration

## Future Enhancements

1. **ML-Based Detection**
   - Distinguish legitimate admin access from adversary activity
   - Anomaly detection on access patterns

2. **Advanced Canary Tokens**
   - Network canary tokens (DNS, HTTP callbacks)
   - Cloud service canary tokens
   - Email canary tokens

3. **Threat Intelligence Integration**
   - Automatic IOC extraction
   - Threat actor attribution
   - Campaign correlation

4. **Response Orchestration**
   - Integration with SOAR platforms
   - Automated containment workflows
   - Incident response playbooks

5. **Deception Analytics**
   - Attack path reconstruction
   - Adversary TTPs mapping
   - Effectiveness optimization

## References

- MITRE ATT&CK T1083 - File and Directory Discovery
- NIST SP 800-53 SC-26 - Honeypots
- [Attivo Networks ThreatDefend](https://attivonetworks.com/)
- [SentinelOne Singularity Hologram](https://www.sentinelone.com/)
