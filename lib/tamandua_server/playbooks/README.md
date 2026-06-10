# YAML Playbook Editor - Automated Incident Response

## Overview

The YAML Playbook Editor is a comprehensive incident response automation system for Tamandua EDR. It allows security analysts to define, test, and execute automated response workflows using YAML syntax.

## Features

### 1. Monaco Editor Integration
- Full-featured YAML editor with syntax highlighting
- Real-time validation with error/warning markers
- Auto-completion and formatting
- Dark theme optimized for security operations

### 2. Live YAML Validation
- Validates playbook structure on every change (debounced 500ms)
- Checks required fields: `name`, `trigger`, `actions`
- Validates trigger conditions:
  - `detection_type`: ransomware, malware, lateral_movement, etc.
  - `confidence`: 0.0 to 1.0
  - `mitre_techniques`: T1234 or T1234.001 format
  - `severity`: low, medium, high, critical
- Validates action chains and parameters
- Provides actionable error messages

### 3. Playbook Templates
Pre-built templates for common scenarios:
- **Ransomware Auto-Response**: Immediate containment with isolation and forensics
- **Lateral Movement Response**: Network blocking and threat hunting
- **Data Exfiltration Response**: C2 blocking and network isolation
- **Credential Theft Response**: Memory forensics and process termination

### 4. Test Mode (Dry-Run Simulation)
- Simulates playbook execution without affecting systems
- Shows what would happen for each action
- Validates trigger condition matching
- Displays execution results in real-time
- Helps analysts verify playbooks before deployment

### 5. Action Library
Supported actions:
- `isolate_host` - Network isolation
- `kill_process` - Process termination
- `quarantine_file` - File quarantine
- `block_ip` - IP address blocking
- `block_domain` - DNS blocking
- `collect_forensics` - Evidence collection
- `create_ticket` - SIEM/ticketing integration
- `send_notification` - Slack/email alerts
- `trigger_scan` - On-demand scanning
- `wait` - Delayed execution
- `disable_user` - Account disabling
- `run_script` - Custom script execution
- `update_blocklist` - Threat intel updates

## YAML Schema

### Basic Structure

```yaml
name: "Playbook Name"
description: "Optional description"

trigger:
  detection_type: "ransomware"
  confidence: 0.9
  severity: "high"
  mitre_techniques:
    - "T1486"
    - "T1490"

actions:
  - action: "isolate_host"
    isolate_host: {}

  - action: "kill_process"
    kill_process:
      force: true

  - action: "quarantine_file"
    quarantine_file:
      delete_after: false

  - action: "collect_forensics"
    collect_forensics:
      memory_dump: true
      process_list: true
      network_connections: true

  - action: "create_ticket"
    create_ticket:
      severity: "critical"
      priority: "P1"

  - action: "send_notification"
    send_notification:
      channel: "slack"
      message: "Ransomware detected and contained"
```

### Trigger Conditions

Playbooks execute when ALL trigger conditions are met:

```yaml
trigger:
  # Detection type matching
  detection_type: "ransomware"

  # Confidence threshold (0.0 - 1.0)
  confidence: 0.85

  # Severity threshold (escalates: low < medium < high < critical)
  severity: "high"

  # MITRE ATT&CK techniques (any match triggers)
  mitre_techniques:
    - "T1021"    # Remote Services
    - "T1570"    # Lateral Tool Transfer

  # MITRE ATT&CK tactic (checks if in mitre_tactics array)
  mitre_tactic: "lateral-movement"

  # Category matching
  category: "credential_theft"
```

### Action Parameters

#### Isolate Host
```yaml
- action: "isolate_host"
  isolate_host:
    allowed_ips:
      - "10.0.0.1"  # Optional: management IPs
    duration_seconds: 3600  # Optional: auto-restore after 1 hour
```

#### Kill Process
```yaml
- action: "kill_process"
  kill_process:
    pid: 1234  # Optional: defaults to context.pid
    force: true
```

#### Quarantine File
```yaml
- action: "quarantine_file"
  quarantine_file:
    path: "C:\\malware.exe"  # Optional: defaults to context.file_path
    delete_after: false
```

#### Block IP
```yaml
- action: "block_ip"
  block_ip:
    ip: "192.168.1.100"  # Optional: defaults to context.remote_ip
    reason: "C2 communication detected"
    agent_id: "agent-123"  # Optional: block on specific agent
```

#### Block Domain
```yaml
- action: "block_domain"
  block_domain:
    domain: "evil.com"  # Optional: defaults to context.domain
    reason: "Known C2 domain"
```

#### Collect Forensics
```yaml
- action: "collect_forensics"
  collect_forensics:
    memory_dump: true
    process_list: true
    network_connections: true
    registry_hives: false  # Windows only
    event_logs: true
    prefetch: false  # Windows only
    browser_history: false
```

#### Create Ticket
```yaml
- action: "create_ticket"
  create_ticket:
    title: "Security Incident"
    severity: "high"
    priority: "P1"
    webhook_url: "https://jira.company.com/webhook"
    auth_token: "${JIRA_TOKEN}"
```

#### Send Notification
```yaml
- action: "send_notification"
  send_notification:
    channel: "slack"  # or "email", "webhook"
    message: "Alert message"
    slack_webhook_url: "${SLACK_WEBHOOK}"
    # For email:
    to: "security@company.com"
    subject: "Security Alert"
```

#### Wait
```yaml
- action: "wait"
  wait:
    duration_seconds: 30
```

#### Update Blocklist
```yaml
- action: "update_blocklist"
  update_blocklist:
    blocklist_type: "ip"  # or "domain", "hash"
    values:
      - "192.168.1.100"
      - "192.168.1.101"
    reason: "Threat actor infrastructure"
```

### Context Variables

Actions can reference alert context variables:

```yaml
actions:
  - action: "block_ip"
    block_ip:
      # Uses context.remote_ip automatically if not specified
      ip: "${remote_ip}"
```

Available context variables:
- `${agent_id}` - Agent UUID
- `${alert_id}` - Alert UUID
- `${severity}` - Alert severity
- `${detection_type}` - Detection type
- `${confidence}` - ML confidence score
- `${file_path}` - Suspicious file path
- `${pid}` - Process ID
- `${process_name}` - Process name
- `${remote_ip}` - Remote IP address
- `${domain}` - Domain name
- `${mitre_tactics}` - MITRE tactics array
- `${mitre_techniques}` - MITRE techniques array

## Usage

### 1. Access the Editor

Navigate to `/playbooks/editor` in the Tamandua web interface.

### 2. Load a Template

Select a template from the dropdown to start with a pre-built playbook:
- Ransomware Auto-Response
- Lateral Movement Response
- Data Exfiltration Response
- Credential Theft Response

### 3. Edit the Playbook

Modify the YAML in the Monaco Editor. Validation runs automatically after 500ms of inactivity.

### 4. Validate

Click "Validate" to manually trigger validation and see errors/warnings.

### 5. Test (Dry-Run)

Click "Test (Dry-Run)" to simulate execution with mock data:
- No actual commands are sent to agents
- Shows what would happen for each action
- Validates trigger condition matching
- Displays simulated results

### 6. Save

Click "Save" to persist the playbook to the database. Saved playbooks can be:
- Triggered manually
- Auto-triggered when alerts match conditions
- Cloned and modified
- Enabled/disabled

## Validation Rules

### Required Fields
- `name` - Playbook name (non-empty string)
- `trigger` - Trigger conditions (object)
- `actions` - Action array (non-empty)

### Trigger Validation
- `detection_type` must be in: ransomware, malware, lateral_movement, credential_theft, data_exfiltration, command_and_control, privilege_escalation, persistence, defense_evasion
- `confidence` must be 0.0 to 1.0
- `mitre_techniques` must match pattern `T1234` or `T1234.001`
- `severity` must be: low, medium, high, critical

### Action Validation
- Action type must be in the supported actions list
- `wait` requires `duration_seconds` > 0
- `send_notification` channel must be: slack, email, webhook
- `conditional` requires `condition`, `true_step`, `false_step`
- `parallel` requires non-empty `steps` array

### Action Order Warnings
- Warns if forensics collection happens before isolation
- Warns if process kill happens after file quarantine

## API Integration

### Execute Playbook Programmatically

```elixir
# From Elixir code
alias TamanduaServer.Playbooks.Executor

yaml = File.read!("playbook.yaml")
context = %{
  agent_id: "agent-123",
  detection_type: "ransomware",
  severity: "critical",
  confidence: 0.95
}

# Dry-run mode
{:ok, result} = Executor.execute(yaml, context, dry_run: true)

# Production mode
{:ok, result} = Executor.execute(yaml, context, dry_run: false)

# With options
{:ok, result} = Executor.execute(yaml, context,
  dry_run: false,
  continue_on_error: true,
  timeout: 300_000  # 5 minutes
)
```

### Validate Playbook

```elixir
alias TamanduaServer.Playbooks.Validator

yaml = File.read!("playbook.yaml")

case Validator.validate(yaml) do
  {:ok, playbook} ->
    IO.puts("Valid playbook: #{playbook["name"]}")
  {:error, errors} ->
    IO.inspect(errors, label: "Validation errors")
end

# Quick check
if Validator.valid?(yaml) do
  # Proceed
end
```

## Best Practices

1. **Start with Templates**: Use pre-built templates as starting points
2. **Test First**: Always dry-run before deploying to production
3. **Progressive Response**: Order actions from reconnaissance to containment
4. **Collect Evidence Early**: Run forensics collection before destructive actions
5. **Isolate Strategically**: Consider network dependencies before full isolation
6. **Document Context**: Use descriptive names and add comments in YAML
7. **Version Control**: Store playbooks in git for change tracking
8. **Regular Review**: Audit playbook effectiveness and update as threats evolve

## Troubleshooting

### Validation Fails
- Check YAML syntax (indentation, quotes, colons)
- Ensure required fields are present
- Verify action types are spelled correctly
- Check parameter types (numbers vs strings)

### Test Execution Fails
- Verify trigger conditions match test context
- Check that required context variables are provided
- Review error messages in execution log

### Action Not Executing
- Confirm agent is online
- Verify agent_id is correct in context
- Check response executor logs for errors

## Security Considerations

1. **Approval Workflows**: Set `require_approval: true` for destructive actions
2. **Least Privilege**: Only grant playbook editing to authorized analysts
3. **Audit Logging**: All executions are logged with full context
4. **Secrets Management**: Use environment variables for API keys/tokens
5. **Rate Limiting**: Prevent playbook abuse with execution throttling
6. **Rollback Capability**: Store pre-action state for incident recovery

## Examples

See the `templates/` directory for complete working examples:
- `ransomware.yaml` - Ransomware containment
- `lateral_movement.yaml` - Lateral movement response
- `data_exfiltration.yaml` - Data exfiltration blocking
- `credential_theft.yaml` - Credential theft investigation
