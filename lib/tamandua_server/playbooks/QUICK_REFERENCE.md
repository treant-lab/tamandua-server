# Playbook Editor - Quick Reference Card

## Basic Template

```yaml
name: "Your Playbook Name"
description: "What this playbook does"

trigger:
  detection_type: "ransomware"  # What triggers this
  confidence: 0.9               # Minimum confidence (0.0-1.0)
  severity: "high"              # Minimum severity

actions:
  - action: "isolate_host"      # What to do
  - action: "collect_forensics"
  - action: "alert_soc"
```

## Common Actions Cheat Sheet

### Containment Actions
```yaml
# Isolate host from network
- action: "isolate_host"

# Kill suspicious process
- action: "kill_process"

# Quarantine malicious file
- action: "quarantine_file"

# Block IP address
- action: "block_ip"
  block_ip:
    ip: "192.168.1.100"

# Block domain
- action: "block_domain"
  block_domain:
    domain: "evil.com"
```

### Investigation Actions
```yaml
# Collect forensic evidence
- action: "collect_forensics"
  collect_forensics:
    memory_dump: true
    process_list: true
    network_connections: true

# Trigger malware scan
- action: "trigger_scan"
  trigger_scan:
    path: "C:\\Suspicious"
```

### Notification Actions
```yaml
# Create SIEM ticket
- action: "create_ticket"
  create_ticket:
    title: "Security Incident"
    severity: "critical"

# Send Slack alert
- action: "send_notification"
  send_notification:
    channel: "slack"
    message: "Alert: Ransomware detected"

# Send email alert
- action: "send_notification"
  send_notification:
    channel: "email"
    to: "security@company.com"
    message: "Critical security alert"
```

### Advanced Actions
```yaml
# Wait before next action
- action: "wait"
  wait:
    duration_seconds: 30

# Run custom script
- action: "run_script"
  run_script:
    script: "Get-Process | Export-CSV processes.csv"
    script_type: "powershell"

# Update threat blocklist
- action: "update_blocklist"
  update_blocklist:
    blocklist_type: "ip"
    values:
      - "10.0.0.1"
      - "10.0.0.2"
```

## Trigger Conditions

### Detection Type
```yaml
trigger:
  detection_type: "ransomware"
  # Options: ransomware, malware, lateral_movement,
  #          credential_theft, data_exfiltration,
  #          command_and_control, privilege_escalation,
  #          persistence, defense_evasion
```

### Confidence Threshold
```yaml
trigger:
  confidence: 0.9  # Only execute if ML confidence >= 90%
```

### Severity Level
```yaml
trigger:
  severity: "high"  # Only execute for high/critical alerts
  # Options: low, medium, high, critical
```

### MITRE Techniques
```yaml
trigger:
  mitre_techniques:
    - "T1486"  # Ransomware
    - "T1003"  # Credential Dumping
  # Triggers if ANY technique matches
```

### Multiple Conditions (ALL must match)
```yaml
trigger:
  detection_type: "ransomware"
  confidence: 0.85
  severity: "high"
  mitre_techniques:
    - "T1486"
```

## Context Variables

Use these in your actions:
- `${agent_id}` - Agent identifier
- `${file_path}` - Suspicious file path
- `${pid}` - Process ID
- `${process_name}` - Process name
- `${remote_ip}` - Remote IP address
- `${domain}` - Domain name

Example:
```yaml
- action: "block_ip"
  block_ip:
    ip: "${remote_ip}"  # Uses IP from alert context
```

## Action Order Best Practices

### Recommended Order
1. **Contain** - Isolate, block, kill
2. **Collect** - Gather forensic evidence
3. **Investigate** - Scan, analyze
4. **Notify** - Create tickets, send alerts

### Good Example
```yaml
actions:
  - action: "isolate_host"        # 1. Contain threat
  - action: "kill_process"
  - action: "collect_forensics"   # 2. Gather evidence
  - action: "create_ticket"       # 3. Notify team
```

### Avoid This
```yaml
actions:
  - action: "collect_forensics"   # ❌ Evidence first
  - action: "isolate_host"        # ❌ Contain second (too late!)
```

## Quick Tips

1. **Test First**: Always use "Test (Dry-Run)" before saving
2. **Start Simple**: Begin with templates, customize as needed
3. **One Goal**: Each playbook should handle one scenario
4. **Document**: Use clear names and descriptions
5. **Review Logs**: Check execution logs after dry-runs

## Common Patterns

### Ransomware Response
```yaml
name: "Ransomware Auto-Response"
trigger:
  detection_type: "ransomware"
  confidence: 0.9
actions:
  - action: "isolate_host"
  - action: "kill_process"
  - action: "collect_forensics"
  - action: "create_ticket"
```

### Suspicious Network Activity
```yaml
name: "Block Suspicious C2"
trigger:
  detection_type: "command_and_control"
  confidence: 0.8
actions:
  - action: "block_ip"
  - action: "block_domain"
  - action: "isolate_host"
  - action: "send_notification"
```

### Credential Theft
```yaml
name: "Credential Theft Response"
trigger:
  mitre_techniques:
    - "T1003"
actions:
  - action: "collect_forensics"
    collect_forensics:
      memory_dump: true
  - action: "kill_process"
  - action: "create_ticket"
```

## Validation Errors

| Error | Fix |
|-------|-----|
| "Missing required fields" | Add `name`, `trigger`, and `actions` |
| "actions cannot be empty" | Add at least one action |
| "Invalid detection_type" | Use valid type (ransomware, malware, etc.) |
| "confidence must be between 0.0 and 1.0" | Use decimal like `0.9` |
| "Invalid MITRE technique" | Format as `T1234` or `T1234.001` |
| "invalid action type" | Check spelling, use supported actions |
| "duration_seconds required" | Add `duration_seconds: 30` to wait action |

## Keyboard Shortcuts (Monaco Editor)

- `Ctrl+Space` - Auto-complete
- `Ctrl+F` - Find
- `Ctrl+H` - Find and replace
- `Ctrl+/` - Toggle comment
- `Ctrl+Z` - Undo
- `Ctrl+Shift+Z` - Redo
- `F1` - Command palette

## Need Help?

1. Check templates for examples
2. Review validation errors/warnings
3. Test in dry-run mode
4. Read full documentation in `README.md`
5. Contact security team lead

## Version

Last Updated: 2025
Compatible with: Tamandua EDR v0.1.0+
