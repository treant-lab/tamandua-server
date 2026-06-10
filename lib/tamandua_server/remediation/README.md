# Remediation Module - Quick Start Guide

## Overview

The Remediation module provides automated incident response capabilities for Tamandua EDR with 15+ action types, multi-tier approval workflows, and comprehensive audit trails.

## Module Structure

```
tamandua_server/lib/tamandua_server/remediation/
├── playbook.ex              # Playbook schema and CRUD operations
├── execution.ex             # Execution tracking schema
├── executor.ex              # Main execution engine (15+ action handlers)
├── approval_manager.ex      # Approval workflow GenServer
├── templates.ex             # Pre-built playbook templates (12 templates)
└── README.md               # This file
```

## Quick Start

### 1. Run Database Migration

```bash
cd apps/tamandua_server
mix ecto.migrate
```

### 2. Seed Template Playbooks

```elixir
# In IEx or seeds.exs
alias TamanduaServer.Remediation.{Playbook, Templates}

Templates.list_templates()
|> Enum.each(fn template ->
  Playbook.create_playbook(template)
end)
```

### 3. Start Approval Manager

The ApprovalManager GenServer should be added to your application supervision tree:

```elixir
# In lib/tamandua_server/application.ex
children = [
  # ... existing children ...
  TamanduaServer.Remediation.ApprovalManager
]
```

### 4. Execute Your First Playbook

```elixir
# Get a template
{:ok, [template | _]} = Playbook.list_playbooks(%{is_template: true})

# Execute in dry-run mode
context = %{
  agent_id: "your-agent-id",
  alert_id: "your-alert-id"
}

{:ok, execution} = TamanduaServer.Remediation.Executor.execute_playbook(
  template.id,
  context,
  dry_run: true
)

# Check execution status
execution = Execution.get_execution(execution.id)
IO.inspect(execution.status)
```

## Available Action Types

### Network & Firewall
- `isolate_network` - Isolate host from network
- `block_ip` - Block IP address
- `block_domain` - Block domain via DNS

### Process & Service
- `kill_process` - Terminate process
- `stop_service` - Stop service
- `disable_service` - Disable service (with rollback)

### File Operations
- `quarantine_file` - Quarantine file (with rollback)
- `delete_file` - Delete file permanently
- `restore_file` - Restore quarantined file

### User & Identity
- `disable_user` - Disable account (with rollback)
- `enable_user` - Re-enable account
- `force_password_reset` - Force password change
- `enforce_mfa` - Require MFA
- `terminate_session` - Kill user sessions

### System Management
- `reboot_agent` - Reboot endpoint
- `deploy_patch` - Deploy security update
- `delete_registry_key` - Remove registry key (Windows)
- `run_script` - Execute custom script

### Security Operations
- `collect_forensics` - Collect evidence
- `revoke_certificate` - Revoke certificate
- `create_ticket` - Create incident ticket
- `send_notification` - Send alerts

## Pre-Built Templates

1. **Ransomware Response** - Immediate containment
2. **Malware Cleanup** - Comprehensive removal
3. **Credential Compromise** - Identity protection
4. **Data Exfiltration** - Stop data leaks
5. **Insider Threat** - Evidence preservation
6. **Phishing Response** - Email threat mitigation
7. **Lateral Movement** - APT containment
8. **Privilege Escalation** - Permission reversion
9. **Brute Force Attack** - Authentication protection
10. **Vulnerability Exploitation** - Patch deployment
11. **Zero-Day Threat** - Emergency response
12. **Supply Chain Attack** - Vendor compromise

## Creating Custom Playbooks

### Via Code

```elixir
{:ok, playbook} = Playbook.create_playbook(%{
  name: "Custom Malware Response",
  description: "Custom workflow for specific threat",
  category: "malware",
  trigger_type: "alert",
  trigger_conditions: %{
    "detection_type" => "malware",
    "severity" => "high"
  },
  require_approval: true,
  approval_tier: "analyst",
  auto_rollback_on_failure: true,
  risk_level: "high",
  steps: [
    %{
      "action" => "isolate_network",
      "name" => "Isolate Infected Host",
      "params" => %{},
      "max_retries" => 3,
      "timeout_seconds" => 60
    },
    %{
      "action" => "kill_process",
      "name" => "Kill Malicious Process",
      "params" => %{"pid" => "{{pid}}"},
      "max_retries" => 2,
      "continue_on_failure" => false
    },
    %{
      "action" => "quarantine_file",
      "name" => "Quarantine Malware",
      "params" => %{"path" => "{{file_path}}"},
      "max_retries" => 2
    },
    %{
      "action" => "send_notification",
      "name" => "Alert Security Team",
      "params" => %{
        "channel" => "slack",
        "message" => "Malware contained on {{agent_id}}"
      },
      "continue_on_failure" => true
    }
  ],
  tags: ["malware", "custom", "automated"]
})
```

### Via LiveView Editor

Navigate to `/remediation/playbooks/new` and use the visual editor.

## Approval Workflow

### Approval Tiers

- **analyst** - Basic security analysts
- **senior_analyst** - Senior security analysts
- **manager** - Security managers
- **security_director** - Security directors

### Approving Executions

```elixir
# List pending approvals
{:ok, pending} = ApprovalManager.list_pending_approvals()

# Approve an execution
{:ok, execution} = ApprovalManager.approve(
  execution_id,
  approver_id,
  "Approved after threat analysis"
)

# Reject an execution
{:ok, execution} = ApprovalManager.reject(
  execution_id,
  approver_id,
  "Additional investigation required"
)

# Delegate approval
{:ok, delegation} = ApprovalManager.delegate(
  execution_id,
  from_user_id,
  to_user_id,
  "Delegating to on-call analyst"
)
```

## Rollback Support

Actions that support rollback:
- `quarantine_file` → `restore_file`
- `disable_user` → `enable_user`
- `disable_service` → `enable_service`

```elixir
# Rollback an execution
{:ok, execution} = Executor.rollback_execution(
  execution_id,
  user_id
)
```

## Context Variables

Use `{{variable}}` syntax in playbook parameters to reference context:

```elixir
# Context
context = %{
  agent_id: "agent-123",
  pid: 1234,
  file_path: "/tmp/malware.exe",
  username: "compromised_user"
}

# Step with variables
%{
  "action" => "kill_process",
  "params" => %{"pid" => "{{pid}}"}  # Will be replaced with 1234
}

%{
  "action" => "quarantine_file",
  "params" => %{"path" => "{{file_path}}"}  # Will be replaced with /tmp/malware.exe
}
```

## Monitoring & Metrics

### Execution Status

```elixir
execution = Execution.get_execution(execution_id)

IO.puts("Status: #{execution.status}")
IO.puts("Progress: #{execution.steps_completed}/#{execution.steps_total}")
IO.puts("Duration: #{Execution.calculate_duration(execution)}s")
```

### Playbook Metrics

```elixir
playbook = Playbook.get_playbook(playbook_id)

IO.puts("Total Executions: #{playbook.execution_count}")
IO.puts("Success Rate: #{playbook.success_count / playbook.execution_count * 100}%")
```

## Testing

```bash
# Run tests
mix test test/tamandua_server/remediation/

# Run specific test
mix test test/tamandua_server/remediation/executor_test.exs
```

## Troubleshooting

### Execution Stuck in "pending_approval"

Check approval timeout settings and verify approvers have correct permissions.

```elixir
# Check timeout
execution = Execution.get_execution(execution_id)
timeout_at = DateTime.add(execution.inserted_at, execution.approval_timeout_minutes * 60, :second)
IO.puts("Timeout at: #{timeout_at}")
```

### Action Failing

Check execution results for error details:

```elixir
execution = Execution.get_execution(execution_id)
IO.inspect(execution.execution_results, label: "Results")
IO.inspect(execution.error_message, label: "Error")
```

### Rollback Not Available

Verify the action supports rollback and rollback data was saved:

```elixir
execution = Execution.get_execution(execution_id)
IO.puts("Rollback Available: #{execution.rollback_available}")
IO.inspect(execution.rollback_data, label: "Rollback Data")
```

## Configuration

### Environment Variables

```bash
# Approval settings
REMEDIATION_APPROVAL_TIMEOUT_DEFAULT=30  # minutes

# Notification settings
REMEDIATION_SLACK_WEBHOOK_URL=https://hooks.slack.com/...
REMEDIATION_EMAIL_RECIPIENTS=security@company.com

# Ticketing
REMEDIATION_TICKETING_WEBHOOK_URL=https://jira.company.com/api/...
```

### Application Config

```elixir
# config/config.exs
config :tamandua_server, TamanduaServer.Remediation.ApprovalManager,
  check_timeout_interval: 60_000,  # 1 minute
  reminder_interval: 300_000  # 5 minutes

config :tamandua_server, TamanduaServer.Remediation.Executor,
  default_timeout: 300_000,  # 5 minutes
  max_retries: 3,
  retry_delay: 1000  # ms
```

## API Reference

See `REMEDIATION_PLAYBOOKS.md` for complete API documentation.

## Best Practices

1. **Test with Dry-Run First**: Always test new playbooks in dry-run mode
2. **Use Templates**: Start with templates and customize
3. **Set Appropriate Approvals**: Match risk level to approval tier
4. **Enable Auto-Rollback**: For non-destructive actions
5. **Monitor Metrics**: Track success rates and failures
6. **Document Playbooks**: Add clear descriptions and tags
7. **Use Context Variables**: Make playbooks reusable
8. **Set Realistic Timeouts**: Based on action complexity

## Support

- **Full Documentation**: `/REMEDIATION_PLAYBOOKS.md`
- **Implementation Summary**: `/REMEDIATION_IMPLEMENTATION_SUMMARY.md`
- **API Docs**: `/api/docs#remediation`

## License

Part of Tamandua EDR. See LICENSE file.
