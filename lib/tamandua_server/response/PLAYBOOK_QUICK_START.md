# Playbook Engine - Quick Start Guide

## 5-Minute Quick Start

### 1. Start the Engine

```elixir
# Add to application.ex supervision tree
children = [
  # ... other supervisors
  TamanduaServer.Response.Playbook,
  TamanduaServer.Response.PlaybookEngine
]
```

### 2. Create Your First Playbook

```elixir
{:ok, playbook} = TamanduaServer.Response.Playbook.create_playbook(%{
  name: "Simple Alert Response",
  description: "Send notification on high-severity alert",
  trigger_type: "alert",
  steps: [
    %{
      "action" => "send_notification",
      "name" => "Alert SOC",
      "params" => %{
        "channel" => "slack",
        "message" => "High severity alert detected"
      }
    }
  ]
})
```

### 3. Execute the Playbook

```elixir
context = %{
  agent_id: "agent-001",
  severity: "high",
  alert_id: "alert-123"
}

{:ok, execution} = TamanduaServer.Response.PlaybookEngine.execute_playbook(
  playbook.id,
  context,
  skip_approval: true
)
```

### 4. Check Execution Status

```elixir
{:ok, status} = TamanduaServer.Response.PlaybookEngine.get_execution_status(execution.id)

IO.inspect(status)
# %{
#   execution: %Execution{status: "completed", ...},
#   steps: [%StepExecution{status: "completed", ...}],
#   progress: 100,
#   current_step: 1
# }
```

## Common Playbook Patterns

### Pattern 1: Isolate and Investigate

```elixir
%{
  name: "Isolate and Investigate",
  steps: [
    %{
      "action" => "isolate_host",
      "name" => "Isolate compromised host"
    },
    %{
      "action" => "collect_forensics",
      "name" => "Collect evidence",
      "params" => %{
        "memory_dump" => true,
        "process_list" => true,
        "network_connections" => true
      },
      "timeout_seconds" => 300
    },
    %{
      "action" => "create_ticket",
      "name" => "Create incident",
      "params" => %{
        "title" => "Security Incident - {{agent_id}}",
        "priority" => "high"
      }
    }
  ]
}
```

### Pattern 2: Severity-Based Response

```elixir
%{
  name: "Adaptive Response",
  steps: [
    %{
      "action" => "conditional",
      "params" => %{
        "condition" => %{"type" => "severity_gte", "value" => "high"},
        "true_step" => 1,   # High: aggressive
        "false_step" => 3   # Low: monitor
      }
    },
    # Step 1 - High severity path
    %{"action" => "isolate_host"},
    %{"action" => "kill_process"},
    # Step 3 - Low severity path
    %{
      "action" => "send_notification",
      "params" => %{"message" => "Low severity alert - monitoring"}
    }
  ]
}
```

### Pattern 3: Parallel Forensics

```elixir
%{
  name: "Fast Forensics",
  steps: [
    %{
      "action" => "parallel",
      "params" => %{
        "steps" => [
          %{
            "action" => "collect_artifact",
            "params" => %{"path" => "/var/log/syslog"}
          },
          %{
            "action" => "collect_artifact",
            "params" => %{"path" => "/var/log/auth.log"}
          },
          %{
            "action" => "collect_artifact",
            "params" => %{"path" => "/etc/passwd"}
          }
        ]
      },
      "timeout_seconds" => 60
    }
  ]
}
```

### Pattern 4: Retry on Failure

```elixir
%{
  name: "Resilient Action",
  steps: [
    %{
      "action" => "kill_process",
      "name" => "Terminate malware",
      "max_retries" => 3,
      "params" => %{"pid" => 12345}
    },
    %{
      "action" => "quarantine_file",
      "name" => "Quarantine malware",
      "max_retries" => 2,
      "continue_on_failure" => true  # Continue even if this fails
    },
    %{
      "action" => "send_notification",
      "params" => %{"message" => "Remediation complete"}
    }
  ]
}
```

## Step Actions Reference

### Host Actions
```elixir
# Isolate host
%{"action" => "isolate_host"}

# Kill process
%{"action" => "kill_process", "params" => %{"pid" => 12345}}

# Quarantine file
%{"action" => "quarantine_file", "params" => %{"path" => "/tmp/malware"}}

# Trigger scan
%{"action" => "trigger_scan", "params" => %{"path" => "/"}}

# Run script
%{
  "action" => "run_script",
  "params" => %{
    "script" => "Get-Process | Where-Object {$_.CPU -gt 50}",
    "script_type" => "powershell"
  }
}
```

### Network Actions
```elixir
# Block IP
%{
  "action" => "block_ip",
  "params" => %{
    "ip" => "192.168.1.100",
    "reason" => "Malicious activity"
  }
}

# Block domain
%{
  "action" => "block_domain",
  "params" => %{"domain" => "malicious.com"}
}

# Update blocklist
%{
  "action" => "update_blocklist",
  "params" => %{
    "blocklist_type" => "ip",
    "values" => ["10.0.0.1", "10.0.0.2"],
    "reason" => "Known C2 servers"
  }
}
```

### Forensics Actions
```elixir
# Collect forensics
%{
  "action" => "collect_forensics",
  "params" => %{
    "memory_dump" => true,
    "process_list" => true,
    "network_connections" => true,
    "registry_hives" => false,
    "event_logs" => true
  },
  "timeout_seconds" => 600
}
```

### Integration Actions
```elixir
# Create ticket
%{
  "action" => "create_ticket",
  "params" => %{
    "title" => "Security Incident",
    "priority" => "high",
    "webhook_url" => "https://jira.example.com/api/ticket"
  }
}

# Send notification - Slack
%{
  "action" => "send_notification",
  "params" => %{
    "channel" => "slack",
    "message" => "Alert: {{severity}} on {{agent_id}}",
    "slack_webhook_url" => "https://hooks.slack.com/..."
  }
}

# Send notification - Email
%{
  "action" => "send_notification",
  "params" => %{
    "channel" => "email",
    "to" => "soc@example.com",
    "subject" => "Security Alert",
    "message" => "Alert details..."
  }
}
```

### Control Flow Actions
```elixir
# Conditional
%{
  "action" => "conditional",
  "params" => %{
    "condition" => %{"type" => "field_equals", "field" => "severity", "value" => "high"},
    "true_step" => 2,
    "false_step" => 5
  }
}

# Wait
%{
  "action" => "wait",
  "params" => %{"duration_seconds" => 30}
}

# Parallel
%{
  "action" => "parallel",
  "params" => %{
    "steps" => [
      %{"action" => "..."},
      %{"action" => "..."}
    ]
  }
}
```

## Context Variables

Use `{{variable}}` syntax to reference execution context:

```elixir
context = %{
  agent_id: "agent-001",
  severity: "high",
  file_path: "/tmp/malware.exe",
  ip: "192.168.1.100"
}

# In step params
%{
  "action" => "send_notification",
  "params" => %{
    "message" => "Malware on {{agent_id}}: {{file_path}}"
  }
}
# Result: "Malware on agent-001: /tmp/malware.exe"
```

## Execution Options

```elixir
# Skip approval
PlaybookEngine.execute_playbook(playbook_id, context, skip_approval: true)

# Dry run (simulate only)
PlaybookEngine.execute_playbook(playbook_id, context, dry_run: true)

# Custom timeout
PlaybookEngine.execute_playbook(playbook_id, context, timeout: 300000)
```

## Approval Workflow

```elixir
# Create playbook with approval
{:ok, playbook} = Playbook.create_playbook(%{
  name: "Critical Action",
  require_approval: true,
  approval_timeout_minutes: 30,
  steps: [...]
})

# Execute (will wait)
{:ok, execution} = PlaybookEngine.execute_playbook(playbook.id, context)
# execution.status == "pending_approval"

# Approve manually
alias TamanduaServer.Response.Playbook.Execution

execution
|> Execution.changeset(%{
  status: "running",
  approved_by: user_id,
  approved_at: DateTime.utc_now()
})
|> Repo.update()
```

## Monitoring Executions

```elixir
# Get status
{:ok, status} = PlaybookEngine.get_execution_status(execution_id)

# List active
{:ok, active} = PlaybookEngine.list_active_executions()

# Cancel
PlaybookEngine.cancel_execution(execution_id, "User cancelled")

# Query history
from(e in Execution,
  where: e.playbook_id == ^playbook_id,
  order_by: [desc: e.started_at],
  limit: 10
)
|> Repo.all()

# Query failed steps
from(s in StepExecution,
  where: s.status == "failed",
  order_by: [desc: s.started_at],
  limit: 20
)
|> Repo.all()
```

## Error Handling

```elixir
# Retry a failed step
{:ok, result} = PlaybookEngine.retry_step(execution_id, step_index)

# Continue on failure
%{
  "action" => "quarantine_file",
  "continue_on_failure" => true  # Don't stop execution
}

# Automatic retries
%{
  "action" => "kill_process",
  "max_retries" => 3  # Retry up to 3 times
}
```

## Testing Playbooks

```elixir
# Use dry run mode
{:ok, execution} = PlaybookEngine.execute_playbook(
  playbook.id,
  %{agent_id: "test"},
  dry_run: true
)

# Check execution
{:ok, status} = PlaybookEngine.get_execution_status(execution.id)
assert status.execution.dry_run == true
```

## Best Practices

1. **Always name your steps** - Makes debugging easier
2. **Set appropriate timeouts** - Especially for long operations
3. **Use context variables** - Makes playbooks reusable
4. **Test with dry run first** - Validate before production
5. **Enable retries for transient failures** - Network, process termination
6. **Use approval for destructive actions** - Isolate, delete, etc.
7. **Monitor execution history** - Identify patterns and optimize
8. **Use parallel execution** - For independent operations
9. **Add descriptive error messages** - In conditional branches
10. **Version your playbooks** - Track changes over time

## Troubleshooting

### Execution stuck?
```elixir
# Check status
{:ok, status} = PlaybookEngine.get_execution_status(execution_id)
IO.inspect(status)

# Cancel if needed
PlaybookEngine.cancel_execution(execution_id, "Stuck - manual cancel")
```

### Step failed?
```elixir
# Check step details
step = Repo.get_by(StepExecution, execution_id: execution_id, step_index: 0)
IO.inspect(step.error_message)

# Retry if appropriate
PlaybookEngine.retry_step(execution_id, 0)
```

### Playbook not executing?
```elixir
# Verify playbook exists
{:ok, playbook} = Playbook.get_playbook(playbook_id)

# Check if enabled
IO.inspect(playbook.enabled)

# Check trigger conditions
IO.inspect(playbook.trigger_conditions)
```

## Examples from Production

See `PLAYBOOK_ENGINE.md` for complete examples:
- Ransomware response
- Lateral movement detection
- Parallel forensics collection
- Multi-agent coordination
- Error recovery workflows
