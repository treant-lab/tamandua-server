# Playbook Execution Engine

## Overview

The Playbook Execution Engine provides a sophisticated SOAR-like automation framework for Tamandua EDR. It enables automated, multi-step response workflows with advanced features like retry mechanisms, parallel execution, conditional branching, and approval workflows.

## Architecture

### Components

1. **PlaybookEngine (GenServer)** - Core execution orchestrator
2. **Playbook (GenServer)** - Playbook management and storage
3. **Execution** - Execution record schema
4. **StepExecution** - Step-level execution tracking
5. **ConditionEvaluator** - Condition evaluation logic
6. **Executor** - Command execution interface

### Database Schema

#### playbook_executions
```sql
CREATE TABLE playbook_executions (
  id UUID PRIMARY KEY,
  playbook_id UUID REFERENCES playbooks(id),
  trigger_event JSONB,
  status VARCHAR,  -- pending_approval, running, completed, failed, cancelled
  steps_completed JSONB[],
  current_step INTEGER,
  error_message TEXT,
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  approved_by UUID REFERENCES users(id),
  approved_at TIMESTAMP,
  execution_context JSONB,
  dry_run BOOLEAN DEFAULT false,
  inserted_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

#### playbook_step_executions
```sql
CREATE TABLE playbook_step_executions (
  id UUID PRIMARY KEY,
  execution_id UUID REFERENCES playbook_executions(id),
  step_index INTEGER,
  step_name VARCHAR,
  action_type VARCHAR,
  status VARCHAR,  -- pending, running, completed, failed, skipped, retrying
  params JSONB,
  result JSONB,
  error_message TEXT,
  retry_count INTEGER DEFAULT 0,
  max_retries INTEGER DEFAULT 0,
  timeout_seconds INTEGER,
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  duration_ms INTEGER,
  inserted_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

## Features

### 1. Step Types

#### Command Steps
Execute actions on agents:
- `isolate_host` - Isolate agent from network
- `kill_process` - Terminate a process
- `quarantine_file` - Quarantine a file
- `block_ip` - Block an IP address
- `block_domain` - Block a domain
- `collect_forensics` - Collect forensic evidence
- `trigger_scan` - Initiate a scan
- `run_script` - Execute a script
- `disable_user` - Disable a user account

#### Workflow Steps
- `conditional` - Branch based on conditions
- `parallel` - Execute multiple steps concurrently
- `wait` - Pause execution
- `approval` - Pause for human approval

#### Integration Steps
- `create_ticket` - Create incident ticket
- `send_notification` - Send alerts (Slack, email, webhook)
- `enrich_ioc` - Enrich indicators
- `update_blocklist` - Update threat intel

### 2. Retry Mechanism

Failed steps are automatically retried with exponential backoff:

```elixir
%{
  "action" => "kill_process",
  "max_retries" => 3,  # Retry up to 3 times
  "params" => %{"pid" => 12345}
}
```

Retry delay: `1000ms * 2^retry_count`
- 1st retry: 1 second
- 2nd retry: 2 seconds
- 3rd retry: 4 seconds

### 3. Conditional Branching

Execute different paths based on runtime conditions:

```elixir
%{
  "action" => "conditional",
  "params" => %{
    "condition" => %{
      "type" => "severity_gte",
      "value" => "high"
    },
    "true_step" => 2,   # Jump to step 2 if true
    "false_step" => 5   # Jump to step 5 if false
  }
}
```

#### Supported Conditions
- `severity_gte` / `severity_lte` - Severity comparison
- `field_equals` - Exact match
- `field_contains` - Contains check
- `field_matches` - Regex match
- `count_gte` - Threshold check
- `mitre_technique_in` - MITRE ATT&CK technique
- `mitre_tactic_in` - MITRE ATT&CK tactic
- `agent_tag_in` - Agent tag filtering
- `time_window` - Time-based filtering
- `and` / `or` / `not` - Boolean combinators

### 4. Parallel Execution

Run multiple steps concurrently for performance:

```elixir
%{
  "action" => "parallel",
  "params" => %{
    "steps" => [
      %{"action" => "collect_forensics", "params" => %{"type" => "memory"}},
      %{"action" => "collect_forensics", "params" => %{"type" => "network"}},
      %{"action" => "collect_forensics", "params" => %{"type" => "registry"}}
    ]
  },
  "timeout_seconds" => 300
}
```

Max parallel steps: 10 (configurable)

### 5. Timeout Handling

Each step can have its own timeout:

```elixir
%{
  "action" => "collect_forensics",
  "timeout_seconds" => 300,  # 5 minutes
  "params" => %{"type" => "full"}
}
```

Default timeout: 300 seconds (5 minutes)

### 6. Approval Workflow

Require human approval before execution:

```elixir
# Create playbook with approval
Playbook.create_playbook(%{
  name: "Critical Response",
  require_approval: true,
  approval_timeout_minutes: 30,
  steps: [...]
})

# Execute (will wait for approval)
{:ok, execution} = PlaybookEngine.execute_playbook(playbook_id, context)
# execution.status == "pending_approval"

# Approve
execution
|> Execution.changeset(%{
  status: "running",
  approved_by: user_id,
  approved_at: DateTime.utc_now()
})
|> Repo.update()

# Or skip approval programmatically
{:ok, execution} = PlaybookEngine.execute_playbook(
  playbook_id,
  context,
  skip_approval: true
)
```

### 7. Context Variables

Use context variables in step parameters:

```elixir
# Execution context
context = %{
  agent_id: "agent-001",
  severity: "high",
  file_path: "/tmp/malware.exe"
}

# Step with variable interpolation
%{
  "action" => "send_notification",
  "params" => %{
    "message" => "Malware detected on {{agent_id}}: {{file_path}}"
  }
}
# Result: "Malware detected on agent-001: /tmp/malware.exe"
```

### 8. Error Handling

Continue execution even when steps fail:

```elixir
%{
  "action" => "quarantine_file",
  "params" => %{"path" => "/tmp/malware"},
  "continue_on_failure" => true  # Don't stop on error
}
```

### 9. Dry Run Mode

Simulate execution without actually running steps:

```elixir
{:ok, execution} = PlaybookEngine.execute_playbook(
  playbook_id,
  context,
  dry_run: true  # Simulate only
)
```

## Usage Examples

### Example 1: Ransomware Response

```elixir
{:ok, playbook} = Playbook.create_playbook(%{
  name: "Ransomware Response",
  description: "Automated ransomware containment",
  trigger_type: "alert",
  require_approval: false,
  steps: [
    %{
      "action" => "isolate_host",
      "name" => "Isolate infected host",
      "max_retries" => 2
    },
    %{
      "action" => "kill_process",
      "name" => "Terminate malicious process",
      "max_retries" => 2
    },
    %{
      "action" => "quarantine_file",
      "name" => "Quarantine malware",
      "continue_on_failure" => true
    },
    %{
      "action" => "collect_forensics",
      "name" => "Collect evidence",
      "params" => %{"type" => "full"},
      "timeout_seconds" => 300
    },
    %{
      "action" => "create_ticket",
      "name" => "Create incident",
      "params" => %{
        "title" => "Ransomware Detected",
        "priority" => "critical"
      }
    },
    %{
      "action" => "send_notification",
      "name" => "Alert SOC",
      "params" => %{
        "channel" => "slack",
        "message" => "CRITICAL: Ransomware detected and contained on {{agent_id}}"
      }
    }
  ]
})

# Execute
context = %{
  agent_id: "agent-001",
  severity: "critical",
  file_path: "/home/user/ransom.exe",
  pid: 12345
}

{:ok, execution} = PlaybookEngine.execute_playbook(playbook.id, context)
```

### Example 2: Conditional Lateral Movement Response

```elixir
{:ok, playbook} = Playbook.create_playbook(%{
  name: "Lateral Movement Response",
  description: "Response based on confidence level",
  trigger_type: "alert",
  require_approval: true,
  approval_timeout_minutes: 15,
  steps: [
    %{
      "action" => "collect_forensics",
      "name" => "Gather evidence",
      "params" => %{"type" => "network"}
    },
    %{
      "action" => "conditional",
      "name" => "Check confidence",
      "params" => %{
        "condition" => %{
          "type" => "and",
          "conditions" => [
            %{"type" => "severity_gte", "value" => "high"},
            %{"type" => "field_equals", "field" => "confidence", "value" => 0.8}
          ]
        },
        "true_step" => 3,   # High confidence: isolate
        "false_step" => 4   # Low confidence: just monitor
      }
    },
    %{
      "action" => "isolate_host",
      "name" => "Isolate compromised host"
    },
    %{
      "action" => "send_notification",
      "name" => "Notify for investigation",
      "params" => %{
        "message" => "Potential lateral movement detected, manual review required"
      }
    }
  ]
})
```

### Example 3: Parallel Forensics Collection

```elixir
{:ok, playbook} = Playbook.create_playbook(%{
  name: "Parallel Forensics",
  description: "Collect multiple artifacts concurrently",
  trigger_type: "manual",
  steps: [
    %{
      "action" => "parallel",
      "name" => "Collect all artifacts",
      "params" => %{
        "steps" => [
          %{
            "action" => "collect_forensics",
            "params" => %{"type" => "memory", "memory_dump" => true}
          },
          %{
            "action" => "collect_forensics",
            "params" => %{"type" => "network", "network_connections" => true}
          },
          %{
            "action" => "collect_forensics",
            "params" => %{"type" => "registry", "registry_hives" => true}
          }
        ]
      },
      "timeout_seconds" => 600
    },
    %{
      "action" => "create_ticket",
      "name" => "Create forensic report ticket",
      "params" => %{
        "title" => "Forensic Evidence Collected",
        "priority" => "high"
      }
    }
  ]
})
```

## API Reference

### PlaybookEngine

#### execute_playbook/3
```elixir
@spec execute_playbook(String.t(), map(), keyword()) ::
  {:ok, Execution.t()} | {:error, term()}
```

Execute a playbook with the given context.

**Options:**
- `:skip_approval` - Skip approval even if required (default: false)
- `:dry_run` - Simulate execution (default: false)
- `:timeout` - Overall execution timeout in ms (default: 600000)
- `:on_complete` - Callback when execution completes

#### get_execution_status/1
```elixir
@spec get_execution_status(String.t()) :: {:ok, map()} | {:error, :not_found}
```

Get current status of an execution including progress and step details.

#### cancel_execution/2
```elixir
@spec cancel_execution(String.t(), String.t()) :: :ok | {:error, term()}
```

Cancel a running or pending execution.

#### retry_step/2
```elixir
@spec retry_step(String.t(), integer()) :: {:ok, map()} | {:error, term()}
```

Manually retry a failed step.

#### list_active_executions/0
```elixir
@spec list_active_executions() :: {:ok, [map()]}
```

List all currently running executions.

## Performance Considerations

### Parallel Execution
- Max concurrent steps: 10 (configurable via `@max_parallel_steps`)
- Each parallel task runs in its own process
- Timeout applies to the entire parallel block

### Retry Delays
- Exponential backoff prevents system overload
- Base delay: 1000ms
- Formula: `1000 * 2^retry_count`

### Database Operations
- Step executions are inserted atomically
- Execution status updates are batched
- Indexes on execution_id, status, and timestamps

### Memory Usage
- Active executions kept in GenServer state
- Completed executions cleaned up after 1 hour
- Step results stored in JSONB for efficient querying

## Monitoring and Observability

### Metrics
- Execution duration
- Step success/failure rates
- Retry counts
- Parallel step concurrency

### Logging
All steps log at INFO level:
```
[info] Executing step 0: Isolate infected host (isolate_host)
[info] Step 0 completed in 1234ms
[error] Step 1 failed: Connection timeout (retry 1/3)
[info] Playbook execution abc-123 completed successfully
```

### Audit Trail
Complete execution history stored in:
- `playbook_executions` - Execution-level records
- `playbook_step_executions` - Step-level details

## Troubleshooting

### Execution Stuck
```elixir
# Check active executions
{:ok, active} = PlaybookEngine.list_active_executions()

# Cancel if stuck
PlaybookEngine.cancel_execution(execution_id, "Manual cancellation")
```

### Step Failures
```elixir
# Query failed steps
from(s in StepExecution,
  where: s.status == "failed" and s.execution_id == ^execution_id
)
|> Repo.all()

# Retry specific step
PlaybookEngine.retry_step(execution_id, step_index)
```

### Performance Issues
- Reduce max parallel steps if system is overloaded
- Increase step timeouts for slow operations
- Use dry run mode to test playbooks
- Monitor database query performance

## Best Practices

1. **Use Descriptive Names** - Name steps clearly for audit trail
2. **Set Appropriate Timeouts** - Don't use default for long operations
3. **Enable Retries Judiciously** - Not all failures should retry
4. **Test with Dry Run** - Validate playbooks before production
5. **Use Conditional Logic** - Make playbooks adaptive
6. **Monitor Execution History** - Review failures and optimize
7. **Implement Rollback Steps** - Plan for failure scenarios
8. **Use Approval for Critical Actions** - Isolate, delete, etc.
9. **Context Variables** - Make playbooks reusable
10. **Document Playbooks** - Add descriptions and comments

## Future Enhancements

- [ ] Playbook versioning
- [ ] Step dependency graphs
- [ ] Dynamic step generation
- [ ] Machine learning-based optimization
- [ ] Cross-playbook orchestration
- [ ] Webhook triggers
- [ ] Visual playbook editor
- [ ] Execution replay/debugging mode
- [ ] Cost estimation for cloud operations
- [ ] Integration with external SOAR platforms
