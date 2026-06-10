# Persistent Agent Command Queue - Usage Guide

## Overview

The agent command queue has been migrated from in-memory storage to PostgreSQL, ensuring commands survive worker crashes and server restarts.

## Key Components

1. **AgentCommand Schema** - Ecto schema for persisting commands
2. **CommandManager** - High-level API for managing commands
3. **Worker** - Updated to send/receive commands from database
4. **CleanupCommandsWorker** - Oban job for periodic cleanup

## Database Schema

Commands are stored in the `agent_commands` table with the following fields:

- `id` (UUID) - Unique command identifier
- `agent_id` (string) - Target agent ID
- `command_type` (string) - Type of command (kill_process, quarantine_file, etc.)
- `command_params` (jsonb) - Command parameters
- `status` (string) - Command status (pending, sent, acknowledged, completed, failed)
- `priority` (integer) - Priority 0-10 (higher = more urgent)
- `expires_at` (utc_datetime) - When the command expires
- `sent_at`, `acknowledged_at`, `completed_at` - Lifecycle timestamps
- `error` (text) - Error message if failed
- `result` (jsonb) - Result data from agent

## Usage Examples

### Queue a Command

```elixir
alias TamanduaServer.Agents.CommandManager

# Basic usage
{:ok, command} = CommandManager.queue_command(
  "agent-id-123",
  :kill_process,
  %{pid: 1234}
)

# With priority and timeout
{:ok, command} = CommandManager.queue_command(
  "agent-id-123",
  :isolate_network,
  %{},
  priority: 10,      # Urgent (0-10 scale)
  timeout: 300       # Expires in 5 minutes
)
```

### Query Commands

```elixir
# Get a specific command
{:ok, command} = CommandManager.get_command(command_id)

# Get all pending commands for an agent
pending = CommandManager.pending_commands("agent-id-123")

# Get all active commands (pending/sent/acknowledged)
active = CommandManager.active_commands("agent-id-123")

# Get statistics
stats = CommandManager.command_stats("agent-id-123")
# => %{
#   total: 15,
#   by_status: %{"pending" => 3, "completed" => 10, "failed" => 2},
#   avg_completion_seconds: 12.5
# }
```

### Cancel a Command

```elixir
# Cancel a pending command (only works if not yet sent)
:ok = CommandManager.cancel_command(command_id)
```

### Retry a Failed Command

```elixir
# Creates a new command with the same parameters
{:ok, new_command} = CommandManager.retry_command(failed_command_id)
```

## Command Lifecycle

1. **pending** - Command created, queued for sending
2. **sent** - Sent to agent via WebSocket
3. **acknowledged** - Agent acknowledged receipt
4. **completed** - Agent executed successfully
5. **failed** - Execution failed or timed out

## Automatic Cleanup

The `CleanupCommandsWorker` runs every 30 minutes and:

1. Marks expired commands (past `expires_at`) as failed
2. Deletes completed/failed commands older than 7 days
3. Reports queue health statistics

You can also manually trigger cleanup:

```elixir
# Enqueue immediate cleanup with custom retention
{:ok, _job} = TamanduaServer.Workers.CleanupCommandsWorker.new(%{
  "retention_days" => 30
}) |> Oban.insert()
```

## Worker Crash Recovery

When an agent reconnects after a worker crash:

1. Worker initialization calls `send_pending_commands(state)`
2. Loads up to 10 pending commands from database, ordered by priority
3. Sends commands to agent and marks as "sent"
4. Agent responses update command status in database

Command callbacks are stored in process dictionary:
- If worker crashes, caller receives `{:error, :disconnected}`
- Command remains in database for retry when agent reconnects

## Migration

To apply the database changes:

```bash
cd apps/tamandua_server
mix ecto.migrate
```

This creates:
- `agent_commands` table
- Indexes on (agent_id, status) and (status, inserted_at)
- Expiration index for cleanup queries

## Testing

Run the test suite:

```bash
mix test test/tamandua_server/agents/command_manager_test.exs
```

## Monitoring

Commands can be monitored via:

1. **Database queries** - Query `agent_commands` table directly
2. **PubSub events** - Subscribe to `"agent_commands"` topic for cleanup stats
3. **LiveView dashboard** - View pending commands per agent

Example PubSub subscription:

```elixir
Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agent_commands")

# Receive messages like:
# {:cleanup_stats, %{expired: 5, deleted: 120, ...}}
```

## Best Practices

1. **Use appropriate priorities** - Reserve priority 10 for critical actions (e.g., network isolation)
2. **Set reasonable timeouts** - Default is 1 hour; adjust based on command type
3. **Monitor queue depth** - High pending counts may indicate connectivity issues
4. **Review failed commands** - Check error messages to identify patterns
5. **Use CommandManager API** - Don't directly insert into `agent_commands` table

## Backwards Compatibility

The Worker interface remains unchanged:

```elixir
# Still works exactly as before
TamanduaServer.Agents.Worker.send_command(worker_pid, %{
  type: :kill_process,
  params: %{pid: 1234}
})
```

The command is now automatically persisted to the database.
