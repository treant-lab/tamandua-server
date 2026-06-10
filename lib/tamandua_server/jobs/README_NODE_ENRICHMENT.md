# Knowledge Graph Node Enrichment System

## Overview

The Knowledge Graph now implements a robust node enrichment system that eliminates stub nodes and provides automatic background enrichment of missing node data.

## Problem Solved

Previously, when edges were created to nodes that didn't exist, the system would create "stub" nodes with `stub: true` flag. These stubs had several issues:

1. No mechanism to fetch real data for stub nodes
2. Stubs could accumulate without cleanup
3. No differentiation between "pending enrichment" and "permanently missing"
4. Analytics and queries had to handle stub nodes specially

## Solution Architecture

### 1. Pending Status (Instead of Stubs)

Nodes are now created with `status: :pending` instead of `stub: true`:

```elixir
%{
  type: :process,
  id: "agent123:1234",
  status: :pending,
  pending_since: ~U[2026-02-20 10:00:00Z],
  node_key: {:process, "agent123:1234"}
}
```

### 2. Background Enrichment Jobs

When a pending node is created, an Oban job is automatically queued:

```elixir
%{node_type: "process", node_id: "agent123:1234"}
|> TamanduaServer.Jobs.NodeEnrichmentJob.new()
|> Oban.insert()
```

The job fetches real data from:
- Database (alerts, devices, users, vulnerabilities)
- Telemetry cache (recent process events)
- Threat intelligence APIs (network IPs)
- External enrichment services (DNS, WHOIS)

### 3. Status Transition

Once enriched, the node transitions from `:pending` to `:complete`:

```elixir
# Before enrichment
%{status: :pending, pending_since: ~U[...]}

# After enrichment
%{
  status: :complete,
  enriched_at: ~U[...],
  # ... real data fields (hostname, path, hash, etc.)
}
```

### 4. Automatic Cleanup

Orphaned pending nodes (no edges, pending > 1 hour) are automatically pruned:

```elixir
defp prune_stale_pending_nodes do
  # Remove pending nodes that:
  # - Have status: :pending
  # - Are older than 1 hour
  # - Have no edges (orphaned)
end
```

## Files Modified

### Core Implementation

1. **apps/tamandua_server/lib/tamandua_server/graph/knowledge_graph.ex**
   - Lines 398-432: Updated `do_upsert_node` to handle pending → complete transition
   - Lines 434-456: Updated `do_add_edge` to validate endpoints
   - Lines 488-518: Replaced `ensure_node_exists` stub creation with pending nodes
   - Lines 506-518: Added `queue_enrichment_job` function
   - Lines 1052-1076: Added `prune_stale_pending_nodes` and `is_orphaned_node?`
   - Lines 380-394: Updated prune handler to clean stale pending nodes
   - Lines 208-214: Added `pending_nodes/0` API function
   - Lines 337-363: Updated stats to include pending node count
   - Lines 1115-1118: Added `count_pending_nodes` helper

2. **apps/tamandua_server/lib/tamandua_server/graph/analytics.ex**
   - Line 276: Changed stub flag to status: :pending

### New Files

3. **apps/tamandua_server/lib/tamandua_server/jobs/node_enrichment_job.ex**
   - Complete Oban worker implementation
   - Type-specific enrichment strategies
   - Threat intel integration
   - Error handling and retry logic

### Configuration

4. **apps/tamandua_server/config/config.exs**
   - Line 85: Added `graph_enrichment: 5` queue

## Usage

### Creating Edges (Automatic Enrichment)

```elixir
# Add edge - both nodes will be created as pending if missing
KnowledgeGraph.add_edge(
  {:process, "agent1:1234"},
  {:network, "192.168.1.1:443"},
  :communicates_with
)

# NodeEnrichmentJob automatically queued for both nodes if they don't exist
```

### Checking Pending Nodes

```elixir
# Get all pending nodes (limit 100)
pending = KnowledgeGraph.pending_nodes()

# Get pending count in stats
stats = KnowledgeGraph.stats()
# => %{pending_nodes: 42, ...}
```

### Manual Enrichment

```elixir
# Queue enrichment for specific node
%{node_type: "device", node_id: "agent-abc-123"}
|> TamanduaServer.Jobs.NodeEnrichmentJob.new()
|> Oban.insert()
```

## Enrichment Sources by Node Type

| Node Type       | Primary Source                | Fallback              |
|-----------------|-------------------------------|-----------------------|
| device          | agents table                  | -                     |
| process         | telemetry cache               | -                     |
| user            | users table                   | telemetry (username)  |
| network         | IP parsing + threat intel     | -                     |
| file            | alerts table (file events)    | -                     |
| alert           | alerts table                  | -                     |
| vulnerability   | vulnerabilities table         | -                     |
| service         | service discovery             | pending               |
| ai_model        | AI inventory                  | pending               |
| mcp_server      | MCP inventory                 | pending               |
| group           | groups table                  | -                     |

## Performance Characteristics

- **Node creation**: O(1) - instant pending node creation
- **Edge creation**: O(1) - no blocking on enrichment
- **Enrichment**: Async via Oban (5 concurrent workers)
- **Cleanup**: Runs every 30 minutes, O(n) scan
- **Memory**: Minimal - pending nodes only store metadata

## Benefits

1. **No Blocking**: Edge creation never blocks on data fetch
2. **Automatic Enrichment**: Real data arrives asynchronously
3. **Clean Graph**: Orphaned pending nodes auto-cleanup
4. **Retry Logic**: Oban provides automatic retry on failure
5. **Observability**: Pending node count in stats, dedicated queue
6. **Extensible**: Easy to add new enrichment sources

## Testing

```elixir
# Create edge to non-existent node
KnowledgeGraph.add_edge(
  {:device, "known-device"},
  {:process, "unknown-process"},
  :runs_on
)

# Immediately check - should be pending
{:ok, node} = KnowledgeGraph.get_node(:process, "unknown-process")
assert node.status == :pending

# Wait for job to complete
:timer.sleep(1000)

# Should now be enriched (or still pending if no data found)
{:ok, node} = KnowledgeGraph.get_node(:process, "unknown-process")
```

## Monitoring

Monitor pending node health:

```elixir
# Check pending count
stats = KnowledgeGraph.stats()
if stats.pending_nodes > 1000 do
  Logger.warning("High pending node count: #{stats.pending_nodes}")
end

# Check Oban queue
Oban.check_queue(:graph_enrichment)
```

## Future Enhancements

1. **Batch Enrichment**: Group multiple pending nodes by type for bulk fetching
2. **Priority Enrichment**: High-criticality nodes enriched first
3. **External APIs**: WHOIS, passive DNS, certificate transparency logs
4. **Cache Integration**: Store enriched data in Redis for faster lookup
5. **Metrics**: Prometheus metrics for enrichment success rate
