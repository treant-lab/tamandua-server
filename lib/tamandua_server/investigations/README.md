# Investigation Graph System

Interactive graph visualization for analyzing security incidents through process, file, network, registry, and user relationships.

## Overview

The Investigation Graph system provides a powerful visual interface for understanding attack chains and lateral movement by constructing directed graphs from telemetry events and alerts.

## Features

### Graph Construction

- **Process Execution Trees**: Parent-child process relationships showing execution chains
- **File Operations**: Read, write, create, delete, rename, execute operations
- **Network Connections**: TCP/UDP connections with IP, port, and protocol details
- **DNS Queries**: Domain resolution with answer records
- **Registry Modifications**: Windows registry key/value changes
- **Module Loads**: DLL/shared library loading
- **User Context**: User accounts executing processes

### Interactive Features

- **Zoom & Pan**: Navigate large graphs with mouse/touch controls
- **Timeline Slider**: Replay attack progression over time
- **Node Selection**: Click nodes/edges to view detailed metadata
- **Filtering**: Filter by node type, suspicious only, MITRE techniques
- **Export**: PNG, SVG, and GraphML formats for external analysis
- **Fullscreen Mode**: Maximize screen space for complex investigations

### Performance Optimizations

- **Node Limits**: Configurable max nodes (default: 1000)
- **Event Sampling**: Intelligent sampling for large datasets
- **Deduplication**: Automatic node/edge deduplication
- **Lazy Loading**: On-demand node expansion

## Architecture

### Backend Components

#### GraphBuilder Module

```elixir
TamanduaServer.Investigations.GraphBuilder
```

Core graph construction engine that:
- Queries telemetry events from PostgreSQL and ClickHouse
- Builds nodes and edges from event payloads
- Applies filters and time windows
- Exports to GraphML format

**Key Functions:**

```elixir
# Build from alert(s)
GraphBuilder.build_from_alert(alert_id, opts)
GraphBuilder.build_from_alert([alert_id1, alert_id2], opts)

# Build from event range
GraphBuilder.build_from_events(
  agent_id: "...",
  start_time: ~U[2024-01-01 00:00:00Z],
  end_time: ~U[2024-01-01 23:59:59Z]
)

# Filter by time
GraphBuilder.filter_by_time(graph, start_time, end_time)

# Export
GraphBuilder.export_graphml(graph)
```

**Options:**

- `:depth` - How many hops from alert to include (default: 2)
- `:time_window` - Time window in minutes before/after alert (default: 60)
- `:include_benign` - Include non-suspicious events (default: false)
- `:max_nodes` - Maximum nodes to include (default: 1000)

#### InvestigationGraphLive

```elixir
TamanduaServerWeb.InvestigationGraphLive
```

Phoenix LiveView providing real-time interactivity:
- Manages graph state
- Handles user interactions (zoom, filter, select)
- Receives PubSub updates for new alerts/events
- Serializes graph data for JavaScript

### Frontend Components

#### InvestigationGraphViz (JavaScript)

D3.js-based force-directed graph renderer:
- SVG rendering with zoom/pan
- Force simulation for automatic layout
- Node/edge styling by type
- Export to PNG/SVG

**Node Colors:**

| Type     | Color  |
|----------|--------|
| Process  | Blue   |
| File     | Green  |
| Network  | Purple |
| DNS      | Yellow |
| Registry | Red    |
| User     | Cyan   |
| Module   | Orange |
| Alert    | Pink   |

**Edge Types:**

| Type         | Description                  |
|--------------|------------------------------|
| spawns       | Process parent-child         |
| executes     | User/process execution       |
| creates      | File creation                |
| writes       | File write                   |
| reads        | File read                    |
| deletes      | File deletion                |
| modifies     | Registry modification        |
| connects_to  | Network connection           |
| resolves     | DNS resolution               |
| loads        | Module/DLL load              |

## Usage

### From Alert Detail Page

Add a link to the alert detail page:

```heex
<.link navigate={~p"/investigation_graph?alert_id=#{@alert.id}"}>
  <button class="btn btn-primary">
    View Investigation Graph
  </button>
</.link>
```

### From Timeline View

Build graph for a specific time range:

```heex
<.link navigate={
  ~p"/investigation_graph?agent_id=#{@agent.id}&start_time=#{@start_time}&end_time=#{@end_time}"
}>
  <button class="btn btn-secondary">
    Visualize Timeline as Graph
  </button>
</.link>
```

### Multiple Alerts

Combine multiple alerts into one graph:

```heex
<.link navigate={
  ~p"/investigation_graph?alert_ids[]=#{@alert1.id}&alert_ids[]=#{@alert2.id}"
}>
  <button class="btn btn-secondary">
    Compare Alerts
  </button>
</.link>
```

## Graph Data Structure

### Node Schema

```elixir
%{
  id: "process_agent123_1234",           # Unique identifier
  type: :process,                        # Node type atom
  label: "malware.exe",                  # Display label
  timestamp: ~U[2024-01-01 12:00:00Z],   # Event timestamp
  suspicious: true,                      # Suspicious flag
  mitre_techniques: ["T1055", "T1059"],  # MITRE ATT&CK techniques
  metadata: %{                           # Type-specific metadata
    pid: 1234,
    path: "C:\\malware.exe",
    command_line: "malware.exe --evil",
    user: "SYSTEM",
    is_elevated: true
  }
}
```

### Edge Schema

```elixir
%{
  source: "process_agent123_1234",       # Source node ID
  target: "file_hash123",                # Target node ID
  type: :writes,                         # Edge type atom
  label: "writes",                       # Display label
  timestamp: ~U[2024-01-01 12:00:01Z],   # Event timestamp
  metadata: %{                           # Additional context
    action: "write",
    bytes: 1024
  }
}
```

### Timeline Schema

```elixir
%{
  start: ~U[2024-01-01 11:00:00Z],       # Earliest event
  end: ~U[2024-01-01 13:00:00Z],         # Latest event
  buckets: [                             # Time histogram
    %{
      start: ~U[2024-01-01 11:00:00Z],
      end: ~U[2024-01-01 11:06:00Z],
      count: 15                          # Events in bucket
    },
    ...
  ]
}
```

## Integration Points

### Alert Correlation

Link to existing `TamanduaServer.Alerts.GraphBuilder`:

```elixir
# In your alert detail page
def handle_event("view_graph", %{"alert_id" => alert_id}, socket) do
  {:noreply, push_navigate(socket, to: ~p"/investigation_graph?alert_id=#{alert_id}")}
end
```

### Timeline View

Integrate with existing timeline:

```elixir
# In TimelineLive
def handle_event("visualize_graph", _params, socket) do
  start_time = socket.assigns.filters.start_time
  end_time = socket.assigns.filters.end_time
  agent_id = socket.assigns.agent_id

  path = ~p"/investigation_graph?agent_id=#{agent_id}&start_time=#{start_time}&end_time=#{end_time}"
  {:noreply, push_navigate(socket, to: path)}
end
```

### Real-time Updates

Subscribe to PubSub for live updates:

```elixir
# Already implemented in InvestigationGraphLive
PubSub.subscribe(TamanduaServer.PubSub, "alerts")
PubSub.subscribe(TamanduaServer.PubSub, "telemetry")

# Broadcast from detection engine
PubSub.broadcast(
  TamanduaServer.PubSub,
  "alerts",
  {:alert_updated, alert.id}
)
```

## Examples

### Basic Investigation

```elixir
# Build graph from alert
alert_id = "550e8400-e29b-41d4-a716-446655440000"
graph = GraphBuilder.build_from_alert(alert_id)

# Inspect nodes
Enum.each(graph.nodes, fn node ->
  IO.inspect({node.type, node.label, node.suspicious})
end)

# Find suspicious network connections
suspicious_network = Enum.filter(graph.nodes, fn node ->
  node.type == :network && node.suspicious
end)
```

### Advanced Filtering

```elixir
# Build with custom options
graph = GraphBuilder.build_from_alert(
  alert_id,
  depth: 3,                  # 3 hops from alert
  time_window: 120,          # 2 hours before/after
  include_benign: true,      # Include all events
  max_nodes: 2000            # Higher limit
)

# Filter to specific time range
filtered = GraphBuilder.filter_by_time(
  graph,
  ~U[2024-01-01 12:00:00Z],
  ~U[2024-01-01 12:30:00Z]
)
```

### Export for Analysis

```elixir
# Export to GraphML for Gephi/Cytoscape
graphml = GraphBuilder.export_graphml(graph)
File.write!("investigation.graphml", graphml)
```

## Performance Considerations

### Node Limits

The default limit of 1000 nodes balances visualization performance with completeness. For larger investigations:

1. Use `include_benign: false` to focus on suspicious activity
2. Reduce `time_window` to narrow the scope
3. Reduce `depth` to limit graph expansion
4. Export to GraphML for analysis in desktop tools

### ClickHouse Optimization

For agents with ClickHouse enabled, event queries are much faster:

```elixir
# Automatically uses ClickHouse when available
events = ClickHouseQuery.timeline(agent_id, start_time, end_time, limit: 1000)
```

### Caching

Consider caching graph results for frequently accessed alerts:

```elixir
def get_graph_cached(alert_id) do
  cache_key = "investigation_graph:#{alert_id}"

  case Cachex.get(:graph_cache, cache_key) do
    {:ok, nil} ->
      graph = GraphBuilder.build_from_alert(alert_id)
      Cachex.put(:graph_cache, cache_key, graph, ttl: :timer.minutes(15))
      graph

    {:ok, graph} ->
      graph
  end
end
```

## Testing

### Unit Tests

```bash
# Test graph builder
mix test test/tamandua_server/investigations/graph_builder_test.exs

# Test LiveView
mix test test/tamandua_server_web/live/investigation_graph_live_test.exs
```

### Manual Testing

1. Create test data:

```elixir
# In IEx
Mix.install([{:faker, "~> 0.17"}])

agent = TamanduaServer.Agents.Agent.create(%{
  agent_id: "test-agent",
  hostname: "test-host",
  ip_address: "192.168.1.100",
  os_type: "Windows"
})

# Generate synthetic attack chain
GraphBuilder.generate_test_attack(agent.id)
```

2. Navigate to `/investigation_graph?agent_id=<agent_id>`

3. Test interactions:
   - Zoom/pan
   - Node selection
   - Timeline slider
   - Filters
   - Export

## Troubleshooting

### Graph is Empty

**Symptom:** 0 nodes, 0 edges displayed

**Solutions:**
- Verify alert has `event_ids` populated
- Check events exist in database
- Ensure agent_id matches
- Increase `time_window` if events are outside default range

### Performance Issues

**Symptom:** Slow rendering, browser lag

**Solutions:**
- Reduce `max_nodes` limit
- Enable `suspicious_only` filter
- Use GraphML export for large graphs
- Check browser console for JavaScript errors

### Missing Relationships

**Symptom:** Nodes exist but edges are missing

**Solutions:**
- Verify event payloads include PIDs for linking
- Check process parent_pid fields
- Ensure events are within time window
- Review edge construction logic for event type

### Export Fails

**Symptom:** PNG/SVG export doesn't work

**Solutions:**
- Check browser console for errors
- Verify D3.js is loaded correctly
- Test with smaller graph first
- Try GraphML export as alternative

## Future Enhancements

- [ ] 3D graph visualization for complex attacks
- [ ] Graph diffing to compare incidents
- [ ] Automated attack pattern recognition
- [ ] Graph clustering for large investigations
- [ ] Integration with threat intelligence (IP reputation, hash lookups)
- [ ] Collaborative annotations on graph nodes
- [ ] Graph-based hunting queries
- [ ] Attack chain reconstruction from partial data

## References

- [D3.js Force Layout](https://d3js.org/d3-force)
- [GraphML Specification](http://graphml.graphdrawing.org/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Gephi](https://gephi.org/) - Graph analysis tool
- [Cytoscape](https://cytoscape.org/) - Network visualization platform
