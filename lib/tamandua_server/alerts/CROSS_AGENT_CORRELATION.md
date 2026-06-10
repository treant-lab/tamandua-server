# Cross-Agent Alert Correlation

## Overview

The Cross-Agent Alert Correlation system detects coordinated attacks across multiple endpoints by analyzing temporal patterns, shared IOCs, MITRE techniques, network topology, and behavioral patterns. It automatically groups related alerts into attack campaigns and builds network graphs to visualize lateral movement.

## Features

### 1. Temporal Pattern Matching

Finds alerts across all agents within configurable time windows (default 30 minutes):

```elixir
# Find alerts related to a specific alert
{:ok, related} = Alerts.find_related_alerts(alert, time_window_minutes: 60)
# Returns: [{related_alert, similarity_score}, ...]
```

**How it works:**
- Queries alerts within time window from target alert's timestamp
- Filters by organization
- Calculates multi-factor similarity scores
- Returns alerts above similarity threshold (default 0.7)

### 2. Probabilistic Alert Grouping

Calculates weighted similarity scores based on multiple factors:

#### Shared MITRE Techniques (35% weight)
- Weighted by technique rarity
- Rare techniques (T1055, T1003) have higher weight
- Common techniques (T1059, T1071) have lower weight

#### Shared IOCs (25% weight)
- File hashes (SHA256)
- IP addresses
- Domain names
- DNS queries
- Process hashes

#### Network Proximity (15% weight)
- Same agent: 1.0
- Same /24 subnet: 0.7
- Different subnets: 0.3

#### Temporal Proximity (10% weight)
- < 5 minutes: 1.0
- < 15 minutes: 0.8
- < 30 minutes: 0.6
- < 1 hour: 0.4
- Older: 0.2

#### Entity Similarity (15% weight)
- Same user: 1.0
- Same process name: 0.8
- Same file path: 0.9

### 3. Attack Chain Detection

Detects common attack patterns by matching tactic sequences:

```elixir
{:ok, chains} = Alerts.detect_attack_chains([alert1, alert2, alert3])
# Returns patterns with confidence scores
```

**Supported patterns:**
- **Lateral Movement**: `credential_access → lateral_movement → execution`
- **Ransomware**: `initial_access → execution → impact`
- **Exfiltration**: `collection → exfiltration`
- **Full Kill Chain**: All 11 MITRE tactics in sequence
- **Credential Theft**: `credential_access → collection`
- **Persistence + Escalation**: `persistence → privilege_escalation`
- **Reconnaissance**: `reconnaissance → discovery`

### 4. Network Graph Analysis

Builds visual network topology from alert relationships:

```elixir
graph = Alerts.build_network_graph([alert_id1, alert_id2, alert_id3])
# Returns:
# %{
#   "nodes" => [%{"id" => "agent-1", "hostname" => "server1", "ip" => "192.168.1.10"}],
#   "edges" => [%{"source" => "agent-1", "target" => "agent-2", "type" => "network"}]
# }
```

**Graph features:**
- Nodes represent agents/endpoints
- Edges represent network connections (derived from alert evidence)
- Visualizes lateral movement paths
- Identifies pivot points

### 5. Adaptive Deduplication Windows

Per-technique deduplication windows based on noise level:

```elixir
{:ok, window_seconds} = CrossAgentCorrelator.get_dedup_window("T1055", org_id)
```

**Default windows:**
- Low noise techniques: Longer windows (10+ minutes)
- Normal techniques: 5 minutes (default)
- High noise techniques: Shorter windows (1-2 minutes)

Configurable per organization and per technique via `dedup_windows` table.

### 6. Attack Campaign Management

Automatically creates and manages attack campaigns:

```elixir
# List campaigns
campaigns = Alerts.list_attack_campaigns(organization_id: org_id, status: "active")

# Get campaign details
{:ok, campaign} = Alerts.get_attack_campaign(campaign_id)

# Manually add alert to campaign
{:ok, _} = Alerts.add_alert_to_campaign(campaign_id, alert_id, role: "lateral")

# Campaign statistics
stats = Alerts.get_campaign_stats(organization_id: org_id, days: 30)
```

**Campaign attributes:**
- Name (auto-generated or manual)
- Severity (highest alert severity in campaign)
- Status (active, contained, resolved)
- Attack pattern (lateral_movement, ransomware, etc.)
- Agent count (unique endpoints affected)
- Alert count
- Time bounds (start, end, last activity)
- MITRE tactics/techniques (aggregated)
- Network graph
- Confidence score

## Architecture

### Database Schema

#### `alert_correlations`
Stores relationships between alerts:
- `alert_id`, `related_alert_id`: The correlated alerts
- `correlation_type`: temporal, ioc, technique, network, user, pattern
- `confidence`: 0.0-1.0 similarity score
- `metadata`: JSON with shared techniques, IOCs, time delta, etc.

#### `attack_campaigns`
Groups correlated alerts:
- `name`, `description`: Campaign details
- `severity`, `status`: Current state
- `agent_count`, `alert_count`: Statistics
- `start_time`, `end_time`, `last_activity`: Timeline
- `mitre_tactics`, `mitre_techniques`: Aggregated TTPs
- `attack_pattern`: Detected pattern type
- `network_graph`: JSON graph structure
- `confidence_score`: Detection confidence

#### `campaign_alerts`
Many-to-many join table:
- `campaign_id`, `alert_id`: Relationship
- `role`: Alert's role in attack chain (initial, pivot, lateral, impact)
- `sequence_order`: Position in attack sequence

#### `correlation_cache`
Pre-computed correlation patterns:
- `cache_key`: Unique identifier
- `cache_data`: JSON correlation data
- `expires_at`: Cache expiration

#### `dedup_windows`
Per-technique deduplication config:
- `mitre_technique`: Technique ID
- `window_seconds`: Dedup window
- `noise_level`: low, normal, high

### GenServer Architecture

**CrossAgentCorrelator** runs as a supervised GenServer:

1. **Startup**: Initializes state, schedules periodic correlation
2. **Alert Creation Hook**: Each new alert triggers async correlation via `correlate_alert/1`
3. **Periodic Processing**: Runs every minute to correlate recent alerts
4. **Campaign Detection**: Automatically creates campaigns when 2+ correlated alerts detected

**Process flow:**
```
Alert Created
    ↓
maybe_schedule_correlation (async spawn)
    ↓
CrossAgentCorrelator.correlate_alert/1 (cast)
    ↓
do_correlate_alert/1 (background process)
    ↓
    ├─→ find_related_alerts (similarity scoring)
    ├─→ create_correlation records
    └─→ maybe_add_to_campaign
        ├─→ find_existing_campaign
        └─→ create_campaign_from_alerts OR add_alert_to_campaign
```

## API Reference

### Public Functions (in `TamanduaServer.Alerts`)

```elixir
# Find related alerts
find_related_alerts(alert, opts \\ [])

# Detect attack chains
detect_attack_chains(alerts)

# Build network graph
build_network_graph(alert_ids)

# Get alert correlations
get_alert_correlations(alert_id)

# List campaigns
list_attack_campaigns(opts \\ [])

# Get campaign
get_attack_campaign(campaign_id)

# Create campaign
create_attack_campaign(attrs)

# Update campaign
update_attack_campaign(campaign, attrs)

# Add alert to campaign
add_alert_to_campaign(campaign_id, alert_id, opts \\ [])

# Remove alert from campaign
remove_alert_from_campaign(campaign_id, alert_id)

# Campaign statistics
get_campaign_stats(opts \\ [])
```

### CrossAgentCorrelator Functions

```elixir
# Find related alerts (with options)
CrossAgentCorrelator.find_related_alerts(alert, [
  time_window_minutes: 60,
  threshold: 0.7,
  organization_id: org_id
])

# Correlate single alert (async)
CrossAgentCorrelator.correlate_alert(alert)

# Run full correlation analysis
CrossAgentCorrelator.run_correlation(organization_id: org_id)

# Detect attack chains
CrossAgentCorrelator.detect_attack_chains(alerts)

# Build network graph
CrossAgentCorrelator.build_network_graph(alert_ids)

# Get dedup window for technique
CrossAgentCorrelator.get_dedup_window(technique, org_id)
```

## Configuration

### Application Config

```elixir
# config/config.exs
config :tamandua_server,
  # Default time window for correlation (minutes)
  correlation_time_window: 30,

  # Minimum similarity threshold for correlation
  correlation_threshold: 0.7,

  # Correlation interval (milliseconds)
  correlation_interval: 60_000,

  # Minimum alerts to create campaign
  min_alerts_for_campaign: 2
```

### Database Config

```bash
# Run migration to create tables
mix ecto.migrate

# Configure per-technique dedup windows
iex> alias TamanduaServer.Repo
iex> Repo.insert!(%{
  mitre_technique: "T1055",
  window_seconds: 600,  # 10 minutes for rare technique
  noise_level: "low",
  organization_id: org_id
})
```

## Usage Examples

### Example 1: Detect Lateral Movement

```elixir
# Simulated lateral movement attack
{:ok, alert1} = Alerts.create_alert(%{
  title: "Credential Dumping via LSASS",
  severity: "critical",
  agent_id: "workstation-1",
  mitre_techniques: ["T1003.001"],
  mitre_tactics: ["credential-access"],
  evidence: %{
    process: %{name: "mimikatz.exe", user: "admin"}
  }
})

{:ok, alert2} = Alerts.create_alert(%{
  title: "RDP Lateral Movement",
  severity: "high",
  agent_id: "server-1",
  mitre_techniques: ["T1021.001"],
  mitre_tactics: ["lateral-movement"],
  evidence: %{
    network: %{remote_ip: "192.168.1.50", remote_port: 3389}
  }
})

{:ok, alert3} = Alerts.create_alert(%{
  title: "Suspicious PowerShell Execution",
  severity: "high",
  agent_id: "server-1",
  mitre_techniques: ["T1059.001"],
  mitre_tactics: ["execution"]
})

# Wait for correlation
Process.sleep(500)

# Check campaigns
campaigns = Alerts.list_attack_campaigns(status: "active")
campaign = List.first(campaigns)

# campaign.name => "Lateral movement - credential-access - 2025-02-20"
# campaign.attack_pattern => "lateral_movement"
# campaign.alert_count => 3
# campaign.agent_count => 2
```

### Example 2: Manual Investigation

```elixir
# Start from a suspicious alert
alert = Alerts.get_alert!(alert_id)

# Find all related alerts
{:ok, related} = Alerts.find_related_alerts(alert, time_window_minutes: 120)

# Extract all alert IDs
all_alerts = [alert | Enum.map(related, fn {a, _} -> a end)]

# Detect attack chains
{:ok, chains} = Alerts.detect_attack_chains(all_alerts)

# Build network graph
alert_ids = Enum.map(all_alerts, & &1.id)
graph = Alerts.build_network_graph(alert_ids)

# Create investigation
{:ok, campaign} = Alerts.create_attack_campaign(%{
  name: "Manual Investigation - #{Date.to_iso8601(Date.utc_today())}",
  description: "Investigating suspicious activity on server cluster",
  severity: "high",
  organization_id: org_id,
  attack_pattern: List.first(chains).pattern
})

# Add alerts to campaign
Enum.each(all_alerts, fn alert ->
  Alerts.add_alert_to_campaign(campaign.id, alert.id)
end)
```

### Example 3: Query Correlations

```elixir
# Get all correlations for an alert
correlations = Alerts.get_alert_correlations(alert_id)

Enum.each(correlations, fn corr ->
  IO.puts("Correlation: #{corr.correlation_type}")
  IO.puts("  Confidence: #{corr.confidence}")
  IO.puts("  Shared techniques: #{inspect(corr.metadata["shared_techniques"])}")
  IO.puts("  Time delta: #{corr.metadata["time_delta_seconds"]}s")
end)
```

## Performance Considerations

### Indexes

All critical query paths are indexed:
- `alert_correlations`: alert_id, related_alert_id, correlation_type, confidence
- `attack_campaigns`: organization_id, status, severity, start_time, attack_pattern
- `campaign_alerts`: campaign_id, alert_id
- `alerts`: campaign_id (new index)

### Optimization Strategies

1. **Async Processing**: Correlation never blocks alert creation
2. **Time Window Limits**: Default 30 minutes, queries only recent data
3. **Result Limits**: Maximum 100 related alerts per query
4. **Caching**: Pre-computed patterns in `correlation_cache` table
5. **Batch Processing**: Periodic correlation runs every minute
6. **Similarity Threshold**: Filters low-confidence matches early

### Scaling

For high-volume environments:

1. **Increase correlation interval**:
   ```elixir
   config :tamandua_server, correlation_interval: 300_000  # 5 minutes
   ```

2. **Reduce time window**:
   ```elixir
   Alerts.find_related_alerts(alert, time_window_minutes: 15)
   ```

3. **Increase similarity threshold**:
   ```elixir
   Alerts.find_related_alerts(alert, threshold: 0.8)
   ```

4. **Partition by organization**: Correlations are already org-scoped

## Testing

Run the comprehensive test suite:

```bash
mix test test/tamandua_server/alerts/cross_agent_correlator_test.exs
```

Test coverage includes:
- Temporal pattern matching
- Probabilistic grouping (techniques, IOCs, network proximity)
- Attack chain detection (lateral movement, ransomware)
- Network graph building
- Campaign creation and management
- Correlation metadata storage

## Troubleshooting

### No correlations detected

Check:
1. Alerts have MITRE techniques/tactics populated
2. Alerts are within time window (default 30 minutes)
3. Similarity threshold isn't too high
4. Alerts belong to same organization
5. CrossAgentCorrelator GenServer is running

```elixir
# Check correlator status
Process.whereis(TamanduaServer.Alerts.CrossAgentCorrelator)

# Manually trigger correlation
TamanduaServer.Alerts.CrossAgentCorrelator.run_correlation()
```

### Campaigns not auto-created

Check:
1. At least 2 related alerts with similarity > 0.7
2. Wait ~1 minute for periodic correlation run
3. Check logs for correlation errors

```bash
# View correlator logs
grep "CrossAgentCorrelator" log/dev.log
```

### Performance issues

Check:
1. Database query performance (EXPLAIN ANALYZE)
2. Alert volume (may need to increase correlation interval)
3. Time window size (reduce if too large)

```elixir
# Check alert count
TamanduaServer.Repo.aggregate(TamanduaServer.Alerts.Alert, :count)

# Check correlation count
TamanduaServer.Repo.aggregate(TamanduaServer.Alerts.AlertCorrelation, :count)
```

## Future Enhancements

Planned improvements:
- Machine learning-based similarity scoring
- Behavioral anomaly detection
- Cross-organization threat sharing (anonymized)
- Real-time campaign updates via PubSub
- Campaign threat scores
- Automated campaign containment actions
- Integration with SOAR playbooks
