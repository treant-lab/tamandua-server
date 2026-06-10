# Agent Health System - Module Overview

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Agent Health System                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │HealthScorer  │  │HealthMonitor │  │HealthPredictor│      │
│  │              │  │  (GenServer) │  │              │       │
│  │ - Calculate  │  │              │  │ - Predict    │       │
│  │   scores     │  │ - Track      │  │   degradation│       │
│  │ - Categorize │  │   agents     │  │ - Resource   │       │
│  │ - Identify   │  │ - Heartbeats │  │   exhaustion │       │
│  │   issues     │  │ - Broadcast  │  │ - Patterns   │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            ▼                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │HealthHistory │  │HealthAlert   │  │HealthAnalyzer│      │
│  │              │  │              │  │              │       │
│  │ - Store      │  │ - Create     │  │ - Anomaly    │       │
│  │   snapshots  │  │   alerts     │  │   detection  │       │
│  │ - Trends     │  │ - Acknowledge│  │ - Fleet      │       │
│  │ - Query      │  │ - Resolve    │  │   comparison │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            ▼                                 │
│                    ┌──────────────┐                          │
│                    │HealthMetrics │                          │
│                    │              │                          │
│                    │ - Store      │                          │
│                    │ - Query      │                          │
│                    │ - Aggregate  │                          │
│                    └──────────────┘                          │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Modules

### Core Scoring

#### `TamanduaServer.Agents.HealthScorer`

**Purpose**: Calculate comprehensive 0-100 health scores based on 7 components.

**Key Functions**:
- `calculate_health_score(agent_id, opts)` - Main scoring function
- `score_uptime(agent, metrics, window)` - Uptime component (20pts)
- `score_cpu_usage(metrics)` - CPU component (15pts)
- `score_memory_usage(metrics)` - Memory component (15pts)
- `score_event_throughput(metrics, baseline)` - Throughput component (15pts)
- `score_error_rate(latest, all)` - Error rate component (15pts)
- `score_detection_coverage(metrics)` - Coverage component (10pts)
- `score_config_compliance(agent)` - Compliance component (10pts)
- `categorize_health(score)` - Convert score to category

**Returns**: Health score with breakdown, category, issues, and timestamp

### Monitoring

#### `TamanduaServer.Agents.HealthMonitor`

**Purpose**: GenServer that continuously monitors agent health.

**Responsibilities**:
- Track agent heartbeats
- Calculate health scores periodically
- Detect stale/offline agents
- Broadcast health updates via PubSub
- Maintain in-memory health state

**Key Functions**:
- `record_heartbeat(agent_id, data)` - Record agent heartbeat
- `get_agent_health(agent_id)` - Get current health status
- `get_all_health(filters)` - Get fleet health with filters
- `get_unhealthy_agents()` - Get agents with issues
- `get_stats()` - Get aggregated fleet statistics

**State**: Map of agent_id => AgentHealth structs

### Prediction

#### `TamanduaServer.Agents.HealthPredictor`

**Purpose**: Predict health degradation and resource exhaustion.

**Algorithms**:
- Linear regression for trend analysis
- Exponential smoothing for short-term predictions
- Pattern recognition for recurring issues
- Correlation analysis between metrics

**Key Functions**:
- `predict_health_degradation(agent_id)` - Full prediction analysis
- `predict_resource_exhaustion(agent_id)` - CPU/memory/disk warnings
- `detect_health_patterns(agent_id)` - Pattern recognition
- `time_until_maintenance_required(agent_id)` - Maintenance scheduling

**Returns**: Predictions with confidence levels, warnings, and recommendations

### Analysis

#### `TamanduaServer.Agents.HealthAnalyzer`

**Purpose**: Anomaly detection and statistical analysis.

**Detection Methods**:
- Z-score outlier detection
- IQR (Interquartile Range) analysis
- Rate of change monitoring
- Moving average analysis
- Fleet deviation comparison

**Key Functions**:
- `analyze_metrics(agent_id)` - Comprehensive anomaly analysis
- `compare_to_fleet(agent_id)` - Fleet-wide comparison
- `detect_memory_leak(agent_id)` - Memory leak detection
- `calculate_health_trend(agent_id, window)` - Trend analysis

**Returns**: List of detected anomalies with severity and recommendations

### Data Storage

#### `TamanduaServer.Agents.HealthHistory`

**Purpose**: Store and query health score history.

**Schema**: `agent_health_history` table

**Key Functions**:
- `record_snapshot(agent_id, health_data)` - Store health snapshot
- `get_history(agent_id, hours)` - Query historical scores
- `get_trend(agent_id, hours)` - Calculate trend direction
- `get_agents_by_category(category)` - Filter by health category
- `cleanup_old_records(days)` - Retention policy

#### `TamanduaServer.Agents.HealthAlert`

**Purpose**: Create and manage health alerts.

**Schema**: `agent_health_alerts` table

**Alert Types**:
- `score_drop` - Sudden health degradation
- `resource_exhaustion` - Resource predicted to run out
- `pattern_detected` - Recurring issue pattern
- `maintenance_required` - Scheduled maintenance needed

**Key Functions**:
- `create_alert(agent_id, attrs)` - Create new alert
- `acknowledge(alert_id, user_id)` - Acknowledge alert
- `resolve(alert_id, notes)` - Mark alert as resolved
- `get_unresolved(agent_id)` - Get active alerts
- `get_critical_unresolved()` - Get critical alerts
- `cleanup_old_alerts(days)` - Retention policy

#### `TamanduaServer.Agents.HealthMetrics`

**Purpose**: Store detailed agent telemetry metrics.

**Schema**: `agent_health_metrics` table

**Metrics Tracked**:
- CPU: Usage, per-core, load average
- Memory: Usage, total, available, swap
- Disk: Usage, I/O rates, IOPS
- Network: RX/TX bytes/packets, errors, latency
- Events: Processing rate, latency, dropped events
- Detection: YARA/Sigma/ML metrics
- Errors: Count, rate, breakdown by component

**Key Functions**:
- `store_metrics(agent_id, telemetry)` - Store metrics
- `get_latest(agent_id)` - Get most recent metrics
- `get_range(agent_id, start, end)` - Query time range
- `aggregate_metrics(agent_id, window)` - Statistical aggregation
- `fleet_stats(window)` - Fleet-wide statistics
- `cleanup_old_metrics(days)` - Retention policy

## Database Tables

### agent_health_history
- Periodic health score snapshots (every 15 minutes)
- Breakdown of component scores
- Issues list
- Indexed by agent_id, recorded_at, category

### agent_health_predictions
- Predictive maintenance analysis results
- Resource exhaustion warnings
- Maintenance recommendations
- Indexed by agent_id, predicted_at, trend

### agent_health_alerts
- Health-related alerts and incidents
- Acknowledgment and resolution tracking
- Alert history
- Indexed by agent_id, triggered_at, severity, resolved

### fleet_health_summary
- Hourly aggregation of fleet metrics
- Category distribution
- Average scores by component
- Indexed by hour_bucket

### agent_baselines
- Baseline metrics per agent (24h average)
- Statistical bounds for anomaly detection
- Calculation metadata
- Indexed by agent_id, calculated_at

### agent_health_metrics
- Detailed telemetry metrics
- All system, network, and detection metrics
- Source of truth for health calculations
- Indexed by agent_id, timestamp

## Data Flow

### 1. Metric Collection
```
Agent → WebSocket → Phoenix Channel → HealthMetrics.store_metrics()
```

### 2. Heartbeat Processing
```
Agent → HealthMonitor.record_heartbeat() → Update in-memory state
```

### 3. Health Calculation
```
(Periodic) → HealthScorer.calculate_health_score()
           → HealthHistory.record_snapshot()
           → PubSub broadcast
```

### 4. Anomaly Detection
```
(Periodic) → HealthAnalyzer.analyze_metrics()
           → If anomaly → HealthAlert.create_alert()
           → PubSub broadcast
```

### 5. Predictive Analysis
```
(Periodic) → HealthPredictor.predict_health_degradation()
           → If warning → HealthAlert.create_alert()
           → PubSub broadcast
```

## PubSub Topics

- `agent_health` - All health updates
- `agent_health:#{agent_id}` - Agent-specific updates
- `agent_health_alerts` - All health alerts
- `agent:#{agent_id}` - Agent-specific alerts

## Message Types

- `{:health_update, agent_id, health_data}` - Health score updated
- `{:stats_update, fleet_stats}` - Fleet statistics updated
- `{:health_alert, alert}` - New health alert created
- `{:agent_critical, health_data}` - Agent in critical state

## Configuration

```elixir
config :tamandua_server, :health_monitoring,
  health_check_interval: 60_000,      # 1 minute
  heartbeat_timeout: 300,             # 5 minutes
  stale_agent_threshold: 900,         # 15 minutes
  cpu_warning_threshold: 80,
  cpu_critical_threshold: 95,
  memory_warning_threshold: 85,
  memory_critical_threshold: 95,
  disk_warning_threshold: 80,
  disk_critical_threshold: 90,
  z_score_threshold: 3.0,
  iqr_multiplier: 1.5,
  rate_of_change_threshold: 50.0,
  memory_leak_detection_window: 60,
  memory_growth_threshold: 5.0,
  history_retention_days: 30,
  alert_retention_days: 90
```

## Usage Examples

### Calculate Health Score

```elixir
alias TamanduaServer.Agents.HealthScorer

{:ok, health} = HealthScorer.calculate_health_score(agent_id)

IO.inspect(health.score)                    # 85
IO.inspect(health.category)                 # :good
IO.inspect(health.breakdown.cpu)            # 15
IO.inspect(health.issues)                   # [%{component: :memory, ...}]
```

### Get Predictions

```elixir
alias TamanduaServer.Agents.HealthPredictor

{:ok, prediction} = HealthPredictor.predict_health_degradation(agent_id)

IO.inspect(prediction.predicted_next_hour)  # 83
IO.inspect(prediction.trend)                # :degrading
IO.inspect(prediction.resource_warnings)    # [%{resource: :memory, ...}]
```

### Query Health History

```elixir
alias TamanduaServer.Agents.HealthHistory

# Last 7 days
history = HealthHistory.get_history(agent_id, 168)

# Get trend
trend = HealthHistory.get_trend(agent_id, 24)
# Returns: :improving | :stable | :degrading
```

### Create Alert

```elixir
alias TamanduaServer.Agents.HealthAlert

HealthAlert.create_alert(agent_id, %{
  alert_type: "score_drop",
  severity: "critical",
  message: "Health score dropped 25 points",
  details: %{drop: 25, time_window: "30 minutes"}
})
```

### Subscribe to Updates

```elixir
# In GenServer or LiveView
Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agent_health")

def handle_info({:health_update, agent_id, health}, state) do
  # Handle update
  {:noreply, state}
end
```

## Testing

```bash
# Run all health tests
mix test test/tamandua_server/agents/health_*

# Run specific module tests
mix test test/tamandua_server/agents/health_scorer_test.exs
mix test test/tamandua_server/agents/health_predictor_test.exs
```

## Maintenance

### Scheduled Tasks

```elixir
# Clean up old records (run daily)
HealthHistory.cleanup_old_records(30)        # Keep 30 days
HealthAlert.cleanup_old_alerts(90)           # Keep 90 days
HealthMetrics.cleanup_old_metrics(30)        # Keep 30 days

# Recalculate baselines (run daily)
BaselineCalculator.recalculate_all_baselines()
```

### Manual Operations

```elixir
# Force health check for agent
HealthMonitor.check_agent_health(agent_id)

# Get fleet statistics
{:ok, stats} = HealthMonitor.get_stats()

# Get unhealthy agents
{:ok, unhealthy} = HealthMonitor.get_unhealthy_agents()
```

## Documentation

- **Full Guide**: `/AGENT_HEALTH_SCORING.md`
- **Quick Start**: `/HEALTH_SCORING_QUICKSTART.md`
- **API Docs**: Generated from `@moduledoc` and `@doc` attributes

## Performance Considerations

- Health scores calculated in-memory for fast access
- Periodic snapshots to database (15min intervals)
- Indices on commonly queried fields
- Retention policies to prevent table bloat
- Aggregated fleet statistics for dashboard

## Troubleshooting

### Health Monitor Not Starting

Check supervision tree:

```elixir
Supervisor.which_children(TamanduaServer.Supervisor)
```

### Missing Metrics

Verify metrics are being stored:

```elixir
HealthMetrics.get_latest(agent_id)
```

### Incorrect Baselines

Recalculate manually:

```elixir
BaselineCalculator.calculate_baseline(agent_id)
```

### False Positive Alerts

Tune thresholds in config or adjust alert creation logic.

## Future Enhancements

- ML-based anomaly detection models
- Automated remediation workflows
- SLO integration and tracking
- Multi-tenant fleet segmentation
- Custom scoring algorithms per organization
- Integration with external monitoring tools

## Related Modules

- `TamanduaServer.Agents.Agent` - Agent schema
- `TamanduaServer.Agents.Registry` - Agent registration
- `TamanduaServer.Agents.Worker` - Agent worker process
- `TamanduaServerWeb.FleetHealthLive` - Fleet dashboard UI
- `TamanduaServerWeb.AgentHealthDetailLive` - Agent detail UI
