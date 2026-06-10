# SLO Monitoring System

Comprehensive SLI/SLO monitoring and error budget tracking for Tamandua EDR.

## Components

### 1. Calculator (`calculator.ex`)
Calculates SLI (Service Level Indicator) metrics from raw data:
- **Availability**: Uptime percentage from health check samples
- **Latency**: p50, p95, p99 percentiles from latency measurements
- **Error Rate**: Percentage of failed requests
- **Throughput**: Events/requests per second
- **Composite SLI**: Weighted average of all SLIs

### 2. Error Budget (`error_budget.ex`)
Tracks error budget consumption and burn rate:
- **Budget Calculation**: Remaining allowable downtime
- **Burn Rate**: Speed at which budget is consumed (1x, 14.4x, etc.)
- **Alerts**: Fast/medium/slow burn rate alerts
- **Violation Recording**: Tracks downtime events

### 3. Tracker (`tracker.ex`)
Collects and aggregates metrics in real-time:
- **ETS Storage**: Fast in-memory metric storage
- **Service Tracking**: API, events, detection, ML services
- **Availability Polling**: Periodic health checks
- **Historical Windows**: 5-minute aggregation windows

## SLO Targets

| Metric | Target | Error Budget |
|--------|--------|--------------|
| Availability | 99.9% | 43.2 min/month |
| P95 Latency | < 500ms | - |
| P99 Latency | < 1000ms | - |
| Error Rate | < 0.1% | - |
| Throughput | >= 1000 events/sec | - |

## Burn Rate Alerts

| Type | Multiplier | Exhaustion | Alert Delay |
|------|------------|------------|-------------|
| Fast | 14.4x | 2 hours | 2 minutes |
| Medium | 6.0x | 5 hours | 15 minutes |
| Slow | 3.0x | 10 hours | 1 hour |

## Usage

### Recording Metrics

```elixir
alias TamanduaServer.SLO.Tracker

# Record API request
Tracker.record_api_request(150, true, "/api/alerts")

# Record event processing
Tracker.record_event_processing(75, true)

# Record detection
Tracker.record_detection(200, true, :yara)

# Record availability
Tracker.record_availability_check(true)
```

### Getting Metrics

```elixir
# Get all metrics
metrics = Tracker.current_metrics()

# Get service-specific metrics
api_metrics = Tracker.service_metrics(:api)

# Get error budget status
budget = Tracker.error_budget_status()
```

### Checking SLO Compliance

```elixir
metrics = Tracker.current_metrics()

if metrics.api.latency.compliant do
  Logger.info("API latency SLO met")
else
  Logger.warning("API latency SLO breached: p95=#{metrics.api.latency.p95}ms")
end
```

## Dashboard

Access the LiveView dashboard at: `http://localhost:4000/live/slo`

Features:
- Real-time SLI values
- SLO compliance status (green/yellow/red)
- Error budget gauge
- Burn rate chart
- Recent alerts
- Historical trends

## Grafana Integration

The Grafana dashboard is available at:
`http://localhost:3000/d/tamandua-slo`

Includes:
- SLI gauges (availability, latency, error rate)
- Error budget visualization
- Burn rate charts
- Latency percentiles
- Throughput graphs
- SLO compliance table

## Prometheus Alerts

Alerts are configured in `monitoring/prometheus/alerts/slo.yml`:

### Critical
- `ErrorBudgetFastBurn`: Burn rate > 14.4x
- `AvailabilitySLOBreach`: Availability < 99.9%
- `MultipleSLOBreaches`: 3+ SLOs breached

### Warning
- `ErrorBudgetMediumBurn`: Burn rate > 6.0x
- `LatencyP95SLOBreach`: P95 latency > 500ms
- `ErrorRateSLOBreach`: Error rate > 0.1%

## Testing

Run tests:
```bash
mix test test/tamandua_server/slo/
```

Test coverage:
- Calculator: SLI calculations, percentiles, compliance checks
- Error Budget: Budget tracking, burn rate, alerts
- Tracker: Metric collection, aggregation, ETS storage

## Architecture

```
Application Code
       │
       ▼
   SLO Tracker (ETS)
       │
       ├──► Calculator ──► SLIs
       │
       └──► ErrorBudget ──► Budget & Burn Rate
               │
               ▼
          LiveView UI
               │
               ▼
           Grafana
               │
               ▼
          Prometheus
               │
               ▼
            Alerts
```

## Configuration

SLO targets are configured in the Calculator module. To customize:

1. Edit `apps/tamandua_server/lib/tamandua_server/slo/calculator.ex`
2. Update the `@slo_targets` module attribute
3. Restart the application

## Error Budget Decision Making

Use error budget for deployment decisions:

```elixir
budget = Tracker.error_budget_status()

decision = cond do
  budget.budget_remaining_percent < 5 ->
    :freeze_deployments

  budget.budget_remaining_percent < 25 ->
    :proceed_with_caution

  true ->
    :proceed_normally
end
```

## Incident Correlation

SLO breaches are automatically broadcasted via Phoenix PubSub:

```elixir
# Subscribe to SLO events
Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "system:slo")

# Handle alerts
def handle_info({:error_budget_alert, alerts}, state) do
  # Create incident ticket
  # Page on-call engineer
  # Update status page
end
```

## Best Practices

1. **Monitor Burn Rate**: Proactive alerts before budget exhaustion
2. **Use for Decisions**: Deployment risk, feature launches
3. **Regular Reviews**: Monthly SLO review meetings
4. **Adjust Targets**: Based on actual performance data
5. **Correlate Incidents**: Tag incidents with SLO impact

## Documentation

See `docs/slo_monitoring.md` for comprehensive documentation including:
- Detailed architecture
- Runbook procedures
- Troubleshooting guide
- API reference
- Integration examples
