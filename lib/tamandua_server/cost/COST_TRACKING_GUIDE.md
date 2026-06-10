# Cost Analysis & Optimization - Complete Guide

## Overview

The Tamandua EDR Cost Analysis & Optimization system provides comprehensive cost tracking, forecasting, and optimization capabilities to help organizations understand and reduce their EDR operating costs.

## Features

### 1. Cost Tracking

Track costs by resource type with granular breakdown:

- **Agent Infrastructure**: CPU hours, memory usage
- **Storage**: Telemetry data, logs, artifacts
- **Network Bandwidth**: Agent-server communication, data exports
- **ML Inference**: Model prediction API calls
- **Third-Party Integrations**: External API costs

**Key Capabilities:**
- Daily cost recording with automatic hourly collection
- Cost allocation by organization, department, project
- Tagging system for chargeback reporting
- Historical cost data retention
- Real-time cost monitoring

### 2. Cost Forecasting

Predict future costs using statistical models:

- **Historical Trend Analysis**: Linear regression on 90-day lookback
- **Growth Scenarios**: 10%, 25%, 50% growth projections
- **Seasonal Adjustments**: Month-over-month pattern detection
- **Confidence Scoring**: Forecast reliability decreases with distance

**Forecasting Algorithm:**
```elixir
# Base forecast = recent average + trend * time
base = recent_30_day_avg + (slope * days_ahead / history_length)

# Apply seasonal adjustment
adjusted = base * (1 + seasonal_factor[month])

# Growth scenarios
growth_10 = adjusted * 1.10
growth_25 = adjusted * 1.25
growth_50 = adjusted * 1.50
```

### 3. Cost Optimization

Automated recommendations with estimated savings:

**Recommendation Types:**
- `overprovisioned_agent` - Low CPU/memory usage
- `idle_agent` - Agent offline for 7+ days
- `excessive_retention` - Unnecessary data retention
- `unused_integration` - Inactive third-party integrations
- `inefficient_query` - Slow or expensive database queries
- `storage_optimization` - Compression/archival opportunities
- `high_bandwidth_usage` - Excessive network traffic
- `expensive_ml_calls` - ML inference optimization

**Implementation Levels:**
- **One-Click**: Automated implementation
- **Easy**: Simple configuration change
- **Moderate**: Requires planning and coordination
- **Complex**: Significant infrastructure change

### 4. Budget Management

Set spending limits with proactive alerts:

- **Budget Types**: Monthly, quarterly, annual
- **Alert Thresholds**: 50%, 75%, 90%, 100% (configurable)
- **Forecast Overrun Detection**: Predict budget breaches
- **Auto-Throttling**: Automatic resource reduction (optional)
- **Multi-Budget Support**: Different budgets for departments/projects

**Throttling Actions:**
- Reduce agent collection frequency
- Pause non-critical ML inference
- Disable expensive integrations
- Archive older telemetry data

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Cost Tracking Flow                    │
└─────────────────────────────────────────────────────────┘

┌──────────────┐    Hourly      ┌──────────────┐
│  Agent       │───Collection───▶│  Tracker     │
│  Metrics     │                 │  GenServer   │
└──────────────┘                 └──────┬───────┘
                                        │
┌──────────────┐                        │ Record
│  Storage     │                        │ Costs
│  Usage       │────────────────────────┤
└──────────────┘                        │
                                        ▼
┌──────────────┐                 ┌──────────────┐
│  ML          │                 │  CostEntry   │
│  Calls       │────────────────▶│  (Database)  │
└──────────────┘                 └──────────────┘
                                        │
                                        │ Daily
                                        ▼ Analysis
┌─────────────────────────────────────────────────────────┐
│                 Analysis & Optimization                 │
├─────────────────────────────────────────────────────────┤
│  ┌────────────┐   ┌────────────┐   ┌────────────┐     │
│  │ Forecaster │   │ Optimizer  │   │  Budget    │     │
│  │  (Trends)  │   │   (Recs)   │   │  Monitor   │     │
│  └────────────┘   └────────────┘   └────────────┘     │
│         │                 │                 │           │
│         └─────────────────┴─────────────────┘           │
│                           │                             │
│                           ▼                             │
│                  ┌────────────────┐                     │
│                  │   LiveView     │                     │
│                  │   Dashboards   │                     │
│                  └────────────────┘                     │
└─────────────────────────────────────────────────────────┘
```

## Database Schema

### cost_entries
Primary cost tracking table.

```sql
CREATE TABLE cost_entries (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL,
  date DATE NOT NULL,
  resource_type VARCHAR NOT NULL,  -- "agent", "storage", "network", "ml", "integration"
  resource_id VARCHAR,              -- specific agent_id, integration name, etc.
  cost_usd DECIMAL(12,4) NOT NULL,
  usage_amount DECIMAL(15,4),       -- CPU hours, GB stored, API calls, etc.
  usage_unit VARCHAR,               -- "cpu_hours", "gb_stored", "api_calls"
  metadata JSONB DEFAULT '{}',      -- tags for allocation
  inserted_at TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE INDEX idx_cost_org_date ON cost_entries(organization_id, date);
CREATE INDEX idx_cost_resource_type ON cost_entries(organization_id, resource_type);
CREATE INDEX idx_cost_resource_id ON cost_entries(organization_id, resource_id);
```

### cost_budgets
Budget configuration and limits.

```sql
CREATE TABLE cost_budgets (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL,
  name VARCHAR NOT NULL,
  budget_type VARCHAR NOT NULL,     -- "monthly", "quarterly", "annual"
  amount_usd DECIMAL(12,2) NOT NULL,
  start_date DATE NOT NULL,
  end_date DATE,
  alert_thresholds INTEGER[],       -- [50, 75, 90, 100]
  auto_throttle_enabled BOOLEAN DEFAULT false,
  throttle_threshold INTEGER DEFAULT 95,
  tags JSONB DEFAULT '{}',
  active BOOLEAN DEFAULT true,
  inserted_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

### cost_recommendations
Optimization suggestions.

```sql
CREATE TABLE cost_recommendations (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL,
  recommendation_type VARCHAR NOT NULL,
  severity VARCHAR NOT NULL,        -- "low", "medium", "high"
  title VARCHAR NOT NULL,
  description TEXT NOT NULL,
  resource_type VARCHAR NOT NULL,
  resource_id VARCHAR,
  current_cost_usd DECIMAL(12,2) NOT NULL,
  estimated_savings_usd DECIMAL(12,2) NOT NULL,
  savings_percent DECIMAL(5,2),
  implementation_effort VARCHAR,    -- "one_click", "easy", "moderate", "complex"
  action_payload JSONB,
  status VARCHAR DEFAULT 'new',     -- "new", "acknowledged", "implemented", "dismissed"
  implemented_by UUID,
  implemented_at TIMESTAMP,
  dismissed_by UUID,
  dismissed_at TIMESTAMP,
  dismissal_reason TEXT,
  metadata JSONB DEFAULT '{}',
  inserted_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

### cost_forecasts
Cost predictions.

```sql
CREATE TABLE cost_forecasts (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL,
  forecast_month DATE NOT NULL,     -- first day of forecasted month
  base_forecast DECIMAL(12,2) NOT NULL,
  growth_10_forecast DECIMAL(12,2),
  growth_25_forecast DECIMAL(12,2),
  growth_50_forecast DECIMAL(12,2),
  seasonal_adjustment DECIMAL(5,2) DEFAULT 0.0,
  confidence_level DECIMAL(5,2),    -- 0.0 to 1.0
  forecast_breakdown JSONB,         -- by resource type
  metadata JSONB DEFAULT '{}',
  inserted_at TIMESTAMP,
  updated_at TIMESTAMP,
  UNIQUE(organization_id, forecast_month)
);
```

## API Reference

### TamanduaServer.Cost.Tracker

#### Record Cost
```elixir
Tracker.record_cost(organization_id, %{
  date: ~D[2026-02-26],
  resource_type: "agent",
  resource_id: agent_id,
  cost_usd: Decimal.from_float(2.50),
  usage_amount: Decimal.from_float(50.0),
  usage_unit: "cpu_hours",
  metadata: %{
    "department" => "Engineering",
    "environment" => "production"
  }
})
```

#### Get Cost Summary
```elixir
summary = Tracker.get_summary(organization_id,
  from_date: ~D[2026-02-01],
  to_date: ~D[2026-02-28]
)

# Returns:
%{
  total_cost: 1234.56,
  breakdown_by_type: %{
    "agent" => 800.00,
    "storage" => 200.00,
    "network" => 150.00,
    "ml" => 84.56
  },
  daily_costs: [{~D[2026-02-01], 40.12}, ...],
  top_resources: [
    %{resource_id: "agent-123", resource_type: "agent", cost: 120.00},
    ...
  ]
}
```

#### Get Chargeback Report
```elixir
costs_by_department = Tracker.get_costs_by_tag(organization_id, "department",
  from_date: ~D[2026-02-01],
  to_date: ~D[2026-02-28]
)

# Returns:
[
  %{
    tag_value: "Engineering",
    total_cost: 800.00,
    breakdown: %{"agent" => 500.00, "storage" => 300.00}
  },
  %{
    tag_value: "Marketing",
    total_cost: 200.00,
    breakdown: %{"agent" => 150.00, "storage" => 50.00}
  }
]
```

### TamanduaServer.Cost.Forecaster

#### Generate Forecast
```elixir
{:ok, count} = Forecaster.generate_forecast(organization_id, 3) # 3 months ahead

forecasts = Forecaster.get_forecasts(organization_id, months: 3)

# Returns list of forecasts:
[
  %{
    forecast_month: ~D[2026-03-01],
    base_forecast: Decimal.new("1250.00"),
    growth_10_forecast: Decimal.new("1375.00"),
    growth_25_forecast: Decimal.new("1562.50"),
    growth_50_forecast: Decimal.new("1875.00"),
    confidence_level: Decimal.new("0.90"),
    forecast_breakdown: %{
      "agent" => 850.00,
      "storage" => 220.00,
      ...
    }
  },
  ...
]
```

### TamanduaServer.Cost.Optimizer

#### Generate Recommendations
```elixir
{:ok, count} = Optimizer.generate_recommendations(organization_id)

recommendations = Optimizer.get_recommendations(organization_id, status: "new")

# Returns list of recommendations:
[
  %{
    id: "rec-uuid",
    recommendation_type: "overprovisioned_agent",
    severity: "medium",
    title: "Underutilized agent: web-server-01",
    description: "Agent web-server-01 is consistently underutilized...",
    resource_type: "agent",
    resource_id: "agent-123",
    current_cost_usd: Decimal.new("120.00"),
    estimated_savings_usd: Decimal.new("36.00"),
    savings_percent: Decimal.new("30.0"),
    implementation_effort: "moderate",
    status: "new"
  },
  ...
]
```

#### Implement Recommendation
```elixir
# For "one_click" recommendations
{:ok, recommendation} = Optimizer.implement_recommendation(recommendation_id, user_id)
```

#### Dismiss Recommendation
```elixir
{:ok, recommendation} = Optimizer.dismiss_recommendation(
  recommendation_id,
  user_id,
  "Already addressed manually"
)
```

### TamanduaServer.Cost.BudgetMonitor

#### Create Budget
```elixir
{:ok, budget} = BudgetMonitor.create_budget(organization_id, %{
  name: "Q1 2026 EDR Budget",
  budget_type: "quarterly",
  amount_usd: Decimal.from_float(10000.00),
  start_date: ~D[2026-01-01],
  end_date: ~D[2026-03-31],
  alert_thresholds: [50, 75, 90, 100],
  auto_throttle_enabled: true,
  throttle_threshold: 95,
  tags: %{"department" => "Engineering"}
})
```

#### Get Budget Status
```elixir
status = BudgetMonitor.get_budget_status(budget_id)

# Returns:
%{
  budget: %CostBudget{...},
  current_spend: Decimal.new("7500.00"),
  budget_amount: Decimal.new("10000.00"),
  percent_used: 75.0,
  forecast_overrun: false,
  recent_alerts: [...]
}
```

## Cost Rate Configuration

Default cost rates (USD):

```elixir
@cost_rates %{
  agent_cpu_hour: 0.05,        # $0.05 per CPU hour
  agent_memory_gb_hour: 0.01,  # $0.01 per GB-hour
  storage_gb_month: 0.10,      # $0.10 per GB/month
  bandwidth_gb: 0.05,          # $0.05 per GB transferred
  ml_inference_call: 0.001,    # $0.001 per ML inference
  integration_api_call: 0.0001 # $0.0001 per integration API call
}
```

**Customization:**
To customize rates for your organization, update the configuration in:
`apps/tamandua_server/lib/tamandua_server/cost/tracker.ex`

## UI Components

### Cost Dashboard (`/cost`)

Main overview with KPIs:
- Current month spend
- Average daily cost
- Budget burn rate
- Potential savings
- Cost breakdown by resource type
- Budget status with progress bars
- Cost trend chart
- Top cost drivers
- Top optimization opportunities

### Cost Analysis (`/cost/analysis`)

Detailed analysis with three views:

**1. Resource Breakdown**
- Costs grouped by resource type (agent, storage, network, ML)
- Drill-down to individual resources
- Historical cost data

**2. Chargeback Reports**
- Costs grouped by tags (department, project, environment)
- Multi-resource breakdown per tag
- CSV export for billing

**3. Forecasts**
- 6-month forecast view
- Base forecast + growth scenarios
- Confidence levels
- Breakdown by resource type

### Cost Optimization (`/cost/optimization`)

Recommendation management:
- Filterable by status (new, acknowledged, implemented, dismissed)
- Grouped by priority (high, medium, low)
- One-click implementation for simple optimizations
- Detailed recommendation view with action plans

## Automated Workflows

### Hourly Cost Collection
```elixir
# Runs every hour
- Collect agent CPU/memory usage
- Calculate hourly costs
- Record CostEntry for each resource
- Apply allocation rules for tagging
```

### Daily Forecast Generation
```elixir
# Runs daily at midnight
- Analyze last 90 days of costs
- Calculate trend and seasonality
- Generate 3-month forecasts
- Update confidence scores
```

### 6-Hour Optimization Analysis
```elixir
# Runs every 6 hours
- Scan for underutilized agents
- Identify idle agents (7+ days offline)
- Detect excessive storage usage
- Generate/update recommendations
```

### 15-Minute Budget Checks
```elixir
# Runs every 15 minutes
- Check all active budgets
- Calculate current spend vs budget
- Trigger alerts at thresholds
- Check for forecast overruns
- Apply auto-throttling if enabled
```

## Best Practices

### 1. Tagging Strategy

Implement a consistent tagging strategy for chargeback:

```elixir
# Recommended tags
%{
  "department" => "Engineering",
  "project" => "web-app",
  "environment" => "production",
  "cost_center" => "CC-1234",
  "owner" => "team-platform"
}
```

### 2. Budget Configuration

- **Start small**: Begin with monitoring-only (no auto-throttle)
- **Multiple budgets**: Separate budgets for dev/staging/prod
- **Realistic thresholds**: Set alerts at 50%, 75%, 90%, 100%
- **Review monthly**: Adjust budgets based on actual usage

### 3. Optimization Workflow

1. **Review weekly**: Check new recommendations
2. **Prioritize**: Focus on high-severity, high-savings items
3. **Test first**: Implement in dev/staging before production
4. **Track impact**: Monitor cost reduction after implementation
5. **Dismiss wisely**: Document reasons for dismissed recommendations

### 4. Cost Allocation

Use allocation rules for automatic tagging:

```elixir
# Example: Tag all dev-* agents as development environment
%{
  name: "Development Agent Tagging",
  match_conditions: %{
    "resource_type" => "agent",
    "hostname_pattern" => "dev-*"
  },
  tags_to_apply: %{
    "environment" => "development",
    "department" => "Engineering",
    "project" => "internal"
  },
  priority: 100  # Lower number = higher priority
}
```

## Troubleshooting

### No cost data showing

**Check:**
1. Tracker GenServer is running
2. Agents are reporting health metrics
3. Organization ID is correct
4. Date range includes recent dates

**Debug:**
```elixir
# Check if costs are being recorded
TamanduaServer.Repo.all(
  from c in TamanduaServer.Cost.CostEntry,
  where: c.organization_id == ^org_id,
  order_by: [desc: c.date],
  limit: 10
)
```

### Forecasts not generating

**Requirements:**
- Minimum 30 days of historical data
- At least one cost entry per day

**Debug:**
```elixir
# Manually trigger forecast generation
TamanduaServer.Cost.Forecaster.generate_forecast(org_id, 3)
```

### Recommendations not appearing

**Check:**
1. Optimizer is running (every 6 hours)
2. Agents have health metrics
3. Sufficient data for analysis (7+ days)

**Manually trigger:**
```elixir
TamanduaServer.Cost.Optimizer.generate_recommendations(org_id)
```

### Budget alerts not triggering

**Check:**
1. BudgetMonitor is running
2. Budget is marked as `active: true`
3. Current spend exceeds threshold
4. No duplicate unacknowledged alerts

**Debug:**
```elixir
# Check budget status
TamanduaServer.Cost.BudgetMonitor.get_budget_status(budget_id)

# Manually trigger budget check
TamanduaServer.Cost.BudgetMonitor.check_budgets()
```

## Performance Considerations

### Database Indexing

Ensure proper indexes for query performance:
```sql
-- Critical indexes for performance
CREATE INDEX idx_cost_org_date ON cost_entries(organization_id, date);
CREATE INDEX idx_cost_resource ON cost_entries(organization_id, resource_type, resource_id);
CREATE INDEX idx_cost_date ON cost_entries(date);

-- For metadata queries (GIN index)
CREATE INDEX idx_cost_metadata ON cost_entries USING GIN (metadata);
```

### Data Retention

Implement archival strategy for old cost data:

```elixir
# Archive costs older than 2 years
# Move to cold storage or aggregate into monthly summaries
# Keep daily granularity for last 2 years only
```

### Query Optimization

For large datasets:
- Use date range filters
- Limit result sets
- Aggregate when possible
- Cache frequently accessed summaries

## Integration Examples

### Export to AWS Cost Explorer
```elixir
# Export cost data in AWS Cost Explorer format
def export_to_aws_format(org_id, date_range) do
  costs = Tracker.get_costs(org_id, from_date: date_range.from, to_date: date_range.to)

  Enum.map(costs, fn cost ->
    %{
      "TimePeriod" => %{
        "Start" => Date.to_string(cost.date),
        "End" => Date.to_string(cost.date)
      },
      "Total" => %{
        "UnblendedCost" => %{
          "Amount" => Decimal.to_string(cost.cost_usd),
          "Unit" => "USD"
        }
      },
      "Groups" => [%{
        "Keys" => [cost.resource_type],
        "Metrics" => %{
          "UnblendedCost" => %{
            "Amount" => Decimal.to_string(cost.cost_usd),
            "Unit" => "USD"
          }
        }
      }]
    }
  end)
end
```

### Webhook Notifications
```elixir
# Send budget alert via webhook
def send_budget_alert_webhook(alert) do
  webhook_url = Application.get_env(:tamandua_server, :budget_alert_webhook)

  payload = %{
    "event" => "budget_alert",
    "threshold" => alert.threshold_percent,
    "current_spend" => Decimal.to_float(alert.current_spend),
    "budget_amount" => Decimal.to_float(alert.budget_amount),
    "forecast_overrun" => alert.forecast_overrun,
    "timestamp" => DateTime.utc_now()
  }

  Finch.build(:post, webhook_url)
  |> Finch.request(TamanduaServer.Finch,
    body: Jason.encode!(payload),
    headers: [{"content-type", "application/json"}]
  )
end
```

## Future Enhancements

- [ ] Custom cost allocation algorithms
- [ ] Integration with cloud provider billing APIs
- [ ] ML-powered anomaly detection for cost spikes
- [ ] What-if analysis for infrastructure changes
- [ ] Cost optimization playbooks
- [ ] Automated remediation for common optimizations
- [ ] Multi-currency support
- [ ] Reserved capacity planning
- [ ] Cost benchmarking across organizations
- [ ] GraphQL API for cost data

## Support

For questions or issues:
- Check logs: `tail -f logs/dev.log | grep Cost`
- Review application status in supervision tree
- Check database for cost entries and recommendations
- Contact support team with org_id and date range

---

**Last Updated:** February 26, 2026
**Version:** 1.0.0
