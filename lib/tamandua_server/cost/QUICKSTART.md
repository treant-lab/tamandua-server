# Cost Analysis & Optimization - Quick Start

## 5-Minute Setup

### 1. Run Migration
```bash
cd apps/tamandua_server
mix ecto.migrate
```

### 2. Add to Application Supervision Tree

Edit `apps/tamandua_server/lib/tamandua_server/application.ex`:

```elixir
children = [
  # ... existing children ...

  # Cost Tracking & Optimization
  TamanduaServer.Cost.Tracker,
  TamanduaServer.Cost.Forecaster,
  TamanduaServer.Cost.Optimizer,
  TamanduaServer.Cost.BudgetMonitor,

  # ... rest of children ...
]
```

### 3. Add Routes

Edit `apps/tamandua_server/lib/tamandua_server_web/router.ex`:

```elixir
scope "/", TamanduaServerWeb do
  pipe_through [:browser, :require_authenticated_user]

  # ... existing routes ...

  # Cost Management
  live "/cost", CostDashboardLive
  live "/cost/analysis", CostAnalysisLive
  live "/cost/optimization", CostOptimizationLive
end
```

### 4. Start the Server
```bash
mix phx.server
```

### 5. Navigate to Dashboard
Open browser: `http://localhost:4000/cost`

## Quick Examples

### Record a Manual Cost Entry
```elixir
# In IEx console
alias TamanduaServer.Cost.Tracker

Tracker.record_cost("org-uuid", %{
  date: Date.utc_today(),
  resource_type: "agent",
  resource_id: "agent-123",
  cost_usd: Decimal.from_float(5.00),
  usage_amount: Decimal.from_float(100.0),
  usage_unit: "cpu_hours",
  metadata: %{"department" => "Engineering"}
})
```

### Create a Monthly Budget
```elixir
alias TamanduaServer.Cost.BudgetMonitor

{:ok, budget} = BudgetMonitor.create_budget("org-uuid", %{
  name: "March 2026 Budget",
  budget_type: "monthly",
  amount_usd: Decimal.from_float(5000.00),
  start_date: ~D[2026-03-01],
  alert_thresholds: [50, 75, 90, 100]
})
```

### Generate Recommendations
```elixir
alias TamanduaServer.Cost.Optimizer

{:ok, count} = Optimizer.generate_recommendations("org-uuid")
recommendations = Optimizer.get_recommendations("org-uuid", status: "new")
```

### Get Cost Summary
```elixir
alias TamanduaServer.Cost.Tracker

summary = Tracker.get_summary("org-uuid",
  from_date: ~D[2026-02-01],
  to_date: ~D[2026-02-28]
)

IO.inspect(summary.total_cost)
IO.inspect(summary.breakdown_by_type)
```

## Default Cost Rates

The system uses these default rates (customizable in `tracker.ex`):

| Resource Type | Rate | Unit |
|--------------|------|------|
| Agent CPU | $0.05 | per CPU hour |
| Agent Memory | $0.01 | per GB-hour |
| Storage | $0.10 | per GB/month |
| Bandwidth | $0.05 | per GB transferred |
| ML Inference | $0.001 | per API call |
| Integration API | $0.0001 | per API call |

## Automated Collection Schedule

| Task | Frequency | Description |
|------|-----------|-------------|
| Cost Collection | Hourly | Collect agent metrics and record costs |
| Forecast Generation | Daily | Update 3-month forecasts |
| Optimization Analysis | 6 hours | Scan for cost-saving opportunities |
| Budget Monitoring | 15 minutes | Check budgets and trigger alerts |

## Common Tasks

### View Current Month Costs
```elixir
summary = Tracker.get_summary("org-uuid",
  from_date: Date.beginning_of_month(Date.utc_today()),
  to_date: Date.utc_today()
)
```

### Get Chargeback Report by Department
```elixir
Tracker.get_costs_by_tag("org-uuid", "department",
  from_date: ~D[2026-02-01],
  to_date: ~D[2026-02-28]
)
```

### Get 3-Month Forecast
```elixir
alias TamanduaServer.Cost.Forecaster

Forecaster.generate_forecast("org-uuid", 3)
forecasts = Forecaster.get_forecasts("org-uuid", months: 3)
```

### Implement a One-Click Recommendation
```elixir
alias TamanduaServer.Cost.Optimizer

# Find one-click recommendations
recs = Optimizer.get_recommendations("org-uuid", status: "new")
one_click = Enum.find(recs, &(&1.implementation_effort == "one_click"))

# Implement it
{:ok, _} = Optimizer.implement_recommendation(one_click.id, user_id)
```

## Troubleshooting

### No costs showing up?
```elixir
# Check if Tracker is running
GenServer.whereis(TamanduaServer.Cost.Tracker)

# Check database
TamanduaServer.Repo.all(TamanduaServer.Cost.CostEntry) |> length()

# Manually trigger collection
send(TamanduaServer.Cost.Tracker, :collect_costs)
```

### Forecasts not generating?
```elixir
# Need 30+ days of data
# Check data availability
query = from c in TamanduaServer.Cost.CostEntry,
  where: c.organization_id == ^org_id,
  select: %{
    min_date: min(c.date),
    max_date: max(c.date),
    count: count(c.id)
  }

TamanduaServer.Repo.one(query)

# Manually generate
TamanduaServer.Cost.Forecaster.generate_forecast(org_id, 3)
```

### Budget alerts not working?
```elixir
# Check budget is active
budget = TamanduaServer.Repo.get(TamanduaServer.Cost.CostBudget, budget_id)
budget.active  # should be true

# Check current spend
status = TamanduaServer.Cost.BudgetMonitor.get_budget_status(budget_id)
IO.inspect(status.percent_used)

# Manually trigger check
TamanduaServer.Cost.BudgetMonitor.check_budgets()
```

## Next Steps

1. **Read Full Documentation**: See `COST_TRACKING_GUIDE.md` for complete details
2. **Configure Custom Rates**: Update cost rates in `tracker.ex` for your infrastructure
3. **Set Up Budgets**: Create budgets for different departments/projects
4. **Review Recommendations**: Check optimization suggestions weekly
5. **Export Data**: Set up CSV exports for finance team

## API Quick Reference

```elixir
# Tracking
Tracker.record_cost(org_id, attrs)
Tracker.get_summary(org_id, opts)
Tracker.get_costs(org_id, opts)
Tracker.get_costs_by_tag(org_id, tag_key, opts)

# Forecasting
Forecaster.generate_forecast(org_id, months_ahead)
Forecaster.get_forecasts(org_id, opts)
Forecaster.get_forecast_for_month(org_id, date)

# Optimization
Optimizer.generate_recommendations(org_id)
Optimizer.get_recommendations(org_id, opts)
Optimizer.implement_recommendation(rec_id, user_id)
Optimizer.dismiss_recommendation(rec_id, user_id, reason)
Optimizer.get_potential_savings(org_id)

# Budgets
BudgetMonitor.create_budget(org_id, attrs)
BudgetMonitor.update_budget(budget_id, attrs)
BudgetMonitor.list_budgets(org_id, opts)
BudgetMonitor.get_budget_status(budget_id)
BudgetMonitor.check_budgets()
```

## Support

- Full Guide: `COST_TRACKING_GUIDE.md`
- Logs: `tail -f logs/dev.log | grep Cost`
- IEx: `iex -S mix phx.server`

---

**Ready to save money!** Navigate to `/cost` to get started.
