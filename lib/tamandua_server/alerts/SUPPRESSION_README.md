# Alert Suppression System Implementation

## Overview

This directory contains the comprehensive alert suppression system for Tamandua EDR. The system provides priority-based rule evaluation, time windows, exemptions, analytics, and a full-featured management UI.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     Alert Suppression System                  │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐ │
│  │ SuppressionRule│  │SuppressedAlert │  │  Analytics     │ │
│  │    (Schema)    │  │   (Schema)     │  │   (Module)     │ │
│  └────────────────┘  └────────────────┘  └────────────────┘ │
│          │                    │                    │          │
│          └────────────────────┴────────────────────┘          │
│                              │                                │
│                    ┌─────────▼─────────┐                      │
│                    │ SuppressionEngine │                      │
│                    │   (GenServer)     │                      │
│                    │  - Priority eval  │                      │
│                    │  - ETS caching    │                      │
│                    │  - Exemptions     │                      │
│                    └───────────────────┘                      │
│                              │                                │
│                    ┌─────────▼─────────┐                      │
│                    │   Suppression     │                      │
│                    │   (Legacy API)    │                      │
│                    └───────────────────┘                      │
│                              │                                │
└──────────────────────────────┼────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │    Alert Creation    │
                    │  (Detection Engine)  │
                    └─────────────────────┘
```

## Files

### Core Modules

- **`suppression_rule.ex`**: Schema and validation for suppression rules
  - Pattern matching logic
  - Time window validation
  - Exemption checks
  - Priority handling

- **`suppression_engine.ex`**: Priority-based evaluation engine (GenServer)
  - ETS-cached priority-sorted rules
  - Rule evaluation with context
  - Template management
  - Auto-unsuppression scheduler

- **`suppressed_alert.ex`**: Schema for stored suppressed alerts
  - Original alert data preservation
  - Suppression metadata
  - Unsuppression tracking

- **`suppression_analytics.ex`**: Metrics and reporting
  - Suppression rate calculations
  - Top rules by match count
  - False positive reduction metrics
  - Time-series data

- **`suppression.ex`**: Legacy API with backward compatibility
  - Contextual auto-suppression
  - Integration with new engine

### UI & Tests

- **`../../tamandua_server_web/lib/tamandua_server_web/live/suppression_rules_live.ex`**:
  Phoenix LiveView for rule management
  - CRUD operations
  - Analytics dashboard
  - Template browser
  - Suppressed alerts viewer

- **`../../test/tamandua_server/alerts/suppression_engine_test.exs`**:
  Comprehensive test suite

### Database & Seeds

- **`../../priv/repo/migrations/20260220800001_create_suppression_system.exs`**:
  Database schema migration
  - alert_suppression_rules table
  - suppressed_alerts table
  - suppression_analytics table
  - suppression_audit_log table

- **`../../priv/repo/seeds/suppression_templates.exs`**:
  Pre-configured rule templates

## Features Implemented

### ✅ Requirement 1: Suppression Rules

- [x] Match criteria (severity, type, agent, MITRE technique, tags)
- [x] Time windows (1h, 24h, 7d, indefinite)
- [x] Exemptions (agents, users)
- [x] Rule priorities (0-100, higher = first evaluated)
- [x] Multiple actions (suppress, reduce_severity, tag)
- [x] Max matches limit
- [x] Wildcard pattern matching

### ✅ Requirement 2: Rule Management

- [x] Create/edit/delete rules
- [x] Enable/disable toggle
- [x] Rule expiration (automatic and scheduled)
- [x] Rule templates (12 common scenarios)
- [x] Template instantiation with overrides
- [x] Validation and error handling

### ✅ Requirement 3: Suppression Analytics

- [x] Suppressed alert count
- [x] Top suppression rules
- [x] False positive reduction metrics
- [x] Suppression rate tracking
- [x] By severity breakdown
- [x] By type breakdown (rule/manual/auto)
- [x] Time-series timeline
- [x] Suppression audit log

### ✅ Requirement 4: Integration

- [x] Apply suppressions during alert creation
- [x] Suppressed alerts stored separately
- [x] Unsuppress functionality
- [x] Auto-unsuppression scheduling
- [x] Notification when suppression expires (via audit log)
- [x] ETS caching for performance
- [x] Priority-based evaluation
- [x] Backward compatibility with legacy API

## Usage Examples

### Creating a Rule

```elixir
# Via UI: Click "Create Rule" button in LiveView

# Via API:
alias TamanduaServer.Alerts.SuppressionRule

%SuppressionRule{}
|> SuppressionRule.changeset(%{
  name: "Suppress test environment alerts",
  action: "suppress",
  priority: 10,
  title_pattern: "*test*",
  time_window_type: "duration",
  time_window_value: 86400,  # 24 hours
  organization_id: org_id,
  created_by_id: user_id
})
|> Repo.insert()
```

### Evaluating During Alert Creation

```elixir
alias TamanduaServer.Alerts.SuppressionEngine

alert_data = %{
  title: "Suspicious activity in test environment",
  severity: "high",
  organization_id: org_id,
  agent_id: agent_id
}

case SuppressionEngine.evaluate_rules(alert_data) do
  :allow ->
    # Create alert normally

  {:suppress, rule_id, reason} ->
    # Store as suppressed
    SuppressionEngine.store_suppressed_alert(alert_data, %{
      reason: reason,
      type: "rule",
      rule_id: rule_id
    })

  {:reduce_severity, new_severity, rule_id, reason} ->
    # Create with reduced severity
end
```

### Using Templates

```elixir
# List available templates
templates = SuppressionEngine.list_templates(org_id)

# Create rule from template
{:ok, rule} = SuppressionEngine.create_from_template(
  template_id,
  %{name: "My Custom Rule", priority: 20},
  org_id
)
```

### Analytics

```elixir
alias TamanduaServer.Alerts.SuppressionAnalytics

# Get 7-day stats
stats = SuppressionAnalytics.get_stats(org_id, period: "7d")

# Returns:
%{
  summary: %{suppression_rate: 15.2, ...},
  top_rules: [...],
  by_severity: %{"critical" => 10, ...},
  timeline: [...]
}
```

## Performance

- **Rule Evaluation**: < 1ms per alert (ETS cached)
- **Cache Refresh**: Every 5 minutes (configurable)
- **Auto-unsuppression**: Checked every 5 minutes
- **ETS Tables**: 2 (priority rules, contextual counters)
- **Database Queries**: Optimized with indexes

## Configuration

```elixir
# config/config.exs
config :tamandua_server,
  # Contextual auto-suppression threshold
  suppression_occurrence_threshold: 5,

  # Contextual reset period (seconds)
  suppression_reset_period_seconds: 86400
```

## Testing

```bash
# Run suppression tests
mix test test/tamandua_server/alerts/suppression_engine_test.exs

# Run all alert tests
mix test test/tamandua_server/alerts/

# Run with coverage
mix test --cover
```

## Migration

```bash
# Run migration
mix ecto.migrate

# Seed templates (optional)
mix run priv/repo/seeds/suppression_templates.exs
```

## API Documentation

See `../../../../docs/ALERT_SUPPRESSION.md` for detailed API documentation.

## Future Enhancements

- [ ] ML-based automatic rule suggestions
- [ ] Regex pattern support
- [ ] Scheduled suppression windows
- [ ] Cross-agent correlation rules
- [ ] SIEM integration for suppression lists
- [ ] Bulk rule import/export
- [ ] Rule versioning and rollback

## Support

For issues or questions:
- See main documentation: `docs/ALERT_SUPPRESSION.md`
- Create an issue: GitHub Issues
- Contact: contato@treantlab.org
