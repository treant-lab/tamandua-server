# Configuration Drift Detection - Quick Start Guide

## 5-Minute Setup

### Step 1: Run Migration

```bash
cd apps/tamandua_server
mix ecto.migrate
```

This creates the following tables:
- `agent_configuration_baselines`
- `agent_configuration_drifts`
- `agent_configuration_scans`
- `agent_compliance_status`

### Step 2: Create Baselines for Existing Agents

```elixir
# In IEx console
iex -S mix

# Create baselines for all agents
TamanduaServer.Agents.list_agents()
|> Enum.each(fn agent ->
  baseline = %TamanduaServer.Agents.ConfigurationBaseline{}
  |> TamanduaServer.Agents.ConfigurationBaseline.from_agent_config(
      agent,
      agent.config,
      is_active: true,
      notes: "Initial baseline"
    )
  |> TamanduaServer.Repo.insert!()

  IO.puts("Created baseline for agent #{agent.hostname}")
end)
```

### Step 3: Run First Scan

```elixir
# Scan a specific agent
{:ok, result} = TamanduaServer.Agents.DriftDetector.scan_agent(agent_id)

IO.inspect(result, label: "Scan Result")
# => %{
#   scan: %ConfigurationScan{...},
#   drifts: [...],
#   severity_counts: %{critical: 0, high: 1, medium: 2, low: 0},
#   compliance_score: 85.0
# }

# Or scan entire organization
{:ok, result} = TamanduaServer.Agents.DriftDetector.scan_organization(org_id)
```

### Step 4: Configure Scheduled Scans

Add to your `config/config.exs`:

```elixir
config :tamandua_server, Oban,
  repo: TamanduaServer.Repo,
  plugins: [
    {Oban.Plugins.Cron,
     crontab: [
       # Hourly drift scans
       {"0 * * * *", TamanduaServer.Workers.DriftScanWorker},

       # Daily compliance report (8 AM)
       {"0 8 * * *", TamanduaServer.Workers.ComplianceReportWorker}
     ]}
  ],
  queues: [
    default: 10,
    scheduled: 5
  ]
```

### Step 5: Access Dashboard

Navigate to:
- **Drift Dashboard**: `http://localhost:4000/agents/drift`
- **Agent Detail**: `http://localhost:4000/agents/drift/:agent_id`

## Common Operations

### Create Baseline from Policy

```elixir
alias TamanduaServer.Agents.{Policy, ConfigurationBaseline}
alias TamanduaServer.Repo

# Get policy for agent
{:ok, policy} = PolicyManager.get_effective_policy(agent_id)

# Create baseline from policy
baseline_attrs = %{
  agent_id: agent_id,
  organization_id: agent.organization_id,
  collector_settings: policy.policy_data["collectors"],
  response_permissions: policy.policy_data["response"],
  network_settings: policy.policy_data["network"],
  file_paths: policy.policy_data["paths"],
  resource_limits: policy.policy_data["resource_limits"],
  enabled_features: %{
    "yara_enabled" => policy.policy_data["detection"]["yara_enabled"],
    "sigma_enabled" => policy.policy_data["detection"]["sigma_enabled"],
    "ml_enabled" => policy.policy_data["detection"]["ml_enabled"]
  },
  is_active: true
}

{:ok, baseline} =
  %ConfigurationBaseline{}
  |> ConfigurationBaseline.changeset(baseline_attrs)
  |> Repo.insert()
```

### Remediate Critical Drifts

```elixir
alias TamanduaServer.Agents.{DriftDetector, DriftRemediator}

# Get all critical drifts
drifts = DriftDetector.get_agent_drifts(agent_id,
  status: "detected",
  severity: "critical"
)

# Remediate each (with approval)
Enum.each(drifts, fn drift ->
  case DriftRemediator.remediate_drift(drift.id,
    require_approval: true,
    approved_by_id: admin_user_id
  ) do
    {:ok, _} -> IO.puts("✓ Remediated drift: #{drift.drift_type}")
    {:error, reason} -> IO.puts("✗ Failed: #{inspect(reason)}")
  end
end)

# Or remediate all at once
{:ok, result} = DriftRemediator.remediate_agent(agent_id,
  approved_by_id: admin_user_id
)

IO.puts("Remediated #{result.drifts_remediated} drifts")
```

### Query Compliance Status

```elixir
# Organization-wide compliance
summary = DriftDetector.get_compliance_summary(org_id)

IO.puts("""
Compliance Summary:
  Total Agents: #{summary.total_agents}
  Compliant: #{summary.compliant}
  Non-Compliant: #{summary.non_compliant}
  Avg Score: #{Float.round(summary.avg_compliance_score, 1)}%

  Critical Drifts: #{summary.total_critical_drifts}
  High Drifts: #{summary.total_high_drifts}
""")

# Per-agent compliance
{:ok, compliance} = Repo.get_by(ComplianceStatus, agent_id: agent_id)

IO.puts("""
Agent Compliance:
  Score: #{compliance.compliance_score}%
  Status: #{if compliance.is_compliant, do: "✓ Compliant", else: "✗ Non-Compliant"}
  Total Drifts: #{compliance.drift_count}
  Last Scan: #{compliance.last_scan_at}
""")
```

### Subscribe to Real-Time Events

```elixir
# In a LiveView or GenServer
defmodule MyApp.DriftMonitor do
  use GenServer

  def start_link(_) do
    GenServer.start_link(__MODULE__, %{})
  end

  def init(state) do
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agents:drift")
    {:ok, state}
  end

  def handle_info({:drift_detected, event}, state) do
    Logger.warning("""
    DRIFT DETECTED!
      Agent: #{event.hostname}
      Drifts: #{event.drift_count}
      Critical: #{event.critical_count}
    """)

    # Send alert, update dashboard, etc.

    {:noreply, state}
  end

  def handle_info({:drift_remediated, event}, state) do
    Logger.info("Drift #{event.drift_type} remediated on #{event.hostname}")
    {:noreply, state}
  end
end
```

## Testing

### Manual Testing

```bash
# Run tests
mix test test/tamandua_server/agents/drift_detector_test.exs

# With coverage
mix test --cover
```

### Create Test Drift

```elixir
# Simulate drift by modifying agent config
agent = Repo.get!(Agent, agent_id)

# Disable a collector
config = put_in(agent.config, ["collectors", "process", "enabled"], false)
Repo.update!(Agent.changeset(agent, %{config: config}))

# Scan to detect
{:ok, result} = DriftDetector.scan_agent(agent_id)

# Should detect collector_disabled drift
assert Enum.any?(result.drifts, &(&1.drift_type == "collector_disabled"))
```

## Integration with Existing Features

### 1. Alert Integration

Create alerts for critical drifts:

```elixir
# In DriftDetector after scan
def broadcast_drift_event(agent, drifts) do
  critical_drifts = Enum.filter(drifts, &(&1.severity == "critical"))

  if length(critical_drifts) > 0 do
    TamanduaServer.Alerts.create_alert(%{
      organization_id: agent.organization_id,
      agent_id: agent.id,
      type: "configuration_drift",
      severity: "critical",
      title: "Critical configuration drift on #{agent.hostname}",
      description: "#{length(critical_drifts)} critical configuration drifts detected",
      metadata: %{
        drift_types: Enum.map(critical_drifts, & &1.drift_type),
        compliance_score: calculate_compliance_score(drifts)
      }
    })
  end
end
```

### 2. Policy Integration

Link baselines to policies:

```elixir
# When policy is deployed
def deploy_policy(policy, agents) do
  Enum.each(agents, fn agent ->
    # Create baseline from policy
    create_baseline_from_policy(agent, policy)

    # Push policy configuration
    push_policy_config(agent, policy)

    # Schedule drift scan
    DriftDetector.scan_agent(agent.id, scan_type: "policy_deployment")
  end)
end
```

### 3. Audit Integration

Log drift events:

```elixir
# In DriftDetector
def persist_drifts(drifts, baseline_id) do
  Enum.each(drifts, fn drift_data ->
    # Save drift
    {:ok, drift} = save_drift(drift_data, baseline_id)

    # Create audit log
    TamanduaServer.Audit.log_event(
      "configuration_drift_detected",
      drift.organization_id,
      nil,
      %{
        agent_id: drift.agent_id,
        drift_type: drift.drift_type,
        severity: drift.severity,
        field_path: drift.field_path
      }
    )
  end)
end
```

## Troubleshooting

### No Baseline Found

```
Error: {:error, :no_baseline}
```

**Solution**: Create a baseline for the agent first:

```elixir
{:ok, agent} = Agents.get_agent(agent_id)

%ConfigurationBaseline{}
|> ConfigurationBaseline.from_agent_config(agent, agent.config, is_active: true)
|> Repo.insert!()
```

### Scan Timeout

```
Error: {:error, :timeout}
```

**Solution**: Increase scan timeout or batch scans:

```elixir
# Batch organization scans
agents
|> Enum.chunk_every(10)
|> Enum.each(fn batch ->
  Enum.each(batch, &DriftDetector.scan_agent(&1.id))
  Process.sleep(1000)
end)
```

### False Positives

**Solution**: Adjust baseline or acknowledge drift:

```elixir
# Acknowledge non-issue drift
drift
|> ConfigurationDrift.changeset(%{status: "acknowledged"})
|> Repo.update!()

# Or update baseline
baseline
|> ConfigurationBaseline.changeset(%{
  collector_settings: updated_settings
})
|> Repo.update!()
```

## Production Checklist

- [ ] Migrate database schema
- [ ] Create baselines for all agents
- [ ] Configure scheduled scans (Oban cron)
- [ ] Set up alert integrations
- [ ] Configure approval workflows
- [ ] Test remediation on non-production agents
- [ ] Document baseline update procedures
- [ ] Train team on drift dashboard
- [ ] Set up monitoring for scan failures
- [ ] Configure backup/retention for drift data

## Next Steps

1. Review [CONFIGURATION_DRIFT_DETECTION.md](./CONFIGURATION_DRIFT_DETECTION.md) for complete documentation
2. Integrate with your alert/notification system
3. Set up compliance reporting
4. Configure auto-remediation policies
5. Implement custom drift detection rules

## Support

For questions or issues:
- Check module documentation: `h TamanduaServer.Agents.DriftDetector`
- Review test examples: `test/tamandua_server/agents/drift_detector_test.exs`
- See implementation: `lib/tamandua_server/agents/drift_detector.ex`
