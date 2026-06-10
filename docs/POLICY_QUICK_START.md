# Policy Management - Quick Start Guide

Get started with Tamandua's policy management system in 5 minutes.

## Prerequisites

- Tamandua EDR server running
- Database migrations applied
- At least one organization and user configured
- One or more agents connected

## Step 1: Run Migrations

Apply the policy management migrations:

```bash
cd apps/tamandua_server
mix ecto.migrate
```

This creates the following tables:
- `agent_policies`
- `agent_policy_group_assignments`
- `agent_policy_assignments`
- `agent_policy_deployments`
- `agent_policy_deployment_results`
- `agent_policy_history`

## Step 2: Create Your First Policy

### Option A: Using a Template (Recommended)

```elixir
# Start IEx
iex -S mix

# Create policy from baseline template
alias TamanduaServer.Agents.PolicyManager

{:ok, policy} = PolicyManager.create_from_template(
  "your-org-id",
  "baseline",
  %{
    name: "Corporate Baseline Policy",
    description: "Standard security policy for all endpoints",
    scope: "organization"
  },
  "your-user-id"
)

# Activate the policy
{:ok, active_policy} = PolicyManager.activate_policy(policy, "your-user-id")
```

### Option B: Create Custom Policy

```elixir
{:ok, policy} = PolicyManager.create_policy(%{
  name: "Custom Policy",
  description: "My custom policy",
  organization_id: "your-org-id",
  scope: "organization",
  policy_data: %{
    "collectors" => %{
      "process" => %{"enabled" => true, "interval_ms" => 5000},
      "file" => %{"enabled" => true, "interval_ms" => 30000},
      "network" => %{"enabled" => true, "interval_ms" => 10000}
    },
    "resource_limits" => %{
      "max_cpu_percent" => 10,
      "max_memory_mb" => 500,
      "max_disk_mb" => 1000
    },
    "detection" => %{
      "yara_enabled" => true,
      "sigma_enabled" => true,
      "ml_enabled" => true
    },
    "response" => %{
      "allowed_actions" => ["isolate", "kill_process"],
      "auto_response_enabled" => false,
      "max_actions_per_hour" => 10
    }
  }
}, "your-user-id")

{:ok, active_policy} = PolicyManager.activate_policy(policy, "your-user-id")
```

## Step 3: Deploy the Policy

### Immediate Deployment

Deploy to all online agents immediately:

```elixir
alias TamanduaServer.Agents.PolicyDeployer

{:ok, deployment} = PolicyDeployer.deploy_policy(
  active_policy.id,
  strategy: "immediate",
  deployed_by_id: "your-user-id"
)
```

### Phased Deployment (Safer for Production)

```elixir
{:ok, deployment} = PolicyDeployer.deploy_policy(
  active_policy.id,
  strategy: "phased",
  deployed_by_id: "your-user-id",
  auto_rollback: true,
  rollback_threshold: 10  # Auto-rollback if >10% fail
)

# Check progress
{:ok, status} = PolicyDeployer.get_deployment_status(deployment.id)
IO.inspect(status.progress)

# Continue to next phase when ready
PolicyDeployer.continue_phased_deployment(deployment.id)
```

### Scheduled Deployment

```elixir
# Schedule for tomorrow at 2 AM UTC
scheduled_at = DateTime.utc_now() |> DateTime.add(86400, :second) |> DateTime.truncate(:second)
scheduled_at = %{scheduled_at | hour: 2, minute: 0, second: 0}

{:ok, deployment} = PolicyDeployer.deploy_policy(
  active_policy.id,
  strategy: "scheduled",
  scheduled_at: scheduled_at,
  deployed_by_id: "your-user-id"
)
```

## Step 4: Verify Deployment

### Check Deployment Status

```elixir
{:ok, status} = PolicyDeployer.get_deployment_status(deployment.id)

IO.puts("Total agents: #{status.progress.total}")
IO.puts("Successful: #{status.progress.successful}")
IO.puts("Failed: #{status.progress.failed}")
IO.puts("Pending: #{status.progress.pending}")
IO.puts("Success rate: #{status.progress.percentage}%")
```

### Check Effective Policy for an Agent

```elixir
{:ok, effective_policy} = PolicyManager.compute_effective_policy("agent-id")
IO.inspect(effective_policy)
```

## Step 5: Using the Web UI

### Access the Policy Editor

Navigate to: `http://localhost:4000/policies` (or your server URL)

### Create Policy via UI

1. Click "Create Policy" button
2. Choose a template or start from scratch:
   - **Baseline**: Balanced security and performance
   - **High Security**: Maximum protection for critical systems
   - **Performance**: Minimal resource usage
   - **Forensics**: Maximum logging for investigations
3. Fill in name and description
4. Customize settings in the visual editor
5. Click "Create"

### Deploy Policy via UI

1. Find your policy in the list
2. Click "Activate" if it's in draft status
3. Click "Deploy"
4. Choose deployment strategy:
   - **Immediate**: Deploy now
   - **Scheduled**: Set a specific time
   - **Phased**: Gradual rollout
5. Configure rollback settings
6. Click "Deploy"

### Monitor Deployment

The right panel shows recent deployments with:
- Deployment strategy
- Current progress
- Phase information (for phased deployments)
- Action buttons (Continue, Rollback, Cancel)

## Common Workflows

### Workflow 1: Organization-Wide Policy

```elixir
# Create organization policy
{:ok, policy} = PolicyManager.create_from_template(
  org_id, "baseline",
  %{name: "Org Policy", scope: "organization"},
  user_id
)

# Activate and deploy
{:ok, active} = PolicyManager.activate_policy(policy, user_id)
{:ok, _deployment} = PolicyDeployer.deploy_policy(
  active.id,
  strategy: "phased",
  deployed_by_id: user_id
)
```

### Workflow 2: Group-Specific Override

```elixir
# Create group policy
{:ok, group_policy} = PolicyManager.create_policy(%{
  name: "Dev Team Policy",
  organization_id: org_id,
  scope: "group",
  policy_data: %{
    "resource_limits" => %{
      "max_cpu_percent" => 5  # Lower limit for dev machines
    }
  }
}, user_id)

# Activate
{:ok, active} = PolicyManager.activate_policy(group_policy, user_id)

# Assign to group
PolicyManager.assign_to_group(active.id, group_id)

# Deploy to group members
{:ok, _deployment} = PolicyDeployer.deploy_policy(
  active.id,
  strategy: "immediate",
  group_ids: [group_id],
  deployed_by_id: user_id
)
```

### Workflow 3: Emergency Forensics Mode

```elixir
# Enable forensics mode on specific agent
{:ok, forensics} = PolicyManager.create_from_template(
  org_id, "forensics",
  %{
    name: "Forensics - Incident #{incident_id}",
    scope: "agent"
  },
  user_id
)

{:ok, active} = PolicyManager.activate_policy(forensics, user_id)
PolicyManager.assign_to_agent(active.id, compromised_agent_id)

# Deploy immediately
PolicyDeployer.deploy_policy(
  active.id,
  strategy: "immediate",
  agent_ids: [compromised_agent_id],
  deployed_by_id: user_id
)
```

## Troubleshooting

### Issue: Deployment failing on all agents

**Check:**
1. Agents are online: `Repo.all(from a in Agent, where: a.status == "online")`
2. Policy is valid: `PolicyManager.get_policy(policy_id)`
3. WebSocket connections working

**Solution:**
- Verify agent connectivity
- Check agent logs for errors
- Test with a single agent first

### Issue: Policy not taking effect

**Check:**
1. Policy is active: `policy.status == "active"`
2. Deployment completed: `deployment.status == "completed"`
3. Agent received update

**Solution:**
```elixir
# Check effective policy
{:ok, effective} = PolicyManager.compute_effective_policy(agent_id)

# Force re-send
agent = Repo.get(Agent, agent_id)
policy_data = effective
AgentWorker.send_command(agent.id, %{
  type: "update_policy",
  policy: policy_data
})
```

### Issue: High failure rate in deployment

**Check deployment errors:**
```elixir
{:ok, status} = PolicyDeployer.get_deployment_status(deployment_id)

# Review failed agents
failed_results = Enum.filter(status.results, &(&1.status == "failed"))
IO.inspect(failed_results)
```

**Solution:**
- Review error messages
- Rollback if needed: `PolicyDeployer.rollback_deployment(deployment_id)`
- Fix policy issues and re-deploy

## Next Steps

1. **Read the full documentation**: See `POLICY_MANAGEMENT.md`
2. **Explore templates**: Review YAML templates in `priv/policy_templates/`
3. **Set up groups**: Organize agents into logical groups
4. **Configure inheritance**: Set up organization → group → agent hierarchy
5. **Test phased rollouts**: Practice with non-critical systems first
6. **Enable compliance tags**: Tag policies for compliance tracking

## Additional Resources

- **Full Documentation**: `docs/POLICY_MANAGEMENT.md`
- **API Reference**: See documentation for `PolicyManager` and `PolicyDeployer`
- **Templates**: `priv/policy_templates/*.yaml`
- **Tests**: `test/tamandua_server/agents/policy_*_test.exs`

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review test files for usage examples
3. Consult the full documentation
4. Check agent logs for deployment errors
