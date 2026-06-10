# Agent Policy Management System

Comprehensive policy management system for Tamandua EDR with support for templates, inheritance, versioning, and phased deployments.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Policy Structure](#policy-structure)
- [Policy Templates](#policy-templates)
- [Policy Inheritance](#policy-inheritance)
- [Deployment Strategies](#deployment-strategies)
- [API Reference](#api-reference)
- [UI Features](#ui-features)
- [Examples](#examples)

## Overview

The policy management system enables centralized configuration of agent behavior, resource usage, detection rules, and response actions. Policies can be assigned at organization, group, or individual agent levels, with automatic inheritance and override support.

## Features

### Core Features

- **Policy Templates**: Pre-built templates for common use cases (baseline, high security, performance, forensics)
- **Policy Inheritance**: Organization → Group → Agent hierarchy with override support
- **Policy Versioning**: Automatic version tracking for active policies
- **Policy Comparison**: Visual diff viewer to compare policy versions
- **Policy Simulation**: Test policy impact before deployment
- **Policy History**: Complete audit trail of all policy changes

### Deployment Features

- **Immediate Deployment**: Deploy instantly to all target agents
- **Scheduled Deployment**: Schedule deployment for maintenance windows
- **Phased Rollout**: Gradual rollout (5% → 25% → 50% → 100%)
- **Automatic Rollback**: Auto-rollback on high failure rate
- **Progress Tracking**: Real-time deployment progress monitoring
- **Manual Controls**: Continue, pause, rollback, or cancel deployments

### Security & Compliance

- **RBAC Integration**: Role-based policy management
- **Compliance Tags**: Tag policies with compliance frameworks (PCI-DSS, HIPAA, etc.)
- **Approval Workflows**: Optional approval for policy changes
- **Change Auditing**: Complete history of policy modifications

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Policy Management Layer                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Policy     │  │   Policy     │  │   Policy     │      │
│  │   Manager    │  │   Deployer   │  │   History    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            │                                 │
├────────────────────────────┼─────────────────────────────────┤
│                    Storage Layer                             │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐  ┌──────────────────────────────┐    │
│  │  agent_policies  │  │  agent_policy_deployments    │    │
│  └──────────────────┘  └──────────────────────────────┘    │
│  ┌──────────────────┐  ┌──────────────────────────────┐    │
│  │  policy_group_   │  │  policy_deployment_results   │    │
│  │  assignments     │  └──────────────────────────────┘    │
│  └──────────────────┘  ┌──────────────────────────────┐    │
│  ┌──────────────────┐  │  agent_policy_history        │    │
│  │  policy_agent_   │  └──────────────────────────────┘    │
│  │  assignments     │                                       │
│  └──────────────────┘                                       │
└───────────────────────────────────────────────────────────────┘
```

## Policy Structure

A policy consists of the following sections:

### 1. Collectors Configuration

Controls which telemetry collectors are enabled and their collection intervals.

```yaml
collectors:
  process:
    enabled: true
    interval_ms: 5000
    options:
      collect_command_line: true
      collect_environment: false
  file:
    enabled: true
    interval_ms: 30000
    options:
      monitored_paths:
        - /etc
        - /usr/bin
  network:
    enabled: true
    interval_ms: 10000
  dns:
    enabled: true
    interval_ms: 10000
  registry:
    enabled: false
    interval_ms: 60000
```

### 2. Resource Limits

Sets resource consumption limits for the agent.

```yaml
resource_limits:
  max_cpu_percent: 10
  max_memory_mb: 500
  max_disk_mb: 1000
  max_network_bandwidth_mbps: 10
```

### 3. Detection Configuration

Enables/disables detection engines and rule sets.

```yaml
detection:
  yara_enabled: true
  sigma_enabled: true
  ml_enabled: true
  behavioral_analysis_enabled: false
  custom_rules: []
  rule_sets:
    - malware_detection
    - suspicious_behavior
```

### 4. Response Actions

Defines allowed response actions and auto-response settings.

```yaml
response:
  allowed_actions:
    - isolate
    - kill_process
    - quarantine
  auto_response_enabled: false
  max_actions_per_hour: 10
  require_approval: true
  approval_timeout_minutes: 30
```

### 5. Network Configuration

Network restrictions and proxy settings.

```yaml
network:
  allowed_domains: []
  blocked_domains: []
  proxy_enabled: false
  proxy_url: null
  ssl_inspection_enabled: false
```

## Policy Templates

### Baseline

**Use Case**: General-purpose endpoints with balanced security and performance.

**Characteristics**:
- Moderate collection intervals
- Standard detection engines enabled
- Manual response actions only
- 10% CPU, 500MB memory limit

### High Security

**Use Case**: Critical systems, sensitive data, compliance requirements.

**Characteristics**:
- Aggressive collection intervals (1-2 seconds)
- All detection engines enabled
- Auto-response enabled
- Higher resource limits (25% CPU, 1GB memory)
- Kernel-level monitoring

### Performance

**Use Case**: Resource-constrained or performance-critical systems.

**Characteristics**:
- Minimal collection (15-60 second intervals)
- Selective detection (Sigma only)
- Manual response only
- Low resource limits (5% CPU, 256MB memory)

### Forensics

**Use Case**: Incident response, forensic investigations.

**Characteristics**:
- Maximum data collection (500ms-2s intervals)
- All detection engines enabled
- Extensive logging and artifact collection
- High resource limits (50% CPU, 2GB memory)
- Full packet capture support

## Policy Inheritance

Policies follow a three-tier hierarchy:

```
Organization Policy (Base)
    ↓ (inherited + overrides)
Group Policy
    ↓ (inherited + overrides)
Agent Policy
```

### Inheritance Rules

1. **Organization-level** policies apply to all agents by default
2. **Group-level** policies inherit from organization and can override specific settings
3. **Agent-level** policies have the highest priority and override both group and organization settings
4. Overrides are applied at the field level (deep merge)

### Example

```elixir
# Organization policy
%{
  "collectors" => %{
    "process" => %{"enabled" => true, "interval_ms" => 5000},
    "file" => %{"enabled" => true, "interval_ms" => 30000}
  }
}

# Group override (for development team)
%{
  "collectors" => %{
    "process" => %{"interval_ms" => 15000}  # Slower collection
  }
}

# Effective policy for agents in group
%{
  "collectors" => %{
    "process" => %{"enabled" => true, "interval_ms" => 15000},  # Overridden
    "file" => %{"enabled" => true, "interval_ms" => 30000}      # Inherited
  }
}
```

## Deployment Strategies

### Immediate Deployment

Deploys policy to all target agents immediately.

```elixir
PolicyDeployer.deploy_policy(policy_id,
  strategy: "immediate",
  deployed_by_id: user_id
)
```

### Scheduled Deployment

Deploys at a specific time (e.g., during maintenance window).

```elixir
PolicyDeployer.deploy_policy(policy_id,
  strategy: "scheduled",
  scheduled_at: ~U[2026-02-21 02:00:00Z],
  deployed_by_id: user_id
)
```

### Phased Rollout

Gradual deployment with automatic progression through phases.

```elixir
PolicyDeployer.deploy_policy(policy_id,
  strategy: "phased",
  rollout_phases: [
    %{percentage: 5, status: "pending"},
    %{percentage: 25, status: "pending"},
    %{percentage: 50, status: "pending"},
    %{percentage: 100, status: "pending"}
  ],
  auto_rollback: true,
  rollback_threshold: 10,  # Rollback if >10% failure rate
  deployed_by_id: user_id
)
```

### Automatic Rollback

Deployments can automatically roll back if the failure rate exceeds a threshold:

- **Default threshold**: 10% failure rate
- **Configurable** per deployment
- **Restores** previous policy configuration
- **Logs** rollback reason

## API Reference

### PolicyManager

#### `create_policy/2`

Creates a new policy.

```elixir
PolicyManager.create_policy(%{
  name: "Production Policy",
  description: "Policy for production servers",
  organization_id: org_id,
  policy_data: %{...}
}, user_id)
```

#### `create_from_template/4`

Creates a policy from a template.

```elixir
PolicyManager.create_from_template(org_id, "baseline", %{
  name: "Baseline Policy",
  description: "Standard security policy"
}, user_id)
```

#### `update_policy/3`

Updates an existing policy.

```elixir
PolicyManager.update_policy(policy, %{
  description: "Updated description",
  policy_data: %{...}
}, user_id)
```

#### `compute_effective_policy/1`

Computes the final policy for an agent after inheritance and overrides.

```elixir
{:ok, effective_policy} = PolicyManager.compute_effective_policy(agent_id)
```

#### `compare_policies/2`

Compares two policies and returns the diff.

```elixir
{:ok, diff} = PolicyManager.compare_policies(policy_id_1, policy_id_2)
```

#### `simulate_policy/2`

Simulates applying a policy to an agent.

```elixir
{:ok, simulation} = PolicyManager.simulate_policy(agent_id, policy_id)
```

### PolicyDeployer

#### `deploy_policy/2`

Starts a policy deployment.

```elixir
PolicyDeployer.deploy_policy(policy_id,
  strategy: "phased",
  deployed_by_id: user_id
)
```

#### `continue_phased_deployment/1`

Advances a phased deployment to the next phase.

```elixir
PolicyDeployer.continue_phased_deployment(deployment_id)
```

#### `rollback_deployment/2`

Rolls back a deployment.

```elixir
PolicyDeployer.rollback_deployment(deployment_id, "Manual rollback")
```

#### `get_deployment_status/1`

Gets deployment progress and status.

```elixir
{:ok, status} = PolicyDeployer.get_deployment_status(deployment_id)
```

## UI Features

### Policy Editor

Visual editor for creating and modifying policies:

- **Template Selection**: Quick-start with pre-built templates
- **Section Editors**: Dedicated UI for collectors, resources, detection, response
- **Validation**: Real-time validation of policy settings
- **Preview**: View rendered policy before saving

### Policy Comparison

Side-by-side comparison of two policies:

- **Diff Viewer**: Highlights differences between policies
- **Version Comparison**: Compare different versions of the same policy
- **Visual Indicators**: Color-coded additions, deletions, changes

### Policy Simulation

Test policy impact before deployment:

- **Agent Selection**: Choose target agent for simulation
- **Impact Preview**: See what would change
- **Risk Assessment**: Identify potential issues

### Deployment Dashboard

Monitor deployment progress:

- **Real-time Progress**: Live updates on deployment status
- **Phase Tracking**: Current phase and next steps for phased rollouts
- **Failure Monitoring**: Track failed deployments and error rates
- **Manual Controls**: Continue, pause, rollback, or cancel

### Compliance Dashboard

Track policy compliance:

- **Compliance Tags**: Filter policies by compliance framework
- **Coverage Reports**: Which agents have which policies
- **Drift Detection**: Identify agents with policy drift
- **Remediation**: Quick remediation for non-compliant agents

## Examples

### Example 1: Create and Deploy a Baseline Policy

```elixir
# Create policy from template
{:ok, policy} = PolicyManager.create_from_template(
  org_id,
  "baseline",
  %{
    name: "Corporate Baseline",
    description: "Standard policy for all corporate endpoints"
  },
  user_id
)

# Activate policy
{:ok, active_policy} = PolicyManager.activate_policy(policy, user_id)

# Deploy immediately to all agents
{:ok, deployment} = PolicyDeployer.deploy_policy(
  active_policy.id,
  strategy: "immediate",
  deployed_by_id: user_id
)
```

### Example 2: Phased Rollout for Critical Systems

```elixir
# Create high-security policy
{:ok, policy} = PolicyManager.create_from_template(
  org_id,
  "high_security",
  %{name: "Production Security Policy"},
  user_id
)

# Activate
{:ok, active_policy} = PolicyManager.activate_policy(policy, user_id)

# Deploy with phased rollout
{:ok, deployment} = PolicyDeployer.deploy_policy(
  active_policy.id,
  strategy: "phased",
  rollout_phases: [
    %{percentage: 5},
    %{percentage: 25},
    %{percentage: 50},
    %{percentage: 100}
  ],
  auto_rollback: true,
  rollback_threshold: 5,  # Strict threshold for critical systems
  deployed_by_id: user_id
)

# Monitor progress
{:ok, status} = PolicyDeployer.get_deployment_status(deployment.id)
IO.inspect(status.progress)

# Continue to next phase after verification
PolicyDeployer.continue_phased_deployment(deployment.id)
```

### Example 3: Group-Specific Policy Override

```elixir
# Assign organization policy
org_policy = PolicyManager.get_policy_by_name(org_id, "Corporate Baseline")
PolicyManager.assign_to_group(org_policy.id, group_id)

# Create group-specific override
{:ok, dev_policy} = PolicyManager.create_policy(%{
  name: "Dev Team Policy",
  organization_id: org_id,
  scope: "group",
  policy_data: %{
    "resource_limits" => %{
      "max_cpu_percent" => 5,  # Lower limits for dev machines
      "max_memory_mb" => 256
    }
  }
}, user_id)

# Assign with overrides
PolicyManager.assign_to_group(
  dev_policy.id,
  dev_group_id,
  overrides: %{
    "collectors" => %{
      "process" => %{"interval_ms" => 15000}  # Less frequent collection
    }
  }
)
```

### Example 4: Incident Response - Enable Forensics Mode

```elixir
# Get compromised agent
agent = Agents.get_agent(agent_id)

# Create forensics policy
{:ok, forensics_policy} = PolicyManager.create_from_template(
  org_id,
  "forensics",
  %{
    name: "Incident Response - #{agent.hostname}",
    scope: "agent",
    description: "Forensics mode for incident IR-2026-001"
  },
  user_id
)

# Activate and deploy immediately
{:ok, active_policy} = PolicyManager.activate_policy(forensics_policy, user_id)

PolicyManager.assign_to_agent(
  active_policy.id,
  agent_id,
  assigned_by_id: user_id
)

# Deploy immediately
PolicyDeployer.deploy_policy(
  active_policy.id,
  strategy: "immediate",
  agent_ids: [agent_id],
  deployed_by_id: user_id
)
```

## Best Practices

1. **Always test in non-production first**: Use simulation or deploy to a test group
2. **Use phased rollouts for critical changes**: Minimize risk with gradual deployment
3. **Enable auto-rollback**: Let the system protect against widespread failures
4. **Monitor deployment progress**: Watch for errors and high failure rates
5. **Document policy changes**: Use the description and change reason fields
6. **Use compliance tags**: Tag policies with relevant compliance frameworks
7. **Regular policy reviews**: Review and update policies quarterly
8. **Least privilege**: Start with restrictive policies and relax as needed

## Troubleshooting

### Deployment Stuck in Progress

Check deployment status and results:

```elixir
{:ok, status} = PolicyDeployer.get_deployment_status(deployment_id)
IO.inspect(status.results)
```

### High Failure Rate

Check error summary:

```elixir
deployment = Repo.get(PolicyDeployment, deployment_id)
IO.inspect(deployment.error_summary)
```

Manually rollback if needed:

```elixir
PolicyDeployer.rollback_deployment(deployment_id, "Manual rollback due to errors")
```

### Agent Not Receiving Policy

1. Check agent is online: `agent.status == "online"`
2. Verify policy is active: `policy.status == "active"`
3. Check effective policy: `PolicyManager.compute_effective_policy(agent_id)`
4. Review deployment results for that agent

### Policy Inheritance Not Working

Use `compute_effective_policy` to debug inheritance chain:

```elixir
{:ok, effective} = PolicyManager.compute_effective_policy(agent_id)
```

Compare with expected policy to identify override issues.

## Future Enhancements

- **Policy Testing Framework**: Unit tests for policy validation
- **Policy Approval Workflows**: Multi-stage approval for sensitive changes
- **Policy Import/Export**: YAML/JSON import/export for policy sharing
- **Policy Recommendations**: ML-based policy recommendations
- **Compliance Scanning**: Automated compliance validation
- **Policy Templates Marketplace**: Community-contributed templates
