# Attack Chain Definitions

This directory contains YAML definitions for multi-step attack chains used by the Tamandua EDR Attack Chain Detection Engine.

## Overview

Attack chains define sequences of MITRE ATT&CK techniques that represent real-world attack patterns. The detection engine tracks events across time and correlates them based on temporal windows, thresholds, and contextual conditions.

## Chain Definition Format

```yaml
name: "Chain Name"
description: "Description of the attack pattern"
severity: critical|high|medium|low|info
author: "Author name"
version: "1.0"
tags:
  - tag1
  - tag2

steps:
  - name: "Step Name"
    techniques:
      - T1234
      - T1234.001
    threshold: 2              # Number of events required
    timeframe: 300            # Seconds window for this step
    conditions:               # Optional correlation conditions
      same_user: true
      same_source_ip: true
      same_agent: true
      same_process: true
      same_dest_ip: true
    description: "What this step detects"

narrative_template: "Alert message with {user}, {source_ip}, {process}, {timespan}, {count} variables"
```

## Available Chains

1. **credential_stuffing.yml** - Brute force to account takeover
2. **recon_to_lateral.yml** - Discovery to lateral movement
3. **ransomware_kill_chain.yml** - Ransomware deployment pattern
4. **phishing_to_persistence.yml** - Email attack to persistence
5. **data_exfiltration.yml** - Data theft operation
6. **password_spray.yml** - Password spray to privilege escalation
7. **living_off_land.yml** - LOLBins abuse chain
8. **web_shell_attack.yml** - Web compromise to shell access
9. **supply_chain.yml** - Supply chain attack indicators
10. **cloud_credential_theft.yml** - Cloud credential harvesting

## Conditions

Conditions ensure events are correlated properly:

- **same_user**: Events must involve same user account
- **same_source_ip**: Events must originate from same IP
- **same_agent**: Events must occur on same endpoint
- **same_process**: Events must involve same process (PID)
- **same_dest_ip**: Events must target same destination IP

## Narrative Templates

Use these placeholders in narrative templates:

- `{user}` - Username from first event
- `{source_ip}` - Source IP from first event
- `{process}` - Process name from first event
- `{timespan}` - Time elapsed between first and last event
- `{count}` - Number of matched events

## Testing Chains

Set `test_mode: true` in a chain definition to run in dry-run mode. This will log detections without creating alerts.

## Custom Chains

To create a custom chain:

1. Copy an existing YAML file as a template
2. Modify the steps, techniques, and conditions
3. Import via the API or UI

Example import:

```elixir
{:ok, content} = File.read("custom_chain.yml")
{:ok, chain} = TamanduaServer.Detection.ChainLibrary.import_from_yaml(content, org_id)
```

## MITRE ATT&CK Reference

For technique IDs and descriptions, see:
- https://attack.mitre.org/techniques/enterprise/

Common techniques used in chains:
- T1110: Brute Force
- T1078: Valid Accounts
- T1059: Command and Scripting Interpreter
- T1053: Scheduled Task/Job
- T1105: Ingress Tool Transfer
- T1486: Data Encrypted for Impact
- T1003: OS Credential Dumping

## Chain Statistics

View chain performance metrics:

```elixir
# Get detector stats
stats = TamanduaServer.Detection.AttackChainDetector.get_stats()

# Get active chains for an agent
active = TamanduaServer.Detection.AttackChainDetector.get_active_chains(agent_id)
```

## Best Practices

1. **Thresholds**: Set realistic thresholds to reduce false positives
2. **Timeframes**: Use appropriate windows (5 min for quick attacks, 1 hour for slow campaigns)
3. **Conditions**: Add correlation conditions to reduce noise
4. **Testing**: Always test new chains in test_mode first
5. **Narratives**: Write clear narrative templates with context
6. **Severity**: Assign appropriate severity based on impact

## Troubleshooting

### Chain Not Triggering

1. Check if chain is enabled
2. Verify events have correct MITRE techniques
3. Check timeframe windows (events may be too far apart)
4. Verify conditions match (e.g., same_user)

### Too Many False Positives

1. Increase threshold values
2. Add more specific conditions
3. Reduce timeframe windows
4. Add additional steps to make chain more specific

### Testing

Run the test suite:

```bash
mix test test/tamandua_server/detection/attack_chain_detector_test.exs
mix test test/tamandua_server/detection/chain_library_test.exs
```
