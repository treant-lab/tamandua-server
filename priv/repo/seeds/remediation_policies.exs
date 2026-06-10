# =============================================================================
# Remediation Policies (Default)
# =============================================================================
# Run with: mix run priv/repo/seeds/remediation_policies.exs

alias TamanduaServer.Remediation.Policy

# Only seed if no policies exist
if Policy.list_policies() == [] do
  IO.puts("Seeding default remediation policies...")

  # Policy 1: Auto-quarantine high-confidence malware (threat_score < 0.3)
  {:ok, _} = Policy.create_policy(%{
    name: "Auto-Quarantine Low-Risk Threats",
    description: "Automatically quarantine files/processes when threat score indicates high confidence (low risk of false positive). No human approval required.",
    is_enabled: true,
    is_default: true,
    priority: 10,
    auto_threshold: 0.3,
    manual_threshold: 0.7,
    action_type: "quarantine",
    action_config: %{
      "notify_on_action" => true,
      "create_backup" => true
    },
    conditions: %{
      "severity" => ["critical", "high"]
    }
  })

  # Policy 2: Notify and queue for medium-risk threats
  {:ok, _} = Policy.create_policy(%{
    name: "Queue Medium-Risk for Review",
    description: "Send notification and queue for analyst review. Auto-execute after 1 hour if no response.",
    is_enabled: true,
    is_default: true,
    priority: 20,
    auto_threshold: 0.3,
    manual_threshold: 0.7,
    action_type: "notify",
    action_config: %{
      "channels" => ["email", "dashboard"],
      "auto_execute_timeout_minutes" => 60
    },
    conditions: %{
      "severity" => ["medium"]
    }
  })

  # Policy 3: Manual approval required for high-risk actions
  {:ok, _} = Policy.create_policy(%{
    name: "Manual Approval Required",
    description: "Require explicit human approval before taking action. Used when threat score indicates uncertainty.",
    is_enabled: true,
    is_default: true,
    priority: 30,
    auto_threshold: 0.7,
    manual_threshold: 1.0,
    action_type: "escalate",
    action_config: %{
      "escalation_team" => "security-analysts",
      "require_approval" => true,
      "approval_timeout_hours" => 24
    },
    conditions: %{
      "min_threat_score" => 0.7
    }
  })

  # Policy 4: Block known-bad indicators immediately
  {:ok, _} = Policy.create_policy(%{
    name: "Block Known-Bad IOCs",
    description: "Immediately block IPs, domains, and hashes that match known-bad threat intelligence.",
    is_enabled: true,
    is_default: true,
    priority: 5,  # Highest priority
    auto_threshold: 0.1,
    manual_threshold: 0.5,
    action_type: "block",
    action_config: %{
      "block_types" => ["ip", "domain", "hash"],
      "duration_hours" => 168  # 1 week
    },
    conditions: %{
      "severity" => ["critical"],
      "mitre_tactics" => ["command-and-control", "exfiltration"]
    }
  })

  IO.puts("Created 4 default remediation policies")
else
  IO.puts("Remediation policies already exist, skipping seed")
end
