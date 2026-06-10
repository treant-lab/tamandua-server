# Seeds for SOAR trigger rules
#
# Run with: mix run priv/repo/seeds/soar_trigger_rules.exs

alias TamanduaServer.Repo
alias TamanduaServer.Integrations.SOAR.TriggerRule

IO.puts("Seeding SOAR trigger rules...")

default_rules = [
  %{
    name: "Critical Alert - Immediate Response",
    description: "Trigger high priority playbook for critical alerts with high threat score",
    enabled: true,
    priority: 100,
    match_criteria: %{
      "severity" => ["critical"],
      "threat_score_gte" => 0.8
    },
    soar_platform: "both",
    playbook_name: "high_priority_incident"
  },
  %{
    name: "Credential Access Response",
    description: "Respond to credential theft and dumping attempts (MITRE T1003, T1552, T1558)",
    enabled: true,
    priority: 90,
    match_criteria: %{
      "mitre_tactics" => ["credential_access"],
      "mitre_techniques" => ["T1003", "T1552", "T1558"]
    },
    soar_platform: "xsoar",
    playbook_name: "credential_theft_response"
  },
  %{
    name: "AI Model Threat Response",
    description: "Respond to AI/ML model security threats (backdoors, pickle exploits, malicious models)",
    enabled: true,
    priority: 85,
    match_criteria: %{
      "title_contains" => ["model", "backdoor", "pickle", "trojan", "safetensors", "GGUF", "neural"]
    },
    soar_platform: "tines",
    playbook_name: "ai_model_incident"
  },
  %{
    name: "Persistence Detection Response",
    description: "Investigate persistence mechanism installations (MITRE T1547, T1543, T1053)",
    enabled: true,
    priority: 80,
    match_criteria: %{
      "mitre_tactics" => ["persistence"],
      "mitre_techniques" => ["T1547", "T1543", "T1053"]
    },
    soar_platform: "xsoar",
    playbook_name: "persistence_investigation"
  },
  %{
    name: "High Severity Alert",
    description: "Create incident for high severity alerts",
    enabled: true,
    priority: 70,
    match_criteria: %{
      "severity" => ["high"]
    },
    soar_platform: "both",
    playbook_name: "standard_incident"
  },
  %{
    name: "Ransomware Detection",
    description: "Immediate response to ransomware indicators",
    enabled: true,
    priority: 100,
    match_criteria: %{
      "title_contains" => ["ransomware", "encrypt", "ransom"],
      "mitre_techniques" => ["T1486", "T1490"]
    },
    soar_platform: "both",
    playbook_name: "ransomware_response"
  },
  %{
    name: "Lateral Movement Detection",
    description: "Investigate lateral movement attempts",
    enabled: true,
    priority: 85,
    match_criteria: %{
      "mitre_tactics" => ["lateral_movement"],
      "mitre_techniques" => ["T1021", "T1570"]
    },
    soar_platform: "xsoar",
    playbook_name: "lateral_movement_investigation"
  },
  %{
    name: "Data Exfiltration Detection",
    description: "Alert on potential data exfiltration",
    enabled: true,
    priority: 90,
    match_criteria: %{
      "mitre_tactics" => ["exfiltration"],
      "mitre_techniques" => ["T1041", "T1567"]
    },
    soar_platform: "both",
    playbook_name: "exfiltration_response"
  }
]

# Insert rules, skipping duplicates
created_count = Enum.reduce(default_rules, 0, fn rule, count ->
  case Repo.get_by(TriggerRule, name: rule.name) do
    nil ->
      case TriggerRule.create(rule) do
        {:ok, _created} ->
          IO.puts("  Created: #{rule.name}")
          count + 1
        {:error, changeset} ->
          IO.puts("  Error creating #{rule.name}: #{inspect(changeset.errors)}")
          count
      end
    _existing ->
      IO.puts("  Skipped (exists): #{rule.name}")
      count
  end
end)

IO.puts("\nSeeding complete: #{created_count} rules created, #{length(default_rules) - created_count} skipped")
