defmodule TamanduaServer.Detection.EvidenceTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.Evidence

  describe "extract_detection_info/1" do
    test "normalizes agent DetectionType values into useful alert categories" do
      cases = [
        {"Persistence", "persistence"},
        {"WmiPersistence", "persistence"},
        {"DefenseEvasion", "defense_evasion"},
        {"ScriptThreat", "script_threat"},
        {"CredentialTheft", "credential_theft"},
        {"BrowserStealer", "credential_theft"},
        {"LateralMovement", "lateral_movement"},
        {"ProcessHollowing", "process_injection"},
        {"MemoryThreat", "memory_threat"},
        {"Ransomware", "ransomware"},
        {"ThreatIntel", "threat_intel"},
        {"NetworkAnomaly", "network_anomaly"},
        {"OfficeEmail", "phishing"},
        {"SupplyChain", "supply_chain"}
      ]

      for {agent_type, expected} <- cases do
        assert %{rule_type: ^expected} =
                 Evidence.extract_detection_info([%{"rule_name" => "test", "detection_type" => agent_type}])
      end
    end

    test "infers type from known agent rule names when type is missing or unknown" do
      assert %{rule_type: "persistence"} =
               Evidence.extract_detection_info([%{"rule_name" => "REGISTRY_PERSISTENCE", "type" => "unknown"}])

      assert %{rule_type: "defense_evasion"} =
               Evidence.extract_detection_info([%{"rule_name" => "powershell_execution_policy_bypass"}])

      assert %{rule_type: "defense_evasion"} =
               Evidence.extract_detection_info([%{"rule_name" => "kernel_syscall_0x0063"}])
    end

    test "preserves source detection type and MITRE metadata" do
      info =
        Evidence.extract_detection_info([
          %{
            "rule_name" => "REGISTRY_PERSISTENCE",
            "detection_type" => "Persistence",
            "confidence" => 0.7,
            "mitre_tactics" => ["Persistence"],
            "mitre_techniques" => ["T1547.001"]
          }
        ])

      assert info.rule_type == "persistence"
      assert info.detection_type == "Persistence"
      assert info.confidence == 0.7
      assert info.mitre_tactics == ["Persistence"]
      assert info.mitre_techniques == ["T1547.001"]
    end
  end
end
