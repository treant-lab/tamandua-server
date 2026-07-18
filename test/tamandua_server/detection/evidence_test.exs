defmodule TamanduaServer.Detection.EvidenceTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.Evidence

  describe "extract/2 consumer metadata" do
    test "preserves explicit degraded network visibility without inventing TLS evidence" do
      evidence =
        Evidence.extract(%{
          payload: %{"remote_ip" => "198.51.100.10", "remote_port" => 443},
          metadata: %{
            "ai_network_risk" => "proxy_or_doh_plus_ai_provider",
            "ai_evidence_limit" => "metadata_only_no_payload_or_bind_proof",
            "network_visibility_state" => "degraded",
            "tls_fingerprints_available" => "false",
            "certificate_visibility" => "unavailable"
          }
        })

      assert evidence.ai_network_risk == "proxy_or_doh_plus_ai_provider"
      assert evidence.ai_evidence_limit == "metadata_only_no_payload_or_bind_proof"
      assert evidence.network_visibility_state == "degraded"
      assert evidence.tls_fingerprints_available == "false"
      assert evidence.certificate_visibility == "unavailable"
      refute Map.has_key?(evidence, :tls_fingerprint)
      refute Map.has_key?(evidence, :certificate)
    end

    test "preserves artifact evidence fields from payload" do
      evidence =
        Evidence.extract(%{
          payload: %{
            "artifact_type" => "mcp_config",
            "redacted_preview" => "tools: [redacted]",
            "matched_patterns" => ["approval_bypass"],
            "risk_indicators" => ["unsigned_source"]
          }
        })

      assert evidence.artifact_type == "mcp_config"
      assert evidence.redacted_preview == "tools: [redacted]"
      assert evidence.matched_patterns == ["approval_bypass"]
      assert evidence.risk_indicators == ["unsigned_source"]
    end
  end

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
        assert %{rule_type: ^expected, source: ^expected, detection_source: ^expected} =
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
      assert info.source == "persistence"
      assert info.detection_source == "persistence"
      assert info.detection_type == "Persistence"
      assert info.confidence == 0.7
      assert info.mitre_tactics == ["Persistence"]
      assert info.mitre_techniques == ["T1547.001"]
    end

    test "marks ML detections as ML source for alert API and GUI filters" do
      info =
        Evidence.extract_detection_info([
          %{
            "rule_name" => "agent_ml_malware_classification",
            "detection_type" => "Ml",
            "confidence" => 0.91,
            "mitre_tactics" => ["execution"],
            "mitre_techniques" => ["T1204"]
          }
        ])

      assert info.rule_type == "ml"
      assert info.source == "ml"
      assert info.detection_source == "ml"
      assert info.detection_type == "Ml"
      assert info.confidence == 0.91
    end
  end
end
