defmodule TamanduaServer.ThreatIntel.EmergingActionsTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.ThreatIntel.EmergingActions

  describe "recommend/2" do
    test "maps critical Emerging Threats C2 IP to hunts, actions, and prerequisites" do
      recommendation =
        EmergingActions.recommend(%{
          type: "ip",
          value: "203.0.113.10",
          source: "emerging_threats_emerging_botcc",
          severity: "critical",
          confidence: 0.9,
          tags: ["botnet", "c2", "et"],
          metadata: %{"provider" => "emerging_threats", "feed" => "emerging_botcc"}
        })

      assert recommendation.execution == %{status: "not_executed", reason: "recommendations_only"}
      assert recommendation.threat.feed == "emerging_botcc"

      assert Enum.any?(recommendation.recommended_hunts, &(&1.language == "tql" and &1.query =~ "network.dst_ip"))
      assert Enum.any?(recommendation.recommended_hunts, &(&1.language == "kql" and &1.query =~ "DeviceNetworkEvents"))
      assert Enum.any?(recommendation.recommended_hunts, &(&1.type == "sigma_label"))
      assert Enum.any?(recommendation.recommended_hunts, &("tag:c2" in &1.labels))
      assert Enum.any?(recommendation.recommended_hunts, &(&1.name == "Beaconing around IOC contact"))

      actions = Enum.map(recommendation.recommended_actions, & &1.action)
      assert actions == ["collect_evidence", "block_ioc", "create_case", "create_detection_pack"]

      block = Enum.find(recommendation.recommended_actions, &(&1.action == "block_ioc"))
      assert block.state == "requires_approval"
      assert block.integration_ref == "response.playbook.update_blocklist.ip"
      assert "allowlist_check_required" in block.payload.guardrails

      assert recommendation.prerequisites.supported_ioc_type
      assert recommendation.prerequisites.minimum_confidence_for_blocking
      assert Enum.any?(recommendation.coverage, &(&1.capability == "network flow destination IP visibility"))
      assert Enum.any?(recommendation.safety, &(&1.id == "confidence_gate" and &1.status == "met"))
    end

    test "keeps low confidence Tor domain hunt-only for enforcement" do
      recommendation =
        EmergingActions.recommend(%{
          "type" => "domain",
          "value" => "Exit.Example",
          "source" => "emerging_threats_tor_exit_nodes",
          "severity" => "medium",
          "confidence" => 0.65,
          "tags" => ["tor", "anonymizer"]
        })

      assert recommendation.threat.value == "exit.example"
      refute Enum.any?(recommendation.recommended_actions, &(&1.action == "block_ioc"))
      refute Enum.any?(recommendation.recommended_actions, &(&1.action == "create_case"))
      assert Enum.any?(recommendation.recommended_actions, &(&1.action == "collect_evidence"))
      assert Enum.any?(recommendation.recommended_actions, &(&1.action == "create_detection_pack"))
      assert Enum.any?(recommendation.recommended_hunts, &(&1.name == "Repeated anonymizer egress"))

      refute recommendation.prerequisites.minimum_confidence_for_blocking
      assert Enum.any?(recommendation.safety, &(&1.id == "confidence_gate" and &1.status == "not_met"))
    end

    test "does not recommend block_ioc for file hashes" do
      recommendation =
        EmergingActions.recommend(%{
          type: :sha256,
          value: "ABCDEF",
          source: "malwarebazaar",
          severity: :high,
          confidence: "0.95",
          tags: [:malware]
        })

      assert recommendation.threat.type == "hash_sha256"
      assert recommendation.threat.value == "abcdef"
      assert recommendation.threat.confidence == 0.95

      assert Enum.any?(recommendation.recommended_hunts, &(&1.query =~ "file.hash_sha256"))
      assert Enum.any?(recommendation.recommended_hunts, &(&1.language == "sigma"))
      refute Enum.any?(recommendation.recommended_actions, &(&1.action == "block_ioc"))
      assert Enum.any?(recommendation.recommended_actions, &(&1.action == "create_case"))
      refute recommendation.prerequisites.manual_approval_for_enforcement
    end

    test "escapes quoted IOC values in generated query strings" do
      recommendation =
        EmergingActions.recommend(%{
          type: "domain",
          value: ~s(bad"domain.example),
          source: "emerging_threats",
          severity: "high",
          confidence: 0.8
        })

      tql = Enum.find(recommendation.recommended_hunts, &(&1.language == "tql"))
      kql = Enum.find(recommendation.recommended_hunts, &(&1.language == "kql"))

      assert tql.query =~ ~s("bad\\"domain.example")
      assert kql.query =~ ~s("bad\\"domain.example")
    end
  end

  describe "for_threat/2" do
    test "is an alias for recommend/2" do
      threat = %{type: "ip", value: "198.51.100.5"}

      assert EmergingActions.for_threat(threat) == EmergingActions.recommend(threat)
    end
  end
end
