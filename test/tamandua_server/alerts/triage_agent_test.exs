defmodule TamanduaServer.Alerts.TriageAgentTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Alerts.TriageAgent

  describe "build/1" do
    test "builds a structured triage contract with evidence gaps and pivots" do
      alert = %{
        severity: "high",
        title: "Agent detection: suspicious PowerShell",
        threat_score: 0.86,
        source_event_id: "event-1",
        agent_id: "agent-1",
        evidence: %{
          "detection" => %{"rule_name" => "Encoded PowerShell", "source" => "agent"},
          "process" => %{"pid" => 4242, "name" => "powershell.exe"}
        },
        raw_event: %{"event_type" => "process_create"},
        detection_metadata: %{
          "source" => "agent",
          "investigation_enrichment" => %{
            "needed" => true,
            "status" => "planned",
            "missing_context" => ["command line"],
            "requested_actions" => ["process_tree_list", "network_connections"]
          }
        },
        mitre_techniques: ["T1059.001"]
      }

      triage = TriageAgent.build(alert)

      assert triage["schema_version"] == "alert-triage/v1"
      assert triage["status"] == "needs_evidence"
      assert triage["evidence_strength"]["level"] == "direct"
      assert triage["false_positive_likelihood"]["label"] == "low"
      assert triage["confidence"] > 0.6
      assert triage["hypothesis"] =~ "T1059.001"
      assert Enum.any?(triage["gaps"], &(&1["field"] == "command line"))
      assert Enum.any?(triage["recommended_pivots"], &(&1["action"] == "collect_command_line"))
      assert Enum.any?(triage["recommended_pivots"], &(&1["action"] == "process_tree_list"))
      assert Enum.any?(triage["recommended_pivots"], &(&1["action"] == "review_response_actions"))
    end

    test "marks reduced weak alerts as false positive candidates without suppressing them" do
      alert = %{
        severity: "info",
        title: "Agent detection: behavioral unusual execution time",
        threat_score: 0.2,
        severity_adjusted: true,
        false_positive_notes: "benign_unusual_execution_time_structured",
        raw_event: %{"event_type" => "process_create"}
      }

      triage = TriageAgent.build(alert)

      assert triage["status"] == "false_positive_candidate"
      assert triage["false_positive_likelihood"]["label"] == "high"
      assert "severity_was_adjusted" in triage["false_positive_likelihood"]["basis"]
      assert triage["recommended_response"] =~ "Do not auto-contain"
    end
  end

  describe "attach_contract/1" do
    test "persists triage under enrichment without replacing explicit triage" do
      attrs = %{
        severity: "medium",
        title: "Network connect",
        enrichment: %{"triage" => %{"status" => "manual_override"}}
      }

      assert TriageAgent.attach_contract(attrs) == attrs
    end

    test "adds triage to attrs enrichment" do
      attrs = %{
        severity: "medium",
        title: "Network connect",
        evidence: %{"detection" => %{"rule_name" => "DoH"}, "network" => %{"remote_ip" => "8.8.8.8"}},
        raw_event: %{"event_type" => "network_connect"}
      }

      updated = TriageAgent.attach_contract(attrs)

      assert get_in(updated, [:enrichment, "triage", "schema_version"]) == "alert-triage/v1"
      assert get_in(updated, [:enrichment, "triage", "recommended_pivots"]) |> is_list()
    end
  end
end
