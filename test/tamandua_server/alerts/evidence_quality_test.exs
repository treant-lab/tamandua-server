defmodule TamanduaServer.Alerts.EvidenceQualityTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Alerts.EvidenceQuality

  describe "classify/1" do
    test "marks source-event anchored alerts with evidence and raw event as direct" do
      alert = %{
        source_event_id: "event-1",
        event_ids: ["event-1"],
        evidence: %{
          detection: %{rule_name: "Suspicious Process"},
          process: %{pid: 1234, name: "powershell.exe"}
        },
        raw_event: %{process_name: "powershell.exe"}
      }

      quality = EvidenceQuality.classify(alert)

      assert quality.quality == "direct"
      assert quality.claimable
      assert quality.benchmark_eligible
      assert quality.checks.source_event
      assert quality.checks.evidence_bundle
      assert quality.checks.raw_event
      assert quality.missing == []
    end

    test "marks evidence without persisted source event as derived" do
      alert = %{
        evidence: %{
          "detection" => %{"rule_name" => "ML malware classification"},
          "process" => %{"name" => "sample.exe"}
        },
        raw_event: %{"score" => 0.91}
      }

      quality = EvidenceQuality.classify(alert)

      assert quality.quality == "derived"
      assert quality.claimable
      refute quality.benchmark_eligible
      assert "source_event_id" in quality.missing
    end

    test "marks raw payload without evidence bundle as synthetic" do
      alert = %{
        raw_event: %{"payload" => %{"event_type" => "app_guard_event"}}
      }

      quality = EvidenceQuality.classify(alert)

      assert quality.quality == "synthetic"
      refute quality.claimable
      refute quality.benchmark_eligible
      assert "source_event_id" in quality.missing
      assert "evidence" in quality.missing
    end

    test "treats lists of evidence maps as present context" do
      alert = %{
        evidence: %{
          "detection" => %{"rule_name" => "Suspicious Network Activity"},
          "network" => [%{"remote_ip" => "203.0.113.7"}],
          "file_hashes" => [%{"sha256" => "abc123"}],
          "registry" => [%{"key" => "HKCU\\Software\\Run"}]
        }
      }

      quality = EvidenceQuality.classify(alert)

      assert quality.quality == "derived"
      assert quality.checks.network
      assert quality.checks.file
      assert quality.checks.registry
    end

    test "does not require process evidence for protected-app App Guard telemetry" do
      alert = %{
        source_event_id: "mobile-event-1",
        evidence: app_guard_evidence(%{}),
        raw_event: %{"payload" => %{"schema" => "tamandua.app_guard.event/v1"}}
      }

      quality = EvidenceQuality.classify(alert)

      assert quality.quality == "direct"
      assert quality.checks.app_guard_profile
      assert quality.checks.app_guard_protected_app
      assert quality.checks.app_guard_claim_boundary
      assert quality.checks.app_guard_decision
      assert quality.checks.network
      assert quality.checks.app_guard_iocs
      refute quality.checks.process
      refute "process evidence" in quality.missing
      assert quality.missing == []
    end

    test "keeps App Guard gaps for missing network IOCs and decision" do
      alert = %{
        source_event_id: "mobile-event-2",
        evidence:
          app_guard_evidence(%{
            "app_guard" => %{
              "protected_app" => %{"bundle_id" => "com.example.wallet"}
            },
            "policy" => %{"id" => "policy-1", "mode" => "monitor"},
            "decision_trace" => %{},
            "network" => %{},
            "iocs" => []
          }),
        raw_event: %{"payload" => %{"schema" => "tamandua.app_guard.event/v1"}}
      }

      quality = EvidenceQuality.classify(alert)

      assert quality.quality == "direct"
      refute quality.claimable
      refute quality.benchmark_eligible
      assert quality.checks.app_guard_profile
      refute quality.checks.app_guard_decision
      refute quality.checks.network
      refute quality.checks.app_guard_iocs
      refute "process evidence" in quality.missing
      assert "network evidence" in quality.missing
      assert "IOC evidence" in quality.missing
      assert "policy decision" in quality.missing
    end

    test "reports missing App Guard claim boundary without falling back to process evidence" do
      alert = %{
        source_event_id: "mobile-event-3",
        evidence: Map.delete(app_guard_evidence(%{}), "claim_boundary"),
        raw_event: %{"payload" => %{"schema" => "tamandua.app_guard.event/v1"}}
      }

      quality = EvidenceQuality.classify(alert)

      assert quality.quality == "direct"
      refute quality.claimable
      refute quality.benchmark_eligible
      assert quality.checks.app_guard_protected_app
      refute quality.checks.app_guard_profile
      refute quality.checks.app_guard_claim_boundary
      refute "process evidence" in quality.missing
      assert "claim boundary" in quality.missing
      assert quality.investigation_context.fields.process == "not_applicable"
    end

    test "still requires process evidence for endpoint alerts" do
      alert = %{
        source_event_id: "event-2",
        evidence: %{
          "detection" => %{"rule_name" => "Suspicious Endpoint Activity"},
          "network" => %{"remote_ip" => "203.0.113.9"}
        },
        raw_event: %{"event_type" => "network_connect"}
      }

      quality = EvidenceQuality.classify(alert)

      assert quality.quality == "direct"
      refute quality.checks.app_guard_profile
      refute quality.checks.process
      assert "process evidence" in quality.missing
    end

    test "marks alerts without provenance as missing" do
      quality = EvidenceQuality.classify(%{})

      assert quality.quality == "missing"
      refute quality.claimable
      refute quality.benchmark_eligible
      assert "source_event_id" in quality.missing
      assert "evidence" in quality.missing
      assert "raw_event" in quality.missing
    end

    test "reports partial endpoint investigation context without treating gaps as collected" do
      alert = %{
        evidence: %{
          "process" => %{"pid" => 4242, "name" => "sample.exe"},
          "detection" => %{"rule_id" => "rule-1"}
        },
        raw_event: %{"event_type" => "process_create"}
      }

      quality = EvidenceQuality.classify(alert)
      context = quality.investigation_context

      assert context.state == "partial"
      assert context.fields.process == "collected"
      assert context.fields.parent_process == "not_collected"
      assert context.fields.command_line == "not_collected"
      assert context.fields.network == "not_collected"
      assert context.missing == ["command line", "network context", "parent process"]
    end

    test "marks App Guard process fields not applicable instead of missing" do
      alert = %{
        evidence: app_guard_evidence(%{}),
        raw_event: %{"event_type" => "app_guard"}
      }

      context = EvidenceQuality.classify(alert).investigation_context

      assert context.state == "ready"
      assert context.fields.process == "not_applicable"
      assert context.fields.parent_process == "not_applicable"
      assert context.fields.command_line == "not_applicable"
      assert context.fields.network == "collected"
      assert context.missing == []
    end

    test "scores missing evidence as uncertain FP signal without claiming benign context" do
      triage = EvidenceQuality.classify(%{}).false_positive_triage

      assert triage.level == "low"
      assert triage.confidence == "low"
      assert Enum.any?(triage.fp_signals, &(&1.key == :missing_evidence))
      assert Enum.any?(triage.limitations, &String.contains?(&1, "missing evidence"))
      assert triage.summary =~ "uncertain"
    end

    test "raises FP likelihood for trusted goodware and prevalent benign metadata" do
      alert = %{
        source_event_id: "event-goodware-1",
        event_ids: ["event-goodware-1"],
        evidence: %{
          "detection" => %{"rule_name" => "Suspicious child process"},
          "process" => %{
            "pid" => 1200,
            "name" => "notepad.exe",
            "path" => "C:\\Windows\\System32\\notepad.exe",
            "is_signed" => true,
            "signer" => "Microsoft Corporation",
            "signature_status" => "valid"
          },
          "reputation" => %{
            "verdict" => "goodware",
            "prevalence" => "high",
            "known_good" => true
          }
        },
        raw_event: %{"process_name" => "notepad.exe", "path" => "C:\\Windows\\System32\\notepad.exe"}
      }

      triage = EvidenceQuality.classify(alert).false_positive_triage

      assert triage.level == "high"
      assert triage.confidence == "high"
      assert Enum.any?(triage.fp_signals, &(&1.key == :trusted_signer))
      assert Enum.any?(triage.fp_signals, &(&1.key == :benign_reputation))
      assert Enum.any?(triage.fp_signals, &(&1.key == :high_prevalence))
      assert Enum.any?(triage.fp_signals, &(&1.key == :trusted_install_path))
      assert triage.counter_signals == []
    end

    test "keeps FP likelihood low when suspicious command and IOC evidence are present" do
      alert = %{
        source_event_id: "event-suspicious-1",
        event_ids: ["event-suspicious-1"],
        evidence: %{
          "detection" => %{"rule_name" => "Encoded PowerShell"},
          "process" => %{
            "pid" => 991,
            "name" => "powershell.exe",
            "path" => "C:\\Users\\Public\\powershell.exe",
            "command_line" => "powershell.exe -EncodedCommand SQBFAFgA",
            "is_signed" => false
          },
          "network" => [%{"remote_ip" => "203.0.113.45", "domain" => "payload.example.xyz"}],
          "iocs" => [%{"type" => "ip", "value" => "203.0.113.45"}]
        },
        raw_event: %{"process_name" => "powershell.exe"}
      }

      triage = EvidenceQuality.classify(alert).false_positive_triage

      assert triage.level == "low"
      assert Enum.any?(triage.counter_signals, &(&1.key == :unsigned_binary))
      assert Enum.any?(triage.counter_signals, &(&1.key == :suspicious_path))
      assert Enum.any?(triage.counter_signals, &(&1.key == :suspicious_process_or_command))
      assert Enum.any?(triage.counter_signals, &(&1.key == :suspicious_network_context))
      assert Enum.any?(triage.counter_signals, &(&1.key == :ioc_evidence_present))
    end

    test "adds App Guard limitation signal when protected-app scope is incomplete" do
      alert = %{
        source_event_id: "mobile-event-fp",
        evidence: Map.delete(app_guard_evidence(%{}), "claim_boundary"),
        raw_event: %{"event_type" => "app_guard"}
      }

      triage = EvidenceQuality.classify(alert).false_positive_triage

      assert triage.confidence in ["low", "medium"]
      assert Enum.any?(triage.fp_signals, &(&1.key == :app_guard_scope_unclear))
      assert Enum.any?(triage.limitations, &String.contains?(&1, "App Guard telemetry"))
    end
  end

  defp app_guard_evidence(overrides) do
    Map.merge(
      %{
        "detection" => %{"rule_name" => "App Guard debugger_detected"},
        "app_guard" => %{
          "protected_app" => %{"bundle_id" => "com.example.wallet"},
          "decision" => %{"decision" => "step_up"},
          "domain" => "wallet.example"
        },
        "policy" => %{"id" => "policy-1", "mode" => "monitor", "decision" => "step_up"},
        "decision_trace" => %{"decision" => "step_up", "source" => "app_guard_sdk"},
        "network" => %{"domain" => "wallet.example"},
        "iocs" => [%{"type" => "package", "value" => "com.example.wallet"}],
        "claim_boundary" => "protected-app App Guard telemetry; not full mobile EDR device-wide visibility"
      },
      overrides
    )
  end
end
