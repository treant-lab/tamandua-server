defmodule TamanduaServer.Telemetry.IngestorTest do
  use ExUnit.Case, async: false

  alias Broadway.Message
  alias TamanduaServer.Detection.Evidence
  alias TamanduaServer.Telemetry.Ingestor

  setup do
    previous = System.get_env("TAMANDUA_AGENT_DETECTION_ALERTS")
    System.put_env("TAMANDUA_AGENT_DETECTION_ALERTS", "false")

    on_exit(fn ->
      if is_nil(previous) do
        System.delete_env("TAMANDUA_AGENT_DETECTION_ALERTS")
      else
        System.put_env("TAMANDUA_AGENT_DETECTION_ALERTS", previous)
      end
    end)
  end

  describe "timeline severity normalization for contextless ETW tamper detections" do
    test "downgrades high ETW tamper without actionable context and records adjustment reason" do
      event =
        base_event([
          %{
            "rule_name" => "etw_patch_detected",
            "mitre_techniques" => ["T1562.006"]
          }
        ])

      normalized = ingest(event)

      assert normalized[:severity] == "medium"
      assert normalized["severity"] == "medium"
      assert enrichment(normalized)["timeline_severity_adjusted"] == true
      assert enrichment(normalized)["original_severity"] == "high"
      assert enrichment(normalized)["adjusted_severity"] == "medium"
      assert enrichment(normalized)["timeline_adjustment_reason"] ==
               "etw_tamper_missing_actionable_context"
    end

    test "keeps high ETW tamper severity when metadata contains process context" do
      event =
        base_event(
          [
            %{
              "rule_name" => "etw_patch_detected",
              "mitre_techniques" => ["T1562.006"]
            }
          ],
          %{"metadata" => %{"process_name" => "rundll32.exe"}}
        )

      normalized = ingest(event)

      assert normalized[:severity] == "high"
      refute enrichment(normalized)["timeline_severity_adjusted"]
    end

    test "keeps high ETW tamper severity when enrichment contains provider context" do
      event =
        base_event(
          [
            %{
              "rule_name" => "etw_patch_detected",
              "mitre_techniques" => ["T1562.006"]
            }
          ],
          %{"enrichment" => %{"provider_name" => "Microsoft-Windows-Threat-Intelligence"}}
        )

      normalized = ingest(event)

      assert normalized[:severity] == "high"
      refute enrichment(normalized)["timeline_severity_adjusted"]
    end
  end

  describe "agent ML detection contract" do
    test "preserves high severity for ML detection events" do
      event =
        base_event(
          [
            %{
              "detection_type" => "ml",
              "rule_name" => "ML_MALWARE_TROJAN",
              "confidence" => 1.0,
              "description" => "ML model detected trojan malware",
              "mitre_tactics" => ["execution"],
              "mitre_techniques" => ["T1204"]
            }
          ],
          %{
            "event_type" => "file_create",
            "severity" => "critical",
            "payload" => %{
              "path" => "D:\\ProgramData\\Tamandua\\ml-bench\\samples\\malware_00000.bin",
              "ml_verdict" => "trojan",
              "model_version" => "malware_smell_knn"
            }
          }
        )

      normalized = ingest(event)

      assert normalized[:severity] == "critical"
      assert normalized["severity"] == "critical"
      refute enrichment(normalized)["timeline_severity_adjusted"]
    end

    test "extracts ml source metadata from agent detection payload" do
      metadata =
        Evidence.extract_detection_info([
          %{
            "detection_type" => "ml",
            "rule_name" => "ML_MALWARE_TROJAN",
            "confidence" => 1.0,
            "description" => "ML model detected trojan malware"
          }
        ])

      assert metadata.source == "ml"
      assert metadata.detection_source == "ml"
      assert metadata.detection_type == "ml"
      assert metadata.rule_name == "ML_MALWARE_TROJAN"
      assert metadata.confidence == 1.0
    end
  end

  describe "timeline severity normalization for contextless ntdll writes" do
    test "downgrades high ntdll write without target context and records adjustment reason" do
      event = base_event([%{"rule_name" => "ntdll_write_ntwritevirtualmemory"}])

      normalized = ingest(event)

      assert normalized[:severity] == "medium"
      assert normalized["severity"] == "medium"
      assert enrichment(normalized)["timeline_severity_adjusted"] == true
      assert enrichment(normalized)["original_severity"] == "high"
      assert enrichment(normalized)["adjusted_severity"] == "medium"
      assert enrichment(normalized)["timeline_adjustment_reason"] ==
               "ntdll_write_missing_target_context"
    end

    test "keeps high ntdll write severity when metadata contains target context" do
      event =
        base_event(
          [%{"rule_name" => "ntdll_write_ntwritevirtualmemory"}],
          %{"metadata" => %{"target_process_name" => "lsass.exe"}}
        )

      normalized = ingest(event)

      assert normalized[:severity] == "high"
      refute enrichment(normalized)["timeline_severity_adjusted"]
    end

    test "keeps high ntdll write severity when enrichment contains target context" do
      event =
        base_event(
          [%{"rule_name" => "ntdll_write_ntwritevirtualmemory"}],
          %{"enrichment" => %{"target_address" => "0x7ffb00001234"}}
        )

      normalized = ingest(event)

      assert normalized[:severity] == "high"
      refute enrichment(normalized)["timeline_severity_adjusted"]
    end

    test "downgrades self-targeted image writes with no memory permission transition" do
      event =
        base_event(
          [%{"rule_name" => "ntdll_write_writeprocessmemory"}],
          %{
            "enrichment" => %{
              "metadata" => %{
                "source_pid" => "4242",
                "target_pid" => "4242",
                "mem_type_str" => "MEM_IMAGE",
                "old_protection_str" => "PAGE_EXECUTE_READ",
                "new_protection_str" => "PAGE_EXECUTE_READ",
                "target_function" => "ntdll.dll!.text",
                "thread_from_unbacked" => false,
                "thread_start_address" => nil
              }
            }
          }
        )

      normalized = ingest(event)

      assert normalized[:severity] == "medium"
      assert normalized["severity"] == "medium"
      assert enrichment(normalized)["timeline_severity_adjusted"] == true
      assert enrichment(normalized)["original_severity"] == "high"
      assert enrichment(normalized)["adjusted_severity"] == "medium"
      assert enrichment(normalized)["timeline_adjustment_reason"] ==
               "ntdll_self_write_no_permission_transition"
    end

    test "keeps high ntdll self-targeted writes when protection changes to RWX" do
      event =
        base_event(
          [%{"rule_name" => "ntdll_write_writeprocessmemory"}],
          %{
            "enrichment" => %{
              "metadata" => %{
                "source_pid" => "4242",
                "target_pid" => "4242",
                "mem_type_str" => "MEM_IMAGE",
                "old_protection_str" => "PAGE_READWRITE",
                "new_protection_str" => "PAGE_EXECUTE_READWRITE",
                "target_function" => "ntdll.dll!.text"
              }
            }
          }
        )

      normalized = ingest(event)

      assert normalized[:severity] == "high"
      refute enrichment(normalized)["timeline_severity_adjusted"]
    end
  end

  defp base_event(detections, overrides \\ %{}) do
    Map.merge(
      %{
        "event_id" => Ecto.UUID.generate(),
        "event_type" => "defense_evasion",
        "severity" => "high",
        "payload" => %{},
        "detections" => detections
      },
      overrides
    )
  end

  defp ingest(event) do
    message = %Message{
      data: event,
      acknowledger: {Broadway.NoopAcknowledger, nil, nil}
    }

    assert %Message{data: normalized} = Ingestor.handle_message(:default, message, %{})
    normalized
  end

  defp enrichment(event), do: event[:enrichment] || event["enrichment"] || %{}
end
