defmodule TamanduaServer.Detection.EtwTamperingHandlerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Detection.EtwTamperingHandler
  alias TamanduaServer.Detection.EventTypes

  describe "etw_tampering_event?/1" do
    test "returns true for ETW tampering event types" do
      assert EtwTamperingHandler.etw_tampering_event?("etw_tampering")
      assert EtwTamperingHandler.etw_tampering_event?("etw_prologue_patched")
      assert EtwTamperingHandler.etw_tampering_event?("ntdll_stub_modified")
      assert EtwTamperingHandler.etw_tampering_event?("fresh_ntdll_mapping")
      assert EtwTamperingHandler.etw_tampering_event?("ntdll_write_detected")
      assert EtwTamperingHandler.etw_tampering_event?("syscall_region_tampered")
    end

    test "returns true for atom event types" do
      assert EtwTamperingHandler.etw_tampering_event?(:etw_tampering)
      assert EtwTamperingHandler.etw_tampering_event?(:etw_prologue_patched)
    end

    test "returns false for non-ETW event types" do
      refute EtwTamperingHandler.etw_tampering_event?("process_create")
      refute EtwTamperingHandler.etw_tampering_event?("file_modify")
      refute EtwTamperingHandler.etw_tampering_event?("network_connect")
      refute EtwTamperingHandler.etw_tampering_event?(nil)
    end
  end

  describe "extract_details/1" do
    test "extracts ETW tampering details from payload" do
      payload = %{
        "target_function" => "NtTraceEvent",
        "original_bytes" => <<0x4C, 0x8B, 0xD1>>,
        "patched_bytes" => <<0x31, 0xC0, 0xC3>>,
        "patch_pattern" => "xor_eax_ret",
        "target_region" => "syscall_stub",
        "detection_method" => "prologue_scan",
        "process_name" => "malware.exe",
        "process_id" => 1234
      }

      details = EtwTamperingHandler.extract_details(payload)

      assert details.target_function == "NtTraceEvent"
      assert details.original_bytes == <<0x4C, 0x8B, 0xD1>>
      assert details.patched_bytes == <<0x31, 0xC0, 0xC3>>
      assert details.patch_pattern == "xor_eax_ret"
      assert details.target_region == "syscall_stub"
      assert details.detection_method == "prologue_scan"
      assert details.process_name == "malware.exe"
      assert details.process_id == 1234
    end

    test "classifies patch pattern from bytes when not provided" do
      payload = %{
        "target_function" => "NtTraceEvent",
        "patched_bytes" => <<0xC3, 0x00, 0x00>>
      }

      details = EtwTamperingHandler.extract_details(payload)
      assert details.patch_pattern == "ret"
    end

    test "classifies xor_eax_ret pattern from bytes" do
      payload = %{
        "target_function" => "NtTraceEvent",
        "patched_bytes" => <<0x31, 0xC0, 0xC3>>
      }

      details = EtwTamperingHandler.extract_details(payload)
      assert details.patch_pattern == "xor_eax_ret"
    end

    test "classifies jmp_rel32 pattern from bytes" do
      payload = %{
        "target_function" => "NtTraceEvent",
        "patched_bytes" => <<0xE9, 0x12, 0x34, 0x56, 0x78>>
      }

      details = EtwTamperingHandler.extract_details(payload)
      assert details.patch_pattern == "jmp_rel32"
    end

    test "classifies target region from function name" do
      assert EtwTamperingHandler.extract_details(%{"target_function" => "NtTraceEvent"}).target_region == "syscall_stub"
      assert EtwTamperingHandler.extract_details(%{"target_function" => "EtwEventWrite"}).target_region == "etw_function"
      assert EtwTamperingHandler.extract_details(%{"target_function" => "AmsiScanBuffer"}).target_region == "amsi_function"
    end
  end

  describe "build_detections/1" do
    test "builds detection entries for ETW tampering events" do
      event = %{
        event_type: "etw_prologue_patched",
        agent_id: Ecto.UUID.generate(),
        payload: %{
          "target_function" => "NtTraceEvent",
          "patch_pattern" => "xor_eax_ret"
        }
      }

      detections = EtwTamperingHandler.build_detections(event)

      assert length(detections) == 1
      detection = hd(detections)

      assert detection.type == :etw_tampering
      assert detection.rule_id == "tamandua-etw-patch-001"
      assert detection.severity == "critical"
      assert "T1562.006" in detection.mitre_techniques
      assert "defense-evasion" in detection.mitre_tactics
    end
  end

  describe "process_event/1" do
    test "returns error for missing agent_id" do
      event = %{payload: %{target_function: "NtTraceEvent"}}
      assert {:error, :missing_agent_id} = EtwTamperingHandler.process_event(event)
    end

    test "returns error for nil agent_id" do
      event = %{agent_id: nil, payload: %{target_function: "NtTraceEvent"}}
      assert {:error, :missing_agent_id} = EtwTamperingHandler.process_event(event)
    end
  end

  describe "binary handling" do
    test "handles list input for patched_bytes" do
      payload = %{"patched_bytes" => [0xC3, 0x00, 0x00]}
      details = EtwTamperingHandler.extract_details(payload)
      assert details.patched_bytes == <<0xC3, 0x00, 0x00>>
    end

    test "handles invalid list gracefully" do
      payload = %{"patched_bytes" => ["invalid", :atom]}
      details = EtwTamperingHandler.extract_details(payload)
      assert details.patched_bytes == nil
    end
  end

  describe "timestamp handling" do
    test "uses fallback timestamp for malformed input" do
      payload = %{"timestamp" => "not-a-timestamp"}
      details = EtwTamperingHandler.extract_details(payload)
      assert %DateTime{} = details.timestamp
    end
  end

  describe "EventTypes integration" do
    test "ETW tampering event types are recognized" do
      assert EventTypes.normalize("etw_tampering") == :etw_tampering
      assert EventTypes.normalize("etw_prologue_patched") == :etw_prologue_patched
      assert EventTypes.normalize("ntdll_stub_modified") == :ntdll_stub_modified
    end

    test "ETW tampering events have defense_evasion category" do
      assert EventTypes.category(:etw_tampering) == :defense_evasion
      assert EventTypes.category(:etw_prologue_patched) == :defense_evasion
      assert EventTypes.category(:syscall_region_tampered) == :defense_evasion
    end

    test "etw_tampering? helper works" do
      assert EventTypes.etw_tampering?(:etw_tampering)
      assert EventTypes.etw_tampering?(:etw_prologue_patched)
      refute EventTypes.etw_tampering?(:process_create)
    end
  end
end
