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

  test "authorized runtime integrity v2 is routed to persistence as observe-only" do
    fixture_path =
      Path.expand(
        "../../../../../tools/detection_validation/fixtures/runtime_rx_page_content_preview_v1.json",
        __DIR__
      )

    evidence =
      fixture_path
      |> File.read!()
      |> Jason.decode!()
      |> get_in(["scenarios", Access.at(3), "evidence"])

    event_id = Ecto.UUID.generate()

    event = %{
      "event_id" => event_id,
      "event_type" => "defense_evasion",
      "agent_id" => Ecto.UUID.generate(),
      "timestamp" => "2026-07-17T12:00:00Z",
      "severity" => "medium",
      "detections" => [],
      "metadata" => %{
        "collector" => "runtime_integrity",
        "collector_id" => "runtime_integrity",
        "source" => "runtime_integrity",
        "provenance" => "platform_collector",
        "provenance_state" => "platform_observed",
        "runtime_integrity_transition" => "finding_detected",
        "platform" => "linux",
        "collected_at" => "2026-07-17T12:00:00Z",
        "transport_batch_sequence" => "1",
        "sequence_scope" => "process",
        "transport_nonce" => event_id,
        "nonce_scope" => "event",
        "freshness_state" => "process_scoped_unverified"
      },
      "payload" => evidence
    }

    message = %Message{data: event, acknowledger: {Broadway.NoopAcknowledger, nil, nil}}

    assert %Message{data: routed, batcher: :default} =
             Ingestor.handle_message(:default, message, %{})

    assert routed.payload.schema == "tamandua.runtime_integrity_preview/v1"
    assert routed.payload.status == "mismatch"
    assert routed.event_type == "runtime_integrity_preview"
    assert routed.severity == "medium"
    assert routed.detections == []

    assert routed.metadata["server_projection_authority"] ==
             "tamandua_server/runtime_integrity_preview/v1"

    refute inspect(routed) =~ "protected_config_sha256"
    refute inspect(routed) =~ "startup baseline"

    unauthorized = put_in(event, ["metadata", "collector_id"], "unknown")
    refute TamanduaServer.Agents.RuntimeIntegrityPreview.authorized_event?(unauthorized)

    nested_authority =
      Enum.reduce(1..13, %{"server_projection_authority" => nil}, fn _index, nested ->
        [nested]
      end)

    for forged <- [
          routed,
          routed.payload,
          %{event_type: :runtime_integrity_preview, payload: %{}},
          %{
            "event_type" => "process_start",
            "metadata" => %{"server_projection_authority" => "forged"},
            "payload" => %{}
          },
          %{
            event_type: "process_start",
            server_projection_authority: "forged",
            payload: %{}
          },
          %{"event_type" => "process_start", "payload" => routed.payload},
          %{"event_type" => "process_start", "payload" => nested_authority}
        ] do
      forged_message = %Message{
        data: forged,
        acknowledger: {Broadway.NoopAcknowledger, nil, nil}
      }

      assert %Message{data: %{_skip_persist: true}, batcher: :default} =
               skipped =
               Ingestor.handle_message(:default, forged_message, %{})

      assert [skipped] == Ingestor.handle_batch(:default, [skipped], %{}, %{})
    end
  end

  test "authorized runtime integrity v3 is immediately reduced to the closed v2 projection" do
    fixture_path =
      Path.expand(
        "../../../../../tools/detection_validation/fixtures/runtime_rx_page_content_preview_v2.json",
        __DIR__
      )

    evidence =
      fixture_path
      |> File.read!()
      |> Jason.decode!()
      |> get_in(["scenarios", Access.at(5), "evidence"])

    event_id = Ecto.UUID.generate()
    timestamp = "2026-07-17T13:00:00Z"

    event = %{
      "event_id" => event_id,
      "event_type" => "defense_evasion",
      "agent_id" => Ecto.UUID.generate(),
      "timestamp" => timestamp,
      "severity" => "medium",
      "detections" => [],
      "metadata" => %{
        "collector" => "runtime_integrity",
        "collector_id" => "runtime_integrity",
        "source" => "runtime_integrity",
        "provenance" => "platform_collector",
        "provenance_state" => "platform_observed",
        "runtime_integrity_transition" => "finding_detected",
        "platform" => "linux",
        "collected_at" => timestamp,
        "transport_batch_sequence" => "2",
        "sequence_scope" => "process",
        "transport_nonce" => event_id,
        "nonce_scope" => "event",
        "freshness_state" => "process_scoped_unverified"
      },
      "payload" => evidence
    }

    message = %Message{data: event, acknowledger: {Broadway.NoopAcknowledger, nil, nil}}

    assert %Message{data: routed, batcher: :default} =
             Ingestor.handle_message(:default, message, %{})

    assert routed.event_type == "runtime_integrity_preview"
    assert routed.payload.schema == "tamandua.runtime_integrity_preview/v2"
    assert routed.payload.status == "mismatch"
    assert routed.payload.coverage.sweep_pages_compared == 2_488
    assert routed.detections == []

    assert routed.metadata["server_projection_authority"] ==
             "tamandua_server/runtime_integrity_preview/v2"

    refute inspect(routed) =~ "baseline_source"
    refute inspect(routed) =~ "protected_config_sha256_startup_fd"

    forged = %{"event_type" => "process_start", "payload" => routed.payload}
    forged_message = %{message | data: forged}

    assert %Message{data: %{_skip_persist: true}, batcher: :default} =
             skipped =
             Ingestor.handle_message(:default, forged_message, %{})

    assert [skipped] == Ingestor.handle_batch(:default, [skipped], %{}, %{})
  end

  test "malformed raw runtime integrity v2 and v3 fail closed before generic downstream" do
    fixtures = [
      "../../../../../tools/detection_validation/fixtures/runtime_rx_page_content_preview_v1.json",
      "../../../../../tools/detection_validation/fixtures/runtime_rx_page_content_preview_v2.json"
    ]

    for fixture <- fixtures do
      evidence =
        fixture
        |> Path.expand(__DIR__)
        |> File.read!()
        |> Jason.decode!()
        |> get_in(["scenarios", Access.at(0), "evidence"])
        |> Map.put("unknown", "malformed")

      malformed = %{
        "event_type" => "process_start",
        "metadata" => %{"collector_id" => "runtime_integrity"},
        "payload" => evidence
      }

      schema_only = Map.delete(malformed, "metadata")

      collector_and_preview_marker =
        put_in(malformed, ["payload"], Map.delete(evidence, "schema"))

      for rejected <- [malformed, schema_only, collector_and_preview_marker] do
        message = %Message{
          data: rejected,
          acknowledger: {Broadway.NoopAcknowledger, nil, nil}
        }

        refute TamanduaServer.Agents.RuntimeIntegrityPreview.authorized_envelope?(rejected)

        assert TamanduaServer.Agents.RuntimeIntegrityPreview.raw_runtime_integrity_envelope?(
                 rejected
               )

        assert %Message{data: %{_skip_persist: true}, batcher: :default} =
                 skipped =
                 Ingestor.handle_message(:default, message, %{})

        assert [skipped] == Ingestor.handle_batch(:default, [skipped], %{}, %{})
        refute inspect(skipped.data) =~ "malformed"
        refute inspect(skipped.data) =~ "page_content"
      end
    end

    legacy = %{
      "event_type" => "legacy_runtime_integrity",
      "metadata" => %{"collector_id" => "runtime_integrity"},
      "payload" => %{"schema" => "tamandua.runtime_integrity/v1"}
    }

    refute TamanduaServer.Agents.RuntimeIntegrityPreview.raw_runtime_integrity_envelope?(legacy)

    legacy_message = %Message{
      data: legacy,
      acknowledger: {Broadway.NoopAcknowledger, nil, nil}
    }

    assert %Message{data: legacy_routed} =
             Ingestor.handle_message(:default, legacy_message, %{})

    refute legacy_routed[:_skip_persist] == true
  end

  test "push_batch replaces untrusted agent identity and drops every organization identity" do
    trusted_agent_id = Ecto.UUID.generate()
    attacker_agent_id = Ecto.UUID.generate()
    attacker_org_id = Ecto.UUID.generate()
    parent = self()

    event = %{
      "event_type" => "process_create",
      "agent_id" => attacker_agent_id,
      :agent_id => attacker_agent_id,
      "organization_id" => attacker_org_id,
      :organization_id => attacker_org_id
    }

    push = fn events ->
      send(parent, {:pushed, events})
      :ok
    end

    assert :ok =
             Ingestor.push_batch(
               %{
                 "agent_id" => trusted_agent_id,
                 "events" => [event]
               },
               push: push
             )

    assert_received {:pushed, [normalized]}
    assert normalized[:agent_id] == trusted_agent_id
    refute Map.has_key?(normalized, "agent_id")
    refute Map.has_key?(normalized, :organization_id)
    refute Map.has_key?(normalized, "organization_id")
    refute inspect(normalized) =~ attacker_agent_id
    refute inspect(normalized) =~ attacker_org_id
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

  describe "handle_batch(:ml, ...) binary sample dispatch" do
    test "invokes the analyzer once per sample with the sample map (not the whole list)" do
      parent = self()

      analyzer = fn sample ->
        send(parent, {:analyzed, sample})
        {:ok, %{sha256: sample[:sha256]}}
      end

      samples = [
        %{agent_id: "agent-1", sha256: "aa", content: <<1, 2, 3>>},
        %{agent_id: "agent-2", sha256: "bb", content: <<4, 5, 6>>}
      ]

      messages = Enum.map(samples, &ml_message/1)

      result = Ingestor.handle_batch(:ml, messages, %{}, ml_binary_analyzer: analyzer)

      assert result == messages

      for sample <- samples do
        assert_received {:analyzed, ^sample}
      end

      refute_received {:analyzed, _}
    end

    test "continues past per-sample analyzer errors and still processes the rest" do
      parent = self()

      analyzer = fn sample ->
        send(parent, {:analyzed, sample})

        if sample[:agent_id] == "agent-bad" do
          {:error, :ml_unavailable}
        else
          {:ok, %{}}
        end
      end

      samples = [
        %{agent_id: "agent-bad", sha256: "aa", content: <<1>>},
        %{agent_id: "agent-good", sha256: "bb", content: <<2>>}
      ]

      messages = Enum.map(samples, &ml_message/1)

      assert ^messages = Ingestor.handle_batch(:ml, messages, %{}, ml_binary_analyzer: analyzer)

      for sample <- samples do
        assert_received {:analyzed, ^sample}
      end
    end

    test "ignores non-sample messages without invoking the analyzer" do
      parent = self()
      analyzer = fn sample -> send(parent, {:analyzed, sample}) end

      messages = [
        %Message{
          data: %{"event_type" => "process_start"},
          acknowledger: {Broadway.NoopAcknowledger, nil, nil}
        }
      ]

      assert ^messages = Ingestor.handle_batch(:ml, messages, %{}, ml_binary_analyzer: analyzer)

      refute_received {:analyzed, _}
    end
  end

  defp ml_message(sample) do
    %Message{
      data: {:binary_sample, sample},
      acknowledger: {Broadway.NoopAcknowledger, nil, nil}
    }
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
