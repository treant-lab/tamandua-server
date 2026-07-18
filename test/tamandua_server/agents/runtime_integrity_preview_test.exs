defmodule TamanduaServer.Agents.RuntimeIntegrityPreviewTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Agents.RuntimeIntegrityPreview

  @fixture_path Path.expand(
                  "../../../../../tools/detection_validation/fixtures/runtime_rx_page_content_preview_v1.json",
                  __DIR__
                )
  @fixture_v2_path Path.expand(
                     "../../../../../tools/detection_validation/fixtures/runtime_rx_page_content_preview_v2.json",
                     __DIR__
                   )
  @schema_v2_path Path.expand(
                    "../../../../../schemas/runtime_rx_page_content_preview_v2.schema.json",
                    __DIR__
                  )
  @fixture_v2_sha256 "e1e93c2b6d7345cdf004669e950742382a3181aaf91d5cccd7082a6b50307fba"
  @schema_v2_sha256 "24ff9b6b7e66d4c7a7951fb24d742e77ae3f466dfb4ec134780219d827209b99"

  test "consumes the frozen v3 evidence and emits the exact closed v2 UI projection" do
    assert sha256(@fixture_v2_path) == @fixture_v2_sha256
    assert sha256(@schema_v2_path) == @schema_v2_sha256

    fixture = fixture_v2()
    assert fixture["runtime_schema"] == "tamandua.runtime_integrity/v3"
    assert fixture["server_projection_schema"] == "tamandua.runtime_integrity_preview/v2"

    for scenario <- fixture["scenarios"] do
      observed_at = "2026-07-17T13:00:00Z"
      evidence = scenario["evidence"]

      assert {:ok, projection} =
               RuntimeIntegrityPreview.project(evidence, observed_at: observed_at)

      assert projection.schema == "tamandua.runtime_integrity_preview/v2"
      assert projection.capability_id == "linux_self_file_backed_elf_rx_page_content_preview_v2"
      assert projection.external_claim_allowed == false
      assert projection.maturity == "preview"
      assert projection.mode == "observe_only"
      assert projection.observed_at == observed_at

      assert Map.keys(projection) |> Enum.sort() ==
               ~w(capability_id coverage enabled external_claim_allowed finding_kinds limitations maturity mode observed_at runtime_state schema status)a
               |> Enum.sort()

      assert Map.keys(projection.coverage) |> Enum.sort() ==
               ~w(budget_limit_us budget_state elapsed_us_this_tick eligible_pages excluded_relocation_pages full_sweep_completed memory_bytes_read_this_tick pages_compared_this_tick sweep_pages_compared unstable_pages_this_tick)a
               |> Enum.sort()

      refute inspect(projection) =~ "baseline_source"
      refute inspect(projection) =~ "protected_config_sha256"
      assert {:ok, ^projection} = RuntimeIntegrityPreview.project(projection)

      raw_event = event_v2(evidence, observed_at)
      assert RuntimeIntegrityPreview.authorized_envelope?(raw_event)
      assert {:ok, canonical} = RuntimeIntegrityPreview.canonical_event(raw_event)
      assert canonical.payload == projection
      assert canonical.event_type == RuntimeIntegrityPreview.canonical_event_type()

      assert canonical.metadata[RuntimeIntegrityPreview.authority_key()] ==
               RuntimeIntegrityPreview.authority_value(projection.schema)

      assert RuntimeIntegrityPreview.server_authorized_canonical_event?(canonical)
    end
  end

  test "v3 rejects malformed progress, IO, completion, cause and privacy relations" do
    partial = scenario_v2("eligible-17-first-tick")["evidence"]
    clean = scenario_v2("eligible-17-full-clean")["evidence"]
    mismatch = scenario_v2("release-4964-mismatch")["evidence"]
    identity_race = scenario_v2("unstable-double-read-degraded")["evidence"]
    capacity = scenario_v2("capacity-8193-degraded")["evidence"]

    invalid = [
      put_in(partial, ["page_content", "sweep_pages_compared"], 18),
      put_in(partial, ["page_content", "pages_compared_this_tick"], 9),
      put_in(partial, ["page_content", "memory_bytes_read_this_tick"], 61_440),
      put_in(partial, ["page_content", "full_sweep_completed"], true),
      put_in(clean, ["page_content", "full_sweep_completed"], false),
      Map.put(partial, "limitations", ["rx_page_content_budget_exceeded"]),
      Map.put(partial, "limitations", [
        "rx_page_content_anonymous_jit_out_of_scope",
        "rx_page_content_budget_exceeded"
      ]),
      Map.put(mismatch, "findings", []),
      Map.put(identity_race, "limitations", ["rx_page_content_memory_read_unavailable"]),
      put_in(capacity, ["page_content", "baseline_source"], "protected_config_sha256_startup_fd"),
      put_in(partial, ["page_content", "path"], "/private/runtime"),
      put_in(partial, ["page_content", "unknown"], true)
    ]

    for evidence <- invalid do
      assert {:error, :invalid_contract} = RuntimeIntegrityPreview.project(evidence)

      refute RuntimeIntegrityPreview.authorized_envelope?(
               event_v2(evidence, "2026-07-17T13:00:00Z")
             )
    end
  end

  test "v3 transitions are coherent and recovered cannot mask findings or degradation" do
    benign = scenario_v2("eligible-17-first-tick")["evidence"]
    mismatch = scenario_v2("release-4964-mismatch")["evidence"]
    degraded = scenario_v2("tick-budget-degraded")["evidence"]
    timestamp = "2026-07-17T13:00:00Z"

    assert RuntimeIntegrityPreview.authorized_envelope?(
             event_v2(benign, timestamp, "collector_observed")
           )

    assert RuntimeIntegrityPreview.authorized_envelope?(event_v2(benign, timestamp, "recovered"))

    for {evidence, invalid_transition} <- [
          {mismatch, "collector_observed"},
          {mismatch, "recovered"},
          {degraded, "collector_observed"},
          {degraded, "recovered"},
          {benign, "finding_changed"},
          {benign, "collector_degraded"}
        ] do
      refute RuntimeIntegrityPreview.authorized_envelope?(
               event_v2(evidence, timestamp, invalid_transition)
             )
    end
  end

  test "direct v2 projection and its authority are reserved against inbound forgery" do
    evidence = scenario_v2("release-4964-full-clean")["evidence"]

    assert {:ok, projection} =
             RuntimeIntegrityPreview.project(evidence, observed_at: "2026-07-17T13:00:00Z")

    assert {:ok, ^projection} = RuntimeIntegrityPreview.project(projection)

    assert {:error, :invalid_contract} =
             projection |> Map.put(:unknown, true) |> RuntimeIntegrityPreview.project()

    for forged <- [
          projection,
          %{"event_type" => "process_start", "payload" => projection},
          %{
            "event_type" => "process_start",
            "metadata" => %{
              "server_projection_authority" => "tamandua_server/runtime_integrity_preview/v2"
            }
          },
          %{"safe" => "tamandua.runtime_integrity_preview/v2"},
          %{"safe" => :"tamandua_server/runtime_integrity_preview/v2"}
        ] do
      assert RuntimeIntegrityPreview.reserved_inbound?(forged)
      refute RuntimeIntegrityPreview.authorized_envelope?(forged)
    end
  end

  test "canonical authority never accepts raw, unknown, missing or cross-version authority" do
    timestamp = "2026-07-17T13:00:00Z"
    raw_v1 = event(scenario("full-sweep-clean")["evidence"], timestamp)
    raw_v2 = event_v2(scenario_v2("eligible-17-full-clean")["evidence"], timestamp)

    for raw <- [raw_v1, raw_v2] do
      forged = %{
        event_type: RuntimeIntegrityPreview.canonical_event_type(),
        timestamp: timestamp,
        payload: raw["payload"],
        metadata: %{"collector_id" => "runtime_integrity"}
      }

      refute RuntimeIntegrityPreview.server_authorized_canonical_event?(forged)
    end

    assert {:ok, canonical_v1} = RuntimeIntegrityPreview.canonical_event(raw_v1)
    assert {:ok, canonical_v2} = RuntimeIntegrityPreview.canonical_event(raw_v2)

    for invalid <- [
          Map.delete(canonical_v1, :metadata),
          put_in(canonical_v1, [:metadata, RuntimeIntegrityPreview.authority_key()], nil),
          put_in(
            canonical_v1,
            [:metadata, RuntimeIntegrityPreview.authority_key()],
            RuntimeIntegrityPreview.authority_value("tamandua.runtime_integrity_preview/v2")
          ),
          put_in(
            canonical_v2,
            [:metadata, RuntimeIntegrityPreview.authority_key()],
            RuntimeIntegrityPreview.authority_value("tamandua.runtime_integrity_preview/v1")
          ),
          %{canonical_v2 | payload: Map.put(canonical_v2.payload, :schema, "unknown")}
        ] do
      refute RuntimeIntegrityPreview.server_authorized_canonical_event?(invalid)
    end

    assert RuntimeIntegrityPreview.server_authorized_canonical_event?(canonical_v1)
    assert RuntimeIntegrityPreview.server_authorized_canonical_event?(canonical_v2)
  end

  test "raw envelope recognition closes exact schemas and marked preview envelopes only" do
    for schema <- ["tamandua.runtime_integrity/v2", "tamandua.runtime_integrity/v3"] do
      assert RuntimeIntegrityPreview.raw_runtime_integrity_envelope?(%{
               "metadata" => %{"collector_id" => "runtime_integrity"},
               "payload" => %{"schema" => schema}
             })

      assert RuntimeIntegrityPreview.raw_runtime_integrity_envelope?(%{
               "metadata" => %{"collector_id" => "process"},
               "payload" => %{"schema" => schema}
             })
    end

    assert RuntimeIntegrityPreview.raw_runtime_integrity_envelope?(%{
             "metadata" => %{"collector_id" => "runtime_integrity"},
             "payload" => %{
               "schema" => "unknown",
               "page_content" => %{
                 "capability_id" => "linux_self_file_backed_elf_rx_page_content_preview_v2"
               }
             }
           })

    for payload <- [
          %{"schema" => "tamandua.runtime_integrity/v1"},
          %{"schema" => "tamandua.runtime_integrity_preview/v2"},
          %{"event" => "legacy_generic"}
        ] do
      refute RuntimeIntegrityPreview.raw_runtime_integrity_envelope?(%{
               "metadata" => %{"collector_id" => "runtime_integrity"},
               "payload" => payload
             })
    end
  end

  test "projects every canonical synthetic scenario into the closed privacy shape" do
    for scenario <- fixture()["scenarios"] do
      assert {:ok, projection} = RuntimeIntegrityPreview.project(scenario["evidence"])
      assert projection.schema == "tamandua.runtime_integrity_preview/v1"
      assert projection.external_claim_allowed == false
      assert projection.capability_id == "linux_self_file_backed_elf_rx_page_content_preview_v1"
      assert projection.maturity == "preview"
      assert projection.mode == "observe_only"
      assert projection.observed_at == nil

      assert Map.keys(projection) |> Enum.sort() ==
               ~w(capability_id coverage enabled external_claim_allowed finding_kinds limitations maturity mode observed_at runtime_state schema status)a
               |> Enum.sort()

      assert Map.keys(projection.coverage) |> Enum.sort() ==
               ~w(budget_limit_us budget_state bytes_read compared_pages elapsed_us eligible_pages excluded_relocation_pages full_sweep_completed unstable_pages)a
               |> Enum.sort()

      encoded = inspect(projection)
      refute encoded =~ "protected_config"
      refute encoded =~ "startup baseline"
      refute encoded =~ "finding evidence"
      refute encoded =~ "page_hash"
      refute encoded =~ "virtual_address"
    end
  end

  test "selects the newest authorized event and ignores unknown contracts" do
    clean = scenario("full-sweep-clean")["evidence"]
    mismatch = scenario("controlled-page-mismatch")["evidence"]

    events = [
      event(clean, "2026-07-17T12:00:00Z"),
      event(Map.put(mismatch, "unknown", true), "2026-07-17T12:02:00Z"),
      event(mismatch, "2026-07-17T12:01:00Z")
    ]

    projection = RuntimeIntegrityPreview.latest(events)
    assert projection.status == "mismatch"
    assert projection.observed_at == "2026-07-17T12:01:00Z"
    assert projection.finding_kinds == ["file_backed_executable_page_drift"]
  end

  test "fails closed for collector, provenance, shape, privacy and relational mutations" do
    evidence = scenario("full-sweep-clean")["evidence"]
    page = evidence["page_content"]

    invalid = [
      event(evidence, "not-a-time"),
      put_in(event(evidence, "2026-07-17T12:00:00Z"), ["metadata", "collector_id"], "process"),
      Map.put(evidence, "raw_path", "/secret/agent"),
      Map.put(evidence, "provenance", "client_claimed"),
      Map.put(evidence, "limitations", ["path=/secret/agent"]),
      put_in(evidence, ["page_content", "bytes_read"], page["bytes_read"] - 1),
      put_in(evidence, ["page_content", "budget_state"], "exceeded"),
      put_in(evidence, ["page_content", "compared_pages"], 0),
      Map.update!(evidence, "limitations", fn limitations ->
        (limitations ++ ["rx_page_content_backing_replaced"]) |> Enum.sort()
      end),
      put_in(evidence, ["findings"], [
        %{"kind" => "debugger_or_tracer_attached", "evidence" => "attached tracer pid 424242"}
      ])
    ]

    for input <- invalid do
      assert {:error, :invalid_contract} = RuntimeIntegrityPreview.project(input)
    end
  end

  test "direct payload is projectable but never an authorized ingestion envelope" do
    evidence = scenario("full-sweep-clean")["evidence"]
    assert {:ok, _projection} = RuntimeIntegrityPreview.project(evidence)
    refute RuntimeIntegrityPreview.authorized_envelope?(evidence)

    forged_persisted_shape = %{
      "enrichment" => %{"metadata" => %{"collector_id" => "runtime_integrity"}},
      "payload" => evidence,
      "timestamp" => "2026-07-17T12:00:00Z"
    }

    refute RuntimeIntegrityPreview.authorized_envelope?(forged_persisted_shape)
    assert RuntimeIntegrityPreview.runtime_integrity_envelope?(forged_persisted_shape)
    assert {:ok, _projection} = RuntimeIntegrityPreview.project(forged_persisted_shape)
  end

  test "accepts the agent wire timestamp in Unix milliseconds" do
    evidence = scenario("full-sweep-clean")["evidence"]
    event = event(evidence, 1_752_753_600_000)

    assert RuntimeIntegrityPreview.authorized_envelope?(event)

    assert {:ok, %{observed_at: "2025-07-17T12:00:00.000Z"}} =
             RuntimeIntegrityPreview.project(event)
  end

  test "wire authorization rejects non-canonical identity, type, metadata and top-level fields" do
    evidence = scenario("controlled-page-mismatch")["evidence"]
    valid = event(evidence, "2026-07-17T12:00:00Z")
    assert RuntimeIntegrityPreview.authorized_envelope?(valid)

    invalid = [
      Map.put(valid, "event_type", "runtime_integrity"),
      Map.put(valid, "event_id", "not-a-uuid"),
      Map.put(valid, :agent_id, "not-a-uuid"),
      Map.put(valid, "detections", [%{"rule" => "forged"}]),
      Map.put(valid, "severity", "critical"),
      Map.put(valid, "analysis", %{}),
      Map.put(valid, "organization_id", Ecto.UUID.generate()),
      put_in(valid, ["metadata", "unknown"], "value"),
      put_in(valid, ["metadata", "provenance"], "client_claimed")
    ]

    for envelope <- invalid do
      refute RuntimeIntegrityPreview.authorized_envelope?(envelope)
      assert {:error, :invalid_contract} = RuntimeIntegrityPreview.canonical_event(envelope)
    end
  end

  test "canonical event contains only the closed v1 payload and can be reprojected" do
    raw = event(scenario("controlled-page-mismatch")["evidence"], "2026-07-17T12:00:00Z")
    assert {:ok, canonical} = RuntimeIntegrityPreview.canonical_event(raw)

    assert Map.keys(canonical) |> Enum.sort() ==
             ~w(agent_id detections event_id event_type metadata payload severity timestamp)a
             |> Enum.sort()

    assert canonical.payload.schema == "tamandua.runtime_integrity_preview/v1"
    assert canonical.event_type == RuntimeIntegrityPreview.canonical_event_type()

    assert canonical.metadata[RuntimeIntegrityPreview.authority_key()] ==
             RuntimeIntegrityPreview.authority_value()

    assert canonical.severity == "medium"
    assert canonical.detections == []
    refute inspect(canonical) =~ "protected_config_sha256"
    refute inspect(canonical) =~ "startup baseline"

    persisted = %{
      event_type: canonical.event_type,
      payload: canonical.payload,
      timestamp: DateTime.from_iso8601(canonical.timestamp) |> elem(1),
      enrichment: %{metadata: canonical.metadata}
    }

    assert {:ok, projection} = RuntimeIntegrityPreview.project(persisted)
    assert projection == canonical.payload
    assert RuntimeIntegrityPreview.server_authorized_canonical_event?(persisted)
  end

  test "reserves v1 type and authority against direct or forged inbound events" do
    raw = event(scenario("full-sweep-clean")["evidence"], "2026-07-17T12:00:00Z")
    assert {:ok, canonical} = RuntimeIntegrityPreview.canonical_event(raw)

    assert {:ok, canonical.payload} == RuntimeIntegrityPreview.project(canonical.payload)

    assert {:error, :invalid_contract} =
             canonical.payload
             |> Map.put(:unknown, true)
             |> RuntimeIntegrityPreview.project()

    missing_authority = Map.delete(canonical, :metadata)
    wrong_type = Map.put(canonical, :event_type, "defense_evasion")

    assert {:error, :invalid_contract} = RuntimeIntegrityPreview.project(missing_authority)
    assert {:error, :invalid_contract} = RuntimeIntegrityPreview.project(wrong_type)
    refute RuntimeIntegrityPreview.server_authorized_canonical_event?(missing_authority)
    refute RuntimeIntegrityPreview.server_authorized_canonical_event?(wrong_type)

    for inbound <- [
          canonical,
          canonical.payload,
          %{"event_type" => "runtime_integrity_preview", "payload" => %{}},
          %{event_type: :runtime_integrity_preview, payload: %{}},
          %{"event_type" => "process_start", "server_projection_authority" => "forged"},
          %{"event_type" => "process_start", "server_projection_authority" => nil},
          %{event_type: "process_start", metadata: %{server_projection_authority: "forged"}},
          %{"event_type" => "process_start", "payload" => canonical.payload},
          %{"safe" => nested_value(%{"server_projection_authority" => nil}, 13)},
          %{"safe" => nested_value(%{"tamandua.runtime_integrity_preview/v1" => true}, 13)},
          %{"safe" => nested_value(:runtime_integrity_preview, 14)},
          %{"safe" => nested_value("runtime_integrity_preview", 14)},
          %{"safe" => nested_value(:server_projection_authority, 14)},
          %{"safe" => nested_value("server_projection_authority", 14)},
          %{"safe" => nested_value(:"tamandua.runtime_integrity_preview/v1", 14)},
          %{"safe" => nested_value("tamandua.runtime_integrity_preview/v1", 14)},
          %{"safe" => nested_value(:"tamandua_server/runtime_integrity_preview/v1", 14)},
          %{"safe" => nested_value("tamandua_server/runtime_integrity_preview/v1", 14)}
        ] do
      assert RuntimeIntegrityPreview.reserved_inbound?(inbound)
      refute RuntimeIntegrityPreview.authorized_envelope?(inbound)
    end

    depth_16 = %{"safe" => nested_value("ordinary", 15)}
    depth_17 = %{"safe" => nested_value("ordinary", 16)}
    refute RuntimeIntegrityPreview.reserved_inbound?(depth_16)
    assert RuntimeIntegrityPreview.reserved_inbound?(depth_17)

    nodes_4_096 = %{"safe" => List.duplicate(0, 4_093)}
    nodes_4_097 = %{"safe" => List.duplicate(0, 4_094)}
    refute RuntimeIntegrityPreview.reserved_inbound?(nodes_4_096)
    assert RuntimeIntegrityPreview.reserved_inbound?(nodes_4_097)

    bytes_1_mib = term_with_external_size(1_048_576)
    bytes_over_1_mib = term_with_external_size(1_048_577)
    assert :erlang.external_size(bytes_1_mib) == 1_048_576
    assert :erlang.external_size(bytes_over_1_mib) == 1_048_577
    refute RuntimeIntegrityPreview.reserved_inbound?(bytes_1_mib)
    assert RuntimeIntegrityPreview.reserved_inbound?(bytes_over_1_mib)
  end

  test "bounded scanner counts every map key and value exactly once" do
    safe = %{ordinary_key: "ordinary_value"}
    reserved_key = %{RuntimeIntegrityPreview.authority_key() => "ordinary_value"}
    reserved_value = %{ordinary_key: RuntimeIntegrityPreview.authority_value()}

    refute RuntimeIntegrityPreview.reserved_inbound?(safe)
    assert RuntimeIntegrityPreview.reserved_inbound?(reserved_key)
    assert RuntimeIntegrityPreview.reserved_inbound?(reserved_value)
  end

  test "enforces partial and full-sweep relations while allowing degraded overall runtime" do
    partial = scenario("bounded-round-robin-partial")["evidence"]
    clean = scenario("full-sweep-clean")["evidence"]
    mismatch = scenario("controlled-page-mismatch")["evidence"]

    assert {:error, :invalid_contract} =
             partial
             |> put_in(["page_content", "eligible_pages"], 16)
             |> RuntimeIntegrityPreview.project()

    assert {:error, :invalid_contract} =
             mismatch
             |> put_in(["page_content", "full_sweep_completed"], true)
             |> RuntimeIntegrityPreview.project()

    for evidence <- [clean, mismatch] do
      assert {:ok, projection} =
               evidence
               |> Map.put("state", "degraded")
               |> RuntimeIntegrityPreview.project()

      assert projection.runtime_state == "degraded"
    end
  end

  test "terminal degradation can report that no protected baseline became available" do
    degraded = scenario("backing-deleted-degraded")["evidence"]
    unsupported = scenario("elf-unsupported")["evidence"]

    degraded =
      degraded
      |> put_in(["page_content", "baseline_source"], "none")
      |> Map.update!("limitations", fn limitations ->
        limitations
        |> List.delete("rx_page_content_backing_deleted")
        |> Kernel.++(["rx_page_content_baseline_unavailable"])
        |> Enum.sort()
      end)

    unsupported = put_in(unsupported, ["page_content", "baseline_source"], "none")

    assert {:ok, %{status: "degraded"}} = RuntimeIntegrityPreview.project(degraded)
    assert {:ok, %{status: "unsupported"}} = RuntimeIntegrityPreview.project(unsupported)
  end

  test "legacy aggregate findings coexist without becoming page drift" do
    legacy = %{
      "kind" => "debugger_or_tracer_attached",
      "evidence" => "current process reported a debugger or tracer attached"
    }

    for id <- ["default-off-disabled", "full-sweep-clean"] do
      evidence = scenario(id)["evidence"] |> Map.put("findings", [legacy])
      assert {:ok, projection} = RuntimeIntegrityPreview.project(evidence)
      assert projection.finding_kinds == ["debugger_or_tracer_attached"]
      refute "file_backed_executable_page_drift" in projection.finding_kinds
    end
  end

  test "projection emits only allowlisted limitation ids and sorted finding kinds" do
    evidence = scenario("controlled-page-mismatch")["evidence"]
    assert {:ok, projection} = RuntimeIntegrityPreview.project(evidence)

    assert projection.limitations == ["rx_page_content_anonymous_jit_out_of_scope"]
    assert projection.finding_kinds == ["file_backed_executable_page_drift"]
    refute Enum.any?(projection.limitations, &String.contains?(&1, "userspace observation"))
  end

  defp fixture do
    @fixture_path |> File.read!() |> Jason.decode!()
  end

  defp fixture_v2 do
    @fixture_v2_path |> File.read!() |> Jason.decode!()
  end

  defp scenario(id), do: Enum.find(fixture()["scenarios"], &(&1["id"] == id))
  defp scenario_v2(id), do: Enum.find(fixture_v2()["scenarios"], &(&1["id"] == id))

  defp sha256(path) do
    path |> File.read!() |> then(&:crypto.hash(:sha256, &1)) |> Base.encode16(case: :lower)
  end

  defp nested_value(value, depth) do
    Enum.reduce(1..depth, value, fn _index, nested -> [nested] end)
  end

  defp term_with_external_size(target_size) do
    empty = %{"safe" => ""}
    %{"safe" => String.duplicate("x", target_size - :erlang.external_size(empty))}
  end

  defp event(payload, timestamp) do
    findings = payload["findings"]
    state = payload["state"]

    severity =
      cond do
        Enum.any?(findings, &(&1["kind"] == "instrumentation_library_loaded")) or
            length(findings) > 1 ->
          "high"

        findings != [] ->
          "medium"

        state == "supported" ->
          "info"

        true ->
          "low"
      end

    transition =
      cond do
        findings != [] -> "finding_detected"
        state == "degraded" -> "collector_degraded"
        true -> "recovered"
      end

    event_id = Ecto.UUID.generate()

    %{
      "event_id" => event_id,
      "event_type" => "defense_evasion",
      :agent_id => Ecto.UUID.generate(),
      "detections" => [],
      "severity" => severity,
      "metadata" => %{
        "collector" => "runtime_integrity",
        "collector_id" => "runtime_integrity",
        "source" => "runtime_integrity",
        "provenance" => "platform_collector",
        "provenance_state" => "platform_observed",
        "runtime_integrity_transition" => transition,
        "platform" => "linux",
        "collected_at" => to_string(timestamp),
        "transport_batch_sequence" => "1",
        "sequence_scope" => "process",
        "transport_nonce" => event_id,
        "nonce_scope" => "event",
        "freshness_state" => "process_scoped_unverified"
      },
      "payload" => payload,
      "timestamp" => timestamp
    }
  end

  defp event_v2(payload, timestamp, transition \\ nil) do
    findings = payload["findings"]
    state = payload["state"]

    severity =
      cond do
        Enum.any?(findings, &(&1["kind"] == "instrumentation_library_loaded")) or
            length(findings) > 1 ->
          "high"

        findings != [] ->
          "medium"

        state == "supported" ->
          "info"

        true ->
          "low"
      end

    transition =
      transition ||
        cond do
          findings != [] -> "finding_detected"
          state == "degraded" -> "collector_degraded"
          true -> "collector_observed"
        end

    event_id = Ecto.UUID.generate()

    %{
      "event_id" => event_id,
      "event_type" => "defense_evasion",
      :agent_id => Ecto.UUID.generate(),
      "detections" => [],
      "severity" => severity,
      "metadata" => %{
        "collector" => "runtime_integrity",
        "collector_id" => "runtime_integrity",
        "source" => "runtime_integrity",
        "provenance" => "platform_collector",
        "provenance_state" => "platform_observed",
        "runtime_integrity_transition" => transition,
        "platform" => "linux",
        "collected_at" => to_string(timestamp),
        "transport_batch_sequence" => "1",
        "sequence_scope" => "process",
        "transport_nonce" => event_id,
        "nonce_scope" => "event",
        "freshness_state" => "process_scoped_unverified"
      },
      "payload" => payload,
      "timestamp" => timestamp
    }
  end
end
