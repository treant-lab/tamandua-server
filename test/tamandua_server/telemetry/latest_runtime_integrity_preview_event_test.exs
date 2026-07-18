defmodule TamanduaServer.Telemetry.LatestRuntimeIntegrityPreviewEventTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Agents.RuntimeIntegrityPreview
  alias TamanduaServer.Telemetry

  test "query is tenant, agent, event-type and canonical-schema bound" do
    organization_id = Ecto.UUID.generate()
    agent_id = Ecto.UUID.generate()

    query =
      Telemetry.latest_runtime_integrity_preview_event_query(organization_id, agent_id)

    assert %Ecto.Query{} = query

    parameters =
      query.wheres
      |> Enum.flat_map(& &1.params)
      |> Enum.map(&elem(&1, 0))

    assert organization_id in parameters
    assert agent_id in parameters
    assert Enum.any?(query.limit.params, fn {value, _type} -> value == 32 end)
    assert length(query.order_bys) == 1

    source =
      Path.expand("../../../lib/tamandua_server/telemetry.ex", __DIR__)
      |> File.read!()

    assert source =~ "?->>'schema' = 'tamandua.runtime_integrity_preview/v1'"
    assert source =~ "?->>'schema' = 'tamandua.runtime_integrity_preview/v2'"
    assert source =~ ~s(where: e.event_type == "runtime_integrity_preview")

    assert source =~
             "?->'metadata'->>'server_projection_authority' = 'tamandua_server/runtime_integrity_preview/v1'"

    assert source =~
             "?->'metadata'->>'server_projection_authority' = 'tamandua_server/runtime_integrity_preview/v2'"

    assert source =~ "order_by: [desc: e.timestamp, desc: e.id]"

    cursor_timestamp = ~U[2026-07-17 12:00:00Z]
    cursor_id = Ecto.UUID.generate()

    cursor_query =
      Telemetry.latest_runtime_integrity_preview_event_query(
        organization_id,
        agent_id,
        {cursor_timestamp, cursor_id},
        7
      )

    cursor_parameters =
      cursor_query.wheres
      |> Enum.flat_map(& &1.params)
      |> Enum.map(&elem(&1, 0))

    assert cursor_timestamp in cursor_parameters
    assert cursor_id in cursor_parameters
    assert Enum.any?(cursor_query.limit.params, fn {value, _type} -> value == 7 end)

    controller_source =
      Path.expand(
        "../../../lib/tamandua_server_web/controllers/inertia_controller.ex",
        __DIR__
      )
      |> File.read!()

    assert controller_source =~ "latest_runtime_integrity_preview_event_for_agent("
    assert controller_source =~ "RuntimeIntegrityPreview.project(event)"
    refute controller_source =~ "tamandua.runtime_integrity_preview/v1"
    refute controller_source =~ "tamandua.runtime_integrity_preview/v2"
    refute controller_source =~ "list_events_for_agent(agent_id, 500)"
  end

  test "newer invalid or forged rows cannot shadow the prior valid projection" do
    payload = %{
      schema: "tamandua.runtime_integrity_preview/v1",
      external_claim_allowed: false,
      capability_id: "linux_self_file_backed_elf_rx_page_content_preview_v1",
      maturity: "preview",
      mode: "observe_only",
      enabled: true,
      runtime_state: "supported",
      status: "clean",
      observed_at: "2026-07-17T12:00:00Z",
      coverage: %{
        budget_limit_us: 10_000,
        budget_state: "within_budget",
        bytes_read: 8192,
        compared_pages: 2,
        elapsed_us: 200,
        eligible_pages: 2,
        excluded_relocation_pages: 0,
        full_sweep_completed: true,
        unstable_pages: 0
      },
      finding_kinds: [],
      limitations: []
    }

    valid = %{
      id: Ecto.UUID.generate(),
      event_type: RuntimeIntegrityPreview.canonical_event_type(),
      timestamp: ~U[2026-07-17 12:00:00Z],
      payload: payload,
      enrichment: %{
        metadata: %{
          RuntimeIntegrityPreview.authority_key() => RuntimeIntegrityPreview.authority_value()
        }
      }
    }

    invalid =
      valid
      |> Map.put(:timestamp, ~U[2026-07-17 12:02:00Z])
      |> put_in([:payload, :observed_at], "2026-07-17T12:02:00Z")
      |> put_in([:payload, :unknown], true)

    forged =
      valid
      |> Map.put(:timestamp, ~U[2026-07-17 12:01:00Z])
      |> put_in([:payload, :observed_at], "2026-07-17T12:01:00Z")
      |> put_in(
        [:enrichment, :metadata, RuntimeIntegrityPreview.authority_key()],
        "forged"
      )

    assert Telemetry.latest_valid_runtime_integrity_preview_event([invalid, forged, valid]) ==
             valid
  end

  test "newest valid authorized projection wins across v1 and v2 without cross-version shadow" do
    v1 = valid_event(~U[2026-07-17 12:00:00Z])
    v2 = valid_event_v2(~U[2026-07-17 12:01:00Z])

    assert Telemetry.latest_valid_runtime_integrity_preview_event([v2, v1]) == v2

    invalid_v2 = put_in(v2, [:payload, :coverage, :sweep_pages_compared], 8_193)
    assert Telemetry.latest_valid_runtime_integrity_preview_event([invalid_v2, v1]) == v1

    invalid_v1 = put_in(v1, [:payload, :coverage, :compared_pages], 17)
    assert Telemetry.latest_valid_runtime_integrity_preview_event([invalid_v1, v2]) == v2

    cross_marked =
      put_in(
        v2,
        [:enrichment, :metadata, RuntimeIntegrityPreview.authority_key()],
        RuntimeIntegrityPreview.authority_value("tamandua.runtime_integrity_preview/v1")
      )

    assert Telemetry.latest_valid_runtime_integrity_preview_event([cross_marked, v1]) == v1
  end

  test "keyset scan finds a valid row after more than 32 invalid newer rows" do
    valid = valid_event(~U[2026-07-17 12:00:00Z])

    rows = invalid_newer_rows(valid, 33) ++ [valid]

    assert Telemetry.latest_valid_runtime_integrity_preview_event(fetch_rows(rows)) == valid
  end

  test "keyset scan has an explicit no-result ceiling" do
    invalid = valid_event(~U[2026-07-17 12:00:00Z]) |> put_in([:payload, :unknown], true)
    Process.put(:runtime_integrity_fetches, 0)

    fetch_page = fn _cursor, limit ->
      Process.put(:runtime_integrity_fetches, Process.get(:runtime_integrity_fetches) + 1)
      List.duplicate(invalid, limit)
    end

    assert Telemetry.latest_valid_runtime_integrity_preview_event(fetch_page) == nil
    assert Process.get(:runtime_integrity_fetches) == 32
  end

  test "keyset ceiling accepts a valid event at ordinal 1024" do
    valid = valid_event(~U[2026-07-17 12:00:00Z])
    rows = invalid_newer_rows(valid, 1_023) ++ [valid]

    assert Telemetry.latest_valid_runtime_integrity_preview_event(fetch_rows(rows)) == valid
  end

  test "keyset ceiling returns nil when the first valid event is ordinal 1025" do
    valid = valid_event(~U[2026-07-17 12:00:00Z])
    rows = invalid_newer_rows(valid, 1_024) ++ [valid]

    assert Telemetry.latest_valid_runtime_integrity_preview_event(fetch_rows(rows)) == nil
  end

  defp invalid_newer_rows(valid, count) do
    for offset <- count..1 do
      valid.timestamp
      |> DateTime.add(offset, :second)
      |> valid_event()
      |> put_in([:payload, :unknown], true)
    end
  end

  defp fetch_rows(rows) do
    fn
      nil, limit ->
        Enum.take(rows, limit)

      {timestamp, id}, limit ->
        cursor_index = Enum.find_index(rows, &(&1.timestamp == timestamp and &1.id == id))
        rows |> Enum.drop(cursor_index + 1) |> Enum.take(limit)
    end
  end

  defp valid_event(timestamp) do
    observed_at = DateTime.to_iso8601(timestamp)

    %{
      id: Ecto.UUID.generate(),
      event_type: RuntimeIntegrityPreview.canonical_event_type(),
      timestamp: timestamp,
      payload: valid_payload(observed_at),
      enrichment: %{
        metadata: %{
          RuntimeIntegrityPreview.authority_key() => RuntimeIntegrityPreview.authority_value()
        }
      }
    }
  end

  defp valid_event_v2(timestamp) do
    observed_at = DateTime.to_iso8601(timestamp)

    %{
      id: Ecto.UUID.generate(),
      event_type: RuntimeIntegrityPreview.canonical_event_type(),
      timestamp: timestamp,
      payload: valid_payload_v2(observed_at),
      enrichment: %{
        metadata: %{
          RuntimeIntegrityPreview.authority_key() =>
            RuntimeIntegrityPreview.authority_value("tamandua.runtime_integrity_preview/v2")
        }
      }
    }
  end

  defp valid_payload(observed_at) do
    %{
      schema: "tamandua.runtime_integrity_preview/v1",
      external_claim_allowed: false,
      capability_id: "linux_self_file_backed_elf_rx_page_content_preview_v1",
      maturity: "preview",
      mode: "observe_only",
      enabled: true,
      runtime_state: "supported",
      status: "clean",
      observed_at: observed_at,
      coverage: %{
        budget_limit_us: 10_000,
        budget_state: "within_budget",
        bytes_read: 8192,
        compared_pages: 2,
        elapsed_us: 200,
        eligible_pages: 2,
        excluded_relocation_pages: 0,
        full_sweep_completed: true,
        unstable_pages: 0
      },
      finding_kinds: [],
      limitations: []
    }
  end

  defp valid_payload_v2(observed_at) do
    %{
      schema: "tamandua.runtime_integrity_preview/v2",
      external_claim_allowed: false,
      capability_id: "linux_self_file_backed_elf_rx_page_content_preview_v2",
      maturity: "preview",
      mode: "observe_only",
      enabled: true,
      runtime_state: "supported",
      status: "clean",
      observed_at: observed_at,
      coverage: %{
        budget_limit_us: 10_000,
        budget_state: "within_budget",
        elapsed_us_this_tick: 1_500,
        eligible_pages: 17,
        excluded_relocation_pages: 3,
        full_sweep_completed: true,
        memory_bytes_read_this_tick: 8_192,
        pages_compared_this_tick: 1,
        sweep_pages_compared: 17,
        unstable_pages_this_tick: 0
      },
      finding_kinds: [],
      limitations: ["rx_page_content_anonymous_jit_out_of_scope"]
    }
  end
end
