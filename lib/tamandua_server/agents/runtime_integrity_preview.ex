defmodule TamanduaServer.Agents.RuntimeIntegrityPreview do
  @moduledoc """
  Closed, privacy-preserving server projection for the Linux RX page-content
  Preview collector.

  This projection is observe-only. It deliberately excludes raw finding
  evidence, payload metadata, file identity, paths, process identifiers,
  addresses, hashes, and baseline material.
  """

  @runtime_schema "tamandua.runtime_integrity/v2"
  @runtime_schema_v2 "tamandua.runtime_integrity/v3"
  @projection_schema "tamandua.runtime_integrity_preview/v1"
  @projection_schema_v2 "tamandua.runtime_integrity_preview/v2"
  @collector_id "runtime_integrity"
  @canonical_event_type "runtime_integrity_preview"
  @authority_key "server_projection_authority"
  @authority_value "tamandua_server/runtime_integrity_preview/v1"
  @authority_value_v2 "tamandua_server/runtime_integrity_preview/v2"
  @reserved_scalar_tokens [
    "runtime_integrity_preview",
    :runtime_integrity_preview,
    "tamandua.runtime_integrity_preview/v1",
    :"tamandua.runtime_integrity_preview/v1",
    "tamandua.runtime_integrity_preview/v2",
    :"tamandua.runtime_integrity_preview/v2",
    "server_projection_authority",
    :server_projection_authority,
    "tamandua_server/runtime_integrity_preview/v1",
    :"tamandua_server/runtime_integrity_preview/v1",
    "tamandua_server/runtime_integrity_preview/v2",
    :"tamandua_server/runtime_integrity_preview/v2"
  ]
  @inbound_scan_max_depth 16
  @inbound_scan_max_items 4_096
  @inbound_scan_max_bytes 1_048_576
  @provenance "platform_collector"
  @capability_id "linux_self_file_backed_elf_rx_page_content_preview_v1"
  @capability_id_v2 "linux_self_file_backed_elf_rx_page_content_preview_v2"
  @statuses ~w(disabled partial clean mismatch degraded unsupported)
  @runtime_states ~w(supported degraded)
  @finding_evidence %{
    "writable_executable_mapping" => "current process exposed a writable executable mapping",
    "debugger_or_tracer_attached" => "current process reported a debugger or tracer attached",
    "instrumentation_library_loaded" =>
      "current process loaded a known instrumentation library marker",
    "file_backed_executable_page_drift" =>
      "file-backed executable page content differed from the protected startup baseline"
  }
  @limitation_ids ~w(
    rx_page_content_anonymous_jit_out_of_scope
    rx_page_content_backing_deleted
    rx_page_content_backing_replaced
    rx_page_content_baseline_mismatch
    rx_page_content_baseline_unavailable
    rx_page_content_budget_exceeded
    rx_page_content_disabled
    rx_page_content_elf_unsupported
    rx_page_content_execute_only
    rx_page_content_identity_race
    rx_page_content_memory_read_unavailable
    rx_page_content_no_eligible_pages
    rx_page_content_relocation_unsupported
  )
  @limitation_ids_v2 Enum.sort(
                       @limitation_ids ++
                         ~w(rx_page_content_bootstrap_budget_exceeded rx_page_content_coverage_limit_exceeded)
                     )
  @legacy_limitation "point-in-time userspace observation of the current process only"
  @degraded_limitation_ids @limitation_ids --
                             ~w(rx_page_content_anonymous_jit_out_of_scope rx_page_content_disabled)

  @payload_keys ~w(schema provenance platform state findings limitations page_content)
  @page_keys ~w(
    capability_id maturity mode enabled status baseline_source eligible_pages
    compared_pages excluded_relocation_pages unstable_pages bytes_read elapsed_us
    budget_limit_us full_sweep_completed budget_state
  )
  @page_keys_v2 ~w(
    baseline_source budget_limit_us budget_state capability_id elapsed_us_this_tick eligible_pages
    enabled excluded_relocation_pages full_sweep_completed maturity memory_bytes_read_this_tick mode
    pages_compared_this_tick status sweep_pages_compared unstable_pages_this_tick
  )
  @finding_keys ~w(kind evidence)
  @wire_event_keys ~w(agent_id detections event_id event_type metadata payload severity timestamp)
  @wire_metadata_keys ~w(
    collected_at collector collector_id freshness_state nonce_scope platform provenance
    provenance_state runtime_integrity_transition sequence_scope source transport_batch_sequence
    transport_nonce
  )
  @projection_keys ~w(
    capability_id coverage enabled external_claim_allowed finding_kinds limitations maturity mode
    observed_at runtime_state schema status
  )
  @coverage_keys ~w(
    budget_limit_us budget_state bytes_read compared_pages elapsed_us eligible_pages
    excluded_relocation_pages full_sweep_completed unstable_pages
  )
  @coverage_keys_v2 ~w(
    budget_limit_us budget_state elapsed_us_this_tick eligible_pages excluded_relocation_pages
    full_sweep_completed memory_bytes_read_this_tick pages_compared_this_tick sweep_pages_compared
    unstable_pages_this_tick
  )

  @spec project(map(), keyword()) :: {:ok, map()} | {:error, :invalid_contract}
  def project(event_or_payload, opts \\ [])

  def project(event_or_payload, opts) when is_map(event_or_payload) and is_list(opts) do
    with {:ok, payload, observed_at} <- unwrap(event_or_payload, opts) do
      case value(payload, "schema") do
        @runtime_schema -> project_runtime_payload(payload, observed_at)
        @runtime_schema_v2 -> project_runtime_payload_v2(payload, observed_at)
        @projection_schema -> project_canonical_payload(payload, observed_at)
        @projection_schema_v2 -> project_canonical_payload_v2(payload, observed_at)
        _ -> {:error, :invalid_contract}
      end
    else
      _ -> {:error, :invalid_contract}
    end
  end

  def project(_, _), do: {:error, :invalid_contract}

  @spec latest([map()]) :: map() | nil
  def latest(events) when is_list(events) do
    events
    |> Enum.with_index()
    |> Enum.reduce([], fn {event, index}, acc ->
      case project(event) do
        {:ok, projection} -> [{sort_key(projection.observed_at, index), projection} | acc]
        {:error, :invalid_contract} -> acc
      end
    end)
    |> Enum.max_by(&elem(&1, 0), fn -> nil end)
    |> case do
      nil -> nil
      {_key, projection} -> projection
    end
  end

  def latest(_), do: nil

  @spec authorized_event?(term()) :: boolean()
  def authorized_event?(event), do: authorized_envelope?(event)

  @spec authorized_envelope?(term()) :: boolean()
  def authorized_envelope?(event) when is_map(event) do
    # Ingestion accepts only the wire envelope's top-level metadata. The
    # persisted enrichment fallback is intentionally confined to project/2.
    strict_wire_event?(event)
  end

  def authorized_envelope?(_), do: false

  @spec canonical_event(map()) :: {:ok, map()} | {:error, :invalid_contract}
  def canonical_event(event) when is_map(event) do
    with true <- strict_wire_event?(event),
         {:ok, projection} <- project(event),
         {:ok, timestamp} <- normalize_observed_at(value(event, "timestamp")) do
      metadata = value(event, "metadata")
      authority = authority_value_for_schema(value(projection, "schema"))

      {:ok,
       %{
         event_id: value(event, "event_id"),
         event_type: @canonical_event_type,
         agent_id: value(event, "agent_id"),
         timestamp: timestamp,
         severity: canonical_severity(projection),
         payload: projection,
         detections: [],
         metadata: %{
           "collector_id" => @collector_id,
           "provenance" => @provenance,
           "runtime_integrity_transition" => value(metadata, "runtime_integrity_transition"),
           @authority_key => authority
         }
       }}
    else
      _ -> {:error, :invalid_contract}
    end
  end

  def canonical_event(_), do: {:error, :invalid_contract}

  @spec reserved_inbound?(term()) :: boolean()
  def reserved_inbound?(event) when is_map(event) do
    case bounded_reserved_scan(event) do
      :clear -> false
      :reserved_or_unbounded -> true
    end
  end

  def reserved_inbound?(_), do: false

  @spec server_authorized_canonical_event?(term()) :: boolean()
  def server_authorized_canonical_event?(event) when is_map(event) do
    metadata = value(event, "metadata") || persisted_metadata(event)
    payload = value(event, "payload")
    schema = if is_map(payload), do: value(payload, "schema"), else: nil
    expected_authority = authority_value_for_schema(schema)

    value(event, "event_type") == @canonical_event_type and
      schema in [@projection_schema, @projection_schema_v2] and
      not is_nil(expected_authority) and is_map(metadata) and
      value(metadata, @authority_key) == expected_authority and
      match?({:ok, _}, project(event))
  end

  def server_authorized_canonical_event?(_), do: false

  def canonical_event_type, do: @canonical_event_type
  def authority_key, do: @authority_key
  def authority_value, do: @authority_value
  def authority_value(schema), do: authority_value_for_schema(schema)

  @spec raw_runtime_integrity_envelope?(term()) :: boolean()
  def raw_runtime_integrity_envelope?(event) when is_map(event) do
    metadata = value(event, "metadata")
    payload = value(event, "payload")

    raw_schema? =
      is_map(payload) and value(payload, "schema") in [@runtime_schema, @runtime_schema_v2]

    preview_marker? =
      if is_map(payload) do
        page_content = value(payload, "page_content")

        is_map(page_content) and
          value(page_content, "capability_id") in [@capability_id, @capability_id_v2]
      else
        false
      end

    raw_schema? or
      (is_map(metadata) and value(metadata, "collector_id") == @collector_id and
         preview_marker?)
  end

  def raw_runtime_integrity_envelope?(_), do: false

  @spec runtime_integrity_envelope?(term()) :: boolean()
  def runtime_integrity_envelope?(event) when is_map(event) do
    metadata = value(event, "metadata") || persisted_metadata(event)
    payload = value(event, "payload")

    (is_map(metadata) and value(metadata, "collector_id") == @collector_id) or
      (is_map(payload) and
         value(payload, "schema") in [@projection_schema, @projection_schema_v2])
  end

  def runtime_integrity_envelope?(_), do: false

  defp unwrap(map, opts) do
    if value(map, "schema") in [
         @runtime_schema,
         @runtime_schema_v2,
         @projection_schema,
         @projection_schema_v2
       ] do
      {:ok, map, Keyword.get(opts, :observed_at)}
    else
      metadata = value(map, "metadata") || persisted_metadata(map)
      payload = value(map, "payload")

      if projectable_envelope?(map, metadata, payload) do
        {:ok, payload, envelope_observed_at(map)}
      else
        :error
      end
    end
  end

  defp projectable_envelope?(event, metadata, payload)
       when is_map(metadata) and is_map(payload) do
    case value(payload, "schema") do
      @runtime_schema ->
        value(metadata, "collector_id") == @collector_id

      @runtime_schema_v2 ->
        value(metadata, "collector_id") == @collector_id

      @projection_schema ->
        value(event, "event_type") == @canonical_event_type and
          value(metadata, @authority_key) == @authority_value

      @projection_schema_v2 ->
        value(event, "event_type") == @canonical_event_type and
          value(metadata, @authority_key) == @authority_value_v2

      _ ->
        false
    end
  end

  defp projectable_envelope?(_, _, _), do: false

  defp project_runtime_payload(payload, observed_at) do
    with true <- valid_payload?(payload),
         {:ok, projected_at} <- normalize_observed_at(observed_at) do
      page = value(payload, "page_content")
      findings = value(payload, "findings")

      {:ok,
       %{
         schema: @projection_schema,
         external_claim_allowed: false,
         capability_id: @capability_id,
         maturity: "preview",
         mode: "observe_only",
         enabled: value(page, "enabled"),
         status: value(page, "status"),
         runtime_state: value(payload, "state"),
         observed_at: projected_at,
         finding_kinds: findings |> Enum.map(&value(&1, "kind")) |> Enum.uniq() |> Enum.sort(),
         limitations:
           payload
           |> value("limitations")
           |> Enum.filter(&(&1 in @limitation_ids))
           |> Enum.uniq()
           |> Enum.sort(),
         coverage: coverage_from_page(page)
       }}
    else
      _ -> {:error, :invalid_contract}
    end
  end

  defp project_runtime_payload_v2(payload, observed_at) do
    with true <- valid_payload_v2?(payload),
         {:ok, projected_at} <- normalize_observed_at(observed_at) do
      page = value(payload, "page_content")
      findings = value(payload, "findings")

      {:ok,
       %{
         schema: @projection_schema_v2,
         external_claim_allowed: false,
         capability_id: @capability_id_v2,
         maturity: "preview",
         mode: "observe_only",
         enabled: value(page, "enabled"),
         status: value(page, "status"),
         runtime_state: value(payload, "state"),
         observed_at: projected_at,
         finding_kinds: findings |> Enum.map(&value(&1, "kind")) |> Enum.uniq() |> Enum.sort(),
         limitations: value(payload, "limitations"),
         coverage: coverage_from_page_v2(page)
       }}
    else
      _ -> {:error, :invalid_contract}
    end
  end

  defp project_canonical_payload(payload, envelope_observed_at) do
    with true <- valid_projection?(payload),
         {:ok, projected_at} <- normalize_observed_at(value(payload, "observed_at")),
         {:ok, envelope_at} <- normalize_observed_at(envelope_observed_at),
         true <- is_nil(envelope_at) or envelope_at == projected_at do
      {:ok,
       %{
         schema: @projection_schema,
         external_claim_allowed: false,
         capability_id: @capability_id,
         maturity: "preview",
         mode: "observe_only",
         enabled: value(payload, "enabled"),
         status: value(payload, "status"),
         runtime_state: value(payload, "runtime_state"),
         observed_at: projected_at,
         finding_kinds: value(payload, "finding_kinds"),
         limitations: value(payload, "limitations"),
         coverage: canonical_coverage(value(payload, "coverage"))
       }}
    else
      _ -> {:error, :invalid_contract}
    end
  end

  defp project_canonical_payload_v2(payload, envelope_observed_at) do
    with true <- valid_projection_v2?(payload),
         {:ok, projected_at} <- normalize_observed_at(value(payload, "observed_at")),
         {:ok, envelope_at} <- normalize_observed_at(envelope_observed_at),
         true <- is_nil(envelope_at) or envelope_at == projected_at do
      {:ok,
       %{
         schema: @projection_schema_v2,
         external_claim_allowed: false,
         capability_id: @capability_id_v2,
         maturity: "preview",
         mode: "observe_only",
         enabled: value(payload, "enabled"),
         status: value(payload, "status"),
         runtime_state: value(payload, "runtime_state"),
         observed_at: projected_at,
         finding_kinds: value(payload, "finding_kinds"),
         limitations: value(payload, "limitations"),
         coverage: canonical_coverage_v2(value(payload, "coverage"))
       }}
    else
      _ -> {:error, :invalid_contract}
    end
  end

  defp coverage_from_page(page) do
    %{
      eligible_pages: value(page, "eligible_pages"),
      compared_pages: value(page, "compared_pages"),
      excluded_relocation_pages: value(page, "excluded_relocation_pages"),
      unstable_pages: value(page, "unstable_pages"),
      bytes_read: value(page, "bytes_read"),
      elapsed_us: value(page, "elapsed_us"),
      budget_limit_us: value(page, "budget_limit_us"),
      full_sweep_completed: value(page, "full_sweep_completed"),
      budget_state: value(page, "budget_state")
    }
  end

  defp canonical_coverage(coverage) do
    %{
      eligible_pages: value(coverage, "eligible_pages"),
      compared_pages: value(coverage, "compared_pages"),
      excluded_relocation_pages: value(coverage, "excluded_relocation_pages"),
      unstable_pages: value(coverage, "unstable_pages"),
      bytes_read: value(coverage, "bytes_read"),
      elapsed_us: value(coverage, "elapsed_us"),
      budget_limit_us: value(coverage, "budget_limit_us"),
      full_sweep_completed: value(coverage, "full_sweep_completed"),
      budget_state: value(coverage, "budget_state")
    }
  end

  defp coverage_from_page_v2(page) do
    %{
      eligible_pages: value(page, "eligible_pages"),
      pages_compared_this_tick: value(page, "pages_compared_this_tick"),
      sweep_pages_compared: value(page, "sweep_pages_compared"),
      excluded_relocation_pages: value(page, "excluded_relocation_pages"),
      unstable_pages_this_tick: value(page, "unstable_pages_this_tick"),
      memory_bytes_read_this_tick: value(page, "memory_bytes_read_this_tick"),
      elapsed_us_this_tick: value(page, "elapsed_us_this_tick"),
      budget_limit_us: value(page, "budget_limit_us"),
      full_sweep_completed: value(page, "full_sweep_completed"),
      budget_state: value(page, "budget_state")
    }
  end

  defp canonical_coverage_v2(coverage), do: coverage_from_page_v2(coverage)

  defp persisted_metadata(event) do
    case value(event, "enrichment") do
      enrichment when is_map(enrichment) -> value(enrichment, "metadata")
      _ -> nil
    end
  end

  defp envelope_observed_at(event) do
    value(event, "timestamp") || value(event, "observed_at") || value(event, "inserted_at")
  end

  defp valid_payload?(payload) do
    page = value(payload, "page_content")
    findings = value(payload, "findings")
    limitations = value(payload, "limitations")

    exact_keys?(payload, @payload_keys) and
      value(payload, "schema") == @runtime_schema and
      value(payload, "provenance") == @provenance and
      value(payload, "platform") == "linux" and
      value(payload, "state") in @runtime_states and
      is_list(findings) and valid_findings?(findings) and
      is_list(limitations) and valid_limitations?(limitations) and
      is_map(page) and valid_page?(page, value(payload, "state"), findings, limitations)
  end

  defp valid_payload_v2?(payload) do
    page = value(payload, "page_content")
    findings = value(payload, "findings")
    limitations = value(payload, "limitations")

    exact_keys?(payload, @payload_keys) and
      value(payload, "schema") == @runtime_schema_v2 and
      value(payload, "provenance") == @provenance and
      value(payload, "platform") == "linux" and
      value(payload, "state") in @runtime_states and
      is_list(findings) and valid_findings?(findings) and
      valid_projection_limitations_v2?(limitations) and
      is_map(page) and
      valid_page_v2?(page, value(payload, "state"), findings, limitations)
  end

  defp valid_runtime_payload_for_schema?(payload, @runtime_schema), do: valid_payload?(payload)

  defp valid_runtime_payload_for_schema?(payload, @runtime_schema_v2),
    do: valid_payload_v2?(payload)

  defp valid_runtime_payload_for_schema?(_, _), do: false

  defp strict_wire_event?(event) do
    metadata = value(event, "metadata")
    payload = value(event, "payload")
    timestamp = value(event, "timestamp")
    schema = if is_map(payload), do: value(payload, "schema"), else: nil

    with true <- exact_keys?(event, @wire_event_keys),
         true <- value(event, "event_type") == "defense_evasion",
         true <- valid_uuid?(value(event, "event_id")),
         true <- valid_uuid?(value(event, "agent_id")),
         true <- not is_nil(timestamp),
         {:ok, _timestamp} <- normalize_observed_at(timestamp),
         true <- value(event, "detections") == [],
         true <- schema in [@runtime_schema, @runtime_schema_v2],
         true <- valid_wire_metadata?(metadata, event, schema),
         true <- valid_runtime_payload_for_schema?(payload, schema),
         {:ok, projection} <- project(payload, observed_at: timestamp),
         true <- value(event, "severity") == canonical_severity(projection),
         true <-
           valid_transition?(value(metadata, "runtime_integrity_transition"), projection, schema) do
      true
    else
      _ -> false
    end
  end

  defp valid_wire_metadata?(metadata, event, schema) when is_map(metadata) do
    transitions =
      if schema == @runtime_schema_v2 do
        ~w(finding_detected finding_changed collector_degraded recovered collector_observed)
      else
        ~w(finding_detected finding_changed collector_degraded recovered)
      end

    exact_keys?(metadata, @wire_metadata_keys) and
      value(metadata, "collector") == @collector_id and
      value(metadata, "collector_id") == @collector_id and
      value(metadata, "source") == @collector_id and
      value(metadata, "provenance") == @provenance and
      value(metadata, "provenance_state") == "platform_observed" and
      value(metadata, "platform") == "linux" and
      value(metadata, "collected_at") == to_string(value(event, "timestamp")) and
      value(metadata, "sequence_scope") == "process" and
      value(metadata, "nonce_scope") == "event" and
      value(metadata, "freshness_state") == "process_scoped_unverified" and
      value(metadata, "transport_nonce") == value(event, "event_id") and
      valid_decimal_u64?(value(metadata, "transport_batch_sequence")) and
      value(metadata, "runtime_integrity_transition") in transitions
  end

  defp valid_wire_metadata?(_, _, _), do: false

  defp valid_transition?(transition, projection, @runtime_schema) do
    cond do
      projection.finding_kinds != [] -> transition in ~w(finding_detected finding_changed)
      projection.runtime_state == "degraded" -> transition == "collector_degraded"
      true -> transition == "recovered"
    end
  end

  defp valid_transition?(transition, projection, @runtime_schema_v2) do
    cond do
      projection.finding_kinds != [] -> transition in ~w(finding_detected finding_changed)
      projection.runtime_state == "degraded" -> transition == "collector_degraded"
      projection.status not in ~w(disabled partial clean) -> false
      transition == "collector_observed" -> true
      transition == "recovered" -> true
      true -> false
    end
  end

  defp valid_transition?(_, _, _), do: false

  defp canonical_severity(projection) do
    findings = projection.finding_kinds

    cond do
      "instrumentation_library_loaded" in findings or length(findings) > 1 -> "high"
      findings != [] -> "medium"
      projection.runtime_state == "supported" -> "info"
      true -> "low"
    end
  end

  defp authority_value_for_schema(@projection_schema), do: @authority_value
  defp authority_value_for_schema(@projection_schema_v2), do: @authority_value_v2
  defp authority_value_for_schema(_), do: nil

  defp valid_projection?(payload) do
    coverage = value(payload, "coverage")
    findings = value(payload, "finding_kinds")
    limitations = value(payload, "limitations")
    status = value(payload, "status")
    runtime_state = value(payload, "runtime_state")
    enabled = value(payload, "enabled")

    exact_keys?(payload, @projection_keys) and
      value(payload, "schema") == @projection_schema and
      value(payload, "external_claim_allowed") == false and
      value(payload, "capability_id") == @capability_id and
      value(payload, "maturity") == "preview" and
      value(payload, "mode") == "observe_only" and
      is_boolean(enabled) and status in @statuses and runtime_state in @runtime_states and
      valid_projection_findings?(findings) and valid_projection_limitations?(limitations) and
      is_map(coverage) and exact_keys?(coverage, @coverage_keys) and
      valid_projection_coverage?(coverage, status, runtime_state, enabled, findings, limitations) and
      match?(
        {:ok, projected_at} when not is_nil(projected_at),
        normalize_observed_at(value(payload, "observed_at"))
      )
  end

  defp valid_projection_findings?(findings) when is_list(findings) do
    valid_string_set?(findings) and Enum.all?(findings, &Map.has_key?(@finding_evidence, &1))
  end

  defp valid_projection_findings?(_), do: false

  defp valid_projection_limitations?(limitations) when is_list(limitations) do
    valid_string_set?(limitations) and Enum.all?(limitations, &(&1 in @limitation_ids))
  end

  defp valid_projection_limitations?(_), do: false

  defp valid_projection_coverage?(coverage, status, runtime_state, enabled, findings, limitations) do
    eligible = value(coverage, "eligible_pages")
    compared = value(coverage, "compared_pages")
    excluded = value(coverage, "excluded_relocation_pages")
    unstable = value(coverage, "unstable_pages")
    bytes = value(coverage, "bytes_read")
    elapsed = value(coverage, "elapsed_us")
    budget = value(coverage, "budget_limit_us")
    full = value(coverage, "full_sweep_completed")
    budget_state = value(coverage, "budget_state")
    drift? = "file_backed_executable_page_drift" in findings

    bounded_integer?(eligible, 0, 1024) and bounded_integer?(compared, 0, 16) and
      bounded_integer?(excluded, 0, 16_384) and bounded_integer?(unstable, 0, 16) and
      bounded_integer?(bytes, 0, 65_536) and bounded_integer?(elapsed, 0, 60_000) and
      budget == 10_000 and is_boolean(full) and budget_state in ~w(within_budget exceeded) and
      compared <= eligible and unstable <= compared and bytes == compared * 4096 and
      (not full or compared == eligible) and
      ((budget_state == "within_budget" and elapsed <= budget) or
         (budget_state == "exceeded" and elapsed > budget)) and
      budget_limit_consistent?(budget_state, limitations) and
      valid_projection_status?(
        status,
        runtime_state,
        enabled,
        eligible,
        compared,
        excluded,
        unstable,
        bytes,
        full,
        budget_state,
        drift?,
        limitations
      )
  end

  defp valid_projection_status?(
         "disabled",
         _runtime_state,
         false,
         0,
         0,
         0,
         0,
         0,
         false,
         "within_budget",
         false,
         ["rx_page_content_disabled"]
       ),
       do: true

  defp valid_projection_status?(
         "partial",
         _runtime_state,
         true,
         eligible,
         compared,
         _excluded,
         _unstable,
         _bytes,
         false,
         "within_budget",
         false,
         limitations
       ),
       do: compared > 0 and compared < eligible and benign_page_limitations?(limitations)

  defp valid_projection_status?(
         "clean",
         _runtime_state,
         true,
         eligible,
         compared,
         _excluded,
         0,
         _bytes,
         true,
         "within_budget",
         false,
         limitations
       ),
       do: eligible > 0 and compared == eligible and benign_page_limitations?(limitations)

  defp valid_projection_status?(
         "mismatch",
         _runtime_state,
         true,
         _eligible,
         compared,
         _excluded,
         _unstable,
         _bytes,
         _full,
         "within_budget",
         true,
         limitations
       ),
       do: compared > 0 and benign_page_limitations?(limitations)

  defp valid_projection_status?(
         "degraded",
         "degraded",
         true,
         _eligible,
         _compared,
         _excluded,
         _unstable,
         _bytes,
         false,
         _budget_state,
         false,
         limitations
       ),
       do: Enum.any?(limitations, &(&1 in @degraded_limitation_ids))

  defp valid_projection_status?(
         "unsupported",
         "degraded",
         true,
         0,
         0,
         0,
         0,
         0,
         false,
         "within_budget",
         false,
         limitations
       ),
       do: "rx_page_content_elf_unsupported" in limitations

  defp valid_projection_status?(_, _, _, _, _, _, _, _, _, _, _, _), do: false

  defp valid_projection_v2?(payload) do
    coverage = value(payload, "coverage")
    findings = value(payload, "finding_kinds")
    limitations = value(payload, "limitations")

    exact_keys?(payload, @projection_keys) and
      value(payload, "schema") == @projection_schema_v2 and
      value(payload, "external_claim_allowed") == false and
      value(payload, "capability_id") == @capability_id_v2 and
      value(payload, "maturity") == "preview" and
      value(payload, "mode") == "observe_only" and
      is_boolean(value(payload, "enabled")) and value(payload, "status") in @statuses and
      value(payload, "runtime_state") in @runtime_states and
      valid_projection_findings?(findings) and
      valid_projection_limitations_v2?(limitations) and is_map(coverage) and
      exact_keys?(coverage, @coverage_keys_v2) and
      valid_projection_coverage_v2?(
        coverage,
        value(payload, "status"),
        value(payload, "runtime_state"),
        value(payload, "enabled"),
        findings,
        limitations
      ) and
      match?({:ok, _}, normalize_observed_at(value(payload, "observed_at")))
  end

  defp valid_projection_limitations_v2?([limitation]) when limitation in @limitation_ids_v2,
    do: true

  defp valid_projection_limitations_v2?(_), do: false

  defp valid_projection_coverage_v2?(
         coverage,
         status,
         runtime_state,
         enabled,
         findings,
         [limitation]
       ) do
    eligible = value(coverage, "eligible_pages")
    per_tick = value(coverage, "pages_compared_this_tick")
    sweep = value(coverage, "sweep_pages_compared")
    excluded = value(coverage, "excluded_relocation_pages")
    unstable = value(coverage, "unstable_pages_this_tick")
    bytes = value(coverage, "memory_bytes_read_this_tick")
    elapsed = value(coverage, "elapsed_us_this_tick")
    budget = value(coverage, "budget_limit_us")
    full = value(coverage, "full_sweep_completed")
    budget_state = value(coverage, "budget_state")
    drift? = "file_backed_executable_page_drift" in findings

    bounded_integer?(eligible, 0, 8_192) and bounded_integer?(per_tick, 0, 8) and
      bounded_integer?(sweep, 0, 8_192) and bounded_integer?(excluded, 0, 16_384) and
      bounded_integer?(unstable, 0, 8) and bounded_integer?(bytes, 0, 65_536) and
      rem(bytes, 4_096) == 0 and bounded_integer?(elapsed, 0, 60_000) and
      budget == 10_000 and is_boolean(full) and budget_state in ~w(within_budget exceeded) and
      sweep <= eligible and unstable <= per_tick and full == (eligible > 0 and sweep == eligible) and
      ((budget_state == "within_budget" and elapsed <= budget) or
         (budget_state == "exceeded" and elapsed > budget)) and
      budget_state == "exceeded" == (limitation == "rx_page_content_budget_exceeded") and
      unstable > 0 == (limitation == "rx_page_content_identity_race") and
      valid_projection_status_v2?(
        status,
        runtime_state,
        enabled,
        eligible,
        per_tick,
        sweep,
        excluded,
        unstable,
        bytes,
        elapsed,
        full,
        budget_state,
        drift?,
        limitation
      )
  end

  defp valid_projection_coverage_v2?(_, _, _, _, _, _), do: false

  defp valid_projection_status_v2?(
         "disabled",
         "supported",
         false,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         false,
         "within_budget",
         false,
         "rx_page_content_disabled"
       ),
       do: true

  defp valid_projection_status_v2?(
         "partial",
         "supported",
         true,
         eligible,
         per_tick,
         sweep,
         _excluded,
         _unstable,
         bytes,
         _elapsed,
         false,
         "within_budget",
         false,
         "rx_page_content_anonymous_jit_out_of_scope"
       ),
       do: per_tick > 0 and sweep > 0 and sweep < eligible and bytes == per_tick * 8_192

  defp valid_projection_status_v2?(
         "clean",
         "supported",
         true,
         _eligible,
         per_tick,
         _sweep,
         _excluded,
         0,
         bytes,
         _elapsed,
         true,
         "within_budget",
         false,
         "rx_page_content_anonymous_jit_out_of_scope"
       ),
       do: per_tick > 0 and bytes == per_tick * 8_192

  defp valid_projection_status_v2?(
         "mismatch",
         "supported",
         true,
         _eligible,
         per_tick,
         sweep,
         _excluded,
         _unstable,
         bytes,
         _elapsed,
         _full,
         "within_budget",
         true,
         "rx_page_content_anonymous_jit_out_of_scope"
       ),
       do: per_tick > 0 and sweep > 0 and bytes == per_tick * 8_192

  defp valid_projection_status_v2?(
         "degraded",
         "degraded",
         true,
         eligible,
         per_tick,
         sweep,
         excluded,
         unstable,
         bytes,
         elapsed,
         full,
         budget_state,
         false,
         limitation
       ) do
    degraded_bytes? = bytes in [per_tick * 8_192, per_tick * 8_192 + 4_096]

    cause? =
      limitation in (@limitation_ids_v2 --
                       ~w(rx_page_content_anonymous_jit_out_of_scope rx_page_content_disabled rx_page_content_elf_unsupported))

    fail_closed_cause? =
      limitation in ~w(rx_page_content_coverage_limit_exceeded rx_page_content_bootstrap_budget_exceeded)

    cause? and degraded_bytes? and
      (not fail_closed_cause? or
         (eligible == 0 and per_tick == 0 and sweep == 0 and excluded == 0 and unstable == 0 and
            bytes == 0 and elapsed == 0 and full == false and budget_state == "within_budget"))
  end

  defp valid_projection_status_v2?(
         "unsupported",
         "degraded",
         true,
         0,
         0,
         0,
         0,
         0,
         0,
         _elapsed,
         false,
         "within_budget",
         false,
         "rx_page_content_elf_unsupported"
       ),
       do: true

  defp valid_projection_status_v2?(_, _, _, _, _, _, _, _, _, _, _, _, _, _), do: false

  defp valid_uuid?(value) when is_binary(value), do: match?({:ok, _}, Ecto.UUID.cast(value))
  defp valid_uuid?(_), do: false

  defp valid_decimal_u64?(value) when is_binary(value) do
    case Integer.parse(value) do
      {number, ""} when number >= 0 and number <= 18_446_744_073_709_551_615 ->
        Integer.to_string(number) == value

      _ ->
        false
    end
  end

  defp valid_decimal_u64?(_), do: false

  defp valid_findings?(findings) do
    length(findings) <= map_size(@finding_evidence) and
      Enum.all?(findings, fn finding ->
        is_map(finding) and exact_keys?(finding, @finding_keys) and
          Map.get(@finding_evidence, value(finding, "kind")) == value(finding, "evidence")
      end) and
      findings
      |> Enum.map(&value(&1, "kind"))
      |> valid_string_set?()
  end

  defp valid_page?(page, runtime_state, findings, limitations) do
    status = value(page, "status")
    enabled = value(page, "enabled")
    eligible = value(page, "eligible_pages")
    compared = value(page, "compared_pages")
    excluded = value(page, "excluded_relocation_pages")
    unstable = value(page, "unstable_pages")
    bytes = value(page, "bytes_read")
    elapsed = value(page, "elapsed_us")
    budget = value(page, "budget_limit_us")
    full = value(page, "full_sweep_completed")
    budget_state = value(page, "budget_state")
    baseline = value(page, "baseline_source")
    drift? = Enum.any?(findings, &(value(&1, "kind") == "file_backed_executable_page_drift"))

    exact_keys?(page, @page_keys) and
      value(page, "capability_id") == @capability_id and
      value(page, "maturity") == "preview" and
      value(page, "mode") == "observe_only" and
      is_boolean(enabled) and status in @statuses and
      baseline in ~w(none protected_config_sha256_startup_fd) and
      bounded_integer?(eligible, 0, 1024) and bounded_integer?(compared, 0, 16) and
      bounded_integer?(excluded, 0, 16_384) and bounded_integer?(unstable, 0, 16) and
      bounded_integer?(bytes, 0, 65_536) and bounded_integer?(elapsed, 0, 60_000) and
      budget == 10_000 and is_boolean(full) and budget_state in ~w(within_budget exceeded) and
      compared <= eligible and unstable <= compared and bytes == compared * 4096 and
      (not full or compared == eligible) and
      ((budget_state == "within_budget" and elapsed <= budget) or
         (budget_state == "exceeded" and elapsed > budget)) and
      budget_limit_consistent?(budget_state, limitations) and
      valid_status?(
        status,
        runtime_state,
        enabled,
        baseline,
        eligible,
        compared,
        excluded,
        unstable,
        bytes,
        full,
        budget_state,
        drift?,
        findings,
        limitations
      )
  end

  defp valid_page_v2?(page, runtime_state, findings, limitations) do
    status = value(page, "status")
    baseline = value(page, "baseline_source")
    finding_kinds = Enum.map(findings, &value(&1, "kind"))
    coverage = coverage_from_page_v2(page)

    exact_keys?(page, @page_keys_v2) and
      value(page, "capability_id") == @capability_id_v2 and
      value(page, "maturity") == "preview" and value(page, "mode") == "observe_only" and
      baseline in ~w(none protected_config_sha256_startup_fd) and
      valid_projection_coverage_v2?(
        coverage,
        status,
        runtime_state,
        value(page, "enabled"),
        finding_kinds,
        limitations
      ) and valid_baseline_v2?(status, baseline, limitations)
  end

  defp valid_baseline_v2?(status, baseline, [limitation]) do
    cond do
      status in ~w(disabled unsupported) ->
        baseline == "none"

      status in ~w(partial clean mismatch) ->
        protected_baseline?(baseline)

      limitation in ~w(rx_page_content_coverage_limit_exceeded rx_page_content_bootstrap_budget_exceeded) ->
        baseline == "none"

      status == "degraded" ->
        valid_terminal_baseline?(baseline)

      true ->
        false
    end
  end

  defp valid_baseline_v2?(_, _, _), do: false

  defp valid_status?(
         "disabled",
         _runtime_state,
         false,
         "none",
         0,
         0,
         0,
         0,
         0,
         false,
         "within_budget",
         false,
         _findings,
         limitations
       ),
       do: page_limitation_ids(limitations) == ["rx_page_content_disabled"]

  defp valid_status?(
         "partial",
         _runtime_state,
         true,
         baseline,
         eligible,
         compared,
         _excluded,
         _unstable,
         _bytes,
         false,
         "within_budget",
         false,
         findings,
         limitations
       ),
       do:
         protected_baseline?(baseline) and compared > 0 and compared < eligible and
           benign_page_limitations?(limitations) and is_list(findings)

  defp valid_status?(
         "clean",
         _runtime_state,
         true,
         baseline,
         eligible,
         compared,
         _excluded,
         unstable,
         _bytes,
         true,
         "within_budget",
         false,
         findings,
         limitations
       ),
       do:
         protected_baseline?(baseline) and compared > 0 and compared == eligible and unstable == 0 and
           benign_page_limitations?(limitations) and is_list(findings)

  defp valid_status?(
         "mismatch",
         _runtime_state,
         true,
         baseline,
         _eligible,
         compared,
         _excluded,
         _unstable,
         _bytes,
         _full,
         "within_budget",
         true,
         findings,
         limitations
       ),
       do:
         protected_baseline?(baseline) and compared > 0 and benign_page_limitations?(limitations) and
           Enum.count(findings, &(value(&1, "kind") == "file_backed_executable_page_drift")) == 1

  defp valid_status?(
         "degraded",
         "degraded",
         true,
         baseline,
         _eligible,
         _compared,
         _excluded,
         _unstable,
         _bytes,
         false,
         budget_state,
         false,
         findings,
         limitations
       ),
       do:
         valid_terminal_baseline?(baseline) and is_list(findings) and
           Enum.any?(limitations, &(&1 in @degraded_limitation_ids)) and
           ((budget_state == "exceeded" and "rx_page_content_budget_exceeded" in limitations) or
              budget_state == "within_budget")

  defp valid_status?(
         "unsupported",
         "degraded",
         true,
         baseline,
         0,
         0,
         0,
         0,
         0,
         false,
         "within_budget",
         false,
         findings,
         limitations
       ),
       do:
         valid_terminal_baseline?(baseline) and is_list(findings) and
           "rx_page_content_elf_unsupported" in limitations

  defp valid_status?(_, _, _, _, _, _, _, _, _, _, _, _, _, _), do: false

  defp protected_baseline?(value), do: value == "protected_config_sha256_startup_fd"
  defp valid_terminal_baseline?(value), do: value in ~w(none protected_config_sha256_startup_fd)

  defp benign_page_limitations?(limitations) do
    Enum.all?(
      page_limitation_ids(limitations),
      &(&1 == "rx_page_content_anonymous_jit_out_of_scope")
    )
  end

  defp page_limitation_ids(limitations), do: Enum.filter(limitations, &(&1 in @limitation_ids))

  defp normalize_observed_at(nil), do: {:ok, nil}
  defp normalize_observed_at(%DateTime{} = value), do: {:ok, DateTime.to_iso8601(value)}

  defp normalize_observed_at(%NaiveDateTime{} = value) do
    {:ok, value |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_iso8601()}
  end

  defp normalize_observed_at(value) when is_integer(value) and value > 0 do
    case DateTime.from_unix(value, :millisecond) do
      {:ok, datetime} -> {:ok, DateTime.to_iso8601(datetime)}
      _ -> {:error, :invalid_contract}
    end
  end

  defp normalize_observed_at(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> {:ok, DateTime.to_iso8601(datetime)}
      _ -> {:error, :invalid_contract}
    end
  end

  defp normalize_observed_at(_), do: {:error, :invalid_contract}

  defp sort_key(nil, index), do: {-1, -index}

  defp sort_key(value, index) do
    {:ok, datetime, _offset} = DateTime.from_iso8601(value)
    {DateTime.to_unix(datetime, :microsecond), -index}
  end

  defp exact_keys?(map, expected) when is_map(map) do
    keys = map |> Map.keys() |> Enum.map(&to_string/1) |> Enum.sort()
    keys == Enum.sort(expected) and length(keys) == map_size(map)
  end

  defp valid_string_set?(values) when is_list(values) do
    Enum.all?(values, &is_binary/1) and values == Enum.sort(values) and
      length(values) == length(Enum.uniq(values))
  end

  defp valid_limitations?(values) do
    valid_string_set?(values) and
      Enum.all?(values, &(&1 == @legacy_limitation or &1 in @limitation_ids))
  end

  defp budget_limit_consistent?(budget_state, limitations) do
    budget_state == "exceeded" ==
      "rx_page_content_budget_exceeded" in limitations
  end

  defp bounded_integer?(value, min, max), do: is_integer(value) and value >= min and value <= max

  defp bounded_reserved_scan(term) do
    if :erlang.external_size(term) > @inbound_scan_max_bytes do
      :reserved_or_unbounded
    else
      scan_reserved(term, 0, 0)
      |> elem(0)
    end
  rescue
    _ -> :reserved_or_unbounded
  end

  defp scan_reserved(term, depth, nodes) do
    cond do
      depth > @inbound_scan_max_depth ->
        {:reserved_or_unbounded, nodes}

      nodes + 1 > @inbound_scan_max_items ->
        {:reserved_or_unbounded, nodes}

      term in @reserved_scalar_tokens ->
        {:reserved_or_unbounded, nodes + 1}

      is_map(term) ->
        scan_reserved_map(term, depth, nodes + 1)

      is_list(term) ->
        scan_reserved_list(term, depth, nodes + 1)

      true ->
        {:clear, nodes + 1}
    end
  end

  defp scan_reserved_map(map, depth, nodes) do
    Enum.reduce_while(map, {:clear, nodes}, fn {key, value}, {:clear, count} ->
      with {:clear, count} <- scan_reserved(key, depth + 1, count),
           {:clear, count} <- scan_reserved(value, depth + 1, count) do
        {:cont, {:clear, count}}
      else
        {:reserved_or_unbounded, count} -> {:halt, {:reserved_or_unbounded, count}}
      end
    end)
  end

  defp scan_reserved_list(list, depth, nodes) do
    Enum.reduce_while(list, {:clear, nodes}, fn child, {:clear, count} ->
      case scan_reserved(child, depth + 1, count) do
        {:clear, count} -> {:cont, {:clear, count}}
        {:reserved_or_unbounded, count} -> {:halt, {:reserved_or_unbounded, count}}
      end
    end)
  end

  defp value(map, key) when is_map(map) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, String.to_existing_atom(key))
    end
  rescue
    ArgumentError -> Map.get(map, key)
  end
end
