defmodule TamanduaServer.Agents.TrustPosture do
  @moduledoc """
  Pure, metadata-only projection of endpoint trust signals.

  The projection never treats a client-provided identity label as attestation.
  `verified` requires an explicit server-side verification source and fresh,
  complete evidence for every source selected as required by the caller.

  This module performs no persistence, tenant lookup, policy action, or event
  ingestion. Callers own tenancy and pass only the signals already authorized
  for the endpoint being projected.
  """

  @schema "tamandua.trust_posture/v1"
  @states ~w(verified unverified degraded suspected_clone revoked)
  @sources [:device_identity, :runtime_integrity, :app_guard, :offline_checkpoint]
  @server_verifiers ~w(
    server_verified
    server_challenge
    platform_verifier
    google_play_integrity
    android_key_attestation
    apple_app_attest
    apple_devicecheck
    mdm_server
  )
  @runtime_findings ~w(
    writable_executable_mapping
    debugger_or_tracer_attached
    instrumentation_library_loaded
    file_backed_executable_page_drift
  )
  @app_guard_signals ~w(
    app_integrity_violation
    code_signature_drift_detected
    debugger_detected
    device_identity_drift
    device_clone_suspected
    frida_detected
    hook_framework_detected
    native_hook_detected
    runtime_memory_tamper_detected
    tampering_detected
  )
  @adverse_states ~w(degraded suspected_clone revoked)
  @fixed_reason_codes ~w(
    identity_server_verified
    identity_not_verified
    client_claimed_attestation_unverified
    device_credential_revoked
    device_identity_drift
    runtime_integrity_adverse
    app_guard_adverse
    offline_checkpoint_adverse
    corroborated_clone_or_tamper
  )
  @source_reason_prefixes ~w(
    source_missing
    source_unsupported
    source_degraded
    source_stale
    source_future_timestamp
    source_freshness_unknown
  )

  @type projection_state :: String.t()

  @doc """
  Projects a deterministic trust posture from already scoped signals.

  Required options for deterministic freshness evaluation:

    * `:now` - a `DateTime` or ISO8601 timestamp;
    * `:max_age_seconds` - freshness window, defaults to 900;
    * `:required_sources` - applicable source atoms, defaults to all sources;
    * `:previous` - an earlier projection used only for sanitized recovery history.

  When `:now` is omitted, timestamped evidence has `unknown` freshness and can
  never produce `verified`.
  """
  @spec project(map(), keyword()) :: map()
  def project(signals, opts \\ []) when is_map(signals) and is_list(opts) do
    now = parse_datetime(Keyword.get(opts, :now))
    max_age_seconds = positive_integer(Keyword.get(opts, :max_age_seconds), 900)
    future_tolerance_seconds = positive_integer(Keyword.get(opts, :future_tolerance_seconds), 300)
    required_sources = required_sources(Keyword.get(opts, :required_sources, @sources))

    provenance =
      Map.new(@sources, fn source ->
        raw = source_value(signals, source)

        {source,
         summarize_source(
           source,
           raw,
           now,
           max_age_seconds,
           future_tolerance_seconds
         )}
      end)

    completeness = evidence_completeness(provenance, required_sources)
    findings = trust_findings(provenance)
    corroboration = corroboration(findings)
    reasons = reason_codes(provenance, completeness, findings, corroboration)
    state = posture_state(provenance, completeness, findings, corroboration)
    risk_score = risk_score(provenance, completeness, findings, corroboration, state)

    %{
      schema: @schema,
      state: state,
      risk_score: risk_score,
      confidence: confidence(state, completeness, provenance),
      evaluated_at: datetime_to_iso8601(now),
      reason_codes: reasons,
      evidence_completeness: completeness,
      provenance: provenance,
      correlation: %{
        corroborated: corroboration.corroborated,
        contributing_sources: corroboration.sources,
        signal_families: corroboration.families
      },
      history: recovery_history(Keyword.get(opts, :previous), state, reasons, provenance)
    }
  end

  def states, do: @states
  def sources, do: @sources

  defp summarize_source(source, nil, _now, _max_age, _future_tolerance) do
    base_source(source, "missing", "missing", nil)
    |> Map.merge(source_details(source, %{}))
  end

  defp summarize_source(source, raw, now, max_age, future_tolerance) when is_map(raw) do
    status = source_status(source, raw)
    collected_at = parse_datetime(value(raw, :collected_at) || value(raw, :observed_at))
    freshness = freshness(status, collected_at, now, max_age, future_tolerance)

    base_source(source, status, freshness, datetime_to_iso8601(collected_at))
    |> Map.merge(source_details(source, raw))
  end

  defp summarize_source(source, _raw, _now, _max_age, _future_tolerance) do
    base_source(source, "degraded", "missing", nil)
    |> Map.merge(source_details(source, %{}))
  end

  defp base_source(source, status, freshness, collected_at) do
    %{
      source: Atom.to_string(source),
      status: status,
      freshness: freshness,
      collected_at: collected_at
    }
  end

  defp source_details(:device_identity, raw) do
    assurance = identity_assurance(raw)

    %{
      assurance: assurance,
      server_verified: assurance == "server_verified",
      client_claimed_attestation: client_claimed_attestation?(raw),
      drift_indicators: identity_drift_indicators(raw)
    }
  end

  defp source_details(:runtime_integrity, raw) do
    finding_kinds =
      raw
      |> list_value(:finding_kinds, :findings)
      |> normalize_named_items()
      |> Enum.filter(&(&1 in @runtime_findings))
      |> Enum.uniq()
      |> Enum.sort()

    %{
      transition: runtime_transition(raw, finding_kinds),
      finding_kinds: finding_kinds
    }
  end

  defp runtime_transition(raw, _finding_kinds) do
    allow(value(raw, :transition), ~w(
      finding_detected finding_changed collector_degraded recovered collector_observed
    ))
  end

  defp source_details(:app_guard, raw) do
    %{
      decision: allow(value(raw, :decision), ~w(allow observe warn step_up block kill_session)),
      risk_score: bounded_integer(value(raw, :risk_score) || value(raw, :score)),
      active_signals:
        raw
        |> list_value(:active_signals, :signals)
        |> normalize_named_items()
        |> Enum.filter(&(&1 in @app_guard_signals))
        |> Enum.uniq()
        |> Enum.sort()
    }
  end

  defp source_details(:offline_checkpoint, raw) do
    %{
      protection: allow(value(raw, :protection), ~w(authenticated degraded_unkeyed unavailable)),
      checkpoint_result: allow(value(raw, :checkpoint_result) || value(raw, :result), ~w(
          verified mismatch rollback_detected replay_detected unavailable
        ))
    }
  end

  defp source_status(:device_identity, raw) do
    cond do
      normalized(value(raw, :status)) == "revoked" -> "revoked"
      normalized(value(raw, :credential_state)) == "revoked" -> "revoked"
      true -> generic_status(raw)
    end
  end

  defp source_status(:runtime_integrity, raw) do
    status = normalized(value(raw, :status))

    cond do
      status == "unsupported" ->
        "unsupported"

      status == "degraded" ->
        "degraded"

      true ->
        case normalized(value(raw, :runtime_state) || value(raw, :state) || value(raw, :status)) do
          "supported" -> "available"
          "recovered" -> "available"
          other -> normalize_status(other)
        end
    end
  end

  defp source_status(:offline_checkpoint, raw) do
    case normalized(value(raw, :checkpoint_result) || value(raw, :result)) do
      result when result in ~w(mismatch rollback_detected replay_detected) -> "degraded"
      _ -> generic_status(raw)
    end
  end

  defp source_status(_source, raw), do: generic_status(raw)

  defp generic_status(raw) do
    raw
    |> value(:status)
    |> normalized()
    |> normalize_status()
  end

  defp normalize_status(status)
       when status in ~w(available healthy supported verified unverified active),
       do: "available"

  defp normalize_status(status) when status in ~w(missing unsupported degraded revoked),
    do: status

  defp normalize_status(_status), do: "degraded"

  defp freshness("missing", _collected_at, _now, _max_age, _future_tolerance), do: "missing"

  defp freshness("unsupported", _collected_at, _now, _max_age, _future_tolerance),
    do: "unsupported"

  defp freshness(_status, nil, _now, _max_age, _future_tolerance), do: "missing"
  defp freshness(_status, _collected_at, nil, _max_age, _future_tolerance), do: "unknown"

  defp freshness(_status, collected_at, now, max_age, future_tolerance) do
    age = DateTime.diff(now, collected_at, :second)

    cond do
      age < -future_tolerance -> "invalid_future"
      age > max_age -> "stale"
      true -> "fresh"
    end
  end

  defp identity_assurance(raw) do
    cond do
      source_status(:device_identity, raw) == "revoked" -> "revoked"
      server_verified_identity?(raw) -> "server_verified"
      client_claimed_attestation?(raw) -> "client_claimed"
      true -> "unverified"
    end
  end

  defp server_verified_identity?(raw) do
    [:proof_of_possession, :attestation]
    |> Enum.map(&value(raw, &1))
    |> Enum.any?(&server_verified_proof?/1)
  end

  defp server_verified_proof?(proof) when is_map(proof) do
    normalized(value(proof, :status)) == "verified" and
      normalized(value(proof, :verification_source)) in @server_verifiers and
      normalized(value(proof, :verification_authority)) in ~w(server tamandua_server)
  end

  defp server_verified_proof?(_proof), do: false

  defp client_claimed_attestation?(raw) do
    claimed_source =
      normalized(value(raw, :identity_source)) in ~w(platform_attested mdm_attested)

    explicit_claim =
      [:proof_of_possession, :attestation]
      |> Enum.map(&value(raw, &1))
      |> Enum.any?(fn
        proof when is_map(proof) ->
          normalized(value(proof, :status)) == "client_claimed" or
            normalized(value(proof, :verification_source)) == "client_claimed"

        _ ->
          false
      end)

    (claimed_source or explicit_claim) and not server_verified_identity?(raw)
  end

  defp identity_drift_indicators(raw) do
    indicators =
      raw
      |> list_value(:drift_indicators, :signals)
      |> normalize_named_items()

    direct =
      [
        {"device_identity_drift", truthy?(value(raw, :device_identity_drift))},
        {"device_clone_suspected", truthy?(value(raw, :clone_suspected))},
        {"device_key_reuse", truthy?(value(raw, :key_reuse_detected))},
        {"device_rebind_anomaly", truthy?(value(raw, :rebind_anomaly))}
      ]
      |> Enum.filter(fn {_name, present} -> present end)
      |> Enum.map(&elem(&1, 0))

    (indicators ++ direct)
    |> Enum.filter(&(&1 in ~w(
      device_identity_drift device_clone_suspected device_key_reuse device_rebind_anomaly
    )))
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp evidence_completeness(provenance, required_sources) do
    required = Map.take(provenance, required_sources)

    %{
      required_sources: Enum.map(required_sources, &Atom.to_string/1),
      present_sources: selected_sources(required, &(&1.status != "missing")),
      fresh_sources: selected_sources(required, &(&1.freshness == "fresh")),
      missing_sources: selected_sources(required, &(&1.status == "missing")),
      unsupported_sources: selected_sources(required, &(&1.status == "unsupported")),
      degraded_sources: selected_sources(required, &(&1.status == "degraded")),
      stale_sources: selected_sources(required, &(&1.freshness == "stale")),
      invalid_future_sources: selected_sources(required, &(&1.freshness == "invalid_future")),
      unknown_freshness_sources: selected_sources(required, &(&1.freshness == "unknown")),
      complete:
        Enum.all?(required, fn {_source, item} ->
          item.status == "available" and item.freshness == "fresh"
        end)
    }
  end

  defp selected_sources(provenance, predicate) do
    provenance
    |> Enum.filter(fn {_source, item} -> predicate.(item) end)
    |> Enum.map(fn {source, _item} -> Atom.to_string(source) end)
    |> Enum.sort()
  end

  defp trust_findings(provenance) do
    identity = provenance.device_identity
    runtime = provenance.runtime_integrity
    app_guard = provenance.app_guard
    offline = provenance.offline_checkpoint

    %{
      revoked: identity.status == "revoked" or identity.assurance == "revoked",
      identity_drift: actionable_source?(identity) and identity.drift_indicators != [],
      runtime_tamper:
        actionable_source?(runtime) and runtime.finding_kinds != [] and
          runtime.transition in ~w(finding_detected finding_changed),
      app_guard_tamper:
        actionable_source?(app_guard) and
          (Enum.any?(app_guard.active_signals, &(&1 in ~w(
             app_integrity_violation code_signature_drift_detected frida_detected
             hook_framework_detected native_hook_detected runtime_memory_tamper_detected
             tampering_detected device_identity_drift device_clone_suspected
           ))) or app_guard.decision in ~w(block kill_session)),
      app_guard_identity_drift:
        actionable_source?(app_guard) and
          Enum.any?(
            app_guard.active_signals,
            &(&1 in ~w(device_identity_drift device_clone_suspected))
          ),
      offline_rollback:
        actionable_source?(offline) and
          offline.checkpoint_result in ~w(mismatch rollback_detected replay_detected)
    }
  end

  defp actionable_source?(source) do
    source.status in ~w(available degraded) and source.freshness == "fresh"
  end

  defp corroboration(findings) do
    sources =
      []
      |> maybe_add(findings.identity_drift, "device_identity")
      |> maybe_add(findings.runtime_tamper, "runtime_integrity")
      |> maybe_add(findings.app_guard_tamper, "app_guard")
      |> maybe_add(findings.offline_rollback, "offline_checkpoint")
      |> Enum.uniq()
      |> Enum.sort()

    corroborated =
      (findings.identity_drift and length(sources -- ["device_identity"]) > 0) or
        (findings.app_guard_identity_drift and length(sources -- ["app_guard"]) > 0)

    families =
      []
      |> maybe_add(findings.identity_drift or findings.app_guard_identity_drift, "identity_drift")
      |> maybe_add(findings.runtime_tamper or findings.app_guard_tamper, "runtime_tamper")
      |> maybe_add(findings.offline_rollback, "offline_rollback")
      |> Enum.uniq()
      |> Enum.sort()

    %{corroborated: corroborated, sources: sources, families: families}
  end

  defp posture_state(_provenance, _completeness, %{revoked: true}, _corroboration),
    do: "revoked"

  defp posture_state(_provenance, _completeness, _findings, %{corroborated: true}),
    do: "suspected_clone"

  defp posture_state(provenance, completeness, findings, _corroboration) do
    degraded =
      completeness.missing_sources != [] or
        completeness.degraded_sources != [] or
        completeness.stale_sources != [] or
        completeness.invalid_future_sources != [] or
        completeness.unknown_freshness_sources != [] or
        findings.runtime_tamper or findings.app_guard_tamper or findings.offline_rollback

    cond do
      degraded ->
        "degraded"

      provenance.device_identity.assurance == "server_verified" and completeness.complete ->
        "verified"

      true ->
        "unverified"
    end
  end

  defp reason_codes(provenance, completeness, findings, corroboration) do
    []
    |> maybe_add(
      provenance.device_identity.assurance == "server_verified",
      "identity_server_verified"
    )
    |> maybe_add(provenance.device_identity.assurance == "unverified", "identity_not_verified")
    |> maybe_add(
      provenance.device_identity.client_claimed_attestation,
      "client_claimed_attestation_unverified"
    )
    |> maybe_add(findings.revoked, "device_credential_revoked")
    |> maybe_add(findings.identity_drift, "device_identity_drift")
    |> maybe_add(findings.runtime_tamper, "runtime_integrity_adverse")
    |> maybe_add(findings.app_guard_tamper, "app_guard_adverse")
    |> maybe_add(findings.offline_rollback, "offline_checkpoint_adverse")
    |> maybe_add(corroboration.corroborated, "corroborated_clone_or_tamper")
    |> add_source_reasons("source_missing", completeness.missing_sources)
    |> add_source_reasons("source_unsupported", completeness.unsupported_sources)
    |> add_source_reasons("source_degraded", completeness.degraded_sources)
    |> add_source_reasons("source_stale", completeness.stale_sources)
    |> add_source_reasons("source_future_timestamp", completeness.invalid_future_sources)
    |> add_source_reasons("source_freshness_unknown", completeness.unknown_freshness_sources)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp risk_score(provenance, completeness, findings, corroboration, state) do
    score =
      0
      |> add_points(provenance.device_identity.assurance == "unverified", 10)
      |> add_points(provenance.device_identity.client_claimed_attestation, 10)
      |> add_points(findings.identity_drift, 35)
      |> add_points(findings.runtime_tamper, 25)
      |> add_points(findings.app_guard_tamper, 25)
      |> add_points(findings.offline_rollback, 35)
      |> add_points(corroboration.corroborated, 20)
      |> add_points(true, length(completeness.missing_sources) * 10)
      |> add_points(true, length(completeness.unsupported_sources) * 5)
      |> add_points(true, length(completeness.degraded_sources) * 15)
      |> add_points(true, length(completeness.stale_sources) * 8)
      |> add_points(true, length(completeness.invalid_future_sources) * 15)
      |> add_points(true, length(completeness.unknown_freshness_sources) * 5)
      |> min(100)

    if state == "revoked", do: 100, else: score
  end

  defp confidence("verified", completeness, _provenance) when completeness.complete, do: 95
  defp confidence("revoked", _completeness, _provenance), do: 100
  defp confidence("suspected_clone", _completeness, _provenance), do: 90

  defp confidence(_state, completeness, provenance) do
    fresh = length(completeness.fresh_sources)
    required = max(length(completeness.required_sources), 1)

    assurance_bonus =
      if provenance.device_identity.assurance == "server_verified", do: 15, else: 0

    min(80, div(fresh * 60, required) + assurance_bonus)
  end

  defp recovery_history(previous, state, reasons, provenance) when is_map(previous) do
    previous_state = normalized(value(previous, :state))
    previous_reasons = safe_reason_codes(value(previous, :reason_codes))
    previous_provenance = value(previous, :provenance) || %{}

    recovered_sources =
      @sources
      |> Enum.filter(fn source ->
        current = Map.fetch!(provenance, source)
        prior = source_value(previous_provenance, source) || %{}

        source_recovered?(source, prior, current)
      end)
      |> Enum.map(&Atom.to_string/1)
      |> Enum.sort()

    last_adverse_state =
      cond do
        previous_state in @adverse_states ->
          previous_state

        normalized(get_in_any(previous, [:history, :last_adverse_state])) in @adverse_states ->
          normalized(get_in_any(previous, [:history, :last_adverse_state]))

        true ->
          nil
      end

    %{
      previous_state: allow(previous_state, @states),
      last_adverse_state: last_adverse_state,
      previous_reason_codes: previous_reasons,
      recovered_sources: recovered_sources,
      recovery_observed: recovered_sources != [] and state not in @adverse_states,
      current_reason_codes: reasons
    }
  end

  defp recovery_history(_previous, _state, reasons, _provenance) do
    %{
      previous_state: nil,
      last_adverse_state: nil,
      previous_reason_codes: [],
      recovered_sources: [],
      recovery_observed: false,
      current_reason_codes: reasons
    }
  end

  defp source_recovered?(source, prior, current) do
    prior_adverse =
      normalized(value(prior, :status)) in ~w(missing unsupported degraded revoked) or
        normalized(value(prior, :freshness)) in ~w(stale invalid_future unknown missing) or
        (source == :runtime_integrity and
           normalized(value(prior, :transition)) in ~w(finding_detected finding_changed collector_degraded))

    current_recovered =
      current.status == "available" and current.freshness == "fresh" and
        (source != :runtime_integrity or current.transition in [nil, "recovered"])

    prior_adverse and current_recovered
  end

  defp required_sources(values) when is_list(values) do
    normalized_sources =
      values
      |> Enum.map(fn
        value when is_atom(value) -> value
        value when is_binary(value) -> Enum.find(@sources, &(Atom.to_string(&1) == value))
        _ -> nil
      end)
      |> Enum.filter(&(&1 in @sources))

    [:device_identity | normalized_sources]
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp required_sources(_values), do: @sources

  defp source_value(map, source) when is_map(map), do: value(map, source)
  defp source_value(_map, _source), do: nil

  defp value(map, key) when is_map(map) and is_atom(key) do
    case Map.fetch(map, key) do
      {:ok, result} -> result
      :error -> Map.get(map, Atom.to_string(key))
    end
  end

  defp value(_map, _key), do: nil

  defp get_in_any(map, [key | rest]) when is_map(map) do
    case value(map, key) do
      nil -> nil
      child when rest == [] -> child
      child -> get_in_any(child, rest)
    end
  end

  defp get_in_any(_map, _keys), do: nil

  defp list_value(map, primary, fallback) do
    case value(map, primary) do
      values when is_list(values) and values != [] ->
        values

      _ ->
        case value(map, fallback) do
          values when is_list(values) -> values
          _ -> []
        end
    end
  end

  defp normalize_named_items(items) do
    Enum.flat_map(items, fn
      item when is_binary(item) ->
        [normalized(item)]

      item when is_atom(item) ->
        [normalized(item)]

      item when is_map(item) ->
        case value(item, :kind) || value(item, :name) do
          nil -> []
          name -> [normalized(name)]
        end

      _ ->
        []
    end)
  end

  defp normalized(nil), do: nil
  defp normalized(value), do: value |> to_string() |> String.trim() |> String.downcase()

  defp allow(value, allowed) do
    normalized = normalized(value)
    if normalized in allowed, do: normalized, else: nil
  end

  defp parse_datetime(%DateTime{} = value), do: value

  defp parse_datetime(%NaiveDateTime{} = value) do
    DateTime.from_naive!(value, "Etc/UTC")
  end

  defp parse_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> datetime
      _ -> nil
    end
  end

  defp parse_datetime(_value), do: nil

  defp datetime_to_iso8601(%DateTime{} = value), do: DateTime.to_iso8601(value)
  defp datetime_to_iso8601(_value), do: nil

  defp positive_integer(value, _default) when is_integer(value) and value > 0, do: value
  defp positive_integer(_value, default), do: default

  defp bounded_integer(value) when is_integer(value), do: value |> max(0) |> min(100)
  defp bounded_integer(_value), do: nil

  defp truthy?(value), do: value in [true, 1, "true", "present", "detected"]

  defp maybe_add(list, true, value), do: [value | list]
  defp maybe_add(list, _condition, _value), do: list

  defp add_source_reasons(reasons, prefix, sources) do
    Enum.reduce(sources, reasons, fn source, acc -> ["#{prefix}:#{source}" | acc] end)
  end

  defp add_points(score, true, points), do: score + points
  defp add_points(score, _condition, _points), do: score

  defp safe_reason_codes(values) when is_list(values) do
    values
    |> Enum.map(&normalized/1)
    |> Enum.filter(&valid_reason_code?/1)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp safe_reason_codes(_values), do: []

  defp valid_reason_code?(value) when is_binary(value) do
    value in @fixed_reason_codes or
      Enum.any?(@sources, fn source ->
        source_name = Atom.to_string(source)
        Enum.any?(@source_reason_prefixes, &(&1 <> ":" <> source_name == value))
      end)
  end

  defp valid_reason_code?(_value), do: false
end
