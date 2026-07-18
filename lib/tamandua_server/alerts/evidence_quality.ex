defmodule TamanduaServer.Alerts.EvidenceQuality do
  @moduledoc """
  Classifies alert evidence provenance for UI, API, and benchmark gates.

  This is intentionally derived from already persisted alert fields. It does not
  mutate alerts and it does not promote synthetic UI context into claimable
  evidence.
  """

  @quality_order %{
    "direct" => 5,
    "correlated" => 4,
    "derived" => 3,
    "synthetic" => 2,
    "missing" => 1
  }

  @doc """
  Return an evidence-quality summary for an alert struct or alert-like map.
  """
  def classify(alert) do
    evidence = get_map(alert, :evidence)
    raw_event = get_map(alert, :raw_event)
    detection_metadata = get_map(alert, :detection_metadata)
    source_event_id = get_value(alert, :source_event_id)
    event_ids = get_list(alert, :event_ids)
    contributing_events = get_list(alert, :contributing_events)
    process_chain = get_list(alert, :process_chain)

    app_guard_profile = app_guard_profile?(evidence)
    browser_guard_profile = browser_guard_profile?(evidence)

    investigation_context =
      investigation_context(
        evidence,
        raw_event,
        process_chain,
        app_guard_protected_app?(evidence)
      )

    checks = %{
      source_event: present?(source_event_id),
      linked_events: event_ids != [],
      contributing_events: contributing_events != [],
      evidence_bundle: non_empty_map?(evidence),
      raw_event: non_empty_map?(raw_event),
      detection: non_empty_map?(get_nested_map(evidence, :detection)) or non_empty_map?(detection_metadata),
      process: non_empty_map?(get_nested_map(evidence, :process)) or process_chain != [],
      network: network_evidence?(evidence),
      file: non_empty_map?(get_nested_map(evidence, :file)) or non_empty_list_or_map?(get_nested_value(evidence, :file_hashes)),
      registry: non_empty_list_or_map?(get_nested_value(evidence, :registry)),
      app_guard_profile: app_guard_profile,
      app_guard_protected_app: app_guard_protected_app?(evidence),
      app_guard_decision: app_guard_decision?(evidence),
      app_guard_iocs: non_empty_list_or_map?(get_nested_value(evidence, :iocs)),
      app_guard_claim_boundary: app_guard_claim_boundary?(evidence),
      browser_guard_profile: browser_guard_profile,
      browser_guard_event: browser_guard_event?(evidence, raw_event, detection_metadata),
      browser_guard_policy: browser_guard_policy?(evidence),
      browser_guard_native_bridge: browser_guard_native_bridge?(evidence),
      browser_guard_agent_link: browser_guard_agent_link?(evidence),
      browser_guard_dnr: browser_guard_dnr?(evidence),
      browser_guard_target: browser_guard_target?(evidence),
      analyst_verdict: present?(get_value(alert, :verdict)) and get_value(alert, :verdict) != "unconfirmed",
      fp_adjustment: get_value(alert, :severity_adjusted) == true or present?(get_value(alert, :false_positive_notes)),
      rule_version: present?(get_value(alert, :rule_version))
    }

    missing = missing_fields(checks)
    quality = quality(checks)
    critical_gaps? = critical_gaps?(checks, missing)
    false_positive_triage =
      false_positive_triage(alert, evidence, raw_event, detection_metadata, checks, missing, investigation_context)

    %{
      quality: quality,
      label: label(quality),
      claimable: quality in ["direct", "correlated", "derived"] and not critical_gaps?,
      benchmark_eligible: quality in ["direct", "correlated"] and not critical_gaps?,
      summary: summary(quality, checks),
      checks: checks,
      missing: missing,
      investigation_context: investigation_context,
      false_positive_triage: false_positive_triage,
      score: Map.fetch!(@quality_order, quality)
    }
  end

  defp false_positive_triage(alert, evidence, raw_event, detection_metadata, checks, missing, investigation_context) do
    signals =
      []
      |> add_missing_evidence_signals(missing, investigation_context)
      |> add_goodware_signals(alert, evidence, raw_event, detection_metadata)
      |> add_context_signals(alert, evidence, raw_event, detection_metadata, checks)

    positive = Enum.filter(signals, &(&1.direction == "fp_likelihood_up"))
    negative = Enum.filter(signals, &(&1.direction == "fp_likelihood_down"))
    limitations = fp_limitations(checks, missing)
    score = fp_score(positive, negative)

    %{
      likelihood: score,
      level: fp_level(score),
      confidence: fp_confidence(signals, checks),
      summary: fp_summary(score, positive, negative, limitations),
      signals: signals,
      fp_signals: positive,
      counter_signals: negative,
      limitations: limitations
    }
  end

  defp add_missing_evidence_signals(signals, missing, investigation_context) do
    missing_count = length(missing)

    signals =
      if missing_count > 0 do
        [
          fp_signal(
            :missing_evidence,
            "fp_likelihood_up",
            "Missing evidence limits confidence in the alert.",
            min(18, missing_count * 4),
            %{missing: missing}
          )
          | signals
        ]
      else
        signals
      end

    if investigation_context.state in ["partial", "unavailable"] do
      [
        fp_signal(
          :investigation_context_gap,
          "fp_likelihood_up",
          "Core investigation context is incomplete.",
          if(investigation_context.state == "unavailable", do: 14, else: 8),
          %{state: investigation_context.state, missing: investigation_context.missing}
        )
        | signals
      ]
    else
      signals
    end
  end

  defp add_goodware_signals(signals, alert, evidence, raw_event, detection_metadata) do
    process = get_nested_map(evidence, :process)
    file = get_nested_map(evidence, :file)
    reputation = merged_map(get_nested_map(evidence, :reputation), get_nested_map(detection_metadata, :reputation))
    baseline = merged_map(get_nested_map(evidence, :baseline), get_nested_map(detection_metadata, :baseline))
    path = first_present([get_nested_value(process, :path), get_nested_value(process, :image), get_nested_value(file, :path), get_nested_value(raw_event, :path)])
    signer = first_present([get_nested_value(process, :signer), get_nested_value(file, :signer), get_nested_value(raw_event, :signer)])

    signals
    |> maybe_add_trusted_signer(signer, process, file, raw_event)
    |> maybe_add_benign_reputation(reputation, detection_metadata)
    |> maybe_add_prevalence_signal(reputation, baseline)
    |> maybe_add_known_good_path(path)
    |> maybe_add_repeated_benign_signal(alert, evidence, detection_metadata)
  end

  defp add_context_signals(signals, _alert, evidence, raw_event, detection_metadata, checks) do
    process = get_nested_map(evidence, :process)
    file = get_nested_map(evidence, :file)
    path = first_present([get_nested_value(process, :path), get_nested_value(process, :image), get_nested_value(file, :path), get_nested_value(raw_event, :path)])
    command_line = first_present([get_nested_value(process, :command_line), get_nested_value(process, :cmdline), get_nested_value(raw_event, :command_line), get_nested_value(raw_event, :cmdline)])
    process_name = first_present([get_nested_value(process, :name), get_nested_value(raw_event, :process_name), get_nested_value(raw_event, :process)])

    signals
    |> maybe_add_unsigned_counter_signal(process, file, raw_event)
    |> maybe_add_suspicious_path_counter_signal(path)
    |> maybe_add_suspicious_process_counter_signal(process_name, command_line)
    |> maybe_add_network_counter_signal(evidence)
    |> maybe_add_ioc_counter_signal(evidence)
    |> maybe_add_model_counter_signal(detection_metadata)
    |> maybe_add_app_guard_limit_signal(checks)
  end

  defp maybe_add_trusted_signer(signals, nil, _process, _file, _raw_event), do: signals

  defp maybe_add_trusted_signer(signals, signer, process, file, raw_event) do
    signature_status =
      first_present([
        get_nested_value(process, :signature_status),
        get_nested_value(file, :signature_status),
        get_nested_value(raw_event, :signature_status),
        get_nested_value(process, :signature),
        get_nested_value(file, :signature)
      ])

    signed? =
      true_value?(get_nested_value(process, :is_signed)) or
        true_value?(get_nested_value(file, :is_signed)) or
        true_value?(get_nested_value(raw_event, :is_signed)) or
        normalized_value(signature_status) in ["valid", "trusted", "verified"]

    if signed? and trusted_publisher?(signer) do
      [
        fp_signal(
          :trusted_signer,
          "fp_likelihood_up",
          "Binary is signed by a commonly trusted publisher.",
          18,
          %{signer: signer, signature_status: signature_status}
        )
        | signals
      ]
    else
      signals
    end
  end

  defp maybe_add_benign_reputation(signals, reputation, detection_metadata) do
    verdict =
      first_present([
        get_nested_value(reputation, :verdict),
        get_nested_value(reputation, :classification),
        get_nested_value(detection_metadata, :classification),
        get_nested_value(detection_metadata, :model_prediction)
      ])

    cond do
      benign_value?(verdict) ->
        [
          fp_signal(
            :benign_reputation,
            "fp_likelihood_up",
            "Reputation or model metadata labels the artifact as benign/goodware.",
            24,
            %{verdict: verdict}
          )
          | signals
        ]

      malicious_value?(verdict) ->
        [
          fp_signal(
            :malicious_reputation,
            "fp_likelihood_down",
            "Reputation or model metadata labels the artifact as suspicious/malicious.",
            28,
            %{verdict: verdict}
          )
          | signals
        ]

      true_value?(get_nested_value(reputation, :known_good)) or true_value?(get_nested_value(reputation, :goodware)) ->
        [
          fp_signal(
            :known_good_artifact,
            "fp_likelihood_up",
            "Artifact is marked known-good in persisted metadata.",
            22,
            %{}
          )
          | signals
        ]

      true ->
        signals
    end
  end

  defp maybe_add_prevalence_signal(signals, reputation, baseline) do
    prevalence =
      first_present([
        get_nested_value(reputation, :prevalence),
        get_nested_value(reputation, :global_prevalence),
        get_nested_value(reputation, :tenant_prevalence),
        get_nested_value(baseline, :prevalence),
        get_nested_value(baseline, :seen_count),
        get_nested_value(baseline, :host_count)
      ])

    cond do
      high_prevalence?(prevalence) ->
        [
          fp_signal(
            :high_prevalence,
            "fp_likelihood_up",
            "Artifact or behavior appears prevalent in available metadata.",
            16,
            %{prevalence: prevalence}
          )
          | signals
        ]

      low_prevalence?(prevalence) ->
        [
          fp_signal(
            :low_prevalence,
            "fp_likelihood_down",
            "Artifact or behavior appears rare in available metadata.",
            12,
            %{prevalence: prevalence}
          )
          | signals
        ]

      true ->
        signals
    end
  end

  defp maybe_add_known_good_path(signals, nil), do: signals
  defp maybe_add_known_good_path(signals, path) when not is_binary(path), do: signals

  defp maybe_add_known_good_path(signals, path) do
    normalized = String.downcase(path)

    if Enum.any?(known_good_path_prefixes(), &String.starts_with?(normalized, &1)) do
      [
        fp_signal(
          :trusted_install_path,
          "fp_likelihood_up",
          "Process path is under a common OS or managed application directory.",
          12,
          %{path: path}
        )
        | signals
      ]
    else
      signals
    end
  end

  defp maybe_add_repeated_benign_signal(signals, alert, evidence, detection_metadata) do
    verdict = get_value(alert, :verdict)
    status = get_value(alert, :status)
    historical_count =
      first_present([
        get_nested_value(evidence, :historical_false_positive_count),
        get_nested_value(detection_metadata, :historical_false_positive_count),
        get_nested_value(detection_metadata, :benign_recurrence_count),
        get_nested_value(detection_metadata, :suppressed_match_count)
      ])

    cond do
      verdict in ["false_positive", "benign"] or status in ["false_positive", "benign"] ->
        [
          fp_signal(
            :analyst_benign_verdict,
            "fp_likelihood_up",
            "Analyst verdict already marks this alert benign or false positive.",
            35,
            %{verdict: verdict, status: status}
          )
          | signals
        ]

      numeric_value(historical_count) >= 3 ->
        [
          fp_signal(
            :repeated_benign_pattern,
            "fp_likelihood_up",
            "Similar alert pattern has repeated as benign in persisted metadata.",
            20,
            %{count: historical_count}
          )
          | signals
        ]

      present?(get_value(alert, :false_positive_notes)) ->
        [
          fp_signal(
            :false_positive_notes,
            "fp_likelihood_up",
            "False-positive notes are attached to this alert.",
            14,
            %{notes_present: true}
          )
          | signals
        ]

      true ->
        signals
    end
  end

  defp maybe_add_unsigned_counter_signal(signals, process, file, raw_event) do
    signed =
      first_present([
        get_nested_value(process, :is_signed),
        get_nested_value(file, :is_signed),
        get_nested_value(raw_event, :is_signed)
      ])

    if false_value?(signed) do
      [
        fp_signal(
          :unsigned_binary,
          "fp_likelihood_down",
          "Binary is explicitly unsigned in collected metadata.",
          18,
          %{}
        )
        | signals
      ]
    else
      signals
    end
  end

  defp maybe_add_suspicious_path_counter_signal(signals, nil), do: signals
  defp maybe_add_suspicious_path_counter_signal(signals, path) when not is_binary(path), do: signals

  defp maybe_add_suspicious_path_counter_signal(signals, path) do
    normalized = String.downcase(path)

    if Enum.any?(suspicious_path_fragments(), &String.contains?(normalized, &1)) do
      [
        fp_signal(
          :suspicious_path,
          "fp_likelihood_down",
          "Process path is under a user-writable or staging location.",
          16,
          %{path: path}
        )
        | signals
      ]
    else
      signals
    end
  end

  defp maybe_add_suspicious_process_counter_signal(signals, process_name, command_line) do
    text =
      [process_name, command_line]
      |> Enum.map(&text_value/1)
      |> Enum.reject(&blank?/1)
      |> Enum.join(" ")
      |> String.downcase()

    if text != "" and String.match?(text, ~r/(encodedcommand|frombase64string|mimikatz|procdump|rundll32|regsvr32|mshta|wmic|bitsadmin)/) do
      [
        fp_signal(
          :suspicious_process_or_command,
          "fp_likelihood_down",
          "Process name or command line contains known suspicious execution markers.",
          24,
          %{process_name: process_name}
        )
        | signals
      ]
    else
      signals
    end
  end

  defp maybe_add_network_counter_signal(signals, evidence) do
    if network_evidence?(evidence) and suspicious_network_evidence?(evidence) do
      [
        fp_signal(
          :suspicious_network_context,
          "fp_likelihood_down",
          "Network evidence includes external destination context.",
          14,
          %{}
        )
        | signals
      ]
    else
      signals
    end
  end

  defp maybe_add_ioc_counter_signal(signals, evidence) do
    iocs = get_nested_value(evidence, :iocs)

    if non_empty_list_or_map?(iocs) do
      [
        fp_signal(
          :ioc_evidence_present,
          "fp_likelihood_down",
          "Normalized IOC evidence is attached to the alert.",
          18,
          %{ioc_count: count_items(iocs)}
        )
        | signals
      ]
    else
      signals
    end
  end

  defp maybe_add_model_counter_signal(signals, detection_metadata) do
    confidence = numeric_value(first_present([get_nested_value(detection_metadata, :confidence), get_nested_value(detection_metadata, :score)]))
    verdict = first_present([get_nested_value(detection_metadata, :classification), get_nested_value(detection_metadata, :model_prediction)])

    if confidence >= 0.85 and malicious_value?(verdict) do
      [
        fp_signal(
          :high_confidence_malicious_model,
          "fp_likelihood_down",
          "Detection metadata contains a high-confidence malicious classification.",
          20,
          %{confidence: confidence, verdict: verdict}
        )
        | signals
      ]
    else
      signals
    end
  end

  defp maybe_add_app_guard_limit_signal(signals, %{app_guard_protected_app: true, app_guard_claim_boundary: false}) do
    [
      fp_signal(
        :app_guard_scope_unclear,
        "fp_likelihood_up",
        "Protected-app telemetry lacks a claim boundary, so device-wide conclusions are not defensible.",
        12,
        %{}
      )
      | signals
    ]
  end

  defp maybe_add_app_guard_limit_signal(signals, _checks), do: signals

  defp fp_limitations(checks, missing) do
    []
    |> maybe_add_limit(length(missing) > 0, "FP score is limited by missing evidence: #{Enum.join(missing, ", ")}.")
    |> maybe_add_limit(checks.app_guard_protected_app == true, "App Guard telemetry describes protected-app/runtime signals, not full device-wide EDR visibility.")
    |> maybe_add_limit(checks.raw_event == false, "Raw event payload is missing, so source-field validation is incomplete.")
  end

  defp maybe_add_limit(limits, true, limit), do: [limit | limits]
  defp maybe_add_limit(limits, false, _limit), do: limits

  defp fp_score(positive, negative) do
    positive_score = Enum.reduce(positive, 0, fn signal, acc -> acc + signal.weight end)
    negative_score = Enum.reduce(negative, positive_score, fn signal, acc -> acc - signal.weight end)

    negative_score
    |> max(0)
    |> min(100)
  end

  defp fp_level(score) when score >= 70, do: "high"
  defp fp_level(score) when score >= 40, do: "medium"
  defp fp_level(_score), do: "low"

  defp fp_confidence(signals, checks) do
    data_backed =
      Enum.count(signals, fn signal ->
        signal.key not in [:missing_evidence, :investigation_context_gap, :app_guard_scope_unclear]
      end)

    cond do
      checks.source_event and checks.evidence_bundle and checks.raw_event and data_backed >= 2 -> "high"
      checks.evidence_bundle and data_backed >= 1 -> "medium"
      true -> "low"
    end
  end

  defp fp_summary(score, positive, negative, limitations) do
    cond do
      positive == [] and negative == [] ->
        "No FP-likelihood signals were found in persisted alert metadata."

      score >= 70 ->
        "FP likelihood is high based on available benign/trust signals; analyst confirmation is still required."

      score >= 40 ->
        "FP likelihood is moderate; review the listed signals and limitations before changing verdict."

      negative != [] ->
        "FP likelihood is low because suspicious or malicious counter-signals are present."

      limitations != [] ->
        "FP likelihood is uncertain because evidence is incomplete."

      true ->
        "FP likelihood is low based on available metadata."
    end
  end

  defp fp_signal(key, direction, reason, weight, evidence) do
    %{
      key: key,
      direction: direction,
      reason: reason,
      weight: weight,
      evidence: evidence
    }
  end

  defp investigation_context(evidence, raw_event, process_chain, app_guard_profile) do
    process = get_nested_map(evidence, :process)

    fields = %{
      process: context_status(app_guard_profile, process_present?(process, process_chain)),
      parent_process: context_status(app_guard_profile, parent_process_present?(process, process_chain, raw_event)),
      command_line: context_status(app_guard_profile, command_line_present?(process, process_chain, raw_event)),
      network: if(network_evidence?(evidence), do: "collected", else: "not_collected")
    }

    missing =
      fields
      |> Enum.filter(fn {_field, status} -> status == "not_collected" end)
      |> Enum.map(fn {field, _status} -> context_label(field) end)
      |> Enum.sort()

    collected = Enum.count(fields, fn {_field, status} -> status == "collected" end)

    state =
      cond do
        missing == [] -> "ready"
        collected == 0 -> "unavailable"
        true -> "partial"
      end

    %{
      state: state,
      fields: fields,
      missing: missing,
      summary: investigation_context_summary(state)
    }
  end

  defp context_status(true, _present), do: "not_applicable"
  defp context_status(false, true), do: "collected"
  defp context_status(false, false), do: "not_collected"

  defp process_present?(process, process_chain) do
    Enum.any?([process | process_chain], fn candidate ->
      present?(get_nested_value(candidate, :pid)) or
        present?(get_nested_value(candidate, :name)) or
        present?(get_nested_value(candidate, :path)) or
        present?(get_nested_value(candidate, :image))
    end)
  end

  defp parent_process_present?(process, process_chain, raw_event) do
    length(process_chain) > 1 or
      Enum.any?([process, raw_event | process_chain], fn candidate ->
        present?(get_nested_value(candidate, :ppid)) or
          present?(get_nested_value(candidate, :parent_pid)) or
          present?(get_nested_value(candidate, :parent_process))
      end)
  end

  defp command_line_present?(process, process_chain, raw_event) do
    Enum.any?([process, raw_event | process_chain], fn candidate ->
      present?(get_nested_value(candidate, :command_line)) or
        present?(get_nested_value(candidate, :cmdline)) or
        present?(get_nested_value(candidate, :command))
    end)
  end

  defp context_label(:process), do: "process identity"
  defp context_label(:parent_process), do: "parent process"
  defp context_label(:command_line), do: "command line"
  defp context_label(:network), do: "network context"

  defp investigation_context_summary("ready"), do: "Core investigation context is available."
  defp investigation_context_summary("partial"), do: "Some investigation context was not collected."
  defp investigation_context_summary("unavailable"), do: "Investigation context was not collected."

  defp quality(%{source_event: true, evidence_bundle: true, raw_event: true}), do: "direct"

  defp quality(%{source_event: true, linked_events: true, evidence_bundle: true}), do: "direct"

  defp quality(%{source_event: true, contributing_events: true, evidence_bundle: true}), do: "correlated"

  defp quality(%{source_event: true, evidence_bundle: true}), do: "correlated"

  defp quality(%{evidence_bundle: true, raw_event: true, detection: true}), do: "derived"

  defp quality(%{evidence_bundle: true, detection: true}), do: "derived"

  defp quality(%{raw_event: true}), do: "synthetic"

  defp quality(_checks), do: "missing"

  defp label("direct"), do: "Direct evidence"
  defp label("correlated"), do: "Correlated evidence"
  defp label("derived"), do: "Derived evidence"
  defp label("synthetic"), do: "Synthetic context"
  defp label("missing"), do: "Missing evidence"

  defp summary("direct", _checks), do: "Persisted source event and evidence bundle are linked to this alert."
  defp summary("correlated", _checks), do: "Alert has persisted event lineage plus evidence or related-event context."
  defp summary("derived", _checks), do: "Alert is derived from detection/model evidence without a persisted source-event anchor."
  defp summary("synthetic", _checks), do: "Display context was reconstructed from raw alert payload; treat as partial evidence."
  defp summary("missing", _checks), do: "Minimum alert evidence provenance is missing."

  defp missing_fields(%{app_guard_protected_app: true} = checks) do
    common_missing_fields(checks)
    |> Kernel.++([
      {:network, "network evidence"},
      {:app_guard_iocs, "IOC evidence"},
      {:app_guard_decision, "policy decision"},
      {:app_guard_claim_boundary, "claim boundary"}
    ])
    |> reject_present(checks)
  end

  defp missing_fields(%{browser_guard_profile: true} = checks) do
    common_missing_fields(checks)
    |> Kernel.++([
      {:browser_guard_event, "browser guard event"},
      {:browser_guard_policy, "browser policy decision"},
      {:browser_guard_native_bridge, "native bridge status"},
      {:browser_guard_agent_link, "linked agent status"},
      {:browser_guard_dnr, "DNR rule evidence"},
      {:browser_guard_target, "browser target URL/domain"},
      {:process, "owning browser process"}
    ])
    |> reject_present(checks)
  end

  defp missing_fields(checks) do
    common_missing_fields(checks)
    |> Kernel.++([
      {:process, "process evidence"}
    ])
    |> reject_present(checks)
  end

  defp common_missing_fields(_checks) do
    [
      {:source_event, "source_event_id"},
      {:evidence_bundle, "evidence"},
      {:raw_event, "raw_event"},
      {:detection, "detection metadata"}
    ]
  end

  defp reject_present(fields, checks) do
    fields
    |> Enum.reject(fn {key, _label} -> Map.get(checks, key) end)
    |> Enum.map(fn {_key, label} -> label end)
  end

  defp critical_gaps?(%{app_guard_protected_app: true}, missing) do
    Enum.any?(missing, &(&1 in ["network evidence", "IOC evidence", "policy decision", "claim boundary"]))
  end

  defp critical_gaps?(%{browser_guard_profile: true}, missing) do
    Enum.any?(
      missing,
      &(&1 in [
          "browser guard event",
          "browser policy decision",
          "native bridge status",
          "linked agent status",
          "browser target URL/domain",
          "owning browser process"
        ])
    )
  end

  defp critical_gaps?(_checks, _missing), do: false

  defp app_guard_profile?(evidence) do
    app_guard_protected_app?(evidence) and
      app_guard_claim_boundary?(evidence)
  end

  defp app_guard_protected_app?(evidence) do
    non_empty_map?(get_nested_map(evidence, :app_guard)) and
      non_empty_map?(get_path_map(evidence, [:app_guard, :protected_app]))
  end

  defp app_guard_decision?(evidence) do
    present?(get_path_value(evidence, [:decision_trace, :decision])) or
      present?(get_path_value(evidence, [:policy, :decision])) or
      present?(get_path_value(evidence, [:app_guard, :decision, :decision])) or
      present?(get_path_value(evidence, [:evidence_snapshot, :policy_decision, :decision]))
  end

  defp network_evidence?(evidence) do
    non_empty_list_or_map?(get_nested_value(evidence, :network)) or
      non_empty_map?(get_path_map(evidence, [:evidence_snapshot, :network])) or
      present?(get_path_value(evidence, [:app_guard, :domain])) or
      present?(get_path_value(evidence, [:app_guard, :url]))
  end

  defp app_guard_claim_boundary?(evidence) do
    protected_app_claim_boundary?(get_nested_value(evidence, :claim_boundary)) or
      protected_app_claim_boundary?(get_path_value(evidence, [:app_guard, :claim_boundary]))
  end

  defp browser_guard_profile?(evidence) do
    non_empty_map?(get_nested_map(evidence, :browser_guard)) or
      present?(get_path_value(evidence, [:browser_guard, :extension_id])) or
      present?(get_path_value(evidence, [:browser_guard, :native_bridge])) or
      browser_guard_text_marker?(evidence)
  end

  defp browser_guard_event?(evidence, raw_event, detection_metadata) do
    Enum.any?([evidence, raw_event, detection_metadata], fn candidate ->
      event_type = get_nested_value(candidate, :event_type) || get_nested_value(candidate, :rule_name)
      source = get_nested_value(candidate, :source) || get_nested_value(candidate, :collector)

      browser_guard_text?(event_type) or browser_guard_text?(source)
    end) or browser_guard_profile?(evidence)
  end

  defp browser_guard_policy?(evidence) do
    present?(get_path_value(evidence, [:browser_guard, :policy])) or
      present?(get_path_value(evidence, [:browser_guard, :decision])) or
      present?(get_path_value(evidence, [:policy, :decision])) or
      present?(get_path_value(evidence, [:policy_decision, :decision]))
  end

  defp browser_guard_native_bridge?(evidence) do
    present?(get_path_value(evidence, [:browser_guard, :native_bridge])) or
      present?(get_path_value(evidence, [:native_bridge, :status])) or
      present?(get_nested_value(evidence, :native_bridge_status))
  end

  defp browser_guard_agent_link?(evidence) do
    present?(get_path_value(evidence, [:browser_guard, :agent_link])) or
      present?(get_path_value(evidence, [:agent_link, :status])) or
      present?(get_nested_value(evidence, :agent_id)) or
      present?(get_nested_value(evidence, :agent_link_status))
  end

  defp browser_guard_dnr?(evidence) do
    present?(get_path_value(evidence, [:browser_guard, :dnr])) or
      present?(get_path_value(evidence, [:browser_guard, :dnr_rule])) or
      present?(get_nested_value(evidence, :dnr_rule))
  end

  defp browser_guard_target?(evidence) do
    Enum.any?([:url, :domain, :host, :hostname, :tls_sni], &present?(get_nested_value(evidence, &1))) or
      Enum.any?([:url, :domain, :host, :hostname, :tls_sni], &present?(get_path_value(evidence, [:browser_guard, &1]))) or
      network_evidence?(evidence)
  end

  defp browser_guard_text_marker?(value) do
    browser_guard_text?(inspect(value))
  end

  defp browser_guard_text?(value) when is_binary(value) do
    normalized = String.downcase(value)

    String.contains?(normalized, "browser_guard") or
      String.contains?(normalized, "browser guard") or
      String.contains?(normalized, "browser_tamper") or
      String.contains?(normalized, "native_bridge") or
      String.contains?(normalized, "extension_id") or
      String.contains?(normalized, "dnr")
  end

  defp browser_guard_text?(_value), do: false

  defp protected_app_claim_boundary?(value) when is_binary(value) do
    normalized = String.downcase(value)

    String.contains?(normalized, "protected-app") and
      String.contains?(normalized, "app guard telemetry")
  end

  defp protected_app_claim_boundary?(_value), do: false

  defp suspicious_network_evidence?(evidence) do
    network = get_nested_value(evidence, :network)
    candidates = network_candidates(network) ++ network_candidates(get_path_map(evidence, [:evidence_snapshot, :network]))

    Enum.any?(candidates, fn candidate ->
      ip =
        first_present([
          get_nested_value(candidate, :remote_ip),
          get_nested_value(candidate, :dst_ip),
          get_nested_value(candidate, :destination_ip),
          get_nested_value(candidate, :ip)
        ])

      domain =
        first_present([
          get_nested_value(candidate, :domain),
          get_nested_value(candidate, :host),
          get_nested_value(candidate, :dns_name),
          get_nested_value(candidate, :sni)
        ])

      external_ip?(ip) or suspicious_domain?(domain)
    end)
  end

  defp network_candidates(value) when is_list(value), do: Enum.filter(value, &is_map/1)
  defp network_candidates(value) when is_map(value), do: [value]
  defp network_candidates(_value), do: []

  defp external_ip?(ip) when is_binary(ip) do
    not String.starts_with?(ip, ["10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "0.0.0.0", "::1"])
  end

  defp external_ip?(_ip), do: false

  defp suspicious_domain?(domain) when is_binary(domain) do
    normalized = String.downcase(domain)
    String.ends_with?(normalized, [".xyz", ".top", ".tk", ".ml", ".zip", ".mov"]) or String.contains?(normalized, "pastebin")
  end

  defp suspicious_domain?(_domain), do: false

  defp trusted_publisher?(publisher) when is_binary(publisher) do
    normalized = normalized_value(publisher)

    Enum.any?(
      [
        "microsoft",
        "google",
        "apple",
        "mozilla",
        "adobe",
        "oracle",
        "vmware",
        "crowdstrike",
        "sentinelone",
        "elastic",
        "wazuh",
        "cloudflare",
        "github"
      ],
      &String.contains?(normalized, &1)
    )
  end

  defp trusted_publisher?(_publisher), do: false

  defp benign_value?(value) when is_binary(value) or is_atom(value) do
    normalized_value(value) in ["benign", "goodware", "known_good", "clean", "trusted", "allowlisted"]
  end

  defp benign_value?(_value), do: false

  defp malicious_value?(value) when is_binary(value) or is_atom(value) do
    normalized_value(value) in ["malicious", "malware", "suspicious", "pua", "pup", "trojan", "ransomware"]
  end

  defp malicious_value?(_value), do: false

  defp high_prevalence?(value) when is_binary(value) or is_atom(value) do
    normalized = normalized_value(value)
    normalized in ["high", "common", "widespread"] or numeric_value(value) >= 50
  end

  defp high_prevalence?(value), do: numeric_value(value) >= 50

  defp low_prevalence?(value) when is_binary(value) or is_atom(value) do
    normalized = normalized_value(value)
    normalized in ["low", "rare", "first_seen", "new"] or (numeric_value(value) > 0 and numeric_value(value) <= 2)
  end

  defp low_prevalence?(value), do: numeric_value(value) > 0 and numeric_value(value) <= 2

  defp numeric_value(value) when is_integer(value), do: value
  defp numeric_value(value) when is_float(value), do: value

  defp numeric_value(value) when is_binary(value) do
    case Float.parse(value) do
      {number, _rest} -> number
      :error -> 0
    end
  end

  defp numeric_value(_value), do: 0

  defp true_value?(value) when value in [true, "true", "yes", "valid", "trusted", "verified", 1], do: true
  defp true_value?(value) when is_atom(value), do: normalized_value(value) in ["true", "yes", "valid", "trusted", "verified"]
  defp true_value?(_value), do: false

  defp false_value?(value) when value in [false, "false", "no", "invalid", "unsigned", 0], do: true
  defp false_value?(value) when is_atom(value), do: normalized_value(value) in ["false", "no", "invalid", "unsigned"]
  defp false_value?(_value), do: false

  defp normalized_value(value) when is_binary(value), do: String.downcase(value)
  defp normalized_value(value) when is_atom(value), do: value |> Atom.to_string() |> String.downcase()
  defp normalized_value(value), do: value

  defp text_value(value) when is_binary(value), do: value
  defp text_value(value) when is_atom(value), do: Atom.to_string(value)
  defp text_value(value) when is_integer(value) or is_float(value), do: to_string(value)
  defp text_value(_value), do: nil

  defp known_good_path_prefixes do
    [
      "c:\\windows\\system32\\",
      "c:\\windows\\syswow64\\",
      "c:\\program files\\",
      "c:\\program files (x86)\\",
      "/usr/bin/",
      "/usr/sbin/",
      "/bin/",
      "/sbin/",
      "/applications/"
    ]
  end

  defp suspicious_path_fragments do
    [
      "\\appdata\\local\\temp\\",
      "\\downloads\\",
      "\\users\\public\\",
      "\\programdata\\",
      "\\temp\\",
      "/tmp/",
      "/var/tmp/",
      "/downloads/"
    ]
  end

  defp merged_map(left, right) when is_map(left) and is_map(right), do: Map.merge(left, right)
  defp merged_map(left, _right) when is_map(left), do: left
  defp merged_map(_left, right) when is_map(right), do: right
  defp merged_map(_left, _right), do: %{}

  defp first_present(values), do: Enum.find(values, &present?/1)

  defp count_items(value) when is_list(value), do: Enum.count(value, &present?/1)
  defp count_items(value) when is_map(value), do: map_size(value)
  defp count_items(value), do: if(present?(value), do: 1, else: 0)

  defp get_map(source, key) do
    case get_value(source, key) do
      value when is_map(value) -> value
      _ -> %{}
    end
  end

  defp get_list(source, key) do
    case get_value(source, key) do
      value when is_list(value) -> Enum.reject(value, &blank?/1)
      value -> if present?(value), do: [value], else: []
    end
  end

  defp get_nested_map(source, key) do
    case get_nested_value(source, key) do
      value when is_map(value) -> value
      _ -> %{}
    end
  end

  defp get_nested_value(source, key) when is_map(source) do
    Map.get(source, key) || Map.get(source, Atom.to_string(key)) || Map.get(source, camelize(key))
  end

  defp get_nested_value(_source, _key), do: nil

  defp get_path_map(source, path) do
    case get_path_value(source, path) do
      value when is_map(value) -> value
      _ -> %{}
    end
  end

  defp get_path_value(source, path) when is_list(path) do
    Enum.reduce_while(path, source, fn
      key, value when is_map(value) -> {:cont, get_nested_value(value, key)}
      _key, _value -> {:halt, nil}
    end)
  end

  defp get_value(source, key) when is_map(source) do
    Map.get(source, key) || Map.get(source, Atom.to_string(key)) || Map.get(source, camelize(key))
  end

  defp get_value(_source, _key), do: nil

  defp non_empty_map?(value) when is_map(value), do: map_size(value) > 0
  defp non_empty_map?(_value), do: false

  defp non_empty_list_or_map?(value) when is_list(value), do: Enum.any?(value, &present?/1)
  defp non_empty_list_or_map?(value) when is_map(value), do: map_size(value) > 0
  defp non_empty_list_or_map?(_value), do: false

  defp present?(value), do: not blank?(value)

  defp blank?(nil), do: true
  defp blank?(""), do: true
  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?([]), do: true
  defp blank?(value) when is_map(value), do: map_size(value) == 0
  defp blank?(_value), do: false

  defp camelize(key) do
    key
    |> Atom.to_string()
    |> String.split("_")
    |> case do
      [head | tail] -> head <> Enum.map_join(tail, "", &String.capitalize/1)
      [] -> ""
    end
  end
end
