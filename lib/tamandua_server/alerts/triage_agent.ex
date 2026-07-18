defmodule TamanduaServer.Alerts.TriageAgent do
  @moduledoc """
  Builds a deterministic first-pass triage contract for alerts.

  This module does not decide incident truth by itself. It records the current
  hypothesis, evidence strength, gaps, FP likelihood, next pivots, response
  guidance, confidence, and operational status so alert/storyline consumers can
  render or persist a consistent investigation starting point.
  """

  alias TamanduaServer.Alerts.EvidenceQuality

  @schema_version "alert-triage/v1"

  @doc """
  Return a triage contract for an alert struct or alert-like map.
  """
  def build(alert) do
    quality = EvidenceQuality.classify(alert)
    severity = get_value(alert, :severity) |> normalize_text()
    title = get_value(alert, :title) |> normalize_text()
    threat_score = normalized_threat_score(get_value(alert, :threat_score))
    fp = false_positive_likelihood(alert, quality, severity, threat_score)
    confidence = confidence_score(quality, fp, threat_score)
    gaps = triage_gaps(alert, quality)
    pivots = recommended_pivots(alert, quality, gaps)
    response = recommended_response(alert, severity, fp, gaps)

    %{
      "schema_version" => @schema_version,
      "status" => triage_status(quality, fp, gaps, confidence),
      "hypothesis" => hypothesis(alert, title, severity, quality),
      "evidence_strength" => evidence_strength(quality),
      "gaps" => gaps,
      "false_positive_likelihood" => fp,
      "recommended_pivots" => pivots,
      "recommended_response" => response,
      "confidence" => confidence,
      "generated_at" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
    }
  end

  @doc """
  Attach a triage contract to alert attrs under `enrichment["triage"]`.
  Existing explicit triage data is preserved.
  """
  def attach_contract(attrs) when is_map(attrs) do
    enrichment = get_value(attrs, :enrichment) |> ensure_map()

    if non_empty_map?(get_map_value(enrichment, :triage)) do
      attrs
    else
      Map.put(attrs, :enrichment, Map.put(enrichment, "triage", build(attrs)))
    end
  end

  @doc """
  Return persisted triage when present, otherwise build a fresh contract.
  """
  def contract_for(alert) do
    alert
    |> get_value(:enrichment)
    |> ensure_map()
    |> get_map_value(:triage)
    |> case do
      triage when is_map(triage) and map_size(triage) > 0 -> stringify_keys(triage)
      _ -> build(alert)
    end
  end

  defp hypothesis(alert, "", severity, quality) do
    hypothesis(alert, "security alert", severity, quality)
  end

  defp hypothesis(alert, title, severity, quality) do
    technique = alert |> get_list(:mitre_techniques) |> List.first()
    source = detection_source(alert)

    parts =
      [
        "#{severity_label(severity)} alert `#{title}` requires triage",
        maybe_part(source != "", "from #{source}"),
        maybe_part(is_binary(technique), "mapped to #{technique}"),
        maybe_part(quality.claimable == false, "with incomplete claimable evidence")
      ]
      |> Enum.reject(&is_nil/1)

    Enum.join(parts, " ")
  end

  defp evidence_strength(%{quality: quality, label: label, claimable: claimable, benchmark_eligible: benchmark}) do
    %{
      "level" => quality,
      "label" => label,
      "claimable" => claimable,
      "benchmark_eligible" => benchmark
    }
  end

  defp triage_gaps(alert, quality) do
    explicit_gaps =
      quality.missing
      |> Enum.map(&gap("evidence", &1))

    context_gaps =
      quality.investigation_context.missing
      |> Enum.map(&gap("investigation_context", &1))

    enrichment_gaps =
      case get_path(alert, [:detection_metadata, :investigation_enrichment]) do
        %{"status" => status, "missing_context" => missing} when status in ["planned", "failed", "capability_degraded"] ->
          missing |> List.wrap() |> Enum.map(&gap("auto_investigation", &1))

        _ ->
          []
      end

    (explicit_gaps ++ context_gaps ++ enrichment_gaps)
    |> Enum.uniq_by(fn item -> {item["source"], item["field"]} end)
  end

  defp gap(source, field) do
    %{
      "source" => source,
      "field" => to_string(field),
      "severity" => gap_severity(field)
    }
  end

  defp gap_severity(field) do
    case to_string(field) do
      value when value in ["source_event_id", "evidence", "raw_event"] -> "high"
      value when value in ["process evidence", "command line", "parent process"] -> "medium"
      _ -> "low"
    end
  end

  defp false_positive_likelihood(alert, quality, severity, threat_score) do
    notes = get_value(alert, :false_positive_notes)
    verdict = get_value(alert, :verdict) |> normalize_text()
    severity_adjusted = get_value(alert, :severity_adjusted) == true

    score =
      0.25
      |> add_if(quality.quality in ["missing", "synthetic"], 0.2)
      |> add_if(quality.claimable == false, 0.15)
      |> add_if(severity in ["info", "low"] and threat_score < 0.5, 0.15)
      |> add_if(severity_adjusted, 0.2)
      |> add_if(present?(notes), 0.25)
      |> add_if(verdict in ["false_positive", "benign"], 0.45)
      |> add_if(verdict in ["true_positive", "suspicious"], -0.25)
      |> add_if(quality.quality in ["direct", "correlated"] and threat_score >= 0.8, -0.15)
      |> clamp()

    %{
      "score" => Float.round(score, 2),
      "label" => likelihood_label(score),
      "basis" => fp_basis(alert, quality, severity_adjusted)
    }
  end

  defp fp_basis(alert, quality, severity_adjusted) do
    []
    |> maybe_cons(quality.quality in ["missing", "synthetic"], "weak_evidence_provenance")
    |> maybe_cons(quality.claimable == false, "missing_claimable_evidence")
    |> maybe_cons(severity_adjusted, "severity_was_adjusted")
    |> maybe_cons(present?(get_value(alert, :false_positive_notes)), "false_positive_notes_present")
    |> Enum.reverse()
  end

  defp recommended_pivots(alert, quality, gaps) do
    base =
      [
        maybe_pivot(missing_field?(gaps, "source_event_id"), "link_source_event", "Find and link the triggering source event.", "high"),
        maybe_pivot(missing_field?(gaps, "process evidence"), "collect_process_tree", "Collect process identity and ancestry.", "high"),
        maybe_pivot(missing_field?(gaps, "command line"), "collect_command_line", "Collect command line and decoded command context.", "medium"),
        maybe_pivot(missing_field?(gaps, "network context") or missing_field?(gaps, "network evidence"), "collect_network_context", "Collect network, DNS, SNI and remote endpoint context.", "medium"),
        maybe_pivot(quality.checks.app_guard_protected_app and missing_field?(gaps, "IOC evidence"), "extract_app_guard_iocs", "Extract app/package/domain indicators from App Guard evidence.", "medium")
      ]
      |> Enum.reject(&is_nil/1)

    investigation_plan =
      case get_path(alert, [:detection_metadata, :investigation_enrichment]) do
        %{"requested_actions" => actions} when is_list(actions) ->
          Enum.map(actions, fn action ->
            %{
              "action" => to_string(action),
              "reason" => "Existing auto-investigation plan requested this pivot.",
              "priority" => "medium"
            }
          end)

        _ ->
          []
      end

    response_pivot =
      if get_value(alert, :agent_id) do
        [%{"action" => "review_response_actions", "reason" => "Check queued and completed response actions for this agent.", "priority" => "low"}]
      else
        []
      end

    (base ++ investigation_plan ++ response_pivot)
    |> Enum.uniq_by(& &1["action"])
    |> Enum.take(8)
  end

  defp maybe_pivot(true, action, reason, priority), do: %{"action" => action, "reason" => reason, "priority" => priority}
  defp maybe_pivot(false, _action, _reason, _priority), do: nil

  defp recommended_response(alert, severity, fp, gaps) do
    existing = get_value(alert, :recommended_response)

    cond do
      present?(existing) ->
        existing

      fp["score"] >= 0.65 ->
        "Do not auto-contain yet. Collect missing evidence and review false-positive basis."

      missing_high_gap?(gaps) ->
        "Collect missing source/evidence context before containment unless active impact is confirmed."

      severity in ["critical", "high"] ->
        "Preserve evidence and prepare containment; isolate only after confirming process/network context."

      true ->
        "Review related events, validate baseline fit, and escalate if new suspicious pivots appear."
    end
  end

  defp confidence_score(quality, fp, threat_score) do
    base =
      case quality.quality do
        "direct" -> 0.82
        "correlated" -> 0.72
        "derived" -> 0.58
        "synthetic" -> 0.38
        _ -> 0.22
      end

    (base + min(threat_score, 1.0) * 0.12 - fp["score"] * 0.18)
    |> clamp()
    |> Float.round(2)
  end

  defp triage_status(quality, fp, gaps, confidence) do
    cond do
      fp["score"] >= 0.7 -> "false_positive_candidate"
      missing_high_gap?(gaps) or quality.investigation_context.state in ["partial", "unavailable"] -> "needs_evidence"
      confidence >= 0.75 and quality.claimable -> "ready_for_response_review"
      true -> "needs_triage"
    end
  end

  defp detection_source(alert) do
    get_path(alert, [:detection_metadata, :source]) ||
      get_path(alert, [:evidence, :detection, :source]) ||
      get_path(alert, [:raw_event, :source]) ||
      ""
  end

  defp severity_label(""), do: "Unclassified"
  defp severity_label(value), do: String.capitalize(value)

  defp missing_field?(gaps, field), do: Enum.any?(gaps, &(&1["field"] == field))
  defp missing_high_gap?(gaps), do: Enum.any?(gaps, &(&1["severity"] == "high"))

  defp normalized_threat_score(value) when is_number(value), do: if(value > 1.0, do: value / 100, else: value)
  defp normalized_threat_score(_), do: 0.0

  defp normalize_text(nil), do: ""
  defp normalize_text(value) when is_binary(value), do: String.downcase(value)
  defp normalize_text(value), do: value |> to_string() |> String.downcase()

  defp present?(value) when is_binary(value), do: String.trim(value) != ""
  defp present?(nil), do: false
  defp present?(_), do: true

  defp add_if(score, true, delta), do: score + delta
  defp add_if(score, false, _delta), do: score

  defp maybe_cons(list, true, value), do: [value | list]
  defp maybe_cons(list, false, _value), do: list

  defp clamp(value), do: value |> max(0.0) |> min(1.0)

  defp likelihood_label(score) when score >= 0.7, do: "high"
  defp likelihood_label(score) when score >= 0.45, do: "medium"
  defp likelihood_label(_), do: "low"

  defp get_list(source, key) do
    case get_value(source, key) do
      values when is_list(values) -> values
      _ -> []
    end
  end

  defp get_value(source, key) when is_map(source), do: Map.get(source, key) || Map.get(source, Atom.to_string(key))
  defp get_value(_source, _key), do: nil

  defp get_path(source, keys), do: Enum.reduce_while(keys, source, &path_step/2)

  defp path_step(key, value) when is_map(value) do
    case get_map_value(value, key) do
      nil -> {:halt, nil}
      next -> {:cont, next}
    end
  end

  defp path_step(_key, _value), do: {:halt, nil}

  defp get_map_value(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, Atom.to_string(key))
  defp get_map_value(_, _), do: nil

  defp ensure_map(value) when is_map(value), do: value
  defp ensure_map(_), do: %{}

  defp non_empty_map?(value), do: is_map(value) and map_size(value) > 0

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn {key, value} -> {to_string(key), stringify_value(value)} end)
  end

  defp stringify_value(value) when is_map(value), do: stringify_keys(value)
  defp stringify_value(value) when is_list(value), do: Enum.map(value, &stringify_value/1)
  defp stringify_value(value), do: value

  defp maybe_part(true, value), do: value
  defp maybe_part(false, _value), do: nil
end
