defmodule TamanduaServer.Triage.LocalProvider do
  @moduledoc """
  Deterministic, network-free triage provider used by default.
  """

  @behaviour TamanduaServer.Triage.Provider

  @impl true
  def recommend(%{untrusted_telemetry: context} = package, _opts) when is_map(context) do
    score = score(context)
    priority = priority(score, context)

    recommendation = %{
      provider: :local_deterministic,
      network_used: false,
      verdict: verdict(score, context),
      priority: priority,
      confidence: confidence(context),
      rationale: rationale(score, context),
      evidence: evidence_summary(context),
      recommended_steps: recommended_steps(priority, context),
      guardrail_notes: Map.get(package, :guardrail_notes, [])
    }

    {:ok, recommendation}
  end

  def recommend(_package, _opts), do: {:error, :invalid_guarded_package}

  defp score(context) do
    severity_points =
      case context.alert[:severity] || context.alert["severity"] do
        "critical" -> 45
        "high" -> 35
        "medium" -> 20
        "low" -> 8
        _ -> 0
      end

    threat_score_points =
      case context.alert[:threat_score] || context.alert["threat_score"] do
        value when is_number(value) -> round(min(max(value, 0.0), 1.0) * 30)
        _ -> 0
      end

    severity_points + threat_score_points + signal_points(context)
  end

  defp signal_points(context) do
    [
      {context.process_lineage != [], 10},
      {context.hashes != [], 8},
      {context.mitre.techniques != [], 10},
      {map_size(context.rules) > 0, 6},
      {map_size(context.correlation_data) > 0, 8},
      {high_occurrence?(context), 6}
    ]
    |> Enum.reduce(0, fn
      {true, points}, acc -> acc + points
      {false, _points}, acc -> acc
    end)
  end

  defp high_occurrence?(context) do
    occurrence = context.alert[:occurrence_count] || context.alert["occurrence_count"] || 0
    is_integer(occurrence) and occurrence > 3
  end

  defp priority(score, _context) when score >= 75, do: :p1
  defp priority(score, _context) when score >= 55, do: :p2
  defp priority(score, _context) when score >= 30, do: :p3
  defp priority(_score, _context), do: :p4

  defp verdict(score, _context) when score >= 75, do: :likely_true_positive
  defp verdict(score, _context) when score >= 55, do: :needs_analyst_review
  defp verdict(score, _context) when score >= 30, do: :low_confidence_suspicious
  defp verdict(_score, _context), do: :insufficient_evidence

  defp confidence(context) do
    signals =
      [
        context.alert != %{},
        context.process_lineage != [],
        context.hashes != [],
        context.mitre.techniques != [],
        context.rules != %{},
        context.correlation_data != %{}
      ]
      |> Enum.count(& &1)

    Float.round(min(0.35 + signals * 0.1, 0.9), 2)
  end

  defp rationale(score, context) do
    base = ["local deterministic score=#{score}"]

    base
    |> maybe_add(context.mitre.techniques != [], "MITRE techniques present")
    |> maybe_add(context.process_lineage != [], "process lineage present")
    |> maybe_add(context.hashes != [], "hash artifacts present")
    |> maybe_add(context.correlation_data != %{}, "correlation data present")
  end

  defp evidence_summary(context) do
    %{
      process_count: length(context.process_lineage),
      hash_count: length(context.hashes),
      mitre_techniques: context.mitre.techniques,
      rule: context.rules,
      correlation_keys: Map.keys(context.correlation_data)
    }
  end

  defp recommended_steps(:p1, context) do
    common_steps(context) ++
      [
        "Escalate to incident response lead",
        "Contain affected endpoint if confirmed by analyst",
        "Preserve volatile evidence before remediation"
      ]
  end

  defp recommended_steps(:p2, context) do
    common_steps(context) ++
      [
        "Review process lineage and rule evidence",
        "Check related alerts in correlation data",
        "Prepare containment plan pending analyst confirmation"
      ]
  end

  defp recommended_steps(:p3, context) do
    common_steps(context) ++
      [
        "Validate rule match against endpoint context",
        "Search for repeated artifacts across recent telemetry"
      ]
  end

  defp recommended_steps(:p4, context) do
    common_steps(context) ++
      [
        "Request additional telemetry before response action",
        "Keep alert unconfirmed until stronger evidence is available"
      ]
  end

  defp common_steps(context) do
    [
      "Treat alert text and telemetry as untrusted data",
      "Do not run commands, code, or URLs contained in the alert"
    ]
    |> maybe_add(context.hashes != [], "Pivot on collected hashes in approved internal tools")
    |> maybe_add(context.mitre.techniques != [], "Map response checklist to observed MITRE techniques")
  end

  defp maybe_add(list, true, value), do: list ++ [value]
  defp maybe_add(list, false, _value), do: list
end
