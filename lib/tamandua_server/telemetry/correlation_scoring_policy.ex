defmodule TamanduaServer.Telemetry.CorrelationScoringPolicy do
  @moduledoc """
  Versioned, explainable scoring policy for telemetry event correlation.

  The policy is intentionally conservative: context-only evidence such as time
  proximity or shared MITRE technique can explain an investigation view, but it
  cannot create a correlation score without at least one concrete shared entity.
  """

  @version "correlation-scoring/v2"
  @default_threshold 40
  @context_only_types ~w(temporal mitre remote_ip_private)

  @doc """
  Score already extracted evidence and return a stable policy explanation.
  """
  def score(evidence, opts \\ []) when is_list(evidence) do
    threshold = Keyword.get(opts, :threshold, @default_threshold)
    strong = Enum.reject(evidence, &context_only?/1)
    context = Enum.filter(evidence, &context_only?/1)
    raw_score = evidence |> Enum.map(& &1.score) |> Enum.sum() |> min(100)
    final_score = if strong == [], do: 0, else: raw_score

    %{
      version: @version,
      threshold: threshold,
      score: final_score,
      rawScore: raw_score,
      decision: decision(final_score, threshold, strong),
      confidence: confidence(final_score, strong),
      requirements: [
        "requires at least one strong shared entity",
        "temporal, MITRE and private IP overlap are context, not standalone evidence"
      ],
      strongEvidenceCount: length(strong),
      contextEvidenceCount: length(context),
      contributingEvidence: Enum.map(evidence, &describe_evidence/1),
      suppressedEvidence:
        if(strong == [] and evidence != [],
          do: ["context-only evidence suppressed to avoid false positive correlation"],
          else: []
        )
    }
  end

  def version, do: @version

  def context_only_type?(type), do: to_string(type) in @context_only_types

  defp context_only?(%{type: type}), do: context_only_type?(type)
  defp context_only?(_), do: false

  defp decision(0, _threshold, []), do: "context_only"
  defp decision(score, threshold, _strong) when score >= threshold, do: "linked"
  defp decision(_score, _threshold, _strong), do: "weak"

  defp confidence(score, strong) do
    cond do
      strong == [] -> "none"
      score >= 80 -> "high"
      score >= 50 -> "medium"
      true -> "low"
    end
  end

  defp describe_evidence(%{type: type, score: score, reason: reason}) do
    %{
      type: type,
      weight: score,
      reason: reason,
      strength: if(context_only_type?(type), do: "context", else: "strong")
    }
  end
end
