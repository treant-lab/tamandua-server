defmodule TamanduaServer.AISecurity.ModelObservation do
  @moduledoc false

  @max_observations 32
  @max_text 256
  @claim_boundary "shadow_observation_no_verdict"

  @doc """
  Projects endpoint model observations into a bounded, model-agnostic shape.

  The projection deliberately excludes verdict, threat, safety, confidence and
  enforcement fields. A score crossing a threshold remains an observation.
  """
  def project_many(observations) when is_list(observations) do
    observations
    |> Enum.take(@max_observations)
    |> Enum.map(&project/1)
    |> Enum.reject(&is_nil/1)
  end

  def project_many(_), do: []

  def claim_boundary, do: @claim_boundary

  defp project(observation) when is_map(observation) do
    detector_id = text(value(observation, "detector_id"))
    status = text(value(observation, "status"))
    runtime_lane = text(value(observation, "runtime_lane"))
    model_contract_id = text(value(observation, "model_contract_id"))
    score = number(value(observation, "score"))
    threshold_met = value(observation, "threshold_met")

    if detector_id && status && runtime_lane && model_contract_id && is_number(score) &&
         is_boolean(threshold_met) do
      %{
        detector_id: detector_id,
        status: status,
        score: score,
        threshold_met: threshold_met,
        runtime_lane: runtime_lane,
        model_contract_id: model_contract_id,
        artifact_sha256: sha256(value(observation, "artifact_sha256")),
        threshold: number(value(observation, "threshold")),
        feature_contract_id: text(value(observation, "feature_contract_id")),
        calibration_id: text(value(observation, "calibration_id")),
        score_orientation: text(value(observation, "score_orientation")),
        claim_boundary: @claim_boundary
      }
    end
  end

  defp project(_), do: nil

  defp value(map, key) do
    if Map.has_key?(map, key) do
      Map.get(map, key)
    else
      Map.get(map, String.to_existing_atom(key))
    end
  end

  defp text(value) when is_binary(value) do
    value
    |> String.trim()
    |> case do
      "" -> nil
      value -> String.slice(value, 0, @max_text)
    end
  end

  defp text(value) when is_atom(value), do: value |> Atom.to_string() |> text()
  defp text(_), do: nil

  defp number(value) when is_integer(value), do: value * 1.0
  defp number(value) when is_float(value), do: value
  defp number(_), do: nil

  defp sha256(value) when is_binary(value) do
    normalized = String.downcase(value)
    if Regex.match?(~r/\A[0-9a-f]{64}\z/, normalized), do: normalized
  end

  defp sha256(_), do: nil
end
