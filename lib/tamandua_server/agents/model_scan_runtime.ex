defmodule TamanduaServer.Agents.ModelScanRuntime do
  @moduledoc """
  Projects the latest AI discovery model-scan event into an API-safe runtime summary.

  Scan outcomes remain distinct: `degraded` is never collapsed into `failed`
  or into a successful state.
  """

  @known_statuses ~w(pending scanning completed cached unsupported timeout degraded failed)

  alias TamanduaServer.AISecurity.ModelObservation

  @spec summarize([map() | struct()]) :: map() | nil
  def summarize(events) when is_list(events) do
    case Enum.find(events, &ai_discovery_event?/1) do
      nil -> nil
      event -> summarize_event(event)
    end
  end

  def summarize(_events), do: nil

  defp summarize_event(event) do
    payload = value(event, :payload) || %{}
    counts = normalize_counts(value(payload, :model_scan_status))
    components = value(payload, :components) || []
    model_artifacts = normalize_model_artifacts(payload)
    primary_artifact = if length(model_artifacts) == 1, do: hd(model_artifacts), else: %{}

    %{
      runtime_lane: value(payload, :runtime_lane) || "unknown",
      model_contract_id: value(payload, :model_contract_id),
      decision_mode: value(payload, :decision_mode) || "unknown",
      ensemble_votes: normalize_votes(value(payload, :ensemble_votes)),
      model_observations: normalize_model_observations(payload, components),
      model_artifacts: model_artifacts,
      artifact_sha256: value(primary_artifact, :artifact_sha256),
      threshold: value(primary_artifact, :threshold),
      feature_contract_id: value(primary_artifact, :feature_contract_id),
      calibration_id: value(primary_artifact, :calibration_id),
      score_orientation: value(primary_artifact, :score_orientation),
      scan_status: overall_status(counts),
      status_counts: counts,
      scan_errors: scan_errors(components),
      last_seen_at: value(event, :timestamp)
    }
  end

  defp ai_discovery_event?(event) do
    payload = value(event, :payload) || %{}
    value(payload, :ai_discovery) == true
  end

  defp normalize_counts(counts) when is_map(counts) do
    Enum.reduce(@known_statuses, %{}, fn status, acc ->
      case value(counts, status) do
        count when is_integer(count) and count >= 0 -> Map.put(acc, status, count)
        _ -> acc
      end
    end)
  end

  defp normalize_counts(_), do: %{}

  defp overall_status(counts) do
    Enum.find(
      ~w(degraded failed timeout scanning pending unsupported completed cached),
      "unknown",
      &(Map.get(counts, &1, 0) > 0)
    )
  end

  defp scan_errors(components) when is_list(components) do
    components
    |> Enum.flat_map(fn component ->
      status = value(component, :scan_status)
      error = value(component, :scan_error)

      if status in ~w(degraded failed timeout) and is_binary(error) and error != "" do
        [%{name: value(component, :name), status: status, error: error}]
      else
        []
      end
    end)
    |> Enum.take(20)
  end

  defp scan_errors(_), do: []

  defp normalize_votes(votes) when is_list(votes) do
    votes
    |> Enum.reduce([], fn vote, acc ->
      status = value(vote, :status)
      decision = value(vote, :decision)
      detector_id = value(vote, :detector_id)
      score = value(vote, :score)
      confidence = value(vote, :confidence)

      if is_binary(detector_id) and byte_size(detector_id) in 1..256 and
           status in ~w(completed cached degraded timeout failed unsupported) and
           decision in ~w(malicious suspicious benign unknown) and
           (is_nil(score) or is_number(score)) and is_number(confidence) and
           confidence >= 0 and confidence <= 1 and
           valid_vote_state?(status, decision, score, confidence) do
        [
          %{
            detector_id: detector_id,
            status: status,
            decision: decision,
            score: score,
            confidence: confidence
          }
          | acc
        ]
      else
        acc
      end
    end)
    |> Enum.reverse()
    |> Enum.take(32)
  end

  defp normalize_votes(_), do: []

  defp normalize_model_observations(payload, components) do
    top_level = ModelObservation.project_many(value(payload, :model_observations))

    if top_level == [] and is_list(components) do
      components
      |> Enum.flat_map(fn component ->
        ModelObservation.project_many(value(component, :model_observations))
      end)
      |> Enum.take(32)
    else
      top_level
    end
  end

  defp normalize_model_artifacts(payload) do
    candidates =
      case value(payload, :model_artifacts) do
        artifacts when is_list(artifacts) -> artifacts
        _ -> [payload]
      end

    candidates
    |> Enum.reduce([], fn artifact, acc ->
      case normalize_model_artifact(artifact) do
        nil -> acc
        normalized -> [normalized | acc]
      end
    end)
    |> Enum.reverse()
    |> Enum.uniq()
    |> Enum.take(32)
  end

  defp normalize_model_artifact(artifact) when is_map(artifact) do
    hash = value(artifact, :artifact_sha256)
    threshold = value(artifact, :threshold)
    feature_contract_id = value(artifact, :feature_contract_id)
    calibration_id = value(artifact, :calibration_id)
    orientation = value(artifact, :score_orientation)

    has_governance =
      Enum.any?(
        [hash, threshold, feature_contract_id, calibration_id, orientation],
        fn item -> not is_nil(item) end
      )

    if has_governance and valid_optional_sha256?(hash) and valid_optional_score?(threshold) and
         valid_optional_id?(feature_contract_id) and valid_optional_id?(calibration_id) and
         orientation in [nil, "higher_is_more_malicious", "lower_is_more_malicious"] do
      %{
        artifact_sha256: hash,
        threshold: threshold,
        feature_contract_id: feature_contract_id,
        calibration_id: calibration_id,
        score_orientation: orientation,
        model_contract_id: bounded_text(value(artifact, :model_contract_id), 128),
        component_name: bounded_text(value(artifact, :component_name), 4096),
        scanned_file_sha256: optional_sha256(value(artifact, :scanned_file_sha256))
      }
    end
  end

  defp normalize_model_artifact(_), do: nil

  defp valid_optional_sha256?(nil), do: true
  defp valid_optional_sha256?(value), do: not is_nil(optional_sha256(value))

  defp optional_sha256(value) when is_binary(value) and byte_size(value) == 64 do
    if String.match?(value, ~r/^[a-f0-9]{64}$/), do: value
  end

  defp optional_sha256(_), do: nil

  defp valid_optional_score?(nil), do: true
  defp valid_optional_score?(value), do: is_number(value) and value >= 0 and value <= 1

  defp valid_optional_id?(nil), do: true
  defp valid_optional_id?(value), do: is_binary(value) and byte_size(value) in 1..128

  defp bounded_text(value, max) when is_binary(value) do
    if byte_size(value) > 0 and byte_size(value) <= max, do: value
  end

  defp bounded_text(_, _), do: nil

  defp valid_vote_state?(status, decision, score, _confidence)
       when status in ~w(completed cached),
       do: is_number(score) and decision in ~w(malicious suspicious benign)

  defp valid_vote_state?(status, decision, score, confidence)
       when status in ~w(degraded timeout failed unsupported),
       do: is_nil(score) and decision == "unknown" and confidence == 0

  defp valid_vote_state?(_, _, _, _), do: false

  defp value(map, key) when is_map(map) and is_atom(key),
    do: Map.get(map, key) || Map.get(map, Atom.to_string(key))

  defp value(map, key) when is_map(map) and is_binary(key),
    do: Map.get(map, key) || existing_atom_value(map, key)

  defp value(_, _), do: nil

  defp existing_atom_value(map, key) do
    Map.get(map, String.to_existing_atom(key))
  rescue
    ArgumentError -> nil
  end
end
