defmodule TamanduaServer.Investigations.DetectorObservationConsensusV1 do
  @moduledoc """
  Strict, model-agnostic admission validator for detector observations.

  This module only validates and normalizes data. It never loads or executes
  detector artifacts, model files, URIs or provenance references.
  """

  @api_version "tamandua.io/detector-observation-consensus/v1"
  @decisions ~w(malicious suspicious benign unknown)
  @orientations ~w(higher_is_more_malicious lower_is_more_malicious categorical)
  @detector_types ~w(model rule heuristic reputation sandbox human ensemble other)
  @statuses ~w(completed cached degraded timeout failed unsupported)
  @runtime_lanes ~w(embedded_onnx embedded_treelite local_service endpoint_shadow backend decision_only none)
  @decision_modes ~w(detect_only decision_only enforced failed_enforcement)
  @evidence_classes ~w(contract_smoke synthetic_parity bootstrap_calibration governed_holdout production_telemetry)
  @claim_scopes ~w(contract_only parity_only calibration_only efficacy)
  @default_max_age_seconds 86_400
  @default_max_future_skew_seconds 300
  @max_configured_age_seconds 604_800
  @max_configured_future_skew_seconds 3_600
  @credential_query_keys ~w(
    access_token api_key apikey auth authorization credential credentials
    password passwd secret signature sig token
  )

  @spec validate_and_normalize(map()) :: {:ok, map()} | {:error, [String.t()]}
  def validate_and_normalize(payload) when is_map(payload) do
    payload = stringify_keys(payload)

    errors =
      []
      |> exact_keys(
        payload,
        ~w(api_version artifact input_contract observations consensus validation_context),
        "root"
      )
      |> require_value(payload["api_version"] == @api_version, "api_version is unsupported")
      |> validate_artifact(payload["artifact"])
      |> validate_input_contract(payload["input_contract"])
      |> validate_observations(payload["observations"])
      |> validate_consensus(payload["consensus"], payload["observations"])
      |> validate_context(payload["validation_context"])
      |> validate_size(payload)

    if errors == [], do: {:ok, normalize(payload)}, else: {:error, Enum.reverse(errors)}
  rescue
    _error -> {:error, ["envelope contains unsupported values"]}
  end

  def validate_and_normalize(_payload), do: {:error, ["envelope must be an object"]}

  @spec hash(map()) :: String.t()
  def hash(normalized) do
    normalized
    |> :erlang.term_to_binary([:deterministic])
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  @doc "Labels producer-computed consensus that Tamandua has not independently recomputed."
  @spec consensus_claim_status(map()) :: String.t()
  def consensus_claim_status(normalized) do
    if Enum.any?(list_or_empty(normalized["observations"]), &observation_only?/1),
      do: "not_computed",
      else: "producer_assertion"
  end

  defp validate_artifact(errors, artifact) do
    artifact = object_or_empty(artifact)

    errors
    |> exact_keys(
      artifact,
      ~w(artifact_id sha256 media_type size_bytes),
      "artifact",
      ~w(artifact_id sha256 media_type)
    )
    |> nonempty_string(artifact["artifact_id"], "artifact.artifact_id", 256)
    |> sha256(artifact["sha256"], "artifact.sha256")
    |> nonempty_string(artifact["media_type"], "artifact.media_type", 128)
    |> optional_nonnegative_integer(artifact["size_bytes"], "artifact.size_bytes")
  end

  defp validate_input_contract(errors, contract) do
    contract = object_or_empty(contract)

    errors
    |> exact_keys(
      contract,
      ~w(contract_id contract_version schema_sha256 feature_set),
      "input_contract",
      ~w(contract_id contract_version schema_sha256)
    )
    |> nonempty_string(contract["contract_id"], "input_contract.contract_id", 256)
    |> nonempty_string(contract["contract_version"], "input_contract.contract_version", 128)
    |> sha256(contract["schema_sha256"], "input_contract.schema_sha256")
    |> optional_nonempty_string(contract["feature_set"], "input_contract.feature_set", 256)
  end

  defp validate_observations(errors, observations) when is_list(observations) do
    errors =
      require_value(
        errors,
        observations != [] and length(observations) <= 32,
        "observations must contain 1..32 items"
      )

    errors =
      observations
      |> Enum.with_index()
      |> Enum.reduce(errors, fn {observation, index}, acc ->
        validate_observation(acc, observation, index)
      end)

    ids =
      for observation when is_map(observation) <- observations,
          do: stringify_keys(observation)["detector_id"]

    require_value(
      errors,
      length(Enum.reject(ids, &is_nil/1)) == length(Enum.uniq(Enum.reject(ids, &is_nil/1))),
      "observation detector_id values must be unique"
    )
  end

  defp validate_observations(errors, _observations),
    do: ["observations must be an array" | errors]

  defp validate_observation(errors, observation, index) do
    observation = object_or_empty(observation)
    prefix = "observations[#{index}]"

    required =
      ~w(detector_id detector_type detector_version score score_orientation threshold decision confidence latency_ms status degraded error provenance observed_at)

    allowed =
      required ++ ~w(runtime_lane model_contract_id decision_mode ensemble_votes)

    errors =
      errors
      |> exact_keys(observation, allowed, prefix, required)
      |> nonempty_string(observation["detector_id"], "#{prefix}.detector_id", 256)
      |> included(observation["detector_type"], @detector_types, "#{prefix}.detector_type")
      |> nonempty_string(observation["detector_version"], "#{prefix}.detector_version", 128)
      |> nullable_number(observation["score"], "#{prefix}.score")
      |> included(observation["score_orientation"], @orientations, "#{prefix}.score_orientation")
      |> nullable_number(observation["threshold"], "#{prefix}.threshold")
      |> included(observation["decision"], @decisions, "#{prefix}.decision")
      |> bounded_number(observation["confidence"], 0, 1, "#{prefix}.confidence")
      |> bounded_number(observation["latency_ms"], 0, 86_400_000, "#{prefix}.latency_ms")
      |> included(observation["status"], @statuses, "#{prefix}.status")
      |> boolean(observation["degraded"], "#{prefix}.degraded")
      |> validate_error(observation["error"], "#{prefix}.error")
      |> validate_provenance(observation["provenance"], "#{prefix}.provenance")
      |> fresh_timestamp(observation["observed_at"], "#{prefix}.observed_at")
      |> optional_included(observation["runtime_lane"], @runtime_lanes, "#{prefix}.runtime_lane")
      |> optional_nonempty_string(
        observation["model_contract_id"],
        "#{prefix}.model_contract_id",
        256
      )
      |> optional_included(
        observation["decision_mode"],
        @decision_modes,
        "#{prefix}.decision_mode"
      )
      |> validate_ensemble_votes(observation["ensemble_votes"], "#{prefix}.ensemble_votes")

    errors
    |> validate_observation_state(observation, prefix)
    |> validate_decision_mode_state(observation, prefix)
  end

  defp validate_ensemble_votes(errors, nil, _prefix), do: errors

  defp validate_ensemble_votes(errors, votes, prefix) when is_list(votes) do
    errors = require_value(errors, length(votes) <= 32, "#{prefix} must contain at most 32 items")

    votes
    |> Enum.with_index()
    |> Enum.reduce(errors, fn {vote, index}, acc ->
      validate_ensemble_vote(acc, vote, "#{prefix}[#{index}]")
    end)
  end

  defp validate_ensemble_votes(errors, _votes, prefix),
    do: ["#{prefix} must be an array" | errors]

  defp validate_ensemble_vote(errors, vote, prefix) do
    vote = object_or_empty(vote)
    required = ~w(detector_id status score decision confidence)

    errors =
      errors
      |> exact_keys(vote, required, prefix)
      |> nonempty_string(vote["detector_id"], "#{prefix}.detector_id", 256)
      |> included(vote["status"], @statuses, "#{prefix}.status")
      |> nullable_number(vote["score"], "#{prefix}.score")
      |> included(vote["decision"], @decisions, "#{prefix}.decision")
      |> bounded_number(vote["confidence"], 0, 1, "#{prefix}.confidence")

    if vote["status"] in ~w(completed cached) do
      errors
      |> require_value(is_number(vote["score"]), "#{prefix}.score must be numeric when completed")
      |> require_value(
        vote["decision"] in ~w(malicious suspicious benign),
        "#{prefix}.decision must be decisive when completed"
      )
    else
      errors
      |> require_value(is_nil(vote["score"]), "#{prefix}.score must be null when degraded")
      |> require_value(
        vote["decision"] == "unknown",
        "#{prefix}.decision must be unknown when degraded"
      )
      |> require_value(vote["confidence"] == 0, "#{prefix}.confidence must be zero when degraded")
    end
  end

  defp validate_decision_mode_state(
         errors,
         %{"decision_mode" => "enforced"} = observation,
         prefix
       ) do
    require_value(
      errors,
      observation["status"] in ~w(completed cached),
      "#{prefix}.decision_mode enforced requires a completed result"
    )
  end

  defp validate_decision_mode_state(errors, observation, prefix) do
    if observation_only?(observation) do
      errors
      |> require_value(
        observation["decision"] == "unknown",
        "#{prefix}.decision must be unknown in endpoint shadow"
      )
      |> require_value(
        observation["confidence"] == 0,
        "#{prefix}.confidence must be zero in endpoint shadow"
      )
      |> require_value(
        observation["ensemble_votes"] in [nil, []],
        "#{prefix}.ensemble_votes must be empty in endpoint shadow"
      )
    else
      errors
    end
  end

  defp validate_observation_state(errors, %{"status" => status} = observation, prefix)
       when status in ["completed", "cached"] do
    errors =
      errors
      |> require_value(
        is_number(observation["score"]),
        "#{prefix}.score must be numeric when completed"
      )
      |> require_value(
        is_number(observation["threshold"]),
        "#{prefix}.threshold must be numeric when completed"
      )
      |> require_value(
        observation["degraded"] == false,
        "#{prefix}.degraded must be false when completed"
      )
      |> require_value(
        is_nil(observation["error"]),
        "#{prefix}.error must be null when completed"
      )

    if observation_only?(observation) do
      errors
    else
      require_value(
        errors,
        observation["decision"] in ~w(malicious suspicious benign),
        "#{prefix}.decision must be decisive when completed"
      )
    end
  end

  defp validate_observation_state(errors, %{"status" => status} = observation, prefix)
       when status in ["degraded", "timeout", "failed", "unsupported"] do
    errors
    |> require_value(is_nil(observation["score"]), "#{prefix}.score must be null when degraded")
    |> require_value(
      is_nil(observation["threshold"]),
      "#{prefix}.threshold must be null when degraded"
    )
    |> require_value(
      observation["decision"] == "unknown",
      "#{prefix}.decision must be unknown when degraded"
    )
    |> require_value(
      observation["confidence"] == 0,
      "#{prefix}.confidence must be zero when degraded"
    )
    |> require_value(
      observation["degraded"] == true,
      "#{prefix}.degraded must be true when degraded"
    )
    |> require_value(is_map(observation["error"]), "#{prefix}.error is required when degraded")
  end

  defp validate_observation_state(errors, _observation, _prefix), do: errors

  defp validate_consensus(errors, consensus, observations) do
    consensus = object_or_empty(consensus)

    required =
      ~w(strategy strategy_version member_detector_ids score score_orientation threshold decision confidence degraded error generated_at)

    errors =
      errors
      |> exact_keys(consensus, required, "consensus")
      |> nonempty_string(consensus["strategy"], "consensus.strategy", 128)
      |> nonempty_string(consensus["strategy_version"], "consensus.strategy_version", 128)
      |> string_list(consensus["member_detector_ids"], "consensus.member_detector_ids", 1, 32)
      |> nullable_number(consensus["score"], "consensus.score")
      |> included(consensus["score_orientation"], @orientations, "consensus.score_orientation")
      |> nullable_number(consensus["threshold"], "consensus.threshold")
      |> included(consensus["decision"], @decisions, "consensus.decision")
      |> bounded_number(consensus["confidence"], 0, 1, "consensus.confidence")
      |> boolean(consensus["degraded"], "consensus.degraded")
      |> validate_error(consensus["error"], "consensus.error")
      |> fresh_timestamp(consensus["generated_at"], "consensus.generated_at")

    detector_ids =
      for observation when is_map(observation) <- list_or_empty(observations),
          do: stringify_keys(observation)["detector_id"]

    members = list_or_empty(consensus["member_detector_ids"])

    errors
    |> require_value(
      Enum.uniq(members) == members,
      "consensus.member_detector_ids must be unique"
    )
    |> require_value(
      Enum.all?(members, &(&1 in detector_ids)),
      "consensus references unknown detector_id"
    )
    |> validate_consensus_state(consensus)
    |> validate_observation_only_consensus(consensus, observations)
  end

  defp validate_observation_only_consensus(errors, consensus, observations) do
    if Enum.any?(list_or_empty(observations), &observation_only?/1) do
      errors
      |> require_value(consensus["degraded"] == true, "endpoint shadow cannot claim consensus")
      |> require_value(
        consensus["decision"] == "unknown",
        "endpoint shadow consensus must be unknown"
      )
      |> require_value(
        consensus["confidence"] == 0,
        "endpoint shadow consensus confidence must be zero"
      )
    else
      errors
    end
  end

  defp validate_consensus_state(errors, %{"degraded" => false} = consensus) do
    errors
    |> require_value(is_number(consensus["score"]), "consensus.score must be numeric")
    |> require_value(is_number(consensus["threshold"]), "consensus.threshold must be numeric")
    |> require_value(
      consensus["decision"] in ~w(malicious suspicious benign),
      "consensus.decision must be decisive"
    )
    |> require_value(is_nil(consensus["error"]), "consensus.error must be null")
  end

  defp validate_consensus_state(errors, %{"degraded" => true} = consensus) do
    errors
    |> require_value(is_nil(consensus["score"]), "consensus.score must be null when degraded")
    |> require_value(
      is_nil(consensus["threshold"]),
      "consensus.threshold must be null when degraded"
    )
    |> require_value(
      consensus["decision"] == "unknown",
      "consensus.decision must be unknown when degraded"
    )
    |> require_value(
      consensus["confidence"] == 0,
      "consensus.confidence must be zero when degraded"
    )
    |> require_value(is_map(consensus["error"]), "consensus.error is required when degraded")
  end

  defp validate_consensus_state(errors, _consensus), do: errors

  defp validate_context(errors, context) do
    context = object_or_empty(context)

    errors =
      errors
      |> exact_keys(
        context,
        ~w(evidence_class claim_scope effectiveness_metrics),
        "validation_context"
      )
      |> included(
        context["evidence_class"],
        @evidence_classes,
        "validation_context.evidence_class"
      )
      |> included(context["claim_scope"], @claim_scopes, "validation_context.claim_scope")
      |> string_list(
        context["effectiveness_metrics"],
        "validation_context.effectiveness_metrics",
        0,
        32
      )

    if context["evidence_class"] == "contract_smoke" do
      errors
      |> require_value(
        context["claim_scope"] == "contract_only",
        "contract_smoke claim_scope must be contract_only"
      )
      |> require_value(
        context["effectiveness_metrics"] == [],
        "contract_smoke cannot claim effectiveness metrics"
      )
    else
      errors
    end
  end

  defp validate_provenance(errors, provenance, prefix) do
    provenance = object_or_empty(provenance)

    errors
    |> exact_keys(
      provenance,
      ~w(source revision artifact_sha256 uri),
      prefix,
      ~w(source revision artifact_sha256)
    )
    |> nonempty_string(provenance["source"], "#{prefix}.source", 256)
    |> nonempty_string(provenance["revision"], "#{prefix}.revision", 256)
    |> sha256(provenance["artifact_sha256"], "#{prefix}.artifact_sha256")
    |> optional_nonempty_string(provenance["uri"], "#{prefix}.uri", 1_024)
    |> safe_provenance_uri(provenance["uri"], "#{prefix}.uri")
  end

  defp validate_error(errors, nil, _prefix), do: errors

  defp validate_error(errors, error, prefix) do
    error = object_or_empty(error)

    errors
    |> exact_keys(error, ~w(code message retryable), prefix, ~w(code message))
    |> nonempty_string(error["code"], "#{prefix}.code", 128)
    |> nonempty_string(error["message"], "#{prefix}.message", 512)
    |> optional_boolean(error["retryable"], "#{prefix}.retryable")
  end

  defp normalize(payload) do
    Map.take(
      payload,
      ~w(api_version artifact input_contract observations consensus validation_context)
    )
  end

  defp stringify_keys(map) when is_map(map),
    do: Map.new(map, fn {key, value} -> {to_string(key), stringify_keys(value)} end)

  defp stringify_keys(list) when is_list(list), do: Enum.map(list, &stringify_keys/1)
  defp stringify_keys(value), do: value

  defp object_or_empty(value) when is_map(value), do: stringify_keys(value)
  defp object_or_empty(_value), do: %{}
  defp list_or_empty(value) when is_list(value), do: value
  defp list_or_empty(_value), do: []

  defp observation_only?(observation) when is_map(observation) do
    observation = stringify_keys(observation)

    observation["decision_mode"] == "detect_only" and
      observation["runtime_lane"] == "endpoint_shadow"
  end

  defp observation_only?(_observation), do: false

  defp exact_keys(errors, map, allowed, prefix, required \\ nil) do
    required = required || allowed
    keys = Map.keys(map)
    unknown = keys -- allowed
    missing = required -- keys

    errors =
      Enum.reduce(unknown, errors, fn key, acc -> ["#{prefix}.#{key} is not allowed" | acc] end)

    Enum.reduce(missing, errors, fn key, acc -> ["#{prefix}.#{key} is required" | acc] end)
  end

  defp require_value(errors, true, _message), do: errors
  defp require_value(errors, false, message), do: [message | errors]

  defp nonempty_string(errors, value, field, max),
    do:
      require_value(
        errors,
        is_binary(value) and byte_size(value) in 1..max,
        "#{field} must be a non-empty bounded string"
      )

  defp optional_nonempty_string(errors, nil, _field, _max), do: errors

  defp optional_nonempty_string(errors, value, field, max),
    do: nonempty_string(errors, value, field, max)

  defp optional_included(errors, nil, _values, _field), do: errors
  defp optional_included(errors, value, values, field), do: included(errors, value, values, field)

  defp sha256(errors, value, field),
    do:
      require_value(
        errors,
        is_binary(value) and Regex.match?(~r/^[a-f0-9]{64}$/, value),
        "#{field} must be lowercase sha256"
      )

  defp included(errors, value, allowed, field),
    do: require_value(errors, value in allowed, "#{field} is invalid")

  defp boolean(errors, value, field),
    do: require_value(errors, is_boolean(value), "#{field} must be boolean")

  defp optional_boolean(errors, nil, _field), do: errors
  defp optional_boolean(errors, value, field), do: boolean(errors, value, field)

  defp nullable_number(errors, value, field),
    do:
      require_value(errors, is_nil(value) or is_number(value), "#{field} must be numeric or null")

  defp bounded_number(errors, value, min, max, field),
    do:
      require_value(
        errors,
        is_number(value) and value >= min and value <= max,
        "#{field} is out of range"
      )

  defp optional_nonnegative_integer(errors, nil, _field), do: errors

  defp optional_nonnegative_integer(errors, value, field),
    do:
      require_value(
        errors,
        is_integer(value) and value >= 0,
        "#{field} must be a non-negative integer"
      )

  defp string_list(errors, value, field, min, max) do
    valid =
      is_list(value) and length(value) in min..max and
        Enum.all?(value, &(is_binary(&1) and byte_size(&1) in 1..256))

    require_value(errors, valid, "#{field} must be a bounded string array")
  end

  defp fresh_timestamp(errors, value, field) do
    case parse_datetime(value) do
      {:ok, datetime} ->
        now = DateTime.utc_now()
        age_seconds = DateTime.diff(now, datetime, :second)

        max_age =
          configured_bound(
            :max_age_seconds,
            @default_max_age_seconds,
            @max_configured_age_seconds
          )

        max_future_skew =
          configured_bound(
            :max_future_skew_seconds,
            @default_max_future_skew_seconds,
            @max_configured_future_skew_seconds
          )

        errors
        |> require_value(age_seconds <= max_age, "#{field} is older than the admission window")
        |> require_value(age_seconds >= -max_future_skew, "#{field} is too far in the future")

      :error ->
        ["#{field} must be an ISO8601 timestamp" | errors]
    end
  end

  defp parse_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> {:ok, datetime}
      _ -> :error
    end
  end

  defp parse_datetime(_value), do: :error

  defp configured_bound(key, default, maximum) do
    value =
      Application.get_env(:tamandua_server, __MODULE__, [])
      |> then(fn
        config when is_list(config) -> Keyword.get(config, key, default)
        config when is_map(config) -> Map.get(config, key, default)
        _ -> default
      end)

    if is_integer(value) and value >= 0 and value <= maximum, do: value, else: default
  end

  defp safe_provenance_uri(errors, nil, _field), do: errors

  defp safe_provenance_uri(errors, uri, field) when is_binary(uri) do
    safe =
      case URI.parse(uri) do
        %URI{userinfo: userinfo, query: query} ->
          is_nil(userinfo) and not credential_query?(query)

        _ ->
          false
      end

    require_value(
      errors,
      safe,
      "#{field} must not contain credentials or secret query parameters"
    )
  rescue
    _error -> ["#{field} must not contain credentials or secret query parameters" | errors]
  end

  defp safe_provenance_uri(errors, _uri, field),
    do: ["#{field} must not contain credentials or secret query parameters" | errors]

  defp credential_query?(nil), do: false

  defp credential_query?(query) do
    query
    |> URI.query_decoder()
    |> Enum.any?(fn {key, _value} ->
      key
      |> String.downcase()
      |> String.replace(~r/[^a-z0-9]+/, "_")
      |> then(&(&1 in @credential_query_keys))
    end)
  rescue
    _error -> true
  end

  defp validate_size(errors, payload) do
    require_value(
      errors,
      byte_size(Jason.encode!(payload)) <= 262_144,
      "envelope exceeds 256 KiB"
    )
  rescue
    _error -> ["envelope is not JSON serializable" | errors]
  end
end
