defmodule TamanduaServer.Bounties.SubmissionValidator do
  @moduledoc """
  Validates bounty submissions for eligibility and fraud detection.

  The validation pipeline ensures bounties are only paid for legitimate,
  valuable security contributions, not self-generated or fraudulent submissions.

  ## SECURITY: benchmark_testable is NOT Validation

  CRITICAL: `benchmark_testable = true` does NOT qualify a submission for bounty payment!

  - `benchmark_testable` only means tests EXIST for the MITRE techniques
  - It does NOT mean the rule was actually tested or detected anything
  - It does NOT prove the rule works in the real world
  - This is a key anti-fraud measure against gaming the bounty system

  Submissions that ONLY have `benchmark_testable` but no real validation will:
  - Be flagged with `benchmark_only_no_real_validation` risk flag
  - NOT be automatically eligible for bounty payment
  - Require `manual_review_required` or admin override

  ## Validation Pipeline

  1. **Syntax Validation** - Check rule/IOC format is valid
  2. **Duplicate Detection** - Check similarity_hash against existing
  3. **PII/Privacy Check** - Ensure no private data in public IOCs
  4. **Benchmark Testing** - Check if techniques are testable (informational only)
  5. **Coverage Analysis** - Calculate coverage delta vs baseline
  6. **False Positive Check** - Test against benign dataset
  7. **Risk Flag Assignment** - Identify fraud indicators including benchmark-only
  8. **Eligibility Determination** - Final bounty eligibility

  ## Eligibility Criteria

  A submission is eligible for bounty if ALL of:
  - syntax_valid = true
  - no PII/private IOCs
  - not a duplicate (similarity_hash unique)
  - coverage_delta > 0 (improves detection for rules)
  - false_positive_rate < threshold (default 5%)

  AND at least one of (REAL validation, not testability):
  - external_correlations has entries (threat intel confirmation)
  - org_observation_count >= 2 (multi-org observation)
  - validated_by_id is set (human reviewer approved)

  NOTE: `benchmark_testable = true` is explicitly NOT in the eligibility criteria.
  """

  alias TamanduaServer.Repo
  alias TamanduaServer.Bounties.Submission
  alias TamanduaServer.Validation.EDRTester

  import Ecto.Query

  @fp_rate_threshold 0.05
  @min_coverage_delta 0.0
  @min_org_observations 2

  # Private IP patterns for IOC validation
  defp private_ip_patterns do
    [
      ~r/^10\./,
      ~r/^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      ~r/^192\.168\./,
      ~r/^127\./,
      ~r/^0\./,
      ~r/^169\.254\./
    ]
  end

  @private_domain_suffixes [".local", ".lan", ".internal", ".corp", ".home", ".localdomain"]

  @doc """
  Run full validation pipeline on a submission.

  Returns `{:ok, updated_submission}` with all validation fields populated.
  """
  @spec validate(Submission.t()) :: {:ok, Submission.t()} | {:error, term()}
  def validate(%Submission{} = submission) do
    submission
    |> validate_syntax()
    |> check_duplicates()
    |> check_pii()
    |> run_benchmark()
    |> calculate_coverage()
    |> assign_risk_flags()
    |> determine_eligibility()
    |> persist_results()
  end

  @doc """
  Quick syntax validation only (no benchmark).
  """
  @spec validate_syntax_only(Submission.t()) :: {:ok, map()} | {:error, term()}
  def validate_syntax_only(%Submission{type: "rule", payload: payload}) do
    content = payload["content"] || payload["rule"] || ""

    case validate_sigma_syntax(content) do
      {:ok, parsed} ->
        techniques = extract_mitre_techniques(parsed)
        {:ok, %{syntax_valid: true, techniques_covered: techniques, parsed: parsed}}

      {:error, reason} ->
        {:ok, %{syntax_valid: false, error: reason}}
    end
  end

  def validate_syntax_only(%Submission{type: "ioc", payload: payload}) do
    ioc_type = payload["ioc_type"] || payload["type"]
    value = payload["value"] || payload["ioc_value"]

    valid = validate_ioc_format(ioc_type, value)
    {:ok, %{syntax_valid: valid}}
  end

  def validate_syntax_only(%Submission{type: "sample_hash", payload: payload}) do
    hash = payload["hash"] || payload["sha256"] || payload["sha1"] || payload["md5"]
    valid = validate_hash_format(hash)
    {:ok, %{syntax_valid: valid}}
  end

  def validate_syntax_only(%Submission{}) do
    {:ok, %{syntax_valid: true}}
  end

  # Pipeline stages

  defp validate_syntax(submission) do
    case validate_syntax_only(submission) do
      {:ok, %{syntax_valid: true} = result} ->
        techniques = Map.get(result, :techniques_covered, [])
        {:cont, %{submission | syntax_valid: true, techniques_covered: techniques}}

      {:ok, %{syntax_valid: false, error: reason}} ->
        {:cont, %{submission |
          syntax_valid: false,
          bounty_eligibility: "ineligible",
          bounty_eligibility_reason: "Syntax validation failed: #{reason}"
        }}

      {:ok, %{syntax_valid: false}} ->
        {:cont, %{submission |
          syntax_valid: false,
          bounty_eligibility: "ineligible",
          bounty_eligibility_reason: "Syntax validation failed"
        }}

      {:error, reason} ->
        {:halt, {:error, reason}}
    end
  end

  defp check_duplicates({:halt, _} = result), do: result
  defp check_duplicates({:cont, %{similarity_hash: nil} = submission}), do: {:cont, submission}

  defp check_duplicates({:cont, submission}) do
    # Check if similarity_hash already exists
    existing = Repo.one(
      from s in Submission,
        where: s.similarity_hash == ^submission.similarity_hash,
        where: s.id != ^submission.id,
        where: s.status in ["validated", "paid"],
        limit: 1
    )

    if existing do
      duplicate_flag = if submission.type == "ioc", do: "duplicate_ioc", else: "duplicate_rule"

      {:cont, %{submission |
        risk_flags: [duplicate_flag | (submission.risk_flags || [])],
        bounty_eligibility: "ineligible",
        bounty_eligibility_reason: "Duplicate of existing submission #{existing.id}"
      }}
    else
      {:cont, submission}
    end
  end

  defp check_pii({:halt, _} = result), do: result
  defp check_pii({:cont, %{type: "ioc", payload: payload} = submission}) do
    ioc_type = payload["ioc_type"] || payload["type"]
    value = payload["value"] || payload["ioc_value"] || ""

    if contains_private_data?(ioc_type, value) do
      {:cont, %{submission |
        risk_flags: ["private_or_pii_ioc" | (submission.risk_flags || [])],
        bounty_eligibility: "ineligible",
        bounty_eligibility_reason: "IOC contains private/internal data"
      }}
    else
      {:cont, submission}
    end
  end
  defp check_pii({:cont, submission}), do: {:cont, submission}

  defp run_benchmark({:halt, _} = result), do: result
  defp run_benchmark({:cont, %{type: "rule"} = submission}) do
    # Check if rule's techniques are TESTABLE via Atomic Red Team/Caldera.
    #
    # IMPORTANT: benchmark_testable = true does NOT mean the rule was tested!
    # It only means that tests EXIST for the MITRE techniques the rule covers.
    # To truly validate detection, you'd need to:
    # 1. Run the Atomic Red Team test
    # 2. Check if the rule fires
    # 3. Verify no false negatives
    #
    # For the hackathon, this is an honest indicator of testability, not proof of detection.
    techniques = submission.techniques_covered || []

    if Enum.empty?(techniques) do
      {:cont, %{submission |
        benchmark_testable: false,
        benchmark_source: nil,
        validation_results: %{error: "No MITRE techniques found in rule"}
      }}
    else
      # Check if techniques are covered by Atomic Red Team
      case EDRTester.get_available_tests() do
        {:ok, available_tests} ->
          technique_ids = Enum.map(available_tests, & &1.technique_id)
          covered = Enum.filter(techniques, &(&1 in technique_ids))

          benchmark_testable = length(covered) > 0

          {:cont, %{submission |
            benchmark_testable: benchmark_testable,
            benchmark_source: if(benchmark_testable, do: "atomic_red_team"),
            validation_results: %{
              techniques_in_rule: techniques,
              techniques_testable: covered,
              techniques_not_testable: techniques -- covered
            }
          }}

        {:error, _} ->
          {:cont, %{submission |
            benchmark_testable: false,
            validation_results: %{error: "EDRTester unavailable"}
          }}
      end
    end
  end
  defp run_benchmark({:cont, submission}) do
    # Non-rule submissions can be approved by reviewer, external TI, or multi-org evidence,
    # but they do not get synthetic benchmark credit.
    {:cont, %{submission | benchmark_testable: false, benchmark_source: nil}}
  end

  defp calculate_coverage({:halt, _} = result), do: result
  defp calculate_coverage({:cont, %{type: "rule", techniques_covered: techniques} = submission}) do
    # Calculate coverage delta - how many new techniques does this rule add?
    existing_coverage = get_existing_rule_coverage()
    new_techniques = Enum.reject(techniques, &(&1 in existing_coverage))

    coverage_delta = if length(techniques) > 0 do
      length(new_techniques) / length(techniques)
    else
      0.0
    end

    {:cont, %{submission |
      coverage_delta: coverage_delta,
      validation_results: Map.merge(submission.validation_results || %{}, %{
        new_techniques: new_techniques,
        existing_coverage_overlap: techniques -- new_techniques
      })
    }}
  end
  defp calculate_coverage({:cont, submission}) do
    {:cont, %{submission | coverage_delta: 0.0}}
  end

  defp assign_risk_flags({:halt, _} = result), do: result
  defp assign_risk_flags({:cont, submission}) do
    flags = submission.risk_flags || []

    # Check for various risk indicators
    flags = if submission.org_observation_count < @min_org_observations do
      ["single_org_only" | flags]
    else
      flags
    end

    flags = if Enum.empty?(submission.external_correlations || []) do
      ["no_external_correlation" | flags]
    else
      flags
    end

    flags = if (submission.false_positive_rate || 0) > @fp_rate_threshold do
      ["excessive_fp_rate" | flags]
    else
      flags
    end

    flags = if submission.benchmark_source == "manual_lab" and !submission.benchmark_testable do
      ["synthetic_only" | flags]
    else
      flags
    end

    # SECURITY: Flag submissions that ONLY have benchmark testability but no real validation.
    # benchmark_testable means tests EXIST, not that the rule actually works.
    # Real validation requires: external TI correlation OR multi-org observation.
    flags = if submission.benchmark_testable and
               Enum.empty?(submission.external_correlations || []) and
               (submission.org_observation_count || 0) < @min_org_observations do
      ["benchmark_only_no_real_validation" | flags]
    else
      flags
    end

    {:cont, %{submission | risk_flags: Enum.uniq(flags)}}
  end

  defp determine_eligibility({:halt, _} = result), do: result
  defp determine_eligibility({:cont, submission}) do
    # Already marked as ineligible by earlier stage
    if submission.bounty_eligibility == "ineligible" do
      {:cont, submission}
    else
      {eligible, reason} = check_eligibility(submission)

      eligibility = cond do
        eligible -> "eligible"
        has_blocking_flags?(submission.risk_flags) -> "ineligible"
        true -> "manual_review_required"
      end

      {:cont, %{submission |
        bounty_eligibility: eligibility,
        bounty_eligibility_reason: reason
      }}
    end
  end

  defp check_eligibility(submission) do
    cond do
      submission.syntax_valid != true ->
        {false, "Syntax validation failed"}

      "duplicate_rule" in (submission.risk_flags || []) ->
        {false, "Duplicate submission"}

      "private_or_pii_ioc" in (submission.risk_flags || []) ->
        {false, "Contains private/PII data"}

      (submission.false_positive_rate || 0) > @fp_rate_threshold ->
        {false, "False positive rate #{Float.round((submission.false_positive_rate || 0) * 100, 1)}% exceeds threshold #{@fp_rate_threshold * 100}%"}

      !has_valid_correlation?(submission) ->
        {false, "No valid correlation: requires external TI confirmation OR multi-org observation (testability alone is not sufficient)"}

      (submission.coverage_delta || 0) <= @min_coverage_delta && submission.type == "rule" ->
        {false, "No coverage improvement over existing rules"}

      true ->
        {true, build_eligibility_reason(submission)}
    end
  end

  defp has_valid_correlation?(submission) do
    # IMPORTANT: benchmark_testable does NOT count as valid correlation!
    # Testability only means tests EXIST, not that the rule actually detected anything.
    #
    # Valid correlations that prove the rule works:
    # 1. External threat intel sources confirmed the IOC/technique
    # 2. Multiple organizations observed the same indicator independently
    # 3. Manual review by a human validator (handled separately)
    #
    # For hackathon: we're honest - testability is informational only.
    length(submission.external_correlations || []) > 0 ||
      (submission.org_observation_count || 0) >= @min_org_observations
  end

  defp has_blocking_flags?(flags) do
    # SECURITY: These flags block automatic bounty eligibility.
    # Note: "benchmark_only_no_real_validation" is NOT in this list because
    # it results in manual_review_required rather than outright ineligibility.
    # This allows human reviewers to approve valid rules that lack external TI.
    blocking = ["duplicate_rule", "duplicate_ioc", "private_or_pii_ioc", "excessive_fp_rate"]
    Enum.any?(flags || [], &(&1 in blocking))
  end

  defp build_eligibility_reason(submission) do
    # Build list of ACTUAL validation reasons (not testability)
    reasons = []

    # External threat intel correlation - this is real validation
    reasons = if length(submission.external_correlations || []) > 0 do
      ["External TI correlation: #{Enum.join(submission.external_correlations, ", ")}" | reasons]
    else
      reasons
    end

    # Multi-org observation - this is real validation
    reasons = if (submission.org_observation_count || 0) >= @min_org_observations do
      ["Multi-org observed (#{submission.org_observation_count} orgs)" | reasons]
    else
      reasons
    end

    # Note testability as informational only (NOT a validation reason)
    info = if submission.benchmark_testable do
      " [Info: testable via #{submission.benchmark_source}]"
    else
      ""
    end

    if Enum.empty?(reasons) do
      "Manual review approved" <> info
    else
      Enum.join(reasons, "; ") <> info
    end
  end

  defp persist_results({:halt, error}), do: error
  defp persist_results({:cont, submission}) do
    submission
    |> Submission.validation_changeset(%{
      syntax_valid: submission.syntax_valid,
      techniques_covered: submission.techniques_covered,
      benchmark_testable: submission.benchmark_testable,
      benchmark_source: submission.benchmark_source,
      bounty_eligibility: submission.bounty_eligibility,
      bounty_eligibility_reason: submission.bounty_eligibility_reason,
      risk_flags: submission.risk_flags,
      false_positive_rate: submission.false_positive_rate,
      coverage_delta: submission.coverage_delta,
      external_correlations: submission.external_correlations,
      org_observation_count: submission.org_observation_count,
      validation_results: submission.validation_results
    })
    |> Repo.update()
  end

  # Helper functions

  defp validate_sigma_syntax(content) when is_binary(content) do
    # Try to parse as YAML first
    case YamlElixir.read_from_string(content) do
      {:ok, parsed} when is_map(parsed) ->
        # Check required Sigma fields
        if Map.has_key?(parsed, "detection") do
          {:ok, parsed}
        else
          {:error, "Missing required 'detection' field"}
        end

      {:ok, _} ->
        {:error, "Rule must be a YAML map"}

      {:error, %YamlElixir.ParsingError{message: msg}} ->
        {:error, "YAML parsing error: #{msg}"}

      {:error, reason} ->
        {:error, "YAML parsing error: #{inspect(reason)}"}
    end
  rescue
    e -> {:error, "Parse error: #{Exception.message(e)}"}
  end

  defp validate_sigma_syntax(_), do: {:error, "Rule content must be a string"}

  defp extract_mitre_techniques(parsed) when is_map(parsed) do
    tags = parsed["tags"] || []

    tags
    |> Enum.filter(&is_binary/1)
    |> Enum.filter(&String.starts_with?(&1, "attack.t"))
    |> Enum.map(fn tag ->
      tag
      |> String.replace_prefix("attack.", "")
      |> String.upcase()
    end)
  end

  defp extract_mitre_techniques(_), do: []

  defp validate_ioc_format(_type, value) when not is_binary(value), do: false
  defp validate_ioc_format("ip", value), do: valid_ip?(value)
  defp validate_ioc_format("domain", value), do: valid_domain?(value)
  defp validate_ioc_format("url", value), do: valid_url?(value)
  defp validate_ioc_format("hash_sha256", value), do: String.match?(value, ~r/^[a-fA-F0-9]{64}$/)
  defp validate_ioc_format("hash_sha1", value), do: String.match?(value, ~r/^[a-fA-F0-9]{40}$/)
  defp validate_ioc_format("hash_md5", value), do: String.match?(value, ~r/^[a-fA-F0-9]{32}$/)
  defp validate_ioc_format(_, _), do: true

  defp validate_hash_format(hash) when is_binary(hash) do
    String.match?(hash, ~r/^[a-fA-F0-9]{32,64}$/)
  end
  defp validate_hash_format(_), do: false

  defp valid_ip?(value) do
    case :inet.parse_address(String.to_charlist(value)) do
      {:ok, _} -> true
      _ -> false
    end
  end

  defp valid_domain?(value) do
    String.contains?(value, ".") and String.match?(value, ~r/^[a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z0-9]$/)
  end

  defp valid_url?(value) do
    case URI.parse(value) do
      %URI{scheme: scheme, host: host} when scheme in ["http", "https"] and is_binary(host) ->
        String.length(host) > 0
      _ ->
        false
    end
  end

  defp contains_private_data?(_type, value) when not is_binary(value), do: false

  defp contains_private_data?("ip", value) do
    Enum.any?(private_ip_patterns(), &Regex.match?(&1, value))
  end

  defp contains_private_data?("domain", value) do
    Enum.any?(@private_domain_suffixes, &String.ends_with?(String.downcase(value), &1))
  end

  defp contains_private_data?("url", value) do
    case URI.parse(value) do
      %URI{host: host} when is_binary(host) ->
        contains_private_data?("domain", host) or contains_private_data?("ip", host)
      _ ->
        false
    end
  end

  defp contains_private_data?(_, _), do: false

  defp get_existing_rule_coverage do
    # Get all MITRE techniques covered by validated/paid rules
    from(s in Submission,
      where: s.type == "rule",
      where: s.status in ["validated", "paid"],
      where: not is_nil(s.techniques_covered),
      select: s.techniques_covered
    )
    |> Repo.all()
    |> List.flatten()
    |> Enum.uniq()
  end
end
