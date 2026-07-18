defmodule TamanduaServer.Detection.RuleLifecycle do
  @moduledoc """
  Canonical, read-only lifecycle view for detection rules.

  The facade joins the current rule with its `RuleVersion` snapshots, runs the
  existing syntax validator, and evaluates whether the available evidence is
  sufficient for a target environment. It does not promote or mutate rules.

  Evidence requirements are intentionally conservative:

    * development accepts a passing syntax smoke check;
    * staging requires passing synthetic parity evidence;
    * production requires a passing governed holdout (or production telemetry).

  Callers may supply a test result with `:test_result`. Test results are
  evaluated for the current request but are not persisted by this facade.
  """

  import Ecto.Query

  alias TamanduaServer.Detection.{RuleValidator, RuleVersion, SigmaRule, YaraRule}
  alias TamanduaServer.Repo

  @evidence_ranks %{
    "smoke" => 0,
    "synthetic_parity" => 1,
    "governed_holdout" => 2,
    "production_telemetry" => 3
  }

  @required_evidence %{
    "development" => "smoke",
    "staging" => "synthetic_parity",
    "production" => "governed_holdout"
  }

  @doc """
  Returns the tenant-scoped lifecycle view for a YARA or Sigma rule.

  Options:

    * `:environment` - current environment, defaults to `"development"`;
    * `:target_environment` - promotion target, defaults to `"staging"`;
    * `:test_result` - optional `%{status: ..., evidence_class: ...}` result.
  """
  def describe(rule_type, rule_id, organization_id, opts \\ []) do
    with {:ok, normalized_type} <- normalize_rule_type(rule_type),
         {:ok, environment} <-
           normalize_environment(Keyword.get(opts, :environment, "development")),
         {:ok, target_environment} <-
           normalize_environment(Keyword.get(opts, :target_environment, "staging")),
         {:ok, test_result} <- normalize_test_result(Keyword.get(opts, :test_result)),
         {:ok, rule} <- fetch_rule(normalized_type, rule_id, organization_id) do
      versions = version_history(normalized_type, rule.id, organization_id)
      validation = validate_rule(normalized_type, rule)

      {:ok,
       %{
         rule: %{
           id: rule.id,
           type: Atom.to_string(normalized_type),
           name: rule.name,
           state: if(rule.enabled, do: "enabled", else: "disabled"),
           owner: %{
             content_author: Map.get(rule, :author),
             last_changed_by: versions |> List.first() |> then(&(&1 && &1.changed_by))
           }
         },
         environment: environment,
         current_version: versions |> List.first() |> then(&(&1 && &1.version)),
         history: Enum.map(versions, &history_entry/1),
         validation: validation,
         test_result: test_result,
         promotion_gate:
           promotion_gate(rule, versions, validation, test_result, target_environment)
       }}
    end
  end

  defp fetch_rule(_rule_type, _rule_id, organization_id) when not is_binary(organization_id),
    do: {:error, :invalid_organization_id}

  defp fetch_rule(rule_type, rule_id, organization_id) do
    schema = if rule_type == :yara, do: YaraRule, else: SigmaRule

    case Repo.get_by(schema, id: rule_id, organization_id: organization_id) do
      nil -> {:error, :not_found}
      rule -> {:ok, rule}
    end
  end

  defp version_history(rule_type, rule_id, organization_id) do
    type = Atom.to_string(rule_type)

    Repo.all(
      from(version in RuleVersion,
        where:
          version.rule_type == ^type and version.rule_id == ^rule_id and
            version.organization_id == ^organization_id,
        order_by: [desc: version.version, desc: version.inserted_at]
      )
    )
  end

  defp validate_rule(:yara, rule), do: validation_result(RuleValidator.validate_yara(rule.source))

  defp validate_rule(:sigma, rule),
    do: validation_result(RuleValidator.validate_sigma(rule.source))

  defp validation_result({:ok, _parsed}) do
    %{status: "passed", evidence_class: "smoke", validator: "syntax"}
  end

  defp validation_result({:error, reason}) do
    %{
      status: "failed",
      evidence_class: "smoke",
      validator: "syntax",
      reason: inspect_reason(reason)
    }
  end

  defp promotion_gate(rule, versions, validation, test_result, target_environment) do
    required_evidence = Map.fetch!(@required_evidence, target_environment)
    effective_evidence = effective_evidence(validation, test_result)

    blockers =
      []
      |> add_reason(not rule.enabled, "rule_disabled")
      |> add_reason(validation.status != "passed", "syntax_validation_failed")
      |> add_reason(Enum.empty?(versions), "version_snapshot_missing")
      |> add_reason(test_result && test_result.status == "failed", "test_failed")

    evidence_sufficient =
      Map.fetch!(@evidence_ranks, effective_evidence) >=
        Map.fetch!(@evidence_ranks, required_evidence)

    {decision, reasons} =
      cond do
        blockers != [] ->
          {"blocked", blockers}

        not evidence_sufficient ->
          {"review_required", ["insufficient_evidence"]}

        true ->
          {"eligible", []}
      end

    %{
      decision: decision,
      target_environment: target_environment,
      evidence_class: effective_evidence,
      required_evidence_class: required_evidence,
      reasons: reasons
    }
  end

  defp effective_evidence(_validation, %{status: "passed", evidence_class: evidence_class}),
    do: evidence_class

  defp effective_evidence(validation, _test_result), do: validation.evidence_class

  defp add_reason(reasons, true, reason), do: reasons ++ [reason]
  defp add_reason(reasons, false, _reason), do: reasons
  defp add_reason(reasons, nil, _reason), do: reasons

  defp history_entry(version) do
    %{
      version: version.version,
      checksum: version.checksum,
      change_summary: version.change_summary,
      changed_by: version.changed_by,
      inserted_at: version.inserted_at
    }
  end

  defp normalize_rule_type(type) when type in [:yara, "yara"], do: {:ok, :yara}
  defp normalize_rule_type(type) when type in [:sigma, "sigma"], do: {:ok, :sigma}
  defp normalize_rule_type(_type), do: {:error, :unsupported_rule_type}

  defp normalize_environment(environment) when is_atom(environment),
    do: normalize_environment(Atom.to_string(environment))

  defp normalize_environment(environment) when is_binary(environment) do
    normalized = String.downcase(environment)

    if Map.has_key?(@required_evidence, normalized),
      do: {:ok, normalized},
      else: {:error, :invalid_environment}
  end

  defp normalize_environment(_environment), do: {:error, :invalid_environment}

  defp normalize_test_result(nil), do: {:ok, nil}

  defp normalize_test_result(result) when is_map(result) do
    status = result[:status] || result["status"]
    evidence_class = result[:evidence_class] || result["evidence_class"]
    normalized_status = if is_atom(status), do: Atom.to_string(status), else: status

    normalized_evidence =
      if is_atom(evidence_class), do: Atom.to_string(evidence_class), else: evidence_class

    if normalized_status in ["passed", "failed"] and
         Map.has_key?(@evidence_ranks, normalized_evidence) do
      {:ok, %{status: normalized_status, evidence_class: normalized_evidence}}
    else
      {:error, :invalid_test_result}
    end
  end

  defp normalize_test_result(_result), do: {:error, :invalid_test_result}

  defp inspect_reason(reason) when is_binary(reason), do: reason
  defp inspect_reason(reason), do: inspect(reason)
end
