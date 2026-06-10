defmodule TamanduaServer.Cloud.PolicyEngine do
  @moduledoc """
  Cloud Security Policy Engine for CSPM.

  Evaluates cloud resources against security policies defined in YAML/JSON format.
  Supports:
  - CIS Benchmark policies (AWS, Azure, GCP)
  - Custom policy definitions
  - Policy expressions with AND/OR/NOT logic
  - Remediation guidance with IaC templates

  ## Policy Format

  Policies are defined in YAML with the following structure:

      id: "aws-s3-001"
      name: "S3 Bucket Public Access"
      description: "Ensure S3 buckets do not allow public access"
      provider: "aws"
      resource_type: "aws_s3_bucket"
      severity: "critical"
      category: "data_protection"
      compliance:
        - "CIS AWS 2.1.1"
        - "PCI DSS 7.1"
      condition:
        or:
          - field: "metadata.allow_blob_public_access"
            operator: "equals"
            value: true
          - field: "metadata.public_access_block.BlockPublicAcls"
            operator: "not_equals"
            value: true
      recommendation: "Enable S3 Block Public Access settings"
      remediation:
        terraform: |
          resource "aws_s3_bucket_public_access_block" "example" {
            bucket = aws_s3_bucket.example.id
            block_public_acls = true
          }
  """

  require Logger
  alias TamanduaServer.Cloud.Finding

  @type policy :: %{
          id: String.t(),
          name: String.t(),
          description: String.t(),
          provider: String.t(),
          resource_type: String.t() | [String.t()],
          severity: String.t(),
          category: String.t(),
          enabled: boolean(),
          compliance: [String.t()],
          condition: map(),
          recommendation: String.t(),
          remediation: map()
        }

  @type evaluation_result :: %{
          policy_id: String.t(),
          resource_id: String.t(),
          passed: boolean(),
          finding: map() | nil
        }

  # ETS tables for policy storage
  @policies_table :cloud_policies
  @custom_policies_table :cloud_custom_policies

  @policies_dir "priv/cloud_policies"

  # ============================================================================
  # Policy Loading
  # ============================================================================

  @doc """
  Initialize the policy engine and load all built-in policies.
  """
  @spec init() :: :ok
  def init do
    ensure_tables()
    load_builtin_policies()
    Logger.info("Cloud Policy Engine initialized")
    :ok
  end

  @doc """
  Load all built-in policies from the priv/cloud_policies directory.
  """
  @spec load_builtin_policies() :: {:ok, integer()} | {:error, term()}
  def load_builtin_policies do
    ensure_tables()

    policies_path = Application.app_dir(:tamandua_server, @policies_dir)

    case File.ls(policies_path) do
      {:ok, files} ->
        yaml_files = Enum.filter(files, fn f -> String.ends_with?(f, [".yaml", ".yml"]) end)

        count =
          Enum.reduce(yaml_files, 0, fn file, acc ->
            path = Path.join(policies_path, file)

            case load_policy_file(path) do
              {:ok, policies} ->
                Enum.each(policies, fn policy ->
                  :ets.insert(@policies_table, {policy.id, policy})
                end)

                acc + length(policies)

              {:error, reason} ->
                Logger.warning("Failed to load policy file #{file}: #{inspect(reason)}")
                acc
            end
          end)

        Logger.info("Loaded #{count} built-in cloud security policies")
        {:ok, count}

      {:error, :enoent} ->
        Logger.warning("Policies directory not found: #{policies_path}")
        {:ok, 0}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Load policies from a YAML file.
  """
  @spec load_policy_file(String.t()) :: {:ok, [policy()]} | {:error, term()}
  def load_policy_file(path) do
    case File.read(path) do
      {:ok, content} ->
        case YamlElixir.read_from_string(content) do
          {:ok, data} ->
            policies = parse_policies(data)
            {:ok, policies}

          {:error, reason} ->
            {:error, {:yaml_parse_error, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse_policies(data) when is_list(data) do
    Enum.map(data, &parse_policy/1)
  end

  defp parse_policies(%{"policies" => policies}) when is_list(policies) do
    Enum.map(policies, &parse_policy/1)
  end

  defp parse_policies(data) when is_map(data) do
    [parse_policy(data)]
  end

  defp parse_policy(data) do
    %{
      id: data["id"],
      name: data["name"],
      description: data["description"],
      provider: data["provider"],
      resource_type: data["resource_type"],
      severity: data["severity"] || "medium",
      category: data["category"] || "other",
      enabled: Map.get(data, "enabled", true),
      compliance: data["compliance"] || [],
      condition: parse_condition(data["condition"]),
      recommendation: data["recommendation"],
      remediation: %{
        terraform: get_in(data, ["remediation", "terraform"]),
        cloudformation: get_in(data, ["remediation", "cloudformation"]),
        arm: get_in(data, ["remediation", "arm"]),
        gcloud: get_in(data, ["remediation", "gcloud"]),
        cli: get_in(data, ["remediation", "cli"])
      }
    }
  end

  defp parse_condition(nil), do: %{always: false}

  defp parse_condition(condition) when is_map(condition) do
    cond do
      Map.has_key?(condition, "and") ->
        %{and: Enum.map(condition["and"], &parse_condition/1)}

      Map.has_key?(condition, "or") ->
        %{or: Enum.map(condition["or"], &parse_condition/1)}

      Map.has_key?(condition, "not") ->
        %{not: parse_condition(condition["not"])}

      Map.has_key?(condition, "field") ->
        %{
          field: condition["field"],
          operator: condition["operator"] || "equals",
          value: condition["value"]
        }

      true ->
        condition
    end
  end

  # ============================================================================
  # Custom Policy Management
  # ============================================================================

  @doc """
  Add a custom policy.
  """
  @spec add_custom_policy(map()) :: {:ok, policy()} | {:error, term()}
  def add_custom_policy(params) do
    ensure_tables()

    policy = parse_policy(params)

    case validate_policy(policy) do
      :ok ->
        policy = Map.put(policy, :id, params["id"] || generate_policy_id())
        :ets.insert(@custom_policies_table, {policy.id, policy})
        Logger.info("Added custom cloud policy: #{policy.id}")
        {:ok, policy}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Update a custom policy.
  """
  @spec update_custom_policy(String.t(), map()) :: {:ok, policy()} | {:error, term()}
  def update_custom_policy(policy_id, params) do
    ensure_tables()

    case :ets.lookup(@custom_policies_table, policy_id) do
      [{^policy_id, existing}] ->
        updated =
          existing
          |> Map.merge(atomize_keys(params))
          |> Map.put(:id, policy_id)

        case validate_policy(updated) do
          :ok ->
            :ets.insert(@custom_policies_table, {policy_id, updated})
            {:ok, updated}

          {:error, reason} ->
            {:error, reason}
        end

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  Delete a custom policy.
  """
  @spec delete_custom_policy(String.t()) :: :ok | {:error, :not_found}
  def delete_custom_policy(policy_id) do
    ensure_tables()

    case :ets.lookup(@custom_policies_table, policy_id) do
      [{^policy_id, _}] ->
        :ets.delete(@custom_policies_table, policy_id)
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  List all policies (built-in and custom).
  """
  @spec list_policies(map()) :: [policy()]
  def list_policies(filters \\ %{}) do
    ensure_tables()

    builtin =
      :ets.tab2list(@policies_table)
      |> Enum.map(fn {_id, policy} -> Map.put(policy, :source, :builtin) end)

    custom =
      :ets.tab2list(@custom_policies_table)
      |> Enum.map(fn {_id, policy} -> Map.put(policy, :source, :custom) end)

    (builtin ++ custom)
    |> apply_policy_filters(filters)
  end

  @doc """
  Get a specific policy by ID.
  """
  @spec get_policy(String.t()) :: {:ok, policy()} | {:error, :not_found}
  def get_policy(policy_id) do
    ensure_tables()

    case :ets.lookup(@policies_table, policy_id) do
      [{^policy_id, policy}] ->
        {:ok, Map.put(policy, :source, :builtin)}

      [] ->
        case :ets.lookup(@custom_policies_table, policy_id) do
          [{^policy_id, policy}] ->
            {:ok, Map.put(policy, :source, :custom)}

          [] ->
            {:error, :not_found}
        end
    end
  end

  # ============================================================================
  # Policy Evaluation
  # ============================================================================

  @doc """
  Evaluate a resource against all applicable policies.
  """
  @spec evaluate_resource(map()) :: [evaluation_result()]
  def evaluate_resource(resource) do
    ensure_tables()

    applicable_policies =
      list_policies(%{
        provider: resource[:provider] || resource["provider"],
        resource_type: resource[:type] || resource["type"]
      })
      |> Enum.filter(fn p -> p.enabled end)

    Enum.map(applicable_policies, fn policy ->
      evaluate_policy(policy, resource)
    end)
  end

  @doc """
  Evaluate a single policy against a resource.
  """
  @spec evaluate_policy(policy(), map()) :: evaluation_result()
  def evaluate_policy(policy, resource) do
    passed = evaluate_condition(policy.condition, resource)

    if passed do
      %{
        policy_id: policy.id,
        resource_id: resource[:id] || resource["id"],
        passed: true,
        finding: nil
      }
    else
      finding =
        Finding.create(%{
          provider: policy.provider,
          account_id: resource[:account_id] || resource[:project_id] || resource[:subscription_id],
          resource_id: resource[:id] || resource["id"],
          resource_arn: resource[:arn] || resource[:self_link] || resource["id"],
          resource_name: resource[:name] || resource["name"],
          resource_type: resource[:type] || resource["type"],
          region: resource[:region] || resource[:location] || resource[:zone],
          category: policy.category,
          severity: policy.severity,
          title: policy.name,
          description: policy.description,
          recommendation: policy.recommendation,
          compliance: policy.compliance,
          remediation_terraform: policy.remediation[:terraform],
          remediation_cloudformation: policy.remediation[:cloudformation],
          remediation_arm: policy.remediation[:arm]
        })

      %{
        policy_id: policy.id,
        resource_id: resource[:id] || resource["id"],
        passed: false,
        finding: finding
      }
    end
  end

  @doc """
  Evaluate a condition expression against a resource.
  """
  @spec evaluate_condition(map(), map()) :: boolean()
  def evaluate_condition(%{and: conditions}, resource) when is_list(conditions) do
    Enum.all?(conditions, fn c -> evaluate_condition(c, resource) end)
  end

  def evaluate_condition(%{or: conditions}, resource) when is_list(conditions) do
    Enum.any?(conditions, fn c -> evaluate_condition(c, resource) end)
  end

  def evaluate_condition(%{not: condition}, resource) do
    not evaluate_condition(condition, resource)
  end

  def evaluate_condition(%{always: value}, _resource), do: value

  def evaluate_condition(%{field: field, operator: operator, value: expected}, resource) do
    actual = get_nested_value(resource, field)
    compare_values(operator, actual, expected)
  end

  def evaluate_condition(%{"field" => field, "operator" => operator, "value" => expected}, resource) do
    actual = get_nested_value(resource, field)
    compare_values(operator, actual, expected)
  end

  def evaluate_condition(_, _), do: true

  defp get_nested_value(resource, field) when is_binary(field) do
    path = String.split(field, ".")
    get_in_path(resource, path)
  end

  defp get_in_path(value, []), do: value
  defp get_in_path(nil, _), do: nil

  defp get_in_path(map, [key | rest]) when is_map(map) do
    value = Map.get(map, key) || Map.get(map, String.to_atom(key))
    get_in_path(value, rest)
  end

  defp get_in_path(_, _), do: nil

  defp compare_values("equals", actual, expected), do: actual == expected
  defp compare_values("not_equals", actual, expected), do: actual != expected
  defp compare_values("greater_than", actual, expected) when is_number(actual), do: actual > expected
  defp compare_values("greater_than_or_equals", actual, expected) when is_number(actual), do: actual >= expected
  defp compare_values("less_than", actual, expected) when is_number(actual), do: actual < expected
  defp compare_values("less_than_or_equals", actual, expected) when is_number(actual), do: actual <= expected
  defp compare_values("contains", actual, expected) when is_binary(actual), do: String.contains?(actual, expected)
  defp compare_values("contains", actual, expected) when is_list(actual), do: expected in actual
  defp compare_values("not_contains", actual, expected) when is_binary(actual), do: not String.contains?(actual, expected)
  defp compare_values("not_contains", actual, expected) when is_list(actual), do: expected not in actual
  defp compare_values("starts_with", actual, expected) when is_binary(actual), do: String.starts_with?(actual, expected)
  defp compare_values("ends_with", actual, expected) when is_binary(actual), do: String.ends_with?(actual, expected)
  defp compare_values("regex", actual, expected) when is_binary(actual), do: Regex.match?(~r/#{expected}/, actual)
  defp compare_values("is_empty", actual, _), do: is_nil(actual) or actual == "" or actual == [] or actual == %{}
  defp compare_values("is_not_empty", actual, _), do: not (is_nil(actual) or actual == "" or actual == [] or actual == %{})
  defp compare_values("is_true", actual, _), do: actual == true
  defp compare_values("is_false", actual, _), do: actual == false or actual == nil
  defp compare_values("is_nil", actual, _), do: is_nil(actual)
  defp compare_values("is_not_nil", actual, _), do: not is_nil(actual)
  defp compare_values("in", actual, expected) when is_list(expected), do: actual in expected
  defp compare_values("not_in", actual, expected) when is_list(expected), do: actual not in expected
  defp compare_values("all_of", actual, expected) when is_list(actual) and is_list(expected), do: Enum.all?(expected, fn e -> e in actual end)
  defp compare_values("any_of", actual, expected) when is_list(actual) and is_list(expected), do: Enum.any?(expected, fn e -> e in actual end)
  defp compare_values("none_of", actual, expected) when is_list(actual) and is_list(expected), do: Enum.all?(expected, fn e -> e not in actual end)
  defp compare_values(_, _, _), do: false

  # ============================================================================
  # Batch Evaluation
  # ============================================================================

  @doc """
  Evaluate all resources from a scan against applicable policies.
  """
  @spec evaluate_scan_results([map()], String.t()) :: %{
          total_resources: integer(),
          total_evaluations: integer(),
          passed: integer(),
          failed: integer(),
          findings: [map()]
        }
  def evaluate_scan_results(resources, provider) do
    ensure_tables()

    policies =
      list_policies(%{provider: provider})
      |> Enum.filter(fn p -> p.enabled end)

    {passed, failed, findings} =
      Enum.reduce(resources, {0, 0, []}, fn resource, {p_acc, f_acc, findings_acc} ->
        applicable = Enum.filter(policies, fn policy ->
          policy_matches_resource_type?(policy, resource)
        end)

        results = Enum.map(applicable, fn policy -> evaluate_policy(policy, resource) end)

        new_passed = Enum.count(results, fn r -> r.passed end)
        new_failed = Enum.count(results, fn r -> not r.passed end)
        new_findings = results |> Enum.reject(fn r -> r.passed end) |> Enum.map(fn r -> r.finding end)

        {p_acc + new_passed, f_acc + new_failed, findings_acc ++ new_findings}
      end)

    %{
      total_resources: length(resources),
      total_evaluations: passed + failed,
      passed: passed,
      failed: failed,
      findings: findings
    }
  end

  defp policy_matches_resource_type?(policy, resource) do
    resource_type = resource[:type] || resource["type"]

    case policy.resource_type do
      types when is_list(types) -> resource_type in types
      type when is_binary(type) -> resource_type == type
      _ -> true
    end
  end

  # ============================================================================
  # Policy Statistics
  # ============================================================================

  @doc """
  Get policy statistics.
  """
  @spec statistics() :: map()
  def statistics do
    ensure_tables()

    policies = list_policies()

    by_provider = Enum.group_by(policies, & &1.provider)
    by_severity = Enum.group_by(policies, & &1.severity)
    by_category = Enum.group_by(policies, & &1.category)
    by_source = Enum.group_by(policies, & &1.source)

    %{
      total: length(policies),
      by_provider: Enum.map(by_provider, fn {k, v} -> {k, length(v)} end) |> Enum.into(%{}),
      by_severity: Enum.map(by_severity, fn {k, v} -> {k, length(v)} end) |> Enum.into(%{}),
      by_category: Enum.map(by_category, fn {k, v} -> {k, length(v)} end) |> Enum.into(%{}),
      builtin: length(Map.get(by_source, :builtin, [])),
      custom: length(Map.get(by_source, :custom, [])),
      enabled: Enum.count(policies, & &1.enabled),
      disabled: Enum.count(policies, fn p -> not p.enabled end)
    }
  end

  # ============================================================================
  # Compliance Framework Mapping
  # ============================================================================

  @doc """
  Get policies mapped to a compliance framework.
  """
  @spec policies_by_compliance(String.t()) :: [policy()]
  def policies_by_compliance(framework) do
    list_policies()
    |> Enum.filter(fn policy ->
      Enum.any?(policy.compliance, fn c ->
        String.contains?(String.downcase(c), String.downcase(framework))
      end)
    end)
  end

  @doc """
  Calculate compliance score for a set of evaluation results.
  """
  @spec compliance_score([evaluation_result()], String.t()) :: %{
          framework: String.t(),
          total_controls: integer(),
          passed_controls: integer(),
          failed_controls: integer(),
          score: float()
        }
  def compliance_score(results, framework) do
    framework_policies = policies_by_compliance(framework)
    framework_policy_ids = Enum.map(framework_policies, & &1.id) |> MapSet.new()

    relevant_results = Enum.filter(results, fn r -> r.policy_id in framework_policy_ids end)

    total = length(relevant_results)
    passed = Enum.count(relevant_results, & &1.passed)
    failed = total - passed

    %{
      framework: framework,
      total_controls: total,
      passed_controls: passed,
      failed_controls: failed,
      score: if(total > 0, do: Float.round(passed / total * 100, 1), else: 100.0)
    }
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp ensure_tables do
    tables = [@policies_table, @custom_policies_table]

    Enum.each(tables, fn table ->
      case :ets.whereis(table) do
        :undefined -> :ets.new(table, [:set, :public, :named_table])
        _ -> :ok
      end
    end)
  end

  defp validate_policy(policy) do
    cond do
      is_nil(policy.id) or policy.id == "" ->
        {:error, "Policy ID is required"}

      is_nil(policy.name) or policy.name == "" ->
        {:error, "Policy name is required"}

      is_nil(policy.provider) ->
        {:error, "Policy provider is required"}

      policy.provider not in ["aws", "azure", "gcp", "all"] ->
        {:error, "Invalid provider: #{policy.provider}"}

      policy.severity not in ["critical", "high", "medium", "low", "informational"] ->
        {:error, "Invalid severity: #{policy.severity}"}

      true ->
        :ok
    end
  end

  defp apply_policy_filters(policies, filters) do
    policies
    |> filter_by(:provider, filters[:provider])
    |> filter_by(:severity, filters[:severity])
    |> filter_by(:category, filters[:category])
    |> filter_by(:enabled, filters[:enabled])
    |> filter_by_resource_type(filters[:resource_type])
    |> filter_by_compliance(filters[:compliance])
  end

  defp filter_by(list, _field, nil), do: list
  defp filter_by(list, field, value), do: Enum.filter(list, fn p -> Map.get(p, field) == value end)

  defp filter_by_resource_type(list, nil), do: list

  defp filter_by_resource_type(list, type) do
    Enum.filter(list, fn policy ->
      case policy.resource_type do
        types when is_list(types) -> type in types
        t when is_binary(t) -> t == type
        _ -> true
      end
    end)
  end

  defp filter_by_compliance(list, nil), do: list

  defp filter_by_compliance(list, framework) do
    Enum.filter(list, fn policy ->
      Enum.any?(policy.compliance, fn c ->
        String.contains?(String.downcase(c), String.downcase(framework))
      end)
    end)
  end

  defp generate_policy_id do
    "custom-#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
  end

  defp atomize_keys(map) when is_map(map) do
    Enum.reduce(map, %{}, fn
      {key, value}, acc when is_binary(key) ->
        Map.put(acc, String.to_atom(key), value)

      {key, value}, acc ->
        Map.put(acc, key, value)
    end)
  end
end
