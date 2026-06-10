defmodule TamanduaServer.MlRules.Generator do
  @moduledoc """
  Integration with ML service for rule generation from hunt findings.

  Orchestrates the hunt-to-rule pipeline:
  1. Extract features from hunt findings
  2. Generate detection rules (YARA, Sigma, ML)
  3. Optimize rules using historical data
  4. Validate rules
  5. Store rules for review
  """

  require Logger
  alias TamanduaServer.MlRules.MlRule
  alias TamanduaServer.Hunting.HuntSession
  alias TamanduaServer.Repo

  @ml_service_url Application.compile_env(:tamandua_server, :ml_service_url, "http://localhost:8000")

  @doc """
  Generate detection rules from a hunt session.

  Returns {:ok, rules} or {:error, reason}
  """
  def generate_from_hunt(hunt_session_id, opts \\ []) do
    with {:ok, hunt_session} <- get_hunt_session(hunt_session_id),
         {:ok, findings} <- get_hunt_findings(hunt_session),
         {:ok, features} <- extract_features(findings),
         {:ok, rules} <- generate_rules(features, hunt_session, opts),
         {:ok, optimized_rules} <- optimize_rules(rules, opts),
         {:ok, saved_rules} <- save_rules(optimized_rules, hunt_session) do
      Logger.info("Generated #{length(saved_rules)} rules from hunt #{hunt_session.id}")
      {:ok, saved_rules}
    else
      {:error, reason} = error ->
        Logger.error("Failed to generate rules from hunt: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Extract features from hunt findings using ML service.
  """
  def extract_features(findings) do
    payload = %{
      findings: findings,
      min_frequency_threshold: 0.3,
      max_features: 50
    }

    case http_client().post("#{@ml_service_url}/api/v1/rule-generation/extract-features", payload) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body["features"]}

      {:ok, %{status: status, body: body}} ->
        Logger.error("Feature extraction failed with status #{status}: #{inspect(body)}")
        {:error, "Feature extraction failed: #{body["detail"] || "unknown error"}"}

      {:error, reason} ->
        Logger.error("HTTP request failed: #{inspect(reason)}")
        {:error, "Failed to connect to ML service"}
    end
  end

  @doc """
  Generate detection rules from extracted features.
  """
  def generate_rules(features, hunt_session, opts) do
    rule_types = Keyword.get(opts, :rule_types, ["yara", "sigma", "ml_custom"])

    payload = %{
      features: features,
      hunt_name: hunt_session.query,
      rule_types: rule_types
    }

    case http_client().post("#{@ml_service_url}/api/v1/rule-generation/generate", payload) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body["rules"]}

      {:ok, %{status: status, body: body}} ->
        Logger.error("Rule generation failed with status #{status}: #{inspect(body)}")
        {:error, "Rule generation failed: #{body["detail"] || "unknown error"}"}

      {:error, reason} ->
        Logger.error("HTTP request failed: #{inspect(reason)}")
        {:error, "Failed to connect to ML service"}
    end
  end

  @doc """
  Optimize rules using historical data and Optuna.
  """
  def optimize_rules(rules, opts) do
    enable_optimization = Keyword.get(opts, :optimize, true)

    if enable_optimization do
      # Get historical data for validation
      historical_data = get_historical_data(opts)

      optimized = Enum.map(rules, fn rule ->
        case optimize_single_rule(rule, historical_data) do
          {:ok, optimized_rule} -> optimized_rule
          {:error, _reason} -> rule  # Fall back to unoptimized
        end
      end)

      {:ok, optimized}
    else
      {:ok, rules}
    end
  end

  @doc """
  Optimize a single rule using ML service.
  """
  def optimize_single_rule(rule, historical_data) do
    payload = %{
      rule: rule,
      historical_data: historical_data,
      target_precision: 0.95,
      target_recall: 0.80,
      n_trials: 100,
      timeout: 300
    }

    case http_client().post("#{@ml_service_url}/api/v1/rule-generation/optimize", payload) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body["optimized_rule"]}

      {:ok, %{status: status, body: body}} ->
        Logger.warning("Rule optimization failed with status #{status}: #{inspect(body)}")
        {:error, "Optimization failed"}

      {:error, reason} ->
        Logger.warning("Optimization request failed: #{inspect(reason)}")
        {:error, "Optimization request failed"}
    end
  end

  @doc """
  Save generated rules to database.
  """
  def save_rules(rules, hunt_session) do
    saved_rules = Enum.map(rules, fn rule ->
      attrs = %{
        rule_id: rule["rule_id"],
        rule_type: rule["rule_type"],
        name: rule["name"],
        description: rule["description"],
        content: rule["content"],
        severity: rule["severity"],
        enabled: false,  # Disabled until approved
        approved: false,
        hunt_campaign: hunt_session.query,
        hunt_session_id: hunt_session.id,
        finding_count: rule["metadata"]["finding_count"],
        confidence_score: rule["confidence_score"],
        mitre_techniques: rule["mitre_techniques"] || [],
        tags: rule["tags"] || [],
        precision: get_in(rule, ["metadata", "precision"]),
        recall: get_in(rule, ["metadata", "recall"]),
        f1_score: get_in(rule, ["metadata", "f1_score"]),
        true_positives: get_in(rule, ["metadata", "true_positives"]),
        false_positives: get_in(rule, ["metadata", "false_positives"]),
        true_negatives: get_in(rule, ["metadata", "true_negatives"]),
        false_negatives: get_in(rule, ["metadata", "false_negatives"]),
        optimized_params: rule["metadata"]["optimized_params"] || %{},
        validation_passed: rule["metadata"]["validation_passed"] || false,
        metadata: rule["metadata"] || %{},
        organization_id: hunt_session.organization_id || get_default_org_id()
      }

      case create_ml_rule(attrs) do
        {:ok, ml_rule} -> ml_rule
        {:error, changeset} ->
          Logger.error("Failed to save rule: #{inspect(changeset.errors)}")
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)

    {:ok, saved_rules}
  end

  @doc """
  Create an ML rule.
  """
  def create_ml_rule(attrs) do
    %MlRule{}
    |> MlRule.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Approve a rule for deployment.
  """
  def approve_rule(rule_id, user_id) do
    case get_ml_rule(rule_id) do
      nil ->
        {:error, :not_found}

      rule ->
        attrs = %{
          approved: true,
          approved_at: DateTime.utc_now(),
          approved_by_id: user_id,
          enabled: true
        }

        rule
        |> MlRule.approval_changeset(attrs)
        |> Repo.update()
    end
  end

  @doc """
  Reject a rule.
  """
  def reject_rule(rule_id) do
    case get_ml_rule(rule_id) do
      nil -> {:error, :not_found}
      rule -> Repo.delete(rule)
    end
  end

  @doc """
  Deploy approved rule to detection engine.
  """
  def deploy_rule(rule_id) do
    case get_ml_rule(rule_id) do
      nil ->
        {:error, :not_found}

      %{approved: false} ->
        {:error, :not_approved}

      rule ->
        deploy_to_engine(rule)
    end
  end

  @doc """
  Start A/B test for a rule.
  """
  def start_ab_test(rule_id, test_group, duration_hours \\ 24) do
    case get_ml_rule(rule_id) do
      nil ->
        {:error, :not_found}

      rule ->
        attrs = %{
          ab_test_group: test_group,
          ab_test_start: DateTime.utc_now(),
          ab_test_end: DateTime.utc_now() |> DateTime.add(duration_hours * 3600, :second),
          ab_test_metrics: %{}
        }

        rule
        |> MlRule.ab_test_changeset(attrs)
        |> Repo.update()
    end
  end

  @doc """
  List ML rules with optional filters.
  """
  def list_ml_rules(filters \\ %{}) do
    import Ecto.Query

    query = from(r in MlRule, order_by: [desc: r.inserted_at])

    query =
      if filters[:approved] != nil do
        where(query, [r], r.approved == ^filters[:approved])
      else
        query
      end

    query =
      if filters[:enabled] != nil do
        where(query, [r], r.enabled == ^filters[:enabled])
      else
        query
      end

    query =
      if filters[:rule_type] do
        where(query, [r], r.rule_type == ^filters[:rule_type])
      else
        query
      end

    query =
      if filters[:hunt_session_id] do
        where(query, [r], r.hunt_session_id == ^filters[:hunt_session_id])
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Get a single ML rule.
  """
  def get_ml_rule(id) do
    Repo.get(MlRule, id)
  end

  # Private helper functions

  defp get_hunt_session(hunt_session_id) do
    case Repo.get(HuntSession, hunt_session_id) do
      nil -> {:error, :hunt_session_not_found}
      hunt_session -> {:ok, hunt_session}
    end
  end

  defp get_hunt_findings(hunt_session) do
    # In a real implementation, this would query the events/alerts table
    # based on the hunt session's findings
    findings = hunt_session.findings || []
    {:ok, findings}
  end

  defp get_historical_data(_opts) do
    # In a real implementation, this would fetch historical events
    # with labels (malicious/benign) for validation
    # For now, return empty list
    []
  end

  defp deploy_to_engine(rule) do
    case rule.rule_type do
      "yara" ->
        deploy_yara_rule(rule)

      "sigma" ->
        deploy_sigma_rule(rule)

      "ml_custom" ->
        deploy_ml_custom_rule(rule)

      _ ->
        {:error, :unsupported_rule_type}
    end
  end

  defp deploy_yara_rule(rule) do
    # Create YARA rule in the main detection engine
    attrs = %{
      name: rule.rule_id,
      description: rule.description,
      source: rule.content,
      enabled: rule.enabled,
      severity: rule.severity,
      mitre_techniques: rule.mitre_techniques,
      tags: rule.tags ++ ["ml-generated"],
      metadata: rule.metadata,
      organization_id: rule.organization_id
    }

    case TamanduaServer.Detection.create_yara_rule(attrs) do
      {:ok, _yara_rule} ->
        Logger.info("Deployed YARA rule #{rule.rule_id}")
        {:ok, :deployed}

      {:error, changeset} ->
        Logger.error("Failed to deploy YARA rule: #{inspect(changeset.errors)}")
        {:error, :deployment_failed}
    end
  end

  defp deploy_sigma_rule(rule) do
    # Parse Sigma YAML and create Sigma rule
    case YamlElixir.read_from_string(rule.content) do
      {:ok, sigma_dict} ->
        attrs = %{
          name: rule.rule_id,
          title: sigma_dict["title"],
          description: sigma_dict["description"],
          raw_yaml: rule.content,
          enabled: rule.enabled,
          level: sigma_dict["level"] || "medium",
          mitre_tactics: extract_mitre_tactics(sigma_dict),
          mitre_techniques: extract_mitre_techniques(sigma_dict),
          tags: sigma_dict["tags"] || [],
          metadata: rule.metadata,
          organization_id: rule.organization_id
        }

        case TamanduaServer.Detection.create_sigma_rule(attrs) do
          {:ok, _sigma_rule} ->
            Logger.info("Deployed Sigma rule #{rule.rule_id}")
            {:ok, :deployed}

          {:error, changeset} ->
            Logger.error("Failed to deploy Sigma rule: #{inspect(changeset.errors)}")
            {:error, :deployment_failed}
        end

      {:error, reason} ->
        Logger.error("Failed to parse Sigma YAML: #{inspect(reason)}")
        {:error, :invalid_sigma_yaml}
    end
  rescue
    _ ->
      {:error, :invalid_sigma_yaml}
  end

  defp deploy_ml_custom_rule(rule) do
    # Store ML custom rule in a dedicated table or config
    # For now, just log it
    Logger.info("ML custom rule #{rule.rule_id} ready for deployment")
    {:ok, :deployed}
  end

  defp extract_mitre_tactics(sigma_dict) do
    tags = sigma_dict["tags"] || []

    tags
    |> Enum.filter(&String.starts_with?(&1, "attack."))
    |> Enum.map(&String.replace(&1, "attack.", ""))
    |> Enum.filter(fn tag ->
      # Only tactics, not techniques (techniques have dots)
      not String.contains?(tag, ".")
    end)
  end

  defp extract_mitre_techniques(sigma_dict) do
    tags = sigma_dict["tags"] || []

    tags
    |> Enum.filter(&String.starts_with?(&1, "attack.t"))
    |> Enum.map(&String.replace(&1, "attack.", ""))
    |> Enum.map(&String.upcase/1)
  end

  defp get_default_org_id do
    # Get first organization or nil
    import Ecto.Query
    from(o in TamanduaServer.Accounts.Organization, limit: 1)
    |> Repo.one()
    |> case do
      nil -> nil
      org -> org.id
    end
  end

  defp http_client do
    # Use HTTPoison or Finch for HTTP requests
    # For now, return a module that we'll implement
    TamanduaServer.MlRules.HttpClient
  end
end
