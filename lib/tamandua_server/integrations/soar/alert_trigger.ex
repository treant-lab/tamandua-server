defmodule TamanduaServer.Integrations.SOAR.AlertTrigger do
  @moduledoc """
  Alert-to-SOAR trigger engine.

  Evaluates alerts against trigger rules and dispatches to SOAR platforms.

  ## Flow

  1. `trigger_for_alert/1` is called when an alert is created
  2. All enabled trigger rules are evaluated against the alert
  3. For each matching rule, the alert is dispatched to the configured SOAR platform(s)
  4. Execution results are logged for tracking

  ## Rule Evaluation

  Rules can match on:
  - `severity` - Alert severity in a list of values
  - `mitre_tactics` - Any tactic matches any in the list
  - `mitre_techniques` - Any technique matches any in the list
  - `threat_score_gte` - Threat score >= threshold
  - `title_contains` - Any keyword appears in alert title (case-insensitive)

  ## Default Rules

  Pre-configured rules for common patterns:
  - Critical Alert Response - High threat score critical alerts
  - Credential Access Response - MITRE credential access tactics
  - AI Model Threat Response - AI/ML model related alerts
  """

  require Logger

  alias TamanduaServer.Integrations.SOAR.{TriggerRule, PlaybookRouter}

  # Default rules (seeded into database)
  @default_rules [
    %{
      name: "Critical Alert - Immediate Response",
      description: "Trigger high priority playbook for critical alerts with high threat score",
      enabled: true,
      priority: 100,
      match_criteria: %{
        "severity" => ["critical"],
        "threat_score_gte" => 0.8
      },
      soar_platform: "both",
      playbook_name: "high_priority_incident"
    },
    %{
      name: "Credential Access Response",
      description: "Respond to credential theft and dumping attempts",
      enabled: true,
      priority: 90,
      match_criteria: %{
        "mitre_tactics" => ["credential_access"],
        "mitre_techniques" => ["T1003", "T1552", "T1558"]
      },
      soar_platform: "xsoar",
      playbook_name: "credential_theft_response"
    },
    %{
      name: "AI Model Threat Response",
      description: "Respond to AI/ML model security threats (backdoors, pickle exploits)",
      enabled: true,
      priority: 85,
      match_criteria: %{
        "title_contains" => ["model", "backdoor", "pickle", "trojan", "safetensors", "GGUF"]
      },
      soar_platform: "tines",
      playbook_name: "ai_model_incident"
    },
    %{
      name: "Persistence Detection Response",
      description: "Investigate persistence mechanism installations",
      enabled: true,
      priority: 80,
      match_criteria: %{
        "mitre_tactics" => ["persistence"],
        "mitre_techniques" => ["T1547", "T1543", "T1053"]
      },
      soar_platform: "xsoar",
      playbook_name: "persistence_investigation"
    },
    %{
      name: "High Severity Alert",
      description: "Create incident for high severity alerts",
      enabled: true,
      priority: 70,
      match_criteria: %{
        "severity" => ["high"]
      },
      soar_platform: "both",
      playbook_name: "standard_incident"
    }
  ]

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Evaluate an alert against all enabled trigger rules and dispatch to SOAR platforms.

  ## Parameters

  - `alert` - Alert map with id, title, severity, mitre_tactics, mitre_techniques, threat_score

  ## Returns

  `{:ok, dispatched_rules}` - List of rules that matched and were dispatched
  `{:error, reason}` - If all dispatches failed
  """
  @spec trigger_for_alert(map()) :: {:ok, [map()]} | {:error, term()}
  def trigger_for_alert(alert) do
    Logger.debug("[AlertTrigger] Evaluating alert #{alert_id(alert)} against trigger rules")

    rules = get_trigger_rules(organization_id: alert[:organization_id])
    matching_rules = Enum.filter(rules, &rule_matches?(&1, alert))

    if matching_rules == [] do
      Logger.debug("[AlertTrigger] No rules matched for alert #{alert_id(alert)}")
      {:ok, []}
    else
      Logger.info("[AlertTrigger] #{length(matching_rules)} rules matched for alert #{alert_id(alert)}")

      results = Enum.map(matching_rules, fn rule ->
        case dispatch_to_soar(rule, alert) do
          {:ok, execution_ids} ->
            Logger.info("[AlertTrigger] Dispatched rule '#{rule.name}' for alert #{alert_id(alert)}: #{inspect(execution_ids)}")
            {:ok, %{rule: rule.name, execution_ids: execution_ids}}

          {:error, reason} ->
            Logger.warning("[AlertTrigger] Failed to dispatch rule '#{rule.name}': #{inspect(reason)}")
            {:error, %{rule: rule.name, error: reason}}
        end
      end)

      successful = Enum.filter(results, &match?({:ok, _}, &1)) |> Enum.map(fn {:ok, r} -> r end)
      {:ok, successful}
    end
  end

  @doc """
  Get all trigger rules, optionally filtered by organization.

  ## Options

  - `:organization_id` - Filter to rules for this organization (plus global rules)
  - `:enabled_only` - If true, only return enabled rules (default: true)

  ## Returns

  List of TriggerRule structs.
  """
  @spec get_trigger_rules(keyword()) :: [TriggerRule.t()]
  def get_trigger_rules(opts \\ []) do
    enabled_only = Keyword.get(opts, :enabled_only, true)

    if enabled_only do
      TriggerRule.list_enabled(opts)
    else
      TriggerRule.list_all(opts)
    end
  end

  @doc """
  Add a new trigger rule.

  ## Parameters

  - `attrs` - Rule attributes (name, match_criteria, soar_platform, playbook_name, etc.)

  ## Returns

  `{:ok, rule}` or `{:error, changeset}`.
  """
  @spec add_trigger_rule(map()) :: {:ok, TriggerRule.t()} | {:error, Ecto.Changeset.t()}
  def add_trigger_rule(attrs) do
    TriggerRule.create(attrs)
  end

  @doc """
  Update an existing trigger rule.

  ## Parameters

  - `rule` - TriggerRule struct or rule ID
  - `attrs` - Attributes to update

  ## Returns

  `{:ok, rule}` or `{:error, changeset}`.
  """
  @spec update_trigger_rule(TriggerRule.t() | binary(), map()) :: {:ok, TriggerRule.t()} | {:error, term()}
  def update_trigger_rule(%TriggerRule{} = rule, attrs) do
    TriggerRule.update(rule, attrs)
  end

  def update_trigger_rule(rule_id, attrs) when is_binary(rule_id) do
    case TriggerRule.get(rule_id) do
      nil -> {:error, :not_found}
      rule -> TriggerRule.update(rule, attrs)
    end
  end

  @doc """
  Delete a trigger rule.

  ## Parameters

  - `rule` - TriggerRule struct or rule ID

  ## Returns

  `{:ok, rule}` or `{:error, reason}`.
  """
  @spec delete_trigger_rule(TriggerRule.t() | binary()) :: {:ok, TriggerRule.t()} | {:error, term()}
  def delete_trigger_rule(rule_or_id) do
    TriggerRule.delete(rule_or_id)
  end

  @doc """
  Get the default trigger rules for seeding.

  ## Returns

  List of default rule configurations.
  """
  @spec get_default_rules() :: [map()]
  def get_default_rules, do: @default_rules

  @doc """
  Seed default trigger rules into the database.

  Skips rules that already exist (by name).

  ## Returns

  `{:ok, created_count}` - Number of rules created.
  """
  @spec seed_default_rules() :: {:ok, non_neg_integer()}
  def seed_default_rules do
    existing_names = get_trigger_rules(enabled_only: false)
    |> Enum.map(& &1.name)
    |> MapSet.new()

    created = @default_rules
    |> Enum.reject(fn rule -> MapSet.member?(existing_names, rule.name) end)
    |> Enum.map(fn rule_attrs ->
      case add_trigger_rule(rule_attrs) do
        {:ok, _rule} -> 1
        {:error, _} -> 0
      end
    end)
    |> Enum.sum()

    Logger.info("[AlertTrigger] Seeded #{created} default trigger rules")
    {:ok, created}
  end

  # ============================================================================
  # Rule Evaluation
  # ============================================================================

  @doc """
  Check if a rule matches an alert.

  ## Parameters

  - `rule` - TriggerRule struct
  - `alert` - Alert map

  ## Returns

  Boolean indicating if the rule matches.
  """
  @spec evaluate_rule(TriggerRule.t(), map()) :: boolean()
  def evaluate_rule(rule, alert) do
    rule_matches?(rule, alert)
  end

  defp rule_matches?(rule, alert) do
    criteria = rule.match_criteria || %{}

    # If no criteria, rule matches everything
    if criteria == %{} do
      true
    else
      # All criteria must match (AND logic)
      Enum.all?(criteria, fn {key, value} ->
        criterion_matches?(key, value, alert)
      end)
    end
  end

  defp criterion_matches?("severity", expected_severities, alert) when is_list(expected_severities) do
    alert_severity = String.downcase(to_string(alert[:severity] || alert["severity"] || ""))
    normalized = Enum.map(expected_severities, &String.downcase(to_string(&1)))
    alert_severity in normalized
  end

  defp criterion_matches?("mitre_tactics", expected_tactics, alert) when is_list(expected_tactics) do
    alert_tactics = get_list_field(alert, :mitre_tactics)
    normalized_expected = Enum.map(expected_tactics, &String.downcase(to_string(&1)))
    normalized_alert = Enum.map(alert_tactics, &String.downcase(to_string(&1)))

    # Any tactic match triggers
    Enum.any?(normalized_expected, &(&1 in normalized_alert))
  end

  defp criterion_matches?("mitre_techniques", expected_techniques, alert) when is_list(expected_techniques) do
    alert_techniques = get_list_field(alert, :mitre_techniques)
    normalized_expected = Enum.map(expected_techniques, &String.upcase(to_string(&1)))
    normalized_alert = Enum.map(alert_techniques, &String.upcase(to_string(&1)))

    # Any technique match triggers
    Enum.any?(normalized_expected, &(&1 in normalized_alert))
  end

  defp criterion_matches?("threat_score_gte", threshold, alert) when is_number(threshold) do
    score = alert[:threat_score] || alert["threat_score"] || 0
    is_number(score) and score >= threshold
  end

  defp criterion_matches?("title_contains", keywords, alert) when is_list(keywords) do
    title = String.downcase(to_string(alert[:title] || alert["title"] || ""))
    normalized_keywords = Enum.map(keywords, &String.downcase(to_string(&1)))

    # Any keyword match triggers
    Enum.any?(normalized_keywords, &String.contains?(title, &1))
  end

  defp criterion_matches?(key, _value, _alert) do
    Logger.warning("[AlertTrigger] Unknown criterion key: #{key}")
    false
  end

  defp get_list_field(alert, key) do
    value = alert[key] || alert[to_string(key)] || []
    if is_list(value), do: value, else: []
  end

  # ============================================================================
  # SOAR Dispatch
  # ============================================================================

  defp dispatch_to_soar(rule, alert) do
    PlaybookRouter.route_to_playbook(
      rule.soar_platform,
      alert,
      playbook_name: rule.playbook_name,
      webhook_url: rule.webhook_url,
      params: rule.params,
      rule_id: rule.id
    )
  end

  defp alert_id(alert) do
    alert[:id] || alert["id"] || "unknown"
  end
end
