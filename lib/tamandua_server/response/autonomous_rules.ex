defmodule TamanduaServer.Response.AutonomousRules do
  @moduledoc """
  Autonomous Response Rules Engine

  Manages IF/THEN rules for autonomous response decisions.
  Rules define conditions under which specific response actions
  can be taken automatically without analyst approval.

  Rule Structure:
  - conditions: IF clauses (alert severity, confidence, asset type, etc.)
  - actions: THEN clauses (kill process, quarantine, isolate, etc.)
  - constraints: Rate limits, time windows, exclusions
  - auto_execute: Whether to execute immediately or queue for approval

  Example Rule:
  ```
  IF severity == "critical" AND confidence >= 95 AND asset_criticality IN [:low, :medium]
  THEN kill_process, quarantine_file
  WITH auto_execute = true, max_per_hour = 10
  ```
  """

  use GenServer
  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert

  # Rule execution modes
  @modes [:auto_execute, :require_approval, :notify_only, :disabled]

  # Condition operators
  @operators [:eq, :neq, :gt, :gte, :lt, :lte, :in, :not_in, :contains, :matches, :exists]

  # Available condition fields
  @condition_fields [
    :severity,
    :confidence_score,
    :asset_criticality,
    :asset_role,
    :alert_type,
    :mitre_tactic,
    :mitre_technique,
    :detection_source,
    :file_hash_known_bad,
    :is_business_hours,
    :agent_status,
    :previous_alerts_count,
    :user_privilege_level,
    :network_zone,
    :has_lateral_movement,
    :is_ransomware_indicator,
    :threat_score
  ]

  # Available response actions
  @available_actions [
    "kill_process",
    "quarantine_file",
    "block_ip",
    "block_domain",
    "isolate_network",
    "disable_user",
    "collect_forensics",
    "trigger_scan",
    "create_snapshot",
    "notify_analyst",
    "escalate_to_soc",
    "run_playbook"
  ]

  # GenServer state
  defstruct [
    :rules_cache,
    :execution_counts,
    :last_reload
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get all rules matching an alert's context.
  Returns rules sorted by priority (highest first).
  """
  @spec get_matching_rules(Alert.t(), String.t()) :: [map()]
  def get_matching_rules(%Alert{} = alert, org_id) do
    GenServer.call(__MODULE__, {:get_matching_rules, alert, org_id})
  end

  @doc """
  Create a new autonomous response rule.
  """
  @spec create_rule(map()) :: {:ok, map()} | {:error, term()}
  def create_rule(attrs) do
    GenServer.call(__MODULE__, {:create_rule, attrs})
  end

  @doc """
  Update an existing rule.
  """
  @spec update_rule(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def update_rule(rule_id, attrs) do
    GenServer.call(__MODULE__, {:update_rule, rule_id, attrs})
  end

  @doc """
  Delete a rule.
  """
  @spec delete_rule(String.t()) :: :ok | {:error, term()}
  def delete_rule(rule_id) do
    GenServer.call(__MODULE__, {:delete_rule, rule_id})
  end

  @doc """
  List all rules for an organization.
  """
  @spec list_rules(String.t(), keyword()) :: [map()]
  def list_rules(org_id, opts \\ []) do
    GenServer.call(__MODULE__, {:list_rules, org_id, opts})
  end

  @doc """
  Get a specific rule by ID.
  """
  @spec get_rule(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_rule(rule_id) do
    GenServer.call(__MODULE__, {:get_rule, rule_id})
  end

  @doc """
  Enable or disable a rule.
  """
  @spec set_rule_enabled(String.t(), boolean()) :: {:ok, map()} | {:error, term()}
  def set_rule_enabled(rule_id, enabled) do
    GenServer.call(__MODULE__, {:set_enabled, rule_id, enabled})
  end

  @doc """
  Test a rule against sample alert data without executing.
  """
  @spec test_rule(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def test_rule(rule_id, sample_alert_data) do
    GenServer.call(__MODULE__, {:test_rule, rule_id, sample_alert_data})
  end

  @doc """
  Get built-in rule templates.
  """
  @spec get_templates() :: [map()]
  def get_templates do
    GenServer.call(__MODULE__, :get_templates)
  end

  @doc """
  Clone a rule template to create a new rule.
  """
  @spec clone_template(String.t(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def clone_template(template_id, org_id, overrides \\ %{}) do
    GenServer.call(__MODULE__, {:clone_template, template_id, org_id, overrides})
  end

  @doc """
  Get rule execution statistics.
  """
  @spec get_rule_stats(String.t()) :: map()
  def get_rule_stats(rule_id) do
    GenServer.call(__MODULE__, {:get_stats, rule_id})
  end

  @doc """
  Reload rules from database.
  """
  @spec reload_rules() :: :ok
  def reload_rules do
    GenServer.cast(__MODULE__, :reload)
  end

  @doc """
  Get available condition fields and operators.
  """
  @spec get_schema() :: map()
  def get_schema do
    %{
      condition_fields: @condition_fields,
      operators: @operators,
      available_actions: @available_actions,
      modes: @modes
    }
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting Autonomous Rules Engine")

    state = %__MODULE__{
      rules_cache: %{},
      execution_counts: %{},
      last_reload: nil
    }

    # Load rules asynchronously
    send(self(), :load_rules)

    {:ok, state}
  end

  @impl true
  def handle_call({:get_matching_rules, alert, org_id}, _from, state) do
    rules = state.rules_cache
    |> Map.get(org_id, [])
    |> Enum.filter(fn rule ->
      rule.enabled and evaluate_conditions(rule.conditions, alert)
    end)
    |> Enum.sort_by(& &1.priority, :desc)

    {:reply, rules, state}
  end

  @impl true
  def handle_call({:create_rule, attrs}, _from, state) do
    case validate_rule(attrs) do
      :ok ->
        rule = build_rule(attrs)
        case save_rule(rule) do
          {:ok, saved_rule} ->
            # Update cache
            org_id = saved_rule.organization_id
            org_rules = Map.get(state.rules_cache, org_id, [])
            new_cache = Map.put(state.rules_cache, org_id, [saved_rule | org_rules])

            {:reply, {:ok, saved_rule}, %{state | rules_cache: new_cache}}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:update_rule, rule_id, attrs}, _from, state) do
    case get_rule_from_db(rule_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      existing_rule ->
        merged = Map.merge(existing_rule, attrs)
        case validate_rule(merged) do
          :ok ->
            case update_rule_in_db(rule_id, attrs) do
              {:ok, updated_rule} ->
                # Update cache
                org_id = updated_rule.organization_id
                org_rules = Map.get(state.rules_cache, org_id, [])
                updated_org_rules = Enum.map(org_rules, fn r ->
                  if r.id == rule_id, do: updated_rule, else: r
                end)
                new_cache = Map.put(state.rules_cache, org_id, updated_org_rules)

                {:reply, {:ok, updated_rule}, %{state | rules_cache: new_cache}}

              {:error, reason} ->
                {:reply, {:error, reason}, state}
            end

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call({:delete_rule, rule_id}, _from, state) do
    case delete_rule_from_db(rule_id) do
      {:ok, deleted_rule} ->
        # Update cache
        org_id = deleted_rule.organization_id
        org_rules = Map.get(state.rules_cache, org_id, [])
        updated_org_rules = Enum.reject(org_rules, fn r -> r.id == rule_id end)
        new_cache = Map.put(state.rules_cache, org_id, updated_org_rules)

        {:reply, :ok, %{state | rules_cache: new_cache}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:list_rules, org_id, opts}, _from, state) do
    rules = Map.get(state.rules_cache, org_id, [])

    filtered = cond do
      Keyword.get(opts, :enabled_only, false) ->
        Enum.filter(rules, & &1.enabled)

      Keyword.get(opts, :auto_execute_only, false) ->
        Enum.filter(rules, & &1.auto_execute)

      true ->
        rules
    end

    sorted = Enum.sort_by(filtered, & &1.priority, :desc)

    {:reply, sorted, state}
  end

  @impl true
  def handle_call({:get_rule, rule_id}, _from, state) do
    # Search in all org caches
    result = state.rules_cache
    |> Map.values()
    |> List.flatten()
    |> Enum.find(fn r -> r.id == rule_id end)

    if result do
      {:reply, {:ok, result}, state}
    else
      {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:set_enabled, rule_id, enabled}, _from, state) do
    case update_rule_in_db(rule_id, %{enabled: enabled}) do
      {:ok, updated_rule} ->
        # Update cache
        org_id = updated_rule.organization_id
        org_rules = Map.get(state.rules_cache, org_id, [])
        updated_org_rules = Enum.map(org_rules, fn r ->
          if r.id == rule_id, do: %{r | enabled: enabled}, else: r
        end)
        new_cache = Map.put(state.rules_cache, org_id, updated_org_rules)

        {:reply, {:ok, updated_rule}, %{state | rules_cache: new_cache}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:test_rule, rule_id, sample_data}, _from, state) do
    case get_rule_from_cache(state.rules_cache, rule_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      rule ->
        sample_alert = struct(Alert, Map.merge(%{id: "test", agent_id: "test"}, sample_data))
        matches = evaluate_conditions(rule.conditions, sample_alert)

        result = %{
          rule_id: rule_id,
          rule_name: rule.name,
          matches: matches,
          would_execute: matches and rule.auto_execute,
          actions: if(matches, do: rule.actions, else: []),
          simulated: true,
          dry_run: true,
          condition_results: evaluate_conditions_detailed(rule.conditions, sample_alert)
        }

        {:reply, {:ok, result}, state}
    end
  end

  @impl true
  def handle_call(:get_templates, _from, state) do
    {:reply, built_in_templates(), state}
  end

  @impl true
  def handle_call({:clone_template, template_id, org_id, overrides}, _from, state) do
    template = built_in_templates()
    |> Enum.find(fn t -> t.id == template_id end)

    if template do
      new_rule = template
      |> Map.drop([:id])
      |> Map.put(:organization_id, org_id)
      |> Map.put(:name, overrides[:name] || "#{template.name} (Copy)")
      |> Map.merge(overrides)

      case validate_rule(new_rule) do
        :ok ->
          rule = build_rule(new_rule)
          case save_rule(rule) do
            {:ok, saved_rule} ->
              org_rules = Map.get(state.rules_cache, org_id, [])
              new_cache = Map.put(state.rules_cache, org_id, [saved_rule | org_rules])
              {:reply, {:ok, saved_rule}, %{state | rules_cache: new_cache}}

            {:error, reason} ->
              {:reply, {:error, reason}, state}
          end

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    else
      {:reply, {:error, :template_not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_stats, rule_id}, _from, state) do
    stats = Map.get(state.execution_counts, rule_id, %{
      total_matches: 0,
      total_executions: 0,
      last_match: nil,
      last_execution: nil
    })

    {:reply, stats, state}
  end

  @impl true
  def handle_cast(:reload, state) do
    Logger.info("Reloading autonomous rules")
    new_cache = load_all_rules()
    {:noreply, %{state | rules_cache: new_cache, last_reload: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:load_rules, state) do
    Logger.debug("Loading autonomous rules from database")
    new_cache = load_all_rules()
    {:noreply, %{state | rules_cache: new_cache, last_reload: DateTime.utc_now()}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Rule Evaluation
  # ============================================================================

  defp evaluate_conditions(conditions, alert) when is_list(conditions) do
    Enum.all?(conditions, fn condition ->
      evaluate_single_condition(condition, alert)
    end)
  end

  defp evaluate_conditions(%{all: conditions}, alert) do
    Enum.all?(conditions, fn c -> evaluate_single_condition(c, alert) end)
  end

  defp evaluate_conditions(%{any: conditions}, alert) do
    Enum.any?(conditions, fn c -> evaluate_single_condition(c, alert) end)
  end

  defp evaluate_conditions(%{none: conditions}, alert) do
    not Enum.any?(conditions, fn c -> evaluate_single_condition(c, alert) end)
  end

  defp evaluate_conditions(_, _), do: false

  defp evaluate_single_condition(%{field: field, operator: op, value: value}, alert) do
    actual_value = get_alert_field(alert, field)
    apply_operator(op, actual_value, value)
  end

  defp evaluate_single_condition(%{"field" => field, "operator" => op, "value" => value}, alert) do
    actual_value = get_alert_field(alert, String.to_atom(field))
    apply_operator(String.to_atom(op), actual_value, value)
  end

  defp evaluate_single_condition(_, _), do: false

  defp evaluate_conditions_detailed(conditions, alert) when is_list(conditions) do
    Enum.map(conditions, fn condition ->
      result = evaluate_single_condition(condition, alert)
      Map.put(condition, :result, result)
    end)
  end

  defp evaluate_conditions_detailed(%{all: conditions}, alert) do
    %{
      type: :all,
      conditions: evaluate_conditions_detailed(conditions, alert)
    }
  end

  defp evaluate_conditions_detailed(conditions, alert), do: evaluate_conditions_detailed([conditions], alert)

  defp get_alert_field(alert, :severity), do: alert.severity
  defp get_alert_field(alert, :confidence_score), do: alert.threat_score || 50
  defp get_alert_field(alert, :alert_type), do: alert.source || "unknown"
  defp get_alert_field(alert, :agent_id), do: alert.agent_id
  defp get_alert_field(alert, :mitre_tactic), do: alert.mitre_tactics || []
  defp get_alert_field(alert, :mitre_technique), do: alert.mitre_techniques || []
  defp get_alert_field(alert, :threat_score), do: alert.threat_score || 0
  defp get_alert_field(alert, :is_ransomware_indicator) do
    techniques = alert.mitre_techniques || []
    Enum.any?(techniques, fn t -> t in ["T1486", "T1490", "T1491"] end)
  end
  defp get_alert_field(_alert, :is_business_hours) do
    now = DateTime.utc_now()
    hour = now.hour
    day = Date.day_of_week(DateTime.to_date(now))
    # Business hours: Mon-Fri 9am-5pm UTC (adjust as needed)
    day in 1..5 and hour in 9..17
  end
  defp get_alert_field(alert, field) do
    # Try to get from detection_metadata or raw_event
    cond do
      is_map(alert.detection_metadata) and Map.has_key?(alert.detection_metadata, field) ->
        Map.get(alert.detection_metadata, field)

      is_map(alert.raw_event) and Map.has_key?(alert.raw_event, field) ->
        Map.get(alert.raw_event, field)

      true ->
        nil
    end
  end

  defp apply_operator(:eq, actual, expected), do: actual == expected
  defp apply_operator(:neq, actual, expected), do: actual != expected
  defp apply_operator(:gt, actual, expected) when is_number(actual), do: actual > expected
  defp apply_operator(:gte, actual, expected) when is_number(actual), do: actual >= expected
  defp apply_operator(:lt, actual, expected) when is_number(actual), do: actual < expected
  defp apply_operator(:lte, actual, expected) when is_number(actual), do: actual <= expected
  defp apply_operator(:in, actual, expected) when is_list(expected), do: actual in expected
  defp apply_operator(:not_in, actual, expected) when is_list(expected), do: actual not in expected
  defp apply_operator(:contains, actual, expected) when is_list(actual), do: expected in actual
  defp apply_operator(:contains, actual, expected) when is_binary(actual), do: String.contains?(actual, expected)
  defp apply_operator(:matches, actual, expected) when is_binary(actual) do
    case Regex.compile(expected) do
      {:ok, regex} -> Regex.match?(regex, actual)
      _ -> false
    end
  end
  defp apply_operator(:exists, actual, true), do: actual != nil
  defp apply_operator(:exists, actual, false), do: actual == nil
  defp apply_operator(_, _, _), do: false

  # ============================================================================
  # Private Functions - Rule Management
  # ============================================================================

  defp validate_rule(attrs) do
    cond do
      not Map.has_key?(attrs, :name) or attrs[:name] == "" ->
        {:error, "Rule name is required"}

      not Map.has_key?(attrs, :conditions) or attrs[:conditions] == [] ->
        {:error, "At least one condition is required"}

      not Map.has_key?(attrs, :actions) or attrs[:actions] == [] ->
        {:error, "At least one action is required"}

      not valid_actions?(attrs[:actions]) ->
        {:error, "Invalid action type specified"}

      true ->
        :ok
    end
  end

  defp valid_actions?(actions) when is_list(actions) do
    Enum.all?(actions, fn action ->
      action_type = action[:type] || action["type"]
      action_type in @available_actions
    end)
  end

  defp valid_actions?(_), do: false

  defp build_rule(attrs) do
    %{
      id: Ecto.UUID.generate(),
      name: attrs[:name] || attrs["name"],
      description: attrs[:description] || attrs["description"],
      organization_id: attrs[:organization_id] || attrs["organization_id"],
      conditions: normalize_conditions(attrs[:conditions] || attrs["conditions"]),
      actions: normalize_actions(attrs[:actions] || attrs["actions"]),
      priority: attrs[:priority] || attrs["priority"] || 50,
      enabled: Map.get(attrs, :enabled, Map.get(attrs, "enabled", true)),
      auto_execute: Map.get(attrs, :auto_execute, Map.get(attrs, "auto_execute", false)),
      mode: attrs[:mode] || attrs["mode"] || :require_approval,
      constraints: attrs[:constraints] || attrs["constraints"] || %{},
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }
  end

  defp normalize_conditions(conditions) when is_list(conditions) do
    Enum.map(conditions, &normalize_condition/1)
  end

  defp normalize_conditions(conditions) when is_map(conditions) do
    cond do
      Map.has_key?(conditions, :all) or Map.has_key?(conditions, "all") ->
        all = conditions[:all] || conditions["all"]
        %{all: Enum.map(all, &normalize_condition/1)}

      Map.has_key?(conditions, :any) or Map.has_key?(conditions, "any") ->
        any = conditions[:any] || conditions["any"]
        %{any: Enum.map(any, &normalize_condition/1)}

      Map.has_key?(conditions, :none) or Map.has_key?(conditions, "none") ->
        none = conditions[:none] || conditions["none"]
        %{none: Enum.map(none, &normalize_condition/1)}

      true ->
        [normalize_condition(conditions)]
    end
  end

  defp normalize_condition(%{} = condition) do
    %{
      field: condition[:field] || condition["field"] |> to_atom_safe(),
      operator: condition[:operator] || condition["operator"] |> to_atom_safe(),
      value: condition[:value] || condition["value"]
    }
  end

  defp normalize_actions(actions) when is_list(actions) do
    Enum.map(actions, &normalize_action/1)
  end

  defp normalize_action(action) when is_map(action) do
    %{
      type: action[:type] || action["type"],
      params: action[:params] || action["params"] || %{}
    }
  end

  defp normalize_action(action) when is_binary(action) do
    %{type: action, params: %{}}
  end

  defp to_atom_safe(value) when is_atom(value), do: value
  defp to_atom_safe(value) when is_binary(value), do: String.to_atom(value)
  defp to_atom_safe(_), do: nil

  # ============================================================================
  # Private Functions - Database Operations
  # ============================================================================

  defp load_all_rules do
    try do
      query = from(r in "autonomous_rules",
        where: r.enabled == true,
        select: %{
          id: r.id,
          name: r.name,
          description: r.description,
          organization_id: r.organization_id,
          conditions: r.conditions,
          actions: r.actions,
          priority: r.priority,
          enabled: r.enabled,
          auto_execute: r.auto_execute,
          mode: r.mode,
          constraints: r.constraints,
          inserted_at: r.inserted_at,
          updated_at: r.updated_at
        }
      )

      Repo.all(query)
      |> Enum.group_by(& &1.organization_id)
    rescue
      e ->
        Logger.warning("Failed to load autonomous rules: #{inspect(e)}")
        %{}
    end
  end

  defp get_rule_from_db(rule_id) do
    try do
      query = from(r in "autonomous_rules",
        where: r.id == ^rule_id,
        select: %{
          id: r.id,
          name: r.name,
          description: r.description,
          organization_id: r.organization_id,
          conditions: r.conditions,
          actions: r.actions,
          priority: r.priority,
          enabled: r.enabled,
          auto_execute: r.auto_execute,
          mode: r.mode,
          constraints: r.constraints
        }
      )

      Repo.one(query)
    rescue
      _ -> nil
    end
  end

  defp get_rule_from_cache(cache, rule_id) do
    cache
    |> Map.values()
    |> List.flatten()
    |> Enum.find(fn r -> r.id == rule_id end)
  end

  defp save_rule(rule) do
    try do
      Repo.insert_all("autonomous_rules", [%{
        id: rule.id,
        name: rule.name,
        description: rule.description,
        organization_id: rule.organization_id,
        conditions: rule.conditions,
        actions: rule.actions,
        priority: rule.priority,
        enabled: rule.enabled,
        auto_execute: rule.auto_execute,
        mode: to_string(rule.mode),
        constraints: rule.constraints,
        updated_at: rule.updated_at || DateTime.utc_now(),
        inserted_at: DateTime.utc_now()
      }])

      {:ok, rule}
    rescue
      e ->
        Logger.error("Failed to save rule: #{inspect(e)}")
        {:error, "Failed to save rule"}
    end
  end

  defp update_rule_in_db(rule_id, attrs) do
    try do
      updates = attrs
      |> Map.put(:updated_at, DateTime.utc_now())
      |> Enum.map(fn {k, v} -> {k, v} end)

      Repo.update_all(
        from(r in "autonomous_rules", where: r.id == ^rule_id),
        set: updates
      )

      {:ok, get_rule_from_db(rule_id)}
    rescue
      e ->
        Logger.error("Failed to update rule: #{inspect(e)}")
        {:error, "Failed to update rule"}
    end
  end

  defp delete_rule_from_db(rule_id) do
    try do
      rule = get_rule_from_db(rule_id)
      if rule do
        Repo.delete_all(from(r in "autonomous_rules", where: r.id == ^rule_id))
        {:ok, rule}
      else
        {:error, :not_found}
      end
    rescue
      e ->
        Logger.error("Failed to delete rule: #{inspect(e)}")
        {:error, "Failed to delete rule"}
    end
  end

  # ============================================================================
  # Built-in Rule Templates
  # ============================================================================

  defp built_in_templates do
    [
      %{
        id: "template-critical-ransomware",
        name: "Critical Ransomware Auto-Isolate",
        description: "Automatically isolate endpoints showing ransomware indicators with critical severity",
        conditions: [
          %{field: :severity, operator: :eq, value: "critical"},
          %{field: :is_ransomware_indicator, operator: :eq, value: true}
        ],
        actions: [
          %{type: "isolate_network", params: %{allowed_ips: ["10.0.0.1"]}},
          %{type: "create_snapshot", params: %{volume: "C:"}},
          %{type: "collect_forensics", params: %{}}
        ],
        priority: 100,
        auto_execute: true,
        mode: :auto_execute,
        constraints: %{max_per_hour: 5}
      },
      %{
        id: "template-high-confidence-malware",
        name: "High Confidence Malware Quarantine",
        description: "Quarantine files detected as malware with 95%+ confidence",
        conditions: [
          %{field: :confidence_score, operator: :gte, value: 95},
          %{field: :alert_type, operator: :eq, value: "ml_detection"}
        ],
        actions: [
          %{type: "quarantine_file", params: %{}},
          %{type: "kill_process", params: %{}}
        ],
        priority: 90,
        auto_execute: true,
        mode: :auto_execute,
        constraints: %{max_per_hour: 20}
      },
      %{
        id: "template-lateral-movement",
        name: "Lateral Movement Detection Response",
        description: "Respond to detected lateral movement attempts",
        conditions: [
          %{field: :severity, operator: :in, value: ["critical", "high"]},
          %{field: :has_lateral_movement, operator: :eq, value: true}
        ],
        actions: [
          %{type: "block_ip", params: %{}},
          %{type: "notify_analyst", params: %{urgency: "high"}},
          %{type: "collect_forensics", params: %{}}
        ],
        priority: 85,
        auto_execute: false,
        mode: :require_approval,
        constraints: %{}
      },
      %{
        id: "template-c2-communication",
        name: "C2 Communication Blocking",
        description: "Block known C2 communications immediately",
        conditions: [
          %{field: :mitre_technique, operator: :contains, value: "T1071"},
          %{field: :threat_score, operator: :gte, value: 80}
        ],
        actions: [
          %{type: "block_domain", params: %{}},
          %{type: "block_ip", params: %{}},
          %{type: "kill_process", params: %{}}
        ],
        priority: 95,
        auto_execute: true,
        mode: :auto_execute,
        constraints: %{max_per_minute: 10}
      },
      %{
        id: "template-off-hours-critical",
        name: "Off-Hours Critical Alert Auto-Response",
        description: "Automatically respond to critical alerts outside business hours",
        conditions: [
          %{field: :severity, operator: :eq, value: "critical"},
          %{field: :is_business_hours, operator: :eq, value: false}
        ],
        actions: [
          %{type: "isolate_network", params: %{}},
          %{type: "escalate_to_soc", params: %{urgency: "critical"}}
        ],
        priority: 80,
        auto_execute: true,
        mode: :auto_execute,
        constraints: %{max_per_hour: 10}
      },
      %{
        id: "template-credential-theft",
        name: "Credential Theft Response",
        description: "Respond to credential theft attempts (LSASS access, etc.)",
        conditions: [
          %{field: :mitre_technique, operator: :contains, value: "T1003"}
        ],
        actions: [
          %{type: "kill_process", params: %{force: true}},
          %{type: "collect_forensics", params: %{type: "memory"}},
          %{type: "disable_user", params: %{}}
        ],
        priority: 92,
        auto_execute: false,
        mode: :require_approval,
        constraints: %{}
      }
    ]
  end
end
