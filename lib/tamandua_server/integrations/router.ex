defmodule TamanduaServer.Integrations.Router do
  @moduledoc """
  Alert Routing Engine

  Routes alerts to different integrations based on configurable rules:
  - Severity-based routing
  - Alert type/category routing
  - Agent group/organization routing
  - Custom condition matching
  - Fan-out to multiple destinations

  ## Example Rules

      %{
        name: "Critical to PagerDuty",
        conditions: [
          %{field: "severity", operator: "eq", value: "critical"}
        ],
        destinations: [:pagerduty, :slack],
        enabled: true
      }

  """

  use GenServer
  require Logger

  alias TamanduaServer.Integrations.Config, as: IntegrationConfig

  defstruct [
    :rules,
    :integrations,
    :stats
  ]

  defmodule Rule do
    @moduledoc "Routing rule structure"
    defstruct [
      :id,
      :name,
      :description,
      :conditions,
      :destinations,
      :transform,
      :enabled,
      :priority,
      :organization_id
    ]
  end

  defmodule Condition do
    @moduledoc "Rule condition structure"
    defstruct [
      :field,
      :operator,
      :value
    ]
  end

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Route an alert to matching integrations.
  """
  @spec route_alert(map()) :: {:ok, [String.t()]} | {:error, term()}
  def route_alert(alert) do
    GenServer.call(__MODULE__, {:route_alert, alert}, 60_000)
  end

  @doc """
  Route multiple alerts.
  """
  @spec route_alerts([map()]) :: {:ok, map()} | {:error, term()}
  def route_alerts(alerts) do
    GenServer.call(__MODULE__, {:route_alerts, alerts}, 120_000)
  end

  @doc """
  Add a routing rule.
  """
  @spec add_rule(map()) :: {:ok, Rule.t()} | {:error, term()}
  def add_rule(rule_config) do
    GenServer.call(__MODULE__, {:add_rule, rule_config})
  end

  @doc """
  Update a routing rule.
  """
  @spec update_rule(String.t(), map()) :: {:ok, Rule.t()} | {:error, term()}
  def update_rule(rule_id, updates) do
    GenServer.call(__MODULE__, {:update_rule, rule_id, updates})
  end

  @doc """
  Remove a routing rule.
  """
  @spec remove_rule(String.t()) :: :ok | {:error, term()}
  def remove_rule(rule_id) do
    GenServer.call(__MODULE__, {:remove_rule, rule_id})
  end

  @doc """
  List all routing rules.
  """
  @spec list_rules(keyword()) :: {:ok, [Rule.t()]}
  def list_rules(opts \\ []) do
    GenServer.call(__MODULE__, {:list_rules, opts})
  end

  @doc """
  Test routing for an alert (dry run).
  """
  @spec test_routing(map()) :: {:ok, [String.t()]}
  def test_routing(alert) do
    GenServer.call(__MODULE__, {:test_routing, alert})
  end

  @doc """
  Reload routing rules from database.
  """
  @spec reload_rules() :: :ok
  def reload_rules do
    GenServer.cast(__MODULE__, :reload_rules)
  end

  @doc """
  Get routing statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Integration Router")

    rules = load_rules(opts)
    integrations = load_integrations()

    state = %__MODULE__{
      rules: rules,
      integrations: integrations,
      stats: %{
        alerts_routed: 0,
        rules_matched: 0,
        destinations_triggered: 0,
        errors: 0,
        by_destination: %{},
        by_rule: %{},
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:route_alert, alert}, _from, state) do
    {destinations, matched_rules} = evaluate_rules(alert, state.rules)

    if length(destinations) > 0 do
      results = send_to_destinations(alert, destinations, state)

      new_stats = update_routing_stats(state.stats, matched_rules, results)

      {:reply, {:ok, Enum.map(results, fn {dest, _} -> dest end)}, %{state | stats: new_stats}}
    else
      {:reply, {:ok, []}, state}
    end
  end

  @impl true
  def handle_call({:route_alerts, alerts}, _from, state) do
    results = Enum.map(alerts, fn alert ->
      {destinations, _matched_rules} = evaluate_rules(alert, state.rules)

      if length(destinations) > 0 do
        send_results = send_to_destinations(alert, destinations, state)
        {alert[:id] || alert["id"], destinations, send_results}
      else
        {alert[:id] || alert["id"], [], []}
      end
    end)

    summary = %{
      total: length(alerts),
      routed: Enum.count(results, fn {_, dests, _} -> length(dests) > 0 end),
      destinations: results |> Enum.flat_map(fn {_, dests, _} -> dests end) |> Enum.uniq() |> length()
    }

    {:reply, {:ok, summary}, state}
  end

  @impl true
  def handle_call({:add_rule, rule_config}, _from, state) do
    rule = build_rule(rule_config)
    new_rules = Map.put(state.rules, rule.id, rule)

    {:reply, {:ok, rule}, %{state | rules: new_rules}}
  end

  @impl true
  def handle_call({:update_rule, rule_id, updates}, _from, state) do
    case Map.get(state.rules, rule_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      existing ->
        updated = merge_rule(existing, updates)
        new_rules = Map.put(state.rules, rule_id, updated)
        {:reply, {:ok, updated}, %{state | rules: new_rules}}
    end
  end

  @impl true
  def handle_call({:remove_rule, rule_id}, _from, state) do
    new_rules = Map.delete(state.rules, rule_id)
    {:reply, :ok, %{state | rules: new_rules}}
  end

  @impl true
  def handle_call({:list_rules, opts}, _from, state) do
    rules = state.rules
    |> Map.values()
    |> filter_rules(opts)
    |> Enum.sort_by(& &1.priority)

    {:reply, {:ok, rules}, state}
  end

  @impl true
  def handle_call({:test_routing, alert}, _from, state) do
    {destinations, matched_rules} = evaluate_rules(alert, state.rules)

    result = %{
      destinations: destinations,
      matched_rules: Enum.map(matched_rules, & &1.name)
    }

    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_cast(:reload_rules, state) do
    rules = load_rules([])
    integrations = load_integrations()
    {:noreply, %{state | rules: rules, integrations: integrations}}
  end

  # ============================================================================
  # Rule Evaluation
  # ============================================================================

  defp evaluate_rules(alert, rules) do
    matched = rules
    |> Map.values()
    |> Enum.filter(& &1.enabled)
    |> Enum.sort_by(& &1.priority)
    |> Enum.filter(&rule_matches?(&1, alert))

    destinations = matched
    |> Enum.flat_map(& &1.destinations)
    |> Enum.uniq()

    {destinations, matched}
  end

  defp rule_matches?(rule, alert) do
    Enum.all?(rule.conditions, &condition_matches?(&1, alert))
  end

  defp condition_matches?(%Condition{field: field, operator: op, value: expected}, alert) do
    actual = get_alert_field(alert, field)
    evaluate_operator(op, actual, expected)
  end

  defp condition_matches?(%{field: field, operator: op, value: expected}, alert) do
    actual = get_alert_field(alert, field)
    evaluate_operator(op, actual, expected)
  end

  defp get_alert_field(alert, field) when is_binary(field) do
    path = String.split(field, ".")

    Enum.reduce(path, alert, fn key, acc ->
      case acc do
        nil -> nil
        map when is_map(map) ->
          Map.get(map, key) || Map.get(map, String.to_atom(key))
        _ -> nil
      end
    end)
  end

  defp get_alert_field(alert, field) when is_atom(field) do
    get_alert_field(alert, to_string(field))
  end

  defp evaluate_operator("eq", actual, expected), do: actual == expected
  defp evaluate_operator("neq", actual, expected), do: actual != expected
  defp evaluate_operator("gt", actual, expected) when is_number(actual), do: actual > expected
  defp evaluate_operator("gte", actual, expected) when is_number(actual), do: actual >= expected
  defp evaluate_operator("lt", actual, expected) when is_number(actual), do: actual < expected
  defp evaluate_operator("lte", actual, expected) when is_number(actual), do: actual <= expected

  defp evaluate_operator("contains", actual, expected) when is_binary(actual) do
    String.contains?(actual, expected)
  end

  defp evaluate_operator("contains", actual, expected) when is_list(actual) do
    expected in actual
  end

  defp evaluate_operator("starts_with", actual, expected) when is_binary(actual) do
    String.starts_with?(actual, expected)
  end

  defp evaluate_operator("ends_with", actual, expected) when is_binary(actual) do
    String.ends_with?(actual, expected)
  end

  defp evaluate_operator("matches", actual, expected) when is_binary(actual) do
    case Regex.compile(expected) do
      {:ok, regex} -> Regex.match?(regex, actual)
      _ -> false
    end
  end

  defp evaluate_operator("in", actual, expected) when is_list(expected) do
    actual in expected
  end

  defp evaluate_operator("not_in", actual, expected) when is_list(expected) do
    actual not in expected
  end

  defp evaluate_operator("exists", actual, _) do
    actual != nil
  end

  defp evaluate_operator("not_exists", actual, _) do
    actual == nil
  end

  defp evaluate_operator(_, _, _), do: false

  # ============================================================================
  # Destination Dispatch
  # ============================================================================

  defp send_to_destinations(alert, destinations, state) do
    destinations
    |> Enum.map(fn dest ->
      result = send_to_destination(alert, dest, state)
      {dest, result}
    end)
  end

  defp send_to_destination(alert, destination, state) when is_atom(destination) do
    send_to_destination(alert, to_string(destination), state)
  end

  defp send_to_destination(alert, destination, state) do
    integration = Map.get(state.integrations, destination)

    if integration && integration.enabled do
      try do
        result = case integration.type do
          :splunk -> TamanduaServer.Integrations.Splunk.forward_alert(alert)
          :sentinel -> TamanduaServer.Integrations.Sentinel.forward_alert(alert)
          :elastic -> TamanduaServer.Integrations.Elastic.forward_alert(alert)
          :webhook -> TamanduaServer.Integrations.Webhook.send_alert(alert)
          :xsoar -> TamanduaServer.Integrations.SOAR.XSOAR.create_incident(alert)
          :swimlane -> TamanduaServer.Integrations.SOAR.Swimlane.create_incident(alert)
          :tines -> TamanduaServer.Integrations.SOAR.Tines.create_incident(alert)
          :servicenow -> TamanduaServer.Integrations.Ticketing.ServiceNow.create_incident(alert)
          :jira -> TamanduaServer.Integrations.Ticketing.Jira.create_issue(alert)
          :pagerduty -> TamanduaServer.Integrations.Ticketing.PagerDuty.trigger_incident(alert)
          _ -> {:error, :unknown_integration_type}
        end

        case result do
          {:error, {:not_configured, msg}} ->
            Logger.warning("Integration #{destination} not configured: #{msg}")
            result

          _ ->
            result
        end
      rescue
        e -> {:error, Exception.message(e)}
      end
    else
      {:error, :integration_not_found_or_disabled}
    end
  end

  # ============================================================================
  # Rule Management
  # ============================================================================

  defp load_rules(opts) do
    # Load from config
    config_rules = opts[:rules] || Application.get_env(:tamandua_server, :routing_rules, [])

    # Load from database if available
    db_rules = try do
      # Future: load from routing_rules table
      []
    rescue
      _ -> []
    end

    # Merge and convert to map
    (config_rules ++ db_rules ++ default_rules())
    |> Enum.map(&build_rule/1)
    |> Enum.into(%{}, fn r -> {r.id, r} end)
  end

  defp default_rules do
    [
      %{
        id: "critical_pagerduty",
        name: "Critical Alerts to PagerDuty",
        description: "Route critical severity alerts to PagerDuty",
        conditions: [
          %{field: "severity", operator: "eq", value: "critical"}
        ],
        destinations: [:pagerduty],
        enabled: true,
        priority: 1
      },
      %{
        id: "high_critical_siem",
        name: "High/Critical to SIEM",
        description: "Route high and critical alerts to configured SIEM",
        conditions: [
          %{field: "severity", operator: "in", value: ["high", "critical"]}
        ],
        destinations: [:splunk, :sentinel, :elastic],
        enabled: true,
        priority: 10
      },
      %{
        id: "all_alerts_webhook",
        name: "All Alerts to Webhook",
        description: "Send all alerts to configured webhooks",
        conditions: [],
        destinations: [:webhook],
        enabled: true,
        priority: 100
      }
    ]
  end

  defp build_rule(config) do
    %Rule{
      id: config[:id] || config["id"] || generate_id(),
      name: config[:name] || config["name"] || "Unnamed Rule",
      description: config[:description] || config["description"],
      conditions: build_conditions(config[:conditions] || config["conditions"] || []),
      destinations: normalize_destinations(config[:destinations] || config["destinations"] || []),
      transform: config[:transform] || config["transform"],
      enabled: config[:enabled] != false && config["enabled"] != false,
      priority: config[:priority] || config["priority"] || 50,
      organization_id: config[:organization_id] || config["organization_id"]
    }
  end

  defp build_conditions(conditions) do
    Enum.map(conditions, fn c ->
      %Condition{
        field: c[:field] || c["field"],
        operator: c[:operator] || c["operator"],
        value: c[:value] || c["value"]
      }
    end)
  end

  defp normalize_destinations(destinations) do
    Enum.map(destinations, fn
      d when is_atom(d) -> d
      d when is_binary(d) -> String.to_atom(d)
    end)
  end

  defp merge_rule(existing, updates) do
    updates_map = Enum.into(updates, %{})

    %{existing |
      name: updates_map[:name] || updates_map["name"] || existing.name,
      description: updates_map[:description] || updates_map["description"] || existing.description,
      conditions: if(Map.has_key?(updates_map, :conditions), do: build_conditions(updates_map[:conditions]), else: existing.conditions),
      destinations: if(Map.has_key?(updates_map, :destinations), do: normalize_destinations(updates_map[:destinations]), else: existing.destinations),
      enabled: if(Map.has_key?(updates_map, :enabled), do: updates_map[:enabled], else: existing.enabled),
      priority: updates_map[:priority] || updates_map["priority"] || existing.priority
    }
  end

  defp filter_rules(rules, opts) do
    rules
    |> maybe_filter_enabled(opts[:enabled])
    |> maybe_filter_org(opts[:organization_id])
  end

  defp maybe_filter_enabled(rules, nil), do: rules
  defp maybe_filter_enabled(rules, enabled), do: Enum.filter(rules, &(&1.enabled == enabled))

  defp maybe_filter_org(rules, nil), do: rules
  defp maybe_filter_org(rules, org_id) do
    Enum.filter(rules, fn r -> r.organization_id == nil || r.organization_id == org_id end)
  end

  # ============================================================================
  # Integration Management
  # ============================================================================

  defp load_integrations do
    try do
      IntegrationConfig.list_integrations(enabled: true)
      |> Enum.into(%{}, fn i -> {to_string(i.type), i} end)
    rescue
      _ -> %{}
    end
  end

  # ============================================================================
  # Statistics
  # ============================================================================

  defp update_routing_stats(stats, matched_rules, results) do
    stats
    |> Map.update(:alerts_routed, 1, &(&1 + 1))
    |> Map.update(:rules_matched, length(matched_rules), &(&1 + length(matched_rules)))
    |> Map.update(:destinations_triggered, length(results), &(&1 + length(results)))
    |> update_destination_stats(results)
    |> update_rule_stats(matched_rules)
    |> Map.put(:last_activity, DateTime.utc_now())
  end

  defp update_destination_stats(stats, results) do
    new_by_dest = Enum.reduce(results, stats.by_destination, fn {dest, result}, acc ->
      key = to_string(dest)
      current = Map.get(acc, key, %{success: 0, failure: 0})

      updated = case result do
        :ok -> %{current | success: current.success + 1}
        {:ok, _} -> %{current | success: current.success + 1}
        _ -> %{current | failure: current.failure + 1}
      end

      Map.put(acc, key, updated)
    end)

    %{stats | by_destination: new_by_dest}
  end

  defp update_rule_stats(stats, matched_rules) do
    new_by_rule = Enum.reduce(matched_rules, stats.by_rule, fn rule, acc ->
      Map.update(acc, rule.id, 1, &(&1 + 1))
    end)

    %{stats | by_rule: new_by_rule}
  end

  defp generate_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end
end
