defmodule TamanduaServer.ASM.Monitor do
  @moduledoc """
  Attack Surface Management - Change Monitoring Module

  Monitors the attack surface for changes and generates alerts:

  - New asset detection (subdomains, IPs, cloud resources)
  - Configuration changes (new ports, services, TLS changes)
  - Exposure changes (new vulnerabilities, expired certificates)
  - Risk level changes (threshold crossing)
  - Certificate transparency alerts
  - Historical change tracking

  Provides real-time notifications and change reports.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.ASM.{Discovery, Exposure, RiskScoring}

  # Change event types
  @change_types [
    :asset_discovered,
    :asset_removed,
    :asset_updated,
    :port_opened,
    :port_closed,
    :service_changed,
    :tls_changed,
    :certificate_expiring,
    :certificate_expired,
    :vulnerability_found,
    :vulnerability_remediated,
    :risk_increased,
    :risk_decreased,
    :exposure_added,
    :exposure_removed
  ]

  # Alert severity mapping for change types
  @change_severity %{
    asset_discovered: :info,
    asset_removed: :low,
    asset_updated: :info,
    port_opened: :medium,
    port_closed: :info,
    service_changed: :low,
    tls_changed: :medium,
    certificate_expiring: :high,
    certificate_expired: :critical,
    vulnerability_found: :high,
    vulnerability_remediated: :info,
    risk_increased: :medium,
    risk_decreased: :info,
    exposure_added: :high,
    exposure_removed: :info
  }

  # State structure
  defstruct [
    :change_log,           # ETS table for change history
    :subscriptions,        # Change event subscriptions
    :alert_rules,          # Rules for generating alerts
    :config,               # Configuration
    :stats                 # Statistics
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Notify of a discovery event.
  """
  @spec notify_discovery(atom(), String.t(), list()) :: :ok
  def notify_discovery(discovery_type, target, results) do
    GenServer.cast(__MODULE__, {:discovery_event, discovery_type, target, results})
  end

  @doc """
  Notify of a change event.
  """
  @spec notify_change(atom(), map(), map() | nil) :: :ok
  def notify_change(change_type, current, previous) do
    GenServer.cast(__MODULE__, {:change_event, change_type, current, previous})
  end

  @doc """
  Notify of a risk threshold crossing.
  """
  @spec notify_risk_threshold(atom(), String.t(), map()) :: :ok
  def notify_risk_threshold(severity, asset_id, risk_data) do
    GenServer.cast(__MODULE__, {:risk_threshold, severity, asset_id, risk_data})
  end

  @doc """
  Get recent changes with optional filters.
  """
  @spec get_changes(keyword()) :: [map()]
  def get_changes(opts \\ []) do
    GenServer.call(__MODULE__, {:get_changes, opts})
  end

  @doc """
  Get changes for a specific asset.
  """
  @spec get_asset_changes(String.t(), keyword()) :: [map()]
  def get_asset_changes(asset_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_asset_changes, asset_id, opts})
  end

  @doc """
  Get change summary/statistics.
  """
  @spec get_change_summary(keyword()) :: map()
  def get_change_summary(opts \\ []) do
    GenServer.call(__MODULE__, {:get_change_summary, opts})
  end

  @doc """
  Subscribe to change events.
  """
  @spec subscribe(atom(), function()) :: {:ok, String.t()}
  def subscribe(change_type, callback) do
    GenServer.call(__MODULE__, {:subscribe, change_type, callback})
  end

  @doc """
  Unsubscribe from change events.
  """
  @spec unsubscribe(String.t()) :: :ok
  def unsubscribe(subscription_id) do
    GenServer.call(__MODULE__, {:unsubscribe, subscription_id})
  end

  @doc """
  Add an alert rule.
  """
  @spec add_alert_rule(map()) :: {:ok, String.t()} | {:error, term()}
  def add_alert_rule(rule) do
    GenServer.call(__MODULE__, {:add_alert_rule, rule})
  end

  @doc """
  Remove an alert rule.
  """
  @spec remove_alert_rule(String.t()) :: :ok
  def remove_alert_rule(rule_id) do
    GenServer.call(__MODULE__, {:remove_alert_rule, rule_id})
  end

  @doc """
  List alert rules.
  """
  @spec list_alert_rules() :: [map()]
  def list_alert_rules do
    GenServer.call(__MODULE__, :list_alert_rules)
  end

  @doc """
  Get monitoring statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Generate a change report.
  """
  @spec generate_report(keyword()) :: {:ok, map()}
  def generate_report(opts \\ []) do
    GenServer.call(__MODULE__, {:generate_report, opts})
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Attack Surface Management - Change Monitor Service")

    # Create ETS table for change log
    change_table = :ets.new(:asm_changes, [:named_table, :ordered_set, :public])

    state = %__MODULE__{
      change_log: change_table,
      subscriptions: %{},
      alert_rules: default_alert_rules(),
      config: build_config(opts),
      stats: initial_stats()
    }

    # Schedule periodic cleanup
    schedule_cleanup()

    {:ok, state}
  end

  @impl true
  def handle_cast({:discovery_event, discovery_type, target, results}, state) do
    timestamp = System.system_time(:millisecond)

    # Process each discovered item
    new_items = Enum.filter(results, fn item ->
      is_new_asset?(item, discovery_type)
    end)

    # Log discovery event
    if length(new_items) > 0 do
      change = %{
        id: generate_change_id(),
        type: :asset_discovered,
        discovery_type: discovery_type,
        target: target,
        items: new_items,
        count: length(new_items),
        timestamp: timestamp,
        detected_at: DateTime.utc_now()
      }

      :ets.insert(state.change_log, {timestamp, change})

      # Trigger notifications
      notify_subscribers(state.subscriptions, :asset_discovered, change)

      # Check alert rules
      check_alert_rules(state.alert_rules, change)

      # Broadcast via PubSub
      broadcast_change(change)

      Logger.info("ASM: Discovered #{length(new_items)} new assets from #{discovery_type} for #{target}")
    end

    new_stats = Map.update(state.stats, :discoveries_processed, 1, & &1 + 1)
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:change_event, change_type, current, previous}, state) do
    timestamp = System.system_time(:millisecond)

    # Build change record
    change = %{
      id: generate_change_id(),
      type: change_type,
      current: current,
      previous: previous,
      asset_id: current[:id] || current[:asset_id],
      timestamp: timestamp,
      detected_at: DateTime.utc_now(),
      severity: Map.get(@change_severity, change_type, :info),
      diff: calculate_diff(change_type, current, previous)
    }

    :ets.insert(state.change_log, {timestamp, change})

    # Trigger notifications
    notify_subscribers(state.subscriptions, change_type, change)

    # Check alert rules
    check_alert_rules(state.alert_rules, change)

    # Broadcast via PubSub
    broadcast_change(change)

    # Create alert for significant changes
    if should_alert?(change_type, change) do
      create_asm_alert(change)
    end

    new_stats = Map.update(state.stats, :changes_detected, 1, & &1 + 1)
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:risk_threshold, severity, asset_id, risk_data}, state) do
    timestamp = System.system_time(:millisecond)

    change = %{
      id: generate_change_id(),
      type: :risk_threshold_crossed,
      severity: severity,
      asset_id: asset_id,
      risk_score: risk_data[:overall_score],
      risk_level: risk_data[:risk_level],
      factors: risk_data[:factors],
      timestamp: timestamp,
      detected_at: DateTime.utc_now()
    }

    :ets.insert(state.change_log, {timestamp, change})

    # Notify and alert
    notify_subscribers(state.subscriptions, :risk_increased, change)
    check_alert_rules(state.alert_rules, change)
    broadcast_change(change)

    # Always create alert for risk threshold crossings
    create_asm_alert(change)

    Logger.warning("ASM: Risk threshold crossed for asset #{asset_id} - #{severity} (score: #{risk_data[:overall_score]})")

    new_stats = Map.update(state.stats, :risk_alerts, 1, & &1 + 1)
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_changes, opts}, _from, state) do
    changes = get_all_changes(state.change_log)

    filtered = changes
    |> filter_by_change_type(opts[:type])
    |> filter_by_severity(opts[:severity])
    |> filter_by_time_range(opts[:from], opts[:to])
    |> maybe_limit(opts[:limit])

    {:reply, filtered, state}
  end

  @impl true
  def handle_call({:get_asset_changes, asset_id, opts}, _from, state) do
    changes = get_all_changes(state.change_log)
    |> Enum.filter(fn c -> c[:asset_id] == asset_id end)
    |> filter_by_time_range(opts[:from], opts[:to])
    |> maybe_limit(opts[:limit])

    {:reply, changes, state}
  end

  @impl true
  def handle_call({:get_change_summary, opts}, _from, state) do
    days = opts[:days] || 7
    cutoff = DateTime.add(DateTime.utc_now(), -days, :day)
    cutoff_ms = DateTime.to_unix(cutoff, :millisecond)

    changes = :ets.select(state.change_log, [{{:"$1", :"$2"}, [{:>=, :"$1", cutoff_ms}], [:"$2"]}])

    summary = %{
      period_days: days,
      total_changes: length(changes),
      by_type: Enum.group_by(changes, & &1[:type]) |> Enum.map(fn {k, v} -> {k, length(v)} end) |> Map.new(),
      by_severity: Enum.group_by(changes, & &1[:severity]) |> Enum.map(fn {k, v} -> {k, length(v)} end) |> Map.new(),
      new_assets: Enum.count(changes, & &1[:type] == :asset_discovered),
      risk_alerts: Enum.count(changes, & &1[:type] == :risk_threshold_crossed),
      vulnerabilities_found: Enum.count(changes, & &1[:type] == :vulnerability_found),
      daily_breakdown: calculate_daily_breakdown(changes, days)
    }

    {:reply, summary, state}
  end

  @impl true
  def handle_call({:subscribe, change_type, callback}, _from, state) do
    subscription_id = generate_subscription_id()

    subscription = %{
      id: subscription_id,
      change_type: change_type,
      callback: callback,
      created_at: DateTime.utc_now()
    }

    new_subscriptions = Map.put(state.subscriptions, subscription_id, subscription)
    {:reply, {:ok, subscription_id}, %{state | subscriptions: new_subscriptions}}
  end

  @impl true
  def handle_call({:unsubscribe, subscription_id}, _from, state) do
    new_subscriptions = Map.delete(state.subscriptions, subscription_id)
    {:reply, :ok, %{state | subscriptions: new_subscriptions}}
  end

  @impl true
  def handle_call({:add_alert_rule, rule}, _from, state) do
    rule_id = generate_rule_id()

    validated_rule = %{
      id: rule_id,
      name: rule[:name] || "Custom Rule",
      change_types: rule[:change_types] || [:all],
      conditions: rule[:conditions] || [],
      severity_override: rule[:severity],
      enabled: Map.get(rule, :enabled, true),
      created_at: DateTime.utc_now()
    }

    new_rules = Map.put(state.alert_rules, rule_id, validated_rule)
    {:reply, {:ok, rule_id}, %{state | alert_rules: new_rules}}
  end

  @impl true
  def handle_call({:remove_alert_rule, rule_id}, _from, state) do
    new_rules = Map.delete(state.alert_rules, rule_id)
    {:reply, :ok, %{state | alert_rules: new_rules}}
  end

  @impl true
  def handle_call(:list_alert_rules, _from, state) do
    rules = Map.values(state.alert_rules)
    {:reply, rules, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    changes = get_all_changes(state.change_log)

    stats = Map.merge(state.stats, %{
      total_changes_logged: length(changes),
      active_subscriptions: map_size(state.subscriptions),
      active_alert_rules: map_size(state.alert_rules)
    })

    {:reply, stats, state}
  end

  @impl true
  def handle_call({:generate_report, opts}, _from, state) do
    report = generate_change_report(state.change_log, opts)
    {:reply, {:ok, report}, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    retention_days = state.config.retention_days
    cutoff_ms = DateTime.utc_now()
    |> DateTime.add(-retention_days, :day)
    |> DateTime.to_unix(:millisecond)

    # Delete old entries
    :ets.select_delete(state.change_log, [{{:"$1", :_}, [{:<, :"$1", cutoff_ms}], [true]}])

    schedule_cleanup()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Change Detection Functions
  # ============================================================================

  defp is_new_asset?(item, :domain) do
    # Check if this subdomain/domain already exists
    case Discovery.get_asset(item) do
      {:ok, _} -> false
      {:error, :not_found} -> true
    end
  end

  defp is_new_asset?(item, :cloud) do
    case Discovery.get_asset(item[:id] || item) do
      {:ok, _} -> false
      {:error, :not_found} -> true
    end
  end

  defp is_new_asset?(_item, _type), do: true

  defp calculate_diff(:asset_updated, current, previous) when is_map(previous) do
    # Calculate what changed between previous and current
    %{
      ip_changes: diff_lists(current[:ip_addresses], previous[:ip_addresses]),
      port_changes: diff_lists(current[:ports], previous[:ports]),
      service_changes: diff_lists(current[:services], previous[:services]),
      risk_change: (current[:risk_score] || 0) - (previous[:risk_score] || 0)
    }
  end

  defp calculate_diff(:port_opened, current, _previous) do
    %{
      port: current[:port],
      service: current[:service],
      risk: current[:risk]
    }
  end

  defp calculate_diff(:vulnerability_found, current, _previous) do
    %{
      cve_id: current[:cve_id],
      cvss: current[:cvss_score],
      severity: current[:severity]
    }
  end

  defp calculate_diff(_type, _current, _previous), do: %{}

  defp diff_lists(current, previous) when is_list(current) and is_list(previous) do
    %{
      added: current -- previous,
      removed: previous -- current
    }
  end
  defp diff_lists(_, _), do: %{added: [], removed: []}

  # ============================================================================
  # Notification Functions
  # ============================================================================

  defp notify_subscribers(subscriptions, change_type, change) do
    subscriptions
    |> Enum.filter(fn {_id, sub} ->
      sub.change_type == :all or sub.change_type == change_type
    end)
    |> Enum.each(fn {_id, sub} ->
      try do
        sub.callback.(change)
      catch
        _, _ -> Logger.error("Error in change subscription callback")
      end
    end)
  end

  defp broadcast_change(change) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "asm:changes",
      {:asm_change, change}
    )
  end

  defp check_alert_rules(rules, change) do
    rules
    |> Enum.filter(fn {_id, rule} -> rule.enabled end)
    |> Enum.filter(fn {_id, rule} ->
      :all in rule.change_types or change.type in rule.change_types
    end)
    |> Enum.each(fn {_id, rule} ->
      if evaluate_conditions(rule.conditions, change) do
        create_rule_alert(rule, change)
      end
    end)
  end

  defp evaluate_conditions([], _change), do: true
  defp evaluate_conditions(conditions, change) do
    Enum.all?(conditions, fn condition ->
      evaluate_condition(condition, change)
    end)
  end

  defp evaluate_condition({:severity, :gte, level}, change) do
    severity_level(change.severity) >= severity_level(level)
  end

  defp evaluate_condition({:count, :gte, count}, change) do
    (change[:count] || 1) >= count
  end

  defp evaluate_condition({:risk_score, :gte, score}, change) do
    (change[:risk_score] || 0) >= score
  end

  defp evaluate_condition(_, _), do: true

  defp severity_level(:critical), do: 4
  defp severity_level(:high), do: 3
  defp severity_level(:medium), do: 2
  defp severity_level(:low), do: 1
  defp severity_level(:info), do: 0
  defp severity_level(_), do: 0

  # ============================================================================
  # Alert Generation Functions
  # ============================================================================

  defp should_alert?(change_type, change) do
    change.severity in [:high, :critical] or
    change_type in [:certificate_expired, :vulnerability_found, :risk_threshold_crossed]
  end

  defp create_asm_alert(change) do
    title = build_alert_title(change)
    description = build_alert_description(change)
    severity = change[:severity] || :medium

    alert_params = %{
      title: "[ASM] #{title}",
      description: description,
      severity: severity,
      source: :asm,
      category: :attack_surface,
      mitre_tactics: ["reconnaissance"],
      mitre_techniques: get_mitre_techniques(change.type),
      metadata: %{
        change_id: change.id,
        change_type: change.type,
        asset_id: change[:asset_id]
      }
    }

    case Alerts.create_alert(alert_params) do
      {:ok, alert} ->
        Logger.info("ASM alert created: #{alert.id} - #{title}")
        broadcast_alert(alert)

      {:error, reason} ->
        Logger.error("Failed to create ASM alert: #{inspect(reason)}")
    end
  end

  defp create_rule_alert(rule, change) do
    title = "#{rule.name}: #{build_alert_title(change)}"
    severity = rule.severity_override || change.severity

    alert_params = %{
      title: "[ASM] #{title}",
      description: build_alert_description(change),
      severity: severity,
      source: :asm,
      category: :attack_surface,
      metadata: %{
        rule_id: rule.id,
        rule_name: rule.name,
        change_id: change.id
      }
    }

    Alerts.create_alert(alert_params)
  end

  defp build_alert_title(%{type: :asset_discovered, count: count, target: target}) do
    "#{count} new assets discovered for #{target}"
  end

  defp build_alert_title(%{type: :risk_threshold_crossed, severity: severity, asset_id: asset_id}) do
    "#{severity} risk level reached for asset #{asset_id}"
  end

  defp build_alert_title(%{type: :certificate_expired, asset_id: asset_id}) do
    "SSL certificate expired for #{asset_id}"
  end

  defp build_alert_title(%{type: :certificate_expiring, asset_id: asset_id}) do
    "SSL certificate expiring soon for #{asset_id}"
  end

  defp build_alert_title(%{type: :vulnerability_found, diff: diff}) do
    "New vulnerability #{diff[:cve_id]} (CVSS: #{diff[:cvss]}) discovered"
  end

  defp build_alert_title(%{type: :port_opened, diff: diff}) do
    "New port #{diff[:port]} (#{diff[:service]}) opened"
  end

  defp build_alert_title(%{type: type}) do
    "Attack surface change: #{type}"
  end

  defp build_alert_description(%{type: :asset_discovered} = change) do
    items = change[:items] || []
    """
    New assets have been discovered on your attack surface.

    Discovery Type: #{change[:discovery_type]}
    Target: #{change[:target]}
    Count: #{length(items)}

    New Assets:
    #{Enum.take(items, 10) |> Enum.map(&("- #{&1}")) |> Enum.join("\n")}
    #{if length(items) > 10, do: "\n... and #{length(items) - 10} more", else: ""}

    Review these assets to ensure they are intended to be exposed.
    """
  end

  defp build_alert_description(%{type: :risk_threshold_crossed} = change) do
    """
    An asset has crossed a risk threshold requiring attention.

    Asset: #{change[:asset_id]}
    Risk Score: #{change[:risk_score]}
    Risk Level: #{change[:risk_level]}

    Contributing Factors:
    #{Enum.map(change[:factors] || [], &("- #{&1}")) |> Enum.join("\n")}

    Immediate action is recommended to reduce the risk exposure.
    """
  end

  defp build_alert_description(%{type: :vulnerability_found} = change) do
    """
    A new vulnerability has been identified in your attack surface.

    CVE: #{change[:diff][:cve_id]}
    CVSS Score: #{change[:diff][:cvss]}
    Severity: #{change[:diff][:severity]}

    Review and remediate this vulnerability as soon as possible.
    """
  end

  defp build_alert_description(change) do
    """
    An attack surface change has been detected.

    Type: #{change[:type]}
    Severity: #{change[:severity]}
    Detected At: #{change[:detected_at]}

    Details:
    #{inspect(change[:diff] || change[:current], pretty: true, limit: 500)}
    """
  end

  defp get_mitre_techniques(:asset_discovered), do: ["T1595"]  # Active Scanning
  defp get_mitre_techniques(:vulnerability_found), do: ["T1190"]  # Exploit Public-Facing Application
  defp get_mitre_techniques(:port_opened), do: ["T1046"]  # Network Service Discovery
  defp get_mitre_techniques(_), do: []

  defp broadcast_alert(alert) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "asm:alerts",
      {:asm_alert, alert}
    )
  end

  # ============================================================================
  # Report Generation
  # ============================================================================

  defp generate_change_report(change_log, opts) do
    days = opts[:days] || 7
    cutoff = DateTime.add(DateTime.utc_now(), -days, :day)
    cutoff_ms = DateTime.to_unix(cutoff, :millisecond)

    changes = :ets.select(change_log, [{{:"$1", :"$2"}, [{:>=, :"$1", cutoff_ms}], [:"$2"]}])

    %{
      report_type: :asm_changes,
      period: %{
        days: days,
        from: cutoff,
        to: DateTime.utc_now()
      },
      generated_at: DateTime.utc_now(),
      summary: %{
        total_changes: length(changes),
        new_assets: Enum.count(changes, & &1[:type] == :asset_discovered),
        risk_alerts: Enum.count(changes, & &1[:type] == :risk_threshold_crossed),
        vulnerabilities: Enum.count(changes, & &1[:type] == :vulnerability_found),
        certificate_issues: Enum.count(changes, fn c ->
          c[:type] in [:certificate_expired, :certificate_expiring]
        end)
      },
      changes_by_severity: Enum.group_by(changes, & &1[:severity])
      |> Enum.map(fn {severity, items} ->
        {severity, %{count: length(items), items: Enum.take(items, 10)}}
      end)
      |> Map.new(),
      top_risk_changes: changes
      |> Enum.filter(& &1[:severity] in [:high, :critical])
      |> Enum.take(20),
      trend_analysis: %{
        daily_changes: calculate_daily_breakdown(changes, days),
        change_velocity: length(changes) / days
      },
      recommendations: generate_report_recommendations(changes)
    }
  end

  defp calculate_daily_breakdown(changes, days) do
    # Group changes by day
    now = DateTime.utc_now()

    0..(days - 1)
    |> Enum.map(fn day_offset ->
      day = DateTime.add(now, -day_offset, :day) |> DateTime.to_date()

      day_changes = Enum.filter(changes, fn c ->
        c[:detected_at] && DateTime.to_date(c[:detected_at]) == day
      end)

      %{
        date: day,
        count: length(day_changes),
        by_type: Enum.group_by(day_changes, & &1[:type])
        |> Enum.map(fn {k, v} -> {k, length(v)} end)
        |> Map.new()
      }
    end)
    |> Enum.reverse()
  end

  defp generate_report_recommendations(changes) do
    recommendations = []

    # Check for new assets
    new_asset_count = Enum.count(changes, & &1[:type] == :asset_discovered)
    recommendations = if new_asset_count > 0 do
      ["Review #{new_asset_count} newly discovered assets for legitimacy" | recommendations]
    else
      recommendations
    end

    # Check for vulnerabilities
    vuln_count = Enum.count(changes, & &1[:type] == :vulnerability_found)
    recommendations = if vuln_count > 0 do
      ["Address #{vuln_count} new vulnerabilities discovered in your attack surface" | recommendations]
    else
      recommendations
    end

    # Check for certificate issues
    cert_issues = Enum.count(changes, fn c -> c[:type] in [:certificate_expired, :certificate_expiring] end)
    recommendations = if cert_issues > 0 do
      ["Renew #{cert_issues} SSL certificates that are expired or expiring" | recommendations]
    else
      recommendations
    end

    # Check for risk increases
    risk_alerts = Enum.count(changes, & &1[:type] == :risk_threshold_crossed)
    recommendations = if risk_alerts > 0 do
      ["Investigate #{risk_alerts} assets that crossed risk thresholds" | recommendations]
    else
      recommendations
    end

    if Enum.empty?(recommendations) do
      ["Attack surface changes within normal parameters"]
    else
      Enum.reverse(recommendations)
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp get_all_changes(table) do
    :ets.tab2list(table)
    |> Enum.map(fn {_ts, change} -> change end)
    |> Enum.sort_by(& &1[:timestamp], :desc)
  end

  defp filter_by_change_type(changes, nil), do: changes
  defp filter_by_change_type(changes, type) do
    type_atom = if is_binary(type), do: String.to_atom(type), else: type
    Enum.filter(changes, & &1[:type] == type_atom)
  end

  defp filter_by_severity(changes, nil), do: changes
  defp filter_by_severity(changes, severity) do
    severity_atom = if is_binary(severity), do: String.to_atom(severity), else: severity
    Enum.filter(changes, & &1[:severity] == severity_atom)
  end

  defp filter_by_time_range(changes, nil, nil), do: changes
  defp filter_by_time_range(changes, from, to) do
    Enum.filter(changes, fn c ->
      detected = c[:detected_at]
      after_from = if from, do: DateTime.compare(detected, from) != :lt, else: true
      before_to = if to, do: DateTime.compare(detected, to) != :gt, else: true
      after_from and before_to
    end)
  end

  defp maybe_limit(changes, nil), do: changes
  defp maybe_limit(changes, limit), do: Enum.take(changes, limit)

  defp default_alert_rules do
    %{
      "critical_risk" => %{
        id: "critical_risk",
        name: "Critical Risk Alert",
        change_types: [:risk_threshold_crossed],
        conditions: [{:severity, :gte, :critical}],
        severity_override: :critical,
        enabled: true,
        created_at: DateTime.utc_now()
      },
      "new_critical_vuln" => %{
        id: "new_critical_vuln",
        name: "Critical Vulnerability",
        change_types: [:vulnerability_found],
        conditions: [{:severity, :gte, :critical}],
        severity_override: :critical,
        enabled: true,
        created_at: DateTime.utc_now()
      },
      "cert_expired" => %{
        id: "cert_expired",
        name: "Certificate Expired",
        change_types: [:certificate_expired],
        conditions: [],
        severity_override: :critical,
        enabled: true,
        created_at: DateTime.utc_now()
      }
    }
  end

  defp generate_change_id do
    "chg_#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
  end

  defp generate_subscription_id do
    "sub_#{:crypto.strong_rand_bytes(6) |> Base.encode16(case: :lower)}"
  end

  defp generate_rule_id do
    "rule_#{:crypto.strong_rand_bytes(6) |> Base.encode16(case: :lower)}"
  end

  defp build_config(opts) do
    %{
      retention_days: Keyword.get(opts, :retention_days, 90),
      enable_alerts: Keyword.get(opts, :enable_alerts, true),
      cleanup_interval: Keyword.get(opts, :cleanup_interval, :timer.hours(24))
    }
  end

  defp initial_stats do
    %{
      discoveries_processed: 0,
      changes_detected: 0,
      risk_alerts: 0,
      started_at: DateTime.utc_now()
    }
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, :timer.hours(24))
  end
end
