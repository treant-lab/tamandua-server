defmodule TamanduaServer.Alerts.Suppression do
  @moduledoc """
  Alert Suppression Engine.

  Manages suppression rules for reducing false positive alert noise.
  Uses ETS for high-performance lookups on the detection hot path and
  PostgreSQL for durable storage.

  ## Contextual Auto-Suppression

  Tracks identical alert occurrences (same type + agent + process context)
  in ETS. After a configurable threshold (default 5), subsequent identical
  alerts are auto-suppressed. The suppression count resets after a
  configurable period (default 24 hours).

  ## Rule-Based Suppression

  Analysts can create explicit suppression rules when marking alerts as
  false positive. These rules match on alert characteristics and either
  suppress entirely or reduce severity.
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.SuppressionRule
  alias TamanduaServer.Detection.ThresholdConfig

  # ETS table for contextual auto-suppression counters
  @context_table :alert_suppression_context
  # ETS table for cached suppression rules
  @rules_cache :alert_suppression_rules_cache

  # Contextual auto-suppression defaults
  @default_occurrence_threshold 5
  @default_reset_period_seconds 24 * 60 * 60  # 24 hours

  # Rule cache refresh interval
  @cache_refresh_interval :timer.minutes(5)
  # Context cleanup interval
  @context_cleanup_interval :timer.minutes(30)

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if an alert should be suppressed before creation.

  This function now integrates with SuppressionEngine for priority-based evaluation.

  Returns:
  - `:allow` - Alert should be created normally
  - `{:suppress, reason}` - Alert should be suppressed entirely
  - `{:reduce_severity, new_severity, reason}` - Alert severity should be reduced
  - `{:auto_suppress, count, reason}` - Alert auto-suppressed due to repeated occurrences
  """
  @spec check_suppression(map(), String.t() | nil) :: :allow | {:suppress, String.t()} | {:reduce_severity, String.t(), String.t()} | {:auto_suppress, integer(), String.t()}
  def check_suppression(alert_data, agent_id) do
    GenServer.call(__MODULE__, {:check_suppression, alert_data, agent_id})
  rescue
    _ -> :allow
  catch
    :exit, reason ->
      Logger.warning("Suppression check unavailable, allowing alert: #{inspect(reason)}")
      :allow
  end

  @doc """
  Check suppression using the new SuppressionEngine (priority-based evaluation).

  This is the recommended method for new integrations.
  """
  @spec check_suppression_v2(map(), map()) :: :allow | {:suppress, String.t(), String.t()} | {:reduce_severity, String.t(), String.t(), String.t()}
  def check_suppression_v2(alert_data, context \\ %{}) do
    case TamanduaServer.Alerts.SuppressionEngine.evaluate_rules(alert_data, context) do
      :allow -> :allow
      {:suppress, rule_id, reason} -> {:suppress, reason}
      {:reduce_severity, new_severity, _rule_id, reason} -> {:reduce_severity, new_severity, reason}
      {:tag, _tags, _rule_id, _reason} -> :allow  # Tags don't block alert creation
    end
  rescue
    _ -> :allow
  end

  @doc """
  Record an alert occurrence for contextual auto-suppression tracking.
  Fire-and-forget -- does not block the caller.
  """
  @spec record_occurrence(map(), String.t() | nil) :: :ok
  def record_occurrence(alert_data, agent_id) do
    GenServer.cast(__MODULE__, {:record_occurrence, alert_data, agent_id})
  end

  @doc """
  Get all active suppression rules, optionally filtered by agent_id.
  """
  @spec get_active_rules(String.t() | nil) :: [SuppressionRule.t()]
  def get_active_rules(agent_id \\ nil) do
    GenServer.call(__MODULE__, {:get_active_rules, agent_id})
  end

  @doc """
  Create a suppression rule from an alert that was marked as FP.
  """
  @spec create_rule_from_alert(map(), keyword()) :: {:ok, SuppressionRule.t()} | {:error, term()}
  def create_rule_from_alert(alert, opts \\ []) do
    GenServer.call(__MODULE__, {:create_rule_from_alert, alert, opts})
  end

  @doc """
  Increment the match count on a suppression rule.
  """
  @spec record_rule_match(String.t()) :: :ok
  def record_rule_match(rule_id) do
    GenServer.cast(__MODULE__, {:record_rule_match, rule_id})
  end

  @doc """
  Get suppression stats.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Force refresh the rules cache from the database.
  """
  @spec refresh_cache() :: :ok
  def refresh_cache do
    GenServer.cast(__MODULE__, :refresh_cache)
  end

  @doc """
  Get contextual suppression configuration.
  """
  @spec get_config() :: map()
  def get_config do
    %{
      occurrence_threshold: occurrence_threshold(),
      reset_period_seconds: reset_period_seconds()
    }
  end

  # ---------------------------------------------------------------------------
  # GenServer Implementation
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@context_table, [
      :named_table, :set, :public,
      read_concurrency: true, write_concurrency: true
    ])

    :ets.new(@rules_cache, [
      :named_table, :set, :public,
      read_concurrency: true
    ])

    # Initialize health-aware suppression rate tracking table
    TamanduaServer.Alerts.HealthAwareSuppression.init_rate_table()

    # Load rules into cache
    load_rules_into_cache()

    # Schedule periodic tasks
    schedule_cache_refresh()
    schedule_context_cleanup()
    schedule_health_rate_cleanup()

    Logger.info("Alert Suppression Engine started (threshold=#{occurrence_threshold()}, reset=#{reset_period_seconds()}s)")
    {:ok, %{total_suppressed: 0, total_checked: 0}}
  end

  @impl true
  def handle_call({:check_suppression, alert_data, agent_id}, _from, state) do
    result = do_check_suppression(alert_data, agent_id)
    new_state = %{state | total_checked: state.total_checked + 1}

    new_state = case result do
      :allow -> new_state
      _ -> %{new_state | total_suppressed: new_state.total_suppressed + 1}
    end

    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:get_active_rules, agent_id}, _from, state) do
    rules = fetch_active_rules(agent_id)
    {:reply, rules, state}
  end

  @impl true
  def handle_call({:create_rule_from_alert, alert, opts}, _from, state) do
    result = do_create_rule_from_alert(alert, opts)

    # Refresh cache if rule was created successfully
    case result do
      {:ok, _rule} -> load_rules_into_cache()
      _ -> :ok
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    context_count = try do
      :ets.info(@context_table, :size)
    rescue
      _ -> 0
    end

    active_rules = length(fetch_active_rules(nil))

    health_rate_entries = try do
      :ets.info(:health_suppression_alert_rates, :size)
    rescue
      _ -> 0
    end

    stats = %{
      total_checked: state.total_checked,
      total_suppressed: state.total_suppressed,
      suppression_rate: if(state.total_checked > 0,
        do: Float.round(state.total_suppressed / state.total_checked * 100, 1),
        else: 0.0),
      active_rules: active_rules,
      context_entries: context_count,
      health_rate_entries: health_rate_entries,
      occurrence_threshold: occurrence_threshold(),
      reset_period_seconds: reset_period_seconds()
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:record_occurrence, alert_data, agent_id}, state) do
    context_key = build_context_key(alert_data, agent_id)
    now = System.system_time(:second)

    case :ets.lookup(@context_table, context_key) do
      [{^context_key, count, first_seen}] ->
        :ets.insert(@context_table, {context_key, count + 1, first_seen})
      [] ->
        :ets.insert(@context_table, {context_key, 1, now})
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_rule_match, rule_id}, state) do
    now = DateTime.utc_now()

    Repo.update_all(
      from(r in SuppressionRule,
        where: r.id == ^rule_id
      ),
      inc: [match_count: 1],
      set: [last_matched_at: now, updated_at: now]
    )

    {:noreply, state}
  end

  @impl true
  def handle_cast(:refresh_cache, state) do
    load_rules_into_cache()
    {:noreply, state}
  end

  @impl true
  def handle_info(:refresh_rules_cache, state) do
    load_rules_into_cache()
    schedule_cache_refresh()
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_context, state) do
    cleanup_stale_context()
    schedule_context_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_health_rates, state) do
    TamanduaServer.Alerts.HealthAwareSuppression.cleanup_rate_table()
    schedule_health_rate_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Internal: Suppression Check
  # ---------------------------------------------------------------------------

  defp do_check_suppression(alert_data, agent_id) do
    # 1. Check rule-based suppression first
    case check_rule_suppression(alert_data) do
      {:suppress, _reason} = result -> result
      {:reduce_severity, _sev, _reason} = result -> result
      :no_match ->
        # 2. Check contextual auto-suppression
        check_contextual_suppression(alert_data, agent_id)
    end
  end

  # Check against cached suppression rules
  defp check_rule_suppression(alert_data) do
    rules = try do
      case :ets.lookup(@rules_cache, :all_rules) do
        [{:all_rules, cached_rules}] -> cached_rules
        [] -> []
      end
    rescue
      _ -> []
    end

    # Find first matching rule
    matching_rule = Enum.find(rules, fn rule ->
      rule_matches_alert_data?(rule, alert_data)
    end)

    case matching_rule do
      nil ->
        :no_match

      %SuppressionRule{action: "suppress"} = rule ->
        record_rule_match(rule.id)
        {:suppress, "Matched suppression rule: #{rule.name} (#{rule.id})"}

      %SuppressionRule{action: "reduce_severity", reduce_to_severity: new_sev} = rule when not is_nil(new_sev) ->
        record_rule_match(rule.id)
        {:reduce_severity, new_sev, "Matched severity reduction rule: #{rule.name} (#{rule.id})"}

      _ ->
        :no_match
    end
  end

  # Check if a rule matches alert data (pre-creation, so we work with the raw map)
  defp rule_matches_alert_data?(rule, alert_data) do
    # Check expiry
    if rule.expires_at && DateTime.compare(DateTime.utc_now(), rule.expires_at) == :gt do
      false
    else
      if rule.max_matches && rule.match_count >= rule.max_matches do
        false
      else
        checks = [
          {rule.title_pattern, get_alert_field(alert_data, :title), :contains},
          {rule.severity, get_alert_field(alert_data, :severity), :exact},
          {rule.agent_id, get_alert_field(alert_data, :agent_id), :exact},
          {rule.rule_name_pattern, get_detection_rule_name(alert_data), :contains},
          {rule.process_name_pattern, get_evidence_process_name(alert_data), :contains},
          {rule.file_path_pattern, get_evidence_file_path(alert_data), :contains}
        ]

        Enum.all?(checks, fn
          {nil, _actual, _mode} -> true
          {"", _actual, _mode} -> true
          {_pattern, nil, _mode} -> false
          {pattern, actual, :exact} -> to_string(pattern) == to_string(actual)
          {pattern, actual, :contains} ->
            String.contains?(String.downcase(to_string(actual)), String.downcase(to_string(pattern)))
        end)
      end
    end
  end

  # Check contextual auto-suppression (same type + agent + process = suppress after N)
  defp check_contextual_suppression(alert_data, agent_id) do
    context_key = build_context_key(alert_data, agent_id)
    threshold = occurrence_threshold()
    reset_seconds = reset_period_seconds()
    now = System.system_time(:second)

    case :ets.lookup(@context_table, context_key) do
      [{^context_key, count, first_seen}] ->
        # Check if the reset period has elapsed
        if now - first_seen > reset_seconds do
          # Reset the counter
          :ets.insert(@context_table, {context_key, 1, now})
          :allow
        else
          if count >= threshold do
            {:auto_suppress, count, "Auto-suppressed: #{count} identical alerts in #{div(now - first_seen, 60)} minutes (threshold: #{threshold})"}
          else
            :allow
          end
        end

      [] ->
        :allow
    end
  end

  # Build a context key for deduplication.
  # Key combines: alert title + agent_id + process name (if available)
  defp build_context_key(alert_data, agent_id) do
    title = get_alert_field(alert_data, :title) || ""
    process = get_evidence_process_name(alert_data) || ""
    rule_name = get_detection_rule_name(alert_data) || ""

    # Use a hash for compact ETS keys (SHA-256; MD5 is avoided project-wide)
    key_str = "#{agent_id}:#{title}:#{process}:#{rule_name}"
    :crypto.hash(:sha256, key_str) |> Base.encode16(case: :lower)
  end

  # ---------------------------------------------------------------------------
  # Internal: Alert Data Extraction Helpers
  # ---------------------------------------------------------------------------

  defp get_alert_field(data, key) when is_atom(key) do
    Map.get(data, key) || Map.get(data, Atom.to_string(key))
  end

  defp get_detection_rule_name(alert_data) do
    meta = Map.get(alert_data, :detection_metadata) || Map.get(alert_data, "detection_metadata") || %{}
    meta[:rule_name] || meta["rule_name"]
  end

  defp get_evidence_process_name(alert_data) do
    evidence = Map.get(alert_data, :evidence) || Map.get(alert_data, "evidence") || %{}
    process = evidence[:process] || evidence["process"] || %{}
    process[:name] || process["name"]
  end

  defp get_evidence_file_path(alert_data) do
    evidence = Map.get(alert_data, :evidence) || Map.get(alert_data, "evidence") || %{}
    process = evidence[:process] || evidence["process"] || %{}
    process[:path] || process["path"]
  end

  # ---------------------------------------------------------------------------
  # Internal: Rule Management
  # ---------------------------------------------------------------------------

  defp do_create_rule_from_alert(alert, opts) do
    user_id = Keyword.get(opts, :user_id)
    ttl_days = Keyword.get(opts, :ttl_days, 30)
    action = Keyword.get(opts, :action, "suppress")
    name = Keyword.get(opts, :name)

    # Extract matching criteria from the alert
    evidence = alert.evidence || %{}
    process = evidence["process"] || evidence[:process] || %{}
    detection_meta = alert.detection_metadata || %{}

    rule_name = detection_meta["rule_name"] || detection_meta[:rule_name]
    process_name = process["name"] || process[:name]
    file_path = process["path"] || process[:path]

    auto_name = name || "FP: #{alert.title}"
    |> String.slice(0, 200)

    expires_at = DateTime.utc_now() |> DateTime.add(ttl_days * 24 * 60 * 60, :second)

    attrs = %{
      name: auto_name,
      description: "Auto-created from false positive alert #{alert.id}",
      enabled: true,
      source_alert_id: alert.id,
      organization_id: alert.organization_id,
      created_by_id: user_id,
      agent_id: alert.agent_id,
      rule_name_pattern: rule_name,
      process_name_pattern: process_name,
      file_path_pattern: file_path,
      title_pattern: alert.title,
      action: action,
      expires_at: expires_at,
      criteria: %{
        "mitre_techniques" => alert.mitre_techniques || [],
        "severity" => alert.severity
      }
    }

    %SuppressionRule{}
    |> SuppressionRule.changeset(attrs)
    |> Repo.insert()
  end

  defp fetch_active_rules(agent_id) do
    now = DateTime.utc_now()
    dumped_agent_id = dump_uuid(agent_id)

    query = from(r in SuppressionRule,
      where: r.enabled == true,
      where: is_nil(r.expires_at) or r.expires_at > ^now,
      order_by: [desc: r.inserted_at]
    )

    query = if dumped_agent_id do
      from(r in query,
        where: is_nil(r.agent_id) or r.agent_id == ^dumped_agent_id
      )
    else
      query
    end

    Repo.all(query)
  rescue
    e ->
      Logger.warning("Failed to fetch suppression rules: #{inspect(e)}")
      []
  end

  defp dump_uuid(nil), do: nil
  defp dump_uuid(<<_::128>> = uuid), do: uuid

  defp dump_uuid(uuid) when is_binary(uuid) do
    case Ecto.UUID.dump(uuid) do
      {:ok, dumped} -> dumped
      :error -> nil
    end
  end

  defp dump_uuid(_), do: nil

  defp load_rules_into_cache do
    rules = fetch_active_rules(nil)
    :ets.insert(@rules_cache, {:all_rules, rules})
    Logger.debug("Suppression: cached #{length(rules)} active rules")
  rescue
    e ->
      Logger.warning("Suppression: failed to load rules cache: #{inspect(e)}")
  end

  # ---------------------------------------------------------------------------
  # Periodic Tasks
  # ---------------------------------------------------------------------------

  defp schedule_cache_refresh do
    Process.send_after(self(), :refresh_rules_cache, @cache_refresh_interval)
  end

  defp schedule_context_cleanup do
    Process.send_after(self(), :cleanup_context, @context_cleanup_interval)
  end

  # Health-aware suppression rate cleanup (every 10 minutes)
  @health_rate_cleanup_interval :timer.minutes(10)

  defp schedule_health_rate_cleanup do
    Process.send_after(self(), :cleanup_health_rates, @health_rate_cleanup_interval)
  end

  defp cleanup_stale_context do
    now = System.system_time(:second)
    reset_seconds = reset_period_seconds()
    cutoff = now - reset_seconds

    # Delete all entries older than the reset period
    match_spec = [
      {{:_, :_, :"$1"}, [{:<, :"$1", cutoff}], [true]}
    ]

    deleted = try do
      :ets.select_delete(@context_table, match_spec)
    rescue
      _ -> 0
    end

    if deleted > 0 do
      Logger.debug("Suppression: cleaned up #{deleted} stale context entries")
    end
  end

  # ---------------------------------------------------------------------------
  # Configuration
  # ---------------------------------------------------------------------------

  defp occurrence_threshold do
    app_env_default =
      Application.get_env(:tamandua_server, :suppression_occurrence_threshold, @default_occurrence_threshold)

    try do
      ThresholdConfig.get(:fp_preset, :suppression_occurrence_threshold, app_env_default)
    rescue
      ArgumentError -> app_env_default
    end
  end

  defp reset_period_seconds do
    Application.get_env(:tamandua_server, :suppression_reset_period_seconds, @default_reset_period_seconds)
  end
end
