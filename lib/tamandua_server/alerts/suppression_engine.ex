defmodule TamanduaServer.Alerts.SuppressionEngine do
  @moduledoc """
  Enhanced Alert Suppression Engine with priority-based rule evaluation.

  This module extends the basic Suppression module with:
  - Priority-based rule evaluation (higher priority rules evaluated first)
  - Exemption support
  - Suppressed alert storage
  - Auto-unsuppression
  - Template management
  - Analytics integration
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.{
    SuppressionRule,
    SuppressedAlert,
    Suppression
  }

  # ETS table for sorted rules by priority
  @priority_rules_table :suppression_priority_rules

  # Auto-unsuppression check interval
  @unsuppression_check_interval :timer.minutes(5)

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Evaluate suppression rules for an alert with priority ordering.

  Returns:
  - `:allow` - Alert should be created normally
  - `{:suppress, rule_id, reason}` - Alert should be fully suppressed
  - `{:reduce_severity, new_severity, rule_id, reason}` - Reduce severity
  - `{:tag, tags, rule_id, reason}` - Add tags to alert
  """
  @spec evaluate_rules(map(), map()) :: :allow | {:suppress, String.t(), String.t()} | {:reduce_severity, String.t(), String.t(), String.t()} | {:tag, [String.t()], String.t(), String.t()}
  def evaluate_rules(alert_data, context \\ %{}) do
    GenServer.call(__MODULE__, {:evaluate_rules, alert_data, context})
  end

  @doc """
  Store a suppressed alert.
  """
  @spec store_suppressed_alert(map(), map()) :: {:ok, SuppressedAlert.t()} | {:error, term()}
  def store_suppressed_alert(alert_data, suppression_details) do
    GenServer.call(__MODULE__, {:store_suppressed_alert, alert_data, suppression_details})
  end

  @doc """
  Unsuppress an alert and optionally create a new alert from it.
  """
  @spec unsuppress_alert(String.t(), String.t() | nil, map()) :: {:ok, map()} | {:error, term()}
  def unsuppress_alert(suppressed_alert_id, user_id, opts \\ %{}) do
    GenServer.call(__MODULE__, {:unsuppress_alert, suppressed_alert_id, user_id, opts})
  end

  @doc """
  Get rule templates.
  """
  @spec list_templates(String.t()) :: [SuppressionRule.t()]
  def list_templates(organization_id) do
    GenServer.call(__MODULE__, {:list_templates, organization_id})
  end

  @doc """
  Create rule from template.
  """
  @spec create_from_template(String.t(), map(), String.t()) :: {:ok, SuppressionRule.t()} | {:error, term()}
  def create_from_template(template_id, overrides, organization_id) do
    GenServer.call(__MODULE__, {:create_from_template, template_id, overrides, organization_id})
  end

  @doc """
  Force refresh of priority rules cache.
  """
  @spec refresh_priority_cache() :: :ok
  def refresh_priority_cache do
    GenServer.cast(__MODULE__, :refresh_priority_cache)
  end

  # ---------------------------------------------------------------------------
  # GenServer Implementation
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Create ETS table for priority-sorted rules
    :ets.new(@priority_rules_table, [
      :named_table, :ordered_set, :public,
      read_concurrency: true
    ])

    # Load rules into priority cache
    load_priority_rules()

    # Schedule periodic tasks
    schedule_unsuppression_check()
    schedule_priority_cache_refresh()

    Logger.info("Suppression Engine started with priority-based evaluation")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:evaluate_rules, alert_data, context}, _from, state) do
    result = do_evaluate_rules(alert_data, context)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:store_suppressed_alert, alert_data, suppression_details}, _from, state) do
    result = do_store_suppressed_alert(alert_data, suppression_details)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:unsuppress_alert, suppressed_alert_id, user_id, opts}, _from, state) do
    result = do_unsuppress_alert(suppressed_alert_id, user_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_templates, organization_id}, _from, state) do
    templates = fetch_templates(organization_id)
    {:reply, templates, state}
  end

  @impl true
  def handle_call({:create_from_template, template_id, overrides, organization_id}, _from, state) do
    result = do_create_from_template(template_id, overrides, organization_id)
    {:reply, result, state}
  end

  @impl true
  def handle_cast(:refresh_priority_cache, state) do
    load_priority_rules()
    {:noreply, state}
  end

  @impl true
  def handle_info(:check_unsuppression, state) do
    check_and_unsuppress_alerts()
    schedule_unsuppression_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(:refresh_priority_cache, state) do
    load_priority_rules()
    schedule_priority_cache_refresh()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Internal: Rule Evaluation
  # ---------------------------------------------------------------------------

  defp do_evaluate_rules(alert_data, context) do
    organization_id = alert_data[:organization_id] || alert_data["organization_id"]

    # Get priority-sorted rules from ETS
    rules = get_priority_rules(organization_id)

    # Find first matching rule (highest priority wins)
    case find_matching_rule(rules, alert_data, context) do
      nil ->
        :allow

      {rule, :suppress} ->
        {:suppress, rule.id, "Matched suppression rule: #{rule.name} (priority: #{rule.priority})"}

      {rule, :reduce_severity} when not is_nil(rule.reduce_to_severity) ->
        {:reduce_severity, rule.reduce_to_severity, rule.id, "Matched severity reduction rule: #{rule.name}"}

      {rule, :tag} when rule.add_tags != [] ->
        {:tag, rule.add_tags, rule.id, "Matched tagging rule: #{rule.name}"}

      _ ->
        :allow
    end
  end

  defp find_matching_rule(rules, alert_data, context) do
    Enum.find_value(rules, fn rule ->
      if rule_matches_alert_data?(rule, alert_data, context) do
        # Record the match asynchronously
        Suppression.record_rule_match(rule.id)

        # Determine action
        action = case rule.action do
          "suppress" -> :suppress
          "reduce_severity" -> :reduce_severity
          "tag" -> :tag
          _ -> nil
        end

        {rule, action}
      end
    end)
  end

  defp rule_matches_alert_data?(rule, alert_data, context) do
    # Check expiry
    if rule.expires_at && DateTime.compare(DateTime.utc_now(), rule.expires_at) == :gt do
      false
    else
      # Check max matches
      if rule.max_matches && rule.match_count >= rule.max_matches do
        false
      else
        # Check exemptions
        if is_exempted?(rule, alert_data, context) do
          false
        else
          # Check criteria match
          matches_criteria?(rule, alert_data) and matches_json_criteria?(rule.criteria || %{}, alert_data)
        end
      end
    end
  end

  defp is_exempted?(rule, alert_data, context) do
    agent_id = alert_data[:agent_id] || alert_data["agent_id"]
    agent_exempted = agent_id && agent_id in (rule.exempted_agent_ids || [])

    user_exempted = case context[:user_email] || context[:username] || get_event_user(alert_data) do
      nil -> false
      username -> user_member?(username, rule.exempted_users || [])
    end

    agent_exempted || user_exempted
  end

  defp matches_criteria?(rule, alert_data) do
    checks = [
      {rule.title_pattern, get_field(alert_data, :title), :contains},
      {rule.severity, get_field(alert_data, :severity), :exact},
      {rule.agent_id, get_field(alert_data, :agent_id), :exact},
      {rule.rule_name_pattern, get_detection_rule_name(alert_data), :contains},
      {rule.process_name_pattern, get_evidence_process_name(alert_data), :contains},
      {rule.parent_process_pattern, get_evidence_parent_process_name(alert_data), :contains},
      {rule.file_path_pattern, get_evidence_file_path(alert_data), :contains}
    ]

    all_match = Enum.all?(checks, fn
      {nil, _actual, _mode} -> true
      {"", _actual, _mode} -> true
      {_pattern, nil, _mode} -> false
      {pattern, actual, :exact} -> to_string(pattern) == to_string(actual)
      {pattern, actual, :contains} -> pattern_matches?(pattern, actual)
    end)

    # Check MITRE techniques if specified
    all_match = if all_match and rule.mitre_techniques != [] do
      alert_techniques = get_field(alert_data, :mitre_techniques) || []
      Enum.any?(rule.mitre_techniques, & &1 in alert_techniques)
    else
      all_match
    end

    # Check tags if specified
    if all_match and rule.tags != [] do
      alert_tags = get_field(alert_data, :tags) || []
      Enum.any?(rule.tags, & &1 in alert_tags)
    else
      all_match
    end
  end

  # ---------------------------------------------------------------------------
  # Internal: Suppressed Alert Management
  # ---------------------------------------------------------------------------

  defp do_store_suppressed_alert(alert_data, suppression_details) do
    SuppressedAlert.from_alert_data(alert_data, suppression_details)
    |> Repo.insert()
  end

  defp do_unsuppress_alert(suppressed_alert_id, user_id, opts) do
    case Repo.get(SuppressedAlert, suppressed_alert_id) do
      nil ->
        {:error, :not_found}

      suppressed_alert ->
        Ecto.Multi.new()
        |> Ecto.Multi.update(:update_suppressed, fn _ ->
          SuppressedAlert.changeset(suppressed_alert, %{
            unsuppressed: true,
            unsuppressed_at: DateTime.utc_now(),
            unsuppressed_by_id: user_id
          })
        end)
        |> maybe_create_alert(suppressed_alert, opts)
        |> Repo.transaction()
        |> case do
          {:ok, result} -> {:ok, result}
          {:error, _step, changeset, _changes} -> {:error, changeset}
        end
    end
  end

  defp maybe_create_alert(multi, suppressed_alert, %{create_alert: true}) do
    Ecto.Multi.insert(multi, :create_alert, fn _ ->
      TamanduaServer.Alerts.Alert.changeset(%TamanduaServer.Alerts.Alert{}, %{
        title: suppressed_alert.title,
        description: suppressed_alert.description,
        severity: suppressed_alert.original_severity || suppressed_alert.severity,
        mitre_tactics: suppressed_alert.mitre_tactics,
        mitre_techniques: suppressed_alert.mitre_techniques,
        threat_score: suppressed_alert.threat_score,
        evidence: suppressed_alert.evidence,
        process_chain: suppressed_alert.process_chain,
        raw_event: suppressed_alert.raw_event,
        detection_metadata: suppressed_alert.detection_metadata,
        organization_id: suppressed_alert.organization_id,
        agent_id: suppressed_alert.agent_id
      })
    end)
  end

  defp maybe_create_alert(multi, _suppressed_alert, _opts), do: multi

  defp check_and_unsuppress_alerts do
    now = DateTime.utc_now()

    # Find all suppressed alerts that should be unsuppressed
    from(sa in SuppressedAlert,
      where: sa.unsuppressed == false,
      where: not is_nil(sa.unsuppress_at),
      where: sa.unsuppress_at <= ^now
    )
    |> Repo.all()
    |> Enum.each(fn suppressed_alert ->
      case do_unsuppress_alert(suppressed_alert.id, nil, %{create_alert: true}) do
        {:ok, _} ->
          Logger.info("Auto-unsuppressed alert: #{suppressed_alert.id}")
        {:error, reason} ->
          Logger.warning("Failed to auto-unsuppress alert #{suppressed_alert.id}: #{inspect(reason)}")
      end
    end)
  end

  # ---------------------------------------------------------------------------
  # Internal: Template Management
  # ---------------------------------------------------------------------------

  defp fetch_templates(organization_id) do
    from(r in SuppressionRule,
      where: r.organization_id == ^organization_id,
      where: r.is_template == true,
      order_by: [desc: r.inserted_at]
    )
    |> Repo.all()
  rescue
    e ->
      Logger.warning("Failed to fetch suppression templates: #{inspect(e)}")
      []
  end

  defp do_create_from_template(template_id, overrides, organization_id) do
    case Repo.get(SuppressionRule, template_id) do
      nil ->
        {:error, :template_not_found}

      template ->
        # Copy template and apply overrides
        attrs = template
        |> Map.from_struct()
        |> Map.drop([:id, :__meta__, :inserted_at, :updated_at, :match_count, :last_matched_at])
        |> Map.merge(%{
          is_template: false,
          template_name: nil,
          template_description: nil,
          organization_id: organization_id
        })
        |> Map.merge(overrides)

        %SuppressionRule{}
        |> SuppressionRule.changeset(attrs)
        |> Repo.insert()
    end
  end

  # ---------------------------------------------------------------------------
  # Internal: Priority Rule Management
  # ---------------------------------------------------------------------------

  defp load_priority_rules do
    now = DateTime.utc_now()

    rules = from(r in SuppressionRule,
      where: r.enabled == true,
      where: is_nil(r.expires_at) or r.expires_at > ^now,
      where: r.is_template == false,
      order_by: [desc: r.priority, desc: r.inserted_at]
    )
    |> Repo.all()
    |> Enum.group_by(& &1.organization_id)

    # Clear and reload ETS table
    :ets.delete_all_objects(@priority_rules_table)

    Enum.each(rules, fn {org_id, org_rules} ->
      :ets.insert(@priority_rules_table, {org_id, org_rules})
    end)

    Logger.debug("Suppression Engine: cached #{Enum.sum(Enum.map(rules, fn {_k, v} -> length(v) end))} priority rules")
  rescue
    e ->
      Logger.warning("Suppression Engine: failed to load priority rules: #{inspect(e)}")
  end

  defp get_priority_rules(organization_id) do
    case :ets.lookup(@priority_rules_table, organization_id) do
      [{^organization_id, rules}] -> rules
      [] -> []
    end
  rescue
    _ -> []
  end

  # ---------------------------------------------------------------------------
  # Periodic Tasks
  # ---------------------------------------------------------------------------

  defp schedule_unsuppression_check do
    Process.send_after(self(), :check_unsuppression, @unsuppression_check_interval)
  end

  defp schedule_priority_cache_refresh do
    Process.send_after(self(), :refresh_priority_cache, :timer.minutes(5))
  end

  # ---------------------------------------------------------------------------
  # Helper Functions
  # ---------------------------------------------------------------------------

  defp get_field(data, key) when is_atom(key) do
    data[key] || data[Atom.to_string(key)]
  end

  defp get_detection_rule_name(alert_data) do
    meta = get_field(alert_data, :detection_metadata) || %{}
    meta[:rule_name] || meta["rule_name"]
  end

  defp get_evidence_process_name(alert_data) do
    evidence = get_field(alert_data, :evidence) || %{}
    process = evidence[:process] || evidence["process"] || %{}
    process[:name] || process["name"]
  end

  defp get_evidence_parent_process_name(alert_data) do
    evidence = get_field(alert_data, :evidence) || %{}
    process = evidence[:process] || evidence["process"] || %{}
    process[:parent_name] || process["parent_name"] || process[:parent_image] || process["parent_image"]
  end

  defp get_evidence_file_path(alert_data) do
    evidence = get_field(alert_data, :evidence) || %{}
    process = evidence[:process] || evidence["process"] || %{}
    file = evidence[:file] || evidence["file"] || %{}

    process[:path] || process["path"] || process[:image] || process["image"] ||
      file[:path] || file["path"]
  end

  defp matches_json_criteria?(nil, _alert_data), do: true
  defp matches_json_criteria?(criteria, _alert_data) when is_map(criteria) and map_size(criteria) == 0, do: true

  defp matches_json_criteria?(criteria, alert_data) when is_map(criteria) do
    criteria
    |> Enum.reject(fn {_key, value} -> blank?(value) end)
    |> Enum.all?(fn {key, expected} ->
      case normalize_criteria_key(key) do
        "severity" -> match_expected?(expected, get_field(alert_data, :severity), :exact)
        "rule_name" -> match_expected?(expected, get_detection_rule_name(alert_data), :contains)
        "rule_name_pattern" -> match_expected?(expected, get_detection_rule_name(alert_data), :contains)
        "process_name" -> match_expected?(expected, get_evidence_process_name(alert_data), :contains)
        "process_name_pattern" -> match_expected?(expected, get_evidence_process_name(alert_data), :contains)
        "parent_process" -> match_expected?(expected, get_evidence_parent_process_name(alert_data), :contains)
        "parent_process_pattern" -> match_expected?(expected, get_evidence_parent_process_name(alert_data), :contains)
        "file_path" -> match_expected?(expected, get_evidence_file_path(alert_data), :contains)
        "file_path_pattern" -> match_expected?(expected, get_evidence_file_path(alert_data), :contains)
        "path" -> match_expected?(expected, get_evidence_file_path(alert_data), :contains)
        "username" -> match_expected?(expected, get_event_user(alert_data), :contains)
        "user" -> match_expected?(expected, get_event_user(alert_data), :contains)
        "user_name" -> match_expected?(expected, get_event_user(alert_data), :contains)
        "event_user" -> match_expected?(expected, get_event_user(alert_data), :contains)
        "mitre_techniques" -> has_overlap?(List.wrap(expected), get_list_field(alert_data, :mitre_techniques))
        "tags" -> has_overlap?(List.wrap(expected), get_list_field(alert_data, :tags))
        _ -> true
      end
    end)
  end

  defp matches_json_criteria?(_criteria, _alert_data), do: true

  defp match_expected?(expected, actual, mode) when is_list(expected) do
    Enum.any?(expected, &match_expected?(&1, actual, mode))
  end

  defp match_expected?(nil, _actual, _mode), do: true
  defp match_expected?("", _actual, _mode), do: true
  defp match_expected?(_expected, nil, _mode), do: false
  defp match_expected?(expected, actual, :exact), do: to_string(expected) == to_string(actual)
  defp match_expected?(expected, actual, :contains), do: pattern_matches?(expected, actual)

  defp pattern_matches?(pattern, actual) do
    pattern_lower = String.downcase(to_string(pattern))
    actual_lower = String.downcase(to_string(actual))

    if String.contains?(pattern_lower, "*") do
      regex_str =
        pattern_lower
        |> Regex.escape()
        |> String.replace("\\*", ".*")

      case Regex.compile("^#{regex_str}$") do
        {:ok, regex} -> Regex.match?(regex, actual_lower)
        _ -> String.contains?(actual_lower, pattern_lower)
      end
    else
      String.contains?(actual_lower, pattern_lower)
    end
  end

  defp has_overlap?(expected, actual) do
    expected_values = expected |> List.wrap() |> Enum.map(&String.downcase(to_string(&1)))
    actual_values = actual |> List.wrap() |> Enum.map(&String.downcase(to_string(&1)))

    Enum.any?(expected_values, &(&1 in actual_values))
  end

  defp user_member?(user, users) do
    normalized_user = String.downcase(to_string(user))

    Enum.any?(users, fn candidate ->
      String.downcase(to_string(candidate)) == normalized_user
    end)
  end

  defp get_event_user(alert_data) do
    evidence = get_field(alert_data, :evidence) || %{}
    process = evidence[:process] || evidence["process"] || %{}
    raw_event = get_field(alert_data, :raw_event) || %{}
    identity = raw_event[:identity] || raw_event["identity"] || %{}

    get_field(alert_data, :username) ||
      get_field(alert_data, :user) ||
      get_field(alert_data, :user_email) ||
      process[:user] || process["user"] ||
      raw_event[:username] || raw_event["username"] ||
      raw_event[:user] || raw_event["user"] ||
      raw_event["User"] || raw_event["UserName"] ||
      raw_event["SubjectUserName"] || raw_event["TargetUserName"] ||
      identity[:user] || identity["user"] ||
      identity[:username] || identity["username"]
  end

  defp get_list_field(data, key) do
    data
    |> get_field(key)
    |> List.wrap()
    |> Enum.reject(&blank?/1)
  end

  defp normalize_criteria_key(key) do
    key
    |> to_string()
    |> String.downcase()
  end

  defp blank?(nil), do: true
  defp blank?(""), do: true
  defp blank?([]), do: true
  defp blank?(%{}), do: true
  defp blank?(_), do: false
end
