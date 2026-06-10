defmodule TamanduaServer.Detection.Exclusions do
  @moduledoc """
  Context module for managing exclusion rules.

  Provides functions for creating, listing, and applying exclusion rules
  to suppress or tune alert generation.
  """

  import Ecto.Query, warn: false
  alias TamanduaServer.Repo
  alias TamanduaServer.TenantScope
  alias TamanduaServer.Detection.ExclusionRule

  # ===========================================================================
  # CRUD Operations
  # ===========================================================================

  @doc """
  Lists all exclusion rules for an organization.
  """
  def list_rules(organization_id, opts \\ []) do
    query =
      ExclusionRule
      |> TenantScope.scope_to_tenant(organization_id)
      |> order_by([r], [desc: r.inserted_at])

    query = if Keyword.get(opts, :enabled_only, false) do
      where(query, [r], r.enabled == true)
    else
      query
    end

    query = if rule_type = Keyword.get(opts, :rule_type) do
      where(query, [r], r.rule_type == ^rule_type)
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Gets a single exclusion rule.
  """
  def get_rule(id) do
    case Repo.get(ExclusionRule, id) do
      nil -> {:error, :not_found}
      rule -> {:ok, rule}
    end
  end

  @doc """
  Gets a single exclusion rule, raising if not found.
  """
  def get_rule!(id), do: Repo.get!(ExclusionRule, id)

  @doc """
  Gets an exclusion rule scoped to an organization.
  """
  def get_rule_for_org(organization_id, rule_id) do
    case TenantScope.get_scoped(ExclusionRule, organization_id, rule_id) do
      nil -> {:error, :not_found}
      rule -> {:ok, rule}
    end
  end

  @doc """
  Creates a new exclusion rule.
  """
  def create_rule(attrs) do
    %ExclusionRule{}
    |> ExclusionRule.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Creates a new exclusion rule for an organization.
  """
  def create_rule_for_org(organization_id, attrs) do
    attrs = Map.put(attrs, :organization_id, organization_id)
    create_rule(attrs)
  end

  @doc """
  Updates an exclusion rule.
  """
  def update_rule(%ExclusionRule{} = rule, attrs) do
    rule
    |> ExclusionRule.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes an exclusion rule.
  """
  def delete_rule(%ExclusionRule{} = rule) do
    Repo.delete(rule)
  end

  @doc """
  Toggles an exclusion rule's enabled status.
  """
  def toggle_rule(%ExclusionRule{} = rule) do
    update_rule(rule, %{enabled: !rule.enabled})
  end

  # ===========================================================================
  # Rule Matching
  # ===========================================================================

  @doc """
  Checks if an event should be excluded based on active rules.

  Returns `{:exclude, rule}` if matched, `{:allow, nil}` otherwise.
  """
  def check_event(organization_id, event) do
    rules = list_rules(organization_id, enabled_only: true)

    case Enum.find(rules, &ExclusionRule.matches?(&1, event)) do
      nil -> {:allow, nil}
      rule ->
        # Update match stats asynchronously
        Task.start(fn -> increment_match_count(rule) end)
        {:exclude, rule}
    end
  end

  @doc """
  Checks if an alert should be excluded or tuned.

  Returns:
  - `{:exclude, rule}` - Alert should be suppressed
  - `{:tune, rule, new_severity}` - Alert severity should be adjusted
  - `{:allow, nil}` - No matching rule
  """
  def check_alert(organization_id, alert_attrs) do
    rules = list_rules(organization_id, enabled_only: true)

    case Enum.find(rules, &ExclusionRule.matches?(&1, alert_attrs)) do
      nil ->
        {:allow, nil}

      %{rule_type: "whitelist"} = rule ->
        Task.start(fn -> increment_match_count(rule) end)
        {:exclude, rule}

      %{rule_type: "suppress"} = rule ->
        Task.start(fn -> increment_match_count(rule) end)
        {:exclude, rule}

      %{rule_type: "tune", adjust_severity: new_severity} = rule when not is_nil(new_severity) ->
        Task.start(fn -> increment_match_count(rule) end)
        {:tune, rule, new_severity}

      %{rule_type: "tune"} = rule ->
        Task.start(fn -> increment_match_count(rule) end)
        {:allow, rule}
    end
  end

  @doc """
  Increments the match count for a rule.
  """
  def increment_match_count(%ExclusionRule{id: id}) do
    from(r in ExclusionRule,
      where: r.id == ^id,
      update: [
        inc: [match_count: 1],
        set: [last_matched_at: ^DateTime.utc_now()]
      ]
    )
    |> Repo.update_all([])
  end

  # ===========================================================================
  # Rule Creation from Alerts
  # ===========================================================================

  @doc """
  Creates an exclusion rule from an alert's attributes.

  This is used when an analyst wants to suppress similar alerts.
  """
  def create_rule_from_alert(alert, opts \\ []) do
    rule_type = Keyword.get(opts, :rule_type, "suppress")
    name = Keyword.get(opts, :name, "Rule from alert: #{alert.title}")
    created_by_id = Keyword.get(opts, :created_by_id)
    expires_in_days = Keyword.get(opts, :expires_in_days)

    # Build criteria from alert evidence
    criteria = build_criteria_from_alert(alert, opts)

    attrs = %{
      name: name,
      description: "Auto-generated from alert #{alert.id}",
      rule_type: rule_type,
      criteria: criteria,
      organization_id: alert.organization_id,
      created_by_id: created_by_id,
      enabled: true
    }

    # Add expiration if specified
    attrs = if expires_in_days do
      expires_at = DateTime.utc_now() |> DateTime.add(expires_in_days * 24 * 60 * 60, :second)
      Map.put(attrs, :expires_at, expires_at)
    else
      attrs
    end

    # Add severity adjustment for tune rules
    attrs = if rule_type == "tune" do
      case Keyword.get(opts, :adjust_severity) do
        nil -> attrs
        new_severity -> Map.put(attrs, :adjust_severity, new_severity)
      end
    else
      attrs
    end

    create_rule(attrs)
  end

  defp build_criteria_from_alert(alert, opts) do
    match_fields = Keyword.get(opts, :match_fields, [:rule_name, :agent_id])
    criteria = %{}

    criteria = if :rule_name in match_fields do
      case get_in(alert.detection_metadata || %{}, [:rule_name]) ||
           get_in(alert.detection_metadata || %{}, ["rule_name"]) do
        nil -> criteria
        rule_name -> Map.put(criteria, "detection_metadata.rule_name", rule_name)
      end
    else
      criteria
    end

    criteria = if :agent_id in match_fields and alert.agent_id do
      Map.put(criteria, "agent_id", alert.agent_id)
    else
      criteria
    end

    criteria = if :severity in match_fields and alert.severity do
      Map.put(criteria, "severity", alert.severity)
    else
      criteria
    end

    # Extract process hash if available
    criteria = if :hash in match_fields do
      case get_in(alert.evidence || %{}, [:process, :sha256]) ||
           get_in(alert.evidence || %{}, ["process", "sha256"]) do
        nil -> criteria
        hash -> Map.put(criteria, "evidence.process.sha256", hash)
      end
    else
      criteria
    end

    # Extract path if available
    criteria = if :path in match_fields do
      case get_in(alert.evidence || %{}, [:process, :path]) ||
           get_in(alert.evidence || %{}, ["process", "path"]) do
        nil -> criteria
        path -> Map.put(criteria, "evidence.process.path", path)
      end
    else
      criteria
    end

    criteria
  end

  # ===========================================================================
  # Statistics
  # ===========================================================================

  @doc """
  Gets statistics about exclusion rules for an organization.
  """
  def get_stats(organization_id) do
    rules = list_rules(organization_id)

    %{
      total: length(rules),
      enabled: Enum.count(rules, & &1.enabled),
      disabled: Enum.count(rules, &(!&1.enabled)),
      by_type: Enum.group_by(rules, & &1.rule_type) |> Enum.map(fn {k, v} -> {k, length(v)} end) |> Map.new(),
      total_matches: Enum.sum(Enum.map(rules, & &1.match_count)),
      recently_matched: Enum.count(rules, fn r ->
        r.last_matched_at && DateTime.diff(DateTime.utc_now(), r.last_matched_at, :hour) < 24
      end)
    }
  end
end
