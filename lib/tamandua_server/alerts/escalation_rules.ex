defmodule TamanduaServer.Alerts.EscalationRules do
  @moduledoc """
  Alert escalation rule management and execution.

  Supports multi-tier escalation (L1 -> L2 -> L3 -> Manager) with configurable
  delays and conditions.

  ## Escalation Flow

  1. Alert is created
  2. Check if any escalation rules match
  3. If matched, schedule escalation job (via Oban)
  4. After escalation delay, check if alert is still unresolved
  5. If unresolved, escalate to next tier
  6. Repeat until resolved or all tiers exhausted

  ## Rule Conditions

  - Severity threshold (e.g., critical/high only)
  - MITRE technique/tactic matching
  - Agent/organization filtering
  - Time-based conditions (business hours, weekends)
  """

  use Ecto.Schema
  import Ecto.{Changeset, Query}
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert

  # This module is its own schema - use __MODULE__ for queries and struct matching
  alias __MODULE__, as: EscalationRule

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "escalation_rules" do
    field :name, :string
    field :description, :string
    field :enabled, :boolean, default: true

    # Matching conditions
    field :severity_filter, {:array, :string}, default: []  # ["critical", "high"]
    field :mitre_techniques, {:array, :string}, default: []
    field :mitre_tactics, {:array, :string}, default: []
    field :agent_ids, {:array, :binary_id}, default: []

    # Escalation configuration
    field :escalation_delay_minutes, :integer, default: 30
    field :escalate_to, {:array, :binary_id}, default: []  # User IDs to notify
    field :escalation_channels, {:array, :string}, default: ["email"]

    # Multi-tier escalation
    field :tiers, {:array, :map}, default: []
    # Example: [
    #   %{tier: 1, delay_minutes: 30, escalate_to: [user_id1], channels: ["email"]},
    #   %{tier: 2, delay_minutes: 60, escalate_to: [user_id2], channels: ["email", "sms"]},
    # ]

    # Business rules
    field :business_hours_only, :boolean, default: false
    field :business_hours_start, :time
    field :business_hours_end, :time
    field :business_days, {:array, :integer}, default: [1, 2, 3, 4, 5]  # Mon-Fri

    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :created_by, TamanduaServer.Accounts.User

    timestamps()
  end

  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [
      :name,
      :description,
      :enabled,
      :severity_filter,
      :mitre_techniques,
      :mitre_tactics,
      :agent_ids,
      :escalation_delay_minutes,
      :escalate_to,
      :escalation_channels,
      :tiers,
      :business_hours_only,
      :business_hours_start,
      :business_hours_end,
      :business_days,
      :organization_id,
      :created_by_id
    ])
    |> validate_required([:name, :escalation_delay_minutes])
    |> validate_number(:escalation_delay_minutes, greater_than: 0)
    |> validate_subset(:severity_filter, ["critical", "high", "medium", "low", "info"])
    |> validate_subset(:escalation_channels, ["email", "sms", "slack"])
  end

  # ===========================================================================
  # Public API
  # ===========================================================================

  @doc """
  Get all escalation rules matching an alert.

  Returns rules that:
  - Are enabled
  - Match the alert's severity (if filter is set)
  - Match the alert's MITRE techniques/tactics (if filter is set)
  - Match the alert's agent (if filter is set)
  """
  def get_matching_rules(%Alert{} = alert) do
    from(r in EscalationRule,
      where: r.enabled == true,
      order_by: [asc: r.escalation_delay_minutes]
    )
    |> filter_by_severity(alert.severity)
    |> filter_by_mitre(alert.mitre_techniques, alert.mitre_tactics)
    |> filter_by_agent(alert.agent_id)
    |> filter_by_organization(alert.organization_id)
    |> Repo.all()
  end

  @doc """
  Schedule an escalation for an alert.

  Creates an Oban job to check and escalate the alert after the configured delay.
  """
  def schedule_escalation(%Alert{} = alert, %EscalationRule{} = rule) do
    # Check if we should escalate now based on business hours
    if should_schedule_now?(rule) do
      delay_seconds = rule.escalation_delay_minutes * 60

      # Use multi-tier escalation if configured
      if rule.tiers && length(rule.tiers) > 0 do
        schedule_tiered_escalation(alert, rule)
      else
        schedule_single_escalation(alert, rule, delay_seconds)
      end
    else
      Logger.info(
        "[Escalation] Skipping escalation for alert #{alert.id} " <>
        "(rule #{rule.id}) - outside business hours"
      )
      {:ok, :skipped}
    end
  end

  @doc """
  Execute an escalation - check if alert is still unresolved and notify.

  This is called by the Oban worker after the escalation delay.
  """
  def execute_escalation(alert_id, rule_id, tier \\ 1) do
    with {:ok, alert} <- TamanduaServer.Alerts.get_alert(alert_id),
         {:ok, rule} <- get_rule(rule_id) do

      if alert_still_needs_escalation?(alert) do
        Logger.info(
          "[Escalation] Escalating alert #{alert_id} to tier #{tier} " <>
          "via rule #{rule_id}"
        )

        # Get escalation configuration for this tier
        tier_config = get_tier_config(rule, tier)

        # Send escalation notifications
        result = TamanduaServer.Alerts.Notifier.send_escalation(alert, tier_config)

        # Schedule next tier if available
        if has_next_tier?(rule, tier) do
          schedule_next_tier(alert, rule, tier + 1)
        end

        result
      else
        Logger.info(
          "[Escalation] Skipping escalation for alert #{alert_id} - " <>
          "already resolved or assigned"
        )
        {:ok, :not_needed}
      end
    else
      {:error, :not_found} ->
        Logger.warning("[Escalation] Alert or rule not found: #{alert_id}, #{rule_id}")
        {:error, :not_found}

      error ->
        error
    end
  end

  @doc """
  Create a new escalation rule.
  """
  def create_rule(attrs) do
    %EscalationRule{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update an escalation rule.
  """
  def update_rule(%EscalationRule{} = rule, attrs) do
    rule
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete an escalation rule.
  """
  def delete_rule(%EscalationRule{} = rule) do
    Repo.delete(rule)
  end

  @doc """
  Get a single escalation rule.
  """
  def get_rule(id) do
    case Repo.get(EscalationRule, id) do
      nil -> {:error, :not_found}
      rule -> {:ok, rule}
    end
  end

  @doc """
  List all escalation rules.
  """
  def list_rules(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    enabled_only = Keyword.get(opts, :enabled_only, false)

    query = from(r in EscalationRule, order_by: [asc: r.escalation_delay_minutes])

    query = if organization_id do
      from(r in query, where: r.organization_id == ^organization_id)
    else
      query
    end

    query = if enabled_only do
      from(r in query, where: r.enabled == true)
    else
      query
    end

    Repo.all(query)
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp filter_by_severity(query, severity) do
    from(r in query,
      where: fragment("array_length(?, 1) IS NULL", r.severity_filter) or
             ^severity in r.severity_filter
    )
  end

  defp filter_by_mitre(query, techniques, tactics) do
    from(r in query,
      where:
        (fragment("array_length(?, 1) IS NULL", r.mitre_techniques) or
         fragment("? && ?", r.mitre_techniques, ^(techniques || []))) or
        (fragment("array_length(?, 1) IS NULL", r.mitre_tactics) or
         fragment("? && ?", r.mitre_tactics, ^(tactics || [])))
    )
  end

  defp filter_by_agent(query, agent_id) do
    from(r in query,
      where: fragment("array_length(?, 1) IS NULL", r.agent_ids) or
             ^agent_id in r.agent_ids
    )
  end

  defp filter_by_organization(query, org_id) do
    from(r in query,
      where: is_nil(r.organization_id) or r.organization_id == ^org_id
    )
  end

  defp should_schedule_now?(%EscalationRule{business_hours_only: false}), do: true
  defp should_schedule_now?(%EscalationRule{} = rule) do
    now = DateTime.utc_now()
    day_of_week = Date.day_of_week(now)

    # Check if today is a business day
    day_ok = day_of_week in (rule.business_days || [1, 2, 3, 4, 5])

    # Check if current time is within business hours
    time_ok = if rule.business_hours_start && rule.business_hours_end do
      current_time = DateTime.to_time(now)
      Time.compare(current_time, rule.business_hours_start) in [:gt, :eq] and
      Time.compare(current_time, rule.business_hours_end) == :lt
    else
      true
    end

    day_ok and time_ok
  end

  defp schedule_single_escalation(alert, rule, delay_seconds) do
    %{
      alert_id: alert.id,
      rule_id: rule.id,
      tier: 1
    }
    |> TamanduaServer.Workers.EscalationWorker.new(schedule_in: delay_seconds)
    |> Oban.insert()
  end

  defp schedule_tiered_escalation(alert, rule) do
    # Schedule first tier
    first_tier = List.first(rule.tiers)
    delay_seconds = (first_tier["delay_minutes"] || first_tier[:delay_minutes]) * 60

    %{
      alert_id: alert.id,
      rule_id: rule.id,
      tier: 1
    }
    |> TamanduaServer.Workers.EscalationWorker.new(schedule_in: delay_seconds)
    |> Oban.insert()
  end

  defp schedule_next_tier(alert, rule, next_tier) do
    tier_config = Enum.at(rule.tiers, next_tier - 1)

    if tier_config do
      delay_seconds = (tier_config["delay_minutes"] || tier_config[:delay_minutes]) * 60

      %{
        alert_id: alert.id,
        rule_id: rule.id,
        tier: next_tier
      }
      |> TamanduaServer.Workers.EscalationWorker.new(schedule_in: delay_seconds)
      |> Oban.insert()
    end
  end

  defp alert_still_needs_escalation?(%Alert{} = alert) do
    # Don't escalate if:
    # - Alert is resolved
    # - Alert is false positive
    # - Alert is assigned to someone
    alert.status not in ["resolved", "false_positive"] and is_nil(alert.assigned_to_id)
  end

  defp get_tier_config(%EscalationRule{tiers: tiers}, tier) when is_list(tiers) and tier > 0 do
    Enum.at(tiers, tier - 1) || %{
      escalate_to: [],
      channels: ["email"]
    }
  end

  defp get_tier_config(%EscalationRule{} = rule, _tier) do
    # Fallback to simple escalation config
    %{
      escalate_to: rule.escalate_to,
      channels: rule.escalation_channels,
      id: rule.id,
      name: rule.name,
      created_by_id: rule.created_by_id
    }
  end

  defp has_next_tier?(%EscalationRule{tiers: tiers}, current_tier) when is_list(tiers) do
    length(tiers) > current_tier
  end
  defp has_next_tier?(_rule, _tier), do: false
end
