defmodule TamanduaServer.Alerts.EscalationEngine do
  @moduledoc """
  Enhanced escalation engine for alerts with auto-escalation and tiered routing.

  ## Auto-Escalation Triggers

  - Time-based: Not acknowledged in N minutes
  - Time-based: Not resolved in N hours
  - Severity-based: Critical alerts auto-escalate faster
  - SLA breach: Escalate when SLA is breached

  ## Escalation Chain

  L1 (Tier 1 Analyst) -> L2 (Senior Analyst) -> L3 (Team Lead) -> Manager

  ## Integration with SLA Tracker

  The escalation engine works closely with the SLA tracker to automatically
  escalate alerts that are approaching or have breached SLA deadlines.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.{Alert, EscalationRules, SLATracker, Assignment}
  import Ecto.Query

  @check_interval :timer.minutes(5) # Check every 5 minutes

  # ===========================================================================
  # GenServer Lifecycle
  # ===========================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    Logger.info("[EscalationEngine] Starting escalation engine")

    # Schedule first check
    schedule_check()

    {:ok, %{last_check: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:check_escalations, state) do
    Logger.debug("[EscalationEngine] Running escalation check")

    check_and_escalate_alerts()

    # Schedule next check
    schedule_check()

    {:noreply, %{state | last_check: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ===========================================================================
  # Public API
  # ===========================================================================

  @doc """
  Manually trigger escalation check (for testing or immediate execution).
  """
  def trigger_check do
    GenServer.cast(__MODULE__, :run_check)
  end

  @doc """
  Escalate a specific alert to the next tier.

  ## Options

  - `:escalated_by_id` - User ID triggering escalation (required for manual)
  - `:reason` - Reason for escalation
  - `:tier` - Target tier level (optional, auto-increments if not provided)
  """
  def escalate_alert(%Alert{} = alert, opts \\ []) do
    escalated_by_id = Keyword.get(opts, :escalated_by_id)
    reason = Keyword.get(opts, :reason, "Manual escalation")
    target_tier = Keyword.get(opts, :tier)

    current_tier = alert.escalation_level || 0
    next_tier = target_tier || current_tier + 1

    # Get escalation rules for this alert
    rules = EscalationRules.get_matching_rules(alert)

    if length(rules) > 0 do
      rule = List.first(rules)

      # Get escalation target for this tier
      tier_config = get_tier_config(rule, next_tier)

      if tier_config do
        perform_escalation(alert, next_tier, rule, tier_config, escalated_by_id, reason)
      else
        Logger.warning("[EscalationEngine] No tier #{next_tier} configuration for alert #{alert.id}")
        {:error, :no_tier_config}
      end
    else
      Logger.warning("[EscalationEngine] No escalation rules match alert #{alert.id}")
      {:error, :no_matching_rules}
    end
  end

  @doc """
  Auto-escalate unacknowledged alerts based on time thresholds.

  This is called periodically by the GenServer.
  """
  def auto_escalate_unacknowledged(threshold_minutes \\ 30) do
    cutoff_time = DateTime.utc_now()
    |> DateTime.add(-threshold_minutes * 60, :second)

    # Find unacknowledged critical/high alerts older than threshold
    alerts = from(a in Alert,
      where: a.severity in ["critical", "high"],
      where: a.inserted_at < ^cutoff_time,
      where: is_nil(a.acknowledged_at),
      where: a.workflow_state not in ["resolved", "false_positive", "closed"],
      where: a.escalation_level < 3, # Don't escalate beyond tier 3
      preload: [:assigned_to, :agent]
    )
    |> Repo.all()

    Logger.info("[EscalationEngine] Found #{length(alerts)} unacknowledged alerts for auto-escalation")

    Enum.each(alerts, fn alert ->
      escalate_alert(alert, reason: "Auto-escalated: not acknowledged within #{threshold_minutes} minutes")
    end)

    length(alerts)
  end

  @doc """
  Auto-escalate unresolved alerts based on time thresholds.
  """
  def auto_escalate_unresolved(threshold_hours \\ 4) do
    cutoff_time = DateTime.utc_now()
    |> DateTime.add(-threshold_hours * 60 * 60, :second)

    # Find unresolved critical alerts older than threshold
    alerts = from(a in Alert,
      where: a.severity == "critical",
      where: a.inserted_at < ^cutoff_time,
      where: is_nil(a.resolved_at),
      where: a.workflow_state not in ["resolved", "false_positive", "closed"],
      where: a.escalation_level < 3,
      preload: [:assigned_to, :agent]
    )
    |> Repo.all()

    Logger.info("[EscalationEngine] Found #{length(alerts)} unresolved critical alerts for auto-escalation")

    Enum.each(alerts, fn alert ->
      escalate_alert(alert, reason: "Auto-escalated: critical alert not resolved within #{threshold_hours} hours")
    end)

    length(alerts)
  end

  @doc """
  Escalate alerts that have breached SLA.
  """
  def escalate_sla_breached do
    # Find alerts with breached SLAs
    alerts = from(a in Alert,
      where: (a.sla_acknowledge_breached == true or a.sla_resolve_breached == true),
      where: a.workflow_state not in ["resolved", "false_positive", "closed"],
      where: a.escalation_level < 2, # Escalate breached alerts to at least tier 2
      preload: [:assigned_to, :agent]
    )
    |> Repo.all()

    Logger.info("[EscalationEngine] Found #{length(alerts)} SLA-breached alerts for escalation")

    Enum.each(alerts, fn alert ->
      breach_type = cond do
        alert.sla_acknowledge_breached and alert.sla_resolve_breached ->
          "acknowledge and resolve SLA breached"
        alert.sla_acknowledge_breached ->
          "acknowledge SLA breached"
        alert.sla_resolve_breached ->
          "resolve SLA breached"
        true ->
          "SLA breached"
      end

      escalate_alert(alert, reason: "Auto-escalated: #{breach_type}")
    end)

    length(alerts)
  end

  @doc """
  Get escalation statistics.
  """
  def get_escalation_stats(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    days = Keyword.get(opts, :days, 7)

    since = DateTime.utc_now() |> DateTime.add(-days * 24 * 60 * 60, :second)

    query = from(a in Alert,
      where: a.escalated_at >= ^since,
      group_by: a.escalation_level,
      select: {a.escalation_level, count(a.id)}
    )

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    results = Repo.all(query)

    %{
      total_escalations: Enum.sum(Enum.map(results, fn {_tier, count} -> count end)),
      by_tier: Enum.into(results, %{}),
      period_days: days
    }
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp schedule_check do
    Process.send_after(self(), :check_escalations, @check_interval)
  end

  defp check_and_escalate_alerts do
    # Check for SLA breaches
    sla_stats = SLATracker.check_sla_breaches()
    Logger.debug("[EscalationEngine] SLA check: #{inspect(sla_stats)}")

    # Auto-escalate based on different criteria
    unack_count = auto_escalate_unacknowledged(30) # 30 min for critical/high
    unresolved_count = auto_escalate_unresolved(4) # 4 hours for critical
    sla_count = escalate_sla_breached()

    Logger.info(
      "[EscalationEngine] Escalation check complete - " <>
      "Unacknowledged: #{unack_count}, Unresolved: #{unresolved_count}, SLA breached: #{sla_count}"
    )
  end

  defp perform_escalation(alert, tier, rule, tier_config, escalated_by_id, reason) do
    _now = DateTime.utc_now()

    # Determine escalation target user
    escalate_to_id = select_escalation_target(tier_config)

    Ecto.Multi.new()
    |> Ecto.Multi.update(:alert, update_alert_escalation(alert, tier, escalate_to_id, reason))
    |> Ecto.Multi.run(:reassign, fn _repo, %{alert: updated_alert} ->
      # Optionally reassign to escalation target
      if escalate_to_id && alert.assigned_to_id != escalate_to_id do
        Assignment.reassign(
          updated_alert,
          escalate_to_id,
          assigned_by_id: escalated_by_id || escalate_to_id,
          handoff_notes: "Escalated to tier #{tier}: #{reason}"
        )
      else
        {:ok, updated_alert}
      end
    end)
    |> Ecto.Multi.run(:transition_state, fn _repo, %{reassign: updated_alert} ->
      # Transition to escalated state if not already there
      if updated_alert.workflow_state != "escalated" do
        TamanduaServer.Alerts.Workflow.transition_state(
          updated_alert,
          "escalated",
          user_id: escalated_by_id || escalate_to_id || alert.assigned_to_id,
          reason: reason
        )
      else
        {:ok, updated_alert}
      end
    end)
    |> Ecto.Multi.run(:notify, fn _repo, %{transition_state: updated_alert} ->
      # Send escalation notifications
      send_escalation_notifications(updated_alert, rule)
      {:ok, updated_alert}
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{notify: updated_alert}} ->
        Logger.info("[EscalationEngine] Alert #{alert.id} escalated to tier #{tier}")
        {:ok, updated_alert}

      {:error, _operation, reason, _changes} ->
        Logger.error("[EscalationEngine] Failed to escalate alert #{alert.id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp update_alert_escalation(alert, tier, escalate_to_id, reason) do
    alert
    |> Ecto.Changeset.change(%{
      escalation_level: tier,
      escalated_at: DateTime.utc_now(),
      escalated_to_id: escalate_to_id,
      escalation_reason: reason
    })
  end

  defp get_tier_config(rule, tier) do
    if rule.tiers && length(rule.tiers) > 0 do
      Enum.at(rule.tiers, tier - 1)
    else
      # Fallback to simple config
      %{
        "escalate_to" => rule.escalate_to,
        "channels" => rule.escalation_channels
      }
    end
  end

  defp select_escalation_target(tier_config) do
    escalate_to = tier_config["escalate_to"] || tier_config[:escalate_to] || []

    if is_list(escalate_to) and length(escalate_to) > 0 do
      # For now, just pick the first target
      # Could be enhanced to use round-robin or least-busy logic
      List.first(escalate_to)
    else
      nil
    end
  end

  # Notifier.send_escalation/2 resolves contacts from the EscalationRule
  # (rule.id / rule.created_by_id); passing a bare tier-config map here was a
  # latent KeyError. The matching rule is already resolved in escalate_alert/2,
  # so thread it through instead of re-querying.
  defp send_escalation_notifications(alert, rule) do
    TamanduaServer.Alerts.Notifier.send_escalation(alert, rule)
  end

  @impl true
  def handle_cast(:run_check, state) do
    check_and_escalate_alerts()
    {:noreply, state}
  end
end
