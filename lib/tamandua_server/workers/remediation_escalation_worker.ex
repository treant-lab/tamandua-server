defmodule TamanduaServer.Workers.RemediationEscalationWorker do
  @moduledoc """
  Oban worker for remediation workflow escalation timeout checks.

  Runs on a schedule (every 5 minutes via Oban cron) to find pending
  approval workflows that have exceeded their escalation timeout.

  ## Escalation Tiers

  1. `analyst` - Initial tier, default timeout
  2. `senior_analyst` - First escalation
  3. `manager` - Second escalation
  4. `security_director` - Final tier, auto-reject if exceeded

  ## Behavior

  When a workflow exceeds its escalation timeout:
  - If not at max tier: Increment escalation_level, notify higher-tier approvers
  - If at max tier (security_director): Auto-reject the workflow
  """

  use Oban.Worker,
    queue: :remediation,
    max_attempts: 3,
    priority: 2

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Remediation.{Workflow, AuditTrail, Notifier}
  import Ecto.Query

  @escalation_tiers ["analyst", "senior_analyst", "manager", "security_director"]

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    Logger.info("[RemediationEscalationWorker] Starting escalation check")
    now = DateTime.utc_now()

    stale_workflows = find_stale_workflows(now)
    Logger.info("[RemediationEscalationWorker] Found #{length(stale_workflows)} stale workflows")

    Enum.each(stale_workflows, fn workflow ->
      try do
        escalate_workflow(workflow, now)
      rescue
        e ->
          Logger.error("[RemediationEscalationWorker] Failed to escalate workflow #{workflow.id}: #{inspect(e)}")
      end
    end)

    :ok
  end

  @doc """
  Find workflows pending approval that have exceeded their escalation timeout.
  """
  def find_stale_workflows(now) do
    from(w in Workflow,
      where: w.state == "pending",
      where: w.execution_mode == "pending_approval",
      preload: [:alert, :policy, :organization]
    )
    |> Repo.all()
    |> Enum.filter(fn workflow ->
      is_past_escalation_deadline?(workflow, now)
    end)
  end

  defp is_past_escalation_deadline?(workflow, now) do
    timeout_minutes = get_escalation_timeout(workflow)
    reference_time = workflow.last_escalated_at || workflow.inserted_at

    case reference_time do
      nil ->
        false

      ref ->
        deadline = DateTime.add(ref, timeout_minutes * 60, :second)
        DateTime.compare(now, deadline) == :gt
    end
  end

  defp get_escalation_timeout(workflow) do
    # Try workflow field first, then policy, then default
    cond do
      workflow.escalation_timeout_minutes && workflow.escalation_timeout_minutes > 0 ->
        workflow.escalation_timeout_minutes

      workflow.policy && workflow.policy.escalation_timeout_minutes &&
          workflow.policy.escalation_timeout_minutes > 0 ->
        workflow.policy.escalation_timeout_minutes

      true ->
        60  # Default: 60 minutes
    end
  end

  defp escalate_workflow(workflow, _now) do
    current_level = workflow.escalation_level || 0
    current_tier = Enum.at(@escalation_tiers, current_level, "analyst")
    next_level = current_level + 1

    if next_level >= length(@escalation_tiers) do
      # Max escalation reached - auto-reject
      handle_max_escalation(workflow, current_tier)
    else
      # Escalate to next tier
      next_tier = Enum.at(@escalation_tiers, next_level)
      handle_escalation(workflow, current_tier, next_tier, next_level)
    end
  end

  defp handle_max_escalation(workflow, current_tier) do
    Logger.warning("[RemediationEscalationWorker] Max escalation reached for workflow #{workflow.id}, auto-rejecting")

    reason = "Auto-rejected: escalation timeout exceeded at #{current_tier} level"

    case Workflow.reject_workflow(workflow.id, "system", reason) do
      {:ok, updated} ->
        # Log auto-rejection audit event
        AuditTrail.log_event(updated, :auto_rejected, :system, %{
          reason: "max_escalation_reached",
          final_tier: current_tier,
          escalation_level: workflow.escalation_level
        })

        Logger.info("[RemediationEscalationWorker] Auto-rejected workflow #{workflow.id}")

      {:error, reason} ->
        Logger.error("[RemediationEscalationWorker] Failed to auto-reject workflow #{workflow.id}: #{inspect(reason)}")
    end
  end

  defp handle_escalation(workflow, current_tier, next_tier, next_level) do
    Logger.info("[RemediationEscalationWorker] Escalating workflow #{workflow.id} from #{current_tier} to #{next_tier}")

    # Update workflow escalation fields
    workflow
    |> Workflow.changeset(%{
      escalation_level: next_level,
      last_escalated_at: DateTime.utc_now()
    })
    |> Repo.update()
    |> case do
      {:ok, updated} ->
        # Log escalation audit event
        AuditTrail.log_event(updated, :escalated, :system, %{
          from_tier: current_tier,
          to_tier: next_tier,
          escalation_level: next_level
        })

        # Send escalation notification
        notify_escalation(updated, next_tier)

        Logger.info("[RemediationEscalationWorker] Escalated workflow #{workflow.id} to #{next_tier}")

      {:error, reason} ->
        Logger.error("[RemediationEscalationWorker] Failed to escalate workflow #{workflow.id}: #{inspect(reason)}")
    end
  end

  defp notify_escalation(workflow, tier) do
    Task.start(fn ->
      try do
        Notifier.notify_escalation(workflow, tier)
      rescue
        e ->
          Logger.error("[RemediationEscalationWorker] Failed to send escalation notification: #{inspect(e)}")
      end
    end)
  end

  @doc "Get escalation tiers"
  def escalation_tiers, do: @escalation_tiers
end
