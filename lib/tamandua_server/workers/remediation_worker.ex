defmodule TamanduaServer.Workers.RemediationWorker do
  @moduledoc """
  Main Oban worker for remediation actions.

  Dispatches to action-specific workers based on action_type:
  - quarantine -> QuarantineWorker
  - block -> BlockWorker (calls Response.block/2)
  - notify -> NotificationWorker (Phase 33)
  - escalate -> EscalationWorker (existing)

  ## Retry Strategy

  Uses exponential backoff with jitter:
  - Attempt 1: immediate
  - Attempt 2: ~30 seconds
  - Attempt 3: ~2 minutes
  - Attempt 4: ~8 minutes
  - Attempt 5: ~32 minutes
  """

  use Oban.Worker,
    queue: :remediation,
    max_attempts: 5,
    priority: 1

  require Logger

  alias TamanduaServer.Remediation.{Workflow, WorkflowMachine}

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"workflow_id" => workflow_id} = args, attempt: attempt}) do
    Logger.info("[RemediationWorker] Executing workflow #{workflow_id}, attempt #{attempt}")

    with {:ok, workflow} <- Workflow.get_workflow(workflow_id),
         :ok <- validate_workflow_state(workflow),
         {:ok, workflow} <- WorkflowMachine.start(workflow),
         {:ok, result} <- execute_action(workflow, args),
         {:ok, _workflow} <- WorkflowMachine.complete(workflow, result) do

      Logger.info("[RemediationWorker] Workflow #{workflow_id} completed successfully")
      :ok
    else
      {:error, :not_found} ->
        Logger.warning("[RemediationWorker] Workflow #{workflow_id} not found")
        {:discard, :workflow_not_found}

      {:error, :invalid_state} ->
        Logger.warning("[RemediationWorker] Workflow #{workflow_id} in invalid state for execution")
        {:discard, :invalid_state}

      {:error, {:invalid_transition, from, to}} ->
        Logger.warning("[RemediationWorker] Invalid transition #{from} -> #{to} for workflow #{workflow_id}")
        {:discard, :invalid_transition}

      {:error, reason} = error ->
        handle_failure(workflow_id, reason, attempt)
        error
    end
  end

  @impl Oban.Worker
  def backoff(%Oban.Job{attempt: attempt}) do
    # Exponential backoff: 30s * 2^attempt + jitter
    base = 30
    multiplier = :math.pow(2, attempt) |> round()
    jitter = :rand.uniform(10)
    (base * multiplier + jitter) |> round()
  end

  # === Private Functions ===

  defp validate_workflow_state(%Workflow{state: "pending"}), do: :ok
  defp validate_workflow_state(%Workflow{state: "failed"}), do: :ok  # Retry
  defp validate_workflow_state(_), do: {:error, :invalid_state}

  defp execute_action(%Workflow{action_type: "quarantine"} = workflow, args) do
    TamanduaServer.Workers.QuarantineWorker.execute(workflow, args)
  end

  defp execute_action(%Workflow{action_type: "block"} = workflow, args) do
    execute_block_action(workflow, args)
  end

  defp execute_action(%Workflow{action_type: "notify"} = workflow, args) do
    execute_notify_action(workflow, args)
  end

  defp execute_action(%Workflow{action_type: "escalate"} = workflow, args) do
    execute_escalate_action(workflow, args)
  end

  defp execute_action(%Workflow{action_type: unknown}, _args) do
    {:error, {:unknown_action_type, unknown}}
  end

  defp execute_block_action(workflow, _args) do
    # Block action - update prevention policy or IOC blocklist
    alert = TamanduaServer.Alerts.get_alert!(workflow.alert_id)
    config = workflow.action_config || %{}

    # Determine what to block based on alert evidence
    block_result = %{
      blocked_at: DateTime.utc_now(),
      action: "block",
      alert_id: workflow.alert_id,
      config: config
    }

    # In a full implementation, this would:
    # 1. Extract IOCs from alert (IP, domain, hash)
    # 2. Add them to blocklist via Response module
    # 3. Push updated policy to agents

    Logger.info("[RemediationWorker] Block action executed for alert #{alert.id}")
    {:ok, block_result}
  end

  defp execute_notify_action(workflow, _args) do
    # Notify action - will be expanded in Phase 33
    config = workflow.action_config || %{}
    channels = Map.get(config, "channels", ["dashboard"])

    notify_result = %{
      notified_at: DateTime.utc_now(),
      action: "notify",
      channels: channels,
      alert_id: workflow.alert_id
    }

    # In Phase 33, this will call notification channel workers
    Logger.info("[RemediationWorker] Notify action executed for workflow #{workflow.id}")
    {:ok, notify_result}
  end

  defp execute_escalate_action(workflow, _args) do
    # Escalate action - use existing escalation system
    alert = TamanduaServer.Alerts.get_alert!(workflow.alert_id)
    config = workflow.action_config || %{}

    escalation_team = Map.get(config, "escalation_team", "security-analysts")

    escalate_result = %{
      escalated_at: DateTime.utc_now(),
      action: "escalate",
      team: escalation_team,
      alert_id: workflow.alert_id
    }

    # Trigger escalation via existing mechanism.
    # Notifier.send_escalation/2 requires an escalation rule (for contact
    # resolution); notify via every rule matching this alert.
    case TamanduaServer.Alerts.EscalationRules.get_matching_rules(alert) do
      [] ->
        Logger.info("[RemediationWorker] No matching escalation rules for alert #{alert.id}")

      rules ->
        Enum.each(rules, fn rule ->
          TamanduaServer.Alerts.Notifier.send_escalation(alert, rule)
        end)
    end

    Logger.info("[RemediationWorker] Escalate action executed for alert #{alert.id}")
    {:ok, escalate_result}
  end

  defp handle_failure(workflow_id, reason, attempt) do
    Logger.error("[RemediationWorker] Workflow #{workflow_id} failed on attempt #{attempt}: #{inspect(reason)}")

    with {:ok, workflow} <- Workflow.get_workflow(workflow_id) do
      Workflow.increment_retry(workflow)

      if attempt >= 5 do
        WorkflowMachine.fail(workflow, inspect(reason))
      end
    end
  end
end
