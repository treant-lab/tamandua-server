defmodule TamanduaServer.Workers.QuarantineWorker do
  @moduledoc """
  Executes quarantine actions for remediation workflows.

  Quarantine involves:
  1. Sending quarantine command to agent
  2. Moving malicious file to encrypted vault
  3. Recording action in audit trail

  This module is called by RemediationWorker, not as a standalone Oban worker.
  """

  require Logger

  alias TamanduaServer.Remediation.Workflow
  alias TamanduaServer.Response

  @doc """
  Execute quarantine action for a workflow.

  Returns {:ok, result} or {:error, reason}.
  """
  def execute(%Workflow{} = workflow, _args) do
    Logger.info("[QuarantineWorker] Executing quarantine for workflow #{workflow.id}")

    with {:ok, alert} <- get_alert(workflow.alert_id),
         {:ok, agent} <- get_agent(alert.agent_id),
         {:ok, action} <- create_response_action(workflow, alert, agent),
         :ok <- send_quarantine_command(agent, alert, workflow.action_config) do

      result = %{
        quarantined_at: DateTime.utc_now(),
        action: "quarantine",
        action_id: action.id,
        agent_id: agent.id,
        alert_id: alert.id,
        config: workflow.action_config
      }

      {:ok, result}
    end
  end

  defp get_alert(alert_id) do
    case TamanduaServer.Alerts.get_alert(alert_id) do
      {:ok, alert} -> {:ok, alert}
      {:error, _} -> {:error, :alert_not_found}
    end
  end

  defp get_agent(nil), do: {:error, :no_agent_associated}
  defp get_agent(agent_id) do
    case TamanduaServer.Agents.get_agent(agent_id) do
      nil -> {:error, :agent_not_found}
      agent -> {:ok, agent}
    end
  end

  defp create_response_action(workflow, alert, agent) do
    Response.create_action(%{
      agent_id: agent.id,
      alert_id: alert.id,
      action_type: "quarantine",
      status: "pending",
      requested_by: "policy_engine",
      metadata: %{
        workflow_id: workflow.id,
        policy_id: workflow.policy_id,
        execution_mode: workflow.execution_mode
      }
    })
  end

  defp send_quarantine_command(agent, alert, config) do
    # Extract target from alert evidence
    target = extract_quarantine_target(alert)

    command = %{
      type: "quarantine",
      target: target,
      create_backup: Map.get(config, "create_backup", true),
      notify_on_action: Map.get(config, "notify_on_action", true)
    }

    # Use existing Response.Executor to send command
    case TamanduaServer.Response.Executor.execute_action(agent.id, "quarantine", command) do
      {:ok, _} ->
        Logger.info("[QuarantineWorker] Quarantine command sent to agent #{agent.id}")
        :ok

      {:error, :agent_offline} ->
        # Queue for when agent comes online
        Logger.warning("[QuarantineWorker] Agent #{agent.id} offline, command queued")
        :ok  # Still consider this a success - command is queued

      {:error, reason} ->
        Logger.error("[QuarantineWorker] Failed to send quarantine command: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp extract_quarantine_target(alert) do
    evidence = alert.evidence || %{}

    cond do
      evidence["file_path"] -> %{type: "file", path: evidence["file_path"]}
      evidence["process_id"] -> %{type: "process", pid: evidence["process_id"]}
      evidence["hash"] -> %{type: "hash", value: evidence["hash"]}
      true -> %{type: "alert", alert_id: alert.id}
    end
  end
end
