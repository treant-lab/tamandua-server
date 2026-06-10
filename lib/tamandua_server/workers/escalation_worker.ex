defmodule TamanduaServer.Workers.EscalationWorker do
  @moduledoc """
  Oban worker for executing alert escalations.

  Handles delayed escalation of unresolved alerts according to
  escalation rules. Supports multi-tier escalation with progressive
  notification.
  """

  use Oban.Worker,
    queue: :escalations,
    max_attempts: 3

  require Logger

  alias TamanduaServer.Alerts.EscalationRules

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"alert_id" => alert_id, "rule_id" => rule_id} = args}) do
    tier = Map.get(args, "tier", 1)

    Logger.info("[EscalationWorker] Processing escalation for alert #{alert_id}, tier #{tier}")

    case EscalationRules.execute_escalation(alert_id, rule_id, tier) do
      {:ok, _result} ->
        :ok

      {:error, :not_needed} ->
        Logger.info("[EscalationWorker] Escalation not needed for alert #{alert_id}")
        :ok

      {:error, :not_found} ->
        Logger.warning("[EscalationWorker] Alert or rule not found: #{alert_id}, #{rule_id}")
        {:discard, :not_found}

      {:error, reason} = error ->
        Logger.error("[EscalationWorker] Escalation failed: #{inspect(reason)}")
        error
    end
  end
end
