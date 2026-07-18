defmodule TamanduaServer.Workers.ApprovalExecutionReconcilerWorker do
  @moduledoc "Marks an expired approval execution for human reconciliation; never executes responses."

  use Oban.Worker, queue: :default, max_attempts: 3

  alias TamanduaServer.AISecurity.ApprovalExecutions

  @impl Oban.Worker
  def perform(%Oban.Job{
        args: %{"organization_id" => organization_id, "execution_id" => execution_id}
      }) do
    case ApprovalExecutions.mark_stale(organization_id, execution_id) do
      {:ok, _execution} -> :ok
      {:error, :not_found} -> {:discard, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end
end
