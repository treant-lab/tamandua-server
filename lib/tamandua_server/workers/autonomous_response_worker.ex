defmodule TamanduaServer.Workers.AutonomousResponseWorker do
  @moduledoc """
  Executes a durably claimed autonomous-response recommendation outside the
  DecisionEngine singleton.

  Jobs are unique by their full args for 24 hours. Endpoint commands carry a
  separate deterministic idempotency key, so an Oban retry cannot redispatch a
  completed action.
  """

  use Oban.Worker,
    queue: :default,
    max_attempts: 5,
    unique: [
      period: 86_400,
      fields: [:worker, :args],
      keys: [:recommendation_id, :organization_id]
    ]

  alias TamanduaServer.Response.DecisionEngine

  @impl Oban.Worker
  def perform(%Oban.Job{
        id: job_id,
        attempt: attempt,
        max_attempts: max_attempts,
        args: %{
          "recommendation_id" => recommendation_id,
          "organization_id" => organization_id,
          "mode" => mode
        } = args
      }) do
    approver_id = args["approver_id"]

    mode = normalize_mode(mode)

    result =
      DecisionEngine.execute_queued_recommendation(
        recommendation_id,
        organization_id,
        approver_id,
        mode
      )

    if match?({:error, _reason}, result) and final_attempt?(attempt, max_attempts) do
      {:error, reason} = result

      case DecisionEngine.reconcile_exhausted_recommendation(
             recommendation_id,
             organization_id,
             job_id,
             attempt,
             sanitized_error(reason)
           ) do
        :ok -> result
        {:error, reconcile_reason} -> {:error, {:final_reconciliation_failed, reconcile_reason, reason}}
      end
    else
      result
    end
  end

  defp normalize_mode(mode) when mode in ["auto", "autonomous"], do: "auto_executed"
  defp normalize_mode(mode) when mode in ["manual", "approved"], do: "approved"
  defp normalize_mode(mode), do: mode

  defp final_attempt?(attempt, max_attempts)
       when is_integer(attempt) and is_integer(max_attempts),
       do: attempt >= max_attempts

  defp final_attempt?(_attempt, _max_attempts), do: false

  defp sanitized_error({outer, {inner, _detail}}) when is_atom(outer) and is_atom(inner),
    do: "#{outer}:#{inner}"

  defp sanitized_error({outer, inner}) when is_atom(outer) and is_atom(inner),
    do: "#{outer}:#{inner}"

  defp sanitized_error({outer, _detail}) when is_atom(outer), do: Atom.to_string(outer)
  defp sanitized_error({outer, _detail, _context}) when is_atom(outer), do: Atom.to_string(outer)
  defp sanitized_error(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp sanitized_error(%{__struct__: module}) when is_atom(module), do: inspect(module)
  defp sanitized_error(_reason), do: "execution_error"
end
