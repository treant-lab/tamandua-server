defmodule TamanduaServer.SOAR.ExecutionEnvelope do
  @moduledoc """
  Normalizes execution results from the local playbook, DAG and external SOAR
  engines into one auditable contract.

  This module is deliberately pure: it does not approve, retry or roll back an
  execution. It records those controls without bypassing the engine that owns
  them.
  """

  @schema "tamandua.soar.execution/v1"
  @engines [:playbook, :dag, :soar]

  @type engine :: :playbook | :dag | :soar

  @spec wrap(engine(), {:ok, map()} | {:error, term()} | map(), keyword()) :: map()
  def wrap(engine, result, opts \\ [])

  def wrap(engine, result, opts) when engine in @engines do
    {outcome, execution} = unwrap(result)
    status = status(outcome, execution, opts)
    approval = approval(opts)
    idempotency_key = value(execution, :idempotency_key) || Keyword.get(opts, :idempotency_key)
    evidence = evidence(execution, opts)

    %{
      schema: @schema,
      engine: Atom.to_string(engine),
      execution_id: execution_id(execution, opts),
      playbook: value(execution, :playbook_name) || Keyword.get(opts, :playbook),
      target: target(execution, opts),
      status: status,
      dry_run: truthy?(value(execution, :dry_run)) || Keyword.get(opts, :dry_run, false),
      approval: approval,
      idempotency: %{
        key: idempotency_key,
        replay: Keyword.get(opts, :idempotency_replay, false),
        enforced: present?(idempotency_key)
      },
      retry: retry(execution, status, opts),
      rollback: rollback(execution, opts),
      evidence: evidence,
      error: error(outcome, execution),
      started_at: timestamp(value(execution, :started_at) || Keyword.get(opts, :started_at)),
      completed_at:
        timestamp(value(execution, :completed_at) || Keyword.get(opts, :completed_at)),
      controls: %{
        ready_to_execute: approval.status in ["approved", "not_required"],
        auditable: present?(idempotency_key) and evidence != []
      }
    }
  end

  def wrap(engine, _result, _opts) do
    raise ArgumentError, "unsupported SOAR execution engine: #{inspect(engine)}"
  end

  defp unwrap({:ok, execution}) when is_map(execution), do: {:ok, execution}

  defp unwrap({:ok, execution_id}) when is_binary(execution_id),
    do: {:ok, %{execution_id: execution_id}}

  defp unwrap({:error, reason}), do: {{:error, reason}, %{}}
  defp unwrap(execution) when is_map(execution), do: {:ok, execution}

  defp status({:error, _reason}, _execution, _opts), do: "failed"

  defp status(:ok, execution, opts) do
    cond do
      approval(opts).status == "pending" -> "pending_approval"
      truthy?(value(execution, :skipped)) -> "skipped"
      true -> normalize_status(value(execution, :status) || "completed")
    end
  end

  defp normalize_status(status) when status in [:pending_approval, "pending_approval"],
    do: "pending_approval"

  defp normalize_status(status) when status in [:pending, "pending", :queued, "queued"],
    do: "pending"

  defp normalize_status(status) when status in [:running, "running", :retrying, "retrying"],
    do: Atom.to_string(to_status_atom(status))

  defp normalize_status(status)
       when status in [:completed, "completed", :success, "success", :succeeded, "succeeded"],
       do: "completed"

  defp normalize_status(status) when status in [:failed, "failed", :error, "error"], do: "failed"

  defp normalize_status(status) when status in [:cancelled, "cancelled", :canceled, "canceled"],
    do: "cancelled"

  defp normalize_status(status) when is_atom(status), do: Atom.to_string(status)
  defp normalize_status(status) when is_binary(status), do: status
  defp normalize_status(_status), do: "unknown"

  defp to_status_atom(status) when is_atom(status), do: status
  defp to_status_atom("running"), do: :running
  defp to_status_atom("retrying"), do: :retrying

  defp approval(opts) do
    required = Keyword.get(opts, :approval_required, false)
    approved_by = Keyword.get(opts, :approved_by)
    rejected_by = Keyword.get(opts, :rejected_by)

    status =
      cond do
        present?(rejected_by) -> "rejected"
        not required -> "not_required"
        present?(approved_by) -> "approved"
        true -> "pending"
      end

    %{required: required, status: status, approved_by: approved_by, rejected_by: rejected_by}
  end

  defp retry(execution, status, opts) do
    attempt = value(execution, :retry_count) || Keyword.get(opts, :retry_count, 0)
    max_attempts = Keyword.get(opts, :max_retries, 0)

    %{
      attempt: attempt,
      max_attempts: max_attempts,
      retryable: status == "failed" and attempt < max_attempts,
      next_retry_at: timestamp(Keyword.get(opts, :next_retry_at))
    }
  end

  defp rollback(execution, opts) do
    policy = Keyword.get(opts, :rollback_policy, value(execution, :on_failure) || :none)
    result = value(execution, :rollback_result) || Keyword.get(opts, :rollback_result)

    %{
      policy: to_string(policy),
      available: policy not in [:none, "none", nil],
      status:
        if(present?(result),
          do: normalize_status(value(result, :status) || :completed),
          else: "not_started"
        ),
      result: result
    }
  end

  defp evidence(execution, opts) do
    action_results = value(execution, :results) || value(execution, :steps) || []

    action_results
    |> normalize_action_results()
    |> Kernel.++(List.wrap(Keyword.get(opts, :evidence, [])))
    |> Enum.with_index(1)
    |> Enum.map(fn {item, sequence} ->
      %{
        sequence: sequence,
        action: value(item, :action) || value(item, :id) || "execution",
        status: normalize_status(value(item, :status) || :completed),
        result: value(item, :result) || item,
        timestamp: timestamp(value(item, :timestamp) || value(item, :completed_at))
      }
    end)
  end

  defp normalize_action_results(results) when is_list(results), do: results

  defp normalize_action_results(results) when is_map(results) do
    Enum.map(results, fn {id, result} ->
      if is_map(result), do: Map.put_new(result, :id, id), else: %{id: id, result: result}
    end)
  end

  defp normalize_action_results(_results), do: []

  defp execution_id(execution, opts) do
    value(execution, :id) || value(execution, :execution_id) || Keyword.get(opts, :execution_id)
  end

  defp target(execution, opts) do
    %{
      agent_id: value(execution, :agent_id) || Keyword.get(opts, :agent_id),
      platform: value(execution, :platform) || Keyword.get(opts, :platform)
    }
  end

  defp error({:error, reason}, _execution), do: inspect(reason)
  defp error(:ok, execution), do: value(execution, :error_message) || value(execution, :error)

  defp value(value, key) when is_map(value),
    do: Map.get(value, key) || Map.get(value, Atom.to_string(key))

  defp value(_value, _key), do: nil

  defp timestamp(nil), do: nil
  defp timestamp(%DateTime{} = value), do: DateTime.to_iso8601(value)
  defp timestamp(%NaiveDateTime{} = value), do: NaiveDateTime.to_iso8601(value)
  defp timestamp(value) when is_binary(value), do: value
  defp timestamp(value), do: inspect(value)

  defp truthy?(value), do: value in [true, "true", 1]
  defp present?(nil), do: false
  defp present?(""), do: false
  defp present?(_value), do: true
end
