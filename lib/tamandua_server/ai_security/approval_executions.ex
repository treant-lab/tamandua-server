defmodule TamanduaServer.AISecurity.ApprovalExecutions do
  @moduledoc """
  Atomic reservation and durable outcome boundary for approved AI response actions.

  The unique tenant/investigation/recommendation tuple is the execution fence.
  Once reserved, retries only observe the persisted state and never claim the
  same response action a second time.
  """

  import Ecto.Query

  alias Ecto.Multi
  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.AISecurity.ApprovalExecution
  alias TamanduaServer.Agents.{Agent, AgentCommand}
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Workers.ApprovalExecutionReconcilerWorker

  @lease_seconds 300

  # Approval action names are deliberately mapped to the exact persisted
  # AgentCommand wire types that can evidence them. Do not fall back to a
  # caller-controlled or fuzzy comparison: a newly introduced response action
  # must explicitly define its evidence contract here before it can be
  # reconciled.
  @action_command_types %{
    "isolate_network" => ["isolate_network"],
    "kill_process" => ["kill_process"],
    "quarantine_file" => ["quarantine_file"],
    "block_remote_access" => ["block_remote_access"],
    "force_password_reset" => ["force_password_reset"],
    "collect_forensics" => ["collect_forensics"]
  }

  @type reservation ::
          {:execute, ApprovalExecution.t()}
          | {:in_progress, ApprovalExecution.t()}
          | {:succeeded, ApprovalExecution.t()}
          | {:failed, ApprovalExecution.t()}

  @spec reserve_and_claim(String.t(), map()) :: {:ok, reservation()} | {:error, term()}
  def reserve_and_claim(organization_id, attrs) when is_map(attrs) do
    with :ok <- valid_uuid(organization_id, :invalid_organization_id),
         :ok <- valid_uuid(attrs[:approver_id], :invalid_approver_id),
         :ok <- required_binary(attrs[:investigation_id], :invalid_investigation_id),
         :ok <- required_binary(attrs[:recommendation_id], :invalid_recommendation_id),
         :ok <- required_binary(attrs[:action_type], :invalid_action_type) do
      idempotency_key =
        idempotency_key(
          organization_id,
          attrs.investigation_id,
          attrs.recommendation_id
        )

      Multi.new()
      |> Multi.run(:approver, fn repo, _changes ->
        authorize_approver(repo, organization_id, attrs.approver_id)
      end)
      |> Multi.run(:target_agent, fn repo, _changes ->
        validate_target_agent(repo, organization_id, Map.get(attrs, :target, %{}))
      end)
      |> Multi.run(:reservation, fn repo, _changes ->
        reserve(repo, organization_id, attrs, idempotency_key)
      end)
      |> Multi.run(:reconciliation_job, fn repo, %{reservation: reservation} ->
        schedule_reconciliation(repo, organization_id, reservation)
      end)
      |> then(&MultiTenant.transaction(organization_id, &1))
      |> case do
        {:ok, %{reservation: reservation}} -> {:ok, reservation}
        {:error, _step, reason, _changes} -> {:error, reason}
      end
    end
  end

  def reserve_and_claim(_organization_id, _attrs), do: {:error, :invalid_attributes}

  @spec succeed(String.t(), String.t(), term()) :: {:ok, ApprovalExecution.t()} | {:error, term()}
  def succeed(organization_id, execution_id, result) do
    persist_outcome(organization_id, execution_id, "succeeded", %{result: json_object(result)})
  end

  @spec fail(String.t(), String.t(), term()) :: {:ok, ApprovalExecution.t()} | {:error, term()}
  def fail(organization_id, execution_id, error) do
    persist_outcome(organization_id, execution_id, "failed", %{
      error: %{"reason" => inspect(error)}
    })
  end

  def status(organization_id, execution_id) do
    case get(organization_id, execution_id) do
      %ApprovalExecution{} = execution -> {:ok, serialize_status(execution)}
      nil -> {:error, :not_found}
    end
  end

  @spec list_reconciliation_required(String.t(), keyword()) ::
          {:ok, [map()]} | {:error, term()}
  def list_reconciliation_required(organization_id, opts \\ []) do
    with :ok <- valid_uuid(organization_id, :invalid_organization_id) do
      limit = opts |> Keyword.get(:limit, 50) |> clamp_limit(1, 200)

      executions =
        MultiTenant.with_organization(organization_id, fn ->
          Repo.all(
            from(execution in ApprovalExecution,
              where:
                execution.organization_id == ^organization_id and
                  execution.status == "reconciliation_required",
              order_by: [asc: execution.lease_expires_at, asc: execution.inserted_at],
              limit: ^limit
            )
          )
        end)

      {:ok, Enum.map(executions, &serialize_reconciliation/1)}
    end
  rescue
    _error -> {:error, :persistence_unavailable}
  catch
    :exit, _reason -> {:error, :persistence_unavailable}
  end

  def mark_stale(organization_id, execution_id, now \\ DateTime.utc_now()) do
    transition(organization_id, execution_id, fn repo, execution ->
      cond do
        execution.status != "running" ->
          {:ok, execution}

        is_nil(execution.lease_expires_at) or
            DateTime.compare(execution.lease_expires_at, now) == :gt ->
          {:ok, execution}

        true ->
          execution
          |> ApprovalExecution.stale_changeset(%{
            status: "reconciliation_required",
            completed_at: now
          })
          |> repo.update()
      end
    end)
  end

  def reconcile(organization_id, execution_id, reconciler_id, outcome, evidence_ref)
      when outcome in ["succeeded", "failed"] do
    with :ok <- valid_uuid(reconciler_id, :invalid_reconciler_id),
         {:ok, evidence} <- normalize_evidence_ref(evidence_ref) do
      transition(organization_id, execution_id, fn repo, execution ->
        with true <- execution.status == "reconciliation_required",
             true <- approver_authorized?(repo, organization_id, reconciler_id),
             {:ok, evidence_fact} <-
               validate_evidence(repo, organization_id, execution, outcome, evidence) do
          now = DateTime.utc_now()

          reconciliation = %{
            "reconciled" => true,
            "evidence_ref" => evidence.typed,
            "evidence_fact" => evidence_fact
          }

          outcome_attrs =
            if outcome == "succeeded" do
              %{result: reconciliation, error: nil}
            else
              %{error: reconciliation, result: nil}
            end

          execution
          |> ApprovalExecution.reconciliation_changeset(
            Map.merge(outcome_attrs, %{
              status: outcome,
              completed_at: now,
              reconciled_by_id: reconciler_id,
              reconciled_at: now,
              reconciliation_evidence_ref: evidence.canonical
            })
          )
          |> repo.update()
          |> normalize_evidence_fence_error()
        else
          false -> {:error, :unauthorized_or_invalid_transition}
          {:error, _reason} -> {:error, :invalid_evidence_ref}
        end
      end)
    end
  end

  def reconcile(_organization_id, _execution_id, _reconciler_id, _outcome, _evidence_ref),
    do: {:error, :invalid_reconciliation}

  @spec get(String.t(), String.t()) :: ApprovalExecution.t() | nil
  def get(organization_id, execution_id) do
    with :ok <- valid_uuid(organization_id, :invalid_organization_id),
         :ok <- valid_uuid(execution_id, :invalid_execution_id) do
      MultiTenant.with_organization(organization_id, fn ->
        Repo.one(
          from(execution in ApprovalExecution,
            where: execution.organization_id == ^organization_id and execution.id == ^execution_id
          )
        )
      end)
    else
      _ -> nil
    end
  end

  defp reserve(repo, organization_id, attrs, idempotency_key) do
    now = DateTime.utc_now()
    execution_id = Ecto.UUID.generate()

    row = %{
      id: execution_id,
      organization_id: organization_id,
      investigation_id: attrs.investigation_id,
      recommendation_id: attrs.recommendation_id,
      approver_id: attrs.approver_id,
      idempotency_key: idempotency_key,
      status: "pending",
      action_type: attrs.action_type,
      target: json_object(Map.get(attrs, :target, %{})),
      lease_expires_at: DateTime.add(now, @lease_seconds, :second),
      inserted_at: now,
      updated_at: now
    }

    case repo.insert_all(ApprovalExecution, [row],
           on_conflict: :nothing,
           conflict_target: [:organization_id, :investigation_id, :recommendation_id]
         ) do
      {1, _} -> claim_inserted(repo, organization_id, execution_id, now)
      {0, _} -> existing_reservation(repo, organization_id, attrs)
    end
  end

  defp authorize_approver(repo, organization_id, approver_id) do
    case scoped_user(repo, organization_id, approver_id) do
      %User{} = user ->
        if Accounts.user_can?(user, :response_approve),
          do: {:ok, approver_id},
          else: {:error, :unauthorized}

      nil ->
        {:error, :unauthorized}
    end
  end

  defp validate_target_agent(repo, organization_id, target) when is_map(target) do
    agent_id = Map.get(target, "agent_id") || Map.get(target, :agent_id)

    with :ok <- bounded_binary(agent_id, 64, :invalid_target_agent),
         {:ok, normalized_id} <- Ecto.UUID.cast(agent_id),
         %Agent{} <-
           repo.one(
             from(agent in Agent,
               where: agent.id == ^normalized_id and agent.organization_id == ^organization_id
             )
           ) do
      {:ok, normalized_id}
    else
      _ -> {:error, :invalid_target_agent}
    end
  end

  defp validate_target_agent(_repo, _organization_id, _target),
    do: {:error, :invalid_target_agent}

  defp claim_inserted(repo, organization_id, execution_id, now) do
    query =
      from(execution in ApprovalExecution,
        where:
          execution.organization_id == ^organization_id and execution.id == ^execution_id and
            execution.status == "pending"
      )

    case repo.update_all(query, set: [status: "running", started_at: now, updated_at: now]) do
      {1, _} -> {:ok, {:execute, scoped_get!(repo, organization_id, execution_id)}}
      _ -> {:error, :reservation_claim_failed}
    end
  end

  defp existing_reservation(repo, organization_id, attrs) do
    execution =
      repo.one(
        from(execution in ApprovalExecution,
          where:
            execution.organization_id == ^organization_id and
              execution.investigation_id == ^attrs.investigation_id and
              execution.recommendation_id == ^attrs.recommendation_id
        )
      )

    case execution do
      %ApprovalExecution{status: "succeeded"} = record -> {:ok, {:succeeded, record}}
      %ApprovalExecution{status: "failed"} = record -> {:ok, {:failed, record}}
      %ApprovalExecution{status: "reconciliation_required"} = record -> {:ok, {:failed, record}}
      %ApprovalExecution{} = record -> {:ok, {:in_progress, record}}
      nil -> {:error, :reservation_conflict_not_visible}
    end
  end

  defp persist_outcome(organization_id, execution_id, status, outcome) do
    with :ok <- valid_uuid(organization_id, :invalid_organization_id),
         :ok <- valid_uuid(execution_id, :invalid_execution_id) do
      Multi.new()
      |> Multi.run(:execution, fn repo, _changes ->
        case repo.one(
               from(execution in ApprovalExecution,
                 where:
                   execution.organization_id == ^organization_id and
                     execution.id == ^execution_id,
                 lock: "FOR UPDATE"
               )
             ) do
          %ApprovalExecution{status: "running"} = execution ->
            execution
            |> ApprovalExecution.outcome_changeset(
              outcome
              |> Map.put(:status, status)
              |> Map.put(:completed_at, DateTime.utc_now())
            )
            |> repo.update()

          %ApprovalExecution{status: ^status} = execution ->
            {:ok, execution}

          %ApprovalExecution{} ->
            {:error, :invalid_execution_transition}

          nil ->
            {:error, :execution_not_found}
        end
      end)
      |> then(&MultiTenant.transaction(organization_id, &1))
      |> case do
        {:ok, %{execution: execution}} -> {:ok, execution}
        {:error, _step, reason, _changes} -> {:error, reason}
      end
    end
  end

  defp transition(organization_id, execution_id, fun) do
    with :ok <- valid_uuid(organization_id, :invalid_organization_id),
         :ok <- valid_uuid(execution_id, :invalid_execution_id) do
      Multi.new()
      |> Multi.run(:execution, fn repo, _changes ->
        case repo.one(
               from(execution in ApprovalExecution,
                 where:
                   execution.organization_id == ^organization_id and
                     execution.id == ^execution_id,
                 lock: "FOR UPDATE"
               )
             ) do
          %ApprovalExecution{} = execution -> fun.(repo, execution)
          nil -> {:error, :not_found}
        end
      end)
      |> then(&MultiTenant.transaction(organization_id, &1))
      |> case do
        {:ok, %{execution: execution}} -> {:ok, execution}
        {:error, _step, reason, _changes} -> {:error, reason}
      end
    end
  end

  defp schedule_reconciliation(repo, organization_id, {:execute, execution}) do
    %{organization_id: organization_id, execution_id: execution.id}
    |> ApprovalExecutionReconcilerWorker.new(
      scheduled_at: execution.lease_expires_at,
      unique: [period: @lease_seconds * 2, fields: [:worker, :args]]
    )
    |> repo.insert()
  end

  defp schedule_reconciliation(_repo, _organization_id, _reservation), do: {:ok, :not_needed}

  defp approver_authorized?(repo, organization_id, user_id) do
    case scoped_user(repo, organization_id, user_id) do
      %User{} = user -> Accounts.user_can?(user, :response_approve)
      nil -> false
    end
  end

  defp scoped_user(repo, organization_id, user_id) do
    repo.one(
      from(user in User,
        where: user.id == ^user_id and user.organization_id == ^organization_id
      )
    )
  end

  # Reconciliation evidence is an authenticated pointer to an immutable DB
  # fact, not a caller-provided assertion. Keep the accepted shape strict so
  # additional unvalidated fields cannot acquire meaning later.
  defp normalize_evidence_ref(evidence_ref)
       when is_map(evidence_ref) and map_size(evidence_ref) == 2 do
    type = Map.get(evidence_ref, "type") || Map.get(evidence_ref, :type)
    id = Map.get(evidence_ref, "id") || Map.get(evidence_ref, :id)

    with "agent_command" <- type,
         :ok <- bounded_binary(id, 64, :invalid_evidence_ref),
         {:ok, normalized_id} <- Ecto.UUID.cast(id) do
      canonical = "agent_command:#{normalized_id}"

      with :ok <- bounded_binary(canonical, 1_024, :invalid_evidence_ref) do
        {:ok,
         %{
           type: "agent_command",
           id: normalized_id,
           canonical: canonical,
           typed: %{"type" => "agent_command", "id" => normalized_id}
         }}
      end
    else
      _ -> {:error, :invalid_evidence_ref}
    end
  end

  defp normalize_evidence_ref(_evidence_ref), do: {:error, :invalid_evidence_ref}

  defp validate_evidence(repo, organization_id, execution, outcome, %{
         type: "agent_command",
         id: command_id
       }) do
    expected_status = if outcome == "succeeded", do: "completed", else: "failed"

    with {:ok, target_agent_id} <- execution_target_agent_id(execution),
         {:ok, command_types} <- evidence_command_types(execution.action_type) do
      query =
        from(command in AgentCommand,
          join: agent in Agent,
          on: fragment("?::text = ?", agent.id, command.agent_id),
          where:
            command.id == ^command_id and agent.organization_id == ^organization_id and
              command.agent_id == ^target_agent_id and command.command_type in ^command_types and
              command.status == ^expected_status and not is_nil(command.completed_at),
          select: %{
            command_id: command.id,
            command_type: command.command_type,
            agent_id: command.agent_id,
            terminal_status: command.status,
            completed_at: command.completed_at
          }
        )

      case repo.one(query) do
        %{
          command_id: id,
          command_type: command_type,
          agent_id: agent_id,
          terminal_status: status,
          completed_at: %DateTime{} = completed_at
        } ->
          completed_at_iso = DateTime.to_iso8601(completed_at)

          canonical_fact =
            "agent-command-evidence-v2:#{id}:#{command_type}:#{agent_id}:#{status}:#{completed_at_iso}"

          {:ok,
           %{
             "command_id" => id,
             "command_type" => command_type,
             "agent_id" => agent_id,
             "terminal_status" => status,
             "completed_at" => completed_at_iso,
             "sha256" => sha256(canonical_fact)
           }}

        _ ->
          {:error, :invalid_evidence_ref}
      end
    end
  end

  defp execution_target_agent_id(%ApprovalExecution{target: target}) when is_map(target) do
    agent_id = Map.get(target, "agent_id") || Map.get(target, :agent_id)

    with :ok <- bounded_binary(agent_id, 64, :invalid_evidence_ref),
         {:ok, normalized_id} <- Ecto.UUID.cast(agent_id) do
      {:ok, normalized_id}
    else
      _ -> {:error, :invalid_evidence_ref}
    end
  end

  defp execution_target_agent_id(_execution), do: {:error, :invalid_evidence_ref}

  defp evidence_command_types(action_type) when is_binary(action_type) do
    case Map.fetch(@action_command_types, action_type) do
      {:ok, command_types} -> {:ok, command_types}
      :error -> {:error, :invalid_evidence_ref}
    end
  end

  defp evidence_command_types(_action_type), do: {:error, :invalid_evidence_ref}

  defp normalize_evidence_fence_error({:error, %Ecto.Changeset{} = changeset}) do
    if Keyword.has_key?(changeset.errors, :reconciliation_evidence_ref),
      do: {:error, :evidence_already_used},
      else: {:error, changeset}
  end

  defp normalize_evidence_fence_error(result), do: result

  defp sha256(value) do
    :crypto.hash(:sha256, value)
    |> Base.encode16(case: :lower)
  end

  defp serialize_status(execution) do
    %{
      execution_id: execution.id,
      idempotency_key: execution.idempotency_key,
      status: execution.status,
      started_at: execution.started_at,
      lease_expires_at: execution.lease_expires_at,
      completed_at: execution.completed_at,
      reconciled_at: execution.reconciled_at,
      inserted_at: execution.inserted_at,
      updated_at: execution.updated_at
    }
  end

  defp serialize_reconciliation(execution) do
    target = json_object(execution.target)

    %{
      execution_id: execution.id,
      investigation_id: execution.investigation_id,
      recommendation_id: execution.recommendation_id,
      status: execution.status,
      action_type: execution.action_type,
      target_agent_id: Map.get(target, "agent_id"),
      started_at: execution.started_at,
      lease_expires_at: execution.lease_expires_at,
      completed_at: execution.completed_at,
      inserted_at: execution.inserted_at,
      updated_at: execution.updated_at
    }
  end

  defp scoped_get!(repo, organization_id, execution_id) do
    repo.one!(
      from(execution in ApprovalExecution,
        where: execution.organization_id == ^organization_id and execution.id == ^execution_id
      )
    )
  end

  defp idempotency_key(organization_id, investigation_id, recommendation_id) do
    :crypto.hash(
      :sha256,
      "approval-execution-v1:#{organization_id}:#{investigation_id}:#{recommendation_id}"
    )
    |> Base.encode16(case: :lower)
  end

  defp valid_uuid(value, error) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, _uuid} -> :ok
      :error -> {:error, error}
    end
  end

  defp valid_uuid(_value, error), do: {:error, error}

  defp required_binary(value, _error) when is_binary(value) and value != "", do: :ok
  defp required_binary(_value, error), do: {:error, error}

  defp bounded_binary(value, max_bytes, _error)
       when is_binary(value) and byte_size(value) in 1..max_bytes//1,
       do: :ok

  defp bounded_binary(_value, _max_bytes, error), do: {:error, error}

  defp clamp_limit(value, minimum, maximum) when is_integer(value),
    do: value |> max(minimum) |> min(maximum)

  defp clamp_limit(_value, minimum, _maximum), do: minimum

  defp json_safe(%DateTime{} = value), do: DateTime.to_iso8601(value)
  defp json_safe(%NaiveDateTime{} = value), do: NaiveDateTime.to_iso8601(value)

  defp json_safe(value) when is_map(value) do
    Map.new(value, fn {key, nested} -> {to_string(key), json_safe(nested)} end)
  end

  defp json_safe(value) when is_list(value), do: Enum.map(value, &json_safe/1)
  defp json_safe(value) when is_binary(value) or is_number(value) or is_boolean(value), do: value
  defp json_safe(nil), do: nil
  defp json_safe(value) when is_atom(value), do: Atom.to_string(value)
  defp json_safe(value), do: inspect(value)

  defp json_object(value) do
    case json_safe(value) do
      normalized when is_map(normalized) -> normalized
      normalized -> %{"value" => normalized}
    end
  end
end
