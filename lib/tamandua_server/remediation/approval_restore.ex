defmodule TamanduaServer.Remediation.ApprovalRestore do
  @moduledoc """
  Restores pending approvals through bounded tenant-exact ordinary-repo reads.

  Authority access discovers only tenant UUIDs. A failure or invalid reference
  rejects the complete restore; callers must never interpret it as an empty
  approval queue.
  """

  import Ecto.Query

  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Remediation.{Execution, Playbook}
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.RemediationApprovalAuthorityAccess

  @tenant_limit 500
  @global_limit 5_000

  @spec restore() :: {:ok, [Execution.t()]} | {:error, term()}
  def restore do
    authority =
      Application.get_env(
        :tamandua_server,
        :remediation_approval_authority_access,
        RemediationApprovalAuthorityAccess
      )

    with {:ok, organization_ids} <- authority.discover_organization_ids() do
      organization_ids
      |> Enum.reduce_while({:ok, [], 0}, fn organization_id, {:ok, acc, count} ->
        with {:ok, executions} <- restore_tenant(organization_id),
             new_count <- count + length(executions),
             true <- new_count <= @global_limit do
          {:cont, {:ok, Enum.reverse(executions, acc), new_count}}
        else
          false -> {:halt, {:error, :restore_limit_exceeded}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)
      |> case do
        {:ok, executions, _count} -> {:ok, Enum.reverse(executions)}
        error -> error
      end
    end
  rescue
    _error -> {:error, :persistence_unavailable}
  catch
    :exit, _reason -> {:error, :persistence_unavailable}
  end

  defp restore_tenant(organization_id) do
    with {:ok, canonical_id} <- canonical_uuid(organization_id) do
      MultiTenant.with_organization(canonical_id, fn ->
        rows =
          Repo.all(
            from(e in Execution,
              where:
                e.organization_id == ^canonical_id and e.status == "pending_approval" and
                  e.approval_status == "pending",
              order_by: [asc: e.inserted_at, asc: e.id],
              limit: ^(@tenant_limit + 1)
            )
          )

        with true <- length(rows) <= @tenant_limit,
             :ok <- validate_rows(rows, canonical_id) do
          {:ok, rows}
        else
          _error -> {:error, :invalid_pending_approvals}
        end
      end)
    else
      _error -> {:error, :invalid_tenant}
    end
  end

  defp validate_rows(rows, organization_id) do
    Enum.reduce_while(rows, :ok, fn execution, :ok ->
      if valid_execution?(execution, organization_id),
        do: {:cont, :ok},
        else: {:halt, {:error, :invalid_pending_approval}}
    end)
  end

  defp valid_execution?(%Execution{} = execution, organization_id) do
    execution.organization_id == organization_id and
      canonical_uuid?(execution.id) and
      same_tenant?(Playbook, execution.playbook_id, organization_id) and
      optional_same_tenant?(Agent, execution.agent_id, organization_id) and
      optional_same_tenant?(Alert, execution.alert_id, organization_id) and
      optional_same_tenant?(User, execution.triggered_by, organization_id)
  end

  defp valid_execution?(_execution, _organization_id), do: false

  defp same_tenant?(_schema, nil, _organization_id), do: false

  defp same_tenant?(schema, id, organization_id) do
    canonical_uuid?(id) and
      Repo.exists?(
        from(resource in schema,
          where: resource.id == ^id and resource.organization_id == ^organization_id
        )
      )
  end

  defp optional_same_tenant?(_schema, nil, _organization_id), do: true

  defp optional_same_tenant?(schema, id, organization_id),
    do: same_tenant?(schema, id, organization_id)

  defp canonical_uuid?(value), do: match?({:ok, _}, canonical_uuid(value))

  defp canonical_uuid(value) do
    case Ecto.UUID.cast(value) do
      {:ok, id} -> {:ok, id}
      :error -> Ecto.UUID.load(value)
    end
  end
end
