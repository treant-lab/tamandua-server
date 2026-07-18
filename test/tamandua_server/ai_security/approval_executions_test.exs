defmodule TamanduaServer.AISecurity.ApprovalExecutionsTest do
  use TamanduaServer.DataCase, async: false
  use Oban.Testing, repo: TamanduaServer.Repo

  alias TamanduaServer.Accounts.{Permission, Role, RolePermission, UserRole}
  alias TamanduaServer.AISecurity.{ApprovalExecution, ApprovalExecutions}
  alias TamanduaServer.Agents.AgentCommand
  alias TamanduaServer.Authorization.RBAC
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  setup do
    organization = insert(:organization)
    approver = insert(:user, organization: organization, role: "admin")
    target_agent = insert(:agent, organization: organization)
    grant_response_approve!(approver, organization)

    attrs = %{
      investigation_id: "inv-123",
      recommendation_id: "rec-456",
      approver_id: approver.id,
      action_type: "isolate_network",
      target: %{agent_id: target_agent.id}
    }

    %{organization: organization, approver: approver, target_agent: target_agent, attrs: attrs}
  end

  defp grant_response_approve!(user, organization) do
    role =
      %Role{}
      |> Role.changeset(%{
        name: "Approval execution test approver",
        slug: "approval_execution_approver_#{user.id}",
        builtin: false,
        priority: 80,
        organization_id: organization.id
      })
      |> Repo.insert!()

    permission =
      Repo.get_by(Permission, slug: "response_approve") ||
        %Permission{}
        |> Permission.changeset(%{
          name: "response_approve",
          slug: "response_approve",
          description: "response_approve",
          category: "response"
        })
        |> Repo.insert!()

    %RolePermission{}
    |> RolePermission.changeset(%{role_id: role.id, permission_id: permission.id})
    |> Repo.insert!()

    %UserRole{}
    |> UserRole.changeset(%{
      user_id: user.id,
      role_id: role.id,
      granted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    })
    |> Repo.insert!()

    RBAC.invalidate_cache(user)
  end

  test "atomically claims once and reports in progress on a concurrent retry", %{
    organization: organization,
    attrs: attrs
  } do
    assert {:ok, {:execute, first}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    assert first.status == "running"
    assert first.started_at

    assert {:ok, {:in_progress, retry}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    assert retry.id == first.id

    count =
      MultiTenant.with_organization(organization.id, fn ->
        Repo.aggregate(
          from(execution in ApprovalExecution,
            where: execution.organization_id == ^organization.id
          ),
          :count
        )
      end)

    assert count == 1
  end

  test "successful outcome is durable and replayed without a new claim", %{
    organization: organization,
    attrs: attrs
  } do
    assert {:ok, {:execute, execution}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    assert {:ok, completed} =
             ApprovalExecutions.succeed(organization.id, execution.id, %{
               command_id: "cmd-1",
               dispatched: true
             })

    assert completed.status == "succeeded"
    assert completed.result == %{"command_id" => "cmd-1", "dispatched" => true}
    assert completed.completed_at

    assert {:ok, {:succeeded, replay}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    assert replay.id == execution.id
    assert replay.result == completed.result
  end

  test "pre-execution failure is terminal and never reclaimed", %{
    organization: organization,
    attrs: attrs
  } do
    assert {:ok, {:execute, execution}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    assert {:ok, failed} =
             ApprovalExecutions.fail(organization.id, execution.id, :agent_offline)

    assert failed.status == "failed"
    assert failed.error == %{"reason" => ":agent_offline"}

    assert {:ok, {:failed, replay}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    assert replay.id == execution.id
  end

  test "same logical identifiers remain isolated by tenant", %{
    organization: organization,
    attrs: attrs
  } do
    other_organization = insert(:organization)
    other_approver = insert(:user, organization: other_organization, role: "admin")
    other_target_agent = insert(:agent, organization: other_organization)
    grant_response_approve!(other_approver, other_organization)

    assert {:ok, {:execute, first}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    assert {:ok, {:execute, second}} =
             ApprovalExecutions.reserve_and_claim(
               other_organization.id,
               %{
                 attrs
                 | approver_id: other_approver.id,
                   target: %{agent_id: other_target_agent.id}
               }
             )

    refute first.id == second.id
  end

  test "reservation rejects a target agent outside the approving tenant", %{
    organization: organization,
    attrs: attrs
  } do
    other_organization = insert(:organization)
    foreign_agent = insert(:agent, organization: other_organization)

    assert {:error, :invalid_target_agent} =
             ApprovalExecutions.reserve_and_claim(
               organization.id,
               %{attrs | target: %{agent_id: foreign_agent.id}}
             )
  end

  test "expired running execution becomes reconciliation required without a new claim", %{
    organization: organization,
    approver: approver,
    attrs: attrs
  } do
    assert {:ok, {:execute, execution}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    stale_now = DateTime.add(execution.lease_expires_at, 1, :second)

    assert {:ok, stale} =
             ApprovalExecutions.mark_stale(organization.id, execution.id, stale_now)

    assert stale.status == "reconciliation_required"

    command = terminal_command(organization, "completed", agent_id: attrs.target.agent_id)

    assert {:ok, reconciled} =
             ApprovalExecutions.reconcile(
               organization.id,
               execution.id,
               approver.id,
               "succeeded",
               %{"type" => "agent_command", "id" => command.id}
             )

    assert reconciled.status == "succeeded"
    assert reconciled.reconciliation_evidence_ref == "agent_command:#{command.id}"
    assert reconciled.result["evidence_ref"] == %{"type" => "agent_command", "id" => command.id}
    assert reconciled.result["evidence_fact"]["command_id"] == command.id
    assert reconciled.result["evidence_fact"]["terminal_status"] == "completed"
    assert is_binary(reconciled.result["evidence_fact"]["completed_at"])
    assert byte_size(reconciled.result["evidence_fact"]["sha256"]) == 64

    assert {:ok, {:succeeded, replay}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    assert replay.id == execution.id
  end

  test "status is tenant scoped and excludes action payloads", %{
    organization: organization,
    attrs: attrs
  } do
    other_organization = insert(:organization)

    assert {:ok, {:execute, execution}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    assert {:error, :not_found} =
             ApprovalExecutions.status(other_organization.id, execution.id)

    assert {:ok, status} = ApprovalExecutions.status(organization.id, execution.id)
    assert status.execution_id == execution.id
    assert status.idempotency_key == execution.idempotency_key
    refute Map.has_key?(status, :target)
    refute Map.has_key?(status, :result)
    refute Map.has_key?(status, :error)
  end

  test "manual reconciliation rejects unbounded evidence references", %{
    organization: organization,
    approver: approver,
    attrs: attrs
  } do
    assert {:ok, {:execute, execution}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    stale_now = DateTime.add(execution.lease_expires_at, 1, :second)
    assert {:ok, _stale} = ApprovalExecutions.mark_stale(organization.id, execution.id, stale_now)

    assert {:error, :invalid_evidence_ref} =
             ApprovalExecutions.reconcile(
               organization.id,
               execution.id,
               approver.id,
               "failed",
               %{"type" => String.duplicate("x", 1_025), "id" => Ecto.UUID.generate()}
             )
  end

  test "manual reconciliation rejects nonexistent and nonterminal command evidence", %{
    organization: organization,
    approver: approver,
    attrs: attrs
  } do
    assert {:ok, {:execute, execution}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    stale_now = DateTime.add(execution.lease_expires_at, 1, :second)
    assert {:ok, _stale} = ApprovalExecutions.mark_stale(organization.id, execution.id, stale_now)

    assert {:error, :invalid_evidence_ref} =
             ApprovalExecutions.reconcile(
               organization.id,
               execution.id,
               approver.id,
               "succeeded",
               %{"type" => "agent_command", "id" => Ecto.UUID.generate()}
             )

    command = terminal_command(organization, "acknowledged", agent_id: attrs.target.agent_id)

    assert {:error, :invalid_evidence_ref} =
             ApprovalExecutions.reconcile(
               organization.id,
               execution.id,
               approver.id,
               "succeeded",
               %{"type" => "agent_command", "id" => command.id}
             )
  end

  test "manual reconciliation rejects cross-tenant and outcome-mismatched command evidence", %{
    organization: organization,
    approver: approver,
    attrs: attrs
  } do
    assert {:ok, {:execute, execution}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    stale_now = DateTime.add(execution.lease_expires_at, 1, :second)
    assert {:ok, _stale} = ApprovalExecutions.mark_stale(organization.id, execution.id, stale_now)

    other_organization = insert(:organization)
    cross_tenant_command = terminal_command(other_organization, "completed")

    assert {:error, :invalid_evidence_ref} =
             ApprovalExecutions.reconcile(
               organization.id,
               execution.id,
               approver.id,
               "succeeded",
               %{"type" => "agent_command", "id" => cross_tenant_command.id}
             )

    failed_command = terminal_command(organization, "failed", agent_id: attrs.target.agent_id)

    assert {:error, :invalid_evidence_ref} =
             ApprovalExecutions.reconcile(
               organization.id,
               execution.id,
               approver.id,
               "succeeded",
               %{"type" => "agent_command", "id" => failed_command.id}
             )
  end

  test "domain boundary rejects a tenant member without response approval permission", %{
    organization: organization,
    attrs: attrs
  } do
    viewer = insert(:user, organization: organization, role: "viewer")

    assert {:error, :unauthorized} =
             ApprovalExecutions.reserve_and_claim(
               organization.id,
               %{attrs | approver_id: viewer.id}
             )
  end

  test "manual reconciliation binds command action and target agent to the frozen execution", %{
    organization: organization,
    approver: approver,
    attrs: attrs
  } do
    assert {:ok, {:execute, execution}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    stale_now = DateTime.add(execution.lease_expires_at, 1, :second)
    assert {:ok, _stale} = ApprovalExecutions.mark_stale(organization.id, execution.id, stale_now)

    wrong_agent = insert(:agent, organization: organization)

    wrong_target_command =
      terminal_command(organization, "completed",
        agent_id: wrong_agent.id,
        command_type: "isolate_network"
      )

    assert {:error, :invalid_evidence_ref} =
             ApprovalExecutions.reconcile(
               organization.id,
               execution.id,
               approver.id,
               "succeeded",
               %{"type" => "agent_command", "id" => wrong_target_command.id}
             )

    wrong_action_command =
      terminal_command(organization, "completed",
        agent_id: attrs.target.agent_id,
        command_type: "kill_process"
      )

    assert {:error, :invalid_evidence_ref} =
             ApprovalExecutions.reconcile(
               organization.id,
               execution.id,
               approver.id,
               "succeeded",
               %{"type" => "agent_command", "id" => wrong_action_command.id}
             )
  end

  test "one AgentCommand evidence cannot reconcile a second approval execution", %{
    organization: organization,
    approver: approver,
    attrs: attrs
  } do
    assert {:ok, {:execute, first}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    second_attrs = %{attrs | recommendation_id: "rec-second"}

    assert {:ok, {:execute, second}} =
             ApprovalExecutions.reserve_and_claim(organization.id, second_attrs)

    first_stale_at = DateTime.add(first.lease_expires_at, 1, :second)
    second_stale_at = DateTime.add(second.lease_expires_at, 1, :second)
    assert {:ok, _} = ApprovalExecutions.mark_stale(organization.id, first.id, first_stale_at)
    assert {:ok, _} = ApprovalExecutions.mark_stale(organization.id, second.id, second_stale_at)

    command = terminal_command(organization, "completed", agent_id: attrs.target.agent_id)
    evidence = %{"type" => "agent_command", "id" => command.id}

    assert {:ok, reconciled} =
             ApprovalExecutions.reconcile(
               organization.id,
               first.id,
               approver.id,
               "succeeded",
               evidence
             )

    assert reconciled.status == "succeeded"

    assert {:error, :evidence_already_used} =
             ApprovalExecutions.reconcile(
               organization.id,
               second.id,
               approver.id,
               "succeeded",
               evidence
             )
  end

  test "reconciliation queue is bounded, tenant scoped and excludes action payloads", %{
    organization: organization,
    attrs: attrs
  } do
    assert {:ok, {:execute, execution}} =
             ApprovalExecutions.reserve_and_claim(organization.id, attrs)

    stale_now = DateTime.add(execution.lease_expires_at, 1, :second)
    assert {:ok, _} = ApprovalExecutions.mark_stale(organization.id, execution.id, stale_now)

    assert {:ok, [queued]} =
             ApprovalExecutions.list_reconciliation_required(organization.id, limit: 10)

    assert queued.execution_id == execution.id
    assert queued.action_type == attrs.action_type
    assert queued.target_agent_id == attrs.target.agent_id
    refute Map.has_key?(queued, :target)
    refute Map.has_key?(queued, :result)
    refute Map.has_key?(queued, :error)

    other_organization = insert(:organization)
    assert {:ok, []} = ApprovalExecutions.list_reconciliation_required(other_organization.id)
  end

  defp terminal_command(organization, status, opts \\ []) do
    agent_id =
      Keyword.get_lazy(opts, :agent_id, fn -> insert(:agent, organization: organization).id end)

    Repo.insert!(%AgentCommand{
      agent_id: agent_id,
      command_type: Keyword.get(opts, :command_type, "isolate_network"),
      status: status,
      completed_at:
        if(status in ["completed", "failed"],
          do: DateTime.utc_now() |> DateTime.truncate(:second),
          else: nil
        )
    })
  end
end
