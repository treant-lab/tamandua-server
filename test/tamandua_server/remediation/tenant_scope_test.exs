defmodule TamanduaServer.Remediation.TenantScopeTest do
  use TamanduaServer.DataCase, async: false

  import TamanduaServer.AccountsFixtures

  alias TamanduaServer.Remediation.{Execution, Executor, Playbook}
  alias TamanduaServer.Repo.MultiTenant

  test "playbook CRUD and execution records are isolated by organization" do
    organization_a = organization_fixture()
    organization_b = organization_fixture()
    scope_a = {:organization, organization_a.id}
    scope_b = {:organization, organization_b.id}

    assert {:ok, playbook} =
             Playbook.create_playbook(
               %{
                 name: "Scoped remediation",
                 trigger_type: "manual",
                 steps: [%{"action" => "wait"}]
               },
               scope_a
             )

    assert playbook.organization_id == organization_a.id
    assert {:ok, ^playbook} = Playbook.get_playbook(playbook.id, scope_a)
    assert {:error, :not_found} = Playbook.get_playbook(playbook.id, scope_b)
    assert {:ok, []} = Playbook.list_playbooks(%{}, scope_b)

    assert {:ok, execution} =
             Execution.create_execution(
               %{playbook_id: playbook.id, status: "running"},
               scope_a
             )

    assert execution.organization_id == organization_a.id
    assert {:ok, ^execution} = Execution.get_execution(execution.id, scope_a)
    assert {:error, :not_found} = Execution.get_execution(execution.id, scope_b)
    assert {:ok, active_executions} = Execution.list_active_executions(scope_a)
    assert Enum.any?(active_executions, &(&1.id == execution.id))
    assert {:ok, []} = Execution.list_active_executions(scope_b)

    assert {:ok, foreign_playbook} =
             Playbook.create_playbook(
               %{name: "Foreign remediation", trigger_type: "manual", steps: [%{"action" => "wait"}]},
               scope_b
             )

    assert {:error, :not_found} =
             Execution.create_execution(
               %{playbook_id: foreign_playbook.id, status: "running"},
               scope_a
             )

    assert {:ok, pending_execution} =
             Execution.create_execution(
               %{
                 playbook_id: playbook.id,
                 status: "pending_approval",
                 approval_status: "pending",
                 approval_tier: "analyst"
               },
               scope_a
             )

    foreign_approver = user_fixture(%{organization_id: organization_b.id, role: "admin"})

    assert {:error, approval_error} =
             Executor.approve_execution(
               pending_execution.id,
               foreign_approver.id,
               "cross-tenant attempt",
               scope_a
             )

    assert approval_error in [:user_not_found, :organization_mismatch]
    assert {:ok, unchanged_execution} = Execution.get_execution(pending_execution.id, scope_a)
    assert unchanged_execution.status == "pending_approval"
  end

  test "unscoped APIs and tenant-wide IP broadcast fail closed" do
    assert {:error, :tenant_required} = Playbook.list_playbooks()
    assert {:error, :tenant_required} = Execution.list_pending_approvals()

    assert {:error, :tenant_required} =
             Playbook.create_playbook(
               %{name: "Unowned", trigger_type: "manual", steps: [%{"action" => "wait"}]},
               :system
             )

    assert {:error, :tenant_required} =
             Executor.execute_action("block_ip", %{"ip" => "203.0.113.10"}, %{})

    organization = organization_fixture()

    assert {:error, :tenant_required} =
             Executor.execute_playbook(
               Ecto.UUID.generate(),
               %{organization_id: organization.id},
               []
             )

    assert {:error, message} =
             Executor.execute_action(
               "block_ip",
               %{"ip" => "203.0.113.10"},
               %{},
               {:organization, organization.id}
             )

    assert message =~ "tenant-wide broadcast is disabled"
  end

  test "legacy remediation artifact tables enforce RLS by organization" do
    organization_a = organization_fixture()
    organization_b = organization_fixture()

    audit_id = Ecto.UUID.generate()
    history_id = Ecto.UUID.generate()
    metric_id = Ecto.UUID.generate()

    MultiTenant.with_organization(organization_a.id, fn ->
      Repo.query!(
        """
        INSERT INTO remediation_audit_log
          (id, organization_id, action_type, status, inserted_at, updated_at)
        VALUES ($1, $2, 'test_action', 'completed', NOW(), NOW())
        """,
        [Ecto.UUID.dump!(audit_id), Ecto.UUID.dump!(organization_a.id)]
      )

      Repo.query!(
        """
        INSERT INTO remediation_approval_history
          (id, organization_id, action, timestamp, inserted_at, updated_at)
        VALUES ($1, $2, 'approved', NOW(), NOW(), NOW())
        """,
        [Ecto.UUID.dump!(history_id), Ecto.UUID.dump!(organization_a.id)]
      )

      Repo.query!(
        """
        INSERT INTO remediation_metrics
          (id, organization_id, metric_date, inserted_at, updated_at)
        VALUES ($1, $2, CURRENT_DATE, NOW(), NOW())
        """,
        [Ecto.UUID.dump!(metric_id), Ecto.UUID.dump!(organization_a.id)]
      )
    end)

    for {table, id} <- [
          {"remediation_audit_log", audit_id},
          {"remediation_approval_history", history_id},
          {"remediation_metrics", metric_id}
        ] do
      assert [[1]] =
               MultiTenant.with_organization(organization_a.id, fn ->
                 %{rows: rows} =
                   Repo.query!("SELECT COUNT(*) FROM #{table} WHERE id = $1", [
                     Ecto.UUID.dump!(id)
                   ])

                 rows
               end)

      assert [[0]] =
               MultiTenant.with_organization(organization_b.id, fn ->
                 %{rows: rows} =
                   Repo.query!("SELECT COUNT(*) FROM #{table} WHERE id = $1", [
                     Ecto.UUID.dump!(id)
                   ])

                 rows
               end)
    end
  end
end
