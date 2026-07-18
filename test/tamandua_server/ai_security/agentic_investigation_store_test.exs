defmodule TamanduaServer.AISecurity.AgenticInvestigationStoreTest do
  use TamanduaServer.DataCase, async: false

  import Ecto.Query

  alias TamanduaServer.AISecurity.{
    AgenticInvestigationSnapshot,
    AgenticInvestigationStore
  }

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  defmodule RestoreAuthorityStub do
    def discover_non_terminal_organization_ids(1, limit) do
      if Process.get(:agentic_restore_test_authority_failure, false) do
        {:error, :persistence_unavailable}
      else
        ids = Process.get(:agentic_restore_test_organization_ids, [])
        {:ok, Enum.take(ids, limit), %{truncated: length(ids) > limit}}
      end
    end
  end

  setup do
    previous_access =
      Application.get_env(:tamandua_server, :agentic_restore_authority_access)

    Application.put_env(
      :tamandua_server,
      :agentic_restore_authority_access,
      RestoreAuthorityStub
    )

    organization = insert(:organization)
    other_organization = insert(:organization)
    Process.put(:agentic_restore_test_organization_ids, [organization.id, other_organization.id])
    agent = insert(:agent, organization: organization)
    alert = insert(:alert, organization: organization, agent: agent)

    on_exit(fn ->
      Process.delete(:agentic_restore_test_organization_ids)
      Process.delete(:agentic_restore_test_authority_failure)

      if previous_access do
        Application.put_env(:tamandua_server, :agentic_restore_authority_access, previous_access)
      else
        Application.delete_env(:tamandua_server, :agentic_restore_authority_access)
      end
    end)

    %{
      organization: organization,
      other_organization: other_organization,
      alert: alert
    }
  end

  test "upserts one tenant-scoped data-only snapshot and restores typed state", %{
    organization: organization,
    alert: alert
  } do
    now = DateTime.utc_now()

    investigation = %{
      id: "inv_durable_test",
      organization_id: organization.id,
      alert_id: alert.id,
      alert: %{
        id: alert.id,
        organization_id: organization.id,
        agent_id: alert.agent_id,
        severity: "high",
        mitre_techniques: ["T1059"],
        event_ids: [],
        title: "Contract test",
        description: "Data-only snapshot"
      },
      state: :pending,
      started_at: now,
      updated_at: now,
      hypotheses: [%{type: :execution, validated: false}],
      evidence: for(index <- 1..250, do: %{index: index}),
      correlations: [],
      recommendations: [],
      analyst_feedback: %{
        submitted_by: %{
          id: Ecto.UUID.generate(),
          email: "analyst@example.test",
          password_hash: "argon-secret-hash",
          mfa_secret: "totp-seed-secret",
          access_token: "bearer-secret-token"
        },
        comments: String.duplicate("bounded", 2_000),
        metadata: %{"__tamandua_type__" => "atom", "value" => "resolved"}
      },
      analyst_notes: fn -> :must_not_be_serialized end
    }

    assert {:ok, first} = AgenticInvestigationStore.upsert(investigation)
    assert first.organization_id == organization.id
    assert first.investigation_id == investigation.id
    assert first.snapshot_version == 1
    assert first.snapshot["analyst_notes"] == nil
    refute inspect(first.snapshot) =~ "Elixir."
    refute inspect(first.snapshot) =~ "#Function"

    encoded_snapshot = Jason.encode!(first.snapshot)
    refute encoded_snapshot =~ "argon-secret-hash"
    refute encoded_snapshot =~ "totp-seed-secret"
    refute encoded_snapshot =~ "bearer-secret-token"
    assert encoded_snapshot =~ "[REDACTED]"

    assert {:ok, second} =
             investigation
             |> Map.put(:state, :triaging)
             |> Map.put(:updated_at, DateTime.add(now, 1, :second))
             |> AgenticInvestigationStore.upsert()

    assert second.id == first.id
    assert second.state == "triaging"

    assert {:ok, restored, restore_meta} =
             AgenticInvestigationStore.restore_non_terminal(:system_startup,
               tenant_limit: 10,
               per_tenant_limit: 10
             )

    refute restore_meta.tenants_truncated
    assert [snapshot] = Enum.filter(restored, &(&1[:id] == investigation.id))
    assert snapshot[:organization_id] == organization.id
    assert snapshot[:state] == :triaging
    assert %DateTime{} = snapshot[:started_at]
    assert snapshot[:hypotheses] == [%{type: :execution, validated: false}]
    assert String.length(snapshot[:analyst_feedback][:comments]) == 8_192
    assert length(snapshot[:evidence]) == 200

    assert snapshot[:analyst_feedback][:metadata] == %{
             "__tamandua_type__" => "atom",
             "value" => "resolved"
           }
  end

  test "RLS hides snapshots from another organization", %{
    organization: organization,
    other_organization: other_organization,
    alert: alert
  } do
    assert {:ok, snapshot} =
             AgenticInvestigationStore.upsert(%{
               id: "inv_rls_test",
               organization_id: organization.id,
               alert_id: alert.id,
               alert: %{id: alert.id, organization_id: organization.id},
               state: :pending,
               updated_at: DateTime.utc_now()
             })

    assert nil ==
             MultiTenant.with_organization(other_organization.id, fn ->
               Repo.one(
                 from(row in AgenticInvestigationSnapshot,
                   where: row.id == ^snapshot.id
                 )
               )
             end)
  end

  test "terminal snapshots remain durable but are not restored", %{
    organization: organization,
    alert: alert
  } do
    assert {:ok, snapshot} =
             AgenticInvestigationStore.upsert(%{
               id: "inv_terminal_test",
               organization_id: organization.id,
               alert_id: alert.id,
               alert: %{id: alert.id, organization_id: organization.id},
               state: :resolved,
               updated_at: DateTime.utc_now()
             })

    assert snapshot.terminal

    assert {:ok, restored, _restore_meta} =
             AgenticInvestigationStore.restore_non_terminal(:system_startup,
               tenant_limit: 10,
               per_tenant_limit: 10
             )

    refute Enum.any?(restored, &(&1[:id] == "inv_terminal_test"))
  end

  test "restore preserves equal investigation ids owned by different tenants", %{
    organization: organization,
    other_organization: other_organization,
    alert: alert
  } do
    other_agent = insert(:agent, organization: other_organization)
    other_alert = insert(:alert, organization: other_organization, agent: other_agent)
    investigation_id = "inv_same_id_two_tenants"
    now = DateTime.utc_now()

    assert {:ok, _snapshot} =
             AgenticInvestigationStore.upsert(%{
               id: investigation_id,
               organization_id: organization.id,
               alert_id: alert.id,
               alert: %{id: alert.id, organization_id: organization.id},
               state: :pending,
               updated_at: now
             })

    assert {:ok, _snapshot} =
             AgenticInvestigationStore.upsert(%{
               id: investigation_id,
               organization_id: other_organization.id,
               alert_id: other_alert.id,
               alert: %{id: other_alert.id, organization_id: other_organization.id},
               state: :triaging,
               updated_at: now
             })

    assert {:ok, restored, _restore_meta} =
             AgenticInvestigationStore.restore_non_terminal(:system_startup,
               tenant_limit: 10,
               per_tenant_limit: 10
             )

    colliding = Enum.filter(restored, &(&1[:id] == investigation_id))

    assert MapSet.new(Enum.map(colliding, & &1[:organization_id])) ==
             MapSet.new([organization.id, other_organization.id])
  end

  test "invalid tenant identity fails closed before persistence", %{alert: alert} do
    assert {:error, :invalid_snapshot} =
             AgenticInvestigationStore.upsert(%{
               id: "inv_invalid_tenant",
               organization_id: "not-a-uuid",
               alert_id: alert.id,
               state: :pending
             })
  end

  test "upsert rejects an alert owned by another organization", %{
    other_organization: other_organization,
    alert: alert
  } do
    assert {:error, :alert_not_found_in_organization} =
             AgenticInvestigationStore.upsert(%{
               id: "inv_cross_tenant_alert",
               organization_id: other_organization.id,
               alert_id: alert.id,
               alert: %{id: alert.id, organization_id: other_organization.id},
               state: :pending,
               updated_at: DateTime.utc_now()
             })
  end

  test "cross-tenant restore requires the explicit startup system scope" do
    assert {:error, :system_scope_required} =
             AgenticInvestigationStore.restore_non_terminal(:tenant_request, limit: 10)
  end

  test "restore rejects invalid limits without clamping" do
    assert {:error, :persistence_unavailable} =
             AgenticInvestigationStore.restore_non_terminal(:system_startup, tenant_limit: 0)

    assert {:error, :persistence_unavailable} =
             AgenticInvestigationStore.restore_non_terminal(:system_startup, tenant_limit: 501)

    assert {:error, :persistence_unavailable} =
             AgenticInvestigationStore.restore_non_terminal(:system_startup,
               per_tenant_limit: "10"
             )
  end

  test "authority failure restores nothing and fails closed" do
    Process.put(:agentic_restore_test_authority_failure, true)

    assert {:error, :persistence_unavailable} =
             AgenticInvestigationStore.restore_non_terminal(:system_startup,
               tenant_limit: 10,
               per_tenant_limit: 10
             )
  end

  test "bounded restore applies a per-tenant cap so one tenant cannot consume the batch", %{
    organization: organization,
    other_organization: other_organization,
    alert: alert
  } do
    other_agent = insert(:agent, organization: other_organization)
    other_alert = insert(:alert, organization: other_organization, agent: other_agent)

    for id <- ["inv_noisy_one", "inv_noisy_two"] do
      assert {:ok, _snapshot} =
               AgenticInvestigationStore.upsert(%{
                 id: id,
                 organization_id: organization.id,
                 alert_id: alert.id,
                 alert: %{id: alert.id, organization_id: organization.id},
                 state: :pending,
                 updated_at: DateTime.utc_now()
               })
    end

    assert {:ok, _snapshot} =
             AgenticInvestigationStore.upsert(%{
               id: "inv_other_tenant",
               organization_id: other_organization.id,
               alert_id: other_alert.id,
               alert: %{id: other_alert.id, organization_id: other_organization.id},
               state: :pending,
               updated_at: DateTime.utc_now()
             })

    assert {:ok, restored, meta} =
             AgenticInvestigationStore.restore_non_terminal(:system_startup,
               tenant_limit: 10,
               per_tenant_limit: 1
             )

    ids = MapSet.new(restored, & &1[:id])
    assert MapSet.member?(ids, "inv_other_tenant")
    assert Enum.count(ids, &(&1 in ["inv_noisy_one", "inv_noisy_two"])) == 1
    assert meta.per_tenant_limit == 1
  end
end
