defmodule TamanduaServerWeb.GraphQL.Resolvers.InvestigationResolverSecurityTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Investigations.CaseInvestigation
  alias TamanduaServerWeb.GraphQL.Resolvers.InvestigationResolver

  setup do
    org_a = Ecto.UUID.generate()
    org_b = Ecto.UUID.generate()

    investigation_b =
      Repo.insert!(%CaseInvestigation{
        title: "Tenant B investigation",
        organization_id: org_b
      })

    alert_b =
      Repo.insert!(%Alert{
        title: "Tenant B alert",
        description: "must not cross the GraphQL boundary",
        severity: "high",
        status: "new",
        organization_id: org_b
      })

    %{org_a: org_a, org_b: org_b, investigation_b: investigation_b, alert_b: alert_b}
  end

  test "investigation lookup is organization scoped", context do
    assert {:error, [message: "Investigation not found", code: "NOT_FOUND"]} =
             InvestigationResolver.get_investigation(
               nil,
               %{id: context.investigation_b.id},
               %{context: %{organization_id: context.org_a}}
             )
  end

  test "nested investigation alerts fail closed for a foreign parent", context do
    foreign_parent = %{
      organization_id: context.org_b,
      alert_ids: [context.alert_b.id]
    }

    assert {:ok, []} =
             InvestigationResolver.alerts(
               foreign_parent,
               %{},
               %{context: %{organization_id: context.org_a}}
             )
  end

  test "nested notes and timeline fail closed for a foreign parent", context do
    foreign_parent = %{
      organization_id: context.org_b,
      notes: "sensitive note",
      timeline: %{"events" => [%{"description" => "sensitive event"}]}
    }

    resolution = %{context: %{organization_id: context.org_a}}

    assert {:ok, []} = InvestigationResolver.notes(foreign_parent, %{}, resolution)
    assert {:ok, []} = InvestigationResolver.timeline(foreign_parent, %{}, resolution)
  end

  test "alert-backed investigation graph cannot read another tenant", context do
    assert {:error, [message: "Alert not found", code: "NOT_FOUND"]} =
             InvestigationResolver.build_investigation_graph(
               nil,
               %{alert_id: context.alert_b.id},
               %{context: %{organization_id: context.org_a}}
             )
  end

  test "missing organization never degrades to a global investigation list" do
    assert {:error, [message: message, code: "UNAUTHORIZED"]} =
             InvestigationResolver.list_investigations(nil, %{}, %{context: %{}})

    assert message =~ "missing organization"
  end
end
