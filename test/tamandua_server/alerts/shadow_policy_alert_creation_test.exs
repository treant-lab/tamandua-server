defmodule TamanduaServer.Alerts.ShadowPolicyAlertCreationTest do
  use TamanduaServer.DataCase, async: false
  use Oban.Testing, repo: TamanduaServer.Repo

  alias TamanduaServer.Alerts
  alias TamanduaServer.Investigations.ShadowOrchestrator
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Workers.ShadowInvestigationWorker

  setup do
    previous = Application.get_env(:tamandua_server, ShadowOrchestrator, [])
    on_exit(fn -> Application.put_env(:tamandua_server, ShadowOrchestrator, previous) end)
    :ok
  end

  test "alert creation remains successful and records one opted-in shadow admission" do
    {organization, agent} = create_agent_with_org(%{os_type: "linux"})

    MultiTenant.with_organization(organization.id, fn ->
      organization
      |> Ecto.Changeset.change(features: %{"automatic_investigation_shadow_v2" => true})
      |> Repo.update!()
    end)

    Application.put_env(:tamandua_server, ShadowOrchestrator,
      alert_creation_trigger: :shadow,
      max_active_per_tenant: 2,
      max_admissions_per_minute: 10,
      worker_timeout_ms: 30_000
    )

    assert {:ok, alert} =
             Alerts.create_alert(%{
               organization_id: organization.id,
               agent_id: agent.id,
               severity: "critical",
               title: "Governed shadow policy integration",
               description: "Alert persistence is authoritative",
               threat_score: 0.93
             })

    assert {:ok, [receipt]} =
             ShadowOrchestrator.list_runs_for_alert(organization.id, alert.id)

    assert receipt.admission_disposition == "enqueued"
    assert receipt.admission_reason == "eligible_shadow_observation"
    assert receipt.policy_version == "shadow-v2"
    assert receipt.summary["enforcement"] == "disabled"

    assert_enqueued(
      worker: ShadowInvestigationWorker,
      queue: :ai_investigations,
      args: %{"organization_id" => organization.id, "run_id" => receipt.id}
    )
  end
end
