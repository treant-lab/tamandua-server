defmodule TamanduaServerWeb.API.V1.InvestigationRunControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  import Plug.Conn

  alias TamanduaServer.Investigations.ShadowOrchestrator
  alias TamanduaServerWeb.API.V1.InvestigationRunController

  setup do
    organization = insert(:organization)
    other_organization = insert(:organization)
    agent = insert(:agent, organization: organization)
    alert = insert(:alert, organization: organization, agent: agent)

    {:ok, run} = ShadowOrchestrator.enqueue(organization.id, alert.id)
    {:ok, _observed_run} = ShadowOrchestrator.process(organization.id, run.id)

    %{
      organization: organization,
      other_organization: other_organization,
      alert: alert,
      run: run
    }
  end

  test "lists model-agnostic runs for a tenant alert", %{
    conn: conn,
    organization: organization,
    alert: alert
  } do
    response =
      conn
      |> assign(:current_organization_id, organization.id)
      |> InvestigationRunController.index_for_alert(%{"alert_id" => alert.id})
      |> json_response(200)

    assert response["meta"]["count"] == 1
    assert [run] = response["data"]
    assert run["alert_id"] == alert.id
    assert run["mode"] == "shadow"
    assert run["status"] == "observed"
    assert run["policy_version"] == "shadow-v2"
    assert run["admission_disposition"] == "enqueued"
    assert run["admission_reason"] == "explicit_request"
    assert run["enforcement"] == "disabled"
    refute Map.has_key?(run, "organization_id")
    refute Map.has_key?(run, "model")
    refute Map.has_key?(run, "model_name")
  end

  test "returns only the persisted evidence contract", %{
    conn: conn,
    organization: organization,
    run: run
  } do
    response =
      conn
      |> assign(:current_organization_id, organization.id)
      |> InvestigationRunController.evidence(%{"id" => run.id})
      |> json_response(200)

    assert response["meta"] == %{"count" => 2, "run_id" => run.id}
    evidence = Enum.find(response["data"], &(&1["kind"] == "alert_normalized"))
    assert evidence["run_id"] == run.id
    assert evidence["kind"] == "alert_normalized"
    assert is_map(evidence["payload"])
    refute Map.has_key?(evidence, "organization_id")
    refute Map.has_key?(evidence, "dedupe_key")
  end

  test "cross-tenant and missing tenant lookups fail closed", %{
    conn: conn,
    other_organization: other_organization,
    alert: alert,
    run: run
  } do
    conn
    |> assign(:current_organization_id, other_organization.id)
    |> InvestigationRunController.index_for_alert(%{"alert_id" => alert.id})
    |> json_response(404)

    build_conn()
    |> assign(:current_organization_id, other_organization.id)
    |> InvestigationRunController.evidence(%{"id" => run.id})
    |> json_response(404)

    build_conn()
    |> InvestigationRunController.evidence(%{"id" => run.id})
    |> json_response(403)
  end

  test "rejects detector observation ingestion without alert update permission", %{
    conn: conn,
    organization: organization,
    alert: alert
  } do
    viewer = insert(:user, organization: organization, role: "viewer")
    {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(viewer)

    response =
      conn
      |> put_req_header("authorization", "Bearer #{token}")
      |> post("/api/v1/alerts/#{alert.id}/detector-observations", %{})

    body = json_response(response, 403)
    assert body["error"] == "forbidden"
    assert body["required_permission"] == "alerts_update"
  end

  test "rejects investigation and evidence reads without alerts_read", %{
    conn: conn,
    organization: organization,
    alert: alert,
    run: run
  } do
    user_without_roles = insert(:user, organization: organization, role: "viewer")
    {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(user_without_roles)

    investigations =
      conn
      |> put_req_header("authorization", "Bearer #{token}")
      |> get("/api/v1/alerts/#{alert.id}/investigations")

    assert investigations.status == 403
    assert json_response(investigations, 403)["required_permission"] == "alerts_read"

    evidence =
      build_conn()
      |> put_req_header("authorization", "Bearer #{token}")
      |> get("/api/v1/investigation-runs/#{run.id}/evidence")

    assert evidence.status == 403
    assert json_response(evidence, 403)["required_permission"] == "alerts_read"
  end

  test "requires a governed producer attestation for ingestion", %{
    conn: conn,
    organization: organization,
    alert: alert
  } do
    response =
      conn
      |> assign(:current_organization_id, organization.id)
      |> InvestigationRunController.attach_detector_observation(%{
        "alert_id" => alert.id,
        "envelope" => %{}
      })
      |> json_response(422)

    assert response["error"] == "Governed producer attestation is required"
  end
end
