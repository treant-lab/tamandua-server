defmodule TamanduaServerWeb.API.V1.InvestigationRunController do
  @moduledoc "Tenant-scoped, model-agnostic API for governed investigation runs."

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Investigations.ShadowOrchestrator

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :alerts_read]
    when action in [:index_for_alert, :evidence]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :alerts_update]
    when action in [:attach_detector_observation]
  )

  def attach_detector_observation(conn, %{"alert_id" => alert_id} = params) do
    envelope =
      params["envelope"] ||
        params |> Map.drop(["alert_id", "producer_attestation_id", "producer_attestation_ids"])

    producer_attestation_ids =
      params["producer_attestation_ids"] || params["producer_attestation_id"]

    with {:ok, organization_id} <- organization_id(conn),
         {:ok, result} <-
           ShadowOrchestrator.attach_detector_observation(
             organization_id,
             alert_id,
             envelope,
             producer_attestation_ids
           ) do
      conn
      |> put_status(:accepted)
      |> json(%{
        data: %{
          contract_hash_sha256: result.contract_hash,
          investigation_run: ShadowOrchestrator.serialize_run(result.run),
          consensus_claim: "producer_assertion",
          enforcement: "disabled"
        }
      })
    else
      {:error, :tenant_required} ->
        tenant_required(conn)

      {:error, {:invalid_envelope, errors}} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Invalid detector observation envelope", details: errors})

      {:error, :producer_attestation_required} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Governed producer attestation is required"})

      {:error, :alert_not_found_in_organization} ->
        not_found(conn)

      {:error, _reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Detector observation admission unavailable"})
    end
  end

  def index_for_alert(conn, %{"alert_id" => alert_id}) do
    with {:ok, organization_id} <- organization_id(conn),
         {:ok, runs} <- ShadowOrchestrator.list_runs_for_alert(organization_id, alert_id) do
      json(conn, %{
        data: Enum.map(runs, &ShadowOrchestrator.serialize_run/1),
        meta: %{count: length(runs)}
      })
    else
      {:error, :tenant_required} -> tenant_required(conn)
      {:error, _reason} -> not_found(conn)
    end
  end

  def evidence(conn, %{"id" => run_id}) do
    with {:ok, organization_id} <- organization_id(conn),
         run when not is_nil(run) <- ShadowOrchestrator.get_run(organization_id, run_id) do
      evidence = ShadowOrchestrator.list_evidence(organization_id, run.id)

      json(conn, %{
        data: Enum.map(evidence, &ShadowOrchestrator.serialize_evidence/1),
        meta: %{count: length(evidence), run_id: run.id}
      })
    else
      {:error, :tenant_required} -> tenant_required(conn)
      nil -> not_found(conn)
    end
  end

  defp organization_id(conn) do
    id =
      conn.assigns[:current_organization_id] ||
        current_user_organization_id(conn.assigns[:current_user])

    if is_binary(id) and id != "", do: {:ok, id}, else: {:error, :tenant_required}
  end

  defp current_user_organization_id(%{organization_id: id}), do: id

  defp current_user_organization_id(user) when is_map(user),
    do: user[:organization_id] || user["organization_id"]

  defp current_user_organization_id(_user), do: nil

  defp tenant_required(conn) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "Tenant context required"})
  end

  defp not_found(conn) do
    conn
    |> put_status(:not_found)
    |> json(%{error: "Investigation resource not found"})
  end
end
