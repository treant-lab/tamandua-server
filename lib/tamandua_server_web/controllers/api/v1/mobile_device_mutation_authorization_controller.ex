defmodule TamanduaServerWeb.API.V1.MobileDeviceMutationAuthorizationController do
  @moduledoc "Authenticated issuance and reconciliation for one-shot mobile device mutations."

  use TamanduaServerWeb, :controller

  import Ecto.Query

  alias TamanduaServer.Mobile.{MobileMutationAuthorization, MobileMutationProof}
  alias TamanduaServer.Repo
  alias TamanduaServer.Tenants

  require Logger

  @request_keys ~w(body installation_id operation)
  @operation "mobile_device_v2_upsert"

  def create(conn, params) do
    with :ok <- exact_request(params),
         {:ok, organization_id} <- active_organization_id(conn),
         {:ok, actor_id} <- current_actor_id(conn),
         {:ok, resource_id} <- resource_id(params["body"]),
         {:ok, issued} <-
           MobileMutationProof.issue(organization_id, %{
             actor_id: actor_id,
             installation_id: params["installation_id"],
             resource_id: resource_id,
             body: params["body"]
           }) do
      conn
      |> no_store()
      |> put_status(:created)
      |> json(%{
        authorization_id: issued.authorization_id,
        signed_fields: issued.signed_fields
      })
    else
      {:error, :unauthorized} ->
        error(conn, :unauthorized, "authentication_required")

      {:error, :tenant_inactive} ->
        error(conn, :forbidden, "tenant_inactive")

      {:error, reason} ->
        issuance_error(conn, reason)
    end
  rescue
    _exception ->
      Logger.error("Mobile mutation authorization issuance raised unexpectedly")
      error(conn, :internal_server_error, "mobile_mutation_authorization_failed")
  catch
    _kind, _reason ->
      Logger.error("Mobile mutation authorization issuance exited unexpectedly")
      error(conn, :internal_server_error, "mobile_mutation_authorization_failed")
  end

  def show(conn, %{"authorization_id" => authorization_id}) do
    with {:ok, organization_id} <- active_organization_id(conn),
         {:ok, actor_id} <- current_actor_id(conn),
         {:ok, id} <- cast_id(authorization_id),
         %MobileMutationAuthorization{} = authorization <-
           Repo.one(
             from(candidate in MobileMutationAuthorization,
               where:
                 candidate.id == ^id and candidate.organization_id == ^organization_id and
                   candidate.actor_id == ^actor_id
             )
           ) do
      conn
      |> no_store()
      |> json(status_payload(authorization, DateTime.utc_now()))
    else
      {:error, :tenant_inactive} -> error(conn, :forbidden, "tenant_inactive")
      _ -> error(conn, :not_found, "mobile_mutation_authorization_unavailable")
    end
  rescue
    _exception ->
      Logger.error("Mobile mutation authorization status lookup raised unexpectedly")
      error(conn, :internal_server_error, "mobile_mutation_authorization_failed")
  catch
    _kind, _reason ->
      Logger.error("Mobile mutation authorization status lookup exited unexpectedly")
      error(conn, :internal_server_error, "mobile_mutation_authorization_failed")
  end

  defp exact_request(params) when is_map(params) do
    if Enum.sort(Map.keys(params)) == @request_keys and params["operation"] == @operation and
         is_binary(params["installation_id"]) and is_map(params["body"]),
       do: :ok,
       else: {:error, :invalid_request}
  end

  defp exact_request(_params), do: {:error, :invalid_request}

  defp resource_id(%{"device_id" => device_id}) when is_binary(device_id) and device_id != "",
    do: {:ok, device_id}

  defp resource_id(_body), do: {:error, :invalid_request}

  defp status_payload(%{consumed_at: consumed_at} = authorization, _now)
       when not is_nil(consumed_at) do
    %{
      authorization_id: authorization.id,
      status: "consumed",
      result: %{
        outcome: authorization.result_outcome,
        resource_id: authorization.result_resource_id
      }
    }
  end

  defp status_payload(authorization, now) do
    status =
      if DateTime.compare(now, authorization.expires_at) == :lt,
        do: "pending",
        else: "expired"

    %{authorization_id: authorization.id, status: status}
  end

  defp cast_id(value) do
    case Ecto.UUID.cast(value) do
      {:ok, id} -> {:ok, id}
      :error -> {:error, :invalid_id}
    end
  end

  defp current_organization_id(conn) do
    value = conn.assigns[:current_organization_id]

    if is_binary(value) and value != "", do: {:ok, value}, else: {:error, :unauthorized}
  end

  defp active_organization_id(conn) do
    with {:ok, organization_id} <- current_organization_id(conn),
         {:ok, organization} <- Tenants.get_organization(organization_id),
         true <- organization.id == organization_id and Tenants.organization_active?(organization) do
      {:ok, organization_id}
    else
      {:error, :unauthorized} -> {:error, :unauthorized}
      _ -> {:error, :tenant_inactive}
    end
  end

  defp current_actor_id(conn) do
    value = field(conn.assigns[:current_user], :id)
    if is_binary(value) and value != "", do: {:ok, value}, else: {:error, :unauthorized}
  end

  defp field(%{} = value, key), do: Map.get(value, key) || Map.get(value, to_string(key))
  defp field(_, _key), do: nil

  defp no_store(conn), do: put_resp_header(conn, "cache-control", "no-store")

  defp issuance_error(conn, reason)
       when reason in [:active_identity_key_not_found, :identity_recovery_in_progress] do
    error(conn, :conflict, "mobile_mutation_authorization_unavailable")
  end

  defp issuance_error(conn, reason)
       when reason in [
              :invalid_request,
              :invalid_request_body,
              :invalid_ttl,
              :invalid_server_time
            ] do
    error(conn, :bad_request, "invalid_mobile_mutation_authorization_request")
  end

  defp issuance_error(conn, {:invalid_field, _field}) do
    error(conn, :bad_request, "invalid_mobile_mutation_authorization_request")
  end

  defp issuance_error(conn, %Ecto.Changeset{}) do
    error(conn, :unprocessable_entity, "mobile_mutation_authorization_rejected")
  end

  defp issuance_error(conn, _unexpected) do
    Logger.error("Mobile mutation authorization issuance returned an unexpected result")
    error(conn, :internal_server_error, "mobile_mutation_authorization_failed")
  end

  defp error(conn, status, code) do
    conn
    |> no_store()
    |> put_status(status)
    |> json(%{error: %{code: code}})
  end
end
