defmodule TamanduaServerWeb.API.V1.MobileDeviceIdentityRecoveryController do
  @moduledoc """
  Tenant-authenticated HTTP surface for server-owned identity recovery intents.

  The clear recovery token is returned only when an intent is created. Status
  and resolution responses expose neither its digest nor cryptographic key
  material. Client-provided authorization and step-up claims are ignored.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Authorization.RBAC
  alias TamanduaServer.Mobile.MobileDeviceIdentityRecovery

  @serialized_fields ~w(
    id installation_id purpose state old_device_key_id candidate_device_key_id
    reason step_up_required authorization_state authorization_provenance resolution
    issued_at expires_at token_consumed_at last_checked_at consumed_at denied_at expired_at
  )a

  def create(conn, params) do
    with {:ok, organization_id} <- tenant_id(conn),
         :ok <- authorize_recovery_create(conn, params),
         {:ok, issued} <-
           MobileDeviceIdentityRecovery.issue(
             organization_id,
             recovery_attrs(params),
             requested_by_id: actor_id(conn),
             authorization_provenance: authorization_provenance(conn)
           ) do
      data =
        issued.intent
        |> serialize_intent()
        |> Map.put(:recovery_token, issued.recovery_token)
        |> Map.put(:token_exposure, "one_time")

      conn |> no_store() |> put_status(:created) |> json(%{data: data})
    else
      error -> render_error(conn, error)
    end
  end

  def status(conn, %{"intent_id" => intent_id}) do
    with {:ok, organization_id} <- tenant_id(conn),
         {:ok, intent_id} <- required_string(intent_id),
         {:ok, intent} <- MobileDeviceIdentityRecovery.status(organization_id, intent_id) do
      conn |> no_store() |> json(%{data: serialize_intent(intent)})
    else
      error -> render_error(conn, error)
    end
  end

  def status(conn, _params), do: render_error(conn, {:error, :invalid_request})

  def resolve(conn, %{"intent_id" => intent_id} = params) do
    with {:ok, organization_id} <- tenant_id(conn),
         {:ok, intent_id} <- required_string(intent_id),
         {:ok, recovery_token} <- required_string(Map.get(params, "recovery_token")),
         {:ok, intent} <-
           MobileDeviceIdentityRecovery.resolve(organization_id, intent_id, recovery_token) do
      status = if intent.authorization_state == "pending_authorization", do: :accepted, else: :ok
      conn |> no_store() |> put_status(status) |> json(%{data: serialize_intent(intent)})
    else
      error -> render_error(conn, error)
    end
  end

  def resolve(conn, _params), do: render_error(conn, {:error, :invalid_request})

  defp recovery_attrs(params) do
    Map.take(params, [
      "installation_id",
      "purpose",
      "old_device_key_id",
      "candidate_device_key_id",
      "reason"
    ])
  end

  defp authorize_recovery_create(_conn, %{"purpose" => "reconcile_rotation"}), do: :ok

  defp authorize_recovery_create(conn, _params) do
    if RBAC.can?(conn.assigns[:current_user], :agents_delete) do
      :ok
    else
      {:error, :recovery_authorization_required}
    end
  end

  defp authorization_provenance(conn) do
    %{
      "actor_user_id" => actor_id(conn),
      "authentication_source" => "authenticated_api_session",
      "requested_via" => "mobile_device_identity_recovery_api",
      "step_up_evidence" => "not_verified"
    }
  end

  defp actor_id(conn) do
    case conn.assigns[:current_user] do
      %{id: id} when is_binary(id) -> id
      _ -> nil
    end
  end

  defp tenant_id(conn) do
    case conn.assigns[:current_organization_id] do
      organization_id when is_binary(organization_id) -> {:ok, organization_id}
      _ -> {:error, :tenant_context_required}
    end
  end

  defp serialize_intent(%MobileDeviceIdentityRecovery{} = intent) do
    intent |> Map.from_struct() |> Map.take(@serialized_fields)
  end

  defp required_string(value) when is_binary(value) do
    case String.trim(value) do
      "" -> {:error, :invalid_request}
      normalized -> {:ok, normalized}
    end
  end

  defp required_string(_value), do: {:error, :invalid_request}

  defp render_error(conn, {:error, %Ecto.Changeset{}}),
    do: error_response(conn, :unprocessable_entity, "recovery_intent_invalid")

  defp render_error(conn, {:error, :tenant_context_required}),
    do: error_response(conn, :forbidden, "tenant_context_required")

  defp render_error(conn, {:error, :invalid_request}),
    do: error_response(conn, :bad_request, "recovery_request_invalid")

  defp render_error(conn, {:error, :recovery_authorization_required}),
    do: error_response(conn, :forbidden, "recovery_authorization_required")

  defp render_error(conn, {:error, :intent_expired}),
    do: error_response(conn, :gone, "recovery_intent_expired")

  defp render_error(conn, {:error, reason})
       when reason in [:intent_unavailable, :invalid_recovery_token, :identity_not_found],
       do: error_response(conn, :not_found, "recovery_intent_unavailable")

  defp render_error(conn, {:error, reason})
       when reason in [
              :invalid_ttl,
              :invalid_purpose,
              :candidate_key_required,
              :candidate_key_must_differ,
              :candidate_key_binding_invalid
            ],
       do: error_response(conn, :unprocessable_entity, "recovery_intent_invalid")

  defp render_error(conn, _error),
    do: error_response(conn, :unprocessable_entity, "recovery_intent_invalid")

  defp error_response(conn, status, code) do
    conn |> no_store() |> put_status(status) |> json(%{error: %{code: code}})
  end

  defp no_store(conn), do: put_resp_header(conn, "cache-control", "no-store")
end
