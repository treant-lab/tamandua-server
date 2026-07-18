defmodule TamanduaServerWeb.API.V1.MobileSignedPostureController do
  @moduledoc "Tenant-authenticated HTTP boundary for signed mobile posture v1."

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Mobile.MobileSignedPostureIngestion

  plug(:put_no_store)
  plug(TamanduaServerWeb.Plugs.Authorize, :agents_update)

  def challenge(conn, params) do
    with :ok <- exact_keys(params, ["installation_id"]),
         {:ok, organization_id} <- tenant_id(conn),
         {:ok, actor_id} <- actor_id(conn),
         {:ok, auth_method} <- auth_method(conn),
         {:ok, installation_id} <- required_string(params["installation_id"]),
         {:ok, issued} <-
           MobileSignedPostureIngestion.issue(organization_id, installation_id,
             requested_by_id: actor_id,
             auth_method: auth_method
           ) do
      conn |> put_status(:created) |> json(%{data: issued})
    else
      error -> render_error(conn, error)
    end
  end

  def verify(conn, params) do
    with :ok <- exact_keys(params, ["envelope", "posture"]),
         {:ok, organization_id} <- tenant_id(conn),
         {:ok, envelope} <- required_map(params["envelope"]),
         {:ok, posture} <- required_map(params["posture"]),
         {:ok, result} <-
           MobileSignedPostureIngestion.verify(organization_id, envelope, posture) do
      receipt = result.receipt

      json(conn, %{
        data: %{
          state: "verified",
          receipt_id: receipt.id,
          installation_id: receipt.installation_id,
          device_key_id: receipt.device_key_id,
          posture_sha256: receipt.posture_sha256,
          observed_at: receipt.observed_at,
          verified_at: receipt.verified_at
        }
      })
    else
      error -> render_error(conn, error)
    end
  end

  def status(conn, %{"request_id" => request_id} = params) do
    with :ok <- exact_keys(params, ["request_id"]),
         {:ok, organization_id} <- tenant_id(conn),
         {:ok, request_id} <- required_string(request_id),
         {:ok, status} <- MobileSignedPostureIngestion.request_status(organization_id, request_id) do
      json(conn, %{data: status})
    else
      error -> render_error(conn, error)
    end
  end

  def status(conn, _params), do: render_error(conn, {:error, :invalid_request})

  defp exact_keys(map, expected) when is_map(map) do
    if Map.keys(map) |> Enum.sort() == Enum.sort(expected),
      do: :ok,
      else: {:error, :invalid_request}
  end

  defp exact_keys(_map, _expected), do: {:error, :invalid_request}
  defp required_map(value) when is_map(value), do: {:ok, value}
  defp required_map(_value), do: {:error, :invalid_request}

  defp required_string(value) when is_binary(value) do
    if value != "" and value == String.trim(value),
      do: {:ok, value},
      else: {:error, :invalid_request}
  end

  defp required_string(_value), do: {:error, :invalid_request}

  defp tenant_id(conn) do
    case conn.assigns[:current_organization_id] do
      value when is_binary(value) ->
        case Ecto.UUID.cast(value) do
          {:ok, organization_id} -> {:ok, organization_id}
          :error -> {:error, :tenant_context_required}
        end

      _ ->
        {:error, :tenant_context_required}
    end
  end

  defp actor_id(conn) do
    case conn.assigns[:current_user] do
      %{id: id} when is_binary(id) ->
        case Ecto.UUID.cast(id) do
          {:ok, actor_id} -> {:ok, actor_id}
          :error -> {:error, :invalid_request}
        end

      _ ->
        {:error, :invalid_request}
    end
  end

  defp auth_method(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] when token != "" -> {:ok, "bearer_user"}
      [] -> {:ok, "authenticated_session"}
      _ -> {:error, :invalid_request}
    end
  end

  defp render_error(conn, {:error, :tenant_context_required}),
    do: error_response(conn, :forbidden, "tenant_context_required")

  defp render_error(conn, {:error, :invalid_request}),
    do: error_response(conn, :bad_request, "signed_posture_request_invalid")

  defp render_error(conn, {:error, :signed_posture_store_unavailable}),
    do: error_response(conn, :service_unavailable, "signed_posture_store_unavailable")

  defp render_error(conn, {:error, :request_expired}),
    do: error_response(conn, :gone, "signed_posture_request_expired")

  defp render_error(conn, {:error, :request_unavailable}),
    do: error_response(conn, :conflict, "signed_posture_request_unavailable")

  defp render_error(conn, {:error, :identity_recovery_in_progress}),
    do: error_response(conn, :conflict, "signed_posture_identity_transition")

  defp render_error(conn, {:error, reason})
       when reason in [
              :active_identity_required,
              :active_identity_ambiguous,
              :active_identity_changed
            ],
       do: error_response(conn, :conflict, "signed_posture_identity_unavailable")

  defp render_error(conn, {:error, %Ecto.Changeset{}}),
    do: error_response(conn, :unprocessable_entity, "signed_posture_request_invalid")

  defp render_error(conn, {:error, _verification_error}),
    do: error_response(conn, :unprocessable_entity, "signed_posture_invalid")

  defp render_error(conn, _error),
    do: error_response(conn, :unprocessable_entity, "signed_posture_invalid")

  defp error_response(conn, status, code) do
    conn |> put_status(status) |> json(%{error: %{code: code}})
  end

  def put_no_store(conn, _opts), do: put_resp_header(conn, "cache-control", "no-store")
end
