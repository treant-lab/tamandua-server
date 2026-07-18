defmodule TamanduaServerWeb.API.V1.MobileDeviceIdentityController do
  @moduledoc """
  Tenant-authenticated HTTP surface for mobile device identity protocols.

  Organization identity always comes from the authenticated connection. Generic
  P-256 proof and the staged iOS App Attest flow have separate entry points;
  only the server-side staged flow may activate an App Attest identity.
  """

  use TamanduaServerWeb, :controller

  import Ecto.Query

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentity,
    MobileDeviceIdentityAppleFlow,
    MobileDeviceIdentityKey
  }

  alias TamanduaServer.Repo

  @serialized_key_fields ~w(
    installation_id platform key_scope_id device_key_id algorithm proof_state
    attestation_state lifecycle_state activated_at last_proof_at revoked_at rotated_at
  )a

  plug(TamanduaServerWeb.Plugs.Authorize, :agents_delete when action in [:revoke])

  def challenge(conn, params) do
    with {:ok, organization_id} <- tenant_id(conn),
         {:ok, issued} <-
           MobileDeviceIdentity.issue_challenge(organization_id, challenge_attrs(params)) do
      conn
      |> put_status(:created)
      |> json(%{data: issued})
    else
      error -> render_error(conn, error)
    end
  end

  def enroll(conn, params), do: verify_proof(conn, params, "enroll")
  def rotate(conn, params), do: verify_proof(conn, params, "rotate")

  def app_attest_challenge(conn, params) do
    with {:ok, organization_id} <- tenant_id(conn),
         {:ok, issued} <- MobileDeviceIdentityAppleFlow.issue_challenge(organization_id, params) do
      conn |> put_status(:created) |> json(%{data: issued})
    else
      error -> render_error(conn, error)
    end
  end

  def app_attest_attestation(conn, params) do
    with {:ok, organization_id} <- tenant_id(conn),
         {:ok, receipt} <-
           MobileDeviceIdentityAppleFlow.submit_attestation(organization_id, params) do
      json(conn, %{data: receipt})
    else
      error -> render_error(conn, error)
    end
  end

  def app_attest_assertion(conn, params) do
    with {:ok, organization_id} <- tenant_id(conn),
         {:ok, receipt} <- MobileDeviceIdentityAppleFlow.submit_assertion(organization_id, params) do
      json(conn, %{data: receipt})
    else
      error -> render_error(conn, error)
    end
  end

  def status(conn, %{"installation_id" => installation_id}) do
    with {:ok, organization_id} <- tenant_id(conn),
         {:ok, installation_id} <- required_string(installation_id) do
      latest = latest_identity(organization_id, installation_id)
      latest_lifecycle_state = latest && latest.lifecycle_state
      active = if latest_lifecycle_state == "active", do: latest

      json(conn, %{
        data: %{
          installation_id: installation_id,
          proof_required: not is_nil(latest_lifecycle_state),
          active_key: active,
          latest_lifecycle_state: latest_lifecycle_state || "unbound"
        }
      })
    else
      error -> render_error(conn, error)
    end
  end

  def status(conn, _params), do: render_error(conn, {:error, :invalid_request})

  def revoke(conn, %{"installation_id" => installation_id} = params) do
    with {:ok, organization_id} <- tenant_id(conn),
         {:ok, installation_id} <- required_string(installation_id),
         {:ok, claimed_key_id} <- required_string(Map.get(params, "device_key_id")),
         {:ok, revoked} <- revoke_bound(organization_id, installation_id, claimed_key_id) do
      json(conn, %{data: serialize_key(revoked)})
    else
      error -> render_error(conn, error)
    end
  end

  def revoke(conn, _params), do: render_error(conn, {:error, :invalid_request})

  defp verify_proof(conn, params, purpose) do
    proof = params |> Map.delete(:purpose) |> Map.put("purpose", purpose)

    with {:ok, organization_id} <- tenant_id(conn),
         {:ok, key} <- MobileDeviceIdentity.verify_and_bind(organization_id, proof) do
      json(conn, %{data: serialize_key(key)})
    else
      error -> render_error(conn, error)
    end
  end

  defp challenge_attrs(params) do
    Map.take(params, ["installation_id", "platform", "purpose"])
  end

  defp tenant_id(conn) do
    case conn.assigns[:current_organization_id] do
      organization_id when is_binary(organization_id) -> {:ok, organization_id}
      _ -> {:error, :tenant_context_required}
    end
  end

  defp identity_query(organization_id, installation_id) do
    MobileDeviceIdentityKey
    |> where(
      [key],
      key.organization_id == ^organization_id and key.installation_id == ^installation_id
    )
  end

  defp latest_identity(organization_id, installation_id) do
    organization_id
    |> identity_query(installation_id)
    |> order_by([key], desc: key.inserted_at)
    |> limit(1)
    |> select([key], map(key, ^@serialized_key_fields))
    |> Repo.one()
  end

  defp revoke_bound(organization_id, installation_id, claimed_key_id) do
    Repo.transaction(fn ->
      active_key_id =
        organization_id
        |> identity_query(installation_id)
        |> where([key], key.lifecycle_state == "active")
        |> lock("FOR UPDATE")
        |> select([key], key.device_key_id)
        |> Repo.one()

      if secure_equal?(active_key_id, claimed_key_id) do
        case MobileDeviceIdentity.revoke_active(organization_id, installation_id) do
          {:ok, revoked} -> revoked
          {:error, reason} -> Repo.rollback(reason)
        end
      else
        Repo.rollback(:identity_not_found)
      end
    end)
  end

  defp serialize_key(nil), do: nil

  defp serialize_key(%MobileDeviceIdentityKey{} = key) do
    key
    |> Map.from_struct()
    |> Map.take(@serialized_key_fields)
  end

  defp required_string(value) when is_binary(value) do
    case String.trim(value) do
      "" -> {:error, :invalid_request}
      normalized -> {:ok, normalized}
    end
  end

  defp required_string(_value), do: {:error, :invalid_request}

  defp secure_equal?(expected, supplied)
       when is_binary(expected) and is_binary(supplied) and
              byte_size(expected) == byte_size(supplied),
       do: Plug.Crypto.secure_compare(expected, supplied)

  defp secure_equal?(_expected, _supplied), do: false

  defp render_error(conn, {:error, %Ecto.Changeset{}}),
    do: error_response(conn, :unprocessable_entity, "identity_request_invalid")

  defp render_error(conn, {:error, :tenant_context_required}),
    do: error_response(conn, :forbidden, "tenant_context_required")

  defp render_error(conn, {:error, :invalid_request}),
    do: error_response(conn, :bad_request, "identity_request_invalid")

  defp render_error(conn, {:error, :challenge_unavailable}),
    do: error_response(conn, :conflict, "challenge_unavailable")

  defp render_error(conn, {:error, :challenge_expired}),
    do: error_response(conn, :gone, "challenge_expired")

  defp render_error(conn, {:error, :app_attest_context_expired}),
    do: error_response(conn, :gone, "app_attest_context_expired")

  defp render_error(conn, {:error, :app_attest_context_unavailable}),
    do: error_response(conn, :conflict, "app_attest_context_unavailable")

  defp render_error(conn, {:error, :device_identity_conflict}),
    do: error_response(conn, :conflict, "device_identity_conflict")

  defp render_error(conn, {:error, :rotation_required}),
    do: error_response(conn, :conflict, "rotation_required")

  defp render_error(conn, {:error, :re_enrollment_authorization_required}),
    do: error_response(conn, :forbidden, "re_enrollment_authorization_required")

  defp render_error(conn, {:error, :active_key_not_found}),
    do: error_response(conn, :not_found, "identity_not_found")

  defp render_error(conn, {:error, :identity_not_found}),
    do: error_response(conn, :not_found, "identity_not_found")

  defp render_error(conn, {:error, reason})
       when reason in [:replacement_key_must_differ, :previous_key_mismatch],
       do: error_response(conn, :conflict, "rotation_invalid")

  defp render_error(conn, {:error, _proof_error}),
    do: error_response(conn, :unprocessable_entity, "device_proof_invalid")

  defp render_error(conn, _error),
    do: error_response(conn, :unprocessable_entity, "identity_request_invalid")

  defp error_response(conn, status, code) do
    conn
    |> put_status(status)
    |> json(%{error: %{code: code}})
  end
end
