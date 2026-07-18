defmodule TamanduaServer.Accounts.PlatformOperatorAuthorization do
  @moduledoc """
  Pure fail-closed policy for platform-operator authorization.

  Callers must supply authority material loaded by the platform authority
  context. Tenant roles and organization membership are intentionally absent.
  """

  alias TamanduaServer.Accounts.{
    PlatformOperatorCapabilities,
    PlatformOperatorElevationProof,
    PlatformOperatorGrant,
    PlatformOperatorSession
  }

  def evaluate(actor, capability, grant, elevation, now \\ DateTime.utc_now()) do
    with {:ok, capability} <- PlatformOperatorCapabilities.normalize(capability),
         :ok <- validate_actor(actor),
         :ok <- valid_grant(actor.user, capability, grant, now),
         :ok <- valid_elevation(actor, capability, grant, elevation, now) do
      {:ok,
       %{
         capability: capability,
         grant_id: grant.id,
         elevation_proof_id: elevation.id,
         user_id: actor.user.id
       }}
    end
  end

  def validate_actor(actor), do: active_session_actor(actor)

  defp active_session_actor(%{
         user: %{id: user_id, is_active: true},
         session: %PlatformOperatorSession{user_id: user_id, auth_method: :session},
         session_binding: session_binding,
         elevation_proof: elevation_proof
       })
       when not is_nil(user_id) and is_binary(session_binding) and
              byte_size(session_binding) >= 32 and
              is_binary(elevation_proof) and byte_size(elevation_proof) >= 32,
       do: :ok

  defp active_session_actor(%{auth_method: method})
       when method in [:api_key, "api_key", :bearer, "bearer"],
       do: {:error, :api_keys_forbidden}

  defp active_session_actor(%{user: %{is_active: false}}), do: {:error, :inactive_user}
  defp active_session_actor(%{user: nil}), do: {:error, :unauthenticated}

  defp active_session_actor(_actor), do: {:error, :persistent_session_required}

  defp valid_grant(user, capability, %PlatformOperatorGrant{} = grant, now) do
    cond do
      grant.user_id != user.id -> {:error, :grant_subject_mismatch}
      not is_nil(grant.revoked_at) -> {:error, :grant_revoked}
      not future?(grant.expires_at, now) -> {:error, :grant_expired}
      capability not in grant.capabilities -> {:error, :capability_not_granted}
      true -> :ok
    end
  end

  defp valid_grant(_user, _capability, _grant, _now), do: {:error, :grant_missing}

  defp valid_elevation(
         actor,
         capability,
         grant,
         %PlatformOperatorElevationProof{} = elevation,
         now
       ) do
    supplied_proof_hash = digest(actor.elevation_proof)
    supplied_session_hash = digest(actor.session_binding)

    cond do
      elevation.revoked_at != nil ->
        {:error, :elevation_revoked}

      elevation.consumed_at != nil ->
        {:error, :elevation_already_consumed}

      elevation.user_id != actor.user.id ->
        {:error, :elevation_subject_mismatch}

      elevation.grant_id != grant.id ->
        {:error, :elevation_grant_mismatch}

      elevation.purpose != PlatformOperatorElevationProof.purpose() ->
        {:error, :elevation_wrong_purpose}

      elevation.audience != capability ->
        {:error, :elevation_wrong_audience}

      not issued_not_future?(elevation.issued_at, now) ->
        {:error, :elevation_issued_in_future}

      not future?(elevation.expires_at, now) ->
        {:error, :elevation_expired}

      not secure_equal?(elevation.proof_hash, supplied_proof_hash) ->
        {:error, :elevation_invalid}

      not secure_equal?(elevation.session_binding_hash, supplied_session_hash) ->
        {:error, :elevation_wrong_session}

      actor.session.revoked_at != nil ->
        {:error, :session_revoked}

      actor.session.user_id != actor.user.id ->
        {:error, :session_subject_mismatch}

      not future?(actor.session.expires_at, now) ->
        {:error, :session_expired}

      not secure_equal?(actor.session.binding_hash, supplied_session_hash) ->
        {:error, :session_binding_mismatch}

      true ->
        :ok
    end
  end

  defp valid_elevation(_actor, _capability, _grant, _elevation, _now),
    do: {:error, :elevation_missing}

  defp future?(%DateTime{} = expires_at, %DateTime{} = now),
    do: DateTime.compare(expires_at, now) == :gt

  defp future?(_expires_at, _now), do: false

  defp issued_not_future?(%DateTime{} = issued_at, %DateTime{} = now),
    do: DateTime.compare(issued_at, now) != :gt

  defp issued_not_future?(_issued_at, _now), do: false

  defp digest(value), do: :crypto.hash(:sha256, value)

  defp secure_equal?(left, right)
       when is_binary(left) and is_binary(right) and byte_size(left) == byte_size(right),
       do: Plug.Crypto.secure_compare(left, right)

  defp secure_equal?(_left, _right), do: false
end
