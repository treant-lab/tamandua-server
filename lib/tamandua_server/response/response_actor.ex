defmodule TamanduaServer.Response.ResponseActor do
  @moduledoc """
  Builds the tenant-bound actor contract used by response execution.

  This helper is intentionally pure. HTTP callers have already authenticated
  the user; this boundary only proves that the authenticated user's tenant is
  exactly the tenant selected for the request before response work is queued.
  """

  @type t :: %{organization_id: Ecto.UUID.t(), user_id: Ecto.UUID.t()}

  @spec from_user_scope(map(), term()) :: {:ok, t()} | {:error, :forbidden}
  def from_user_scope(user, current_organization_id) when is_map(user) do
    with {:ok, user_id} <- canonical_uuid(field(user, :id)),
         {:ok, user_organization_id} <- canonical_uuid(field(user, :organization_id)),
         {:ok, request_organization_id} <- canonical_uuid(current_organization_id),
         true <- user_organization_id == request_organization_id do
      {:ok, %{organization_id: request_organization_id, user_id: user_id}}
    else
      _ -> {:error, :forbidden}
    end
  end

  def from_user_scope(_user, _current_organization_id), do: {:error, :forbidden}

  defp field(map, key), do: Map.get(map, key) || Map.get(map, Atom.to_string(key))

  defp canonical_uuid(value) when is_binary(value), do: Ecto.UUID.cast(value)
  defp canonical_uuid(_value), do: :error
end
