defmodule TamanduaServerWeb.API.V1.DetectorProducerRegistryController do
  @moduledoc "Tenant-scoped administrative API for detector producer attestations."

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Investigations.DetectorProducerRegistry

  plug TamanduaServerWeb.Plugs.RBAC, permission: :system_settings

  def index(conn, _params) do
    with {:ok, organization_id} <- organization_id(conn) do
      records = DetectorProducerRegistry.list(organization_id)
      json(conn, %{data: Enum.map(records, &DetectorProducerRegistry.serialize/1)})
    else
      {:error, :tenant_required} -> tenant_required(conn)
    end
  end

  def create(conn, params) do
    with {:ok, organization_id} <- organization_id(conn),
         {:ok, actor_id} <- actor_id(conn),
         {:ok, record} <- DetectorProducerRegistry.attest(organization_id, actor_id, params) do
      conn
      |> put_status(:created)
      |> json(%{data: DetectorProducerRegistry.serialize(record), enforcement: "disabled"})
    else
      {:error, :tenant_required} -> tenant_required(conn)
      {:error, :actor_required} -> conn |> put_status(:unauthorized) |> json(%{error: "Authenticated actor required"})
      {:error, :unauthorized} -> conn |> put_status(:forbidden) |> json(%{error: "Producer registry administration denied"})
      {:error, %Ecto.Changeset{} = changeset} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "Invalid producer attestation", details: errors(changeset)})
    end
  end

  def revoke(conn, %{"id" => id}) do
    with {:ok, organization_id} <- organization_id(conn),
         {:ok, actor_id} <- actor_id(conn),
         {:ok, record} <- DetectorProducerRegistry.revoke(organization_id, id, actor_id) do
      json(conn, %{data: DetectorProducerRegistry.serialize(record), enforcement: "disabled"})
    else
      {:error, :tenant_required} -> tenant_required(conn)
      {:error, :actor_required} -> conn |> put_status(:unauthorized) |> json(%{error: "Authenticated actor required"})
      {:error, :unauthorized} -> conn |> put_status(:forbidden) |> json(%{error: "Producer registry administration denied"})
      {:error, :not_found} -> conn |> put_status(:not_found) |> json(%{error: "Producer attestation not found"})
    end
  end

  defp organization_id(conn) do
    id = conn.assigns[:current_organization_id] || value(conn.assigns[:current_user], :organization_id)
    if is_binary(id) and id != "", do: {:ok, id}, else: {:error, :tenant_required}
  end

  defp actor_id(conn) do
    id = value(conn.assigns[:current_user], :id)
    if is_binary(id) and id != "", do: {:ok, id}, else: {:error, :actor_required}
  end

  defp value(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, Atom.to_string(key))
  defp value(_, _), do: nil

  defp tenant_required(conn), do: conn |> put_status(:forbidden) |> json(%{error: "Tenant context required"})

  defp errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc -> String.replace(acc, "%{#{key}}", to_string(value)) end)
    end)
  end
end
