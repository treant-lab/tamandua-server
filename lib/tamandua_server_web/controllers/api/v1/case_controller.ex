defmodule TamanduaServerWeb.API.V1.CaseController do
  @moduledoc "API for the canonical security case projection."

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Cases

  def create(conn, params) do
    with {:ok, organization_id} <- organization_id(conn),
         {:ok, user_id} <- user_id(conn),
         attrs <- Map.put(params, "created_by", user_id),
         {:ok, case_view} <- Cases.create(organization_id, attrs) do
      conn
      |> put_status(:created)
      |> json(%{data: case_view})
    else
      {:error, :tenant_required} ->
        tenant_required(conn)

      {:error, :user_required} ->
        conn |> put_status(:forbidden) |> json(%{error: "User context required"})

      {:error, changeset = %Ecto.Changeset{}} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "Invalid case", details: changeset_errors(changeset)})
    end
  end

  def index(conn, params) do
    with {:ok, organization_id} <- organization_id(conn) do
      opts =
        [
          status: params["status"],
          severity: params["severity"],
          assigned_to: params["owner_id"],
          search: params["search"],
          limit: parse_int(params["limit"], 50, 1, 200),
          offset: parse_int(params["offset"], 0, 0, 100_000)
        ]
        |> Enum.reject(fn {_key, value} -> is_nil(value) end)

      cases = Cases.list(organization_id, opts)
      json(conn, %{data: cases, meta: %{count: length(cases)}})
    else
      {:error, :tenant_required} -> tenant_required(conn)
    end
  end

  def show(conn, %{"id" => id}) do
    with {:ok, organization_id} <- organization_id(conn),
         {:ok, case_view} <- Cases.get(organization_id, id) do
      json(conn, %{data: case_view})
    else
      {:error, :tenant_required} ->
        tenant_required(conn)

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Case not found"})
    end
  end

  defp organization_id(%{assigns: %{current_user: %{organization_id: id}}}) when is_binary(id),
    do: {:ok, id}

  defp organization_id(_conn), do: {:error, :tenant_required}

  defp user_id(%{assigns: %{current_user: %{id: id}}}) when is_binary(id), do: {:ok, id}
  defp user_id(_conn), do: {:error, :user_required}

  defp tenant_required(conn) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "Tenant context required"})
  end

  defp parse_int(nil, default, _min, _max), do: default

  defp parse_int(value, _default, min, max) when is_integer(value),
    do: value |> max(min) |> min(max)

  defp parse_int(value, default, min, max) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, ""} -> parsed |> max(min) |> min(max)
      _ -> default
    end
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
