defmodule TamanduaServerWeb.API.V1.IOCController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Detection.IOCs
  alias TamanduaServer.Detection.IOCReload

  action_fallback(TamanduaServerWeb.FallbackController)

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :threat_intel_read] when action in [:index, :show]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :threat_intel_add] when action in [:create, :bulk_create]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :threat_intel_manage] when action in [:update, :delete]
  )

  def index(conn, params) do
    with {:ok, organization_id} <- current_organization_id(conn) do
      filters = %{
        type: params["type"],
        enabled: params["enabled"],
        organization_id: organization_id
      }

      iocs = IOCs.list_iocs(filters)
      json(conn, %{data: Enum.map(iocs, &serialize/1)})
    end
  end

  def show(conn, %{"id" => id}) do
    with {:ok, organization_id} <- current_organization_id(conn),
         %{} = ioc <- IOCs.get_ioc_for_organization(organization_id, id) do
      json(conn, %{data: serialize(ioc)})
    else
      nil -> {:error, :not_found}
      error -> error
    end
  end

  def create(conn, params) do
    with {:ok, organization_id} <- current_organization_id(conn) do
      case IOCs.create_ioc(Map.put(params, "organization_id", organization_id)) do
        {:ok, ioc} ->
          schedule_ioc_reload()

          conn
          |> put_status(:created)
          |> json(%{data: serialize(ioc)})

        {:error, %Ecto.Changeset{} = changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{errors: format_errors(changeset)})

        {:error, _reason} ->
          {:error, :unprocessable_entity}
      end
    end
  end

  def update(conn, %{"id" => id} = params) do
    with {:ok, organization_id} <- current_organization_id(conn),
         %{} = ioc <- IOCs.get_owned_ioc_for_organization(organization_id, id) do
      case IOCs.update_ioc(ioc, Map.delete(params, "organization_id")) do
        {:ok, ioc} ->
          schedule_ioc_reload()
          json(conn, %{data: serialize(ioc)})

        {:error, changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{errors: format_errors(changeset)})
      end
    else
      nil -> {:error, :not_found}
      error -> error
    end
  end

  def delete(conn, %{"id" => id}) do
    with {:ok, organization_id} <- current_organization_id(conn),
         %{} = ioc <- IOCs.get_owned_ioc_for_organization(organization_id, id) do
      case IOCs.delete_ioc(ioc) do
        {:ok, _} ->
          schedule_ioc_reload()
          send_resp(conn, :no_content, "")

        {:error, _} ->
          conn
          |> put_status(400)
          |> json(%{error: "Failed to delete IOC"})
      end
    else
      nil -> {:error, :not_found}
      error -> error
    end
  end

  def bulk_create(conn, %{"iocs" => iocs_params})
      when is_list(iocs_params) and length(iocs_params) <= 100 do
    with {:ok, organization_id} <- current_organization_id(conn),
         true <- Enum.all?(iocs_params, &is_map/1) do
      results =
        Enum.map(iocs_params, fn params ->
          case IOCs.create_ioc(Map.put(params, "organization_id", organization_id)) do
            {:ok, ioc} -> {:ok, serialize(ioc)}
            {:error, %Ecto.Changeset{} = changeset} -> {:error, format_errors(changeset)}
            {:error, reason} -> {:error, %{scope: [to_string(reason)]}}
          end
        end)

      successful = Enum.count(results, fn {status, _} -> status == :ok end)
      failed = length(results) - successful

      if successful > 0, do: schedule_ioc_reload()

      json(conn, %{
        data: %{
          successful: successful,
          failed: failed,
          results:
            Enum.map(results, fn
              {:ok, ioc} -> %{success: true, data: ioc}
              {:error, errors} -> %{success: false, errors: errors}
            end)
        }
      })
    else
      false ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "every IOC entry must be an object"})

      error ->
        error
    end
  end

  def bulk_create(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "iocs must contain at most 100 entries"})
  end

  # Admit a durable, coalesced IOC snapshot reload.
  defp schedule_ioc_reload do
    IOCReload.schedule()
  end

  defp current_organization_id(conn) do
    organization_id =
      conn.assigns[:current_organization_id] ||
        field(conn.assigns[:current_user], :organization_id)

    if is_binary(organization_id) and organization_id != "" do
      {:ok, organization_id}
    else
      {:error, :unauthorized}
    end
  end

  defp field(%{} = value, key), do: Map.get(value, key) || Map.get(value, to_string(key))
  defp field(_, _), do: nil

  defp serialize(ioc) do
    %{
      id: ioc.id,
      type: ioc.type,
      value: ioc.value,
      description: ioc.description,
      enabled: ioc.enabled,
      source: ioc.source,
      severity: ioc.severity,
      tags: ioc.tags || [],
      created_at: iso8601(ioc.inserted_at),
      updated_at: iso8601(ioc.updated_at)
    }
  end

  defp iso8601(nil), do: nil
  defp iso8601(%DateTime{} = value), do: DateTime.to_iso8601(value)

  defp iso8601(%NaiveDateTime{} = value) do
    value
    |> DateTime.from_naive!("Etc/UTC")
    |> DateTime.to_iso8601()
  end

  defp iso8601(value), do: to_string(value)

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> changeset_error_opt(key) |> to_string()
      end)
    end)
  end

  defp changeset_error_opt(opts, "count"), do: Keyword.get(opts, :count, "count")
  defp changeset_error_opt(opts, "validation"), do: Keyword.get(opts, :validation, "validation")
  defp changeset_error_opt(opts, "kind"), do: Keyword.get(opts, :kind, "kind")
  defp changeset_error_opt(opts, "type"), do: Keyword.get(opts, :type, "type")
  defp changeset_error_opt(_opts, key), do: key
end
