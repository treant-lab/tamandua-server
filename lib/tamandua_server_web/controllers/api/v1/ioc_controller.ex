defmodule TamanduaServerWeb.API.V1.IOCController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Detection.IOCs
  alias TamanduaServer.Detection.Engine

  action_fallback TamanduaServerWeb.FallbackController

  def index(conn, params) do
    filters = %{
      type: params["type"],
      enabled: params["enabled"]
    }

    iocs = IOCs.list_iocs(filters)
    json(conn, %{data: Enum.map(iocs, &serialize/1)})
  end

  def show(conn, %{"id" => id}) do
    ioc = IOCs.get_ioc!(id)
    json(conn, %{data: serialize(ioc)})
  end

  def create(conn, params) do
    case IOCs.create_ioc(params) do
      {:ok, ioc} ->
        # Reload IOCs into the detection engine ETS cache so workers see the new IOC
        schedule_ioc_reload()

        conn
        |> put_status(:created)
        |> json(%{data: serialize(ioc)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def update(conn, %{"id" => id} = params) do
    ioc = IOCs.get_ioc!(id)

    case IOCs.update_ioc(ioc, params) do
      {:ok, ioc} ->
        schedule_ioc_reload()
        json(conn, %{data: serialize(ioc)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def delete(conn, %{"id" => id}) do
    ioc = IOCs.get_ioc!(id)

    case IOCs.delete_ioc(ioc) do
      {:ok, _} ->
        schedule_ioc_reload()
        send_resp(conn, :no_content, "")

      {:error, _} ->
        conn
        |> put_status(400)
        |> json(%{error: "Failed to delete IOC"})
    end
  end

  def bulk_create(conn, %{"iocs" => iocs_params}) do
    results = Enum.map(iocs_params, fn params ->
      case IOCs.create_ioc(params) do
        {:ok, ioc} -> {:ok, serialize(ioc)}
        {:error, changeset} -> {:error, format_errors(changeset)}
      end
    end)

    successful = Enum.filter(results, fn {status, _} -> status == :ok end) |> length()
    failed = length(results) - successful

    # Reload IOCs into detection engine ETS if any were successfully created
    if successful > 0, do: schedule_ioc_reload()

    json(conn, %{
      data: %{
        successful: successful,
        failed: failed,
        results: Enum.map(results, fn
          {:ok, ioc} -> %{success: true, data: ioc}
          {:error, errors} -> %{success: false, errors: errors}
        end)
      }
    })
  end

  # Reload IOCs into the detection engine ETS table asynchronously.
  # Uses Task.start to avoid blocking the API response while the
  # ETS table is being refreshed from the database.
  defp schedule_ioc_reload do
    Task.start(fn ->
      Engine.reload_iocs()
    end)
  end

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
      created_at: DateTime.to_iso8601(ioc.inserted_at),
      updated_at: DateTime.to_iso8601(ioc.updated_at)
    }
  end

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
