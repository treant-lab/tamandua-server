defmodule TamanduaServerWeb.API.V1.FleetQueryController do
  @moduledoc """
  Fleet-wide live osquery endpoints.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.FleetQueries

  action_fallback(TamanduaServerWeb.FallbackController)

  def index(conn, params) do
    with_current_organization(conn, fn org_id ->
      limit = parse_int(params["limit"], 50)

      runs =
        org_id
        |> FleetQueries.list_runs(limit: limit)
        |> Enum.map(&format_run/1)

      json(conn, %{data: runs, total: length(runs)})
    end)
  end

  def create(conn, params) do
    with_current_organization(conn, fn org_id ->
      user_id = get_current_user_id(conn)

      case FleetQueries.create_osquery_run(org_id, params, created_by_user_id: user_id) do
        {:ok, run} ->
          conn
          |> put_status(:accepted)
          |> json(%{data: format_run_detail(run), message: "Fleet query queued"})

        {:error, :missing_query} ->
          conn |> put_status(:bad_request) |> json(%{error: "query is required"})

        {:error, reason} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: inspect(reason)})
      end
    end)
  end

  def show(conn, %{"id" => id}) do
    with_current_organization(conn, fn org_id ->
      with {:ok, run} <- FleetQueries.get_run(org_id, id),
           {:ok, targets} <- FleetQueries.list_targets(org_id, id) do
        json(conn, %{data: format_run_detail(run, targets)})
      else
        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "Fleet query not found"})

        {:error, reason} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: inspect(reason)})
      end
    end)
  end

  def targets(conn, %{"id" => id}) do
    with_current_organization(conn, fn org_id ->
      case FleetQueries.list_targets(org_id, id) do
        {:ok, targets} ->
          json(conn, %{data: Enum.map(targets, &format_target/1), total: length(targets)})

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "Fleet query not found"})
      end
    end)
  end

  def cancel(conn, %{"id" => id}) do
    with_current_organization(conn, fn org_id ->
      case FleetQueries.cancel_run(org_id, id) do
        {:ok, run, result} ->
          json(conn, %{
            data: format_run_detail(run),
            cancel_result: format_cancel_result(result),
            message: "Pending fleet query targets cancelled"
          })

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "Fleet query not found"})

        {:error, reason} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: inspect(reason)})
      end
    end)
  end

  defp format_run(run) do
    %{
      id: run.id,
      organization_id: run.organization_id,
      query_hash: run.query_hash,
      query_preview: query_preview(run.query),
      status: run.status,
      target_count: run.target_count,
      queued_count: run.queued_count,
      skipped_count: run.skipped_count,
      completed_count: run.completed_count,
      failed_count: run.failed_count,
      started_at: format_datetime(run.started_at),
      completed_at: format_datetime(run.completed_at),
      inserted_at: format_datetime(run.inserted_at)
    }
  end

  defp format_run_detail(run, targets \\ nil) do
    run
    |> format_run()
    |> Map.merge(%{
      query: run.query,
      requested_agent_ids: run.requested_agent_ids,
      options: run.options,
      targets: if(is_list(targets), do: Enum.map(targets, &format_target/1), else: nil)
    })
  end

  defp format_target(target) do
    %{
      id: target.id,
      agent_id: target.agent_id,
      hostname: target.hostname,
      os_type: target.os_type,
      status: target.status,
      agent_command_id: target.agent_command_id,
      skip_reason: target.skip_reason,
      result_summary: target.result_summary,
      error: target.error,
      completed_at: format_datetime(target.completed_at)
    }
  end

  defp format_cancel_result(result) do
    %{
      cancelled_count: result.cancelled |> length(),
      already_sent_count: result.already_sent |> length(),
      skipped_count: result.skipped |> length(),
      not_cancellable_count: result.not_cancellable |> length()
    }
  end

  defp query_preview(query) when is_binary(query) do
    query
    |> String.replace(~r/\s+/, " ")
    |> String.trim()
    |> String.slice(0, 160)
  end

  defp query_preview(_), do: nil

  defp with_current_organization(conn, fun) do
    case get_current_organization_id(conn) do
      org_id when is_binary(org_id) ->
        fun.(org_id)

      _ ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "organization context required"})
    end
  end

  defp get_current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      case conn.assigns[:current_user] do
        nil -> nil
        user when is_map(user) -> Map.get(user, :organization_id) || Map.get(user, "organization_id")
        _ -> nil
      end
  end

  defp get_current_user_id(conn) do
    case conn.assigns[:current_user] do
      nil -> nil
      user when is_map(user) -> Map.get(user, :id) || Map.get(user, "id")
      _ -> nil
    end
  end

  defp parse_int(value, _default) when is_integer(value), do: value

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(_, default), do: default

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(other), do: to_string(other)
end
