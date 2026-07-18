defmodule TamanduaServerWeb.API.V1.ResponseAuditController do
  @moduledoc """
  API controller for response action audit trail.

  Provides endpoints to query the audit trail of automated response actions,
  including ML-triggered quarantine, playbook executions, and manual analyst actions.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Response.Audit

  action_fallback(TamanduaServerWeb.FallbackController)

  plug(TamanduaServerWeb.Plugs.RBAC, permission: :response_view)

  @doc """
  List recent audit entries with optional filters.

  Query params:
  - `limit` - Maximum entries to return (default 100)
  - `offset` - Pagination offset (default 0)
  - `action_type` - Filter by action type (e.g., "quarantine_file", "kill_process")
  - `agent_id` - Filter by agent ID
  - `actor_type` - Filter by actor type ("system" or "user")
  - `from` - Start datetime (ISO8601)
  - `to` - End datetime (ISO8601)
  """
  def index(conn, params) do
    with {:ok, organization_id} <- current_organization_id(conn),
         {:ok, opts} <- build_filter_opts(params),
         {:ok, entries} <-
           normalize_audit_read_result(Audit.get_recent_actions(organization_id, opts)) do
      json(conn, %{
        data: Enum.map(entries, &serialize/1),
        pagination: %{
          limit: Keyword.get(opts, :limit, 100),
          offset: Keyword.get(opts, :offset, 0),
          returned: length(entries)
        }
      })
    end
  end

  @doc """
  Get audit entries for a specific agent.
  """
  def agent_actions(conn, %{"agent_id" => agent_id} = params) do
    with {:ok, organization_id} <- current_organization_id(conn),
         {:ok, opts} <- build_filter_opts(Map.delete(params, "agent_id")),
         {:ok, entries} <-
           normalize_audit_read_result(
             Audit.get_actions_for_agent(organization_id, agent_id, opts)
           ) do
      json(conn, %{
        data: Enum.map(entries, &serialize/1),
        agent_id: agent_id,
        pagination: %{
          limit: Keyword.get(opts, :limit, 100),
          offset: Keyword.get(opts, :offset, 0),
          returned: length(entries)
        }
      })
    end
  end

  @doc """
  Get audit entries related to a specific alert.
  """
  def alert_actions(conn, %{"alert_id" => alert_id}) do
    with {:ok, organization_id} <- current_organization_id(conn),
         {:ok, entries} <-
           normalize_audit_read_result(Audit.get_actions_for_alert(organization_id, alert_id, [])) do
      json(conn, %{
        data: Enum.map(entries, &serialize/1),
        alert_id: alert_id
      })
    end
  end

  @doc """
  Get action counts grouped by action type.
  """
  def counts(conn, params) do
    with {:ok, organization_id} <- current_organization_id(conn),
         {:ok, opts} <- build_filter_opts(params),
         {:ok, counts} <-
           normalize_audit_read_result(Audit.get_action_counts(organization_id, opts)) do
      json(conn, %{
        data: counts,
        total: Enum.reduce(counts, 0, fn {_type, count}, acc -> acc + count end)
      })
    end
  end

  @doc """
  Search audit entries by a detail field value.
  """
  def search(conn, %{"field" => field, "value" => value} = params) do
    with {:ok, organization_id} <- current_organization_id(conn),
         {:ok, opts} <- build_filter_opts(Map.drop(params, ["field", "value"])),
         {:ok, entries} <-
           normalize_audit_read_result(
             Audit.search_by_details(organization_id, field, value, opts)
           ) do
      json(conn, %{
        data: Enum.map(entries, &serialize/1),
        search: %{field: field, value: value}
      })
    end
  end

  # Private helpers

  defp build_filter_opts(params) do
    with {:ok, limit} <- parse_int(params["limit"], 100),
         {:ok, offset} <- parse_int(params["offset"], 0),
         {:ok, from_datetime} <- parse_datetime(params["from"]),
         {:ok, to_datetime} <- parse_datetime(params["to"]) do
      opts = [limit: limit, offset: offset]

      opts = maybe_put_filter(opts, :action_type, params["action_type"])
      opts = maybe_put_filter(opts, :agent_id, params["agent_id"])
      opts = maybe_put_filter(opts, :actor_type, params["actor_type"])
      opts = maybe_put_filter(opts, :from, from_datetime)
      opts = maybe_put_filter(opts, :to, to_datetime)

      {:ok, opts}
    else
      {:error, :invalid_query_parameter} -> {:error, :invalid_params}
    end
  end

  defp maybe_put_filter(opts, _key, nil), do: opts
  defp maybe_put_filter(opts, key, value), do: [{key, value} | opts]

  defp normalize_audit_read_result({:error, :audit_query_failed}),
    do: {:error, :service_unavailable}

  defp normalize_audit_read_result({:error, reason})
       when reason in [
              :invalid_organization_id,
              :invalid_agent_id,
              :invalid_alert_id,
              :invalid_query_options,
              :invalid_pagination,
              :invalid_filter,
              :invalid_actor_type,
              :invalid_datetime,
              :invalid_time_range,
              :invalid_search_field,
              :invalid_search_value
            ],
       do: {:error, :invalid_params}

  defp normalize_audit_read_result(result), do: result

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

  defp serialize(entry) do
    %{
      id: entry.id,
      actionType: entry.action_type,
      details: entry.details,
      agentId: entry.agent_id,
      organizationId: entry.organization_id,
      actorType: entry.actor_type,
      actorId: entry.actor_id,
      performedAt: entry.performed_at,
      insertedAt: entry.inserted_at
    }
  end

  defp parse_int(nil, default), do: {:ok, default}

  defp parse_int(val, _default) when is_binary(val) do
    case Integer.parse(val) do
      {num, ""} -> {:ok, num}
      _ -> {:error, :invalid_query_parameter}
    end
  end

  defp parse_int(val, _default) when is_integer(val), do: {:ok, val}
  defp parse_int(_, _default), do: {:error, :invalid_query_parameter}

  defp parse_datetime(nil), do: {:ok, nil}

  defp parse_datetime(val) when is_binary(val) do
    case DateTime.from_iso8601(val) do
      {:ok, datetime, _offset} -> {:ok, datetime}
      _ -> {:error, :invalid_query_parameter}
    end
  end

  defp parse_datetime(_), do: {:error, :invalid_query_parameter}
end
