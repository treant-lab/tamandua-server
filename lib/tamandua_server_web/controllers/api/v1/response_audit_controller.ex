defmodule TamanduaServerWeb.API.V1.ResponseAuditController do
  @moduledoc """
  API controller for response action audit trail.

  Provides endpoints to query the audit trail of automated response actions,
  including ML-triggered quarantine, playbook executions, and manual analyst actions.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Response.Audit

  action_fallback TamanduaServerWeb.FallbackController

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
    opts = build_filter_opts(params)
    entries = Audit.get_recent_actions(opts)

    json(conn, %{
      data: Enum.map(entries, &serialize/1),
      pagination: %{
        limit: Keyword.get(opts, :limit, 100),
        offset: Keyword.get(opts, :offset, 0),
        returned: length(entries)
      }
    })
  end

  @doc """
  Get audit entries for a specific agent.
  """
  def agent_actions(conn, %{"agent_id" => agent_id} = params) do
    opts = build_filter_opts(params)
    entries = Audit.get_actions_for_agent(agent_id, opts)

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

  @doc """
  Get audit entries related to a specific alert.
  """
  def alert_actions(conn, %{"alert_id" => alert_id}) do
    entries = Audit.get_actions_for_alert(alert_id)

    json(conn, %{
      data: Enum.map(entries, &serialize/1),
      alert_id: alert_id
    })
  end

  @doc """
  Get action counts grouped by action type.
  """
  def counts(conn, params) do
    opts = build_filter_opts(params)
    counts = Audit.get_action_counts(opts)

    json(conn, %{
      data: counts,
      total: Enum.reduce(counts, 0, fn {_type, count}, acc -> acc + count end)
    })
  end

  @doc """
  Search audit entries by a detail field value.
  """
  def search(conn, %{"field" => field, "value" => value} = params) do
    opts = build_filter_opts(params)
    entries = Audit.search_by_details(field, value, opts)

    json(conn, %{
      data: Enum.map(entries, &serialize/1),
      search: %{field: field, value: value}
    })
  end

  # Private helpers

  defp build_filter_opts(params) do
    opts = [
      limit: parse_int(params["limit"], 100),
      offset: parse_int(params["offset"], 0)
    ]

    opts =
      if params["action_type"],
        do: [{:action_type, params["action_type"]} | opts],
        else: opts

    opts =
      if params["agent_id"],
        do: [{:agent_id, params["agent_id"]} | opts],
        else: opts

    opts =
      if params["actor_type"],
        do: [{:actor_type, params["actor_type"]} | opts],
        else: opts

    opts =
      if params["organization_id"],
        do: [{:organization_id, params["organization_id"]} | opts],
        else: opts

    opts =
      case parse_datetime(params["from"]) do
        {:ok, datetime} -> [{:from, datetime} | opts]
        _ -> opts
      end

    opts =
      case parse_datetime(params["to"]) do
        {:ok, datetime} -> [{:to, datetime} | opts]
        _ -> opts
      end

    opts
  end

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

  defp parse_int(nil, default), do: default

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {num, _} -> num
      :error -> default
    end
  end

  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(_, default), do: default

  defp parse_datetime(nil), do: :error

  defp parse_datetime(val) when is_binary(val) do
    case DateTime.from_iso8601(val) do
      {:ok, datetime, _offset} -> {:ok, datetime}
      _ -> :error
    end
  end

  defp parse_datetime(_), do: :error
end
