defmodule TamanduaServerWeb.GraphQL.Resolvers.EventResolver do
  @moduledoc """
  GraphQL resolvers for Event queries and fields.
  """

  alias TamanduaServer.{Agents, Repo}
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Alerts.Alert
  import Ecto.Query

  # Query resolvers

  def list_events(_parent, args, %{context: context}) do
    org_id = context[:organization_id]
    filter = Map.get(args, :filter, %{})
    pagination = Map.get(args, :pagination, %{})

    limit = pagination[:limit] || 100
    offset = pagination[:offset] || 0

    query = Event
    |> maybe_scope_org(org_id)
    |> order_by([e], [desc: e.timestamp])
    |> apply_event_filters(filter)
    |> limit(^limit)
    |> offset(^offset)

    {:ok, Repo.all(query)}
  end

  def get_event(_parent, %{id: id}, %{context: context}) do
    org_id = context[:organization_id]

    query = Event
    |> maybe_scope_org(org_id)
    |> where([e], e.id == ^id)

    case Repo.one(query) do
      nil -> {:error, "Event not found"}
      event -> {:ok, event}
    end
  end

  def event_stats(_parent, _args, %{context: context}) do
    org_id = context[:organization_id]

    base_query = Event
    |> maybe_scope_org(org_id)

    total = Repo.aggregate(base_query, :count)

    by_type = base_query
    |> group_by([e], e.event_type)
    |> select([e], {e.event_type, count(e.id)})
    |> Repo.all()
    |> Enum.into(%{})

    # Events in last minute for rate calculation
    one_minute_ago = DateTime.utc_now() |> DateTime.add(-60, :second)
    recent_count = base_query
    |> where([e], e.timestamp >= ^one_minute_ago)
    |> Repo.aggregate(:count)

    {:ok, %{
      total: total,
      by_type: by_type,
      by_agent: [],
      rate_per_minute: recent_count,
      trend: []
    }}
  end

  def search_events(_parent, %{input: input}, %{context: context}) do
    org_id = context[:organization_id]
    query_string = input.query
    limit = input[:limit] || 100

    # Parse TQL query (simplified implementation)
    case parse_tql_query(query_string) do
      {:ok, conditions} ->
        query = Event
        |> maybe_scope_org(org_id)
        |> order_by([e], [desc: e.timestamp])
        |> apply_tql_conditions(conditions)
        |> maybe_filter_since_datetime(input[:since])
        |> maybe_filter_until_datetime(input[:until])
        |> limit(^limit)

        {:ok, Repo.all(query)}

      {:error, reason} ->
        {:error, "Invalid TQL query: #{reason}"}
    end
  end

  # Field resolvers

  def agent(event, _args, %{context: context}) do
    if event.agent_id do
      org_id = context[:organization_id]

      # Use tenant-scoped lookup to prevent BOLA/IDOR
      case Agents.get_agent_for_org(org_id, event.agent_id) do
        {:ok, agent} -> {:ok, agent}
        {:error, :not_found} -> {:ok, nil}
      end
    else
      {:ok, nil}
    end
  end

  def related_alerts(event, _args, _resolution) do
    # Find alerts that include this event
    alerts = from(a in Alert,
      where: ^event.id in a.event_ids,
      order_by: [desc: a.inserted_at],
      limit: 10
    )
    |> Repo.all()

    {:ok, alerts}
  end

  # Private helpers

  defp maybe_scope_org(query, nil), do: query
  defp maybe_scope_org(query, org_id) do
    # Join with agents to filter by organization
    from(e in query,
      join: a in TamanduaServer.Agents.Agent,
      on: e.agent_id == a.id,
      where: a.organization_id == ^org_id
    )
  end

  defp apply_event_filters(query, filter) do
    query
    |> maybe_filter_event_type(filter[:event_type])
    |> maybe_filter_agent(filter[:agent_id])
    |> maybe_filter_severity(filter[:severity])
    |> maybe_filter_since_datetime(filter[:since])
    |> maybe_filter_until_datetime(filter[:until])
    |> maybe_filter_sha256(filter[:sha256])
    |> maybe_filter_process_name(filter[:process_name])
    |> maybe_filter_remote_ip(filter[:remote_ip])
    |> maybe_filter_domain(filter[:domain])
  end

  defp maybe_filter_event_type(query, nil), do: query
  defp maybe_filter_event_type(query, event_type) do
    where(query, [e], e.event_type == ^event_type)
  end

  defp maybe_filter_agent(query, nil), do: query
  defp maybe_filter_agent(query, agent_id) do
    where(query, [e], e.agent_id == ^agent_id)
  end

  defp maybe_filter_severity(query, nil), do: query
  defp maybe_filter_severity(query, severity) do
    where(query, [e], e.severity == ^severity)
  end

  defp maybe_filter_since_datetime(query, nil), do: query
  defp maybe_filter_since_datetime(query, since) do
    where(query, [e], e.timestamp >= ^since)
  end

  defp maybe_filter_until_datetime(query, nil), do: query
  defp maybe_filter_until_datetime(query, until_time) do
    where(query, [e], e.timestamp <= ^until_time)
  end

  defp maybe_filter_sha256(query, nil), do: query
  defp maybe_filter_sha256(query, sha256) do
    where(query, [e], e.sha256 == ^sha256 or fragment("payload->>'sha256' = ?", ^sha256))
  end

  defp maybe_filter_process_name(query, nil), do: query
  defp maybe_filter_process_name(query, process_name) do
    where(query, [e], fragment("payload->>'name' ILIKE ?", ^"%#{process_name}%"))
  end

  defp maybe_filter_remote_ip(query, nil), do: query
  defp maybe_filter_remote_ip(query, remote_ip) do
    where(query, [e], fragment("payload->>'remote_ip' = ?", ^remote_ip))
  end

  defp maybe_filter_domain(query, nil), do: query
  defp maybe_filter_domain(query, domain) do
    where(query, [e], fragment("payload->>'query' ILIKE ?", ^"%#{domain}%"))
  end

  # Simple TQL parser (production would use proper parser)
  defp parse_tql_query(query_string) do
    # Very basic parsing - just extracts field:value pairs
    conditions = query_string
    |> String.split(" AND ", trim: true)
    |> Enum.map(&parse_condition/1)
    |> Enum.reject(&is_nil/1)

    {:ok, conditions}
  rescue
    _ -> {:error, "Parse error"}
  end

  defp parse_condition(condition) do
    cond do
      String.contains?(condition, ":") ->
        [field, value] = String.split(condition, ":", parts: 2)
        {String.trim(field), String.trim(value)}
      true ->
        nil
    end
  end

  defp apply_tql_conditions(query, conditions) do
    Enum.reduce(conditions, query, fn {field, value}, acc ->
      apply_tql_condition(acc, field, value)
    end)
  end

  defp apply_tql_condition(query, "event_type", value) do
    where(query, [e], e.event_type == ^value)
  end

  defp apply_tql_condition(query, "severity", value) do
    where(query, [e], e.severity == ^value)
  end

  defp apply_tql_condition(query, "process.name", value) do
    where(query, [e], fragment("payload->>'name' ILIKE ?", ^"%#{value}%"))
  end

  defp apply_tql_condition(query, "process.path", value) do
    where(query, [e], fragment("payload->>'path' ILIKE ?", ^"%#{value}%"))
  end

  defp apply_tql_condition(query, "file.path", value) do
    where(query, [e], fragment("payload->>'path' ILIKE ?", ^"%#{value}%"))
  end

  defp apply_tql_condition(query, "network.remote_ip", value) do
    where(query, [e], fragment("payload->>'remote_ip' = ?", ^value))
  end

  defp apply_tql_condition(query, "dns.query", value) do
    where(query, [e], fragment("payload->>'query' ILIKE ?", ^"%#{value}%"))
  end

  defp apply_tql_condition(query, "sha256", value) do
    where(query, [e], fragment("payload->>'sha256' = ?", ^value))
  end

  defp apply_tql_condition(query, _field, _value) do
    # Unknown field - skip
    query
  end
end
