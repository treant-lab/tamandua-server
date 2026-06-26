defmodule TamanduaServerWeb.API.V1.EventController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Telemetry
  alias TamanduaServer.Detection.Correlator
  require Logger

  action_fallback TamanduaServerWeb.FallbackController

  @default_limit 100
  @max_limit 250

  def index(conn, params) do
    limit = bounded_limit(params["limit"], @default_limit, @max_limit)
    organization_id = current_organization_id(conn)

    filters = %{
      agent_id: params["agent_id"],
      event_type: params["event_type"],
      organization_id: organization_id,
      limit: limit,
      offset: bounded_offset(params["offset"])
    }

    events = safe_list_events(filters, "Event index")

    json(conn, %{
      data: Enum.map(events, &serialize/1),
      meta: %{limit: limit, offset: filters.offset, scoped: not is_nil(organization_id)}
    })
  end

  def show(conn, %{"id" => id}) do
    organization_id = current_organization_id(conn)

    case Ecto.UUID.cast(id) do
      {:ok, valid_id} ->
        case Telemetry.get_event_for_org(valid_id, organization_id) do
          nil ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Event not found"})

          event ->
            json(conn, %{data: serialize(event)})
        end

      :error ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid event id"})
    end
  end

  def purge(conn, params) do
    event_type = params["event_type"]
    organization_id = current_organization_id(conn)

    cond do
      is_nil(event_type) or event_type == "" ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "event_type parameter is required"})

      is_nil(organization_id) ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Organization scope is required to purge events"})

      true ->
        import Ecto.Query
        alias TamanduaServer.Repo
        alias TamanduaServer.Telemetry.Event

        {count, _} =
          Repo.delete_all(
            from e in Event,
              where: e.organization_id == ^organization_id and e.event_type == ^event_type
          )

        json(conn, %{deleted: count, event_type: event_type, scoped: true})
    end
  end

  def search(conn, params) do
    query = params["query"] || ""
    time_range = params["time_range"] || "24h"
    limit = bounded_limit(params["limit"], @default_limit, @max_limit)

    results =
      try do
        Telemetry.search_events(query, time_range, limit)
      rescue
        exception ->
          Logger.warning("[EventController] search failed: #{Exception.message(exception)}")
          []
      catch
        :exit, reason ->
          Logger.warning("[EventController] search failed: exit #{inspect(reason)}")
          []
      end

    json(conn, %{data: Enum.map(results, &serialize/1), meta: %{query: query, time_range: time_range}})
  end

  @doc """
  Get events related to a source event using the Correlator engine.
  Returns events with correlation scores and reasons.

  Required params:
    - id: The source event ID
    - agent_id: The agent ID (required for correlation lookup)

  Optional params:
    - time_window: Time window in minutes (default: 30)
    - limit: Maximum number of related events (default: 50)
  """
  def related(conn, %{"id" => event_id, "agent_id" => agent_id} = params) do
    time_window = bounded_limit(params["time_window"], 30, 24 * 60)
    limit = bounded_limit(params["limit"], 50, @max_limit)

    {related_events, partial_reason} =
      try do
        events =
          Correlator.get_related_events(agent_id, event_id, time_window)
          |> Enum.take(limit)
          |> Enum.map(&serialize_related_event/1)

        {events, nil}
      rescue
        exception ->
          Logger.warning(
            "[EventController] related events correlation failed event=#{event_id} agent=#{agent_id}: #{Exception.message(exception)}"
          )

          fallback_events =
            agent_id
            |> Telemetry.list_events_for_agent(limit)
            |> Enum.map(&serialize_recent_event/1)

          {fallback_events, "correlation_fallback_recent_agent_events"}
      end

    json(conn, %{
      related_events: related_events,
      meta: %{
        source_event_id: event_id,
        agent_id: agent_id,
        time_window_minutes: time_window,
        count: length(related_events),
        partial_reason: partial_reason
      }
    })
  end

  def related(conn, %{"id" => _event_id}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "agent_id parameter is required"})
  end

  defp serialize_related_event(event) do
    payload = event[:payload] || %{}

    %{
      event_id: event[:event_id] || event[:id],
      event_type: event[:event_type] || "unknown",
      timestamp: format_timestamp(event[:timestamp]),
      severity: event[:severity] || "info",
      correlation_score: event[:correlation_score] || 0,
      correlation_reason: event[:correlation_reason] || "",
      pid: payload[:pid] || payload["pid"],
      process_name: payload[:name] || payload["name"],
      summary: build_event_summary(event),
      payload: payload
    }
  end

  defp serialize_recent_event(event) do
    payload = event.payload || %{}

    %{
      event_id: event.id,
      event_type: event.event_type || "unknown",
      timestamp: format_timestamp(event.timestamp),
      severity: event.severity || "info",
      correlation_score: 1,
      correlation_reason: "Fallback: recent event from same agent",
      pid: payload[:pid] || payload["pid"],
      process_name: payload[:name] || payload["name"],
      summary: build_event_summary(%{event_type: event.event_type, payload: payload}),
      payload: payload
    }
  end

  defp build_event_summary(event) do
    event_type = event[:event_type] || "unknown"
    payload = event[:payload] || %{}

    case event_type do
      type when type in ["process_create", "process", :process_create, :process] ->
        name = payload[:name] || payload["name"] || "Unknown"
        "Process created: #{name}"

      type when type in ["network_connect", "network", :network_connect, :network] ->
        ip = payload[:remote_ip] || payload["remote_ip"] || "unknown"
        port = payload[:remote_port] || payload["remote_port"] || ""
        "Network connection to #{ip}:#{port}"

      type when type in ["file_create", "file_modify", "file", :file_create, :file_modify, :file] ->
        path = payload[:path] || payload["path"] || "Unknown"
        "File operation: #{Path.basename(to_string(path))}"

      type when type in ["dns_query", "dns", :dns_query, :dns] ->
        domain = payload[:query] || payload["query"] || payload[:domain] || payload["domain"] || "unknown"
        "DNS query: #{domain}"

      type when type in ["registry", :registry] ->
        key = payload[:key] || payload["key"] || "Unknown"
        "Registry operation: #{key}"

      _ ->
        "#{event_type} event"
    end
  end

  defp serialize(event) do
    %{
      id: event.id,
      agent_id: event.agent_id,
      agent_hostname: Map.get(event, :agent_hostname, nil),
      event_type: event.event_type,
      timestamp: format_timestamp(event.timestamp),
      payload: event.payload || %{}
    }
  end

  defp format_timestamp(%NaiveDateTime{} = ts), do: NaiveDateTime.to_iso8601(ts)
  defp format_timestamp(%DateTime{} = ts), do: DateTime.to_iso8601(ts)
  defp format_timestamp(ts) when is_binary(ts), do: ts
  defp format_timestamp(_), do: nil

  defp parse_int(nil, default), do: default
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(_, default), do: default

  defp bounded_limit(value, default, max_limit) do
    value
    |> parse_int(default)
    |> max(1)
    |> min(max_limit)
  end

  defp bounded_offset(value) do
    value
    |> parse_int(0)
    |> max(0)
  end

  defp current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id)
  end

  defp safe_list_events(filters, label) do
    Telemetry.list_events(filters)
  rescue
    exception ->
      Logger.warning("[EventController] #{label} failed: #{Exception.message(exception)}")
      []
  catch
    :exit, reason ->
      Logger.warning("[EventController] #{label} failed: exit #{inspect(reason)}")
      []
  end
end
