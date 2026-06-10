defmodule TamanduaServerWeb.API.V1.EventController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Telemetry
  alias TamanduaServer.Detection.Correlator
  require Logger

  action_fallback TamanduaServerWeb.FallbackController

  def index(conn, params) do
    filters = %{
      agent_id: params["agent_id"],
      event_type: params["event_type"],
      limit: parse_int(params["limit"], 100),
      offset: parse_int(params["offset"], 0)
    }

    events = Telemetry.list_events(filters)
    json(conn, %{data: Enum.map(events, &serialize/1)})
  end

  def show(conn, %{"id" => id}) do
    event = Telemetry.get_event!(id)
    json(conn, %{data: serialize(event)})
  end

  def purge(conn, params) do
    event_type = params["event_type"]

    if is_nil(event_type) or event_type == "" do
      json(conn, %{error: "event_type parameter is required"})
    else
      import Ecto.Query
      alias TamanduaServer.Repo
      alias TamanduaServer.Telemetry.Event

      {count, _} = Repo.delete_all(from e in Event, where: e.event_type == ^event_type)
      json(conn, %{deleted: count, event_type: event_type})
    end
  end

  def search(conn, params) do
    query = params["query"] || ""
    time_range = params["time_range"] || "24h"
    limit = parse_int(params["limit"], 100)

    results = Telemetry.search_events(query, time_range, limit)
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
    time_window = parse_int(params["time_window"], 30)
    limit = parse_int(params["limit"], 50)

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
end
