defmodule TamanduaServerWeb.API.V1.PollController do
  @moduledoc """
  Long-polling controller for backward compatibility.

  Provides traditional long-polling endpoints:
  - GET /api/v1/poll/alerts?since=<timestamp> - Poll for new alerts
  - GET /api/v1/poll/events?since=<timestamp> - Poll for new events
  - GET /api/v1/poll/detections?since=<timestamp> - Poll for new detections

  Features:
  - Returns batch of events since timestamp
  - Timeout after 30s if no events
  - Pagination support (limit, offset)
  - RBAC enforcement via organization_id filter
  """

  use TamanduaServerWeb, :controller
  require Logger

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Telemetry.Event

  @poll_timeout 30_000
  @default_limit 100
  @max_limit 1000

  @doc """
  Long-poll for new alerts.

  Query parameters:
  - since: Timestamp in milliseconds (required)
  - limit: Max number of alerts to return (default: 100, max: 1000)
  - offset: Pagination offset (default: 0)
  - severity: Filter by severity
  - agent_id: Filter by agent ID
  """
  def poll_alerts(conn, params) do
    current_user = conn.assigns[:current_user]
    organization_id = conn.assigns[:organization_id]

    unless current_user do
      conn
      |> put_status(:unauthorized)
      |> json(%{error: "Authentication required"})
    else
      since = parse_timestamp(params["since"])
      limit = parse_limit(params["limit"])
      offset = parse_offset(params["offset"])

      if is_nil(since) do
        conn
        |> put_status(:bad_request)
        |> json(%{error: "since parameter is required (timestamp in milliseconds)"})
      else
        # Build query with filters
        query = build_alerts_query(since, organization_id, params)

        # Try to get alerts immediately
        alerts = query
          |> limit(^limit)
          |> offset(^offset)
          |> order_by([a], desc: a.inserted_at)
          |> Repo.all()

        if Enum.empty?(alerts) do
          # No alerts yet, wait for new ones
          wait_for_alerts(conn, query, limit, offset, @poll_timeout)
        else
          # Return alerts immediately
          conn
          |> put_status(:ok)
          |> json(%{
            data: serialize_alerts(alerts),
            count: length(alerts),
            has_more: length(alerts) == limit,
            next_offset: offset + length(alerts),
            timestamp: System.system_time(:millisecond)
          })
        end
      end
    end
  end

  @doc """
  Long-poll for new events.

  Query parameters:
  - since: Timestamp in milliseconds (required)
  - limit: Max number of events to return (default: 100, max: 1000)
  - offset: Pagination offset (default: 0)
  - event_type: Filter by event type
  - agent_id: Filter by agent ID
  """
  def poll_events(conn, params) do
    current_user = conn.assigns[:current_user]
    organization_id = conn.assigns[:organization_id]

    unless current_user do
      conn
      |> put_status(:unauthorized)
      |> json(%{error: "Authentication required"})
    else
      since = parse_timestamp(params["since"])
      limit = parse_limit(params["limit"])
      offset = parse_offset(params["offset"])

      if is_nil(since) do
        conn
        |> put_status(:bad_request)
        |> json(%{error: "since parameter is required (timestamp in milliseconds)"})
      else
        # Build query with filters
        query = build_events_query(since, organization_id, params)

        # Try to get events immediately
        events = query
          |> limit(^limit)
          |> offset(^offset)
          |> order_by([e], desc: e.timestamp)
          |> Repo.all()

        if Enum.empty?(events) do
          # No events yet, wait for new ones
          wait_for_events(conn, query, limit, offset, @poll_timeout)
        else
          # Return events immediately
          conn
          |> put_status(:ok)
          |> json(%{
            data: serialize_events(events),
            count: length(events),
            has_more: length(events) == limit,
            next_offset: offset + length(events),
            timestamp: System.system_time(:millisecond)
          })
        end
      end
    end
  end

  # Private Functions

  defp build_alerts_query(since, organization_id, params) do
    # Convert millisecond timestamp to DateTime
    since_datetime = DateTime.from_unix!(since, :millisecond)

    query = from a in Alert,
      where: a.organization_id == ^organization_id,
      where: a.inserted_at > ^since_datetime

    # Add optional filters
    query = maybe_filter_by_severity(query, params["severity"])
    query = maybe_filter_by_agent(query, params["agent_id"])

    query
  end

  defp build_events_query(since, organization_id, params) do
    # Convert millisecond timestamp to DateTime
    since_datetime = DateTime.from_unix!(since, :millisecond)

    query = from e in Event,
      where: e.organization_id == ^organization_id,
      where: e.timestamp > ^since_datetime

    # Add optional filters
    query = maybe_filter_by_event_type(query, params["event_type"])
    query = maybe_filter_by_agent(query, params["agent_id"])

    query
  end

  defp maybe_filter_by_severity(query, nil), do: query
  defp maybe_filter_by_severity(query, severity) when is_binary(severity) do
    severities = String.split(severity, ",") |> Enum.map(&String.trim/1)
    from a in query, where: a.severity in ^severities
  end

  defp maybe_filter_by_agent(query, nil), do: query
  defp maybe_filter_by_agent(query, agent_id) when is_binary(agent_id) do
    agent_ids = String.split(agent_id, ",") |> Enum.map(&String.trim/1)
    from q in query, where: q.agent_id in ^agent_ids
  end

  defp maybe_filter_by_event_type(query, nil), do: query
  defp maybe_filter_by_event_type(query, event_type) when is_binary(event_type) do
    event_types = String.split(event_type, ",") |> Enum.map(&String.trim/1)
    from e in query, where: e.event_type in ^event_types
  end

  defp wait_for_alerts(conn, query, limit, offset, timeout) do
    # Subscribe to PubSub for new alerts
    topic = "alerts:new"
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, topic)

    start_time = System.system_time(:millisecond)

    wait_loop(conn, query, limit, offset, start_time, timeout, :alert)
  end

  defp wait_for_events(conn, query, limit, offset, timeout) do
    # Subscribe to PubSub for new events
    topic = "dashboard:events"
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, topic)

    start_time = System.system_time(:millisecond)

    wait_loop(conn, query, limit, offset, start_time, timeout, :event)
  end

  defp wait_loop(conn, query, limit, offset, start_time, timeout, type) do
    elapsed = System.system_time(:millisecond) - start_time
    remaining = max(0, timeout - elapsed)

    receive do
      {:new_alert, _alert} when type == :alert ->
        # New alert arrived, query again
        results = query
          |> limit(^limit)
          |> offset(^offset)
          |> order_by([a], desc: a.inserted_at)
          |> Repo.all()

        if Enum.empty?(results) do
          # False alarm, keep waiting
          if remaining > 0 do
            wait_loop(conn, query, limit, offset, start_time, timeout, type)
          else
            # Timeout
            send_empty_response(conn)
          end
        else
          # Return results
          conn
          |> put_status(:ok)
          |> json(%{
            data: serialize_alerts(results),
            count: length(results),
            has_more: length(results) == limit,
            next_offset: offset + length(results),
            timestamp: System.system_time(:millisecond)
          })
        end

      {:new_events, _events} when type == :event ->
        # New events arrived, query again
        results = query
          |> limit(^limit)
          |> offset(^offset)
          |> order_by([e], desc: e.timestamp)
          |> Repo.all()

        if Enum.empty?(results) do
          # False alarm, keep waiting
          if remaining > 0 do
            wait_loop(conn, query, limit, offset, start_time, timeout, type)
          else
            # Timeout
            send_empty_response(conn)
          end
        else
          # Return results
          conn
          |> put_status(:ok)
          |> json(%{
            data: serialize_events(results),
            count: length(results),
            has_more: length(results) == limit,
            next_offset: offset + length(results),
            timestamp: System.system_time(:millisecond)
          })
        end

    after
      remaining ->
        # Timeout reached
        send_empty_response(conn)
    end
  end

  defp send_empty_response(conn) do
    conn
    |> put_status(:ok)
    |> json(%{
      data: [],
      count: 0,
      has_more: false,
      next_offset: 0,
      timestamp: System.system_time(:millisecond)
    })
  end

  defp serialize_alerts(alerts) do
    Enum.map(alerts, fn alert ->
      %{
        id: alert.id,
        severity: alert.severity,
        title: alert.title,
        description: alert.description,
        status: alert.status,
        agent_id: alert.agent_id,
        organization_id: alert.organization_id,
        threat_score: alert.threat_score,
        mitre_tactics: alert.mitre_tactics,
        mitre_techniques: alert.mitre_techniques,
        inserted_at: DateTime.to_unix(alert.inserted_at, :millisecond),
        updated_at: DateTime.to_unix(alert.updated_at, :millisecond)
      }
    end)
  end

  defp serialize_events(events) do
    Enum.map(events, fn event ->
      %{
        id: event.id,
        event_type: event.event_type,
        agent_id: event.agent_id,
        organization_id: event.organization_id,
        severity: event.severity,
        payload: event.payload,
        timestamp: DateTime.to_unix(event.timestamp, :millisecond),
        created_at: DateTime.to_unix(event.created_at, :millisecond)
      }
    end)
  end

  defp parse_timestamp(nil), do: nil
  defp parse_timestamp(ts) when is_binary(ts) do
    case Integer.parse(ts) do
      {timestamp, ""} -> timestamp
      _ -> nil
    end
  end
  defp parse_timestamp(ts) when is_integer(ts), do: ts

  defp parse_limit(nil), do: @default_limit
  defp parse_limit(limit) when is_binary(limit) do
    case Integer.parse(limit) do
      {num, ""} -> min(num, @max_limit)
      _ -> @default_limit
    end
  end
  defp parse_limit(limit) when is_integer(limit), do: min(limit, @max_limit)

  defp parse_offset(nil), do: 0
  defp parse_offset(offset) when is_binary(offset) do
    case Integer.parse(offset) do
      {num, ""} -> max(0, num)
      _ -> 0
    end
  end
  defp parse_offset(offset) when is_integer(offset), do: max(0, offset)
end
