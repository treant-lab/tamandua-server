defmodule TamanduaServerWeb.API.V1.StreamController do
  @moduledoc """
  Server-Sent Events (SSE) streaming controller.

  Provides real-time event streaming for external consumers:
  - GET /api/v1/stream/alerts - Stream new alerts
  - GET /api/v1/stream/events - Stream telemetry events
  - GET /api/v1/stream/detections - Stream detection results

  Features:
  - Filter by severity, agent_id, event_type, organization_id
  - Heartbeat every 30s to keep connection alive
  - Event ID for resume capability
  - Automatic reconnection support
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Streaming.StreamManager
  alias TamanduaServer.Streaming.SSEConnection

  @heartbeat_interval 30_000

  @doc """
  Stream alerts via SSE.

  Query parameters:
  - severity: Filter by severity (critical, high, medium, low, info)
  - agent_id: Filter by agent ID
  - organization_id: Filter by organization (enforced by RBAC)
  - last_event_id: Resume from last event ID
  """
  def stream_alerts(conn, params) do
    stream_events(conn, params, :alert)
  end

  @doc """
  Stream telemetry events via SSE.

  Query parameters:
  - event_type: Filter by event type (process, file, network, dns, registry)
  - severity: Filter by severity
  - agent_id: Filter by agent ID
  - organization_id: Filter by organization (enforced by RBAC)
  - last_event_id: Resume from last event ID
  """
  def stream_events(conn, params) do
    stream_events(conn, params, :event)
  end

  @doc """
  Stream detections via SSE.

  Query parameters:
  - severity: Filter by severity
  - agent_id: Filter by agent ID
  - organization_id: Filter by organization (enforced by RBAC)
  - last_event_id: Resume from last event ID
  """
  def stream_detections(conn, params) do
    stream_events(conn, params, :detection)
  end

  # Private Functions

  defp stream_events(conn, params, stream_type) do
    # Extract current user from connection (set by APIAuth plug)
    current_user = conn.assigns[:current_user]
    organization_id = conn.assigns[:organization_id]

    unless current_user do
      conn
      |> put_status(:unauthorized)
      |> json(%{error: "Authentication required"})
      |> halt()
    else
      # Build filters from query params
      filters = build_filters(params, stream_type, organization_id)

      # Generate unique stream ID
      stream_id = generate_stream_id(current_user, stream_type)

      # Get last event ID for resume capability
      last_event_id = params["last_event_id"]

      # Set SSE headers
      conn =
        conn
        |> put_resp_header("content-type", "text/event-stream")
        |> put_resp_header("cache-control", "no-cache")
        |> put_resp_header("connection", "keep-alive")
        |> put_resp_header("x-accel-buffering", "no")
        |> send_chunked(200)

      # Send initial comment with stream info
      {:ok, conn} = chunk(conn, sse_comment("Stream started: #{stream_type}"))

      # If resuming, send resume confirmation
      if last_event_id do
        {:ok, conn} = chunk(conn, sse_comment("Resuming from event: #{last_event_id}"))
      end

      # Register stream with StreamManager
      :ok = StreamManager.register_stream(stream_id, self(), filters, %{})

      # Send initial heartbeat
      {:ok, conn} = send_heartbeat(conn)

      Logger.info("SSE stream started: #{stream_id} (type: #{stream_type}, user: #{current_user.id})")

      # Enter event loop
      stream_loop(conn, stream_id, 0)
    end
  end

  defp stream_loop(conn, stream_id, event_count) do
    receive do
      {:stream_data, type, data} ->
        # Send SSE event
        event_id = event_count + 1
        sse_event = format_sse_event(type, data, event_id)

        case chunk(conn, sse_event) do
          {:ok, conn} ->
            stream_loop(conn, stream_id, event_id)

          {:error, reason} ->
            Logger.info("SSE stream ended: #{stream_id} (reason: #{inspect(reason)})")
            StreamManager.unregister_stream(stream_id)
            conn
        end

      {:stream_error, reason} ->
        Logger.warning("SSE stream error: #{stream_id} (reason: #{inspect(reason)})")
        error_event = format_sse_event(:error, %{error: to_string(reason)}, event_count + 1)
        chunk(conn, error_event)
        StreamManager.unregister_stream(stream_id)
        conn

      :heartbeat ->
        case send_heartbeat(conn) do
          {:ok, conn} ->
            # Schedule next heartbeat
            Process.send_after(self(), :heartbeat, @heartbeat_interval)
            stream_loop(conn, stream_id, event_count)

          {:error, reason} ->
            Logger.info("SSE stream ended during heartbeat: #{stream_id} (reason: #{inspect(reason)})")
            StreamManager.unregister_stream(stream_id)
            conn
        end

    after
      @heartbeat_interval ->
        # Send heartbeat if no events received
        case send_heartbeat(conn) do
          {:ok, conn} ->
            stream_loop(conn, stream_id, event_count)

          {:error, reason} ->
            Logger.info("SSE stream ended: #{stream_id} (reason: #{inspect(reason)})")
            StreamManager.unregister_stream(stream_id)
            conn
        end
    end
  end

  defp build_filters(params, stream_type, organization_id) do
    base_filters = %{
      stream_type: [stream_type],
      organization_id: organization_id
    }

    # Add optional filters
    filters = base_filters
    |> maybe_add_filter(:severity, params["severity"])
    |> maybe_add_filter(:agent_id, params["agent_id"])
    |> maybe_add_filter(:event_type, params["event_type"])

    filters
  end

  defp maybe_add_filter(filters, key, nil), do: filters
  defp maybe_add_filter(filters, key, value) when is_binary(value) do
    # Handle comma-separated values
    values = String.split(value, ",") |> Enum.map(&String.trim/1)
    Map.put(filters, key, values)
  end
  defp maybe_add_filter(filters, key, value), do: Map.put(filters, key, value)

  defp generate_stream_id(user, stream_type) do
    "sse_#{stream_type}_#{user.id}_#{:erlang.unique_integer([:positive])}"
  end

  defp format_sse_event(type, data, event_id) do
    # SSE format:
    # id: <event_id>
    # event: <event_type>
    # data: <json_data>
    # (blank line)

    json_data = case data do
      binary when is_binary(binary) -> binary
      map -> Jason.encode!(map)
    end

    """
    id: #{event_id}
    event: #{type}
    data: #{json_data}

    """
  end

  defp send_heartbeat(conn) do
    # Send SSE comment as heartbeat
    chunk(conn, sse_comment("heartbeat"))
  end

  defp sse_comment(text) do
    ": #{text}\n\n"
  end
end
