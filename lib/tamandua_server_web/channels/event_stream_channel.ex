defmodule TamanduaServerWeb.EventStreamChannel do
  @moduledoc """
  WebSocket channel for streaming telemetry events.

  Topic: "stream:events"

  Join with authentication token and optional filters:
  ```
  channel.join("stream:events", {
    token: "jwt_token",
    filters: {
      event_type: ["process", "file"],
      agent_id: "agent-123",
      severity: ["high", "critical"]
    },
    format: "json",  // or "binary"
    compression: true
  })
  ```

  Pushed events:
  - "event" - New telemetry event matching filters
  - "error" - Stream error (slow consumer, rate limit)
  """

  use TamanduaServerWeb, :channel
  require Logger

  alias TamanduaServer.Streaming.StreamManager

  @impl true
  def join("stream:events", params, socket) do
    # Authenticate user (already done in socket connect, but double-check)
    unless socket.assigns[:current_user] do
      {:error, %{reason: "unauthorized"}}
    else
      # Extract filters from join params
      filters = parse_filters(params)

      # Ensure organization_id is set (RBAC)
      organization_id = get_organization_id(socket)
      filters = Map.put(filters, :organization_id, organization_id)
      filters = Map.put(filters, :stream_type, [:event])

      # Extract format and compression options
      options = %{
        format: params["format"] || :json,
        compression: params["compression"] || false
      }

      # Generate stream ID
      stream_id = generate_stream_id(socket, "events")

      # Register with StreamManager
      :ok = StreamManager.register_stream(stream_id, self(), filters, options)

      # Store stream_id in socket assigns
      socket = assign(socket, :stream_id, stream_id)
      socket = assign(socket, :options, options)
      socket = assign(socket, :event_count, 0)

      Logger.info("Event stream joined: #{stream_id} (user: #{socket.assigns.user_id})")

      {:ok, %{stream_id: stream_id, filters: filters}, socket}
    end
  end

  @impl true
  def handle_info({:stream_data, :event, data}, socket) do
    # Format and push event to client
    formatted_data = format_data(data, socket.assigns.options)

    push(socket, "event", %{
      id: socket.assigns.event_count + 1,
      data: formatted_data,
      timestamp: System.system_time(:millisecond)
    })

    # Update event count
    socket = assign(socket, :event_count, socket.assigns.event_count + 1)

    # Decrement queue size in StreamManager
    # (This is handled by the manager, but we could track locally too)

    {:noreply, socket}
  end

  @impl true
  def handle_info({:stream_error, reason}, socket) do
    Logger.warning("Stream error on #{socket.assigns.stream_id}: #{inspect(reason)}")

    push(socket, "error", %{
      error: to_string(reason),
      code: error_code(reason)
    })

    # Close channel
    {:stop, :normal, socket}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def handle_in("ping", _params, socket) do
    {:reply, {:ok, %{pong: true}}, socket}
  end

  @impl true
  def handle_in("update_filters", %{"filters" => new_filters}, socket) do
    # Allow dynamic filter updates
    stream_id = socket.assigns.stream_id
    organization_id = get_organization_id(socket)

    filters = parse_filters(new_filters)
    filters = Map.put(filters, :organization_id, organization_id)
    filters = Map.put(filters, :stream_type, [:event])

    # Unregister old stream
    StreamManager.unregister_stream(stream_id)

    # Register with new filters
    :ok = StreamManager.register_stream(stream_id, self(), filters, socket.assigns.options)

    Logger.info("Event stream filters updated: #{stream_id}")

    {:reply, {:ok, %{filters: filters}}, socket}
  end

  @impl true
  def terminate(reason, socket) do
    stream_id = socket.assigns[:stream_id]
    if stream_id do
      StreamManager.unregister_stream(stream_id)
      Logger.info("Event stream terminated: #{stream_id} (reason: #{inspect(reason)})")
    end
    :ok
  end

  # Private Functions

  defp parse_filters(params) do
    filters = %{}

    filters = maybe_add_filter(filters, :event_type, params["event_type"])
    filters = maybe_add_filter(filters, :agent_id, params["agent_id"])
    filters = maybe_add_filter(filters, :severity, params["severity"])

    filters
  end

  defp maybe_add_filter(filters, _key, nil), do: filters
  defp maybe_add_filter(filters, key, value) when is_list(value) do
    Map.put(filters, key, value)
  end
  defp maybe_add_filter(filters, key, value) when is_binary(value) do
    Map.put(filters, key, [value])
  end
  defp maybe_add_filter(filters, key, value) do
    Map.put(filters, key, value)
  end

  defp get_organization_id(socket) do
    # Get organization_id from user or socket assigns
    socket.assigns[:organization_id] ||
      socket.assigns[:current_user][:organization_id] ||
      get_user_organization(socket.assigns[:user_id])
  end

  defp get_user_organization(user_id) do
    # Lookup user's organization
    case TamanduaServer.Accounts.get_user(user_id) do
      nil -> nil
      user -> user.organization_id
    end
  end

  defp generate_stream_id(socket, stream_type) do
    user_id = socket.assigns[:user_id] || "unknown"
    "ws_#{stream_type}_#{user_id}_#{:erlang.unique_integer([:positive])}"
  end

  defp format_data(data, options) do
    case options.format do
      :binary ->
        # Binary format - already encoded by StreamManager
        data

      :json ->
        # JSON format - parse if string, return as-is if map
        case data do
          binary when is_binary(binary) ->
            case Jason.decode(binary) do
              {:ok, decoded} -> decoded
              {:error, _} -> %{raw: binary}
            end
          map when is_map(map) -> map
          _ -> %{raw: inspect(data)}
        end

      _ ->
        data
    end
  end

  defp error_code(:slow_consumer), do: "SLOW_CONSUMER"
  defp error_code(:rate_limit), do: "RATE_LIMIT"
  defp error_code(:unauthorized), do: "UNAUTHORIZED"
  defp error_code(_), do: "UNKNOWN_ERROR"
end
