defmodule TamanduaServerWeb.API.V1.EventController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Telemetry
  alias TamanduaServer.Mobile
  alias TamanduaServer.Detection.Correlator
  require Logger

  action_fallback(TamanduaServerWeb.FallbackController)

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
      offset: bounded_offset(params["offset"]),
      since: parse_datetime(params["since"]),
      until: parse_datetime(params["until"]),
      skip_agent_lookup: true
    }

    {events, partial_reason} = safe_list_events(filters, "Event index")

    serialized_events =
      events
      |> Enum.map(&serialize/1)
      |> merge_mobile_events(organization_id, limit, params)

    json(conn, %{
      data: serialized_events,
      meta: %{
        limit: limit,
        offset: filters.offset,
        scoped: not is_nil(organization_id),
        since: format_timestamp(filters.since),
        until: format_timestamp(filters.until),
        partial: not is_nil(partial_reason),
        partial_reason: partial_reason
      }
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
            from(e in Event,
              where: e.organization_id == ^organization_id and e.event_type == ^event_type
            )
          )

        json(conn, %{deleted: count, event_type: event_type, scoped: true})
    end
  end

  def search(conn, params) do
    query = params["query"] || ""
    time_range = params["time_range"] || "24h"
    limit = bounded_limit(params["limit"], @default_limit, @max_limit)
    organization_id = current_organization_id(conn)

    if is_nil(organization_id) do
      conn
      |> put_status(:forbidden)
      |> json(%{error: "Organization scope is required to search events"})
    else
      {results, partial_reason} =
        try do
          results =
            Telemetry.search_events(query, time_range, limit,
              organization_id: organization_id,
              skip_agent_lookup: true
            )

          {results, nil}
        rescue
          exception ->
            Logger.warning("[EventController] search failed: #{Exception.message(exception)}")
            {[], "event_search_failed"}
        catch
          :exit, reason ->
            Logger.warning("[EventController] search failed: exit #{inspect(reason)}")
            {[], "event_search_exit"}
        end

      json(conn, %{
        data: Enum.map(results, &serialize/1),
        meta: %{
          query: query,
          time_range: time_range,
          scoped: true,
          partial: not is_nil(partial_reason),
          partial_reason: partial_reason
        }
      })
    end
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
        partial: not is_nil(partial_reason),
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

      type
      when type in ["file_create", "file_modify", "file", :file_create, :file_modify, :file] ->
        path = payload[:path] || payload["path"] || "Unknown"
        "File operation: #{Path.basename(to_string(path))}"

      type when type in ["dns_query", "dns", :dns_query, :dns] ->
        domain =
          payload[:query] || payload["query"] || payload[:domain] || payload["domain"] ||
            "unknown"

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

  defp merge_mobile_events(serialized_events, nil, _limit, _params), do: serialized_events

  defp merge_mobile_events(serialized_events, organization_id, limit, params) do
    mobile_events =
      organization_id
      |> Mobile.list_organization_events(
        limit: limit,
        offset: bounded_offset(params["offset"]),
        hours: mobile_hours(params)
      )
      |> Enum.map(&serialize_mobile_event/1)
      |> filter_mobile_events_by_agent(params["agent_id"])

    (serialized_events ++ mobile_events)
    |> Enum.sort_by(&(&1.timestamp || ""), :desc)
    |> Enum.take(limit)
  rescue
    exception ->
      Logger.warning(
        "[EventController] mobile event projection failed: #{Exception.message(exception)}"
      )

      serialized_events
  catch
    :exit, reason ->
      Logger.warning("[EventController] mobile event projection failed: exit #{inspect(reason)}")
      serialized_events
  end

  defp serialize_mobile_event(event) do
    payload = event.payload || %{}

    %{
      id: event.id,
      agent_id: mobile_event_agent_id(event),
      agent_hostname: mobile_event_hostname(event),
      event_type: event.event_type || "mobile_event",
      timestamp: format_timestamp(event.timestamp),
      payload:
        payload
        |> Map.put_new("source", "mobile")
        |> Map.put_new("mobile_event_id", event.id)
        |> Map.put_new("mobile_device_id", mobile_event_device_external_id(event))
        |> Map.put_new("app_guard", app_guard_payload?(payload))
    }
  end

  defp mobile_event_agent_id(event) do
    case Map.get(event, :device) do
      %{organization_id: organization_id, device_id: device_id} ->
        Mobile.agent_id_for_device(organization_id, device_id) || device_id

      _ ->
        event.device_id
    end
  end

  defp mobile_event_device_external_id(event) do
    case Map.get(event, :device) do
      %{device_id: device_id} -> device_id
      _ -> event.device_id
    end
  end

  defp mobile_event_hostname(event) do
    case Map.get(event, :device) do
      %{model: model} when is_binary(model) and model != "" -> model
      %{device_id: device_id} -> device_id
      _ -> nil
    end
  end

  defp filter_mobile_events_by_agent(events, nil), do: events
  defp filter_mobile_events_by_agent(events, ""), do: events

  defp filter_mobile_events_by_agent(events, agent_id) when is_binary(agent_id) do
    Enum.filter(events, fn event ->
      event.agent_id == agent_id || get_in(event, [:payload, "mobile_device_id"]) == agent_id
    end)
  end

  defp app_guard_payload?(%{"schema" => "tamandua.app_guard.event/v1"}), do: true
  defp app_guard_payload?(_payload), do: false

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

  defp parse_datetime(nil), do: nil
  defp parse_datetime(""), do: nil

  defp parse_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> datetime
      _ -> nil
    end
  end

  defp parse_datetime(_), do: nil

  defp mobile_hours(%{"since" => since}) when is_binary(since) and since != "" do
    case parse_datetime(since) do
      %DateTime{} = datetime ->
        DateTime.diff(DateTime.utc_now(), datetime, :hour)
        |> max(1)
        |> min(24 * 30)

      _ ->
        24
    end
  end

  defp mobile_hours(_params), do: 24

  defp current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id)
  end

  defp safe_list_events(filters, label) do
    {Telemetry.list_events(filters), nil}
  rescue
    exception ->
      Logger.warning("[EventController] #{label} failed: #{Exception.message(exception)}")
      {[], "event_query_failed"}
  catch
    :exit, reason ->
      Logger.warning("[EventController] #{label} failed: exit #{inspect(reason)}")
      {[], "event_query_exit"}
  end
end
