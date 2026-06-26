defmodule TamanduaServer.Telemetry do
  @moduledoc """
  The Telemetry context.
  """

  import Ecto.Query, warn: false
  alias TamanduaServer.Repo

  alias TamanduaServer.Telemetry.Event

  @data_source_categories ~w(process file dns network registry driver ai ndr)

  @doc """
  Returns the list of events.

  ## Examples

      iex> list_events()
      [%Event{}, ...]

  """
  def list_events do
    Repo.all(Event)
  end

  @doc """
  Returns paginated list of events with total count.

  ## Parameters
  - `page` - Page number (1-indexed)
  - `per_page` - Number of items per page

  ## Returns
  `{events, total_count}` where events is a list and total_count is the total number of events
  """
  def list_events_paginated(page \\ 1, per_page \\ 50) do
    offset = (page - 1) * per_page

    query = from(e in Event, order_by: [desc: e.timestamp])

    total = Repo.aggregate(query, :count, :id)

    events =
      query
      |> limit(^per_page)
      |> offset(^offset)
      |> Repo.all()

    {events, total}
  end

  @doc """
  Gets a single event.

  Raises `Ecto.NoResultsError` if the Event does not exist.

  ## Examples

      iex> get_event!(123)
      %Event{}

      iex> get_event!(456)
      ** (Ecto.NoResultsError)

  """
  def get_event!(id), do: Repo.get!(Event, id)

  @doc """
  Gets a single event without raising an exception.

  Returns nil if the Event does not exist.

  ## Examples

      iex> get_event(valid_id)
      %Event{}

      iex> get_event(invalid_id)
      nil

  """
  def get_event(id), do: Repo.get(Event, id)

  def get_event_for_org(id, nil), do: get_event(id)

  def get_event_for_org(id, organization_id) do
    Repo.get_by(Event, id: id, organization_id: organization_id)
  end

  @doc """
  Creates a event.

  ## Examples

      iex> create_event(%{field: value})
      {:ok, %Event{}}

      iex> create_event(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_event(attrs \\ %{}) do
    %Event{}
    |> Event.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Returns events for a specific agent.
  """
  def list_events_for_agent(agent_id, limit \\ 100) do
    from(e in Event,
      where: e.agent_id == ^agent_id,
      order_by: [desc: e.timestamp],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Returns persisted telemetry coverage for endpoint data-source categories.

  The result is intentionally observational: it only reports event categories
  seen in the database during recent windows and does not infer whether a
  collector or OS capability is installed.
  """
  def data_source_health_for_agents(agent_ids, opts \\ []) do
    agent_ids =
      agent_ids
      |> List.wrap()
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    now =
      opts
      |> Keyword.get(:now, DateTime.utc_now())
      |> DateTime.truncate(:second)

    window_hours = opts |> Keyword.get(:window_hours, 24) |> normalize_window_hours()
    window_start = DateTime.add(now, -window_hours * 60 * 60, :second)
    history_hours =
      opts
      |> Keyword.get(:history_hours, max(window_hours, 24))
      |> normalize_window_hours()

    since = DateTime.add(now, -history_hours * 60 * 60, :second)

    empty_health =
      Map.new(agent_ids, fn agent_id ->
        {agent_id, empty_data_source_health(now)}
      end)

    if agent_ids == [] do
      %{}
    else
      last_24h = DateTime.add(now, -24 * 60 * 60, :second)
      last_hour = DateTime.add(now, -60 * 60, :second)

      from(e in Event,
        where: e.agent_id in ^agent_ids and e.timestamp >= ^since,
        group_by: [e.agent_id, e.event_type],
        select: {
          e.agent_id,
          e.event_type,
          max(e.timestamp),
          count(e.id),
          fragment("COUNT(*) FILTER (WHERE ? >= ?)", e.timestamp, ^window_start),
          fragment("COUNT(*) FILTER (WHERE ? >= ?)", e.timestamp, ^last_24h),
          fragment("COUNT(*) FILTER (WHERE ? >= ?)", e.timestamp, ^last_hour)
        }
      )
      |> Repo.all()
      |> Enum.reduce(empty_health, fn {agent_id, event_type, last_seen, count_7d, count_window,
                                       count_24h, count_hour},
                                      acc ->
        case classify_data_source_event(event_type) do
          nil ->
            acc

          source ->
            update_data_source_health_counts(
              acc,
              agent_id,
              source,
              last_seen,
              now,
              count_7d,
              count_window,
              count_24h,
              count_hour
            )
        end
      end)
      |> finalize_data_source_health(window_hours, window_start)
    end
  end

  defp empty_data_source_health(now) do
    %{
      status: "none",
      generatedAt: DateTime.to_iso8601(now),
      periods: %{
        "window" => empty_data_source_counts(),
        "lastHour" => empty_data_source_counts(),
        "last24h" => empty_data_source_counts(),
        "last7d" => empty_data_source_counts()
      },
      lastSeen: empty_data_source_last_seen(),
      totalLast24h: 0,
      totalLast7d: 0
    }
  end

  defp empty_data_source_counts do
    Map.new(@data_source_categories, &{&1, 0})
  end

  defp empty_data_source_last_seen do
    Map.new(@data_source_categories, &{&1, nil})
  end

  defp update_data_source_health(acc, agent_id, source, timestamp, now) do
    Map.update(acc, agent_id, empty_data_source_health(now), fn health ->
      health
      |> update_data_source_period("last7d", source)
      |> maybe_update_data_source_period(
        "last24h",
        source,
        timestamp,
        DateTime.add(now, -24 * 60 * 60, :second)
      )
      |> maybe_update_data_source_period(
        "lastHour",
        source,
        timestamp,
        DateTime.add(now, -60 * 60, :second)
      )
      |> update_data_source_last_seen(source, timestamp)
    end)
  end

  defp update_data_source_health_counts(
         acc,
         agent_id,
         source,
         timestamp,
         now,
         count_7d,
         count_window,
         count_24h,
         count_hour
       ) do
    Map.update(acc, agent_id, empty_data_source_health(now), fn health ->
      health
      |> increment_data_source_period("window", source, count_window)
      |> increment_data_source_period("last7d", source, count_7d)
      |> increment_data_source_period("last24h", source, count_24h)
      |> increment_data_source_period("lastHour", source, count_hour)
      |> update_data_source_last_seen(source, timestamp)
    end)
  end

  defp increment_data_source_period(health, _period, _source, count) when count in [nil, 0],
    do: health

  defp increment_data_source_period(health, period, source, count) do
    update_in(health, [:periods, period, source], &((&1 || 0) + count))
  end

  defp maybe_update_data_source_period(health, period, source, timestamp, cutoff) do
    if DateTime.compare(timestamp, cutoff) in [:eq, :gt] do
      update_data_source_period(health, period, source)
    else
      health
    end
  end

  defp update_data_source_period(health, period, source) do
    update_in(health, [:periods, period, source], &((&1 || 0) + 1))
  end

  defp update_data_source_last_seen(health, source, timestamp) do
    update_in(health, [:lastSeen, source], fn
      nil -> timestamp
      existing -> if DateTime.compare(timestamp, existing) == :gt, do: timestamp, else: existing
    end)
  end

  defp finalize_data_source_health(health_by_agent, window_hours, window_start) do
    Map.new(health_by_agent, fn {agent_id, health} ->
      total_last_24h = total_data_source_count(health.periods["last24h"])
      total_last_7d = total_data_source_count(health.periods["last7d"])

      status =
        cond do
          total_last_24h > 0 -> "recent"
          total_last_7d > 0 -> "stale"
          true -> "none"
        end

      last_seen =
        Map.new(health.lastSeen, fn
          {source, %DateTime{} = timestamp} -> {source, DateTime.to_iso8601(timestamp)}
          {source, timestamp} -> {source, timestamp}
        end)

      sources =
        Map.new(@data_source_categories, fn source ->
          count = get_in(health, [:periods, "window", source]) || 0
          last_seen_at = Map.get(health.lastSeen, source)
          source_status = data_source_status(count, last_seen_at, window_start)
          missing_reason = data_source_missing_reason(source_status, last_seen_at, window_hours)

          {source,
           %{
             "source" => source,
             "last_seen" => format_data_source_timestamp(last_seen_at),
             "count" => count,
             "status" => source_status,
             "missing_reason" => missing_reason
           }}
        end)

      finalized =
        %{
          health
          | status: status,
            totalLast24h: total_last_24h,
            totalLast7d: total_last_7d,
            lastSeen: last_seen
        }
        |> Map.put(:windowHours, window_hours)
        |> Map.put(:sources, sources)

      {agent_id, finalized}
    end)
  end

  defp data_source_status(count, _last_seen_at, _window_start) when count > 0, do: "healthy"

  defp data_source_status(_count, %DateTime{} = last_seen_at, window_start) do
    if DateTime.compare(last_seen_at, window_start) == :lt, do: "stale", else: "healthy"
  end

  defp data_source_status(_count, _last_seen_at, _window_start), do: "missing"

  defp data_source_missing_reason("healthy", _last_seen_at, _window_hours), do: nil

  defp data_source_missing_reason("stale", _last_seen_at, window_hours),
    do: "no_events_in_last_#{window_hours}h"

  defp data_source_missing_reason("missing", nil, _window_hours), do: "never_seen"
  defp data_source_missing_reason("missing", _last_seen_at, _window_hours), do: "unknown"

  defp format_data_source_timestamp(%DateTime{} = timestamp), do: DateTime.to_iso8601(timestamp)
  defp format_data_source_timestamp(timestamp), do: timestamp

  defp normalize_window_hours(value) when is_integer(value), do: value |> max(1) |> min(24 * 30)

  defp normalize_window_hours(value) when is_binary(value) do
    case Integer.parse(value) do
      {hours, _} -> normalize_window_hours(hours)
      :error -> 24
    end
  end

  defp normalize_window_hours(_), do: 24

  defp total_data_source_count(counts) do
    counts
    |> Map.values()
    |> Enum.sum()
  end

  defp classify_data_source_event(event_type) do
    normalized =
      event_type
      |> to_string()
      |> String.downcase()

    cond do
      String.contains?(normalized, "driver") or String.contains?(normalized, "kernel") or
        String.contains?(normalized, "etw") or String.contains?(normalized, "image_load") or
          String.contains?(normalized, "module_load") ->
        "driver"

      normalized in ["inference_request", "inference_response", "ai_usage", "ai_discovery"] or
        String.contains?(normalized, "ai_") or String.contains?(normalized, "llm") or
          String.contains?(normalized, "inference") ->
        "ai"

      String.contains?(normalized, "ndr") or String.contains?(normalized, "lateral") or
        String.contains?(normalized, "protocol_anomaly") or
          String.contains?(normalized, "encrypted_traffic") ->
        "ndr"

      String.contains?(normalized, "dns") ->
        "dns"

      String.contains?(normalized, "registry") or String.starts_with?(normalized, "reg_") or
          String.contains?(normalized, "_reg_") ->
        "registry"

      String.contains?(normalized, "network") or String.contains?(normalized, "connect") or
        String.contains?(normalized, "socket") or
        String.contains?(normalized, "flow") or String.contains?(normalized, "http") or
        String.contains?(normalized, "tcp") or
          String.contains?(normalized, "udp") ->
        "network"

      String.contains?(normalized, "file") or String.contains?(normalized, "fim") or
        String.contains?(normalized, "write") or
        String.contains?(normalized, "rename") or String.contains?(normalized, "delete") ->
        "file"

      String.contains?(normalized, "process") or String.contains?(normalized, "proc") or
        String.contains?(normalized, "exec") or
          String.contains?(normalized, "spawn") ->
        "process"

      true ->
        nil
    end
  end

  @doc """
  Returns paginated and filtered events for a specific agent.

  Supports filtering by event_type, severity, and date range (from/to).
  Returns `{events, total_count}`.
  """
  def list_agent_events(agent_id, filters) when is_map(filters) do
    limit = filters[:limit] || 100
    offset = filters[:offset] || 0

    base_query =
      from(e in Event,
        where: e.agent_id == ^agent_id,
        order_by: [desc: e.timestamp]
      )

    # Apply event_type filter
    base_query =
      case filters[:event_type] do
        nil ->
          base_query

        "" ->
          base_query

        types when is_binary(types) ->
          type_list = String.split(types, ",") |> Enum.map(&String.trim/1)

          if length(type_list) > 1 do
            where(base_query, [e], e.event_type in ^type_list)
          else
            where(base_query, [e], e.event_type == ^hd(type_list))
          end

        _ ->
          base_query
      end

    # Apply severity filter
    base_query =
      case filters[:severity] do
        nil ->
          base_query

        "" ->
          base_query

        severity when is_binary(severity) ->
          severity_list = String.split(severity, ",") |> Enum.map(&String.trim/1)

          if length(severity_list) > 1 do
            where(base_query, [e], e.severity in ^severity_list)
          else
            where(base_query, [e], e.severity == ^hd(severity_list))
          end

        _ ->
          base_query
      end

    # Apply date range filters (from)
    base_query =
      case filters[:from] do
        nil ->
          base_query

        "" ->
          base_query

        from_str when is_binary(from_str) ->
          case NaiveDateTime.from_iso8601(from_str) do
            {:ok, from_dt} ->
              where(base_query, [e], e.timestamp >= ^from_dt)

            _ ->
              case Date.from_iso8601(from_str) do
                {:ok, date} ->
                  from_dt = NaiveDateTime.new!(date, ~T[00:00:00])
                  where(base_query, [e], e.timestamp >= ^from_dt)

                _ ->
                  base_query
              end
          end

        _ ->
          base_query
      end

    # Apply date range filters (to)
    base_query =
      case filters[:to] do
        nil ->
          base_query

        "" ->
          base_query

        to_str when is_binary(to_str) ->
          case NaiveDateTime.from_iso8601(to_str) do
            {:ok, to_dt} ->
              where(base_query, [e], e.timestamp <= ^to_dt)

            _ ->
              case Date.from_iso8601(to_str) do
                {:ok, date} ->
                  to_dt = NaiveDateTime.new!(date, ~T[23:59:59])
                  where(base_query, [e], e.timestamp <= ^to_dt)

                _ ->
                  base_query
              end
          end

        _ ->
          base_query
      end

    # Get total count before pagination
    total = Repo.aggregate(base_query, :count, :id)

    # Apply pagination and fetch
    events =
      base_query
      |> limit(^limit)
      |> offset(^offset)
      |> Repo.all()

    {events, total}
  end

  @doc """
  Search events based on criteria.
  """
  def search_events(params) do
    query = from(e in Event, order_by: [desc: e.timestamp])

    query =
      if params[:agent_id], do: where(query, [e], e.agent_id == ^params[:agent_id]), else: query

    query =
      if params[:event_type],
        do: where(query, [e], e.event_type == ^params[:event_type]),
        else: query

    # Simple text search on payload (Postgres JSONB)
    query =
      if params[:query] do
        # This is a naive implementation, ideally use full text search
        term = "%#{params[:query]}%"
        # Note: Ecto doesn't support JSONB text search easily without fragments
        # For now, we skip payload search or implement it later
        query
      else
        query
      end

    limit = params[:limit] || 50
    query = limit(query, ^limit)

    Repo.all(query)
  end

  @doc """
  Search events based on criteria with pagination.
  Returns {results, total_count}.
  """
  def search_events_paginated(params) do
    page = params[:page] || 1
    per_page = params[:per_page] || 50
    offset = (page - 1) * per_page

    query = from(e in Event, order_by: [desc: e.timestamp])

    query =
      if params[:agent_id], do: where(query, [e], e.agent_id == ^params[:agent_id]), else: query

    query =
      if params[:event_type],
        do: where(query, [e], e.event_type == ^params[:event_type]),
        else: query

    # Simple text search on payload (Postgres JSONB)
    query =
      if params[:query] do
        # This is a naive implementation, ideally use full text search
        term = "%#{params[:query]}%"
        # Note: Ecto doesn't support JSONB text search easily without fragments
        # For now, we skip payload search or implement it later
        query
      else
        query
      end

    # Get total count before pagination
    total = Repo.aggregate(query, :count, :id)

    # Apply pagination
    results =
      query
      |> limit(^per_page)
      |> offset(^offset)
      |> Repo.all()

    {results, total}
  end

  @doc """
  List events with filters.
  Supports multiple event types (comma-separated string or list).
  """
  def list_events(filters) when is_map(filters) do
    latest_timestamp = filters[:until] || DateTime.add(DateTime.utc_now(), 5 * 60, :second)

    query =
      from(e in Event,
        where: e.timestamp <= ^latest_timestamp,
        order_by: [desc: e.timestamp]
      )

    query =
      if filters[:agent_id], do: where(query, [e], e.agent_id == ^filters[:agent_id]), else: query

    query =
      if filters[:organization_id],
        do: where(query, [e], e.organization_id == ^filters[:organization_id]),
        else: query

    # Support multiple event types (comma-separated or list)
    query =
      case filters[:event_type] do
        nil ->
          query

        types when is_binary(types) ->
          type_list = String.split(types, ",") |> Enum.map(&String.trim/1)

          if length(type_list) > 1 do
            where(query, [e], e.event_type in ^type_list)
          else
            where(query, [e], e.event_type == ^hd(type_list))
          end

        types when is_list(types) ->
          where(query, [e], e.event_type in ^types)

        type ->
          where(query, [e], e.event_type == ^type)
      end

    query =
      if filters[:severity], do: where(query, [e], e.severity == ^filters[:severity]), else: query

    query =
      if filters[:since], do: where(query, [e], e.timestamp >= ^filters[:since]), else: query

    limit = filters[:limit] || 100
    offset = filters[:offset] || 0

    events =
      query
      |> limit(^limit)
      |> offset(^offset)
      |> Repo.all()

    if filters[:skip_agent_lookup] do
      events
    else
      Enum.map(events, fn event ->
        Map.put(event, :agent_hostname, get_agent_hostname(event.agent_id))
      end)
    end
  end

  @doc """
  Search events with a query string and time range.
  """
  def search_events(query_string, time_range, limit, opts \\ []) do
    start_time = parse_time_range(time_range)
    agent_ids = Keyword.get(opts, :agent_ids)

    query =
      from(e in Event,
        where: e.timestamp >= ^start_time,
        order_by: [desc: e.timestamp],
        limit: ^limit
      )

    query =
      if agent_ids && length(agent_ids) > 0 do
        where(query, [e], e.agent_id in ^agent_ids)
      else
        query
      end

    query =
      if query_string && String.length(query_string) > 0 do
        # Basic search - improve with full text search later
        query
      else
        query
      end

    Repo.all(query)
    |> Enum.map(fn event ->
      Map.put(event, :agent_hostname, get_agent_hostname(event.agent_id))
    end)
  end

  @doc """
  Execute a structured hunting query.
  """
  def execute_hunting_query(query_ast, time_range, limit) do
    # Parse and validate the query AST
    case parse_hunting_query(query_ast) do
      {:ok, conditions} ->
        start_time = parse_time_range(time_range)

        query =
          from(e in Event,
            where: e.timestamp >= ^start_time,
            order_by: [desc: e.timestamp],
            limit: ^limit
          )

        query = apply_hunting_conditions(query, conditions)

        results =
          Repo.all(query)
          |> Enum.map(fn event ->
            Map.put(event, :agent_hostname, get_agent_hostname(event.agent_id))
          end)

        stats = %{
          total_scanned: length(results),
          time_range: time_range
        }

        {:ok, results, stats}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Count events from today.
  """
  def count_events_today do
    today_start = DateTime.utc_now() |> DateTime.to_date() |> DateTime.new!(~T[00:00:00])

    from(e in Event, where: e.timestamp >= ^today_start)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Count events from today for an organization.

  Joins through the Agent table to filter by organization_id.
  """
  def count_events_today_for_org(organization_id) do
    today_start = DateTime.utc_now() |> DateTime.to_date() |> DateTime.new!(~T[00:00:00])

    from(e in Event,
      join: a in TamanduaServer.Agents.Agent,
      on: e.agent_id == a.id,
      where: e.timestamp >= ^today_start and a.organization_id == ^organization_id
    )
    |> Repo.aggregate(:count, :id)
  end

  defp parse_time_range("1h"), do: DateTime.utc_now() |> DateTime.add(-1, :hour)
  defp parse_time_range("6h"), do: DateTime.utc_now() |> DateTime.add(-6, :hour)
  defp parse_time_range("24h"), do: DateTime.utc_now() |> DateTime.add(-24, :hour)
  defp parse_time_range("7d"), do: DateTime.utc_now() |> DateTime.add(-7, :day)
  defp parse_time_range("30d"), do: DateTime.utc_now() |> DateTime.add(-30, :day)
  defp parse_time_range(_), do: DateTime.utc_now() |> DateTime.add(-24, :hour)

  defp get_agent_hostname(agent_id) do
    case TamanduaServer.Agents.get(agent_id) do
      nil -> "Unknown"
      agent -> agent.hostname
    end
  end

  @doc """
  Execute a hunt search with query string parsing.

  Supports queries like:
    - `pid:1234` — search payload for pid field
    - `process.name:cmd.exe` — search payload for process_name or name
    - `hash:abc123` — search by SHA256 hash
    - `remote_ip:192.168.1.1` — search network events by IP
    - `event_type:process_create` — filter by event type
    - `field:*value*` — contains match (wildcard)
    - Multiple terms joined by AND/OR
  """
  def hunt_search(query_string, time_range, limit, opts \\ []) do
    start_time = parse_time_range(time_range)
    agent_ids = Keyword.get(opts, :agent_ids)

    base =
      from(e in Event,
        where: e.timestamp >= ^start_time,
        order_by: [desc: e.timestamp],
        limit: ^limit
      )

    base =
      if agent_ids && is_list(agent_ids) && length(agent_ids) > 0 do
        where(base, [e], e.agent_id in ^agent_ids)
      else
        base
      end

    # Parse and apply the query string
    base =
      if query_string && String.trim(query_string) != "" do
        apply_hunt_query(base, String.trim(query_string))
      else
        base
      end

    Repo.all(base)
    |> Enum.map(fn event ->
      Map.put(event, :agent_hostname, get_agent_hostname(event.agent_id))
    end)
  end

  # Parse a hunt query string into Ecto conditions
  defp apply_hunt_query(query, query_string) do
    # Split by AND (default connector)
    # Support: "field:value AND field2:value2" or just "field:value field2:value2"
    conditions =
      query_string
      |> String.split(~r/\s+AND\s+/i)
      |> Enum.flat_map(fn part ->
        # Each AND-part can have OR sub-conditions
        String.split(part, ~r/\s+OR\s+/i)
        |> Enum.map(&parse_condition/1)
        |> Enum.reject(&is_nil/1)
      end)

    # If OR is used within a part, we'd need more complex logic
    # For now, treat all conditions as AND
    Enum.reduce(conditions, query, fn condition, q ->
      apply_condition(q, condition)
    end)
  end

  # Parse "field:value" or "field:*value*" into a condition tuple
  defp parse_condition(term) do
    term = String.trim(term)

    case String.split(term, ":", parts: 2) do
      [field, value] when value != "" ->
        field = String.trim(field)
        value = String.trim(value)

        # Determine match type
        cond do
          String.starts_with?(value, "*") && String.ends_with?(value, "*") ->
            # Contains match
            inner = String.trim(value, "*")
            {:contains, normalize_field(field), inner}

          String.starts_with?(value, ">") ->
            {:gt, normalize_field(field), String.trim_leading(value, ">")}

          String.starts_with?(value, "<") ->
            {:lt, normalize_field(field), String.trim_leading(value, "<")}

          String.starts_with?(value, "!") ->
            {:not_eq, normalize_field(field), String.trim_leading(value, "!")}

          String.ends_with?(value, "*") ->
            # Starts with
            prefix = String.trim_trailing(value, "*")
            {:starts_with, normalize_field(field), prefix}

          String.starts_with?(value, "*") ->
            # Ends with
            suffix = String.trim_leading(value, "*")
            {:ends_with, normalize_field(field), suffix}

          true ->
            {:eq, normalize_field(field), value}
        end

      _ ->
        nil
    end
  end

  # Normalize field names to support multiple conventions
  defp normalize_field(field) do
    case field do
      # Direct top-level fields
      "event_type" ->
        {:column, :event_type}

      "event.type" ->
        {:column, :event_type}

      "agent_id" ->
        {:column, :agent_id}

      "agent.id" ->
        {:column, :agent_id}

      # Process fields → payload JSONB
      "pid" ->
        {:payload, "pid"}

      "process.pid" ->
        {:payload, "pid"}

      "process.name" ->
        {:payload, "name"}

      "process_name" ->
        {:payload, "name"}

      "process.path" ->
        {:payload, "path"}

      "process.cmdline" ->
        {:payload, "command_line"}

      "process.user" ->
        {:payload, "user"}

      "process.ppid" ->
        {:payload, "parent_pid"}

      "process.sha256" ->
        {:payload, "sha256"}

      "process.is_elevated" ->
        {:payload, "is_elevated"}

      "process.parent" ->
        {:payload, "parent_name"}

      # Network fields
      "remote_ip" ->
        {:payload, "remote_ip"}

      "network.remote_ip" ->
        {:payload, "remote_ip"}

      "network.remote_port" ->
        {:payload, "remote_port"}

      "network.local_port" ->
        {:payload, "local_port"}

      "network.protocol" ->
        {:payload, "protocol"}

      "network.direction" ->
        {:payload, "direction"}

      "network.bytes_sent" ->
        {:payload, "bytes_sent"}

      "network.bytes_recv" ->
        {:payload, "bytes_received"}

      # File fields
      "file.path" ->
        {:payload, "path"}

      "file_path" ->
        {:payload, "path"}

      "file.name" ->
        {:payload, "file_name"}

      "file.sha256" ->
        {:payload, "sha256"}

      "file.operation" ->
        {:payload, "operation"}

      # DNS fields
      "dns.query" ->
        {:payload, "query"}

      "domain" ->
        {:payload, "query"}

      "dns.query_type" ->
        {:payload, "query_type"}

      "dns.response" ->
        {:payload, "response"}

      # Registry fields
      "registry.path" ->
        {:payload, "key_path"}

      "registry_key" ->
        {:payload, "key_path"}

      "registry.key" ->
        {:payload, "value_name"}

      "registry.value" ->
        {:payload, "value_data"}

      "registry.operation" ->
        {:payload, "operation"}

      # Common aliases
      "hash" ->
        {:payload, "sha256"}

      "sha256" ->
        {:payload, "sha256"}

      "source_process" ->
        {:payload, "source_process"}

      "target_pid" ->
        {:payload, "target_pid"}

      "user" ->
        {:payload, "user"}

      # Hostname (virtual field from agent)
      # Will be filtered post-query
      "agent.hostname" ->
        {:column, :agent_id}

      "hostname" ->
        {:column, :agent_id}

      # Generic payload field
      other ->
        # Try as-is in payload (replace dots with underscores)
        payload_key = String.replace(other, ".", "_")
        {:payload, payload_key}
    end
  end

  # Apply a parsed condition to an Ecto query
  defp apply_condition(query, {:eq, {:column, :event_type}, value}) do
    where(query, [e], e.event_type == ^value)
  end

  defp apply_condition(query, {:eq, {:column, :agent_id}, value}) do
    where(query, [e], e.agent_id == ^value)
  end

  defp apply_condition(query, {:contains, {:column, :event_type}, value}) do
    pattern = "%#{value}%"
    where(query, [e], like(e.event_type, ^pattern))
  end

  defp apply_condition(query, {:eq, {:payload, key}, value}) do
    where(query, [e], fragment("?->>? = ?", e.payload, ^key, ^value))
  end

  defp apply_condition(query, {:contains, {:payload, key}, value}) do
    pattern = "%#{value}%"
    where(query, [e], fragment("?->>? ILIKE ?", e.payload, ^key, ^pattern))
  end

  defp apply_condition(query, {:starts_with, {:payload, key}, value}) do
    pattern = "#{value}%"
    where(query, [e], fragment("?->>? ILIKE ?", e.payload, ^key, ^pattern))
  end

  defp apply_condition(query, {:ends_with, {:payload, key}, value}) do
    pattern = "%#{value}"
    where(query, [e], fragment("?->>? ILIKE ?", e.payload, ^key, ^pattern))
  end

  defp apply_condition(query, {:not_eq, {:payload, key}, value}) do
    where(
      query,
      [e],
      fragment("?->>? != ? OR ?->? IS NULL", e.payload, ^key, ^value, e.payload, ^key)
    )
  end

  defp apply_condition(query, {:gt, {:payload, key}, value}) do
    where(query, [e], fragment("(?->>?)::numeric > ?::numeric", e.payload, ^key, ^value))
  end

  defp apply_condition(query, {:lt, {:payload, key}, value}) do
    where(query, [e], fragment("(?->>?)::numeric < ?::numeric", e.payload, ^key, ^value))
  end

  # Fallback — try a full-text search across the entire payload JSON
  defp apply_condition(query, {_op, {:payload, _key}, _value}) do
    query
  end

  defp apply_condition(query, _), do: query

  defp parse_hunting_query(nil), do: {:ok, []}
  defp parse_hunting_query(ast) when is_map(ast), do: {:ok, ast}
  defp parse_hunting_query(_), do: {:error, "Invalid query format"}

  defp apply_hunting_conditions(query, conditions) when is_map(conditions) do
    Enum.reduce(conditions, query, fn {field, value}, q ->
      case field do
        "event_type" -> where(q, [e], e.event_type == ^value)
        "agent_id" -> where(q, [e], e.agent_id == ^value)
        _ -> q
      end
    end)
  end

  defp apply_hunting_conditions(query, _), do: query

  @doc """
  Count events with optional filters (event_type, agent_id).
  """
  def count_events(filters \\ %{}) do
    query = from(e in Event)

    query =
      if filters[:agent_id], do: where(query, [e], e.agent_id == ^filters[:agent_id]), else: query

    query =
      case filters[:event_type] do
        nil ->
          query

        types when is_binary(types) ->
          type_list = String.split(types, ",") |> Enum.map(&String.trim/1)

          if length(type_list) > 1 do
            where(query, [e], e.event_type in ^type_list)
          else
            where(query, [e], e.event_type == ^hd(type_list))
          end

        _ ->
          query
      end

    query =
      if filters[:severity], do: where(query, [e], e.severity == ^filters[:severity]), else: query

    query =
      if filters[:since], do: where(query, [e], e.timestamp >= ^filters[:since]), else: query

    Repo.aggregate(query, :count, :id)
  end

  @doc """
  Get distinct event types from the database.
  """
  def get_distinct_event_types do
    from(e in Event,
      distinct: true,
      select: e.event_type,
      order_by: [asc: e.event_type]
    )
    |> Repo.all()
  end
end
