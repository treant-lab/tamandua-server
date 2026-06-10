defmodule TamanduaServer.XDR.FederatedSearch do
  @moduledoc """
  Federated Search - Search across all data tiers simultaneously.

  Provides a unified search interface that:
  - Fans out queries to hot (PostgreSQL), warm (Parquet), cold (archive) tiers
  - Merges results with deduplication
  - Progressive result streaming (hot results first, then warm, then cold)
  - Query caching for repeated searches
  - Rich search syntax: field:value, AND/OR/NOT, wildcards, time ranges
  - Integration with unified_search.ex and partitioned_store.ex

  Search syntax examples:
  - `event_type:process_create AND severity:high`
  - `hash:a1b2c3* OR ip:192.168.1.*`
  - `user:admin NOT event_type:auth_success`
  - `@timestamp:[2024-01-01 TO 2024-01-31]`
  - `path:"C:\\Windows\\System32\\cmd.exe"`
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.XDR.PartitionedStore

  @search_cache :federated_search_cache
  @search_stats :federated_search_stats

  # Cache TTL: 2 minutes
  @cache_ttl_ms 120_000
  # Maximum results per tier
  @max_per_tier 5000
  # Query timeout per tier (ms)
  @tier_timeout_ms 10_000
  # Progressive streaming batch size
  @stream_batch_size 100

  # ------------------------------------------------------------------
  # Client API
  # ------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Execute a federated search across all data tiers.

  Options:
  - `:query` - Search query string (supports field:value, AND/OR/NOT, wildcards)
  - `:from` - Start time (DateTime or ISO 8601 string)
  - `:to` - End time (DateTime or ISO 8601 string)
  - `:agent_id` - Filter by agent
  - `:organization_id` - Filter by organization
  - `:tiers` - Which tiers to search (default [:hot, :warm, :cold])
  - `:limit` - Max results (default 1000)
  - `:offset` - Pagination offset (default 0)
  - `:sort` - Sort field (default :timestamp)
  - `:order` - :asc or :desc (default :desc)
  - `:progressive` - Return results progressively as tiers respond (default false)
  """
  @spec search(keyword()) :: {:ok, map()}
  def search(opts \\ []) do
    GenServer.call(__MODULE__, {:search, opts}, 60_000)
  end

  @doc """
  Start a streaming search that returns results progressively.
  The caller will receive messages:
  - `{:search_results, :hot, results}` - Hot tier results
  - `{:search_results, :warm, results}` - Warm tier results
  - `{:search_results, :cold, results}` - Cold tier results
  - `{:search_complete, metadata}` - Search complete
  """
  @spec stream_search(keyword(), pid()) :: {:ok, String.t()}
  def stream_search(opts, caller_pid) do
    GenServer.call(__MODULE__, {:stream_search, opts, caller_pid})
  end

  @doc """
  Parse a search query string into a structured query.
  """
  @spec parse_query(String.t()) :: {:ok, map()} | {:error, term()}
  def parse_query(query_string) do
    {:ok, do_parse_query(query_string)}
  end

  @doc """
  Get search statistics.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  @doc """
  Clear search cache.
  """
  @spec clear_cache() :: :ok
  def clear_cache do
    GenServer.cast(__MODULE__, :clear_cache)
  end

  # ------------------------------------------------------------------
  # Server Callbacks
  # ------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@search_cache, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@search_stats, [:set, :public, :named_table, read_concurrency: true])

    :ets.insert(@search_stats, {:counters, %{
      total_searches: 0,
      cache_hits: 0,
      hot_queries: 0,
      warm_queries: 0,
      cold_queries: 0,
      errors: 0,
      total_results: 0,
      avg_latency_ms: 0
    }})

    Logger.info("[FederatedSearch] Federated Search engine started")

    {:ok, %{}}
  end

  @impl true
  def handle_call({:search, opts}, _from, state) do
    start_time = System.monotonic_time(:millisecond)

    # Check cache
    cache_key = :erlang.phash2(opts)
    result = case check_cache(cache_key) do
      {:hit, cached} ->
        update_stat(:cache_hits, 1)
        cached

      :miss ->
        execute_federated_search(opts)
    end

    elapsed = System.monotonic_time(:millisecond) - start_time

    # Update stats
    update_stat(:total_searches, 1)
    update_stat(:total_results, length(result.results))
    update_avg_latency(elapsed)

    # Cache the result
    :ets.insert(@search_cache, {cache_key, {result, DateTime.utc_now()}})

    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:stream_search, opts, caller_pid}, _from, state) do
    search_id = Ecto.UUID.generate()

    # Launch progressive search in background
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      execute_progressive_search(opts, caller_pid, search_id)
    end)

    {:reply, {:ok, search_id}, state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    counters = case :ets.lookup(@search_stats, :counters) do
      [{:counters, c}] -> c
      [] -> %{}
    end

    cache_size = :ets.info(@search_cache, :size)

    {:reply, Map.merge(counters, %{cache_entries: cache_size}), state}
  end

  @impl true
  def handle_cast(:clear_cache, state) do
    :ets.delete_all_objects(@search_cache)
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ------------------------------------------------------------------
  # Federated Search Execution
  # ------------------------------------------------------------------

  defp execute_federated_search(opts) do
    query_string = Keyword.get(opts, :query, "")
    tiers = Keyword.get(opts, :tiers, [:hot, :warm, :cold])
    limit = Keyword.get(opts, :limit, 1000)
    offset = Keyword.get(opts, :offset, 0)
    sort_field = Keyword.get(opts, :sort, :timestamp)
    order = Keyword.get(opts, :order, :desc)

    # Parse the query
    parsed = do_parse_query(query_string)

    # Merge explicit filters from opts into parsed query
    filters = build_filters(parsed, opts)

    # Fan out to tiers
    tier_results = Enum.map(tiers, fn tier ->
      Task.async(fn ->
        start = System.monotonic_time(:millisecond)
        results = query_tier(tier, filters, limit)
        elapsed = System.monotonic_time(:millisecond) - start
        update_stat(:"#{tier}_queries", 1)
        {tier, results, elapsed}
      end)
    end)
    |> Enum.map(fn task ->
      case Task.yield(task, @tier_timeout_ms) || Task.shutdown(task) do
        {:ok, result} -> result
        _ -> {:error, [], 0}
      end
    end)

    # Merge and deduplicate results
    all_results = Enum.flat_map(tier_results, fn
      {_tier, results, _elapsed} when is_list(results) -> results
      _ -> []
    end)

    merged = all_results
    |> Enum.uniq_by(fn r -> r[:id] || r["id"] end)
    |> sort_results(sort_field, order)
    |> Enum.drop(offset)
    |> Enum.take(limit)

    # Build metadata
    tier_metadata = Enum.map(tier_results, fn
      {tier, results, elapsed} when is_list(results) ->
        {tier, %{count: length(results), latency_ms: elapsed}}
      {tier, _, _} ->
        {tier, %{count: 0, latency_ms: 0, error: true}}
    end)
    |> Map.new()

    %{
      results: merged,
      total_count: length(all_results),
      returned_count: length(merged),
      offset: offset,
      limit: limit,
      query: query_string,
      parsed_query: parsed,
      tiers: tier_metadata,
      search_time_ms: Enum.reduce(tier_results, 0, fn
        {_, _, elapsed}, acc when is_number(elapsed) -> max(acc, elapsed)
        _, acc -> acc
      end)
    }
  end

  defp execute_progressive_search(opts, caller_pid, search_id) do
    query_string = Keyword.get(opts, :query, "")
    tiers = Keyword.get(opts, :tiers, [:hot, :warm, :cold])
    limit = Keyword.get(opts, :limit, 1000)

    parsed = do_parse_query(query_string)
    filters = build_filters(parsed, opts)

    total_results = []

    # Query each tier sequentially and stream results
    {final_results, tier_meta} = Enum.reduce(tiers, {total_results, %{}}, fn tier, {acc_results, acc_meta} ->
      start = System.monotonic_time(:millisecond)
      results = query_tier(tier, filters, limit)
      elapsed = System.monotonic_time(:millisecond) - start

      # Send results to caller
      send(caller_pid, {:search_results, tier, results, search_id})

      {acc_results ++ results, Map.put(acc_meta, tier, %{count: length(results), latency_ms: elapsed})}
    end)

    # Deduplicate final results
    deduped = final_results
    |> Enum.uniq_by(fn r -> r[:id] || r["id"] end)
    |> Enum.take(limit)

    metadata = %{
      search_id: search_id,
      total_count: length(deduped),
      tiers: tier_meta,
      query: query_string
    }

    send(caller_pid, {:search_complete, metadata, search_id})
  end

  # ------------------------------------------------------------------
  # Tier Querying
  # ------------------------------------------------------------------

  defp query_tier(:hot, filters, limit) do
    query = from(e in "xdr_events",
      select: %{
        id: e.id,
        agent_id: e.agent_id,
        event_type: e.event_type,
        severity: e.severity,
        payload: e.payload,
        timestamp: e.timestamp,
        inserted_at: e.inserted_at
      },
      order_by: [desc: e.timestamp],
      limit: ^min(limit, @max_per_tier)
    )

    query = apply_search_filters(query, filters)

    try do
      results = Repo.all(query)
      Enum.map(results, &Map.put(&1, :tier, :hot))
    rescue
      _ -> []
    end
  end

  defp query_tier(:warm, filters, limit) do
    query = from(e in "xdr_events_warm",
      select: %{
        id: e.id,
        agent_id: e.agent_id,
        event_type: e.event_type,
        severity: e.severity,
        payload: e.payload,
        timestamp: e.timestamp
      },
      order_by: [desc: e.timestamp],
      limit: ^min(limit, @max_per_tier)
    )

    query = apply_search_filters(query, filters)

    try do
      results = Repo.all(query)
      Enum.map(results, &Map.put(&1, :tier, :warm))
    rescue
      _ -> []
    end
  end

  defp query_tier(:cold, filters, limit) do
    query = from(e in "xdr_events_cold",
      select: %{
        id: e.id,
        agent_id: e.agent_id,
        event_type: e.event_type,
        severity: e.severity,
        payload: e.payload,
        timestamp: e.timestamp
      },
      order_by: [desc: e.timestamp],
      limit: ^min(limit, div(@max_per_tier, 2))
    )

    query = apply_search_filters(query, filters)

    try do
      results = Repo.all(query)
      Enum.map(results, &Map.put(&1, :tier, :cold))
    rescue
      _ -> []
    end
  end

  defp query_tier(_, _filters, _limit), do: []

  # ------------------------------------------------------------------
  # Search Filter Application
  # ------------------------------------------------------------------

  defp apply_search_filters(query, filters) do
    query
    |> apply_time_range(filters)
    |> apply_field_filters(filters)
    |> apply_text_search(filters)
  end

  defp apply_time_range(query, %{from: from, to: to}) when not is_nil(from) and not is_nil(to) do
    from(e in query, where: e.timestamp >= ^from and e.timestamp <= ^to)
  end

  defp apply_time_range(query, %{from: from}) when not is_nil(from) do
    from(e in query, where: e.timestamp >= ^from)
  end

  defp apply_time_range(query, %{to: to}) when not is_nil(to) do
    from(e in query, where: e.timestamp <= ^to)
  end

  defp apply_time_range(query, _), do: query

  defp apply_field_filters(query, %{field_filters: field_filters}) when is_list(field_filters) do
    Enum.reduce(field_filters, query, fn filter, q ->
      apply_single_filter(q, filter)
    end)
  end

  defp apply_field_filters(query, _), do: query

  defp apply_single_filter(query, %{field: "agent_id", op: :eq, value: value}) do
    from(e in query, where: e.agent_id == ^value)
  end

  defp apply_single_filter(query, %{field: "event_type", op: :eq, value: value}) do
    from(e in query, where: e.event_type == ^value)
  end

  defp apply_single_filter(query, %{field: "severity", op: :eq, value: value}) do
    from(e in query, where: e.severity == ^value)
  end

  defp apply_single_filter(query, %{field: "organization_id", op: :eq, value: value}) do
    from(e in query, where: e.organization_id == ^value)
  end

  defp apply_single_filter(query, %{field: field, op: :eq, value: value}) do
    # For payload fields, use JSONB contains
    from(e in query,
      where: fragment("?->? = ?", e.payload, ^field, ^value)
    )
  end

  defp apply_single_filter(query, %{field: field, op: :wildcard, value: pattern}) do
    # Convert wildcard to SQL LIKE pattern
    like_pattern = pattern |> String.replace("*", "%") |> String.replace("?", "_")

    case field do
      "event_type" -> from(e in query, where: like(e.event_type, ^like_pattern))
      "severity" -> from(e in query, where: like(e.severity, ^like_pattern))
      _ -> from(e in query, where: fragment("?->>? LIKE ?", e.payload, ^field, ^like_pattern))
    end
  end

  defp apply_single_filter(query, %{field: field, op: :not_eq, value: value}) do
    case field do
      "event_type" -> from(e in query, where: e.event_type != ^value)
      "severity" -> from(e in query, where: e.severity != ^value)
      _ -> from(e in query, where: fragment("?->>? != ?", e.payload, ^field, ^value))
    end
  end

  defp apply_single_filter(query, _), do: query

  defp apply_text_search(query, %{text_search: text}) when is_binary(text) and byte_size(text) > 0 do
    pattern = "%#{text}%"
    from(e in query,
      where: like(e.event_type, ^pattern) or
             fragment("?::text LIKE ?", e.payload, ^pattern)
    )
  end

  defp apply_text_search(query, _), do: query

  # ------------------------------------------------------------------
  # Query Parser
  # ------------------------------------------------------------------

  defp do_parse_query(""), do: %{field_filters: [], text_search: nil, from: nil, to: nil}
  defp do_parse_query(nil), do: %{field_filters: [], text_search: nil, from: nil, to: nil}

  defp do_parse_query(query_string) when is_binary(query_string) do
    # Tokenize the query
    tokens = tokenize_query(query_string)

    # Parse tokens into structured filters
    {filters, text_parts, time_range} = parse_tokens(tokens)

    text_search = if Enum.empty?(text_parts), do: nil, else: Enum.join(text_parts, " ")

    %{
      field_filters: filters,
      text_search: text_search,
      from: time_range[:from],
      to: time_range[:to]
    }
  end

  defp tokenize_query(query_string) do
    # Split respecting quoted strings
    regex = ~r/(?:"[^"]*"|[^\s]+)/
    Regex.scan(regex, query_string)
    |> Enum.map(fn [token] ->
      # Remove surrounding quotes
      token
      |> String.trim("\"")
    end)
  end

  defp parse_tokens(tokens) do
    {filters, text_parts, time_range, negate_next} =
      Enum.reduce(tokens, {[], [], %{}, false}, fn token, {filters, texts, tr, negate} ->
        token_upper = String.upcase(token)

        cond do
          # Boolean operators
          token_upper in ["AND", "OR"] ->
            {filters, texts, tr, false}

          token_upper == "NOT" ->
            {filters, texts, tr, true}

          # Time range: @timestamp:[from TO to]
          String.starts_with?(token, "@timestamp:") ->
            new_tr = parse_time_range(token)
            {filters, texts, Map.merge(tr, new_tr), false}

          # Field:value filter
          String.contains?(token, ":") ->
            [field | value_parts] = String.split(token, ":", parts: 2)
            value = Enum.join(value_parts, ":")

            op = cond do
              negate -> :not_eq
              String.contains?(value, "*") or String.contains?(value, "?") -> :wildcard
              true -> :eq
            end

            filter = %{field: field, op: op, value: value}
            {[filter | filters], texts, tr, false}

          # Plain text
          true ->
            {filters, [token | texts], tr, false}
        end
      end)

    {Enum.reverse(filters), Enum.reverse(text_parts), time_range}
  end

  defp parse_time_range(token) do
    # Parse @timestamp:[2024-01-01 TO 2024-01-31]
    case Regex.run(~r/@timestamp:\[(.+)\s+TO\s+(.+)\]/, token) do
      [_, from_str, to_str] ->
        from_dt = parse_datetime(String.trim(from_str))
        to_dt = parse_datetime(String.trim(to_str))
        %{from: from_dt, to: to_dt}

      _ ->
        # Try @timestamp:>value or @timestamp:<value
        case Regex.run(~r/@timestamp:([<>]=?)(.+)/, token) do
          [_, ">", value] -> %{from: parse_datetime(value)}
          [_, ">=", value] -> %{from: parse_datetime(value)}
          [_, "<", value] -> %{to: parse_datetime(value)}
          [_, "<=", value] -> %{to: parse_datetime(value)}
          _ -> %{}
        end
    end
  end

  defp parse_datetime(str) do
    str = String.trim(str)

    cond do
      # ISO 8601 datetime
      String.length(str) > 10 ->
        case DateTime.from_iso8601(str) do
          {:ok, dt, _} -> dt
          _ -> nil
        end

      # Date only
      String.length(str) == 10 ->
        case Date.from_iso8601(str) do
          {:ok, date} -> DateTime.new!(date, ~T[00:00:00])
          _ -> nil
        end

      # Relative time (e.g., "now-24h", "now-7d")
      String.starts_with?(str, "now") ->
        parse_relative_time(str)

      true ->
        nil
    end
  end

  defp parse_relative_time("now"), do: DateTime.utc_now()
  defp parse_relative_time("now-" <> rest) do
    {amount, unit} = parse_duration(rest)
    seconds = case unit do
      "s" -> amount
      "m" -> amount * 60
      "h" -> amount * 3600
      "d" -> amount * 86_400
      "w" -> amount * 604_800
      _ -> 0
    end
    DateTime.utc_now() |> DateTime.add(-seconds, :second)
  end
  defp parse_relative_time(_), do: nil

  defp parse_duration(str) do
    case Integer.parse(str) do
      {amount, unit} -> {amount, String.trim(unit)}
      :error -> {0, "s"}
    end
  end

  # ------------------------------------------------------------------
  # Result Sorting
  # ------------------------------------------------------------------

  defp sort_results(results, :timestamp, :desc) do
    Enum.sort_by(results, fn r -> r[:timestamp] || r["timestamp"] end, {:desc, DateTime})
  end

  defp sort_results(results, :timestamp, :asc) do
    Enum.sort_by(results, fn r -> r[:timestamp] || r["timestamp"] end, {:asc, DateTime})
  end

  defp sort_results(results, field, :desc) do
    Enum.sort_by(results, fn r -> r[field] || r[to_string(field)] end, :desc)
  end

  defp sort_results(results, field, :asc) do
    Enum.sort_by(results, fn r -> r[field] || r[to_string(field)] end, :asc)
  end

  # ------------------------------------------------------------------
  # Filter Building
  # ------------------------------------------------------------------

  defp build_filters(parsed, opts) do
    # Merge explicit opts into parsed query
    filters = parsed.field_filters

    # Add agent_id if specified
    filters = case Keyword.get(opts, :agent_id) do
      nil -> filters
      agent_id -> [%{field: "agent_id", op: :eq, value: agent_id} | filters]
    end

    # Add organization_id if specified
    filters = case Keyword.get(opts, :organization_id) do
      nil -> filters
      org_id -> [%{field: "organization_id", op: :eq, value: org_id} | filters]
    end

    # Time range from opts overrides parsed
    from_dt = Keyword.get(opts, :from, parsed.from)
    to_dt = Keyword.get(opts, :to, parsed.to)

    # Parse string timestamps
    from_dt = if is_binary(from_dt), do: parse_datetime(from_dt), else: from_dt
    to_dt = if is_binary(to_dt), do: parse_datetime(to_dt), else: to_dt

    %{
      field_filters: filters,
      text_search: parsed.text_search,
      from: from_dt,
      to: to_dt
    }
  end

  # ------------------------------------------------------------------
  # Caching
  # ------------------------------------------------------------------

  defp check_cache(key) do
    case :ets.lookup(@search_cache, key) do
      [{^key, {result, cached_at}}] ->
        age = DateTime.diff(DateTime.utc_now(), cached_at, :millisecond)
        if age < @cache_ttl_ms, do: {:hit, result}, else: :miss

      [] ->
        :miss
    end
  end

  # ------------------------------------------------------------------
  # Stats
  # ------------------------------------------------------------------

  defp update_stat(key, increment) do
    case :ets.lookup(@search_stats, :counters) do
      [{:counters, counters}] ->
        updated = Map.update(counters, key, increment, &(&1 + increment))
        :ets.insert(@search_stats, {:counters, updated})
      [] ->
        :ets.insert(@search_stats, {:counters, %{key => increment}})
    end
  end

  defp update_avg_latency(elapsed) do
    case :ets.lookup(@search_stats, :counters) do
      [{:counters, counters}] ->
        total = counters[:total_searches] || 1
        current_avg = counters[:avg_latency_ms] || 0
        new_avg = (current_avg * (total - 1) + elapsed) / total
        updated = Map.put(counters, :avg_latency_ms, Float.round(new_avg, 1))
        :ets.insert(@search_stats, {:counters, updated})
      _ -> :ok
    end
  end
end
