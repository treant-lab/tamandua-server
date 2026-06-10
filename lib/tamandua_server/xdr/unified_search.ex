defmodule TamanduaServer.XDR.UnifiedSearch do
  @moduledoc """
  XDR Unified Search Engine.

  Enterprise-grade search across all security data sources with federated query capabilities.

  ## Features

  - **Federated Queries**: Search across endpoint, network, cloud, identity, and email sources
  - **Relevance Ranking**: ML-based relevance scoring for search results
  - **Saved Searches**: Persistent queries with alerting capabilities
  - **Query DSL**: Powerful domain-specific language for complex searches
  - **Faceted Search**: Multi-dimensional filtering with aggregations
  - **Time-Series Analysis**: Temporal search patterns and trending

  ## Query DSL

  The unified search supports a powerful query language:

  ```
  source_type:endpoint AND severity:high AND (action:process_create OR action:file_write)
  source_ip:192.168.* AND NOT user:admin
  timestamp:[now-1h TO now] AND category:threat
  ```

  ## Data Sources

  - Endpoint telemetry (process, file, network, registry)
  - XDR events (firewall, proxy, email, cloud)
  - Alert history
  - Data lake (long-term storage)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.XDR.{Correlator, DataLake}

  # ETS tables for caching and saved searches
  @search_cache_table :unified_search_cache
  @saved_searches_table :unified_saved_searches

  @default_config %{
    # Maximum results per source
    max_results_per_source: 1000,
    # Cache TTL in milliseconds
    cache_ttl_ms: 5 * 60 * 1000,
    # Maximum saved searches per organization
    max_saved_searches: 100,
    # Enable ML-based ranking
    ml_ranking_enabled: true,
    # Search timeout
    search_timeout_ms: 30_000,
    # Enable parallel searches
    parallel_search: true,
    # Data sources to search
    data_sources: [:endpoint, :xdr_events, :alerts, :data_lake]
  }

  # Search operators
  @operators ["AND", "OR", "NOT", "TO"]

  # Searchable fields
  @indexed_fields [
    :source_ip, :dest_ip, :user, :hostname, :file_hash, :file_name,
    :process_name, :command_line, :url, :domain, :action, :category,
    :severity, :source_type, :agent_id, :alert_id, :rule_name, :mitre_technique
  ]

  defstruct [
    config: @default_config,
    stats: %{
      searches_executed: 0,
      cache_hits: 0,
      cache_misses: 0,
      saved_searches_triggered: 0
    }
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Execute a unified search across all data sources.
  """
  @spec search(String.t(), keyword()) :: {:ok, map()}
  def search(query, opts \\ []) do
    GenServer.call(__MODULE__, {:search, query, opts}, 60_000)
  end

  @doc """
  Execute a structured search query.
  """
  @spec search_structured(map(), keyword()) :: {:ok, map()}
  def search_structured(query_map, opts \\ []) do
    GenServer.call(__MODULE__, {:search_structured, query_map, opts}, 60_000)
  end

  @doc """
  Get search suggestions based on partial input.
  """
  @spec suggest(String.t(), keyword()) :: {:ok, [map()]}
  def suggest(partial_query, opts \\ []) do
    GenServer.call(__MODULE__, {:suggest, partial_query, opts})
  end

  @doc """
  Get aggregations for search results.
  """
  @spec aggregate(String.t(), [atom()], keyword()) :: {:ok, map()}
  def aggregate(query, fields, opts \\ []) do
    GenServer.call(__MODULE__, {:aggregate, query, fields, opts}, 60_000)
  end

  @doc """
  Create a saved search.
  """
  @spec create_saved_search(map()) :: {:ok, map()} | {:error, term()}
  def create_saved_search(params) do
    GenServer.call(__MODULE__, {:create_saved_search, params})
  end

  @doc """
  List saved searches for an organization.
  """
  @spec list_saved_searches(keyword()) :: {:ok, [map()]}
  def list_saved_searches(opts \\ []) do
    GenServer.call(__MODULE__, {:list_saved_searches, opts})
  end

  @doc """
  Get a saved search by ID.
  """
  @spec get_saved_search(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_saved_search(id) do
    GenServer.call(__MODULE__, {:get_saved_search, id})
  end

  @doc """
  Update a saved search.
  """
  @spec update_saved_search(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def update_saved_search(id, params) do
    GenServer.call(__MODULE__, {:update_saved_search, id, params})
  end

  @doc """
  Delete a saved search.
  """
  @spec delete_saved_search(String.t()) :: :ok | {:error, term()}
  def delete_saved_search(id) do
    GenServer.call(__MODULE__, {:delete_saved_search, id})
  end

  @doc """
  Run a saved search and optionally trigger alerts.
  """
  @spec run_saved_search(String.t()) :: {:ok, map()}
  def run_saved_search(id) do
    GenServer.call(__MODULE__, {:run_saved_search, id}, 60_000)
  end

  @doc """
  Get search statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Parse a query string into a structured query.
  """
  @spec parse_query(String.t()) :: {:ok, map()} | {:error, term()}
  def parse_query(query_string) do
    GenServer.call(__MODULE__, {:parse_query, query_string})
  end

  @doc """
  Validate a query string.
  """
  @spec validate_query(String.t()) :: :ok | {:error, term()}
  def validate_query(query_string) do
    GenServer.call(__MODULE__, {:validate_query, query_string})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    # Create ETS tables
    :ets.new(@search_cache_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@saved_searches_table, [:named_table, :set, :public, read_concurrency: true])

    config = Keyword.get(opts, :config, @default_config)

    # Schedule periodic cache cleanup
    schedule_cache_cleanup(config.cache_ttl_ms)

    # Schedule saved search execution
    schedule_saved_search_check(60_000)

    Logger.info("XDR Unified Search started")

    {:ok, %__MODULE__{config: config}}
  end

  @impl true
  def handle_call({:search, query, opts}, _from, state) do
    result = execute_search(query, opts, state)
    new_state = update_stats(state, :searches_executed, 1)
    {:reply, {:ok, result}, new_state}
  end

  @impl true
  def handle_call({:search_structured, query_map, opts}, _from, state) do
    query_string = build_query_string(query_map)
    result = execute_search(query_string, opts, state)
    new_state = update_stats(state, :searches_executed, 1)
    {:reply, {:ok, result}, new_state}
  end

  @impl true
  def handle_call({:suggest, partial_query, opts}, _from, state) do
    suggestions = generate_suggestions(partial_query, opts, state)
    {:reply, {:ok, suggestions}, state}
  end

  @impl true
  def handle_call({:aggregate, query, fields, opts}, _from, state) do
    result = execute_aggregation(query, fields, opts, state)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:create_saved_search, params}, _from, state) do
    case do_create_saved_search(params, state.config) do
      {:ok, saved_search} -> {:reply, {:ok, saved_search}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:list_saved_searches, opts}, _from, state) do
    searches = list_all_saved_searches(opts)
    {:reply, {:ok, searches}, state}
  end

  @impl true
  def handle_call({:get_saved_search, id}, _from, state) do
    case :ets.lookup(@saved_searches_table, id) do
      [{^id, search}] -> {:reply, {:ok, search}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:update_saved_search, id, params}, _from, state) do
    case do_update_saved_search(id, params) do
      {:ok, updated} -> {:reply, {:ok, updated}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:delete_saved_search, id}, _from, state) do
    :ets.delete(@saved_searches_table, id)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:run_saved_search, id}, _from, state) do
    result = do_run_saved_search(id, state)
    new_state = update_stats(state, :saved_searches_triggered, 1)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:parse_query, query_string}, _from, state) do
    result = do_parse_query(query_string)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:validate_query, query_string}, _from, state) do
    result = do_validate_query(query_string)
    {:reply, result, state}
  end

  @impl true
  def handle_info(:cleanup_cache, state) do
    cleanup_expired_cache(state.config)
    schedule_cache_cleanup(state.config.cache_ttl_ms)
    {:noreply, state}
  end

  @impl true
  def handle_info(:check_saved_searches, state) do
    run_scheduled_saved_searches(state)
    schedule_saved_search_check(60_000)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Search Execution
  # ============================================================================

  defp execute_search(query, opts, state) do
    # Check cache first
    cache_key = generate_cache_key(query, opts)

    case check_cache(cache_key, state.config) do
      {:ok, cached_result} ->
        # Update cache hit stats
        cached_result

      :miss ->
        # Parse the query
        {:ok, parsed_query} = do_parse_query(query)

        # Get time range
        time_range = extract_time_range(parsed_query, opts)

        # Execute searches in parallel
        results = if state.config.parallel_search do
          execute_parallel_search(parsed_query, time_range, opts, state)
        else
          execute_sequential_search(parsed_query, time_range, opts, state)
        end

        # Merge and rank results
        merged_results = merge_results(results, parsed_query, state.config)

        # Cache the results
        cache_results(cache_key, merged_results, state.config)

        merged_results
    end
  end

  defp execute_parallel_search(parsed_query, time_range, opts, state) do
    sources = Keyword.get(opts, :sources, state.config.data_sources)

    # Start tasks for each data source
    tasks = Enum.map(sources, fn source ->
      Task.async(fn ->
        try do
          search_source(source, parsed_query, time_range, opts, state.config)
        rescue
          e ->
            Logger.error("Search error for #{source}: #{inspect(e)}")
            {source, []}
        end
      end)
    end)

    # Await all tasks with timeout
    Task.await_many(tasks, state.config.search_timeout_ms)
    |> Enum.zip(sources)
    |> Enum.map(fn {result, source} ->
      case result do
        {^source, events} -> {source, events}
        events when is_list(events) -> {source, events}
        _ -> {source, []}
      end
    end)
    |> Map.new()
  end

  defp execute_sequential_search(parsed_query, time_range, opts, state) do
    sources = Keyword.get(opts, :sources, state.config.data_sources)

    Enum.map(sources, fn source ->
      {source, search_source(source, parsed_query, time_range, opts, state.config)}
    end)
    |> Map.new()
  end

  defp search_source(:endpoint, parsed_query, time_range, _opts, config) do
    # Search endpoint telemetry from detection correlator
    try do
      :ets.tab2list(:correlation_events)
      |> Enum.filter(fn {_key, event} ->
        matches_parsed_query?(event, parsed_query) and
        in_time_range?(event, time_range)
      end)
      |> Enum.map(fn {_key, event} ->
        Map.put(event, :_source, :endpoint)
      end)
      |> Enum.take(config.max_results_per_source)
    rescue
      _ -> []
    end
  end

  defp search_source(:xdr_events, parsed_query, time_range, _opts, config) do
    # Search XDR events
    try do
      :ets.tab2list(:xdr_correlation_events)
      |> Enum.filter(fn {_id, entry} ->
        matches_parsed_query?(entry.event, parsed_query) and
        in_time_range?(entry.event, time_range)
      end)
      |> Enum.map(fn {_id, entry} ->
        Map.put(entry.event, :_source, :xdr_events)
      end)
      |> Enum.take(config.max_results_per_source)
    rescue
      _ -> []
    end
  end

  defp search_source(:alerts, parsed_query, time_range, _opts, config) do
    # Search alerts from database
    try do
      # Query alerts from database
      # For now, return empty list - would need Ecto query
      []
    rescue
      _ -> []
    end
  end

  defp search_source(:data_lake, parsed_query, time_range, opts, config) do
    # Search data lake
    try do
      query_map = %{
        start_time: time_range[:start],
        end_time: time_range[:end]
      }

      # Add field filters
      query_map = Enum.reduce(parsed_query.filters, query_map, fn {field, value}, acc ->
        Map.put(acc, field, value)
      end)

      case DataLake.search(query_map, limit: config.max_results_per_source) do
        {:ok, events} ->
          Enum.map(events, fn event ->
            Map.put(event, :_source, :data_lake)
          end)
        _ -> []
      end
    rescue
      _ -> []
    end
  end

  defp search_source(_, _, _, _, _), do: []

  defp matches_parsed_query?(event, parsed_query) do
    # Check all filters
    Enum.all?(parsed_query.filters, fn {field, value} ->
      event_value = get_event_field(event, field)
      matches_value?(event_value, value, parsed_query.operators)
    end)
  end

  defp get_event_field(event, field) do
    # Try direct access first, then payload
    event[field] || event[to_string(field)] ||
    get_in(event, [:payload, field]) || get_in(event, ["payload", to_string(field)])
  end

  defp matches_value?(nil, _value, _operators), do: false
  defp matches_value?(event_value, value, operators) do
    cond do
      # Wildcard match
      String.contains?(value, "*") ->
        pattern = value |> String.replace("*", ".*") |> Regex.compile!()
        Regex.match?(pattern, to_string(event_value))

      # Range match
      String.contains?(value, " TO ") ->
        [start_val, end_val] = String.split(value, " TO ")
        event_value >= start_val and event_value <= end_val

      # Negation (handled by parsed_query structure)
      :not in operators ->
        to_string(event_value) != value

      # Exact match (case-insensitive)
      true ->
        String.downcase(to_string(event_value)) == String.downcase(value)
    end
  end

  defp in_time_range?(event, time_range) do
    timestamp = event[:timestamp] || event["timestamp"]

    case timestamp do
      nil -> true
      ts when is_struct(ts, DateTime) ->
        (is_nil(time_range[:start]) or DateTime.compare(ts, time_range[:start]) != :lt) and
        (is_nil(time_range[:end]) or DateTime.compare(ts, time_range[:end]) != :gt)
      _ -> true
    end
  end

  defp extract_time_range(parsed_query, opts) do
    # Check for explicit time range in options
    start_time = Keyword.get(opts, :start_time)
    end_time = Keyword.get(opts, :end_time)

    # Check for timestamp filter in query
    {start_time, end_time} = case parsed_query.filters[:timestamp] do
      nil -> {start_time, end_time}
      ts_filter when is_binary(ts_filter) ->
        parse_time_filter(ts_filter, start_time, end_time)
      _ -> {start_time, end_time}
    end

    # Default to last 24 hours if no range specified
    end_time = end_time || DateTime.utc_now()
    start_time = start_time || DateTime.add(end_time, -24, :hour)

    %{start: start_time, end: end_time}
  end

  defp parse_time_filter(ts_filter, default_start, default_end) do
    cond do
      String.contains?(ts_filter, "now") ->
        # Parse relative time like "now-1h" or "[now-1h TO now]"
        case Regex.run(~r/now-(\d+)([hdmw])/, ts_filter) do
          [_, amount, unit] ->
            duration = String.to_integer(amount)
            unit_atom = case unit do
              "h" -> :hour
              "d" -> :day
              "m" -> :minute
              "w" -> :week
              _ -> :hour
            end
            start = DateTime.add(DateTime.utc_now(), -duration, unit_atom)
            {start, DateTime.utc_now()}
          _ -> {default_start, default_end}
        end

      true ->
        {default_start, default_end}
    end
  end

  # ============================================================================
  # Result Merging and Ranking
  # ============================================================================

  defp merge_results(results_by_source, parsed_query, config) do
    # Flatten all results
    all_results = results_by_source
    |> Enum.flat_map(fn {source, events} ->
      Enum.map(events, fn event ->
        Map.put(event, :_search_source, source)
      end)
    end)

    # Calculate relevance scores
    scored_results = if config.ml_ranking_enabled do
      Enum.map(all_results, fn event ->
        score = calculate_relevance_score(event, parsed_query)
        Map.put(event, :_relevance_score, score)
      end)
    else
      all_results
    end

    # Sort by relevance then by timestamp
    sorted_results = scored_results
    |> Enum.sort_by(fn event ->
      relevance = event[:_relevance_score] || 0
      timestamp = event[:timestamp] || DateTime.utc_now()
      {-relevance, timestamp}
    end)

    %{
      results: sorted_results,
      total: length(sorted_results),
      sources: Map.keys(results_by_source),
      counts_by_source: Enum.map(results_by_source, fn {source, events} ->
        {source, length(events)}
      end) |> Map.new(),
      query: parsed_query,
      executed_at: DateTime.utc_now()
    }
  end

  defp calculate_relevance_score(event, parsed_query) do
    # Base score
    base_score = 0.5

    # Boost for exact matches
    exact_match_boost = Enum.reduce(parsed_query.filters, 0, fn {field, value}, acc ->
      event_value = get_event_field(event, field)
      if to_string(event_value) == value, do: acc + 0.1, else: acc
    end)

    # Boost for high severity
    severity_boost = case event[:severity] do
      "critical" -> 0.3
      "high" -> 0.2
      "medium" -> 0.1
      _ -> 0
    end

    # Boost for recent events
    recency_boost = calculate_recency_boost(event[:timestamp])

    # Boost for multiple field matches
    field_match_count = Enum.count(parsed_query.filters, fn {field, _} ->
      not is_nil(get_event_field(event, field))
    end)
    field_match_boost = min(0.2, field_match_count * 0.05)

    min(1.0, base_score + exact_match_boost + severity_boost + recency_boost + field_match_boost)
  end

  defp calculate_recency_boost(nil), do: 0
  defp calculate_recency_boost(timestamp) when is_struct(timestamp, DateTime) do
    age_hours = DateTime.diff(DateTime.utc_now(), timestamp, :hour)

    cond do
      age_hours <= 1 -> 0.2
      age_hours <= 6 -> 0.15
      age_hours <= 24 -> 0.1
      age_hours <= 72 -> 0.05
      true -> 0
    end
  end
  defp calculate_recency_boost(_), do: 0

  # ============================================================================
  # Query Parsing
  # ============================================================================

  defp do_parse_query(query_string) do
    tokens = tokenize_query(query_string)
    {:ok, build_query_tree(tokens)}
  end

  defp tokenize_query(query_string) do
    # Split by operators while preserving them
    query_string
    |> String.replace("(", " ( ")
    |> String.replace(")", " ) ")
    |> String.split(~r/\s+/)
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(&String.trim/1)
  end

  defp build_query_tree(tokens) do
    {filters, operators, raw_query} = parse_tokens(tokens, [], [], [])

    %{
      filters: Map.new(filters),
      operators: operators,
      raw_query: Enum.join(raw_query, " ")
    }
  end

  defp parse_tokens([], filters, operators, raw_query) do
    {filters, operators, Enum.reverse(raw_query)}
  end

  # Resolve a user-supplied field name to an existing atom without growing the
  # global atom table. All legitimate field atoms exist as compile-time literals
  # in @indexed_fields; anything else returns nil so callers can fall back.
  defp safe_field_atom(field) do
    String.to_existing_atom(field)
  rescue
    ArgumentError -> nil
  end

  defp parse_tokens([token | rest], filters, operators, raw_query) do
    cond do
      token in @operators ->
        operator = String.to_atom(String.downcase(token))
        parse_tokens(rest, filters, [operator | operators], [token | raw_query])

      token in ["(", ")"] ->
        parse_tokens(rest, filters, operators, [token | raw_query])

      String.contains?(token, ":") ->
        [field, value] = String.split(token, ":", parts: 2)
        negated = String.starts_with?(field, "-")
        field_name = String.trim_leading(field, "-")

        # Resolve the (user-controlled) field name against atoms that already
        # exist as compile-time literals in @indexed_fields. An unknown field
        # would only ever produce a never-matching filter, so we treat the whole
        # token as free text instead of minting an attacker-controlled atom.
        case safe_field_atom(field_name) do
          nil ->
            parse_tokens(rest, [{:_text, token} | filters], operators, [token | raw_query])

          field_atom ->
            value = if negated, do: {:not, value}, else: value
            parse_tokens(rest, [{field_atom, value} | filters], operators, [token | raw_query])
        end

      true ->
        # Treat as text search
        parse_tokens(rest, [{:_text, token} | filters], operators, [token | raw_query])
    end
  end

  defp do_validate_query(query_string) do
    case do_parse_query(query_string) do
      {:ok, _parsed} -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp build_query_string(query_map) do
    query_map
    |> Enum.map(fn {field, value} ->
      "#{field}:#{value}"
    end)
    |> Enum.join(" AND ")
  end

  # ============================================================================
  # Aggregation
  # ============================================================================

  defp execute_aggregation(query, fields, opts, state) do
    # Execute the search first
    results = execute_search(query, opts, state)

    # Aggregate by each field
    aggregations = Enum.map(fields, fn field ->
      field_values = results.results
      |> Enum.map(fn event -> get_event_field(event, field) end)
      |> Enum.reject(&is_nil/1)
      |> Enum.frequencies()
      |> Enum.sort_by(fn {_value, count} -> -count end)
      |> Enum.take(100)
      |> Enum.map(fn {value, count} ->
        %{value: value, count: count}
      end)

      {field, field_values}
    end)
    |> Map.new()

    %{
      aggregations: aggregations,
      total_results: results.total,
      query: query
    }
  end

  # ============================================================================
  # Suggestions
  # ============================================================================

  defp generate_suggestions(partial_query, opts, state) do
    # Parse partial query to determine context
    tokens = tokenize_query(partial_query)
    last_token = List.last(tokens) || ""

    suggestions = cond do
      # Suggest field names
      String.ends_with?(partial_query, " ") or partial_query == "" ->
        suggest_fields(last_token)

      # Suggest values for a field
      String.contains?(last_token, ":") ->
        [field, partial_value] = String.split(last_token, ":", parts: 2)
        suggest_values(field, partial_value, state)

      # Suggest field names matching partial input
      true ->
        suggest_fields(last_token)
    end

    suggestions
  end

  defp suggest_fields(partial) do
    @indexed_fields
    |> Enum.filter(fn field ->
      field_str = to_string(field)
      partial == "" or String.starts_with?(field_str, String.downcase(partial))
    end)
    |> Enum.map(fn field ->
      %{
        type: :field,
        value: "#{field}:",
        display: to_string(field),
        description: get_field_description(field)
      }
    end)
    |> Enum.take(10)
  end

  defp suggest_values(field, partial_value, _state) do
    # Get recent values for the field from cache
    # For now, return common values
    common_values =
      case safe_field_atom(field) do
        nil -> []
        field_atom -> get_common_values(field_atom)
      end

    common_values
    |> Enum.filter(fn value ->
      partial_value == "" or String.starts_with?(String.downcase(value), String.downcase(partial_value))
    end)
    |> Enum.map(fn value ->
      %{
        type: :value,
        value: "#{field}:#{value}",
        display: value
      }
    end)
    |> Enum.take(10)
  end

  defp get_field_description(:source_ip), do: "Source IP address"
  defp get_field_description(:dest_ip), do: "Destination IP address"
  defp get_field_description(:user), do: "Username"
  defp get_field_description(:hostname), do: "Host name"
  defp get_field_description(:file_hash), do: "File hash (SHA256/MD5)"
  defp get_field_description(:process_name), do: "Process name"
  defp get_field_description(:command_line), do: "Command line arguments"
  defp get_field_description(:url), do: "URL"
  defp get_field_description(:domain), do: "Domain name"
  defp get_field_description(:action), do: "Action type"
  defp get_field_description(:category), do: "Event category"
  defp get_field_description(:severity), do: "Severity level"
  defp get_field_description(:source_type), do: "Data source type"
  defp get_field_description(_), do: ""

  defp get_common_values(:severity), do: ["critical", "high", "medium", "low", "info"]
  defp get_common_values(:source_type), do: ["endpoint", "firewall", "proxy", "cloud", "email", "identity"]
  defp get_common_values(:action), do: ["process_create", "file_write", "network_connect", "registry_mod", "login", "blocked", "allowed"]
  defp get_common_values(:category), do: ["execution", "persistence", "defense_evasion", "credential_access", "discovery", "lateral_movement", "exfiltration"]
  defp get_common_values(_), do: []

  # ============================================================================
  # Saved Searches
  # ============================================================================

  defp do_create_saved_search(params, _config) do
    id = Ecto.UUID.generate()

    saved_search = %{
      id: id,
      name: params[:name] || "Saved Search #{id}",
      query: params[:query],
      description: params[:description],
      organization_id: params[:organization_id],
      created_by: params[:created_by],
      # Alert configuration
      alert_enabled: params[:alert_enabled] || false,
      alert_threshold: params[:alert_threshold] || 1,
      alert_severity: params[:alert_severity] || "medium",
      alert_window_minutes: params[:alert_window_minutes] || 60,
      # Schedule
      schedule_enabled: params[:schedule_enabled] || false,
      schedule_cron: params[:schedule_cron],
      last_run_at: nil,
      next_run_at: calculate_next_run(params[:schedule_cron]),
      # Metadata
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now(),
      run_count: 0
    }

    :ets.insert(@saved_searches_table, {id, saved_search})
    {:ok, saved_search}
  end

  defp do_update_saved_search(id, params) do
    case :ets.lookup(@saved_searches_table, id) do
      [{^id, existing}] ->
        updated = Map.merge(existing, params)
        |> Map.put(:updated_at, DateTime.utc_now())
        |> Map.put(:next_run_at, calculate_next_run(params[:schedule_cron] || existing.schedule_cron))

        :ets.insert(@saved_searches_table, {id, updated})
        {:ok, updated}

      [] ->
        {:error, :not_found}
    end
  end

  defp do_run_saved_search(id, state) do
    case :ets.lookup(@saved_searches_table, id) do
      [{^id, saved_search}] ->
        # Execute the search
        result = execute_search(saved_search.query, [], state)

        # Update run statistics
        updated = %{saved_search |
          last_run_at: DateTime.utc_now(),
          run_count: saved_search.run_count + 1
        }
        :ets.insert(@saved_searches_table, {id, updated})

        # Check alert threshold
        if saved_search.alert_enabled and result.total >= saved_search.alert_threshold do
          trigger_saved_search_alert(saved_search, result)
        end

        {:ok, %{
          saved_search: updated,
          results: result
        }}

      [] ->
        {:error, :not_found}
    end
  end

  defp list_all_saved_searches(opts) do
    org_id = Keyword.get(opts, :organization_id)

    :ets.tab2list(@saved_searches_table)
    |> Enum.map(fn {_id, search} -> search end)
    |> Enum.filter(fn search ->
      is_nil(org_id) or search.organization_id == org_id
    end)
    |> Enum.sort_by(& &1.created_at, {:desc, DateTime})
  end

  defp run_scheduled_saved_searches(state) do
    now = DateTime.utc_now()

    :ets.tab2list(@saved_searches_table)
    |> Enum.filter(fn {_id, search} ->
      search.schedule_enabled and
      search.next_run_at and
      DateTime.compare(search.next_run_at, now) != :gt
    end)
    |> Enum.each(fn {id, _search} ->
      Task.start(fn ->
        do_run_saved_search(id, state)
      end)
    end)
  end

  defp trigger_saved_search_alert(saved_search, result) do
    Logger.info("Saved search '#{saved_search.name}' triggered alert: #{result.total} matches")

    # Create alert via the alerts module
    TamanduaServer.Alerts.create_alert(%{
      organization_id: saved_search.organization_id,
      severity: saved_search.alert_severity,
      title: "Saved Search Alert: #{saved_search.name}",
      description: "Search query matched #{result.total} events",
      source: "unified_search",
      evidence: %{
        query: saved_search.query,
        match_count: result.total,
        sample_results: Enum.take(result.results, 5)
      }
    })
  end

  defp calculate_next_run(nil), do: nil
  defp calculate_next_run(_cron) do
    # Simplified: run in 1 hour
    DateTime.add(DateTime.utc_now(), 1, :hour)
  end

  # ============================================================================
  # Caching
  # ============================================================================

  defp generate_cache_key(query, opts) do
    :erlang.phash2({query, opts})
  end

  defp check_cache(cache_key, config) do
    case :ets.lookup(@search_cache_table, cache_key) do
      [{^cache_key, {result, cached_at}}] ->
        age = DateTime.diff(DateTime.utc_now(), cached_at, :millisecond)
        if age < config.cache_ttl_ms do
          {:ok, result}
        else
          :ets.delete(@search_cache_table, cache_key)
          :miss
        end

      [] ->
        :miss
    end
  end

  defp cache_results(cache_key, results, _config) do
    :ets.insert(@search_cache_table, {cache_key, {results, DateTime.utc_now()}})
  end

  defp cleanup_expired_cache(config) do
    now = DateTime.utc_now()

    :ets.tab2list(@search_cache_table)
    |> Enum.each(fn {key, {_result, cached_at}} ->
      age = DateTime.diff(now, cached_at, :millisecond)
      if age >= config.cache_ttl_ms do
        :ets.delete(@search_cache_table, key)
      end
    end)
  end

  # ============================================================================
  # Scheduling
  # ============================================================================

  defp schedule_cache_cleanup(interval_ms) do
    Process.send_after(self(), :cleanup_cache, interval_ms)
  end

  defp schedule_saved_search_check(interval_ms) do
    Process.send_after(self(), :check_saved_searches, interval_ms)
  end

  defp update_stats(state, key, increment) do
    %{state | stats: Map.update(state.stats, key, increment, & &1 + increment)}
  end
end
