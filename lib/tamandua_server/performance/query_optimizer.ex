defmodule TamanduaServer.Performance.QueryOptimizer do
  @moduledoc """
  Query optimization utilities for enterprise-scale deployments.

  Provides:
  - Query caching with TTL
  - Batch operations
  - Read replica routing
  - Query analysis and optimization hints
  """

  require Logger
  import Ecto.Query
  alias TamanduaServer.Repo

  @cache_ttl :timer.seconds(30)
  @batch_size 1000

  # ============================================================================
  # Query Caching
  # ============================================================================

  @doc """
  Execute a cached query. Returns cached result if available and not expired.
  """
  @spec cached_query(atom(), keyword(), function()) :: term()
  def cached_query(cache_key, opts \\ [], query_fn) do
    ttl = Keyword.get(opts, :ttl, @cache_ttl)
    force_refresh = Keyword.get(opts, :force_refresh, false)

    unless force_refresh do
      case TamanduaServer.Cache.get(cache_key) do
        nil -> execute_and_cache(cache_key, ttl, query_fn)
        result -> result
      end
    else
      execute_and_cache(cache_key, ttl, query_fn)
    end
  end

  defp execute_and_cache(cache_key, ttl, query_fn) do
    result = query_fn.()
    TamanduaServer.Cache.put(cache_key, result, ttl: ttl)
    result
  end

  @doc """
  Invalidate cached query results.
  """
  @spec invalidate_cache(atom() | [atom()]) :: :ok
  def invalidate_cache(keys) when is_list(keys) do
    Enum.each(keys, &TamanduaServer.Cache.delete/1)
    :ok
  end

  def invalidate_cache(key), do: invalidate_cache([key])

  # ============================================================================
  # Batch Operations
  # ============================================================================

  @doc """
  Insert records in batches to avoid memory pressure.
  """
  @spec batch_insert(module(), [map()], keyword()) :: {:ok, integer()} | {:error, term()}
  def batch_insert(schema, records, opts \\ []) do
    batch_size = Keyword.get(opts, :batch_size, @batch_size)
    on_conflict = Keyword.get(opts, :on_conflict, :nothing)

    records
    |> Enum.chunk_every(batch_size)
    |> Enum.reduce({:ok, 0}, fn batch, {:ok, total} ->
      case Repo.insert_all(schema, batch, on_conflict: on_conflict) do
        {count, _} -> {:ok, total + count}
        error -> error
      end
    end)
  end

  @doc """
  Update records in batches.
  """
  @spec batch_update(Ecto.Query.t(), [keyword()], keyword()) :: {:ok, integer()} | {:error, term()}
  def batch_update(query, updates, opts \\ []) do
    batch_size = Keyword.get(opts, :batch_size, @batch_size)

    # Get IDs to update
    ids = query
    |> select([r], r.id)
    |> Repo.all()

    ids
    |> Enum.chunk_every(batch_size)
    |> Enum.reduce({:ok, 0}, fn batch_ids, {:ok, total} ->
      {count, _} = query
      |> where([r], r.id in ^batch_ids)
      |> Repo.update_all(set: updates)

      {:ok, total + count}
    end)
  end

  @doc """
  Delete records in batches to avoid lock contention.
  """
  @spec batch_delete(Ecto.Query.t(), keyword()) :: {:ok, integer()} | {:error, term()}
  def batch_delete(query, opts \\ []) do
    batch_size = Keyword.get(opts, :batch_size, @batch_size)

    delete_batch(query, batch_size, 0)
  end

  defp delete_batch(query, batch_size, total_deleted) do
    {count, _} = query
    |> limit(^batch_size)
    |> Repo.delete_all()

    if count > 0 do
      delete_batch(query, batch_size, total_deleted + count)
    else
      {:ok, total_deleted}
    end
  end

  # ============================================================================
  # Read Replica Routing
  # ============================================================================

  @doc """
  Execute a read query on a replica (if configured).
  """
  @spec read_replica(function()) :: term()
  def read_replica(query_fn) do
    replica_repo = Application.get_env(:tamandua_server, :read_replica_repo)

    if replica_repo do
      # Use replica for read queries
      query_fn.()
      |> case do
        query when is_struct(query, Ecto.Query) ->
          replica_repo.all(query)
        result ->
          result
      end
    else
      # Fall back to primary
      query_fn.()
    end
  end

  # ============================================================================
  # Query Analysis
  # ============================================================================

  @doc """
  Analyze a query and return optimization hints.
  """
  @spec analyze_query(Ecto.Query.t()) :: {:ok, map()} | {:error, term()}
  def analyze_query(query) do
    {sql, params} = Ecto.Adapters.SQL.to_sql(:all, Repo, query)

    case Repo.query("EXPLAIN (ANALYZE, FORMAT JSON) #{sql}", params) do
      {:ok, %{rows: [[json]]}} ->
        plan = Jason.decode!(json)
        {:ok, analyze_plan(plan)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp analyze_plan(plan) when is_list(plan) do
    plan = List.first(plan)["Plan"]

    %{
      total_cost: plan["Total Cost"],
      actual_time_ms: plan["Actual Total Time"],
      rows_returned: plan["Actual Rows"],
      plan_rows: plan["Plan Rows"],
      node_type: plan["Node Type"],
      warnings: extract_warnings(plan),
      recommendations: generate_recommendations(plan)
    }
  end

  defp extract_warnings(plan) do
    warnings = []

    # Check for sequential scans on large tables
    warnings = if plan["Node Type"] == "Seq Scan" and plan["Actual Rows"] > 10000 do
      ["Sequential scan on large table - consider adding index" | warnings]
    else
      warnings
    end

    # Check for row estimate accuracy
    if plan["Plan Rows"] > 0 do
      estimate_ratio = plan["Actual Rows"] / plan["Plan Rows"]
      warnings = if estimate_ratio > 10 or estimate_ratio < 0.1 do
        ["Row estimate significantly off - consider running ANALYZE" | warnings]
      else
        warnings
      end
    end

    warnings
  end

  defp generate_recommendations(plan) do
    recommendations = []

    recommendations = if plan["Node Type"] == "Seq Scan" do
      ["Consider creating an index on the filtered columns" | recommendations]
    else
      recommendations
    end

    recommendations = if plan["Actual Total Time"] > 1000 do
      ["Query takes >1s - consider query optimization or caching" | recommendations]
    else
      recommendations
    end

    recommendations
  end

  # ============================================================================
  # Connection Pool Management
  # ============================================================================

  @doc """
  Execute a query with a specific timeout.
  """
  @spec with_timeout(integer(), function()) :: term()
  def with_timeout(timeout_ms, query_fn) do
    Repo.transaction(fn ->
      Repo.query!("SET LOCAL statement_timeout = '#{timeout_ms}ms'")
      query_fn.()
    end)
  end

  @doc """
  Get current connection pool stats.
  """
  @spec pool_stats() :: map()
  def pool_stats do
    case DBConnection.get_info(Repo) do
      %{pool_size: size, pool: _pool} ->
        %{
          pool_size: size,
          # Would need to query DBConnection for more details
          active_connections: 0,
          idle_connections: 0
        }

      _ ->
        %{pool_size: 0}
    end
  rescue
    _ -> %{pool_size: 0}
  end

  # ============================================================================
  # Streaming Results
  # ============================================================================

  @doc """
  Stream large result sets to avoid memory issues.
  """
  @spec stream_results(Ecto.Query.t(), keyword()) :: Enum.t()
  def stream_results(query, opts \\ []) do
    max_rows = Keyword.get(opts, :max_rows, 500)

    Repo.transaction(fn ->
      query
      |> Repo.stream(max_rows: max_rows)
      |> Stream.each(fn row ->
        # Process each row
        row
      end)
      |> Enum.to_list()
    end)
  end

  @doc """
  Process large datasets with cursor-based pagination.
  """
  @spec cursor_iterate(Ecto.Query.t(), atom(), integer(), function()) :: :ok
  def cursor_iterate(base_query, cursor_field, batch_size, process_fn) do
    do_cursor_iterate(base_query, cursor_field, batch_size, process_fn, nil)
  end

  defp do_cursor_iterate(base_query, cursor_field, batch_size, process_fn, last_cursor) do
    import Ecto.Query

    query = base_query
    |> order_by([r], asc: field(r, ^cursor_field))
    |> limit(^batch_size)

    query = if last_cursor do
      where(query, [r], field(r, ^cursor_field) > ^last_cursor)
    else
      query
    end

    results = Repo.all(query)

    if length(results) > 0 do
      process_fn.(results)

      last_record = List.last(results)
      last_cursor = Map.get(last_record, cursor_field)

      if length(results) == batch_size do
        do_cursor_iterate(base_query, cursor_field, batch_size, process_fn, last_cursor)
      else
        :ok
      end
    else
      :ok
    end
  end
end
