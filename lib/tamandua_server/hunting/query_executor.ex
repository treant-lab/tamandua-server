defmodule TamanduaServer.Hunting.QueryExecutor do
  @moduledoc """
  Executes compiled TQL queries with support for:

  - Streaming results for large datasets
  - Query timeout and resource limits
  - Aggregation processing
  - Result projection and transformation
  - Pagination support
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Hunting.{QueryCompiler, QueryLanguage}
  alias TamanduaServer.Agents

  @default_timeout 30_000
  @max_timeout 300_000
  @default_page_size 100
  @max_page_size 10_000

  @type execution_options :: %{
    optional(:timeout) => non_neg_integer(),
    optional(:page) => non_neg_integer(),
    optional(:page_size) => non_neg_integer(),
    optional(:stream) => boolean(),
    optional(:organization_id) => String.t() | nil
  }

  @type execution_result :: %{
    data: [map()],
    meta: %{
      total: non_neg_integer(),
      page: non_neg_integer(),
      page_size: non_neg_integer(),
      execution_time_ms: non_neg_integer(),
      query: String.t(),
      has_more: boolean()
    }
  }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Execute a TQL query string and return results.

  ## Options

  - `:timeout` - Query timeout in milliseconds (default: 30000, max: 300000)
  - `:page` - Page number for pagination (1-indexed, default: 1)
  - `:page_size` - Results per page (default: 100, max: 10000)
  - `:stream` - Return a stream instead of list (default: false)
  - `:organization_id` - Filter by organization (multi-tenant)

  ## Examples

      iex> execute("events | where event_type == \"process\" | limit 10")
      {:ok, %{data: [...], meta: %{total: 10, ...}}}

      iex> execute("events | invalid", %{timeout: 5000})
      {:error, "Parse error: ..."}
  """
  @spec execute(String.t(), execution_options()) :: {:ok, execution_result()} | {:error, String.t()}
  def execute(query_string, opts \\ %{}) do
    start_time = System.monotonic_time(:millisecond)
    timeout = min(opts[:timeout] || @default_timeout, @max_timeout)

    task = Task.async(fn ->
      do_execute(query_string, opts)
    end)

    case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} ->
        execution_time = System.monotonic_time(:millisecond) - start_time
        enhance_result(result, query_string, execution_time, opts)

      nil ->
        {:error, "Query timeout after #{timeout}ms"}

      {:exit, reason} ->
        {:error, "Query execution failed: #{inspect(reason)}"}
    end
  end

  @doc """
  Execute a TQL query and stream results.

  Returns a Stream that yields results in batches. Useful for large datasets.

  ## Examples

      iex> stream("events | where timestamp > ago(24h)")
      #Stream<[...]>
  """
  @spec stream(String.t(), execution_options()) :: {:ok, Enumerable.t()} | {:error, String.t()}
  def stream(query_string, opts \\ %{}) do
    case QueryCompiler.compile(query_string) do
      {:ok, compiled} ->
        batch_size = opts[:page_size] || @default_page_size

        stream = Stream.resource(
          fn -> 0 end,
          fn offset ->
            results = execute_batch(compiled, offset, batch_size, opts)

            if results == [] do
              {:halt, offset}
            else
              {results, offset + length(results)}
            end
          end,
          fn _ -> :ok end
        )

        {:ok, stream}

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Execute a query and return aggregated results.

  Handles the summarize operator with grouping and aggregation functions.

  ## Examples

      iex> aggregate("events | where timestamp > ago(24h) | summarize count() by event_type")
      {:ok, %{data: [%{event_type: "process", count_: 150}, ...], ...}}
  """
  @spec aggregate(String.t(), execution_options()) :: {:ok, execution_result()} | {:error, String.t()}
  def aggregate(query_string, opts \\ %{}) do
    execute(query_string, opts)
  end

  @doc """
  Validate a TQL query without executing it.

  ## Examples

      iex> validate("events | where event_type == \"process\"")
      :ok

      iex> validate("events | invalid")
      {:error, "Unknown operator: invalid"}
  """
  @spec validate(String.t()) :: :ok | {:error, String.t()}
  def validate(query_string) do
    case QueryCompiler.compile(query_string) do
      {:ok, _} -> :ok
      {:error, msg} -> {:error, msg}
    end
  end

  @doc """
  Get query statistics without full execution.

  Returns estimated row count and execution plan.
  """
  @spec explain(String.t()) :: {:ok, map()} | {:error, String.t()}
  def explain(query_string) do
    case QueryCompiler.compile(query_string) do
      {:ok, compiled} ->
        # Use EXPLAIN to get query plan
        query_sql = compiled.query
        |> Ecto.Adapters.SQL.to_sql(:all, Repo)
        |> elem(0)

        explain_result = try do
          Repo.query!("EXPLAIN (FORMAT JSON) #{query_sql}")
        rescue
          _ -> %{rows: [[%{"Plan" => %{}}]]}
        end

        plan = case explain_result.rows do
          [[json]] when is_list(json) -> List.first(json)
          [[json]] when is_map(json) -> json
          _ -> %{}
        end

        {:ok, %{
          query: query_string,
          sql: query_sql,
          plan: plan,
          estimated_rows: get_in(plan, ["Plan", "Plan Rows"]) || 0
        }}

      {:error, _} = err ->
        err
    end
  rescue
    e ->
      {:error, "Explain failed: #{Exception.message(e)}"}
  end

  # ============================================================================
  # Internal Execution
  # ============================================================================

  defp do_execute(query_string, opts) do
    case QueryCompiler.compile(query_string) do
      {:ok, compiled} ->
        execute_compiled(compiled, opts)

      {:error, _} = err ->
        err
    end
  end

  defp execute_compiled(compiled, opts) do
    page = max(opts[:page] || 1, 1)
    page_size = min(opts[:page_size] || @default_page_size, @max_page_size)
    offset = (page - 1) * page_size

    # Apply organization filter if provided
    query = if org_id = opts[:organization_id] do
      apply_organization_filter(compiled.query, compiled.source, org_id)
    else
      compiled.query
    end

    # Handle aggregation vs normal query
    if compiled.has_aggregation do
      execute_aggregation(compiled, query, opts)
    else
      execute_normal(compiled, query, offset, page_size, opts)
    end
  end

  defp execute_normal(compiled, query, offset, page_size, _opts) do
    # Apply pagination
    paginated_query = query
    |> Ecto.Query.offset(^offset)
    |> Ecto.Query.limit(^page_size)

    # Execute
    results = Repo.all(paginated_query)

    # Get total count (for pagination)
    total = try do
      Repo.aggregate(compiled.query, :count, :id)
    rescue
      _ -> length(results)
    end

    # Transform results
    transformed = results
    |> transform_results(compiled)
    |> apply_projections(compiled.projections)
    |> apply_post_processors(compiled.post_processors)

    {:ok, %{
      data: transformed,
      total: total,
      has_more: offset + length(results) < total
    }}
  end

  defp execute_aggregation(compiled, query, _opts) do
    # Build aggregation query
    agg_query = build_aggregation_query(query, compiled.aggregations, compiled.group_by, compiled.source)

    # Execute
    results = Repo.all(agg_query)

    # Format aggregation results
    formatted = format_aggregation_results(results, compiled.aggregations, compiled.group_by)

    # Apply sorting to aggregated results if specified
    sorted = if compiled.sort do
      sort_aggregated_results(formatted, compiled.sort)
    else
      formatted
    end

    # Apply limit to aggregated results
    limited = if compiled.limit do
      Enum.take(sorted, compiled.limit)
    else
      sorted
    end

    {:ok, %{
      data: limited,
      total: length(limited),
      has_more: false
    }}
  end

  defp execute_batch(compiled, offset, batch_size, opts) do
    query = if org_id = opts[:organization_id] do
      apply_organization_filter(compiled.query, compiled.source, org_id)
    else
      compiled.query
    end

    query
    |> Ecto.Query.offset(^offset)
    |> Ecto.Query.limit(^batch_size)
    |> Repo.all()
    |> transform_results(compiled)
    |> apply_projections(compiled.projections)
    |> apply_post_processors(compiled.post_processors)
  end

  # ============================================================================
  # Aggregation Building
  # ============================================================================

  defp build_aggregation_query(base_query, aggregations, group_by, source) do
    import Ecto.Query

    # Start with a subquery to get the filtered data
    # Then apply grouping and aggregations

    if Enum.empty?(group_by) do
      # Global aggregation (no GROUP BY)
      build_global_aggregation(base_query, aggregations)
    else
      # Grouped aggregation
      build_grouped_aggregation(base_query, aggregations, group_by, source)
    end
  end

  defp build_global_aggregation(query, aggregations) do
    import Ecto.Query

    # Build select clause with aggregations
    select_fields = Enum.map(aggregations, fn {alias_name, func, field} ->
      {String.to_atom(alias_name), build_agg_expression(func, field)}
    end)

    from(e in subquery(query),
      select: ^Map.new(select_fields)
    )
  end

  defp build_grouped_aggregation(query, aggregations, group_by, source_name) do
    import Ecto.Query

    # This is complex because we need to handle both column and payload fields
    # For simplicity, we'll use a different approach: fetch all matching rows
    # and aggregate in Elixir

    # For now, return the base query and handle aggregation in post-processing
    query
  end

  defp build_agg_expression("count", nil), do: dynamic([e], count(e.id))
  defp build_agg_expression("count", _field), do: dynamic([e], count(e.id))
  defp build_agg_expression("sum", field) when is_binary(field) do
    dynamic([e], sum(fragment("(?->>?)::numeric", e.payload, ^field)))
  end
  defp build_agg_expression("avg", field) when is_binary(field) do
    dynamic([e], avg(fragment("(?->>?)::numeric", e.payload, ^field)))
  end
  defp build_agg_expression("min", field) when is_binary(field) do
    dynamic([e], min(fragment("(?->>?)::numeric", e.payload, ^field)))
  end
  defp build_agg_expression("max", field) when is_binary(field) do
    dynamic([e], max(fragment("(?->>?)::numeric", e.payload, ^field)))
  end
  defp build_agg_expression("dcount", field) when is_binary(field) do
    dynamic([e], count(fragment("DISTINCT ?->>?", e.payload, ^field)))
  end
  defp build_agg_expression(_, _), do: dynamic([e], count(e.id))

  defp format_aggregation_results(results, aggregations, group_by) when is_list(results) do
    if Enum.empty?(group_by) do
      # Global aggregation - single result
      results
    else
      # Grouped aggregation - need to process in Elixir
      results
      |> Enum.group_by(fn row ->
        Enum.map(group_by, fn field ->
          get_field_value(row, field)
        end)
        |> List.to_tuple()
      end)
      |> Enum.map(fn {group_key, rows} ->
        # Build result with group by fields
        group_fields = Enum.zip(group_by, Tuple.to_list(group_key))
        |> Enum.map(fn {field, value} -> {String.to_atom(field), value} end)
        |> Map.new()

        # Calculate aggregations
        agg_fields = Enum.map(aggregations, fn {alias_name, func, field} ->
          value = calculate_aggregation(func, rows, field)
          {String.to_atom(alias_name), value}
        end)
        |> Map.new()

        Map.merge(group_fields, agg_fields)
      end)
    end
  end

  defp format_aggregation_results(results, _aggregations, _group_by), do: [results]

  defp get_field_value(row, field) do
    cond do
      Map.has_key?(row, String.to_atom(field)) ->
        Map.get(row, String.to_atom(field))

      Map.has_key?(row, field) ->
        Map.get(row, field)

      Map.has_key?(row, :payload) and is_map(row.payload) ->
        row.payload[field]

      true ->
        nil
    end
  end

  defp calculate_aggregation("count", rows, _field), do: length(rows)
  defp calculate_aggregation("sum", rows, field) do
    rows
    |> Enum.map(&get_numeric_field(&1, field))
    |> Enum.reject(&is_nil/1)
    |> Enum.sum()
  end
  defp calculate_aggregation("avg", rows, field) do
    values = rows
    |> Enum.map(&get_numeric_field(&1, field))
    |> Enum.reject(&is_nil/1)

    if Enum.empty?(values), do: 0, else: Enum.sum(values) / length(values)
  end
  defp calculate_aggregation("min", rows, field) do
    rows
    |> Enum.map(&get_numeric_field(&1, field))
    |> Enum.reject(&is_nil/1)
    |> Enum.min(fn -> nil end)
  end
  defp calculate_aggregation("max", rows, field) do
    rows
    |> Enum.map(&get_numeric_field(&1, field))
    |> Enum.reject(&is_nil/1)
    |> Enum.max(fn -> nil end)
  end
  defp calculate_aggregation("dcount", rows, field) do
    rows
    |> Enum.map(&get_field_value(&1, field))
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> length()
  end
  defp calculate_aggregation(_, rows, _), do: length(rows)

  defp get_numeric_field(row, field) do
    value = get_field_value(row, field)
    case value do
      n when is_number(n) -> n
      s when is_binary(s) ->
        case Float.parse(s) do
          {f, _} -> f
          :error -> nil
        end
      _ -> nil
    end
  end

  defp sort_aggregated_results(results, sort_items) do
    Enum.sort_by(results, fn row ->
      Enum.map(sort_items, fn {field, _direction} ->
        Map.get(row, String.to_atom(field)) ||
        Map.get(row, field) ||
        0
      end)
    end, fn a, b ->
      # Use first sort item's direction for overall ordering
      case List.first(sort_items) do
        {_, :desc} -> a >= b
        _ -> a <= b
      end
    end)
  end

  # ============================================================================
  # Result Transformation
  # ============================================================================

  defp transform_results(results, compiled) do
    Enum.map(results, fn row ->
      base = %{
        id: row.id,
        event_type: Map.get(row, :event_type),
        timestamp: Map.get(row, :timestamp) || Map.get(row, :inserted_at),
        payload: Map.get(row, :payload, %{}),
        severity: Map.get(row, :severity)
      }

      # Add agent hostname for events
      hostname = case compiled.source do
        TamanduaServer.Telemetry.Event ->
          get_agent_hostname(row.agent_id)
        TamanduaServer.Agents.Agent ->
          row.hostname
        _ ->
          nil
      end

      Map.merge(base, %{
        agent_id: Map.get(row, :agent_id),
        agent_hostname: hostname
      })
    end)
  end

  defp apply_projections(results, nil), do: results
  defp apply_projections(results, []), do: results
  defp apply_projections(results, fields) do
    field_atoms = Enum.map(fields, &String.to_atom/1)

    Enum.map(results, fn row ->
      # Include projected fields from both row and payload
      Enum.reduce(field_atoms, %{}, fn field, acc ->
        value = Map.get(row, field) ||
                get_in(row, [:payload, Atom.to_string(field)])

        Map.put(acc, field, value)
      end)
    end)
  end

  defp apply_post_processors(results, []), do: results
  defp apply_post_processors(results, processors) do
    Enum.reduce(Enum.reverse(processors), results, fn processor, acc ->
      processor.(acc)
    end)
  end

  defp apply_organization_filter(query, source, org_id) do
    import Ecto.Query

    case source do
      TamanduaServer.Telemetry.Event ->
        # Filter through agent relationship
        where(query, [e, a], a.organization_id == ^org_id)

      TamanduaServer.Alerts.Alert ->
        where(query, [a], a.organization_id == ^org_id)

      TamanduaServer.Agents.Agent ->
        where(query, [a], a.organization_id == ^org_id)

      _ ->
        query
    end
  rescue
    _ -> query
  end

  # ============================================================================
  # Result Enhancement
  # ============================================================================

  defp enhance_result({:ok, result}, query_string, execution_time, opts) do
    page = opts[:page] || 1
    page_size = opts[:page_size] || @default_page_size

    {:ok, %{
      data: result.data,
      meta: %{
        total: result.total,
        page: page,
        page_size: page_size,
        execution_time_ms: execution_time,
        query: query_string,
        has_more: result.has_more
      }
    }}
  end

  defp enhance_result({:error, _} = err, _query, _time, _opts), do: err

  defp get_agent_hostname(nil), do: "Unknown"
  defp get_agent_hostname(agent_id) do
    case Agents.get(agent_id) do
      nil -> "Unknown"
      agent -> agent.hostname
    end
  end
end
