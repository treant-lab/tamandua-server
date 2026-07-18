defmodule TamanduaServer.Hunting.QueryBuilder do
  @moduledoc """
  Builds Ecto queries from SQL-like DSL for threat hunting.

  Supports a SQL-like syntax for querying telemetry events:

  ## Syntax Examples

      SELECT process_name, pid, timestamp FROM events
      WHERE event_type = 'process_create' AND timestamp > NOW() - INTERVAL '1 hour'
      ORDER BY timestamp DESC
      LIMIT 100

      SELECT process_name, COUNT(*) as count FROM events
      WHERE event_type = 'process_create'
      GROUP BY process_name
      HAVING COUNT(*) > 10
      ORDER BY count DESC
      LIMIT 10

      SELECT agent_id, COUNT(*) as cnt FROM events
      WHERE event_type = 'process_create'
      GROUP BY agent_id
      HAVING cnt > 100

      SELECT DISTINCT event_type FROM events
      WHERE timestamp > NOW() - INTERVAL '24 hours'

  ## Supported Features

  - SELECT with field selection or COUNT(*), COUNT(DISTINCT field)
  - FROM events (required)
  - WHERE with operators: =, !=, >, <, >=, <=, IN, NOT IN, LIKE, REGEX
  - AND, OR, NOT logical operators
  - GROUP BY with multiple fields
  - **HAVING** with aggregate conditions (supports both function calls and aliases)
  - Aggregations: COUNT(*), COUNT(DISTINCT field), SUM, AVG, MIN, MAX
  - ORDER BY with ASC/DESC
  - LIMIT
  - Time functions: NOW(), INTERVAL
  - JSON field access: payload.process_name, payload.pid

  ## HAVING Clause

  Filter aggregated results with HAVING clause (applied after GROUP BY):

      SELECT agent_id, COUNT(*) as event_count, AVG(severity) as avg_severity
      FROM events
      WHERE timestamp > NOW() - INTERVAL '24 hours'
      GROUP BY agent_id
      HAVING COUNT(*) > 100 AND AVG(severity) > 2
      ORDER BY event_count DESC

  HAVING supports:
  - Aggregate function calls: `HAVING COUNT(*) > 10`, `HAVING SUM(field) >= 1000`
  - Aggregate aliases: `HAVING count > 10` (references alias from SELECT)
  - Comparison operators: =, !=, >, <, >=, <=
  - Logical operators: AND, OR
  - All aggregate functions: COUNT, SUM, AVG, MIN, MAX

  ## Field Mappings

  Top-level fields map directly to Event schema:
  - id, event_type, timestamp, severity, agent_id, created_at

  Payload fields require JSON access:
  - process_name -> payload->>'process_name'
  - pid -> payload->>'pid'
  - Any field not in top-level is assumed to be in payload
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Repo

  @type parsed_query :: %{
    select: list(),
    from: atom(),
    where: term() | nil,
    group_by: list(),
    having: term() | nil,
    order_by: list(),
    limit: integer() | nil,
    distinct: boolean(),
    aggregations: list()
  }

  @type execution_result :: %{
    data: list(map()),
    meta: %{
      query_dsl: String.t(),
      sql: String.t(),
      total: integer(),
      execution_time_ms: integer()
    }
  }

  # Top-level Event schema fields
  @schema_fields ~w(id event_type timestamp severity agent_id created_at sha256 enrichment)a

  # Reserved SQL keywords for tokenization
  @sql_keywords ~w(
    select from where and or not in like regex between
    group by having order asc desc limit distinct
    count sum avg min max now interval
  )

  @default_limit 1000
  @max_limit 10000

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Parse and execute a SQL-like query string.

  ## Examples

      iex> execute("SELECT * FROM events WHERE event_type = 'process_create' LIMIT 10")
      {:ok, %{data: [...], meta: %{...}}}

      iex> execute("SELECT COUNT(*) FROM events WHERE timestamp > NOW() - INTERVAL '1 hour'")
      {:ok, %{data: [%{count: 42}], meta: %{...}}}
  """
  @spec execute(String.t(), keyword()) :: {:ok, execution_result()} | {:error, String.t()}
  def execute(query_string, _opts \\ []) do
    start_time = System.monotonic_time(:millisecond)

    with {:ok, parsed} <- parse(query_string),
         {:ok, ecto_query} <- build_query(parsed),
         {:ok, results} <- execute_query(ecto_query, parsed) do

      execution_time = System.monotonic_time(:millisecond) - start_time
      sql = inspect_sql(ecto_query)

      {:ok, %{
        data: results,
        meta: %{
          query_dsl: query_string,
          sql: sql,
          total: length(results),
          execution_time_ms: execution_time
        }
      }}
    end
  end

  @doc """
  Parse a SQL-like query string into a structured AST.
  """
  @spec parse(String.t()) :: {:ok, parsed_query()} | {:error, String.t()}
  def parse(query_string) when is_binary(query_string) do
    # Simple regex-based parser for SQL-like syntax
    query_string = String.trim(query_string)

    with {:ok, select_clause} <- extract_select(query_string),
         {:ok, from_clause} <- extract_from(query_string),
         {:ok, where_clause} <- extract_where(query_string),
         {:ok, group_by_clause} <- extract_group_by(query_string),
         {:ok, having_clause} <- extract_having(query_string),
         {:ok, order_by_clause} <- extract_order_by(query_string),
         {:ok, limit_clause} <- extract_limit(query_string) do

      {:ok, %{
        select: select_clause.fields,
        distinct: select_clause.distinct,
        aggregations: select_clause.aggregations,
        from: from_clause,
        where: where_clause,
        group_by: group_by_clause,
        having: having_clause,
        order_by: order_by_clause,
        limit: limit_clause
      }}
    end
  end

  @doc """
  Build an Ecto query from a parsed query structure.
  """
  @spec build_query(parsed_query()) :: {:ok, Ecto.Query.t()} | {:error, String.t()}
  def build_query(%{from: from} = _parsed) when from != :events do
    {:error, "Only 'events' table is supported, got: #{from}"}
  end

  def build_query(parsed) do
    try do
      query = from(e in Event)

      query = apply_where(query, parsed.where)
      query = apply_group_by(query, parsed.group_by)
      query = apply_select(query, parsed)
      query = apply_having(query, parsed.having, parsed.aggregations)
      query = apply_order_by(query, parsed.order_by)
      query = apply_limit(query, parsed.limit)

      {:ok, query}
    rescue
      e -> {:error, "Query building error: #{Exception.message(e)}"}
    end
  end

  # ============================================================================
  # Query Extraction (Regex-based parsing)
  # ============================================================================

  defp extract_select(query) do
    # Match: SELECT [DISTINCT] field1, field2, COUNT(*), ... FROM
    select_regex = ~r/SELECT\s+(DISTINCT\s+)?(.+?)\s+FROM/i

    case Regex.run(select_regex, query) do
      [_, distinct, fields_str] ->
        fields = parse_select_fields(fields_str)
        {aggregations, regular_fields} = separate_aggregations(fields)

        {:ok, %{
          distinct: distinct != "",
          fields: regular_fields,
          aggregations: aggregations
        }}

      nil ->
        {:error, "Invalid SELECT clause"}
    end
  end

  defp extract_from(query) do
    # Match: FROM table_name
    from_regex = ~r/FROM\s+(\w+)/i

    case Regex.run(from_regex, query) do
      [_, table] -> {:ok, String.to_atom(table)}
      nil -> {:error, "Missing FROM clause"}
    end
  end

  defp extract_where(query) do
    # Match: WHERE ... [GROUP BY|ORDER BY|LIMIT|$]
    where_regex = ~r/WHERE\s+(.+?)(?:\s+GROUP\s+BY|\s+ORDER\s+BY|\s+LIMIT|\s*$)/i

    case Regex.run(where_regex, query) do
      [_, where_str] -> parse_where_clause(String.trim(where_str))
      nil -> {:ok, nil}
    end
  end

  defp extract_group_by(query) do
    # Match: GROUP BY field1, field2, ... [HAVING ...]
    group_regex = ~r/GROUP\s+BY\s+(.+?)(?:\s+HAVING|\s+ORDER\s+BY|\s+LIMIT|\s*$)/i

    case Regex.run(group_regex, query) do
      [_, fields_str] ->
        fields = fields_str
        |> String.split(",")
        |> Enum.map(&String.trim/1)
        {:ok, fields}

      nil ->
        {:ok, []}
    end
  end

  defp extract_having(query) do
    # Match: HAVING ... [ORDER BY|LIMIT|$]
    having_regex = ~r/HAVING\s+(.+?)(?:\s+ORDER\s+BY|\s+LIMIT|\s*$)/i

    case Regex.run(having_regex, query) do
      [_, having_str] -> parse_where_clause(String.trim(having_str))
      nil -> {:ok, nil}
    end
  end

  defp extract_order_by(query) do
    # Match: ORDER BY field1 [ASC|DESC], field2 [ASC|DESC], ...
    order_regex = ~r/ORDER\s+BY\s+(.+?)(?:\s+LIMIT|\s*$)/i

    case Regex.run(order_regex, query) do
      [_, order_str] ->
        parse_order_by(order_str)

      nil ->
        {:ok, []}
    end
  end

  defp extract_limit(query) do
    # Match: LIMIT n
    limit_regex = ~r/LIMIT\s+(\d+)/i

    case Regex.run(limit_regex, query) do
      [_, num_str] ->
        limit = String.to_integer(num_str)
        {:ok, min(limit, @max_limit)}

      nil ->
        {:ok, @default_limit}
    end
  end

  # ============================================================================
  # Field Parsing
  # ============================================================================

  defp parse_select_fields(fields_str) do
    cond do
      String.trim(fields_str) == "*" ->
        ["*"]

      String.contains?(fields_str, "(") ->
        # Has aggregations, parse carefully
        parse_fields_with_aggregations(fields_str)

      true ->
        # Simple field list
        fields_str
        |> String.split(",")
        |> Enum.map(&String.trim/1)
    end
  end

  defp parse_fields_with_aggregations(fields_str) do
    # Split by comma, but respect parentheses
    fields_str
    |> String.split(~r/,(?![^()]*\))/)
    |> Enum.map(&String.trim/1)
  end

  defp separate_aggregations(fields) do
    Enum.reduce(fields, {[], []}, fn field, {aggs, regular} ->
      cond do
        String.match?(field, ~r/^COUNT\s*\(/i) ->
          {[parse_aggregation(field, :count) | aggs], regular}

        String.match?(field, ~r/^SUM\s*\(/i) ->
          {[parse_aggregation(field, :sum) | aggs], regular}

        String.match?(field, ~r/^AVG\s*\(/i) ->
          {[parse_aggregation(field, :avg) | aggs], regular}

        String.match?(field, ~r/^MIN\s*\(/i) ->
          {[parse_aggregation(field, :min) | aggs], regular}

        String.match?(field, ~r/^MAX\s*\(/i) ->
          {[parse_aggregation(field, :max) | aggs], regular}

        true ->
          {aggs, [field | regular]}
      end
    end)
    |> then(fn {aggs, regular} -> {Enum.reverse(aggs), Enum.reverse(regular)} end)
  end

  defp parse_aggregation(field_str, type) do
    # Parse COUNT(field) [AS alias] or COUNT(*) [AS alias]
    agg_regex = ~r/^#{type}\s*\(\s*(\*|DISTINCT\s+)?(.+?)\s*\)(?:\s+AS\s+(\w+))?/i

    case Regex.run(agg_regex, field_str, capture: :all_but_first) do
      [distinct_or_star, inner, alias_name] ->
        distinct = String.upcase(String.trim(distinct_or_star || "")) == "DISTINCT"
        field = String.trim(inner)
        alias_name = if alias_name == "", do: "#{type}_#{field}", else: alias_name

        %{
          type: type,
          field: if(field == "*", do: nil, else: field),
          distinct: distinct,
          alias: String.to_atom(alias_name)
        }

      [distinct_or_star, inner] ->
        distinct = String.upcase(String.trim(distinct_or_star || "")) == "DISTINCT"
        field = String.trim(inner)

        %{
          type: type,
          field: if(field == "*", do: nil, else: field),
          distinct: distinct,
          alias: String.to_atom("#{type}_" <> (field || "all"))
        }

      _ ->
        %{type: type, field: nil, distinct: false, alias: type}
    end
  end

  defp parse_order_by(order_str) do
    order_str
    |> String.split(",")
    |> Enum.map(fn item ->
      item = String.trim(item)

      case Regex.run(~r/^(\S+)\s+(ASC|DESC)$/i, item) do
        [_, field, dir] ->
          {field, String.downcase(dir) |> String.to_atom()}

        nil ->
          # Default to DESC
          {item, :desc}
      end
    end)
    |> then(&{:ok, &1})
  end

  # ============================================================================
  # WHERE Clause Parsing
  # ============================================================================

  defp parse_where_clause(where_str) do
    # Simple WHERE parser supporting basic operations
    # This is a simplified version - could be enhanced with full expression parsing

    try do
      conditions = parse_conditions(where_str)
      {:ok, conditions}
    rescue
      e -> {:error, "WHERE clause parse error: #{Exception.message(e)}"}
    end
  end

  defp parse_conditions(where_str) do
    # Split by AND/OR while preserving operators
    # This is simplified - a full parser would handle parentheses and precedence

    cond do
      String.contains?(where_str, " OR ") ->
        where_str
        |> String.split(~r/\s+OR\s+/i)
        |> Enum.map(&parse_single_condition/1)
        |> then(&{:or, &1})

      String.contains?(where_str, " AND ") ->
        where_str
        |> String.split(~r/\s+AND\s+/i)
        |> Enum.map(&parse_single_condition/1)
        |> then(&{:and, &1})

      true ->
        parse_single_condition(where_str)
    end
  end

  defp parse_single_condition(cond_str) do
    cond_str = String.trim(cond_str)

    cond do
      # field IN (val1, val2, ...)
      Regex.match?(~r/IN\s*\(/i, cond_str) ->
        parse_in_condition(cond_str, :in)

      # field NOT IN (val1, val2, ...)
      Regex.match?(~r/NOT\s+IN\s*\(/i, cond_str) ->
        parse_in_condition(cond_str, :not_in)

      # field LIKE 'pattern'
      Regex.match?(~r/LIKE/i, cond_str) ->
        parse_like_condition(cond_str)

      # field REGEX 'pattern'
      Regex.match?(~r/REGEX/i, cond_str) ->
        parse_regex_condition(cond_str)

      # field BETWEEN val1 AND val2
      Regex.match?(~r/BETWEEN/i, cond_str) ->
        parse_between_condition(cond_str)

      # Standard comparison: field OP value
      true ->
        parse_comparison_condition(cond_str)
    end
  end

  defp parse_in_condition(cond_str, op) do
    regex = if op == :in do
      ~r/^(.+?)\s+IN\s*\((.+?)\)/i
    else
      ~r/^(.+?)\s+NOT\s+IN\s*\((.+?)\)/i
    end

    case Regex.run(regex, cond_str) do
      [_, field, values_str] ->
        values = values_str
        |> String.split(",")
        |> Enum.map(&parse_value(String.trim(&1)))

        {op, String.trim(field), values}

      nil ->
        {:error, "Invalid IN condition"}
    end
  end

  defp parse_like_condition(cond_str) do
    case Regex.run(~r/^(.+?)\s+LIKE\s+(.+)$/i, cond_str) do
      [_, field, pattern] ->
        {:like, String.trim(field), parse_value(pattern)}

      nil ->
        {:error, "Invalid LIKE condition"}
    end
  end

  defp parse_regex_condition(cond_str) do
    case Regex.run(~r/^(.+?)\s+REGEX\s+(.+)$/i, cond_str) do
      [_, field, pattern] ->
        {:regex, String.trim(field), parse_value(pattern)}

      nil ->
        {:error, "Invalid REGEX condition"}
    end
  end

  defp parse_between_condition(cond_str) do
    case Regex.run(~r/^(.+?)\s+BETWEEN\s+(.+?)\s+AND\s+(.+)$/i, cond_str) do
      [_, field, low, high] ->
        {:between, String.trim(field), parse_value(low), parse_value(high)}

      nil ->
        {:error, "Invalid BETWEEN condition"}
    end
  end

  defp parse_comparison_condition(cond_str) do
    # Support: =, !=, >, <, >=, <=
    comparison_regex = ~r/^(.+?)\s*(>=|<=|!=|<>|=|>|<)\s*(.+)$/

    case Regex.run(comparison_regex, cond_str) do
      [_, field, op, value] ->
        op_atom = case op do
          "=" -> :eq
          "!=" -> :neq
          "<>" -> :neq
          ">" -> :gt
          "<" -> :lt
          ">=" -> :gte
          "<=" -> :lte
        end

        {op_atom, String.trim(field), parse_value(value)}

      nil ->
        {:error, "Invalid comparison condition"}
    end
  end

  defp parse_value(value_str) do
    value_str = String.trim(value_str)

    cond do
      # String literal with quotes
      String.starts_with?(value_str, "'") and String.ends_with?(value_str, "'") ->
        value_str |> String.slice(1..-2//1)

      String.starts_with?(value_str, "\"") and String.ends_with?(value_str, "\"") ->
        value_str |> String.slice(1..-2//1)

      # NOW() - INTERVAL 'duration'
      String.contains?(value_str, "NOW()") ->
        parse_time_expression(value_str)

      # Integer
      Regex.match?(~r/^-?\d+$/, value_str) ->
        String.to_integer(value_str)

      # Float
      Regex.match?(~r/^-?\d+\.\d+$/, value_str) ->
        String.to_float(value_str)

      # Boolean
      String.downcase(value_str) in ["true", "false"] ->
        String.downcase(value_str) == "true"

      # NULL
      String.upcase(value_str) == "NULL" ->
        nil

      # Otherwise treat as identifier (field reference)
      true ->
        {:field, value_str}
    end
  end

  defp parse_time_expression(expr) do
    # Parse: NOW() - INTERVAL 'N hours|days|minutes'
    interval_regex = ~r/NOW\(\)\s*-\s*INTERVAL\s+'(\d+)\s*(hour|day|minute|second|week|month)s?'/i

    case Regex.run(interval_regex, expr) do
      [_, amount, unit] ->
        amount = String.to_integer(amount)
        unit_atom = case String.downcase(unit) do
          "second" -> :second
          "minute" -> :minute
          "hour" -> :hour
          "day" -> :day
          "week" -> :week
          "month" -> :month
        end

        {:datetime, DateTime.utc_now() |> DateTime.add(-amount, unit_atom)}

      nil ->
        # Try NOW() without interval
        if String.contains?(expr, "NOW()") do
          {:datetime, DateTime.utc_now()}
        else
          {:error, "Invalid time expression"}
        end
    end
  end

  # ============================================================================
  # Query Building
  # ============================================================================

  defp apply_where(query, nil), do: query

  defp apply_where(query, conditions) do
    where(query, ^build_where_dynamic(conditions))
  end

  defp build_where_dynamic({:and, conditions}) do
    Enum.reduce(conditions, dynamic(true), fn condition, acc ->
      dynamic(^acc and ^build_where_dynamic(condition))
    end)
  end

  defp build_where_dynamic({:or, conditions}) do
    Enum.reduce(conditions, dynamic(false), fn condition, acc ->
      dynamic(^acc or ^build_where_dynamic(condition))
    end)
  end

  defp build_where_dynamic({:eq, field, value}) do
    build_field_comparison(field, value, fn f, v -> dynamic([e], ^f == ^v) end)
  end

  defp build_where_dynamic({:neq, field, value}) do
    build_field_comparison(field, value, fn f, v -> dynamic([e], ^f != ^v) end)
  end

  defp build_where_dynamic({:gt, field, value}) do
    build_field_comparison(field, value, fn f, v -> dynamic([e], ^f > ^v) end)
  end

  defp build_where_dynamic({:lt, field, value}) do
    build_field_comparison(field, value, fn f, v -> dynamic([e], ^f < ^v) end)
  end

  defp build_where_dynamic({:gte, field, value}) do
    build_field_comparison(field, value, fn f, v -> dynamic([e], ^f >= ^v) end)
  end

  defp build_where_dynamic({:lte, field, value}) do
    build_field_comparison(field, value, fn f, v -> dynamic([e], ^f <= ^v) end)
  end

  defp build_where_dynamic({:in, field, values}) do
    {binding, resolved_field} = resolve_field(field)

    case binding do
      :schema -> dynamic([e], field(e, ^resolved_field) in ^values)
      :payload -> dynamic([e], fragment("?->>? = ANY(?)", e.payload, ^field, ^values))
    end
  end

  defp build_where_dynamic({:not_in, field, values}) do
    {binding, resolved_field} = resolve_field(field)

    case binding do
      :schema -> dynamic([e], field(e, ^resolved_field) not in ^values)
      :payload -> dynamic([e], fragment("NOT (?->>? = ANY(?))", e.payload, ^field, ^values))
    end
  end

  defp build_where_dynamic({:like, field, pattern}) do
    {binding, resolved_field} = resolve_field(field)

    case binding do
      :schema -> dynamic([e], like(field(e, ^resolved_field), ^pattern))
      :payload -> dynamic([e], like(fragment("?->>?", e.payload, ^field), ^pattern))
    end
  end

  defp build_where_dynamic({:regex, field, pattern}) do
    {binding, resolved_field} = resolve_field(field)

    case binding do
      :schema -> dynamic([e], fragment("? ~ ?", field(e, ^resolved_field), ^pattern))
      :payload -> dynamic([e], fragment("(?->>?) ~ ?", e.payload, ^field, ^pattern))
    end
  end

  defp build_where_dynamic({:between, field, low, high}) do
    build_field_comparison(field, {low, high}, fn f, {l, h} ->
      dynamic([e], ^f >= ^l and ^f <= ^h)
    end)
  end

  defp build_field_comparison(field, value, comparison_fn) do
    {binding, resolved_field} = resolve_field(field)
    actual_value = resolve_value(value)

    case binding do
      :schema ->
        comparison_fn.(dynamic([e], field(e, ^resolved_field)), actual_value)

      :payload ->
        # For JSON fields, we need fragment
        json_value = dynamic([e], fragment("?->>?", e.payload, ^field))
        comparison_fn.(json_value, actual_value)
    end
  end

  defp resolve_value({:datetime, dt}), do: dt
  defp resolve_value({:field, _field}), do: nil  # Field references need special handling
  defp resolve_value(v), do: v

  defp resolve_field(field) when is_atom(field) do
    if field in @schema_fields do
      {:schema, field}
    else
      {:payload, Atom.to_string(field)}
    end
  end

  defp resolve_field(field) when is_binary(field) do
    field_atom = String.to_existing_atom(field)

    if field_atom in @schema_fields do
      {:schema, field_atom}
    else
      {:payload, field}
    end
  rescue
    ArgumentError ->
      # Field doesn't exist as atom, must be in payload
      {:payload, field}
  end

  defp apply_group_by(query, []), do: query

  defp apply_group_by(query, fields) do
    Enum.reduce(fields, query, fn field, q ->
      {binding, resolved_field} = resolve_field(field)

      case binding do
        :schema ->
          group_by(q, [e], field(e, ^resolved_field))

        :payload ->
          group_by(q, [e], fragment("?->>?", e.payload, ^field))
      end
    end)
  end

  defp apply_having(query, nil, _aggregations), do: query

  defp apply_having(query, having_conditions, aggregations) do
    # Build dynamic HAVING clause for aggregate filters
    # HAVING conditions can reference aggregate functions (COUNT, SUM, AVG, etc.)
    having_dynamic = build_having_dynamic(having_conditions, aggregations)
    having(query, ^having_dynamic)
  end

  defp build_having_dynamic(conditions, aggregations) do
    case conditions do
      {:and, conds} ->
        Enum.reduce(conds, dynamic(true), fn condition, acc ->
          dynamic(^acc and ^build_having_dynamic(condition, aggregations))
        end)

      {:or, conds} ->
        Enum.reduce(conds, dynamic(false), fn condition, acc ->
          dynamic(^acc or ^build_having_dynamic(condition, aggregations))
        end)

      {:eq, field, value} ->
        build_having_comparison(field, value, aggregations, fn f, v -> dynamic([e], ^f == ^v) end)

      {:neq, field, value} ->
        build_having_comparison(field, value, aggregations, fn f, v -> dynamic([e], ^f != ^v) end)

      {:gt, field, value} ->
        build_having_comparison(field, value, aggregations, fn f, v -> dynamic([e], ^f > ^v) end)

      {:lt, field, value} ->
        build_having_comparison(field, value, aggregations, fn f, v -> dynamic([e], ^f < ^v) end)

      {:gte, field, value} ->
        build_having_comparison(field, value, aggregations, fn f, v -> dynamic([e], ^f >= ^v) end)

      {:lte, field, value} ->
        build_having_comparison(field, value, aggregations, fn f, v -> dynamic([e], ^f <= ^v) end)

      _ ->
        dynamic(true)
    end
  end

  defp build_having_comparison(field, value, aggregations, comparison_fn) do
    actual_value = resolve_value(value)

    # Check if field references an aggregate function
    # Field could be an aggregate alias (e.g., "count_all") or a function call
    cond do
      # Check if it's a direct aggregate alias from SELECT clause
      is_aggregate_alias?(field, aggregations) ->
        agg_expr = get_aggregate_expression(field, aggregations)
        comparison_fn.(agg_expr, actual_value)

      # Check if field contains aggregate function pattern (e.g., "COUNT(*)")
      is_aggregate_function_call?(field) ->
        agg_expr = parse_aggregate_function(field)
        comparison_fn.(agg_expr, actual_value)

      # Otherwise treat as regular field (though this is unusual in HAVING)
      true ->
        {binding, resolved_field} = resolve_field(field)
        case binding do
          :schema ->
            comparison_fn.(dynamic([e], field(e, ^resolved_field)), actual_value)
          :payload ->
            json_value = dynamic([e], fragment("?->>?", e.payload, ^field))
            comparison_fn.(json_value, actual_value)
        end
    end
  end

  defp is_aggregate_alias?(field, aggregations) do
    field_atom = try do
      String.to_existing_atom(field)
    rescue
      ArgumentError -> nil
    end

    field_atom && Enum.any?(aggregations, fn agg -> agg.alias == field_atom end)
  end

  defp get_aggregate_expression(field, aggregations) do
    field_atom = String.to_existing_atom(field)
    agg = Enum.find(aggregations, fn agg -> agg.alias == field_atom end)

    case {agg.type, agg.field, agg.distinct} do
      {:count, nil, _} ->
        dynamic([e], count(e.id))

      {:count, agg_field, true} ->
        {binding, resolved_field} = resolve_field(agg_field)
        case binding do
          :schema -> dynamic([e], count(field(e, ^resolved_field), :distinct))
          :payload -> dynamic([e], fragment("COUNT(DISTINCT ?->>?)", e.payload, ^agg_field))
        end

      {:count, agg_field, false} ->
        {binding, resolved_field} = resolve_field(agg_field)
        case binding do
          :schema -> dynamic([e], count(field(e, ^resolved_field)))
          :payload -> dynamic([e], fragment("COUNT(?->>?)", e.payload, ^agg_field))
        end

      {:sum, agg_field, _} ->
        {binding, resolved_field} = resolve_field(agg_field)
        case binding do
          :schema -> dynamic([e], sum(field(e, ^resolved_field)))
          :payload -> dynamic([e], fragment("SUM((?->>?)::numeric)", e.payload, ^agg_field))
        end

      {:avg, agg_field, _} ->
        {binding, resolved_field} = resolve_field(agg_field)
        case binding do
          :schema -> dynamic([e], avg(field(e, ^resolved_field)))
          :payload -> dynamic([e], fragment("AVG((?->>?)::numeric)", e.payload, ^agg_field))
        end

      {:min, agg_field, _} ->
        {binding, resolved_field} = resolve_field(agg_field)
        case binding do
          :schema -> dynamic([e], min(field(e, ^resolved_field)))
          :payload -> dynamic([e], fragment("MIN(?->>?)", e.payload, ^agg_field))
        end

      {:max, agg_field, _} ->
        {binding, resolved_field} = resolve_field(agg_field)
        case binding do
          :schema -> dynamic([e], max(field(e, ^resolved_field)))
          :payload -> dynamic([e], fragment("MAX(?->>?)", e.payload, ^agg_field))
        end
    end
  end

  defp is_aggregate_function_call?(field) when is_binary(field) do
    String.match?(field, ~r/^(COUNT|SUM|AVG|MIN|MAX)\s*\(/i)
  end

  defp is_aggregate_function_call?(_), do: false

  defp parse_aggregate_function(field) do
    # Parse inline aggregate functions like "COUNT(*)" or "SUM(field)"
    cond do
      String.match?(field, ~r/^COUNT\s*\(\s*\*\s*\)/i) ->
        dynamic([e], count(e.id))

      String.match?(field, ~r/^COUNT\s*\(/i) ->
        # Extract field name from COUNT(field)
        case Regex.run(~r/COUNT\s*\(\s*(.+?)\s*\)/i, field) do
          [_, inner_field] ->
            {binding, resolved_field} = resolve_field(String.trim(inner_field))
            case binding do
              :schema -> dynamic([e], count(field(e, ^resolved_field)))
              :payload -> dynamic([e], fragment("COUNT(?->>?)", e.payload, ^inner_field))
            end
          _ ->
            dynamic([e], count(e.id))
        end

      String.match?(field, ~r/^SUM\s*\(/i) ->
        case Regex.run(~r/SUM\s*\(\s*(.+?)\s*\)/i, field) do
          [_, inner_field] ->
            {binding, resolved_field} = resolve_field(String.trim(inner_field))
            case binding do
              :schema -> dynamic([e], sum(field(e, ^resolved_field)))
              :payload -> dynamic([e], fragment("SUM((?->>?)::numeric)", e.payload, ^inner_field))
            end
          _ ->
            dynamic([e], count(e.id))
        end

      String.match?(field, ~r/^AVG\s*\(/i) ->
        case Regex.run(~r/AVG\s*\(\s*(.+?)\s*\)/i, field) do
          [_, inner_field] ->
            {binding, resolved_field} = resolve_field(String.trim(inner_field))
            case binding do
              :schema -> dynamic([e], avg(field(e, ^resolved_field)))
              :payload -> dynamic([e], fragment("AVG((?->>?)::numeric)", e.payload, ^inner_field))
            end
          _ ->
            dynamic([e], count(e.id))
        end

      String.match?(field, ~r/^MIN\s*\(/i) ->
        case Regex.run(~r/MIN\s*\(\s*(.+?)\s*\)/i, field) do
          [_, inner_field] ->
            {binding, resolved_field} = resolve_field(String.trim(inner_field))
            case binding do
              :schema -> dynamic([e], min(field(e, ^resolved_field)))
              :payload -> dynamic([e], fragment("MIN(?->>?)", e.payload, ^inner_field))
            end
          _ ->
            dynamic([e], count(e.id))
        end

      String.match?(field, ~r/^MAX\s*\(/i) ->
        case Regex.run(~r/MAX\s*\(\s*(.+?)\s*\)/i, field) do
          [_, inner_field] ->
            {binding, resolved_field} = resolve_field(String.trim(inner_field))
            case binding do
              :schema -> dynamic([e], max(field(e, ^resolved_field)))
              :payload -> dynamic([e], fragment("MAX(?->>?)", e.payload, ^inner_field))
            end
          _ ->
            dynamic([e], count(e.id))
        end

      true ->
        dynamic([e], count(e.id))
    end
  end

  defp apply_select(query, %{select: ["*"], aggregations: []}), do: query

  defp apply_select(query, %{select: [], aggregations: aggs}) when aggs != [] do
    # Only aggregations, no regular fields
    select_map = build_aggregation_select(aggs)
    select(query, [e], ^select_map)
  end

  defp apply_select(query, %{select: fields, aggregations: aggs, group_by: _group_by}) when aggs != [] do
    # Mix of fields and aggregations (GROUP BY query)
    select_fields = build_field_select(fields)
    agg_fields = build_aggregation_select(aggs)

    select_map = Map.merge(select_fields, agg_fields)
    select(query, [e], ^select_map)
  end

  defp apply_select(query, %{select: ["*"]}), do: query

  defp apply_select(query, %{select: fields, distinct: true}) do
    select_fields = build_field_select(fields)
    query
    |> select([e], ^select_fields)
    |> distinct(true)
  end

  defp apply_select(query, %{select: fields}) do
    select_fields = build_field_select(fields)
    select(query, [e], ^select_fields)
  end

  defp build_field_select(fields) do
    Enum.reduce(fields, %{}, fn field, acc ->
      {binding, resolved_field} = resolve_field(field)

      key = String.to_atom(field)

      value = case binding do
        :schema -> dynamic([e], field(e, ^resolved_field))
        :payload -> dynamic([e], fragment("?->>?", e.payload, ^field))
      end

      Map.put(acc, key, value)
    end)
  end

  defp build_aggregation_select(aggs) do
    Enum.reduce(aggs, %{}, fn agg, acc ->
      value = case {agg.type, agg.field, agg.distinct} do
        {:count, nil, _} ->
          dynamic([e], count(e.id))

        {:count, field, true} ->
          {binding, resolved_field} = resolve_field(field)
          case binding do
            :schema -> dynamic([e], count(field(e, ^resolved_field), :distinct))
            :payload -> dynamic([e], fragment("COUNT(DISTINCT ?->>?)", e.payload, ^field))
          end

        {:count, field, false} ->
          {binding, resolved_field} = resolve_field(field)
          case binding do
            :schema -> dynamic([e], count(field(e, ^resolved_field)))
            :payload -> dynamic([e], fragment("COUNT(?->>?)", e.payload, ^field))
          end

        {:sum, field, _} ->
          {binding, resolved_field} = resolve_field(field)
          case binding do
            :schema -> dynamic([e], sum(field(e, ^resolved_field)))
            :payload -> dynamic([e], fragment("SUM((?->>?)::numeric)", e.payload, ^field))
          end

        {:avg, field, _} ->
          {binding, resolved_field} = resolve_field(field)
          case binding do
            :schema -> dynamic([e], avg(field(e, ^resolved_field)))
            :payload -> dynamic([e], fragment("AVG((?->>?)::numeric)", e.payload, ^field))
          end

        {:min, field, _} ->
          {binding, resolved_field} = resolve_field(field)
          case binding do
            :schema -> dynamic([e], min(field(e, ^resolved_field)))
            :payload -> dynamic([e], fragment("MIN(?->>?)", e.payload, ^field))
          end

        {:max, field, _} ->
          {binding, resolved_field} = resolve_field(field)
          case binding do
            :schema -> dynamic([e], max(field(e, ^resolved_field)))
            :payload -> dynamic([e], fragment("MAX(?->>?)", e.payload, ^field))
          end
      end

      Map.put(acc, agg.alias, value)
    end)
  end

  defp apply_order_by(query, []), do: query

  defp apply_order_by(query, order_specs) do
    Enum.reduce(order_specs, query, fn {field, direction}, q ->
      {binding, resolved_field} = resolve_field(field)

      case binding do
        :schema ->
          order_by(q, [e], [{^direction, field(e, ^resolved_field)}])

        :payload ->
          # For JSON fields, order by the fragment
          order_by(q, [e], [{^direction, fragment("?->>?", e.payload, ^field)}])
      end
    end)
  end

  defp apply_limit(query, nil), do: limit(query, ^@default_limit)
  defp apply_limit(query, lim), do: limit(query, ^lim)

  # ============================================================================
  # Query Execution
  # ============================================================================

  defp execute_query(ecto_query, _parsed) do
    try do
      results = Repo.all(ecto_query)
      {:ok, results}
    rescue
      e -> {:error, "Query execution error: #{Exception.message(e)}"}
    end
  end

  defp inspect_sql(query) do
    try do
      {sql, _params} = Repo.to_sql(:all, query)
      sql
    rescue
      _ -> "(SQL generation failed)"
    end
  end
end
