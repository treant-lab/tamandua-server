defmodule TamanduaServer.Hunting.QueryDSL do
  @moduledoc """
  Query DSL (Domain Specific Language) parser and compiler for threat hunting.

  Supports multiple input formats:
  - Visual query builder JSON
  - TQL (Tamandua Query Language) - KQL-like syntax
  - SQL (subset)
  - YAML (Sigma-like)

  The DSL is compiled to Ecto queries for efficient database execution.
  """

  alias TamanduaServer.Hunting.{QueryParser, QueryCompiler}
  alias TamanduaServer.Telemetry.Event

  @type query_dsl :: map()
  @type query_format :: :visual | :tql | :sql | :yaml
  @type compile_result :: {:ok, Ecto.Query.t()} | {:error, String.t()}

  @doc """
  Parse a query from the specified format into normalized DSL.

  ## Examples

      iex> parse_query(%{conditions: [...]}, :visual)
      {:ok, %{source: "events", filters: [...]}}

      iex> parse_query("events | where event_type == \\"process\\"", :tql)
      {:ok, %{source: "events", filters: [...]}}
  """
  @spec parse_query(String.t() | map(), query_format()) :: {:ok, query_dsl()} | {:error, String.t()}
  def parse_query(query, format)

  def parse_query(query, :visual) when is_map(query) do
    with {:ok, normalized} <- normalize_visual_query(query) do
      {:ok, normalized}
    end
  end

  def parse_query(query, :tql) when is_binary(query) do
    case QueryParser.parse(query) do
      {:ok, ast} -> {:ok, ast_to_dsl(ast)}
      {:error, msg, line, col} -> {:error, "TQL parse error at line #{line}:#{col}: #{msg}"}
    end
  end

  def parse_query(query, :sql) when is_binary(query) do
    # Basic SQL SELECT parser (subset)
    with {:ok, ast} <- parse_sql(query) do
      {:ok, ast_to_dsl(ast)}
    end
  end

  def parse_query(query, :yaml) when is_binary(query) do
    # Sigma-like YAML query format
    with {:ok, parsed} <- YamlElixir.read_from_string(query),
         {:ok, dsl} <- yaml_to_dsl(parsed) do
      {:ok, dsl}
    else
      {:error, reason} -> {:error, "YAML parse error: #{inspect(reason)}"}
    end
  end

  def parse_query(_query, format) do
    {:error, "Unsupported query format: #{inspect(format)}"}
  end

  @doc """
  Compile a normalized DSL query to an Ecto query.
  """
  @spec compile(query_dsl(), keyword()) :: compile_result()
  def compile(dsl, opts \\ []) do
    QueryCompiler.compile(dsl, opts)
  end

  @doc """
  Validate a query without executing it.
  Returns errors or warnings.
  """
  @spec validate(String.t() | map(), query_format()) :: {:ok, [map()]} | {:error, [map()]}
  def validate(query, format) do
    case parse_query(query, format) do
      {:ok, dsl} ->
        warnings = check_warnings(dsl)
        {:ok, warnings}

      {:error, message} ->
        {:error, [%{type: :error, message: message}]}
    end
  end

  @doc """
  Get autocomplete suggestions for a field.
  """
  @spec autocomplete_field(String.t(), String.t(), keyword()) :: {:ok, [String.t()]}
  def autocomplete_field(field, prefix, opts \\ []) do
    limit = Keyword.get(opts, :limit, 10)
    organization_id = Keyword.get(opts, :organization_id)

    suggestions =
      case field do
        "event.type" ->
          ["process", "network", "file", "dns", "registry"]

        "agent.hostname" ->
          TamanduaServer.Agents.list_agent_hostnames(organization_id, prefix, limit)

        "agent.os" ->
          ["windows", "linux", "macos"]

        "process.name" ->
          TamanduaServer.Telemetry.top_process_names(organization_id, prefix, limit)

        "network.remote_ip" ->
          TamanduaServer.Telemetry.top_remote_ips(organization_id, prefix, limit)

        "file.extension" ->
          TamanduaServer.Telemetry.top_file_extensions(organization_id, prefix, limit)

        _ ->
          []
      end

    {:ok, suggestions}
  end

  # ============================================================================
  # Visual Query Builder Format
  # ============================================================================

  defp normalize_visual_query(%{"conditions" => conditions, "logic" => logic} = query) do
    filters = normalize_conditions(conditions, logic)
    time_range = Map.get(query, "time_range")
    aggregations = Map.get(query, "aggregations", [])
    grouping = Map.get(query, "grouping", [])
    sorting = Map.get(query, "sorting", [])
    limit = Map.get(query, "limit")

    dsl = %{
      source: "events",
      filters: filters,
      time_range: time_range,
      aggregations: normalize_aggregations(aggregations),
      grouping: grouping,
      sorting: sorting,
      limit: limit
    }

    {:ok, dsl}
  end

  defp normalize_visual_query(_query) do
    {:error, "Invalid visual query format"}
  end

  defp normalize_conditions([], _logic), do: []

  defp normalize_conditions(conditions, logic) when is_list(conditions) do
    normalized =
      Enum.map(conditions, fn condition ->
        case condition do
          %{"conditions" => nested_conditions, "logic" => nested_logic} ->
            # Nested group
            {:group, nested_logic, normalize_conditions(nested_conditions, nested_logic)}

          %{"field" => field, "operator" => op, "value" => value} ->
            # Simple condition
            {:condition, field, String.to_atom(op), value}

          _ ->
            nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    if length(normalized) > 1 do
      [{:logic, String.to_atom(logic), normalized}]
    else
      normalized
    end
  end

  defp normalize_aggregations([]), do: []

  defp normalize_aggregations(aggs) when is_list(aggs) do
    Enum.map(aggs, fn %{"function" => func, "field" => field, "alias" => alias_name} ->
      %{
        function: String.to_atom(func),
        field: field,
        alias: alias_name || "#{func}_#{field}"
      }
    end)
  end

  # ============================================================================
  # AST to DSL Conversion (from TQL parser)
  # ============================================================================

  defp ast_to_dsl(%{source: source, operators: operators}) do
    filters = extract_filters(operators)
    aggregations = extract_aggregations(operators)
    grouping = extract_grouping(operators)
    sorting = extract_sorting(operators)
    limit = extract_limit(operators)

    %{
      source: source,
      filters: filters,
      aggregations: aggregations,
      grouping: grouping,
      sorting: sorting,
      limit: limit
    }
  end

  defp extract_filters(operators) do
    operators
    |> Enum.filter(fn
      {:where, _expr} -> true
      {:has, _value} -> true
      _ -> false
    end)
    |> Enum.flat_map(fn
      {:where, expr} -> [normalize_expression(expr)]
      {:has, value} -> [{:has, value}]
    end)
  end

  defp normalize_expression({:and, left, right}) do
    {:logic, :and, [normalize_expression(left), normalize_expression(right)]}
  end

  defp normalize_expression({:or, left, right}) do
    {:logic, :or, [normalize_expression(left), normalize_expression(right)]}
  end

  defp normalize_expression({:not, expr}) do
    {:not, normalize_expression(expr)}
  end

  defp normalize_expression({:comparison, field, op, {:literal, value}}) do
    {:condition, field, op, value}
  end

  defp normalize_expression({:comparison, field, op, value}) do
    {:condition, field, op, value}
  end

  defp normalize_expression(expr), do: expr

  defp extract_aggregations(operators) do
    operators
    |> Enum.filter(fn
      {:summarize, _aggs, _by} -> true
      _ -> false
    end)
    |> Enum.flat_map(fn {:summarize, aggs, _by} ->
      Enum.map(aggs, fn {alias_name, func, field} ->
        %{
          function: String.to_atom(func),
          field: field,
          alias: alias_name
        }
      end)
    end)
  end

  defp extract_grouping(operators) do
    operators
    |> Enum.find_value([], fn
      {:summarize, _aggs, by_fields} -> by_fields
      _ -> nil
    end)
  end

  defp extract_sorting(operators) do
    operators
    |> Enum.find_value([], fn
      {:sort, sort_items} -> sort_items
      _ -> nil
    end)
  end

  defp extract_limit(operators) do
    operators
    |> Enum.find_value(nil, fn
      {:limit, n} -> n
      {:top, n, _field} -> n
      _ -> nil
    end)
  end

  # ============================================================================
  # SQL Parser (Basic SELECT subset)
  # ============================================================================

  defp parse_sql(sql) do
    # Very basic SQL parser for SELECT queries
    # Format: SELECT ... FROM events WHERE ... GROUP BY ... ORDER BY ... LIMIT ...
    sql_lower = String.downcase(sql)

    with {:ok, source} <- extract_from_clause(sql_lower),
         {:ok, where_clause} <- extract_where_clause(sql_lower),
         {:ok, group_by} <- extract_group_by(sql_lower),
         {:ok, order_by} <- extract_order_by(sql_lower),
         {:ok, limit} <- extract_sql_limit(sql_lower) do
      {:ok,
       %{
         source: source,
         operators: [
           {:where, where_clause},
           {:summarize, [], group_by},
           {:sort, order_by},
           {:limit, limit}
         ]
       }}
    end
  end

  defp extract_from_clause(sql) do
    case Regex.run(~r/from\s+(\w+)/i, sql) do
      [_, table] -> {:ok, table}
      _ -> {:error, "Missing FROM clause"}
    end
  end

  defp extract_where_clause(sql) do
    # Simplified: just extract the WHERE clause as a string for now
    case Regex.run(~r/where\s+(.+?)(?:group by|order by|limit|$)/i, sql) do
      [_, where] -> {:ok, {:raw, String.trim(where)}}
      _ -> {:ok, nil}
    end
  end

  defp extract_group_by(sql) do
    case Regex.run(~r/group by\s+(.+?)(?:order by|limit|$)/i, sql) do
      [_, fields] ->
        {:ok, fields |> String.split(",") |> Enum.map(&String.trim/1)}

      _ ->
        {:ok, []}
    end
  end

  defp extract_order_by(sql) do
    case Regex.run(~r/order by\s+(.+?)(?:limit|$)/i, sql) do
      [_, fields] ->
        items =
          fields
          |> String.split(",")
          |> Enum.map(fn field ->
            case String.split(String.trim(field)) do
              [name, dir] when dir in ["asc", "desc"] ->
                {name, String.to_atom(dir)}

              [name] ->
                {name, :asc}
            end
          end)

        {:ok, items}

      _ ->
        {:ok, []}
    end
  end

  defp extract_sql_limit(sql) do
    case Regex.run(~r/limit\s+(\d+)/i, sql) do
      [_, n] -> {:ok, String.to_integer(n)}
      _ -> {:ok, nil}
    end
  end

  # ============================================================================
  # YAML Format (Sigma-like)
  # ============================================================================

  defp yaml_to_dsl(%{"detection" => detection} = query) do
    title = Map.get(query, "title", "Untitled")
    description = Map.get(query, "description")

    filters = detection_to_filters(detection)

    dsl = %{
      source: "events",
      filters: filters,
      metadata: %{
        title: title,
        description: description,
        tags: Map.get(query, "tags", []),
        level: Map.get(query, "level", "medium")
      }
    }

    {:ok, dsl}
  end

  defp yaml_to_dsl(_), do: {:error, "Invalid YAML query format"}

  defp detection_to_filters(detection) do
    # Sigma format: detection has "selection" and "condition"
    selection = Map.get(detection, "selection", %{})
    condition = Map.get(detection, "condition", "selection")

    # Convert selection to filters
    selection
    |> Enum.map(fn {field, value} ->
      cond do
        is_list(value) ->
          {:condition, field, :in, value}

        is_binary(value) && String.starts_with?(value, "*") && String.ends_with?(value, "*") ->
          {:condition, field, :contains, String.slice(value, 1..-2)}

        is_binary(value) && String.starts_with?(value, "*") ->
          {:condition, field, :endswith, String.slice(value, 1..-1)}

        is_binary(value) && String.ends_with?(value, "*") ->
          {:condition, field, :startswith, String.slice(value, 0..-2)}

        true ->
          {:condition, field, :eq, value}
      end
    end)
  end

  # ============================================================================
  # Query Validation
  # ============================================================================

  defp check_warnings(dsl) do
    warnings = []

    # Check for overly broad queries
    warnings =
      if dsl[:filters] == [] or is_nil(dsl[:filters]) do
        [
          %{
            type: :warning,
            message: "Query has no filters. This may return a large number of results."
          }
          | warnings
        ]
      else
        warnings
      end

    # Check for missing time range
    warnings =
      if is_nil(dsl[:time_range]) do
        [
          %{
            type: :warning,
            message: "No time range specified. Query will search all data."
          }
          | warnings
        ]
      else
        warnings
      end

    # Check for expensive aggregations without grouping
    warnings =
      if dsl[:aggregations] != [] and dsl[:grouping] == [] do
        [
          %{
            type: :info,
            message: "Aggregations without grouping will compute over all results."
          }
          | warnings
        ]
      else
        warnings
      end

    warnings
  end

  @doc """
  Convert a DSL query back to visual query builder format.
  """
  def to_visual_format(dsl) do
    %{
      "conditions" => filters_to_conditions(dsl[:filters] || []),
      "logic" => "AND",
      "time_range" => dsl[:time_range],
      "aggregations" => aggregations_to_visual(dsl[:aggregations] || []),
      "grouping" => dsl[:grouping] || [],
      "sorting" => dsl[:sorting] || [],
      "limit" => dsl[:limit]
    }
  end

  defp filters_to_conditions([]), do: []

  defp filters_to_conditions(filters) do
    Enum.map(filters, fn filter ->
      case filter do
        {:condition, field, op, value} ->
          %{
            "field" => field,
            "operator" => to_string(op),
            "value" => value
          }

        {:logic, logic, conditions} ->
          %{
            "logic" => to_string(logic) |> String.upcase(),
            "conditions" => filters_to_conditions(conditions)
          }

        {:group, logic, conditions} ->
          %{
            "logic" => to_string(logic) |> String.upcase(),
            "conditions" => filters_to_conditions(conditions)
          }

        _ ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp aggregations_to_visual(aggregations) do
    Enum.map(aggregations, fn %{function: func, field: field, alias: alias_name} ->
      %{
        "function" => to_string(func),
        "field" => field,
        "alias" => alias_name
      }
    end)
  end

  @doc """
  Convert a DSL query to TQL syntax.
  """
  def to_tql(dsl) do
    parts = ["events"]

    # Add filters
    parts =
      if dsl[:filters] && dsl[:filters] != [] do
        where_clause = filters_to_tql(dsl[:filters])
        parts ++ ["| where #{where_clause}"]
      else
        parts
      end

    # Add aggregations
    parts =
      if dsl[:aggregations] && dsl[:aggregations] != [] do
        agg_clause = aggregations_to_tql(dsl[:aggregations], dsl[:grouping] || [])
        parts ++ ["| #{agg_clause}"]
      else
        parts
      end

    # Add sorting
    parts =
      if dsl[:sorting] && dsl[:sorting] != [] do
        sort_clause =
          dsl[:sorting]
          |> Enum.map(fn {field, dir} -> "#{field} #{dir}" end)
          |> Enum.join(", ")

        parts ++ ["| sort #{sort_clause}"]
      else
        parts
      end

    # Add limit
    parts =
      if dsl[:limit] do
        parts ++ ["| limit #{dsl[:limit]}"]
      else
        parts
      end

    Enum.join(parts, " ")
  end

  defp filters_to_tql(filters) do
    filters
    |> Enum.map(&filter_to_tql/1)
    |> Enum.join(" ")
  end

  defp filter_to_tql({:condition, field, op, value}) do
    op_str =
      case op do
        :eq -> "=="
        :neq -> "!="
        :gt -> ">"
        :gte -> ">="
        :lt -> "<"
        :lte -> "<="
        :contains -> "contains"
        :startswith -> "startswith"
        :endswith -> "endswith"
        :matches -> "matches"
        :in -> "in"
        _ -> to_string(op)
      end

    value_str =
      cond do
        is_binary(value) -> "\"#{value}\""
        is_list(value) -> "(#{Enum.map(value, &inspect/1) |> Enum.join(", ")})"
        true -> inspect(value)
      end

    "#{field} #{op_str} #{value_str}"
  end

  defp filter_to_tql({:logic, :and, conditions}) do
    conditions
    |> Enum.map(&filter_to_tql/1)
    |> Enum.join(" and ")
    |> then(&"(#{&1})")
  end

  defp filter_to_tql({:logic, :or, conditions}) do
    conditions
    |> Enum.map(&filter_to_tql/1)
    |> Enum.join(" or ")
    |> then(&"(#{&1})")
  end

  defp filter_to_tql({:not, condition}) do
    "not (#{filter_to_tql(condition)})"
  end

  defp aggregations_to_tql(aggs, grouping) do
    agg_str =
      aggs
      |> Enum.map(fn %{function: func, field: field, alias: alias_name} ->
        field_str = if field, do: "(#{field})", else: "()"
        "#{alias_name} = #{func}#{field_str}"
      end)
      |> Enum.join(", ")

    if grouping != [] do
      "summarize #{agg_str} by #{Enum.join(grouping, ", ")}"
    else
      "summarize #{agg_str}"
    end
  end
end
