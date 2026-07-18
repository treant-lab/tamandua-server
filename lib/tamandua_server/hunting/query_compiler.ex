defmodule TamanduaServer.Hunting.QueryCompiler do
  @moduledoc """
  Compiles a TQL AST into an executable Ecto query.

  The compiler transforms the parsed AST into Ecto query expressions,
  handling field mappings, aggregations, joins, and optimizations.

  ## Compilation Phases

  1. **Validation** - Verify AST structure and field references
  2. **Optimization** - Reorder operations for efficiency
  3. **Translation** - Convert AST nodes to Ecto expressions
  4. **Finalization** - Apply limits, projections, and sorting
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Hunting.{QueryLanguage, QueryParser}
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Agents.Agent

  @type compiled_query :: %{
    query: Ecto.Query.t(),
    source: atom(),
    projections: [String.t()] | nil,
    aggregations: [tuple()] | nil,
    has_aggregation: boolean(),
    limit: non_neg_integer() | nil,
    post_processors: [function()]
  }

  @default_limit 1000
  @max_limit 10000

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Compile a TQL query string into an executable query structure.

  ## Examples

      iex> compile("events | where event_type == \"process\" | limit 100")
      {:ok, %{query: #Ecto.Query<...>, ...}}

      iex> compile("events | where invalid_syntax")
      {:error, "Parse error: ..."}
  """
  @spec compile(String.t()) :: {:ok, compiled_query()} | {:error, String.t()}
  def compile(query_string) when is_binary(query_string) do
    with {:ok, ast} <- QueryParser.parse(query_string),
         {:ok, validated} <- validate_ast(ast),
         {:ok, optimized} <- optimize_ast(validated),
         {:ok, compiled} <- compile_ast(optimized) do
      {:ok, compiled}
    else
      {:error, message, line, col} ->
        {:error, "Parse error at line #{line}, column #{col}: #{message}"}

      {:error, message} when is_binary(message) ->
        {:error, message}

      {:error, errors} when is_list(errors) ->
        error_msgs = Enum.map_join(errors, "; ", & &1.message)
        {:error, error_msgs}
    end
  end

  @doc """
  Compile a pre-parsed AST into an executable query.
  """
  @spec compile_ast(map()) :: {:ok, compiled_query()} | {:error, String.t()}
  def compile_ast(ast) when is_map(ast) do
    source = get_source_schema(ast.source)

    if is_nil(source) do
      {:error, "Unknown table source: #{ast.source}"}
    else
      initial = %{
        query: base_query(source),
        source: source,
        source_name: ast.source,
        projections: nil,
        aggregations: nil,
        group_by: nil,
        has_aggregation: false,
        limit: @default_limit,
        sort: nil,
        post_processors: [],
        variables: %{}
      }

      result = Enum.reduce_while(ast.operators, {:ok, initial}, fn op, {:ok, acc} ->
        case compile_operator(op, acc) do
          {:ok, new_acc} -> {:cont, {:ok, new_acc}}
          {:error, _} = err -> {:halt, err}
        end
      end)

      case result do
        {:ok, compiled} ->
          # Finalize the query
          finalized = finalize_query(compiled)
          {:ok, finalized}

        {:error, _} = err ->
          err
      end
    end
  end

  # ============================================================================
  # Validation
  # ============================================================================

  defp validate_ast(ast) do
    # Basic structure validation
    cond do
      !is_map(ast) ->
        {:error, "Invalid AST structure"}

      !Map.has_key?(ast, :source) ->
        {:error, "Missing table source"}

      !is_list(ast.operators) ->
        {:error, "Invalid operators list"}

      true ->
        {:ok, ast}
    end
  end

  # ============================================================================
  # Optimization
  # ============================================================================

  defp optimize_ast(ast) do
    # Reorder operators for better query performance:
    # 1. Filters (where) first to reduce dataset early
    # 2. Projections before aggregations
    # 3. Sort and limit last

    operators = ast.operators
    |> group_by_type()
    |> merge_where_clauses()
    |> reorder_for_performance()

    {:ok, %{ast | operators: operators}}
  end

  defp group_by_type(operators) do
    Enum.group_by(operators, fn
      {:where, _} -> :filter
      {:has, _} -> :filter
      {:project, _} -> :projection
      {:project_away, _} -> :projection
      {:extend, _} -> :extend
      {:summarize, _, _} -> :aggregation
      {:sort, _} -> :sort
      {:top, _, _} -> :limit
      {:limit, _} -> :limit
      {:join, _, _, _} -> :join
      {:lookup, _, _} -> :join
      {:let, _, _} -> :let
      _ -> :other
    end)
  end

  defp merge_where_clauses(groups) do
    # Combine multiple WHERE clauses with AND
    filters = Map.get(groups, :filter, [])

    merged_filter = case filters do
      [] -> nil
      [{:where, expr}] -> {:where, expr}
      [{:has, _} = h] -> h
      filters ->
        combined = filters
        |> Enum.map(fn
          {:where, expr} -> expr
          {:has, value} -> {:comparison, "payload", :has, {:literal, value}}
        end)
        |> Enum.reduce(fn expr, acc -> {:and, acc, expr} end)

        {:where, combined}
    end

    Map.put(groups, :filter, if(merged_filter, do: [merged_filter], else: []))
  end

  defp reorder_for_performance(groups) do
    # Order: let -> join -> filter -> extend -> projection -> aggregation -> sort -> limit
    (Map.get(groups, :let, []) ++
     Map.get(groups, :join, []) ++
     Map.get(groups, :filter, []) ++
     Map.get(groups, :extend, []) ++
     Map.get(groups, :projection, []) ++
     Map.get(groups, :aggregation, []) ++
     Map.get(groups, :sort, []) ++
     Map.get(groups, :limit, []) ++
     Map.get(groups, :other, []))
    |> Enum.reject(&is_nil/1)
  end

  # ============================================================================
  # Base Query
  # ============================================================================

  defp get_source_schema("events"), do: Event
  defp get_source_schema("alerts"), do: Alert
  defp get_source_schema("agents"), do: Agent
  defp get_source_schema(_), do: nil

  defp base_query(Event) do
    from(e in Event,
      left_join: a in Agent, on: e.agent_id == a.id,
      as: :event,
      order_by: [desc: e.timestamp]
    )
  end

  defp base_query(Alert) do
    from(a in Alert,
      as: :alert,
      order_by: [desc: a.inserted_at]
    )
  end

  defp base_query(Agent) do
    from(a in Agent,
      as: :agent,
      order_by: [desc: a.last_seen]
    )
  end

  # ============================================================================
  # Operator Compilation
  # ============================================================================

  defp compile_operator({:where, expr}, acc) do
    case compile_expression(expr, acc) do
      {:ok, ecto_expr} ->
        new_query = where(acc.query, ^ecto_expr)
        {:ok, %{acc | query: new_query}}

      {:error, _} = err ->
        err
    end
  end

  defp compile_operator({:has, value}, acc) do
    # Full-text search across payload
    pattern = "%#{value}%"
    new_query = case acc.source do
      Event ->
        where(acc.query, [e], fragment("?::text ILIKE ?", e.payload, ^pattern))
      Alert ->
        where(acc.query, [a], ilike(a.description, ^pattern) or ilike(a.title, ^pattern))
      Agent ->
        where(acc.query, [a], ilike(a.hostname, ^pattern))
    end
    {:ok, %{acc | query: new_query}}
  end

  defp compile_operator({:project, fields}, acc) do
    {:ok, %{acc | projections: fields}}
  end

  defp compile_operator({:project_away, fields}, acc) do
    # Store fields to exclude - handled in post-processing
    processor = fn results ->
      field_atoms = Enum.map(fields, &String.to_atom/1)
      Enum.map(results, fn row ->
        Map.drop(row, field_atoms)
      end)
    end
    {:ok, %{acc | post_processors: [processor | acc.post_processors]}}
  end

  defp compile_operator({:extend, assignments}, acc) do
    # Store extend operations for post-processing
    processor = fn results ->
      Enum.map(results, fn row ->
        Enum.reduce(assignments, row, fn {name, expr}, r ->
          value = evaluate_expression(expr, r, acc.variables)
          Map.put(r, String.to_atom(name), value)
        end)
      end)
    end
    {:ok, %{acc | post_processors: [processor | acc.post_processors]}}
  end

  defp compile_operator({:summarize, aggs, by_fields}, acc) do
    {:ok, %{acc |
      aggregations: aggs,
      group_by: by_fields,
      has_aggregation: true
    }}
  end

  defp compile_operator({:sort, items}, acc) do
    {:ok, %{acc | sort: items}}
  end

  defp compile_operator({:top, n, field}, acc) do
    # Top N is sort desc + limit
    sort_items = [{field, :desc}]
    {:ok, %{acc | sort: sort_items, limit: min(n, @max_limit)}}
  end

  defp compile_operator({:limit, n}, acc) do
    {:ok, %{acc | limit: min(n, @max_limit)}}
  end

  defp compile_operator({:join, kind, subquery, on_field}, acc) do
    # Compile subquery
    case compile_ast(subquery) do
      {:ok, sub_compiled} ->
        # Add join to main query
        # This is simplified - real implementation would handle different join kinds
        new_query = case kind do
          :inner ->
            join(acc.query, :inner, [e], s in subquery(sub_compiled.query),
              on: field(e, ^String.to_atom(on_field)) == field(s, ^String.to_atom(on_field)))
          :left ->
            join(acc.query, :left, [e], s in subquery(sub_compiled.query),
              on: field(e, ^String.to_atom(on_field)) == field(s, ^String.to_atom(on_field)))
          :right ->
            join(acc.query, :right, [e], s in subquery(sub_compiled.query),
              on: field(e, ^String.to_atom(on_field)) == field(s, ^String.to_atom(on_field)))
          _ ->
            acc.query
        end
        {:ok, %{acc | query: new_query}}

      {:error, _} = err ->
        err
    end
  rescue
    _ -> {:ok, acc}  # Skip join on error
  end

  defp compile_operator({:lookup, table, on_field}, acc) do
    # Lookup is a left join with another table
    case get_source_schema(table) do
      nil ->
        {:error, "Unknown lookup table: #{table}"}

      schema ->
        new_query = join(acc.query, :left, [e], t in ^schema,
          on: field(e, ^String.to_atom(on_field)) == field(t, :id))
        {:ok, %{acc | query: new_query}}
    end
  rescue
    _ -> {:ok, acc}
  end

  defp compile_operator({:let, name, expr}, acc) do
    # Store variable for later use
    value = evaluate_expression(expr, %{}, acc.variables)
    {:ok, %{acc | variables: Map.put(acc.variables, name, value)}}
  end

  defp compile_operator(_, acc), do: {:ok, acc}

  # ============================================================================
  # Expression Compilation
  # ============================================================================

  defp compile_expression({:and, left, right}, acc) do
    with {:ok, l} <- compile_expression(left, acc),
         {:ok, r} <- compile_expression(right, acc) do
      {:ok, dynamic([e], ^l and ^r)}
    end
  end

  defp compile_expression({:or, left, right}, acc) do
    with {:ok, l} <- compile_expression(left, acc),
         {:ok, r} <- compile_expression(right, acc) do
      {:ok, dynamic([e], ^l or ^r)}
    end
  end

  defp compile_expression({:not, expr}, acc) do
    case compile_expression(expr, acc) do
      {:ok, e} -> {:ok, dynamic([e], not(^e))}
      err -> err
    end
  end

  defp compile_expression({:comparison, field, op, value}, acc) do
    compile_comparison(field, op, value, acc)
  end

  defp compile_expression({:field, name}, acc) do
    # Field reference in boolean context (e.g., "is_elevated" as truthy)
    case get_field_mapping(name, acc.source_name) do
      {:column, col} ->
        {:ok, dynamic([e], field(e, ^col) == true)}
      {:payload, key} ->
        {:ok, dynamic([e], fragment("(?->>?)::boolean = true", e.payload, ^key))}
      nil ->
        {:error, "Unknown field: #{name}"}
    end
  end

  defp compile_expression({:function, name, args}, acc) do
    # Functions that can be used in filters
    case name do
      "isnull" ->
        case args do
          [{:field, field_name}] ->
            case get_field_mapping(field_name, acc.source_name) do
              {:column, col} ->
                {:ok, dynamic([e], is_nil(field(e, ^col)))}
              {:payload, key} ->
                {:ok, dynamic([e], fragment("?->? IS NULL", e.payload, ^key))}
              nil ->
                {:error, "Unknown field in isnull: #{field_name}"}
            end
          _ ->
            {:error, "isnull requires a field argument"}
        end

      "isnotnull" ->
        case args do
          [{:field, field_name}] ->
            case get_field_mapping(field_name, acc.source_name) do
              {:column, col} ->
                {:ok, dynamic([e], not is_nil(field(e, ^col)))}
              {:payload, key} ->
                {:ok, dynamic([e], fragment("?->? IS NOT NULL", e.payload, ^key))}
              nil ->
                {:error, "Unknown field in isnotnull: #{field_name}"}
            end
          _ ->
            {:error, "isnotnull requires a field argument"}
        end

      "ipv4_is_private" ->
        case args do
          [{:field, field_name}] ->
            case get_field_mapping(field_name, acc.source_name) do
              {:payload, key} ->
                # Check for RFC1918 ranges
                {:ok, dynamic([e],
                  fragment("?->>? LIKE '10.%' OR ?->>? LIKE '192.168.%' OR ?->>? ~ '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'",
                    e.payload, ^key, e.payload, ^key, e.payload, ^key)
                )}
              _ ->
                {:error, "ipv4_is_private requires a payload field"}
            end
          _ ->
            {:error, "ipv4_is_private requires a field argument"}
        end

      _ ->
        # Other functions - evaluate and use as literal
        value = evaluate_expression({:function, name, args}, %{}, acc.variables)
        {:ok, dynamic([e], ^value)}
    end
  end

  defp compile_expression({:literal, value}, _acc) do
    {:ok, dynamic([e], ^value)}
  end

  defp compile_expression(_, _) do
    {:error, "Unsupported expression type"}
  end

  # ============================================================================
  # Comparison Compilation
  # ============================================================================

  defp compile_comparison(field, op, value, acc) do
    field_mapping = get_field_mapping(field, acc.source_name)
    literal_value = extract_literal(value, acc.variables)

    case {field_mapping, op} do
      {nil, _} ->
        # Try as generic payload field
        compile_payload_comparison(field, op, literal_value)

      {{:column, col}, :eq} ->
        {:ok, dynamic([e], field(e, ^col) == ^literal_value)}

      {{:column, col}, :neq} ->
        {:ok, dynamic([e], field(e, ^col) != ^literal_value)}

      {{:column, col}, :gt} ->
        {:ok, dynamic([e], field(e, ^col) > ^literal_value)}

      {{:column, col}, :gte} ->
        {:ok, dynamic([e], field(e, ^col) >= ^literal_value)}

      {{:column, col}, :lt} ->
        {:ok, dynamic([e], field(e, ^col) < ^literal_value)}

      {{:column, col}, :lte} ->
        {:ok, dynamic([e], field(e, ^col) <= ^literal_value)}

      {{:column, col}, :contains} ->
        pattern = "%#{literal_value}%"
        {:ok, dynamic([e], ilike(field(e, ^col), ^pattern))}

      {{:column, col}, :startswith} ->
        pattern = "#{literal_value}%"
        {:ok, dynamic([e], ilike(field(e, ^col), ^pattern))}

      {{:column, col}, :endswith} ->
        pattern = "%#{literal_value}"
        {:ok, dynamic([e], ilike(field(e, ^col), ^pattern))}

      {{:column, col}, :matches} ->
        {:ok, dynamic([e], fragment("? ~* ?", field(e, ^col), ^literal_value))}

      {{:column, col}, :in} when is_list(literal_value) ->
        {:ok, dynamic([e], field(e, ^col) in ^literal_value)}

      {{:column, col}, :between} ->
        {low, high} = literal_value
        {:ok, dynamic([e], field(e, ^col) >= ^low and field(e, ^col) <= ^high)}

      {{:payload, key}, op} ->
        compile_payload_comparison(key, op, literal_value)

      _ ->
        {:error, "Unsupported comparison: #{field} #{op}"}
    end
  end

  defp compile_payload_comparison(key, op, value) do
    case op do
      :eq ->
        {:ok, dynamic([e], fragment("?->>? = ?", e.payload, ^key, ^to_string(value)))}

      :neq ->
        {:ok, dynamic([e], fragment("?->>? != ? OR ?->? IS NULL", e.payload, ^key, ^to_string(value), e.payload, ^key))}

      :gt ->
        {:ok, dynamic([e], fragment("(?->>?)::numeric > ?::numeric", e.payload, ^key, ^value))}

      :gte ->
        {:ok, dynamic([e], fragment("(?->>?)::numeric >= ?::numeric", e.payload, ^key, ^value))}

      :lt ->
        {:ok, dynamic([e], fragment("(?->>?)::numeric < ?::numeric", e.payload, ^key, ^value))}

      :lte ->
        {:ok, dynamic([e], fragment("(?->>?)::numeric <= ?::numeric", e.payload, ^key, ^value))}

      :contains ->
        pattern = "%#{value}%"
        {:ok, dynamic([e], fragment("?->>? ILIKE ?", e.payload, ^key, ^pattern))}

      :startswith ->
        pattern = "#{value}%"
        {:ok, dynamic([e], fragment("?->>? ILIKE ?", e.payload, ^key, ^pattern))}

      :endswith ->
        pattern = "%#{value}"
        {:ok, dynamic([e], fragment("?->>? ILIKE ?", e.payload, ^key, ^pattern))}

      :matches ->
        {:ok, dynamic([e], fragment("?->>? ~* ?", e.payload, ^key, ^value))}

      :has ->
        pattern = "%#{value}%"
        {:ok, dynamic([e], fragment("?->>? ILIKE ?", e.payload, ^key, ^pattern))}

      :in when is_list(value) ->
        str_values = Enum.map(value, &to_string/1)
        {:ok, dynamic([e], fragment("?->>? = ANY(?)", e.payload, ^key, ^str_values))}

      :between ->
        {low, high} = value
        {:ok, dynamic([e],
          fragment("(?->>?)::numeric >= ?::numeric AND (?->>?)::numeric <= ?::numeric",
            e.payload, ^key, ^low, e.payload, ^key, ^high)
        )}

      _ ->
        {:error, "Unsupported payload comparison: #{key} #{op}"}
    end
  end

  # ============================================================================
  # Field Mapping
  # ============================================================================

  defp get_field_mapping(field, source_name) do
    mappings = QueryLanguage.field_mappings()
    source_key = String.to_atom(source_name)

    case Map.get(mappings, source_key, %{}) do
      source_mappings ->
        Map.get(source_mappings, field)
    end
  end

  # ============================================================================
  # Value Extraction
  # ============================================================================

  defp extract_literal({:literal, value}, _vars), do: value

  defp extract_literal({:field, name}, _vars) do
    # Field reference as value - return as string for comparison
    name
  end

  defp extract_literal({:function, name, args}, vars) do
    # Evaluate function
    evaluated_args = Enum.map(args, &extract_literal(&1, vars))
    evaluate_function(name, evaluated_args)
  end

  defp extract_literal(values, vars) when is_list(values) do
    Enum.map(values, &extract_literal(&1, vars))
  end

  defp extract_literal({low, high}, vars) do
    {extract_literal(low, vars), extract_literal(high, vars)}
  end

  defp extract_literal(value, _vars), do: value

  # ============================================================================
  # Function Evaluation
  # ============================================================================

  defp evaluate_function("ago", [duration]) do
    QueryLanguage.func_ago(duration)
  end

  defp evaluate_function("now", []) do
    QueryLanguage.func_now()
  end

  defp evaluate_function("datetime", [value]) do
    QueryLanguage.func_datetime(value)
  end

  defp evaluate_function("tolower", [value]) do
    QueryLanguage.func_tolower(value)
  end

  defp evaluate_function("toupper", [value]) do
    QueryLanguage.func_toupper(value)
  end

  defp evaluate_function("strlen", [value]) do
    QueryLanguage.func_strlen(value)
  end

  defp evaluate_function("base64_decode", [value]) do
    QueryLanguage.func_base64_decode(value)
  end

  defp evaluate_function("ipv4_is_private", [ip]) do
    QueryLanguage.func_ipv4_is_private(ip)
  end

  defp evaluate_function("coalesce", values) do
    QueryLanguage.func_coalesce(values)
  end

  defp evaluate_function("iif", [cond, true_val, false_val]) do
    QueryLanguage.func_iif(cond, true_val, false_val)
  end

  defp evaluate_function(_name, _args), do: nil

  # Evaluate expression against a row
  defp evaluate_expression({:literal, value}, _row, _vars), do: value

  defp evaluate_expression({:field, name}, row, _vars) do
    # Try as atom key first, then string
    Map.get(row, String.to_atom(name)) ||
    Map.get(row, name) ||
    get_in(row, [:payload, name])
  end

  defp evaluate_expression({:function, name, args}, row, vars) do
    evaluated_args = Enum.map(args, &evaluate_expression(&1, row, vars))
    evaluate_function(name, evaluated_args)
  end

  defp evaluate_expression({:comparison, left, op, right}, row, vars) do
    l = evaluate_expression({:field, left}, row, vars)
    r = evaluate_expression(right, row, vars)

    case op do
      :eq -> l == r
      :neq -> l != r
      :gt -> l > r
      :gte -> l >= r
      :lt -> l < r
      :lte -> l <= r
      :contains -> is_binary(l) and is_binary(r) and String.contains?(String.downcase(l), String.downcase(r))
      :startswith -> is_binary(l) and is_binary(r) and String.starts_with?(String.downcase(l), String.downcase(r))
      :endswith -> is_binary(l) and is_binary(r) and String.ends_with?(String.downcase(l), String.downcase(r))
      _ -> false
    end
  end

  defp evaluate_expression({:and, left, right}, row, vars) do
    evaluate_expression(left, row, vars) and evaluate_expression(right, row, vars)
  end

  defp evaluate_expression({:or, left, right}, row, vars) do
    evaluate_expression(left, row, vars) or evaluate_expression(right, row, vars)
  end

  defp evaluate_expression({:not, expr}, row, vars) do
    not evaluate_expression(expr, row, vars)
  end

  defp evaluate_expression(_, _, _), do: nil

  # ============================================================================
  # Query Finalization
  # ============================================================================

  defp finalize_query(compiled) do
    query = compiled.query

    # Apply sorting
    query = if compiled.sort do
      apply_sorting(query, compiled.sort, compiled.source_name)
    else
      query
    end

    # Apply limit
    query = if compiled.limit do
      limit(query, ^compiled.limit)
    else
      query
    end

    %{compiled | query: query}
  end

  defp apply_sorting(query, items, source_name) do
    Enum.reduce(items, query, fn {field, direction}, q ->
      try do
        case get_field_mapping(field, source_name) do
          {:column, col} ->
            case direction do
              :asc -> order_by(q, [e], asc: field(e, ^col))
              :desc -> order_by(q, [e], desc: field(e, ^col))
            end

          {:payload, key} ->
            case direction do
              :asc -> order_by(q, [e], asc: fragment("?->>?", e.payload, ^key))
              :desc -> order_by(q, [e], desc: fragment("?->>?", e.payload, ^key))
            end

          nil ->
            # Try as column name directly
            col = String.to_atom(field)
            case direction do
              :asc -> order_by(q, [e], asc: field(e, ^col))
              :desc -> order_by(q, [e], desc: field(e, ^col))
            end
        end
      rescue
        _ -> q
      end
    end)
  end
end
