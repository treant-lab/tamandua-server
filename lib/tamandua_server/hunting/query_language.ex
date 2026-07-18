defmodule TamanduaServer.Hunting.QueryLanguage do
  @moduledoc """
  Tamandua Query Language (TQL) -- ClickHouse backend.

  A structured query language for threat hunting that compiles to ClickHouse SQL.
  Inspired by S1QL (SentinelOne), KQL (Microsoft Defender), and Splunk SPL.

  ## Syntax Overview

  TQL uses `table.field` references and pipe operators:

      process.name = "powershell.exe" AND process.parent_name = "cmd.exe"
        | where timestamp > ago(24h)

      network.dst_port IN (4444, 5555, 8888) AND network.dst_ip != "10.0.0.0/8"
        | count by network.dst_ip | where count > 5

      file.action = "modify" AND file.path MATCHES "C:\\\\Windows\\\\System32\\\\*"
        | sort timestamp desc | limit 100

      dns.query MATCHES "*.xyz" OR dns.query MATCHES "*.top"
        | count by dns.query, agent_id | where count > 10

      process.name = "psexec.exe" OR (network.dst_port = 445 AND process.name = "svchost.exe")
        | timeline agent_id

  ## Table / Field Prefixes

  | Prefix      | ClickHouse Table              |
  |-------------|-------------------------------|
  | `process.*` | `tamandua.process_events`     |
  | `file.*`    | `tamandua.file_events`        |
  | `network.*` | `tamandua.network_flows`      |
  | `dns.*`     | `tamandua.dns_queries`        |
  | `registry.*`| `tamandua.registry_events`    |
  | `alert.*`   | `tamandua.alert_events`       |

  ## Operators

  Comparison: `=`, `!=`, `>`, `<`, `>=`, `<=`
  String:     `CONTAINS`, `STARTS_WITH`, `ENDS_WITH`, `MATCHES` (glob), `REGEX`
  Set:        `IN (...)`, `NOT IN (...)`
  CIDR:       `IN CIDR "10.0.0.0/8"`
  Boolean:    `AND`, `OR`, `NOT`, parentheses
  Time:       `ago(24h)`, `ago(7d)`, `ago(1h30m)`

  ## Pipe Operators

  `| where <expr>`          -- post-aggregation filter (HAVING)
  `| count by f1, f2`       -- GROUP BY with COUNT
  `| stats agg(f) by f1`    -- arbitrary aggregations
  `| sort field [asc|desc]` -- ORDER BY
  `| limit N`               -- LIMIT
  `| timeline field`        -- ORDER BY timestamp, grouped by field
  """

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Parse, compile, and execute a TQL query string against ClickHouse.
  Returns `{:ok, result_map}` or `{:error, reason}`.
  """
  @spec execute(String.t(), keyword()) :: {:ok, map()} | {:error, String.t()}
  def execute(query_string, opts \\ []) do
    start = System.monotonic_time(:millisecond)

    with {:ok, tokens} <- tokenize(query_string),
         {:ok, ast} <- parse(tokens),
         {:ok, sql} <- compile(ast, opts) do
      elapsed_compile = System.monotonic_time(:millisecond) - start

      case run_sql(sql, opts) do
        {:ok, rows} ->
          elapsed_total = System.monotonic_time(:millisecond) - start

          {:ok, %{
            data: rows,
            meta: %{
              query: query_string,
              sql: sql,
              total: length(rows),
              compile_time_ms: elapsed_compile,
              execution_time_ms: elapsed_total
            }
          }}

        {:error, _} = err ->
          err
      end
    end
  end

  @doc """
  Parse and compile a TQL query to ClickHouse SQL without executing.
  Useful for validation and EXPLAIN.
  """
  @spec to_sql(String.t(), keyword()) :: {:ok, String.t()} | {:error, String.t()}
  def to_sql(query_string, opts \\ []) do
    with {:ok, tokens} <- tokenize(query_string),
         {:ok, ast} <- parse(tokens),
         {:ok, sql} <- compile(ast, opts) do
      {:ok, sql}
    end
  end

  @doc """
  Validate a TQL query without compiling or executing.
  Returns `:ok` or `{:error, message}`.
  """
  @spec validate(String.t()) :: :ok | {:error, String.t()}
  def validate(query_string) do
    with {:ok, tokens} <- tokenize(query_string),
         {:ok, _ast} <- parse(tokens) do
      :ok
    end
  end

  # ============================================================================
  # Token Types
  # ============================================================================

  # A token is `{type, value, position}` where position is the 0-based byte
  # offset in the original query string.

  @type token :: {atom(), any(), non_neg_integer()}

  # ============================================================================
  # Lexer
  # ============================================================================

  @doc "Tokenize a TQL query string into a flat list of tokens."
  @spec tokenize(String.t()) :: {:ok, [token()]} | {:error, String.t()}
  def tokenize(input) when is_binary(input) do
    do_lex(input, 0, [])
  end

  # ---- end of input ---------------------------------------------------------
  defp do_lex(<<>>, pos, acc), do: {:ok, Enum.reverse([{:eof, nil, pos} | acc])}

  # ---- whitespace -----------------------------------------------------------
  defp do_lex(<<c, rest::binary>>, pos, acc) when c in [?\s, ?\t, ?\r, ?\n] do
    do_lex(rest, pos + 1, acc)
  end

  # ---- line comments --------------------------------------------------------
  defp do_lex(<<"//", rest::binary>>, pos, acc) do
    {remaining, new_pos} = skip_line(rest, pos + 2)
    do_lex(remaining, new_pos, acc)
  end

  # ---- pipe -----------------------------------------------------------------
  defp do_lex(<<"|", rest::binary>>, pos, acc) do
    do_lex(rest, pos + 1, [{:pipe, "|", pos} | acc])
  end

  # ---- two-char operators ---------------------------------------------------
  defp do_lex(<<"!=", rest::binary>>, pos, acc), do: do_lex(rest, pos + 2, [{:op, :neq, pos} | acc])
  defp do_lex(<<">=", rest::binary>>, pos, acc), do: do_lex(rest, pos + 2, [{:op, :gte, pos} | acc])
  defp do_lex(<<"<=", rest::binary>>, pos, acc), do: do_lex(rest, pos + 2, [{:op, :lte, pos} | acc])

  # ---- single-char operators ------------------------------------------------
  defp do_lex(<<"=", rest::binary>>, pos, acc), do: do_lex(rest, pos + 1, [{:op, :eq, pos} | acc])
  defp do_lex(<<">", rest::binary>>, pos, acc), do: do_lex(rest, pos + 1, [{:op, :gt, pos} | acc])
  defp do_lex(<<"<", rest::binary>>, pos, acc), do: do_lex(rest, pos + 1, [{:op, :lt, pos} | acc])

  # ---- punctuation ----------------------------------------------------------
  defp do_lex(<<"(", rest::binary>>, pos, acc), do: do_lex(rest, pos + 1, [{:lparen, "(", pos} | acc])
  defp do_lex(<<")", rest::binary>>, pos, acc), do: do_lex(rest, pos + 1, [{:rparen, ")", pos} | acc])
  defp do_lex(<<",", rest::binary>>, pos, acc), do: do_lex(rest, pos + 1, [{:comma, ",", pos} | acc])
  defp do_lex(<<".", rest::binary>>, pos, acc), do: do_lex(rest, pos + 1, [{:dot, ".", pos} | acc])
  defp do_lex(<<"*", rest::binary>>, pos, acc), do: do_lex(rest, pos + 1, [{:star, "*", pos} | acc])

  # ---- string literals (double-quoted) --------------------------------------
  defp do_lex(<<"\"", rest::binary>>, pos, acc) do
    case lex_string(rest, pos + 1, []) do
      {:ok, str, remaining, new_pos} ->
        do_lex(remaining, new_pos, [{:string, str, pos} | acc])

      :error ->
        {:error, "Unterminated string literal at position #{pos}"}
    end
  end

  # ---- string literals (single-quoted) --------------------------------------
  defp do_lex(<<"'", rest::binary>>, pos, acc) do
    case lex_string_sq(rest, pos + 1, []) do
      {:ok, str, remaining, new_pos} ->
        do_lex(remaining, new_pos, [{:string, str, pos} | acc])

      :error ->
        {:error, "Unterminated string literal at position #{pos}"}
    end
  end

  # ---- numbers (integer or float) -------------------------------------------
  defp do_lex(<<c, _::binary>> = input, pos, acc) when c in ?0..?9 do
    {num_str, rest, new_pos} = lex_number(input, pos, [])

    token =
      if String.contains?(num_str, ".") do
        {:float, String.to_float(num_str), pos}
      else
        {:integer, String.to_integer(num_str), pos}
      end

    do_lex(rest, new_pos, [token | acc])
  end

  # ---- identifiers / keywords ----------------------------------------------
  defp do_lex(<<c, _::binary>> = input, pos, acc) when c in ?a..?z or c in ?A..?Z or c == ?_ do
    {word, rest, new_pos} = lex_word(input, pos, [])
    token = classify_word(word, pos)
    do_lex(rest, new_pos, [token | acc])
  end

  # ---- unknown character ----------------------------------------------------
  defp do_lex(<<c, _rest::binary>>, pos, _acc) do
    {:error, "Unexpected character '#{<<c::utf8>>}' at position #{pos}"}
  end

  # -- string helpers ---------------------------------------------------------

  defp lex_string(<<>>, _pos, _acc), do: :error
  defp lex_string(<<"\\", c, rest::binary>>, pos, acc) do
    escaped = case c do
      ?n -> "\n"
      ?t -> "\t"
      ?\\ -> "\\"
      ?" -> "\""
      _ -> <<c>>
    end
    lex_string(rest, pos + 2, [escaped | acc])
  end
  defp lex_string(<<"\"", rest::binary>>, pos, acc) do
    {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary(), rest, pos + 1}
  end
  defp lex_string(<<c, rest::binary>>, pos, acc) do
    lex_string(rest, pos + 1, [<<c>> | acc])
  end

  defp lex_string_sq(<<>>, _pos, _acc), do: :error
  defp lex_string_sq(<<"\\", c, rest::binary>>, pos, acc) do
    escaped = case c do
      ?n -> "\n"
      ?t -> "\t"
      ?\\ -> "\\"
      ?' -> "'"
      _ -> <<c>>
    end
    lex_string_sq(rest, pos + 2, [escaped | acc])
  end
  defp lex_string_sq(<<"'", rest::binary>>, pos, acc) do
    {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary(), rest, pos + 1}
  end
  defp lex_string_sq(<<c, rest::binary>>, pos, acc) do
    lex_string_sq(rest, pos + 1, [<<c>> | acc])
  end

  # -- number helpers ---------------------------------------------------------

  defp lex_number(<<c, rest::binary>>, pos, acc) when c in ?0..?9 do
    lex_number(rest, pos + 1, [<<c>> | acc])
  end
  defp lex_number(<<".", c, rest::binary>>, pos, acc) when c in ?0..?9 do
    lex_number(rest, pos + 2, [<<c>>, "." | acc])
  end
  defp lex_number(rest, pos, acc) do
    {acc |> Enum.reverse() |> IO.iodata_to_binary(), rest, pos}
  end

  # -- word / identifier helpers ----------------------------------------------

  defp lex_word(<<c, rest::binary>>, pos, acc)
       when c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c == ?_ do
    lex_word(rest, pos + 1, [<<c>> | acc])
  end
  defp lex_word(rest, pos, acc) do
    {acc |> Enum.reverse() |> IO.iodata_to_binary(), rest, pos}
  end

  @keywords_set MapSet.new(~w(
    AND OR NOT IN MATCHES REGEX CONTAINS STARTS_WITH ENDS_WITH CIDR
    where count stats sort limit timeline by asc desc
    ago sum avg min max distinct_count
  ))

  defp classify_word(word, pos) do
    upper = String.upcase(word)

    cond do
      upper == "AND" -> {:kw_and, :and, pos}
      upper == "OR" -> {:kw_or, :or, pos}
      upper == "NOT" -> {:kw_not, :not, pos}
      upper == "IN" -> {:kw_in, :in, pos}
      upper == "MATCHES" -> {:op, :matches, pos}
      upper == "REGEX" -> {:op, :regex, pos}
      upper == "CONTAINS" -> {:op, :contains, pos}
      upper == "STARTS_WITH" -> {:op, :starts_with, pos}
      upper == "ENDS_WITH" -> {:op, :ends_with, pos}
      upper == "CIDR" -> {:kw_cidr, :cidr, pos}
      upper == "WHERE" -> {:kw_where, :where, pos}
      upper == "COUNT" -> {:kw_agg, :count, pos}
      upper == "SUM" -> {:kw_agg, :sum, pos}
      upper == "AVG" -> {:kw_agg, :avg, pos}
      upper == "MIN" -> {:kw_agg, :min, pos}
      upper == "MAX" -> {:kw_agg, :max, pos}
      upper == "DISTINCT_COUNT" -> {:kw_agg, :distinct_count, pos}
      upper == "STATS" -> {:kw_stats, :stats, pos}
      upper == "SORT" -> {:kw_sort, :sort, pos}
      upper == "LIMIT" -> {:kw_limit, :limit, pos}
      upper == "TIMELINE" -> {:kw_timeline, :timeline, pos}
      upper == "BY" -> {:kw_by, :by, pos}
      upper == "ASC" -> {:kw_dir, :asc, pos}
      upper == "DESC" -> {:kw_dir, :desc, pos}
      upper == "AGO" -> {:kw_ago, :ago, pos}
      MapSet.member?(@keywords_set, upper) -> {:keyword, String.downcase(word), pos}
      true -> {:ident, word, pos}
    end
  end

  # -- comment helpers --------------------------------------------------------

  defp skip_line(<<"\n", rest::binary>>, pos), do: {rest, pos + 1}
  defp skip_line(<<_, rest::binary>>, pos), do: skip_line(rest, pos + 1)
  defp skip_line(<<>>, pos), do: {<<>>, pos}

  # ============================================================================
  # AST Node Types
  # ============================================================================
  #
  # {:filter, expr}
  # {:pipe_where, expr}          -- post-aggregation HAVING
  # {:pipe_count, [field]}       -- | count by ...
  # {:pipe_stats, [{agg, field, alias}], [group_field]}
  # {:pipe_sort, [{field, :asc | :desc}]}
  # {:pipe_limit, integer}
  # {:pipe_timeline, field}
  #
  # Expressions:
  # {:and, left, right}
  # {:or, left, right}
  # {:not, expr}
  # {:comp, field, op, value}
  # {:in_list, field, [value]}
  # {:not_in_list, field, [value]}
  # {:in_cidr, field, cidr_string}
  # {:field_ref, "table.column"}
  # {:literal, value}
  # {:ago, duration_string}

  # ============================================================================
  # Parser  (recursive descent)
  # ============================================================================

  @doc "Parse a token list into an AST: `{:ok, ast}` or `{:error, msg}`."
  @spec parse([token()]) :: {:ok, map()} | {:error, String.t()}
  def parse(tokens) when is_list(tokens) do
    case parse_filter_expr(tokens) do
      {:ok, filter_expr, rest} ->
        case parse_pipes(rest, []) do
          {:ok, pipes, [{:eof, _, _}]} ->
            {:ok, %{filter: filter_expr, pipes: Enum.reverse(pipes)}}

          {:ok, pipes, []} ->
            {:ok, %{filter: filter_expr, pipes: Enum.reverse(pipes)}}

          {:ok, _pipes, [{_, val, pos} | _]} ->
            {:error, "Unexpected token #{inspect(val)} at position #{pos}"}

          {:error, _} = err ->
            err
        end

      {:error, _} = err ->
        err
    end
  end

  # -- filter expression (everything before the first pipe) -------------------

  defp parse_filter_expr([{:pipe, _, _} | _] = tokens) do
    # No filter expression; starts with pipe
    {:ok, nil, tokens}
  end
  defp parse_filter_expr([{:eof, _, _} | _] = tokens) do
    {:ok, nil, tokens}
  end
  defp parse_filter_expr(tokens) do
    parse_or(tokens)
  end

  # -- OR ---------------------------------------------------------------------

  defp parse_or(tokens) do
    case parse_and(tokens) do
      {:ok, left, [{:kw_or, _, _} | rest]} ->
        case parse_or(rest) do
          {:ok, right, remaining} -> {:ok, {:or, left, right}, remaining}
          err -> err
        end

      other ->
        other
    end
  end

  # -- AND --------------------------------------------------------------------

  defp parse_and(tokens) do
    case parse_not(tokens) do
      {:ok, left, [{:kw_and, _, _} | rest]} ->
        case parse_and(rest) do
          {:ok, right, remaining} -> {:ok, {:and, left, right}, remaining}
          err -> err
        end

      other ->
        other
    end
  end

  # -- NOT --------------------------------------------------------------------

  defp parse_not([{:kw_not, _, _} | rest]) do
    case parse_primary(rest) do
      {:ok, expr, remaining} -> {:ok, {:not, expr}, remaining}
      err -> err
    end
  end
  defp parse_not(tokens), do: parse_primary(tokens)

  # -- primary expressions ----------------------------------------------------

  # Parenthesised group
  defp parse_primary([{:lparen, _, _} | rest]) do
    case parse_or(rest) do
      {:ok, expr, [{:rparen, _, _} | remaining]} ->
        {:ok, expr, remaining}

      {:ok, _, [{_, val, pos} | _]} ->
        {:error, "Expected ')' at position #{pos}, got #{inspect(val)}"}

      {:ok, _, []} ->
        {:error, "Expected ')' but reached end of query"}

      err ->
        err
    end
  end

  # Field reference: ident DOT ident  (then comparison / IN / NOT IN / CIDR)
  defp parse_primary([{:ident, table, _}, {:dot, _, _}, {:ident, col, _} | rest]) do
    field = "#{table}.#{col}"
    parse_comparison_rest(field, rest)
  end

  # Bare identifier (e.g. timestamp, agent_id) -- used in pipe-where
  defp parse_primary([{:ident, name, _} | rest]) do
    parse_comparison_rest(name, rest)
  end

  # Aggregation reference in pipe-where (e.g. "count" used standalone)
  defp parse_primary([{:kw_agg, agg, _} | rest]) do
    parse_comparison_rest(to_string(agg), rest)
  end

  defp parse_primary([{_, val, pos} | _]) do
    {:error, "Expected field reference or '(' at position #{pos}, got #{inspect(val)}"}
  end

  defp parse_primary([]) do
    {:error, "Unexpected end of input in expression"}
  end

  # -- comparison tail after a field ------------------------------------------

  # NOT IN (...)
  defp parse_comparison_rest(field, [{:kw_not, _, _}, {:kw_in, _, _}, {:lparen, _, _} | rest]) do
    case parse_value_list(rest, []) do
      {:ok, values, [{:rparen, _, _} | remaining]} ->
        {:ok, {:not_in_list, field, values}, remaining}

      {:ok, _, [{_, val, pos} | _]} ->
        {:error, "Expected ')' after NOT IN list at position #{pos}, got #{inspect(val)}"}

      err ->
        err
    end
  end

  # IN CIDR "..."
  defp parse_comparison_rest(field, [{:kw_in, _, _}, {:kw_cidr, _, _}, {:string, cidr, _} | rest]) do
    {:ok, {:in_cidr, field, cidr}, rest}
  end

  # IN (...)
  defp parse_comparison_rest(field, [{:kw_in, _, _}, {:lparen, _, _} | rest]) do
    case parse_value_list(rest, []) do
      {:ok, values, [{:rparen, _, _} | remaining]} ->
        {:ok, {:in_list, field, values}, remaining}

      {:ok, _, [{_, val, pos} | _]} ->
        {:error, "Expected ')' after IN list at position #{pos}, got #{inspect(val)}"}

      err ->
        err
    end
  end

  # Standard comparison operators: =, !=, >, <, >=, <=, MATCHES, REGEX,
  #   CONTAINS, STARTS_WITH, ENDS_WITH
  defp parse_comparison_rest(field, [{:op, op, _} | rest]) do
    case parse_value(rest) do
      {:ok, value, remaining} ->
        {:ok, {:comp, field, op, value}, remaining}

      err ->
        err
    end
  end

  # If no operator follows, treat as a bare field reference
  defp parse_comparison_rest(field, rest) do
    {:ok, {:field_ref, field}, rest}
  end

  # -- value parsing ----------------------------------------------------------

  defp parse_value([{:string, s, _} | rest]), do: {:ok, {:literal, s}, rest}
  defp parse_value([{:integer, n, _} | rest]), do: {:ok, {:literal, n}, rest}
  defp parse_value([{:float, f, _} | rest]), do: {:ok, {:literal, f}, rest}

  # ago(24h)  /  ago(7d)  /  ago(1h30m)
  defp parse_value([{:kw_ago, _, _}, {:lparen, _, _} | rest]) do
    case lex_ago_arg(rest) do
      {:ok, duration, remaining} ->
        {:ok, {:ago, duration}, remaining}

      :error ->
        {:error, "Expected duration argument for ago(), e.g. ago(24h)"}
    end
  end

  # Bare identifier used as a value (e.g. field reference on RHS)
  defp parse_value([{:ident, name, _} | rest]) do
    {:ok, {:field_ref, name}, rest}
  end

  # Star (wildcard in glob patterns -- should be in a string, but be lenient)
  defp parse_value([{:star, _, pos} | _]) do
    {:error, "Unexpected '*' at position #{pos} -- use a quoted string for glob patterns"}
  end

  defp parse_value([{_, val, pos} | _]) do
    {:error, "Expected a value at position #{pos}, got #{inspect(val)}"}
  end

  defp parse_value([]) do
    {:error, "Unexpected end of input; expected a value"}
  end

  # -- ago() argument lexing (consumes raw chars until ')' ) ------------------

  defp lex_ago_arg(tokens) do
    # The tokens after `ago(` may be split across ident/integer tokens.
    # Collect everything until `)`.
    collect_ago(tokens, [])
  end

  defp collect_ago([{:rparen, _, _} | rest], acc) do
    duration = acc |> Enum.reverse() |> Enum.join("")

    if duration == "" do
      :error
    else
      {:ok, duration, rest}
    end
  end

  defp collect_ago([{_type, val, _} | rest], acc) when val != nil do
    collect_ago(rest, [to_string(val) | acc])
  end

  defp collect_ago(_, _acc), do: :error

  # -- comma-separated value list ---------------------------------------------

  defp parse_value_list([{:rparen, _, _} | _] = tokens, acc) do
    {:ok, Enum.reverse(acc), tokens}
  end

  defp parse_value_list(tokens, acc) do
    case parse_value(tokens) do
      {:ok, val, [{:comma, _, _} | rest]} ->
        parse_value_list(rest, [val | acc])

      {:ok, val, rest} ->
        {:ok, Enum.reverse([val | acc]), rest}

      err ->
        err
    end
  end

  # ============================================================================
  # Pipe Operator Parsing
  # ============================================================================

  defp parse_pipes([{:pipe, _, _} | rest], acc) do
    case parse_pipe_operator(rest) do
      {:ok, pipe, remaining} ->
        parse_pipes(remaining, [pipe | acc])

      {:error, _} = err ->
        err
    end
  end

  defp parse_pipes(tokens, acc), do: {:ok, acc, tokens}

  # -- | where <expr> --------------------------------------------------------
  defp parse_pipe_operator([{:kw_where, _, _} | rest]) do
    case parse_or(rest) do
      {:ok, expr, remaining} ->
        {:ok, {:pipe_where, expr}, remaining}

      err ->
        err
    end
  end

  # -- | count by field1, field2 ... ------------------------------------------
  defp parse_pipe_operator([{:kw_agg, :count, _}, {:kw_by, _, _} | rest]) do
    case parse_field_ref_list(rest, []) do
      {:ok, fields, remaining} ->
        {:ok, {:pipe_count, fields}, remaining}

      err ->
        err
    end
  end

  # -- | stats agg(field) [as alias], ... by field1, field2 -------------------
  defp parse_pipe_operator([{:kw_stats, _, _} | rest]) do
    case parse_stats_agg_list(rest, []) do
      {:ok, aggs, [{:kw_by, _, _} | after_by]} ->
        case parse_field_ref_list(after_by, []) do
          {:ok, group_fields, remaining} ->
            {:ok, {:pipe_stats, aggs, group_fields}, remaining}

          err ->
            err
        end

      {:ok, aggs, remaining} ->
        {:ok, {:pipe_stats, aggs, []}, remaining}

      err ->
        err
    end
  end

  # -- | sort field [asc|desc], ... -------------------------------------------
  defp parse_pipe_operator([{:kw_sort, _, _} | rest]) do
    case parse_sort_list(rest, []) do
      {:ok, items, remaining} ->
        {:ok, {:pipe_sort, items}, remaining}

      err ->
        err
    end
  end

  # -- | limit N --------------------------------------------------------------
  defp parse_pipe_operator([{:kw_limit, _, _}, {:integer, n, _} | rest]) do
    {:ok, {:pipe_limit, n}, rest}
  end

  defp parse_pipe_operator([{:kw_limit, _, pos} | _]) do
    {:error, "Expected integer after 'limit' at position #{pos}"}
  end

  # -- | timeline field -------------------------------------------------------
  defp parse_pipe_operator([{:kw_timeline, _, _} | rest]) do
    case parse_single_field_ref(rest) do
      {:ok, field, remaining} ->
        {:ok, {:pipe_timeline, field}, remaining}

      err ->
        err
    end
  end

  defp parse_pipe_operator([{_, val, pos} | _]) do
    {:error, "Unknown pipe operator #{inspect(val)} at position #{pos}"}
  end

  defp parse_pipe_operator([]) do
    {:error, "Unexpected end of input after '|'"}
  end

  # -- stats aggregation list: agg(field) [as alias], ... ---------------------

  defp parse_stats_agg_list(tokens, acc) do
    case parse_single_stats_agg(tokens) do
      {:ok, agg, [{:comma, _, _} | rest]} ->
        parse_stats_agg_list(rest, [agg | acc])

      {:ok, agg, rest} ->
        {:ok, Enum.reverse([agg | acc]), rest}

      # Not an aggregation -- return what we have
      _ when acc != [] ->
        {:ok, Enum.reverse(acc), tokens}

      err ->
        err
    end
  end

  defp parse_single_stats_agg([{:kw_agg, func, _}, {:lparen, _, _} | rest]) do
    # agg(field)  or  agg()  for count()
    case rest do
      [{:rparen, _, _} | after_rp] ->
        # No argument: count()
        {:ok, {func, nil, to_string(func)}, after_rp}

      _ ->
        case parse_single_field_ref(rest) do
          {:ok, field, [{:rparen, _, _} | after_rp]} ->
            alias_name = "#{func}_#{String.replace(field, ".", "_")}"
            {:ok, {func, field, alias_name}, after_rp}

          {:ok, _, [{_, val, pos} | _]} ->
            {:error, "Expected ')' after aggregation argument at position #{pos}, got #{inspect(val)}"}

          err ->
            err
        end
    end
  end

  defp parse_single_stats_agg([{_, val, pos} | _]) do
    {:error, "Expected aggregation function at position #{pos}, got #{inspect(val)}"}
  end

  # -- sort list: field [asc|desc], ... ---------------------------------------

  defp parse_sort_list(tokens, acc) do
    case parse_single_field_ref(tokens) do
      {:ok, field, [{:kw_dir, dir, _} | rest]} ->
        continue_sort_list(rest, [{field, dir} | acc])

      {:ok, field, rest} ->
        # Default direction: desc
        continue_sort_list(rest, [{field, :desc} | acc])

      _ when acc != [] ->
        {:ok, Enum.reverse(acc), tokens}

      err ->
        err
    end
  end

  defp continue_sort_list([{:comma, _, _} | rest], acc), do: parse_sort_list(rest, acc)
  defp continue_sort_list(tokens, acc), do: {:ok, Enum.reverse(acc), tokens}

  # -- field reference list (for count-by, stats-by) --------------------------

  defp parse_field_ref_list(tokens, acc) do
    case parse_single_field_ref(tokens) do
      {:ok, field, [{:comma, _, _} | rest]} ->
        parse_field_ref_list(rest, [field | acc])

      {:ok, field, rest} ->
        {:ok, Enum.reverse([field | acc]), rest}

      _ when acc != [] ->
        {:ok, Enum.reverse(acc), tokens}

      err ->
        err
    end
  end

  # -- single field reference: ident.ident or ident ---------------------------

  defp parse_single_field_ref([{:ident, a, _}, {:dot, _, _}, {:ident, b, _} | rest]) do
    {:ok, "#{a}.#{b}", rest}
  end

  defp parse_single_field_ref([{:ident, name, _} | rest]) do
    {:ok, name, rest}
  end

  defp parse_single_field_ref([{_, val, pos} | _]) do
    {:error, "Expected field reference at position #{pos}, got #{inspect(val)}"}
  end

  defp parse_single_field_ref([]) do
    {:error, "Expected field reference but reached end of input"}
  end

  # ============================================================================
  # Compiler  (AST -> ClickHouse SQL)
  # ============================================================================

  @table_map %{
    "process" => "tamandua.process_events",
    "file" => "tamandua.file_events",
    "network" => "tamandua.network_flows",
    "dns" => "tamandua.dns_queries",
    "registry" => "tamandua.registry_events",
    "alert" => "tamandua.alert_events"
  }

  # Map TQL field names to actual ClickHouse column names.
  @field_map %{
    # Process
    "process.name" => {"tamandua.process_events", "process_name"},
    "process.pid" => {"tamandua.process_events", "process_id"},
    "process.ppid" => {"tamandua.process_events", "parent_process_id"},
    "process.parent_name" => {"tamandua.process_events", "process_name"},
    "process.command_line" => {"tamandua.process_events", "command_line"},
    "process.executable_path" => {"tamandua.process_events", "executable_path"},
    "process.user" => {"tamandua.process_events", "user_name"},
    "process.hash" => {"tamandua.process_events", "file_hash"},
    "process.is_elevated" => {"tamandua.process_events", "is_elevated"},
    "process.is_signed" => {"tamandua.process_events", "is_signed"},
    "process.signer" => {"tamandua.process_events", "signer"},
    "process.event_type" => {"tamandua.process_events", "event_type"},
    # File
    "file.path" => {"tamandua.file_events", "file_path"},
    "file.action" => {"tamandua.file_events", "file_action"},
    "file.hash" => {"tamandua.file_events", "file_hash"},
    "file.size" => {"tamandua.file_events", "file_size"},
    "file.process_name" => {"tamandua.file_events", "process_name"},
    "file.user" => {"tamandua.file_events", "user_name"},
    # Network
    "network.src_ip" => {"tamandua.network_flows", "source_ip"},
    "network.dst_ip" => {"tamandua.network_flows", "dest_ip"},
    "network.src_port" => {"tamandua.network_flows", "source_port"},
    "network.dst_port" => {"tamandua.network_flows", "dest_port"},
    "network.protocol" => {"tamandua.network_flows", "protocol"},
    "network.bytes_sent" => {"tamandua.network_flows", "bytes_sent"},
    "network.bytes_received" => {"tamandua.network_flows", "bytes_received"},
    "network.process_name" => {"tamandua.network_flows", "process_name"},
    "network.direction" => {"tamandua.network_flows", "direction"},
    "network.country" => {"tamandua.network_flows", "country_code"},
    # DNS
    "dns.query" => {"tamandua.dns_queries", "query_name"},
    "dns.query_type" => {"tamandua.dns_queries", "query_type"},
    "dns.response_code" => {"tamandua.dns_queries", "response_code"},
    "dns.process_name" => {"tamandua.dns_queries", "process_name"},
    "dns.is_suspicious" => {"tamandua.dns_queries", "is_suspicious"},
    # Registry
    "registry.key" => {"tamandua.registry_events", "registry_key"},
    "registry.value" => {"tamandua.registry_events", "registry_value"},
    "registry.action" => {"tamandua.registry_events", "registry_action"},
    "registry.data" => {"tamandua.registry_events", "registry_data"},
    "registry.type" => {"tamandua.registry_events", "registry_type"},
    "registry.process_name" => {"tamandua.registry_events", "process_name"},
    "registry.user" => {"tamandua.registry_events", "user_name"},
    # Alert
    "alert.rule_name" => {"tamandua.alert_events", "rule_name"},
    "alert.severity" => {"tamandua.alert_events", "severity"},
    "alert.mitre_technique" => {"tamandua.alert_events", "mitre_technique"},
    "alert.mitre_tactic" => {"tamandua.alert_events", "mitre_tactic"},
    "alert.process_name" => {"tamandua.alert_events", "process_name"},
    "alert.command_line" => {"tamandua.alert_events", "command_line"},
    "alert.file_path" => {"tamandua.alert_events", "file_path"},
    "alert.file_hash" => {"tamandua.alert_events", "file_hash"},
    "alert.src_ip" => {"tamandua.alert_events", "source_ip"},
    "alert.dst_ip" => {"tamandua.alert_events", "dest_ip"},
    "alert.verdict" => {"tamandua.alert_events", "verdict"},
    "alert.details" => {"tamandua.alert_events", "details"}
  }

  # Shared columns present in every table.
  @shared_columns ~w(timestamp agent_id event_id organization_id)

  @doc "Compile an AST into a ClickHouse SQL string."
  @spec compile(map(), keyword()) :: {:ok, String.t()} | {:error, String.t()}
  def compile(%{filter: filter, pipes: pipes}, opts \\ []) do
    # 1. Determine the target table from field references in the AST.
    table = infer_table(filter, pipes)

    case table do
      nil ->
        {:error, "Cannot determine target table. Use table-prefixed fields like process.name, network.dst_ip, etc."}

      table_name ->
        # 2. Build WHERE clause from filter expression.
        where_sql = if filter do
          case compile_expr(filter, table_name) do
            {:ok, sql} -> sql
            {:error, _} = err -> throw(err)
          end
        else
          nil
        end

        # 3. Process pipes to build GROUP BY, HAVING, ORDER BY, LIMIT.
        {group_by, aggs, having, order_by, limit_n, is_timeline} =
          compile_pipes(pipes, table_name)

        # 4. Apply organisation scope if provided.
        org_id = Keyword.get(opts, :organization_id)
        org_clause = if org_id, do: "organization_id = '#{escape(org_id)}'", else: nil

        # 5. Assemble the full SQL.
        sql = assemble_sql(table_name, where_sql, org_clause, group_by, aggs, having, order_by, limit_n, is_timeline)

        {:ok, sql}
    end
  catch
    {:error, msg} -> {:error, msg}
  end

  # -- table inference --------------------------------------------------------

  defp infer_table(filter, pipes) do
    # Collect all field references from the AST and pick the table with the most hits.
    fields = collect_fields(filter) ++ collect_pipe_fields(pipes)

    table_votes =
      fields
      |> Enum.map(fn f ->
        case Map.get(@field_map, f) do
          {table, _col} -> table
          nil -> infer_table_from_prefix(f)
        end
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.frequencies()

    case Enum.max_by(table_votes, fn {_t, count} -> count end, fn -> nil end) do
      nil -> nil
      {table, _} -> table
    end
  end

  defp infer_table_from_prefix(field) do
    case String.split(field, ".", parts: 2) do
      [prefix, _] -> Map.get(@table_map, prefix)
      _ -> nil
    end
  end

  defp collect_fields(nil), do: []
  defp collect_fields({:comp, field, _op, _val}), do: [field]
  defp collect_fields({:in_list, field, _vals}), do: [field]
  defp collect_fields({:not_in_list, field, _vals}), do: [field]
  defp collect_fields({:in_cidr, field, _cidr}), do: [field]
  defp collect_fields({:field_ref, field}), do: [field]
  defp collect_fields({:and, l, r}), do: collect_fields(l) ++ collect_fields(r)
  defp collect_fields({:or, l, r}), do: collect_fields(l) ++ collect_fields(r)
  defp collect_fields({:not, e}), do: collect_fields(e)
  defp collect_fields(_), do: []

  defp collect_pipe_fields(pipes) do
    Enum.flat_map(pipes, fn
      {:pipe_where, expr} -> collect_fields(expr)
      {:pipe_count, fields} -> fields
      {:pipe_stats, aggs, group_fields} ->
        agg_fields = Enum.map(aggs, fn {_func, field, _alias} -> field end) |> Enum.reject(&is_nil/1)
        agg_fields ++ group_fields
      {:pipe_sort, items} -> Enum.map(items, fn {f, _dir} -> f end)
      {:pipe_timeline, field} -> [field]
      _ -> []
    end)
  end

  # -- expression compilation -------------------------------------------------

  defp compile_expr({:and, left, right}, table) do
    with {:ok, l} <- compile_expr(left, table),
         {:ok, r} <- compile_expr(right, table) do
      {:ok, "(#{l} AND #{r})"}
    end
  end

  defp compile_expr({:or, left, right}, table) do
    with {:ok, l} <- compile_expr(left, table),
         {:ok, r} <- compile_expr(right, table) do
      {:ok, "(#{l} OR #{r})"}
    end
  end

  defp compile_expr({:not, expr}, table) do
    case compile_expr(expr, table) do
      {:ok, sql} -> {:ok, "NOT (#{sql})"}
      err -> err
    end
  end

  defp compile_expr({:comp, field, op, value}, table) do
    col = resolve_column(field, table)
    val_sql = compile_value(value)

    sql = case op do
      :eq -> "#{col} = #{val_sql}"
      :neq -> "#{col} != #{val_sql}"
      :gt -> "#{col} > #{val_sql}"
      :lt -> "#{col} < #{val_sql}"
      :gte -> "#{col} >= #{val_sql}"
      :lte -> "#{col} <= #{val_sql}"
      :contains -> "#{col} LIKE #{like_contains(val_sql)}"
      :starts_with -> "#{col} LIKE #{like_starts_with(val_sql)}"
      :ends_with -> "#{col} LIKE #{like_ends_with(val_sql)}"
      :matches -> glob_to_like(col, val_sql)
      :regex -> "match(#{col}, #{val_sql})"
    end

    {:ok, sql}
  end

  defp compile_expr({:in_list, field, values}, table) do
    col = resolve_column(field, table)
    vals = Enum.map_join(values, ", ", &compile_value/1)
    {:ok, "#{col} IN (#{vals})"}
  end

  defp compile_expr({:not_in_list, field, values}, table) do
    col = resolve_column(field, table)
    vals = Enum.map_join(values, ", ", &compile_value/1)
    {:ok, "#{col} NOT IN (#{vals})"}
  end

  defp compile_expr({:in_cidr, field, cidr}, table) do
    col = resolve_column(field, table)
    {:ok, "isIPAddressInRange(#{col}, '#{escape(cidr)}')"}
  end

  defp compile_expr({:field_ref, _field}, _table) do
    # A bare field reference in boolean context -- treat as != '' or != 0
    {:ok, "1 = 1"}
  end

  defp compile_expr(nil, _table), do: {:ok, "1 = 1"}

  # -- value compilation ------------------------------------------------------

  defp compile_value({:literal, v}) when is_binary(v), do: "'#{escape(v)}'"
  defp compile_value({:literal, v}) when is_integer(v), do: "#{v}"
  defp compile_value({:literal, v}) when is_float(v), do: "#{v}"
  defp compile_value({:ago, duration}), do: compile_ago(duration)
  defp compile_value({:field_ref, f}), do: f
  defp compile_value(other), do: "'#{escape(inspect(other))}'"

  # -- ago() -> ClickHouse interval -------------------------------------------

  defp compile_ago(duration) when is_binary(duration) do
    parts = parse_duration_parts(duration)

    if parts == [] do
      "now() - INTERVAL 24 HOUR"
    else
      parts
      |> Enum.map_join(" - ", fn {n, unit} -> "INTERVAL #{n} #{unit}" end)
      |> then(&"now() - #{&1}")
    end
  end

  @duration_regex ~r/(\d+)\s*(s|m|h|d|w|mo|y)/i

  defp parse_duration_parts(duration) do
    Regex.scan(@duration_regex, String.downcase(duration))
    |> Enum.map(fn [_, count_str, unit] ->
      count = String.to_integer(count_str)

      ch_unit = case unit do
        "s" -> "SECOND"
        "m" -> "MINUTE"
        "h" -> "HOUR"
        "d" -> "DAY"
        "w" -> "WEEK"
        "mo" -> "MONTH"
        "y" -> "YEAR"
        _ -> "HOUR"
      end

      {count, ch_unit}
    end)
  end

  # -- column resolution ------------------------------------------------------

  defp resolve_column(field, _table) do
    # 1. Check the explicit field map
    case Map.get(@field_map, field) do
      {_table, col} -> col
      nil ->
        # 2. Check if it is a shared column (timestamp, agent_id, etc.)
        if field in @shared_columns do
          field
        else
          # 3. Try stripping the table prefix and using the remainder directly
          case String.split(field, ".", parts: 2) do
            [_prefix, col] -> col
            [bare] -> bare
          end
        end
    end
  end

  # -- pipe compilation -------------------------------------------------------

  defp compile_pipes(pipes, table) do
    initial = {_group_by = nil, _aggs = nil, _having = nil, _order_by = nil, _limit = nil, _timeline = false}

    Enum.reduce(pipes, initial, fn pipe, {gb, ag, hv, ob, lim, tl} ->
      case pipe do
        {:pipe_count, fields} ->
          cols = Enum.map_join(fields, ", ", &resolve_column(&1, table))
          {cols, [{:count, nil, "count"}], hv, ob, lim, tl}

        {:pipe_stats, agg_list, group_fields} ->
          cols = if group_fields != [] do
            Enum.map_join(group_fields, ", ", &resolve_column(&1, table))
          else
            gb
          end

          compiled_aggs = Enum.map(agg_list, fn {func, field, alias_name} ->
            {func, if(field, do: resolve_column(field, table)), alias_name}
          end)

          {cols, compiled_aggs, hv, ob, lim, tl}

        {:pipe_where, expr} ->
          case compile_expr(expr, table) do
            {:ok, sql} ->
              # If we already have aggregations, this is a HAVING clause.
              # Otherwise, it's appended to WHERE.
              if ag != nil do
                new_hv = if hv, do: "(#{hv}) AND (#{sql})", else: sql
                {gb, ag, new_hv, ob, lim, tl}
              else
                # This is a late WHERE -- we'll add it as an extra WHERE condition.
                # Store as having for simplicity; the assembler handles both cases.
                new_hv = if hv, do: "(#{hv}) AND (#{sql})", else: sql
                {gb, ag, new_hv, ob, lim, tl}
              end

            {:error, msg} ->
              throw({:error, msg})
          end

        {:pipe_sort, items} ->
          order = Enum.map_join(items, ", ", fn {field, dir} ->
            col = resolve_column(field, table)
            dir_str = if dir == :asc, do: "ASC", else: "DESC"
            "#{col} #{dir_str}"
          end)

          {gb, ag, hv, order, lim, tl}

        {:pipe_limit, n} ->
          {gb, ag, hv, ob, n, tl}

        {:pipe_timeline, field} ->
          col = resolve_column(field, table)
          timeline_order = "#{col}, timestamp ASC"
          {gb, ag, hv, timeline_order, lim, true}

        _ ->
          {gb, ag, hv, ob, lim, tl}
      end
    end)
  end

  # -- SQL assembly -----------------------------------------------------------

  defp assemble_sql(table, where_sql, org_clause, group_by, aggs, having, order_by, limit_n, _is_timeline) do
    # SELECT clause
    select = if aggs do
      agg_selects = Enum.map(aggs, fn {func, col, alias_name} ->
        agg_sql = case func do
          :count when col == nil -> "count()"
          :count -> "count(#{col})"
          :sum -> "sum(#{col})"
          :avg -> "avg(#{col})"
          :min -> "min(#{col})"
          :max -> "max(#{col})"
          :distinct_count -> "uniq(#{col})"
        end

        "#{agg_sql} AS #{escape_ident(alias_name)}"
      end)

      group_selects = if group_by do
        String.split(group_by, ",")
        |> Enum.map(&String.trim/1)
      else
        []
      end

      Enum.join(group_selects ++ agg_selects, ", ")
    else
      "*"
    end

    # FROM clause
    from = table

    # WHERE clause
    where_parts = [where_sql, org_clause] |> Enum.reject(&is_nil/1)

    where_clause = case where_parts do
      [] -> ""
      parts -> "WHERE " <> Enum.join(parts, " AND ")
    end

    # GROUP BY clause
    group_clause = if group_by, do: "GROUP BY #{group_by}", else: ""

    # HAVING clause
    having_clause = if having && aggs, do: "HAVING #{having}", else: ""

    # If having is set but no aggregation, treat it as additional WHERE
    extra_where = if having && is_nil(aggs), do: having, else: nil

    # Merge extra_where into WHERE
    final_where = case {where_clause, extra_where} do
      {"", nil} -> ""
      {wc, nil} -> wc
      {"", ew} -> "WHERE #{ew}"
      {wc, ew} -> "#{wc} AND #{ew}"
    end

    # ORDER BY clause
    order_clause = if order_by do
      "ORDER BY #{order_by}"
    else
      if is_nil(aggs), do: "ORDER BY timestamp DESC", else: ""
    end

    # LIMIT clause
    limit_clause = if limit_n do
      "LIMIT #{limit_n}"
    else
      if is_nil(aggs), do: "LIMIT 1000", else: "LIMIT 10000"
    end

    parts = [
      "SELECT #{select}",
      "FROM #{from}",
      final_where,
      group_clause,
      having_clause,
      order_clause,
      limit_clause,
      "FORMAT JSON"
    ]

    parts
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n")
  end

  # ============================================================================
  # SQL Execution (via ClickHouse HTTP interface)
  # ============================================================================

  @finch_name TamanduaServer.Finch

  defp run_sql(sql, opts) do
    config = Application.get_env(:tamandua_server, TamanduaServer.Telemetry.ClickHouse, [])

    unless Keyword.get(config, :enabled, false) do
      {:error, "ClickHouse integration is disabled"}
    else
      url = Keyword.get(config, :url, "http://localhost:8123")
      database = Keyword.get(config, :database, "tamandua")
      username = Keyword.get(config, :username, "default")
      password = Keyword.get(config, :password, "")
      timeout = Keyword.get(opts, :timeout, 30_000)

      full_url = "#{url}/?database=#{database}"

      headers =
        [{"content-type", "text/plain"}] ++
          if(username != "", do: [{"X-ClickHouse-User", username}], else: []) ++
          if(password != "", do: [{"X-ClickHouse-Key", password}], else: [])

      request = Finch.build(:post, full_url, headers, sql)

      case Finch.request(request, @finch_name, receive_timeout: timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          case Jason.decode(body) do
            {:ok, %{"data" => data}} -> {:ok, data}
            {:ok, other} -> {:ok, other}
            {:error, _} -> {:ok, body}
          end

        {:ok, %Finch.Response{status: status, body: body}} ->
          {:error, "ClickHouse error (HTTP #{status}): #{String.slice(body, 0, 500)}"}

        {:error, reason} ->
          {:error, "ClickHouse connection failed: #{inspect(reason)}"}
      end
    end
  rescue
    e -> {:error, "ClickHouse query failed: #{Exception.message(e)}"}
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp escape(value) when is_binary(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("'", "\\'")
    |> String.replace("\n", "")
    |> String.replace("\r", "")
  end

  defp escape(value), do: escape(to_string(value))

  defp escape_ident(name) when is_binary(name) do
    # ClickHouse identifiers: replace non-alphanumeric with underscore
    name
    |> String.replace(~r/[^a-zA-Z0-9_]/, "_")
  end

  # LIKE helpers -- strip surrounding quotes from the value string, then wrap.
  defp strip_quotes(val_sql) do
    val_sql
    |> String.trim_leading("'")
    |> String.trim_trailing("'")
  end

  defp like_contains(val_sql) do
    inner = strip_quotes(val_sql) |> escape_like()
    "'%#{inner}%'"
  end

  defp like_starts_with(val_sql) do
    inner = strip_quotes(val_sql) |> escape_like()
    "'#{inner}%'"
  end

  defp like_ends_with(val_sql) do
    inner = strip_quotes(val_sql) |> escape_like()
    "'%#{inner}'"
  end

  defp escape_like(s) do
    s
    |> String.replace("%", "\\%")
    |> String.replace("_", "\\_")
  end

  # Glob-to-LIKE: Convert glob patterns (* -> %, ? -> _) into a LIKE expression.
  defp glob_to_like(col, val_sql) do
    inner = strip_quotes(val_sql)

    like_pattern =
      inner
      |> String.replace("\\*", "\x00ESCAPED_STAR\x00")
      |> String.replace("\\?", "\x00ESCAPED_QMARK\x00")
      |> String.replace("%", "\\%")
      |> String.replace("_", "\\_")
      |> String.replace("*", "%")
      |> String.replace("?", "_")
      |> String.replace("\x00ESCAPED_STAR\x00", "\\*")
      |> String.replace("\x00ESCAPED_QMARK\x00", "\\?")

    "#{col} LIKE '#{like_pattern}'"
  end

  # ============================================================================
  # Public helpers for external consumers (backward compat)
  # ============================================================================

  @doc "Reserved keywords in TQL."
  def keywords do
    MapSet.to_list(@keywords_set) |> Enum.map(&String.downcase/1) |> Enum.sort()
  end

  @doc "Table sources mapping."
  def table_sources, do: @table_map

  @doc "Comparison operators."
  def operators do
    %{
      "=" => :eq, "!=" => :neq, ">" => :gt, "<" => :lt, ">=" => :gte, "<=" => :lte,
      "CONTAINS" => :contains, "STARTS_WITH" => :starts_with, "ENDS_WITH" => :ends_with,
      "MATCHES" => :matches, "REGEX" => :regex, "IN" => :in, "NOT IN" => :not_in,
      "IN CIDR" => :in_cidr
    }
  end

  @doc "Aggregation functions."
  def aggregation_functions, do: ~w(count sum avg min max distinct_count)

  @doc "Scalar functions."
  def scalar_functions, do: %{"ago" => :ago}

  @doc "Field mappings (exposed for the schema endpoint)."
  def field_mappings, do: @field_map

  @doc "Parse a duration string into total seconds."
  def parse_duration(duration) when is_binary(duration) do
    parts = parse_duration_parts(duration)

    if parts == [] do
      :error
    else
      seconds =
        Enum.reduce(parts, 0, fn {n, unit}, acc ->
          multiplier = case unit do
            "SECOND" -> 1
            "MINUTE" -> 60
            "HOUR" -> 3600
            "DAY" -> 86400
            "WEEK" -> 604_800
            "MONTH" -> 2_592_000
            "YEAR" -> 31_536_000
            _ -> 3600
          end

          acc + n * multiplier
        end)

      {:ok, seconds}
    end
  end

  @doc "ago() - compute a DateTime shifted back by the given duration."
  def func_ago(duration) when is_binary(duration) do
    case parse_duration(duration) do
      {:ok, seconds} -> DateTime.utc_now() |> DateTime.add(-seconds, :second)
      :error -> DateTime.utc_now() |> DateTime.add(-86400, :second)
    end
  end

  @doc "now() - current UTC timestamp."
  def func_now, do: DateTime.utc_now()

  @doc "Parse an ISO-8601 datetime string."
  def func_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, dt, _} -> dt
      _ ->
        case NaiveDateTime.from_iso8601(value) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ -> nil
        end
    end
  end
  def func_datetime(value), do: value

  @doc "tolower() - lowercase a string (nil for non-strings)."
  def func_tolower(value) when is_binary(value), do: String.downcase(value)
  def func_tolower(_), do: nil

  @doc "toupper() - uppercase a string (nil for non-strings)."
  def func_toupper(value) when is_binary(value), do: String.upcase(value)
  def func_toupper(_), do: nil

  @doc "strlen() - number of characters in a string (nil for non-strings)."
  def func_strlen(value) when is_binary(value), do: String.length(value)
  def func_strlen(_), do: nil

  @doc "base64_decode() - decode a Base64 string (nil on invalid input)."
  def func_base64_decode(value) when is_binary(value) do
    case Base.decode64(value, ignore: :whitespace) do
      {:ok, decoded} ->
        decoded

      :error ->
        case Base.decode64(value, ignore: :whitespace, padding: false) do
          {:ok, decoded} -> decoded
          :error -> nil
        end
    end
  end

  def func_base64_decode(_), do: nil

  @doc """
  ipv4_is_private() - true when the IPv4 address is in an RFC 1918 private
  range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16); nil for invalid input.
  """
  def func_ipv4_is_private(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, {10, _, _, _}} -> true
      {:ok, {172, b, _, _}} when b >= 16 and b <= 31 -> true
      {:ok, {192, 168, _, _}} -> true
      {:ok, {_, _, _, _}} -> false
      _ -> nil
    end
  end

  def func_ipv4_is_private(_), do: nil

  @doc "coalesce() - first non-nil value in the argument list."
  def func_coalesce(values) when is_list(values) do
    Enum.find(values, &(not is_nil(&1)))
  end

  def func_coalesce(_), do: nil

  @doc "iif() - conditional: returns true_val when condition is truthy."
  def func_iif(condition, true_val, false_val) do
    if condition, do: true_val, else: false_val
  end
end
