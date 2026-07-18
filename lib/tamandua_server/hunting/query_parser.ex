defmodule TamanduaServer.Hunting.QueryParser do
  @moduledoc """
  Recursive descent parser for Tamandua Query Language (TQL).

  Parses query strings into an Abstract Syntax Tree (AST) that can be
  compiled into Ecto queries by the QueryCompiler module.

  ## Grammar (simplified EBNF)

  ```
  query           = table_source { pipe_operator }
  table_source    = identifier
  pipe_operator   = "|" operator
  operator        = where_op | project_op | extend_op | summarize_op |
                    sort_op | top_op | limit_op | join_op | let_op | has_op

  where_op        = "where" expression
  has_op          = "has" string_literal
  project_op      = "project" field_list | "project-away" field_list
  extend_op       = "extend" assignment_list
  summarize_op    = "summarize" agg_list [ "by" field_list ]
  sort_op         = ("sort" | "order") ["by"] sort_list
  top_op          = "top" integer "by" expression
  limit_op        = ("limit" | "take") integer
  join_op         = "join" ["kind" "=" join_kind] "(" subquery ")" "on" field
  let_op          = "let" identifier "=" expression

  expression      = or_expression
  or_expression   = and_expression { "or" and_expression }
  and_expression  = not_expression { "and" not_expression }
  not_expression  = ["not"] primary_expression
  primary_expression = comparison | "(" expression ")" | function_call | field

  comparison      = field comp_op value
                  | field "in" "(" value_list ")"
                  | field "between" value "and" value
                  | field string_op string_literal

  comp_op         = "==" | "!=" | ">" | ">=" | "<" | "<="
  string_op       = "contains" | "!contains" | "startswith" | "endswith" | "matches"

  field           = identifier { "." identifier }
  value           = string_literal | number | boolean | null | function_call
  function_call   = identifier "(" [ arg_list ] ")"
  arg_list        = expression { "," expression }

  agg_list        = agg_expr { "," agg_expr }
  agg_expr        = [ identifier "=" ] agg_function "(" [ field ] ")"
  agg_function    = "count" | "sum" | "avg" | "min" | "max" | "dcount"

  sort_list       = sort_item { "," sort_item }
  sort_item       = field [ "asc" | "desc" ]

  field_list      = field { "," field }
  assignment_list = assignment { "," assignment }
  assignment      = identifier "=" expression

  identifier      = letter { letter | digit | "_" }
  string_literal  = "\"" { char } "\"" | "'" { char } "'"
  number          = digit { digit } [ "." digit { digit } ]
  boolean         = "true" | "false"
  null            = "null"
  ```
  """

  alias TamanduaServer.Hunting.QueryLanguage

  @type token :: {atom(), any(), {non_neg_integer(), non_neg_integer()}}
  @type tokens :: [token()]
  @type ast :: map()
  @type parse_error :: {:error, String.t(), non_neg_integer(), non_neg_integer()}

  # Reserved keywords
  @keywords QueryLanguage.keywords()

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Parse a TQL query string into an AST.

  ## Examples

      iex> parse("events | where event_type == \"process\"")
      {:ok, %{source: "events", operators: [...]}}

      iex> parse("events | invalid")
      {:error, "Unexpected token", 10, 17}
  """
  @spec parse(String.t()) :: {:ok, ast()} | parse_error()
  def parse(query) when is_binary(query) do
    query
    |> tokenize()
    |> parse_tokens()
  end

  @doc """
  Parse and validate a query, returning detailed error information.
  """
  @spec parse_with_errors(String.t()) :: {:ok, ast()} | {:error, [map()]}
  def parse_with_errors(query) when is_binary(query) do
    case tokenize(query) do
      {:error, errors} ->
        {:error, errors}

      tokens ->
        case parse_tokens(tokens) do
          {:ok, ast} ->
            {:ok, ast}

          {:error, message, line, col} ->
            {:error, [%{message: message, line: line, column: col}]}
        end
    end
  end

  # ============================================================================
  # Tokenizer
  # ============================================================================

  @doc """
  Tokenize a query string into a list of tokens.
  """
  @spec tokenize(String.t()) :: tokens() | {:error, [map()]}
  def tokenize(input) when is_binary(input) do
    do_tokenize(input, 1, 1, [])
  end

  defp do_tokenize("", _line, _col, acc), do: Enum.reverse([{:eof, nil, {0, 0}} | acc])

  # Whitespace
  defp do_tokenize(<<"\n", rest::binary>>, line, _col, acc) do
    do_tokenize(rest, line + 1, 1, acc)
  end

  defp do_tokenize(<<c, rest::binary>>, line, col, acc) when c in [?\s, ?\t, ?\r] do
    do_tokenize(rest, line, col + 1, acc)
  end

  # Comments (// style)
  defp do_tokenize(<<"//", rest::binary>>, line, _col, acc) do
    {_, remaining} = consume_until_newline(rest)
    do_tokenize(remaining, line + 1, 1, acc)
  end

  # Pipe operator
  defp do_tokenize(<<"|", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 1, [{:pipe, "|", {line, col}} | acc])
  end

  # Comparison operators (must check multi-char first)
  defp do_tokenize(<<"==", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 2, [{:op, "==", {line, col}} | acc])
  end

  defp do_tokenize(<<"!=", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 2, [{:op, "!=", {line, col}} | acc])
  end

  defp do_tokenize(<<"<>", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 2, [{:op, "!=", {line, col}} | acc])
  end

  defp do_tokenize(<<">=", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 2, [{:op, ">=", {line, col}} | acc])
  end

  defp do_tokenize(<<"<=", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 2, [{:op, "<=", {line, col}} | acc])
  end

  defp do_tokenize(<<">", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 1, [{:op, ">", {line, col}} | acc])
  end

  defp do_tokenize(<<"<", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 1, [{:op, "<", {line, col}} | acc])
  end

  defp do_tokenize(<<"=", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 1, [{:op, "=", {line, col}} | acc])
  end

  # Parentheses
  defp do_tokenize(<<"(", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 1, [{:lparen, "(", {line, col}} | acc])
  end

  defp do_tokenize(<<")", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 1, [{:rparen, ")", {line, col}} | acc])
  end

  # Comma
  defp do_tokenize(<<",", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 1, [{:comma, ",", {line, col}} | acc])
  end

  # Dot
  defp do_tokenize(<<".", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 1, [{:dot, ".", {line, col}} | acc])
  end

  # String literals (double quotes)
  defp do_tokenize(<<"\"", rest::binary>>, line, col, acc) do
    case consume_string(rest, "\"", []) do
      {:ok, str, remaining, consumed_len} ->
        do_tokenize(remaining, line, col + consumed_len + 2, [{:string, str, {line, col}} | acc])
      {:error, _} ->
        {:error, [%{message: "Unterminated string literal", line: line, column: col}]}
    end
  end

  # String literals (single quotes)
  defp do_tokenize(<<"'", rest::binary>>, line, col, acc) do
    case consume_string(rest, "'", []) do
      {:ok, str, remaining, consumed_len} ->
        do_tokenize(remaining, line, col + consumed_len + 2, [{:string, str, {line, col}} | acc])
      {:error, _} ->
        {:error, [%{message: "Unterminated string literal", line: line, column: col}]}
    end
  end

  # Numbers (including negative and decimals)
  defp do_tokenize(<<c, _rest::binary>> = input, line, col, acc) when c in ?0..?9 do
    {num_str, remaining} = consume_number(input)
    token = if String.contains?(num_str, ".") do
      {:float, String.to_float(num_str), {line, col}}
    else
      {:integer, String.to_integer(num_str), {line, col}}
    end
    do_tokenize(remaining, line, col + String.length(num_str), [token | acc])
  end

  # Negative numbers
  defp do_tokenize(<<"-", c, _rest::binary>> = input, line, col, acc) when c in ?0..?9 do
    {num_str, remaining} = consume_number(input)
    token = if String.contains?(num_str, ".") do
      {:float, String.to_float(num_str), {line, col}}
    else
      {:integer, String.to_integer(num_str), {line, col}}
    end
    do_tokenize(remaining, line, col + String.length(num_str), [token | acc])
  end

  # Minus (if not followed by digit)
  defp do_tokenize(<<"-", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 1, [{:op, "-", {line, col}} | acc])
  end

  # Plus
  defp do_tokenize(<<"+", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 1, [{:op, "+", {line, col}} | acc])
  end

  # Star (multiply or wildcard)
  defp do_tokenize(<<"*", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 1, [{:star, "*", {line, col}} | acc])
  end

  # Slash (divide)
  defp do_tokenize(<<"/", rest::binary>>, line, col, acc) do
    do_tokenize(rest, line, col + 1, [{:op, "/", {line, col}} | acc])
  end

  # Identifiers and keywords
  defp do_tokenize(<<c, _rest::binary>> = input, line, col, acc) when c in ?a..?z or c in ?A..?Z or c == ?_ do
    {ident, remaining} = consume_identifier(input)
    lower = String.downcase(ident)

    token = cond do
      lower in @keywords -> {:keyword, lower, {line, col}}
      lower in ["true", "false"] -> {:boolean, lower == "true", {line, col}}
      lower == "null" -> {:null, nil, {line, col}}
      true -> {:ident, ident, {line, col}}
    end

    do_tokenize(remaining, line, col + String.length(ident), [token | acc])
  end

  # Unknown character
  defp do_tokenize(<<c, rest::binary>>, line, col, acc) do
    # Skip unknown characters with warning
    IO.warn("Unknown character: #{<<c>>} at line #{line}, col #{col}")
    do_tokenize(rest, line, col + 1, acc)
  end

  # Token consumption helpers

  defp consume_until_newline(""), do: {"", ""}
  defp consume_until_newline(<<"\n", rest::binary>>), do: {"", rest}
  defp consume_until_newline(<<c, rest::binary>>) do
    {consumed, remaining} = consume_until_newline(rest)
    {<<c>> <> consumed, remaining}
  end

  defp consume_string("", _delim, _acc), do: {:error, :unterminated}
  defp consume_string(<<delim, rest::binary>>, <<delim>>, acc) do
    {:ok, IO.iodata_to_binary(Enum.reverse(acc)), rest, length(acc)}
  end
  defp consume_string(<<"\\", c, rest::binary>>, delim, acc) do
    # Handle escape sequences
    escaped = case c do
      ?n -> "\n"
      ?t -> "\t"
      ?r -> "\r"
      ?\\ -> "\\"
      ?" -> "\""
      ?' -> "'"
      _ -> <<c>>
    end
    consume_string(rest, delim, [escaped | acc])
  end
  defp consume_string(<<c, rest::binary>>, delim, acc) do
    consume_string(rest, delim, [<<c>> | acc])
  end

  defp consume_number(input, acc \\ [])
  defp consume_number(<<c, rest::binary>>, acc) when c in ?0..?9 do
    consume_number(rest, [<<c>> | acc])
  end
  defp consume_number(<<".", c, rest::binary>>, acc) when c in ?0..?9 do
    consume_number(rest, [<<c>>, "." | acc])
  end
  defp consume_number(rest, acc) do
    {IO.iodata_to_binary(Enum.reverse(acc)), rest}
  end

  defp consume_identifier(input, acc \\ [])
  defp consume_identifier(<<c, rest::binary>>, acc) when c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c == ?_ do
    consume_identifier(rest, [<<c>> | acc])
  end
  defp consume_identifier(rest, acc) do
    {IO.iodata_to_binary(Enum.reverse(acc)), rest}
  end

  # ============================================================================
  # Parser
  # ============================================================================

  defp parse_tokens(tokens) do
    case parse_query(tokens) do
      {:ok, ast, [{:eof, _, _}]} -> {:ok, ast}
      {:ok, ast, []} -> {:ok, ast}
      {:ok, _ast, [{_, val, {line, col}} | _]} ->
        {:error, "Unexpected token: #{inspect(val)}", line, col}
      {:error, msg, line, col} -> {:error, msg, line, col}
    end
  end

  # Parse: query = table_source { pipe_operator }
  defp parse_query([{:ident, source, _} | rest]) do
    case parse_operators(rest, []) do
      {:ok, operators, remaining} ->
        ast = %{
          source: source,
          operators: Enum.reverse(operators)
        }
        {:ok, ast, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_query([{:keyword, source, _} | rest]) when source in ["events", "alerts", "agents"] do
    case parse_operators(rest, []) do
      {:ok, operators, remaining} ->
        ast = %{
          source: source,
          operators: Enum.reverse(operators)
        }
        {:ok, ast, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_query([{_, val, {line, col}} | _]) do
    {:error, "Expected table source (events, alerts, agents), got: #{inspect(val)}", line, col}
  end

  defp parse_query([]) do
    {:error, "Empty query", 1, 1}
  end

  # Parse: pipe_operator = "|" operator
  defp parse_operators([{:pipe, _, _} | rest], acc) do
    case parse_operator(rest) do
      {:ok, op, remaining} ->
        parse_operators(remaining, [op | acc])

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_operators(tokens, acc), do: {:ok, acc, tokens}

  # Parse: operator = where_op | project_op | ...
  defp parse_operator([{:keyword, "where", _} | rest]) do
    parse_where(rest)
  end

  defp parse_operator([{:keyword, "has", _} | rest]) do
    parse_has(rest)
  end

  defp parse_operator([{:keyword, "project", _}, {:op, "-", _} | [{:ident, "away", _} | rest]]) do
    parse_project_away(rest)
  end

  defp parse_operator([{:keyword, "project", _} | rest]) do
    parse_project(rest)
  end

  defp parse_operator([{:keyword, "extend", _} | rest]) do
    parse_extend(rest)
  end

  defp parse_operator([{:keyword, "summarize", _} | rest]) do
    parse_summarize(rest)
  end

  defp parse_operator([{:keyword, "sort", _} | rest]) do
    parse_sort(rest)
  end

  defp parse_operator([{:keyword, "order", _} | rest]) do
    parse_sort(rest)
  end

  defp parse_operator([{:keyword, "top", _} | rest]) do
    parse_top(rest)
  end

  defp parse_operator([{:keyword, "limit", _} | rest]) do
    parse_limit(rest)
  end

  defp parse_operator([{:keyword, "take", _} | rest]) do
    parse_limit(rest)
  end

  defp parse_operator([{:keyword, "join", _} | rest]) do
    parse_join(rest)
  end

  defp parse_operator([{:keyword, "lookup", _} | rest]) do
    parse_lookup(rest)
  end

  defp parse_operator([{:keyword, "let", _} | rest]) do
    parse_let(rest)
  end

  defp parse_operator([{_, val, {line, col}} | _]) do
    {:error, "Unknown operator: #{inspect(val)}", line, col}
  end

  # ============================================================================
  # Operator Parsers
  # ============================================================================

  # Parse: where_op = "where" expression
  defp parse_where(tokens) do
    case parse_expression(tokens) do
      {:ok, expr, remaining} ->
        {:ok, {:where, expr}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  # Parse: has_op = "has" string_literal
  defp parse_has([{:string, value, _} | rest]) do
    {:ok, {:has, value}, rest}
  end

  defp parse_has([{_, val, {line, col}} | _]) do
    {:error, "Expected string after 'has', got: #{inspect(val)}", line, col}
  end

  # Parse: project_op = "project" field_list
  defp parse_project(tokens) do
    case parse_field_list(tokens) do
      {:ok, fields, remaining} ->
        {:ok, {:project, fields}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  # Parse: project-away field_list
  defp parse_project_away(tokens) do
    case parse_field_list(tokens) do
      {:ok, fields, remaining} ->
        {:ok, {:project_away, fields}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  # Parse: extend_op = "extend" assignment_list
  defp parse_extend(tokens) do
    case parse_assignment_list(tokens) do
      {:ok, assignments, remaining} ->
        {:ok, {:extend, assignments}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  # Parse: summarize_op = "summarize" agg_list [ "by" field_list ]
  defp parse_summarize(tokens) do
    case parse_aggregation_list(tokens) do
      {:ok, aggs, [{:keyword, "by", _} | rest]} ->
        case parse_field_list(rest) do
          {:ok, by_fields, remaining} ->
            {:ok, {:summarize, aggs, by_fields}, remaining}

          {:error, _, _, _} = error ->
            error
        end

      {:ok, aggs, remaining} ->
        {:ok, {:summarize, aggs, []}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  # Parse: sort_op = "sort" ["by"] sort_list
  defp parse_sort([{:keyword, "by", _} | rest]) do
    parse_sort_list(rest)
  end

  defp parse_sort(tokens) do
    parse_sort_list(tokens)
  end

  defp parse_sort_list(tokens) do
    case parse_sort_items(tokens, []) do
      {:ok, items, remaining} ->
        {:ok, {:sort, Enum.reverse(items)}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_sort_items(tokens, acc) do
    case parse_field_name(tokens) do
      {:ok, field, [{:keyword, dir, _} | rest]} when dir in ["asc", "desc"] ->
        direction = String.to_atom(dir)
        parse_sort_items_continue(rest, [{field, direction} | acc])

      {:ok, field, rest} ->
        # Default to desc
        parse_sort_items_continue(rest, [{field, :desc} | acc])

      {:error, _, _, _} = error when acc == [] ->
        error

      _ ->
        {:ok, acc, tokens}
    end
  end

  defp parse_sort_items_continue([{:comma, _, _} | rest], acc) do
    parse_sort_items(rest, acc)
  end

  defp parse_sort_items_continue(tokens, acc) do
    {:ok, acc, tokens}
  end

  # Parse: top_op = "top" integer "by" expression
  defp parse_top([{:integer, n, _}, {:keyword, "by", _} | rest]) do
    case parse_field_name(rest) do
      {:ok, field, remaining} ->
        {:ok, {:top, n, field}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_top([{_, val, {line, col}} | _]) do
    {:error, "Expected integer after 'top', got: #{inspect(val)}", line, col}
  end

  # Parse: limit_op = "limit" | "take" integer
  defp parse_limit([{:integer, n, _} | rest]) do
    {:ok, {:limit, n}, rest}
  end

  defp parse_limit([{_, val, {line, col}} | _]) do
    {:error, "Expected integer after 'limit', got: #{inspect(val)}", line, col}
  end

  # Parse: join_op = "join" ["kind" "=" join_kind] "(" subquery ")" "on" field
  defp parse_join([{:keyword, "kind", _}, {:op, "=", _}, {:ident, kind, _} | rest]) do
    do_parse_join(rest, String.to_atom(kind))
  end

  defp parse_join(tokens) do
    do_parse_join(tokens, :inner)
  end

  defp do_parse_join([{:lparen, _, _} | rest], kind) do
    case parse_query(rest) do
      {:ok, subquery, [{:rparen, _, _}, {:keyword, "on", _} | after_on]} ->
        case parse_field_name(after_on) do
          {:ok, field, remaining} ->
            {:ok, {:join, kind, subquery, field}, remaining}

          {:error, _, _, _} = error ->
            error
        end

      {:ok, _subquery, [{_, val, {line, col}} | _]} ->
        {:error, "Expected ')' and 'on' after join subquery, got: #{inspect(val)}", line, col}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp do_parse_join([{:ident, table, _}, {:keyword, "on", _} | rest], kind) do
    # Simple table reference instead of subquery
    case parse_field_name(rest) do
      {:ok, field, remaining} ->
        subquery = %{source: table, operators: []}
        {:ok, {:join, kind, subquery, field}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp do_parse_join([{_, val, {line, col}} | _], _kind) do
    {:error, "Expected '(' or table name after 'join', got: #{inspect(val)}", line, col}
  end

  # Parse: lookup_op = "lookup" table "on" field
  defp parse_lookup([{:ident, table, _}, {:keyword, "on", _} | rest]) do
    case parse_field_name(rest) do
      {:ok, field, remaining} ->
        {:ok, {:lookup, table, field}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_lookup([{_, val, {line, col}} | _]) do
    {:error, "Expected table name after 'lookup', got: #{inspect(val)}", line, col}
  end

  # Parse: let_op = "let" identifier "=" expression
  defp parse_let([{:ident, name, _}, {:op, "=", _} | rest]) do
    case parse_expression(rest) do
      {:ok, expr, remaining} ->
        {:ok, {:let, name, expr}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_let([{_, val, {line, col}} | _]) do
    {:error, "Expected identifier after 'let', got: #{inspect(val)}", line, col}
  end

  # ============================================================================
  # Expression Parsers
  # ============================================================================

  # Parse: expression = or_expression
  defp parse_expression(tokens) do
    parse_or_expression(tokens)
  end

  # Parse: or_expression = and_expression { "or" and_expression }
  defp parse_or_expression(tokens) do
    case parse_and_expression(tokens) do
      {:ok, left, [{:keyword, "or", _} | rest]} ->
        case parse_or_expression(rest) do
          {:ok, right, remaining} ->
            {:ok, {:or, left, right}, remaining}

          {:error, _, _, _} = error ->
            error
        end

      result ->
        result
    end
  end

  # Parse: and_expression = not_expression { "and" not_expression }
  defp parse_and_expression(tokens) do
    case parse_not_expression(tokens) do
      {:ok, left, [{:keyword, "and", _} | rest]} ->
        case parse_and_expression(rest) do
          {:ok, right, remaining} ->
            {:ok, {:and, left, right}, remaining}

          {:error, _, _, _} = error ->
            error
        end

      result ->
        result
    end
  end

  # Parse: not_expression = ["not"] primary_expression
  defp parse_not_expression([{:keyword, "not", _} | rest]) do
    case parse_primary_expression(rest) do
      {:ok, expr, remaining} ->
        {:ok, {:not, expr}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_not_expression(tokens) do
    parse_primary_expression(tokens)
  end

  # Parse: primary_expression = comparison | "(" expression ")" | function_call | value
  defp parse_primary_expression([{:lparen, _, _} | rest]) do
    case parse_expression(rest) do
      {:ok, expr, [{:rparen, _, _} | remaining]} ->
        {:ok, expr, remaining}

      {:ok, _expr, [{_, val, {line, col}} | _]} ->
        {:error, "Expected ')', got: #{inspect(val)}", line, col}

      {:error, _, _, _} = error ->
        error
    end
  end

  # Function call or field comparison
  defp parse_primary_expression([{:ident, name, pos} | rest]) do
    case rest do
      [{:lparen, _, _} | after_lparen] ->
        # Function call
        parse_function_call(name, pos, after_lparen)

      [{:dot, _, _} | _] ->
        # Dotted field name, then possibly comparison
        parse_comparison_or_field([{:ident, name, pos} | rest])

      [{:op, _, _} | _] ->
        # Comparison
        parse_comparison_or_field([{:ident, name, pos} | rest])

      [{:keyword, kw, _} | _] when kw in ["contains", "startswith", "endswith", "matches", "in", "between", "has"] ->
        # String operator comparison
        parse_comparison_or_field([{:ident, name, pos} | rest])

      _ ->
        # Just a field reference
        {:ok, {:field, name}, rest}
    end
  end

  # Boolean literal
  defp parse_primary_expression([{:boolean, val, _} | rest]) do
    {:ok, {:literal, val}, rest}
  end

  # Null literal
  defp parse_primary_expression([{:null, _, _} | rest]) do
    {:ok, {:literal, nil}, rest}
  end

  # String literal
  defp parse_primary_expression([{:string, val, _} | rest]) do
    {:ok, {:literal, val}, rest}
  end

  # Number literal
  defp parse_primary_expression([{:integer, val, _} | rest]) do
    {:ok, {:literal, val}, rest}
  end

  defp parse_primary_expression([{:float, val, _} | rest]) do
    {:ok, {:literal, val}, rest}
  end

  # Star (wildcard)
  defp parse_primary_expression([{:star, _, _} | rest]) do
    {:ok, {:wildcard}, rest}
  end

  defp parse_primary_expression([{_, val, {line, col}} | _]) do
    {:error, "Unexpected token in expression: #{inspect(val)}", line, col}
  end

  defp parse_primary_expression([]) do
    {:error, "Unexpected end of expression", 0, 0}
  end

  # Parse comparison or field reference
  defp parse_comparison_or_field(tokens) do
    case parse_field_name(tokens) do
      {:ok, field, [{:op, op, _} | rest]} ->
        # Standard comparison
        case parse_value(rest) do
          {:ok, value, remaining} ->
            {:ok, {:comparison, field, operator_to_atom(op), value}, remaining}

          {:error, _, _, _} = error ->
            error
        end

      {:ok, field, [{:keyword, "contains", _} | rest]} ->
        parse_string_comparison(field, :contains, rest)

      {:ok, field, [{:keyword, "startswith", _} | rest]} ->
        parse_string_comparison(field, :startswith, rest)

      {:ok, field, [{:keyword, "endswith", _} | rest]} ->
        parse_string_comparison(field, :endswith, rest)

      {:ok, field, [{:keyword, "matches", _} | rest]} ->
        parse_string_comparison(field, :matches, rest)

      {:ok, field, [{:keyword, "has", _} | rest]} ->
        parse_string_comparison(field, :has, rest)

      {:ok, field, [{:keyword, "in", _}, {:lparen, _, _} | rest]} ->
        parse_in_list(field, :in, rest)

      {:ok, field, [{:keyword, "between", _} | rest]} ->
        parse_between(field, rest)

      {:ok, field, remaining} ->
        # Just a field reference
        {:ok, {:field, field}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_string_comparison(field, op, tokens) do
    case parse_value(tokens) do
      {:ok, value, remaining} ->
        {:ok, {:comparison, field, op, value}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_in_list(field, op, tokens) do
    case parse_value_list(tokens, []) do
      {:ok, values, [{:rparen, _, _} | remaining]} ->
        {:ok, {:comparison, field, op, values}, remaining}

      {:ok, _values, [{_, val, {line, col}} | _]} ->
        {:error, "Expected ')' after IN list, got: #{inspect(val)}", line, col}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_between(field, tokens) do
    case parse_value(tokens) do
      {:ok, low, [{:keyword, "and", _} | rest]} ->
        case parse_value(rest) do
          {:ok, high, remaining} ->
            {:ok, {:comparison, field, :between, {low, high}}, remaining}

          {:error, _, _, _} = error ->
            error
        end

      {:ok, _low, [{_, val, {line, col}} | _]} ->
        {:error, "Expected 'and' in BETWEEN, got: #{inspect(val)}", line, col}

      {:error, _, _, _} = error ->
        error
    end
  end

  # Parse function call
  defp parse_function_call(name, _pos, tokens) do
    case parse_arg_list(tokens, []) do
      {:ok, args, [{:rparen, _, _} | remaining]} ->
        {:ok, {:function, String.downcase(name), args}, remaining}

      {:ok, _args, [{_, val, {line, col}} | _]} ->
        {:error, "Expected ')' after function arguments, got: #{inspect(val)}", line, col}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_arg_list([{:rparen, _, _} | _] = tokens, acc) do
    {:ok, Enum.reverse(acc), tokens}
  end

  defp parse_arg_list(tokens, acc) do
    case parse_expression(tokens) do
      {:ok, expr, [{:comma, _, _} | rest]} ->
        parse_arg_list(rest, [expr | acc])

      {:ok, expr, rest} ->
        {:ok, Enum.reverse([expr | acc]), rest}

      {:error, _, _, _} = _error when acc == [] ->
        # Empty args
        {:ok, [], tokens}

      {:error, _, _, _} = error ->
        error
    end
  end

  # ============================================================================
  # Helper Parsers
  # ============================================================================

  # Parse dotted field name: field = identifier { "." identifier }
  defp parse_field_name([{:ident, first, _} | rest]) do
    do_parse_field_name(rest, [first])
  end

  defp parse_field_name([{_, val, {line, col}} | _]) do
    {:error, "Expected field name, got: #{inspect(val)}", line, col}
  end

  defp do_parse_field_name([{:dot, _, _}, {:ident, part, _} | rest], acc) do
    do_parse_field_name(rest, [part | acc])
  end

  defp do_parse_field_name(tokens, acc) do
    field = acc |> Enum.reverse() |> Enum.join(".")
    {:ok, field, tokens}
  end

  # Parse value (literal, function call)
  defp parse_value([{:string, val, _} | rest]), do: {:ok, {:literal, val}, rest}
  defp parse_value([{:integer, val, _} | rest]), do: {:ok, {:literal, val}, rest}
  defp parse_value([{:float, val, _} | rest]), do: {:ok, {:literal, val}, rest}
  defp parse_value([{:boolean, val, _} | rest]), do: {:ok, {:literal, val}, rest}
  defp parse_value([{:null, _, _} | rest]), do: {:ok, {:literal, nil}, rest}

  defp parse_value([{:ident, name, pos}, {:lparen, _, _} | rest]) do
    parse_function_call(name, pos, rest)
  end

  defp parse_value([{:ident, name, _} | rest]) do
    # Could be a field reference
    do_parse_field_name(rest, [name])
    |> case do
      {:ok, field, remaining} -> {:ok, {:field, field}, remaining}
      error -> error
    end
  end

  defp parse_value([{_, val, {line, col}} | _]) do
    {:error, "Expected value, got: #{inspect(val)}", line, col}
  end

  # Parse comma-separated value list
  defp parse_value_list([{:rparen, _, _} | _] = tokens, acc) do
    {:ok, Enum.reverse(acc), tokens}
  end

  defp parse_value_list(tokens, acc) do
    case parse_value(tokens) do
      {:ok, val, [{:comma, _, _} | rest]} ->
        parse_value_list(rest, [val | acc])

      {:ok, val, rest} ->
        {:ok, Enum.reverse([val | acc]), rest}

      {:error, _, _, _} = error ->
        error
    end
  end

  # Parse field list
  defp parse_field_list(tokens) do
    parse_field_list_items(tokens, [])
  end

  defp parse_field_list_items(tokens, acc) do
    case parse_field_name(tokens) do
      {:ok, field, [{:comma, _, _} | rest]} ->
        parse_field_list_items(rest, [field | acc])

      {:ok, field, rest} ->
        {:ok, Enum.reverse([field | acc]), rest}

      {:error, _, _, _} = error when acc == [] ->
        error

      {:error, _, _, _} ->
        {:ok, Enum.reverse(acc), tokens}
    end
  end

  # Parse assignment list for extend
  defp parse_assignment_list(tokens) do
    parse_assignment_items(tokens, [])
  end

  defp parse_assignment_items(tokens, acc) do
    case parse_assignment(tokens) do
      {:ok, assign, [{:comma, _, _} | rest]} ->
        parse_assignment_items(rest, [assign | acc])

      {:ok, assign, rest} ->
        {:ok, Enum.reverse([assign | acc]), rest}

      {:error, _, _, _} = error when acc == [] ->
        error

      {:error, _, _, _} ->
        {:ok, Enum.reverse(acc), tokens}
    end
  end

  defp parse_assignment([{:ident, name, _}, {:op, "=", _} | rest]) do
    case parse_expression(rest) do
      {:ok, expr, remaining} ->
        {:ok, {name, expr}, remaining}

      {:error, _, _, _} = error ->
        error
    end
  end

  defp parse_assignment([{_, val, {line, col}} | _]) do
    {:error, "Expected assignment (name = expression), got: #{inspect(val)}", line, col}
  end

  # Parse aggregation list for summarize
  defp parse_aggregation_list(tokens) do
    parse_aggregation_items(tokens, [])
  end

  defp parse_aggregation_items(tokens, acc) do
    case parse_aggregation(tokens) do
      {:ok, agg, [{:comma, _, _} | rest]} ->
        parse_aggregation_items(rest, [agg | acc])

      {:ok, agg, rest} ->
        {:ok, Enum.reverse([agg | acc]), rest}

      {:error, _, _, _} = error when acc == [] ->
        error

      {:error, _, _, _} ->
        {:ok, Enum.reverse(acc), tokens}
    end
  end

  # Parse: agg_expr = [ identifier "=" ] agg_function "(" [ field ] ")"
  defp parse_aggregation([{:ident, alias_name, _}, {:op, "=", _}, {:ident, func, _}, {:lparen, _, _} | rest]) do
    parse_aggregation_body(alias_name, func, rest)
  end

  defp parse_aggregation([{:ident, func, _}, {:lparen, _, _} | rest]) when func in ["count", "sum", "avg", "min", "max", "dcount", "countif", "sumif", "avgif", "percentile"] do
    # Generate default alias
    parse_aggregation_body(func <> "_", func, rest)
  end

  defp parse_aggregation(_tokens) do
    {:error, "Expected aggregation function", 0, 0}
  end

  defp parse_aggregation_body(alias_name, func, tokens) do
    case tokens do
      [{:rparen, _, _} | rest] ->
        # count() with no args
        {:ok, {alias_name, String.downcase(func), nil}, rest}

      _ ->
        case parse_field_name(tokens) do
          {:ok, field, [{:rparen, _, _} | rest]} ->
            {:ok, {alias_name, String.downcase(func), field}, rest}

          {:ok, _field, [{_, val, {line, col}} | _]} ->
            {:error, "Expected ')' after aggregation field, got: #{inspect(val)}", line, col}

          {:error, _, _, _} = error ->
            error
        end
    end
  end

  # Convert operator string to atom
  defp operator_to_atom("=="), do: :eq
  defp operator_to_atom("="), do: :eq
  defp operator_to_atom("!="), do: :neq
  defp operator_to_atom("<>"), do: :neq
  defp operator_to_atom(">"), do: :gt
  defp operator_to_atom(">="), do: :gte
  defp operator_to_atom("<"), do: :lt
  defp operator_to_atom("<="), do: :lte
  defp operator_to_atom(op), do: String.to_atom(op)
end
