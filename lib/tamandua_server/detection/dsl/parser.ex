defmodule TamanduaServer.Detection.DSL.Parser do
  @moduledoc """
  Recursive descent parser for Tamandua DSL.

  Parses token stream into an Abstract Syntax Tree (AST).
  """

  alias TamanduaServer.Detection.DSL.{Lexer, Grammar}

  @type ast :: map()

  @doc """
  Parse DSL source code into an AST.

  ## Returns

  - `{:ok, ast}` - Successfully parsed detection
  - `{:error, message}` - Parse error with details

  ## AST Structure

  ```elixir
  %{
    type: :detection,
    name: "lateral_movement",
    metadata: %{
      name: "Lateral Movement via PsExec",
      description: "...",
      severity: "high",
      mitre: ["T1021.002"]
    },
    sequence: %{
      temporal_constraint: 300,  # seconds
      events: [
        %{
          id: "e1",
          event_type: "process_create",
          where: %{type: :and, left: ..., right: ...},
          captures: ["initiator_host", "user"]
        },
        ...
      ]
    },
    aggregation: [
      %{
        function: "count",
        field: %{distinct: true, ref: ["e2", "target_host"]},
        operator: ">",
        threshold: 3,
        temporal_constraint: 3600,
        action: %{type: :escalate, severity: "critical"}
      },
      ...
    ]
  }
  ```
  """
  @spec parse(String.t()) :: {:ok, ast()} | {:error, String.t()}
  def parse(source) do
    with {:ok, tokens} <- Lexer.tokenize(source) do
      try do
        {ast, remaining} = parse_detection(tokens)

        case remaining do
          [:eof] -> {:ok, ast}
          [] -> {:ok, ast}
          _ -> {:error, "Unexpected tokens after detection: #{inspect(remaining)}"}
        end
      rescue
        e -> {:error, "Parse error: #{Exception.message(e)}"}
      end
    end
  end

  # ─────────────────────────────────────────────────────────────────────
  # Detection
  # ─────────────────────────────────────────────────────────────────────

  defp parse_detection([{:keyword, "detection"}, {:identifier, name} | rest]) do
    {body, _remaining} = expect_symbol(rest, "{")
    {metadata, remaining} = parse_metadata(body, %{})
    {sequence, remaining} = parse_optional_sequence(remaining)
    {aggregation, remaining} = parse_optional_aggregation(remaining)
    {_, remaining} = expect_symbol(remaining, "}")

    ast = %{
      type: :detection,
      name: name,
      metadata: metadata,
      sequence: sequence,
      aggregation: aggregation
    }

    {ast, remaining}
  end

  defp parse_detection(tokens) do
    raise "Expected 'detection' keyword, got: #{inspect(Enum.take(tokens, 3))}"
  end

  # ─────────────────────────────────────────────────────────────────────
  # Metadata
  # ─────────────────────────────────────────────────────────────────────

  defp parse_metadata([{:identifier, key}, {:symbol, ":"} | rest], acc) do
    {value, remaining} = parse_metadata_value(rest)

    # Check if next token is another metadata key or a block keyword
    case remaining do
      [{:keyword, kw} | _] when kw in ["sequence", "aggregation"] ->
        {Map.put(acc, key, value), remaining}

      [{:symbol, "}"} | _] ->
        {Map.put(acc, key, value), remaining}

      _ ->
        parse_metadata(remaining, Map.put(acc, key, value))
    end
  end

  defp parse_metadata(tokens, acc), do: {acc, tokens}

  defp parse_metadata_value([{:string, str} | rest]), do: {str, rest}
  defp parse_metadata_value([{:number, num} | rest]), do: {num, rest}
  defp parse_metadata_value([{:boolean, bool} | rest]), do: {bool, rest}
  defp parse_metadata_value([{:identifier, id} | rest]), do: {id, rest}

  # Array values
  defp parse_metadata_value([{:symbol, "["} | rest]) do
    parse_array(rest, [])
  end

  defp parse_metadata_value(tokens) do
    raise "Expected metadata value, got: #{inspect(Enum.take(tokens, 3))}"
  end

  defp parse_array([{:symbol, "]"} | rest], acc) do
    {Enum.reverse(acc), rest}
  end

  defp parse_array([{:string, str} | rest], acc) do
    case rest do
      [{:symbol, ","} | remaining] -> parse_array(remaining, [str | acc])
      _ -> parse_array(rest, [str | acc])
    end
  end

  defp parse_array([{:number, num} | rest], acc) do
    case rest do
      [{:symbol, ","} | remaining] -> parse_array(remaining, [num | acc])
      _ -> parse_array(rest, [num | acc])
    end
  end

  defp parse_array([{:identifier, id} | rest], acc) do
    case rest do
      [{:symbol, ","} | remaining] -> parse_array(remaining, [id | acc])
      _ -> parse_array(rest, [id | acc])
    end
  end

  defp parse_array(tokens, _acc) do
    raise "Invalid array element: #{inspect(Enum.take(tokens, 3))}"
  end

  # ─────────────────────────────────────────────────────────────────────
  # Sequence Block
  # ─────────────────────────────────────────────────────────────────────

  defp parse_optional_sequence([{:keyword, "sequence"} | rest]) do
    {temporal, remaining} = parse_optional_temporal(rest)
    {_, remaining} = expect_symbol(remaining, "{")
    {events, remaining} = parse_events(remaining, [])
    {_, remaining} = expect_symbol(remaining, "}")

    sequence = %{
      temporal_constraint: temporal,
      events: events
    }

    {sequence, remaining}
  end

  defp parse_optional_sequence(tokens), do: {nil, tokens}

  defp parse_optional_temporal([{:keyword, "within"}, {:duration, {value, unit}} | rest]) do
    seconds = Grammar.duration_to_seconds(value, unit)
    {seconds, rest}
  end

  defp parse_optional_temporal(tokens), do: {nil, tokens}

  defp parse_events([{:keyword, "event"} | rest], acc) do
    {event, remaining} = parse_event(rest)
    parse_events(remaining, [event | acc])
  end

  defp parse_events(tokens, acc) do
    {Enum.reverse(acc), tokens}
  end

  defp parse_event([{:identifier, event_id}, {:symbol, ":"}, {:keyword, event_type} | rest]) do
    {_, remaining} = expect_symbol(rest, "{")
    {where_clause, remaining} = parse_optional_where(remaining)
    {captures, remaining} = parse_optional_capture(remaining)
    {_, remaining} = expect_symbol(remaining, "}")

    event = %{
      id: event_id,
      event_type: event_type,
      where: where_clause,
      captures: captures
    }

    {event, remaining}
  end

  defp parse_event(tokens) do
    raise "Invalid event definition: #{inspect(Enum.take(tokens, 5))}"
  end

  defp parse_optional_where([{:keyword, "where"}, {:symbol, ":"} | rest]) do
    parse_expression(rest)
  end

  defp parse_optional_where(tokens), do: {nil, tokens}

  defp parse_optional_capture([{:keyword, "capture"}, {:symbol, ":"} | rest]) do
    parse_capture_list(rest, [])
  end

  defp parse_optional_capture(tokens), do: {[], tokens}

  defp parse_capture_list([{:identifier, id} | rest], acc) do
    case rest do
      [{:symbol, ","} | remaining] -> parse_capture_list(remaining, [id | acc])
      _ -> {Enum.reverse([id | acc]), rest}
    end
  end

  # ─────────────────────────────────────────────────────────────────────
  # Expression Parsing (Recursive Descent with Precedence)
  # ─────────────────────────────────────────────────────────────────────

  defp parse_expression(tokens) do
    parse_or_expression(tokens)
  end

  defp parse_or_expression(tokens) do
    {left, remaining} = parse_and_expression(tokens)

    case remaining do
      [{:keyword, "or"} | rest] ->
        {right, final} = parse_or_expression(rest)
        {%{type: :or, left: left, right: right}, final}

      _ ->
        {left, remaining}
    end
  end

  defp parse_and_expression(tokens) do
    {left, remaining} = parse_unary_expression(tokens)

    case remaining do
      [{:keyword, "and"} | rest] ->
        {right, final} = parse_and_expression(rest)
        {%{type: :and, left: left, right: right}, final}

      _ ->
        {left, remaining}
    end
  end

  defp parse_unary_expression([{:keyword, "not"} | rest]) do
    {expr, remaining} = parse_primary_expression(rest)
    {%{type: :not, expr: expr}, remaining}
  end

  defp parse_unary_expression(tokens) do
    parse_primary_expression(tokens)
  end

  defp parse_primary_expression([{:symbol, "("} | rest]) do
    {expr, remaining} = parse_expression(rest)
    {_, final} = expect_symbol(remaining, ")")
    {expr, final}
  end

  defp parse_primary_expression(tokens) do
    parse_comparison(tokens)
  end

  defp parse_comparison(tokens) do
    {field_ref, remaining} = parse_field_ref(tokens)

    case remaining do
      [{:operator, op} | rest] when op in ["=", "!=", ">", ">=", "<", "<="] ->
        {value, final} = parse_value(rest)
        {%{type: :comparison, operator: op, left: field_ref, right: value}, final}

      [{:operator, op} | rest] when op in ["contains", "startswith", "endswith"] ->
        {value, final} = parse_value(rest)
        {%{type: :comparison, operator: op, left: field_ref, right: value}, final}

      [{:keyword, "in"} | rest] ->
        {list, final} = parse_value(rest)
        {%{type: :in, field: field_ref, values: list}, final}

      [{:keyword, "matches"} | rest] ->
        {regex, final} = parse_value(rest)
        {%{type: :matches, field: field_ref, pattern: regex}, final}

      _ ->
        # Just a field reference (for boolean fields)
        {field_ref, remaining}
    end
  end

  defp parse_field_ref(tokens) do
    parse_field_ref_parts(tokens, [])
  end

  defp parse_field_ref_parts([{:identifier, part} | rest], acc) do
    case rest do
      [{:symbol, "."} | remaining] -> parse_field_ref_parts(remaining, [part | acc])
      _ -> {%{type: :field_ref, parts: Enum.reverse([part | acc])}, rest}
    end
  end

  defp parse_field_ref_parts(tokens, _acc) do
    raise "Expected field reference, got: #{inspect(Enum.take(tokens, 3))}"
  end

  defp parse_value([{:string, str} | rest]), do: {str, rest}
  defp parse_value([{:number, num} | rest]), do: {num, rest}
  defp parse_value([{:boolean, bool} | rest]), do: {bool, rest}
  defp parse_value([{:identifier, id} | rest]), do: {id, rest}
  defp parse_value([{:regex, pattern} | rest]), do: {%{type: :regex, pattern: pattern}, rest}

  # Array
  defp parse_value([{:symbol, "["} | rest]) do
    parse_array(rest, [])
  end

  # ML call
  defp parse_value([{:keyword, "ml"}, {:symbol, "("} | rest]) do
    {model_name, remaining} = expect_string(rest)
    {_, remaining} = expect_symbol(remaining, ",")
    {field_ref, remaining} = parse_field_ref(remaining)
    {_, remaining} = expect_symbol(remaining, ")")

    ml_call = %{type: :ml_call, model: model_name, field: field_ref}
    {ml_call, remaining}
  end

  defp parse_value(tokens) do
    raise "Expected value, got: #{inspect(Enum.take(tokens, 3))}"
  end

  # ─────────────────────────────────────────────────────────────────────
  # Aggregation Block
  # ─────────────────────────────────────────────────────────────────────

  defp parse_optional_aggregation([{:keyword, "aggregation"} | rest]) do
    {_, remaining} = expect_symbol(rest, "{")
    {rules, remaining} = parse_aggregation_rules(remaining, [])
    {_, remaining} = expect_symbol(remaining, "}")
    {rules, remaining}
  end

  defp parse_optional_aggregation(tokens), do: {[], tokens}

  defp parse_aggregation_rules([{:symbol, "}"} | _] = tokens, acc) do
    {Enum.reverse(acc), tokens}
  end

  defp parse_aggregation_rules(tokens, acc) do
    {rule, remaining} = parse_aggregation_rule(tokens)
    parse_aggregation_rules(remaining, [rule | acc])
  end

  defp parse_aggregation_rule([{:keyword, func} | rest])
       when func in ["count", "sum", "avg", "min", "max", "stddev", "z_score"] do
    {_, remaining} = expect_symbol(rest, "(")
    {field, remaining} = parse_agg_field(remaining)
    {_, remaining} = expect_symbol(remaining, ")")
    {op, remaining} = expect_operator(remaining)
    {threshold, remaining} = expect_number(remaining)
    {temporal, remaining} = parse_optional_temporal(remaining)
    {_, remaining} = expect_symbol(remaining, "->")
    {action, remaining} = parse_action(remaining)

    rule = %{
      function: func,
      field: field,
      operator: op,
      threshold: threshold,
      temporal_constraint: temporal,
      action: action
    }

    {rule, remaining}
  end

  defp parse_aggregation_rule(tokens) do
    raise "Invalid aggregation rule: #{inspect(Enum.take(tokens, 5))}"
  end

  defp parse_agg_field([{:keyword, "distinct"} | rest]) do
    {field_ref, remaining} = parse_field_ref(rest)
    {%{distinct: true, ref: field_ref}, remaining}
  end

  defp parse_agg_field([{:symbol, "*"} | rest]) do
    {%{wildcard: true}, rest}
  end

  defp parse_agg_field(tokens) do
    {field_ref, remaining} = parse_field_ref(tokens)
    {%{distinct: false, ref: field_ref}, remaining}
  end

  defp parse_action([{:keyword, "escalate"}, {:keyword, "to"}, {:keyword, severity} | rest])
       when severity in ["critical", "high", "medium", "low", "info"] do
    {%{type: :escalate, severity: severity}, rest}
  end

  defp parse_action([{:keyword, "create_alert"}, {:string, message} | rest]) do
    {%{type: :create_alert, message: message}, rest}
  end

  defp parse_action([{:keyword, "execute"}, {:string, command} | rest]) do
    {%{type: :execute, command: command}, rest}
  end

  defp parse_action(tokens) do
    raise "Invalid action: #{inspect(Enum.take(tokens, 3))}"
  end

  # ─────────────────────────────────────────────────────────────────────
  # Helper Functions
  # ─────────────────────────────────────────────────────────────────────

  defp expect_symbol([{:symbol, expected} | rest], expected), do: {expected, rest}

  defp expect_symbol(tokens, expected) do
    raise "Expected symbol '#{expected}', got: #{inspect(Enum.take(tokens, 1))}"
  end

  defp expect_operator([{:operator, op} | rest]), do: {op, rest}

  defp expect_operator(tokens) do
    raise "Expected operator, got: #{inspect(Enum.take(tokens, 1))}"
  end

  defp expect_number([{:number, num} | rest]), do: {num, rest}

  defp expect_number(tokens) do
    raise "Expected number, got: #{inspect(Enum.take(tokens, 1))}"
  end

  defp expect_string([{:string, str} | rest]), do: {str, rest}

  defp expect_string(tokens) do
    raise "Expected string, got: #{inspect(Enum.take(tokens, 1))}"
  end

  @doc """
  Pretty-print AST for debugging.
  """
  def format_ast(ast, indent \\ 0) do
    pad = String.duplicate("  ", indent)

    case ast do
      %{type: :detection} ->
        """
        #{pad}Detection: #{ast.name}
        #{pad}  Metadata: #{inspect(ast.metadata)}
        #{format_sequence(ast.sequence, indent + 1)}
        #{format_aggregation(ast.aggregation, indent + 1)}
        """

      _ ->
        "#{pad}#{inspect(ast)}"
    end
  end

  defp format_sequence(nil, _indent), do: ""

  defp format_sequence(sequence, indent) do
    pad = String.duplicate("  ", indent)
    events_str = Enum.map_join(sequence.events, "\n", &format_event(&1, indent + 1))

    """
    #{pad}Sequence (within #{sequence.temporal_constraint}s):
    #{events_str}
    """
  end

  defp format_event(event, indent) do
    pad = String.duplicate("  ", indent)

    """
    #{pad}Event #{event.id}: #{event.event_type}
    #{pad}  Where: #{inspect(event.where)}
    #{pad}  Captures: #{inspect(event.captures)}
    """
  end

  defp format_aggregation([], _indent), do: ""

  defp format_aggregation(rules, indent) do
    pad = String.duplicate("  ", indent)
    rules_str = Enum.map_join(rules, "\n", &"#{pad}  #{inspect(&1)}")

    """
    #{pad}Aggregation:
    #{rules_str}
    """
  end
end
