defmodule TamanduaServer.Detection.DSL.Compiler do
  @moduledoc """
  Compiles DSL AST into executable detection logic.

  The compiler transforms the high-level DSL into optimized Elixir code
  that can be executed by the Runtime module.

  ## Compilation Phases

  1. **Validation** - Type checking, semantic analysis
  2. **Optimization** - Query optimization, constant folding
  3. **Code Generation** - Generate executable detection function
  """

  require Logger

  alias TamanduaServer.Detection.DSL.Grammar

  @type compiled_detection :: %{
          name: String.t(),
          metadata: map(),
          evaluator: function(),
          sequence_matcher: function() | nil,
          aggregator: function() | nil,
          state_key: String.t()
        }

  @doc """
  Compile DSL AST into executable detection.

  Returns `{:ok, compiled_detection}` or `{:error, reason}`.
  """
  @spec compile(map()) :: {:ok, compiled_detection()} | {:error, String.t()}
  def compile(ast) do
    with :ok <- validate_ast(ast),
         {:ok, optimized} <- optimize_ast(ast),
         {:ok, compiled} <- generate_code(optimized) do
      {:ok, compiled}
    end
  rescue
    e -> {:error, "Compilation error: #{Exception.message(e)}"}
  end

  # ─────────────────────────────────────────────────────────────────────
  # Validation Phase
  # ─────────────────────────────────────────────────────────────────────

  defp validate_ast(%{type: :detection} = ast) do
    with :ok <- validate_metadata(ast.metadata),
         :ok <- validate_sequence(ast.sequence),
         :ok <- validate_aggregation(ast.aggregation, ast.sequence) do
      :ok
    end
  end

  defp validate_ast(_), do: {:error, "Invalid AST: must be a detection"}

  defp validate_metadata(metadata) when is_map(metadata) do
    required_fields = ["name", "severity"]
    missing = Enum.filter(required_fields, &(!Map.has_key?(metadata, &1)))

    case missing do
      [] ->
        if Map.get(metadata, "severity") in Grammar.severity_levels() do
          :ok
        else
          {:error, "Invalid severity: #{Map.get(metadata, "severity")}"}
        end

      fields ->
        {:error, "Missing required metadata fields: #{Enum.join(fields, ", ")}"}
    end
  end

  defp validate_sequence(nil), do: :ok

  defp validate_sequence(%{events: events}) when is_list(events) and length(events) > 0 do
    event_ids = Enum.map(events, & &1.id)
    duplicates = event_ids -- Enum.uniq(event_ids)

    if Enum.empty?(duplicates) do
      Enum.reduce_while(events, :ok, fn event, :ok ->
        case validate_event(event, event_ids) do
          :ok -> {:cont, :ok}
          error -> {:halt, error}
        end
      end)
    else
      {:error, "Duplicate event IDs: #{Enum.join(duplicates, ", ")}"}
    end
  end

  defp validate_sequence(_), do: {:error, "Sequence must have at least one event"}

  defp validate_event(event, all_event_ids) do
    with :ok <- validate_event_type(event.event_type),
         :ok <- validate_where_clause(event.where, all_event_ids) do
      :ok
    end
  end

  defp validate_event_type(type) do
    if type in Grammar.event_types() do
      :ok
    else
      {:error, "Invalid event type: #{type}"}
    end
  end

  defp validate_where_clause(nil, _), do: :ok

  defp validate_where_clause(expr, all_event_ids) do
    validate_expression(expr, all_event_ids)
  end

  defp validate_expression(%{type: :and, left: left, right: right}, ids) do
    with :ok <- validate_expression(left, ids),
         :ok <- validate_expression(right, ids) do
      :ok
    end
  end

  defp validate_expression(%{type: :or, left: left, right: right}, ids) do
    with :ok <- validate_expression(left, ids),
         :ok <- validate_expression(right, ids) do
      :ok
    end
  end

  defp validate_expression(%{type: :not, expr: expr}, ids) do
    validate_expression(expr, ids)
  end

  defp validate_expression(%{type: :comparison}, _ids), do: :ok
  defp validate_expression(%{type: :in}, _ids), do: :ok
  defp validate_expression(%{type: :matches}, _ids), do: :ok
  defp validate_expression(%{type: :field_ref}, _ids), do: :ok
  defp validate_expression(_, _), do: :ok

  defp validate_aggregation([], _sequence), do: :ok
  defp validate_aggregation(nil, _sequence), do: :ok

  defp validate_aggregation(rules, sequence) when is_list(rules) do
    Enum.reduce_while(rules, :ok, fn rule, :ok ->
      case validate_aggregation_rule(rule, sequence) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp validate_aggregation_rule(rule, _sequence) do
    if rule.function in Grammar.aggregation_functions() do
      :ok
    else
      {:error, "Invalid aggregation function: #{rule.function}"}
    end
  end

  # ─────────────────────────────────────────────────────────────────────
  # Optimization Phase
  # ─────────────────────────────────────────────────────────────────────

  defp optimize_ast(ast) do
    optimized = %{
      ast
      | sequence: optimize_sequence(ast.sequence),
        aggregation: optimize_aggregation(ast.aggregation)
    }

    {:ok, optimized}
  end

  defp optimize_sequence(nil), do: nil

  defp optimize_sequence(sequence) do
    %{sequence | events: Enum.map(sequence.events, &optimize_event/1)}
  end

  defp optimize_event(event) do
    %{event | where: optimize_expression(event.where)}
  end

  defp optimize_expression(nil), do: nil
  defp optimize_expression(%{type: :and, left: left, right: right}) do
    left_opt = optimize_expression(left)
    right_opt = optimize_expression(right)

    # Constant folding
    case {left_opt, right_opt} do
      {true, expr} -> expr
      {expr, true} -> expr
      {false, _} -> false
      {_, false} -> false
      _ -> %{type: :and, left: left_opt, right: right_opt}
    end
  end

  defp optimize_expression(%{type: :or, left: left, right: right}) do
    left_opt = optimize_expression(left)
    right_opt = optimize_expression(right)

    case {left_opt, right_opt} do
      {true, _} -> true
      {_, true} -> true
      {false, expr} -> expr
      {expr, false} -> expr
      _ -> %{type: :or, left: left_opt, right: right_opt}
    end
  end

  defp optimize_expression(%{type: :not, expr: expr}) do
    optimized = optimize_expression(expr)

    case optimized do
      true -> false
      false -> true
      %{type: :not, expr: inner} -> inner  # Double negation
      _ -> %{type: :not, expr: optimized}
    end
  end

  defp optimize_expression(expr), do: expr

  defp optimize_aggregation(nil), do: nil
  defp optimize_aggregation(rules) when is_list(rules), do: rules

  # ─────────────────────────────────────────────────────────────────────
  # Code Generation Phase
  # ─────────────────────────────────────────────────────────────────────

  defp generate_code(ast) do
    state_key = "dsl_#{ast.name}_#{:erlang.phash2(ast)}"

    evaluator = compile_evaluator(ast)
    sequence_matcher = compile_sequence_matcher(ast.sequence)
    aggregator = compile_aggregator(ast.aggregation)

    compiled = %{
      name: ast.name,
      metadata: ast.metadata,
      evaluator: evaluator,
      sequence_matcher: sequence_matcher,
      aggregator: aggregator,
      state_key: state_key,
      ast: ast  # Keep AST for debugging/introspection
    }

    {:ok, compiled}
  end

  defp compile_evaluator(ast) do
    fn event, state ->
      # Single-event evaluation (for non-sequence detections)
      cond do
        ast.sequence == nil ->
          # No sequence - just evaluate metadata matches
          {:ok, false, state}

        true ->
          # Has sequence - delegate to sequence matcher
          {:ok, false, state}
      end
    end
  end

  defp compile_sequence_matcher(nil), do: nil

  defp compile_sequence_matcher(sequence) do
    fn event, state ->
      agent_id = event["agent_id"] || event[:agent_id]
      key = {agent_id, sequence}

      # Get or initialize sequence state
      sequence_state = Map.get(state, key, %{
        current_step: 0,
        matched_events: [],
        captures: %{},
        started_at: nil
      })

      current_step = sequence_state.current_step

      # Check if we've timed out
      if sequence_state.started_at && sequence.temporal_constraint do
        elapsed = System.system_time(:second) - sequence_state.started_at

        if elapsed > sequence.temporal_constraint do
          # Timeout - reset state
          new_state = Map.delete(state, key)
          {:ok, false, new_state}
        else
          match_sequence_step(event, sequence, sequence_state, state, key)
        end
      else
        match_sequence_step(event, sequence, sequence_state, state, key)
      end
    end
  end

  defp match_sequence_step(event, sequence, sequence_state, state, key) do
    current_step = sequence_state.current_step

    if current_step >= length(sequence.events) do
      # Already completed
      {:ok, true, state}
    else
      expected_event = Enum.at(sequence.events, current_step)

      # Check if event matches current step
      if matches_event_def?(event, expected_event, sequence_state.captures) do
        # Capture values
        new_captures = extract_captures(event, expected_event, sequence_state.captures)

        new_sequence_state = %{
          current_step: current_step + 1,
          matched_events: [event | sequence_state.matched_events],
          captures: new_captures,
          started_at: sequence_state.started_at || System.system_time(:second)
        }

        new_state = Map.put(state, key, new_sequence_state)

        # Check if sequence is complete
        if new_sequence_state.current_step >= length(sequence.events) do
          {:ok, true, new_state}
        else
          {:ok, false, new_state}
        end
      else
        # Event doesn't match - check if it matches step 0 (restart)
        first_event = Enum.at(sequence.events, 0)

        if current_step > 0 && matches_event_def?(event, first_event, %{}) do
          # Restart sequence
          new_captures = extract_captures(event, first_event, %{})

          new_sequence_state = %{
            current_step: 1,
            matched_events: [event],
            captures: new_captures,
            started_at: System.system_time(:second)
          }

          {:ok, false, Map.put(state, key, new_sequence_state)}
        else
          # No match
          {:ok, false, state}
        end
      end
    end
  end

  defp matches_event_def?(event, event_def, captures) do
    event_type = event["event_type"] || event[:event_type]

    # Check event type
    type_matches =
      event_def.event_type == "any" ||
        String.downcase(to_string(event_type)) == event_def.event_type

    # Check where clause
    where_matches =
      if event_def.where do
        evaluate_expression(event_def.where, event, captures)
      else
        true
      end

    type_matches && where_matches
  end

  defp evaluate_expression(%{type: :and, left: left, right: right}, event, captures) do
    evaluate_expression(left, event, captures) && evaluate_expression(right, event, captures)
  end

  defp evaluate_expression(%{type: :or, left: left, right: right}, event, captures) do
    evaluate_expression(left, event, captures) || evaluate_expression(right, event, captures)
  end

  defp evaluate_expression(%{type: :not, expr: expr}, event, captures) do
    !evaluate_expression(expr, event, captures)
  end

  defp evaluate_expression(%{type: :comparison, operator: op, left: left, right: right}, event, captures) do
    left_val = resolve_field_ref(left, event, captures)
    right_val = resolve_value(right, event, captures)

    compare(left_val, op, right_val)
  end

  defp evaluate_expression(%{type: :in, field: field, values: values}, event, captures) do
    field_val = resolve_field_ref(field, event, captures)
    resolved_values = Enum.map(values, &resolve_value(&1, event, captures))

    field_val in resolved_values
  end

  defp evaluate_expression(%{type: :matches, field: field, pattern: %{type: :regex, pattern: pattern}}, event, captures) do
    field_val = resolve_field_ref(field, event, captures) |> to_string()

    case Regex.compile(pattern) do
      {:ok, regex} -> Regex.match?(regex, field_val)
      _ -> false
    end
  end

  defp evaluate_expression(%{type: :field_ref} = field_ref, event, captures) do
    # Boolean field
    resolve_field_ref(field_ref, event, captures) == true
  end

  defp evaluate_expression(true, _event, _captures), do: true
  defp evaluate_expression(false, _event, _captures), do: false
  defp evaluate_expression(_, _event, _captures), do: false

  defp resolve_field_ref(%{type: :field_ref, parts: parts}, event, captures) do
    # Check if first part is a captured value
    [first | rest] = parts

    initial_value =
      case Map.get(captures, first) do
        nil ->
          # Not a capture - look in event
          payload = event["payload"] || event[:payload] || %{}
          Map.get(payload, first) || Map.get(event, first)

        captured ->
          captured
      end

    # Traverse rest of path
    Enum.reduce(rest, initial_value, fn part, val ->
      if is_map(val) do
        Map.get(val, part) || Map.get(val, String.to_atom(part))
      else
        nil
      end
    end)
  end

  defp resolve_field_ref(value, _event, _captures), do: value

  defp resolve_value(%{type: :field_ref} = ref, event, captures) do
    resolve_field_ref(ref, event, captures)
  end

  # DSL `ml("model_name", field.ref)` — score the field value with the ML
  # service and yield a numeric threat score for use in comparisons.
  #
  # The ML service exposes a single POST /predict endpoint (no per-model
  # routing), so the requested model name is forwarded as pass-through
  # request metadata rather than selecting an endpoint. ML.Client.predict/1
  # takes a sample map and returns {:ok, prediction_map}; the map is reduced
  # to a score with the same semantics as the engine's
  # calculate_ml_threat_score (fail-closed on untrained model / unknown
  # verdict). Any error (circuit open, HTTP failure) resolves to 0.0.
  defp resolve_value(%{type: :ml_call, model: model, field: field}, event, captures) do
    field_val = resolve_field_ref(field, event, captures)
    content = ml_call_content(field_val)

    sample = %{
      sha256: :crypto.hash(:sha256, content),
      content: content,
      file_type: "dsl_field",
      entropy: 0.0,
      metadata: %{"model" => model, "source" => "detection_dsl"}
    }

    case TamanduaServer.Detection.ML.Client.predict(sample) do
      {:ok, prediction} -> ml_prediction_score(prediction)
      _ -> 0.0
    end
  rescue
    _ -> 0.0
  end

  defp resolve_value(value, _event, _captures), do: value

  defp ml_call_content(value) when is_binary(value), do: value
  defp ml_call_content(nil), do: <<>>
  defp ml_call_content(value) when is_number(value) or is_atom(value), do: to_string(value)
  defp ml_call_content(value), do: inspect(value)

  # Mirrors EngineWorker.calculate_ml_threat_score: an explicitly untrained
  # model or an unknown/unrecognized verdict contributes no ML signal (0.0).
  defp ml_prediction_score(prediction) do
    if prediction[:model_trained] == false do
      0.0
    else
      confidence = prediction[:confidence] || 0.0

      case prediction[:prediction] do
        "malicious" -> confidence
        "suspicious" -> confidence * 0.7
        "benign" -> 1.0 - confidence
        _ -> 0.0
      end
    end
  end

  defp compare(left, "=", right), do: normalize_value(left) == normalize_value(right)
  defp compare(left, "!=", right), do: normalize_value(left) != normalize_value(right)
  defp compare(left, ">", right), do: to_number(left) > to_number(right)
  defp compare(left, ">=", right), do: to_number(left) >= to_number(right)
  defp compare(left, "<", right), do: to_number(left) < to_number(right)
  defp compare(left, "<=", right), do: to_number(left) <= to_number(right)

  defp compare(left, "contains", right) do
    String.contains?(to_string(left), to_string(right))
  end

  defp compare(left, "startswith", right) do
    String.starts_with?(to_string(left), to_string(right))
  end

  defp compare(left, "endswith", right) do
    String.ends_with?(to_string(left), to_string(right))
  end

  defp normalize_value(val) when is_binary(val), do: String.downcase(val)
  defp normalize_value(val), do: val

  defp to_number(val) when is_number(val), do: val
  defp to_number(val) when is_binary(val) do
    case Float.parse(val) do
      {num, _} -> num
      :error -> 0
    end
  end
  defp to_number(_), do: 0

  defp extract_captures(event, event_def, existing_captures) do
    payload = event["payload"] || event[:payload] || %{}

    new_captures =
      Enum.reduce(event_def.captures, %{}, fn capture, acc ->
        value = Map.get(payload, capture) || Map.get(event, capture)
        Map.put(acc, capture, value)
      end)

    Map.merge(existing_captures, new_captures)
  end

  defp compile_aggregator(nil), do: nil
  defp compile_aggregator([]), do: nil

  defp compile_aggregator(rules) do
    fn matched_events, state ->
      results =
        Enum.map(rules, fn rule ->
          result = evaluate_aggregation(rule, matched_events, state)
          {rule, result}
        end)

      triggered = Enum.filter(results, fn {_rule, result} -> result end)

      if Enum.any?(triggered) do
        actions = Enum.map(triggered, fn {rule, _} -> rule.action end)
        {:ok, actions}
      else
        {:ok, []}
      end
    end
  end

  defp evaluate_aggregation(rule, events, _state) do
    # Filter events by temporal constraint if present
    filtered_events =
      if rule.temporal_constraint do
        cutoff = System.system_time(:second) - rule.temporal_constraint

        Enum.filter(events, fn event ->
          timestamp = event["timestamp"] || event[:timestamp] || System.system_time(:second)
          timestamp >= cutoff
        end)
      else
        events
      end

    # Extract field values
    values = extract_aggregation_values(rule.field, filtered_events)

    # Apply aggregation function
    result = apply_aggregation_function(rule.function, values)

    # Compare against threshold
    compare(result, rule.operator, rule.threshold)
  end

  defp extract_aggregation_values(%{wildcard: true}, events), do: events

  defp extract_aggregation_values(%{distinct: true, ref: field_ref}, events) do
    events
    |> Enum.map(&resolve_field_ref(field_ref, &1, %{}))
    |> Enum.uniq()
  end

  defp extract_aggregation_values(%{distinct: false, ref: field_ref}, events) do
    Enum.map(events, &resolve_field_ref(field_ref, &1, %{}))
  end

  defp apply_aggregation_function("count", values), do: length(values)

  defp apply_aggregation_function("sum", values) do
    values |> Enum.map(&to_number/1) |> Enum.sum()
  end

  defp apply_aggregation_function("avg", values) do
    numbers = Enum.map(values, &to_number/1)
    if Enum.empty?(numbers), do: 0, else: Enum.sum(numbers) / length(numbers)
  end

  defp apply_aggregation_function("min", values) do
    values |> Enum.map(&to_number/1) |> Enum.min(fn -> 0 end)
  end

  defp apply_aggregation_function("max", values) do
    values |> Enum.map(&to_number/1) |> Enum.max(fn -> 0 end)
  end

  defp apply_aggregation_function("stddev", values) do
    numbers = Enum.map(values, &to_number/1)
    avg = Enum.sum(numbers) / max(length(numbers), 1)
    variance = Enum.sum(Enum.map(numbers, fn x -> :math.pow(x - avg, 2) end)) / max(length(numbers), 1)
    :math.sqrt(variance)
  end

  defp apply_aggregation_function("z_score", values) do
    numbers = Enum.map(values, &to_number/1)
    avg = Enum.sum(numbers) / max(length(numbers), 1)
    stddev = apply_aggregation_function("stddev", values)

    if stddev > 0 do
      last_value = List.last(numbers) || 0
      (last_value - avg) / stddev
    else
      0
    end
  end

  defp apply_aggregation_function(_, values), do: length(values)
end
