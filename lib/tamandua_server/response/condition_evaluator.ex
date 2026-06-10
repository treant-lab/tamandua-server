defmodule TamanduaServer.Response.ConditionEvaluator do
  @moduledoc """
  Evaluates trigger and step conditions for playbook execution.

  Supports a rich set of condition types including severity comparison,
  MITRE technique matching, agent tag filtering, time windows,
  count thresholds, and boolean combinators (and/or/not).

  Conditions are expressed as maps with a "type" key and type-specific
  parameters. For example:

      %{"type" => "severity_gte", "value" => "high"}
      %{"type" => "and", "conditions" => [cond1, cond2]}
  """

  require Logger

  @severity_levels %{
    "info" => 0,
    "low" => 1,
    "medium" => 2,
    "high" => 3,
    "critical" => 4
  }

  @doc """
  Evaluate a condition against the given context.

  The context is a map containing alert, agent, and event data
  that the condition can reference.

  Returns `true` if the condition is met, `false` otherwise.
  """
  @spec evaluate(map() | nil, map()) :: boolean()
  def evaluate(nil, _context), do: true
  def evaluate(%{} = condition, context) when map_size(condition) == 0, do: true

  def evaluate(%{"type" => "severity_gte", "value" => min_severity}, context) do
    context_severity = get_context_value(context, :severity)
    severity_to_int(context_severity) >= severity_to_int(min_severity)
  end

  def evaluate(%{"type" => "severity_lte", "value" => max_severity}, context) do
    context_severity = get_context_value(context, :severity)
    severity_to_int(context_severity) <= severity_to_int(max_severity)
  end

  def evaluate(%{"type" => "mitre_technique_in", "value" => techniques}, context)
      when is_list(techniques) do
    context_techniques = get_context_list(context, :mitre_techniques)
    Enum.any?(context_techniques, &(&1 in techniques))
  end

  def evaluate(%{"type" => "mitre_tactic_in", "value" => tactics}, context)
      when is_list(tactics) do
    context_tactics = get_context_list(context, :mitre_tactics)
    Enum.any?(context_tactics, &(&1 in tactics))
  end

  def evaluate(%{"type" => "agent_tag_in", "value" => tags}, context)
      when is_list(tags) do
    agent_tags = get_context_list(context, :agent_tags)
    Enum.any?(agent_tags, &(&1 in tags))
  end

  def evaluate(%{"type" => "time_window", "value" => window_seconds}, context) do
    event_time = get_context_value(context, :event_time) || get_context_value(context, :timestamp)

    case parse_datetime(event_time) do
      {:ok, dt} ->
        now = DateTime.utc_now()
        DateTime.diff(now, dt, :second) <= window_seconds

      _ ->
        # If we cannot parse the time, assume the condition is met
        # (the event is recent enough)
        true
    end
  end

  def evaluate(%{"type" => "count_gte", "value" => threshold, "field" => field}, context) do
    count = get_context_value(context, field)

    case count do
      n when is_integer(n) -> n >= threshold
      n when is_float(n) -> n >= threshold
      _ -> false
    end
  end

  def evaluate(%{"type" => "count_gte", "value" => threshold}, context) do
    count = get_context_value(context, :count) || get_context_value(context, :occurrence_count) || 0

    case count do
      n when is_integer(n) -> n >= threshold
      n when is_float(n) -> n >= threshold
      _ -> false
    end
  end

  def evaluate(%{"type" => "field_equals", "field" => field, "value" => value}, context) do
    get_context_value(context, field) == value
  end

  def evaluate(%{"type" => "field_contains", "field" => field, "value" => value}, context) do
    context_value = get_context_value(context, field)

    case context_value do
      s when is_binary(s) -> String.contains?(s, to_string(value))
      l when is_list(l) -> value in l
      _ -> false
    end
  end

  def evaluate(%{"type" => "field_matches", "field" => field, "value" => pattern}, context) do
    context_value = get_context_value(context, field)

    case {context_value, Regex.compile(to_string(pattern))} do
      {s, {:ok, regex}} when is_binary(s) -> Regex.match?(regex, s)
      _ -> false
    end
  end

  # Boolean combinators
  def evaluate(%{"type" => "and", "conditions" => conditions}, context)
      when is_list(conditions) do
    Enum.all?(conditions, &evaluate(&1, context))
  end

  def evaluate(%{"type" => "or", "conditions" => conditions}, context)
      when is_list(conditions) do
    Enum.any?(conditions, &evaluate(&1, context))
  end

  def evaluate(%{"type" => "not", "condition" => condition}, context) do
    not evaluate(condition, context)
  end

  # Legacy simple condition format (field/operator/value)
  def evaluate(%{"field" => field, "operator" => operator, "value" => value}, context) do
    context_value = get_context_value(context, field)
    evaluate_operator(operator, context_value, value)
  end

  # Fail closed for unknown condition formats.
  def evaluate(condition, _context) do
    Logger.warning("Unknown condition type, denying: #{inspect(condition)}")
    false
  end

  @doc """
  Evaluate a list of trigger conditions (map of key => value).

  This is used for playbook trigger condition matching where conditions
  are stored as a flat map like %{"severity" => "high", "detection_type" => "ransomware"}.
  """
  @spec evaluate_trigger_conditions(map() | nil, map()) :: boolean()
  def evaluate_trigger_conditions(nil, _context), do: true
  def evaluate_trigger_conditions(conditions, _context) when map_size(conditions) == 0, do: true

  def evaluate_trigger_conditions(conditions, context) when is_map(conditions) do
    Enum.all?(conditions, fn {key, value} ->
      evaluate_trigger_field(key, value, context)
    end)
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp evaluate_trigger_field("severity", value, context) do
    context_severity = get_context_value(context, :severity)
    severity_to_int(context_severity) >= severity_to_int(value)
  end

  defp evaluate_trigger_field("detection_type", value, context) do
    context_type = get_context_value(context, :detection_type)
    context_type == value
  end

  defp evaluate_trigger_field("mitre_tactic", value, context) do
    tactics = get_context_list(context, :mitre_tactics)
    value in tactics
  end

  defp evaluate_trigger_field("mitre_technique", value, context) do
    techniques = get_context_list(context, :mitre_techniques)

    Enum.any?(techniques, fn t ->
      t == value or String.starts_with?(to_string(t), to_string(value))
    end)
  end

  defp evaluate_trigger_field("process_name", value, context) do
    process_name = get_context_value(context, :process_name)
    matches_pattern?(process_name, value)
  end

  defp evaluate_trigger_field("category", value, context) do
    category = get_context_value(context, :category)
    category == value
  end

  defp evaluate_trigger_field(_key, _value, _context), do: true

  defp evaluate_operator("equals", context_value, value), do: context_value == value
  defp evaluate_operator("not_equals", context_value, value), do: context_value != value

  defp evaluate_operator("contains", context_value, value) when is_binary(context_value) do
    String.contains?(context_value, to_string(value))
  end

  defp evaluate_operator("contains", context_value, value) when is_list(context_value) do
    value in context_value
  end

  defp evaluate_operator("contains", _context_value, _value), do: false

  defp evaluate_operator("greater_than", context_value, value)
       when is_number(context_value) and is_number(value) do
    context_value > value
  end

  defp evaluate_operator("greater_than", _, _), do: false

  defp evaluate_operator("less_than", context_value, value)
       when is_number(context_value) and is_number(value) do
    context_value < value
  end

  defp evaluate_operator("less_than", _, _), do: false

  defp evaluate_operator("in", context_value, values) when is_list(values) do
    context_value in values
  end

  defp evaluate_operator("in", _, _), do: false

  defp evaluate_operator("not_in", context_value, values) when is_list(values) do
    context_value not in values
  end

  defp evaluate_operator("not_in", _, _), do: true

  defp evaluate_operator("matches", context_value, pattern) when is_binary(context_value) do
    matches_pattern?(context_value, pattern)
  end

  defp evaluate_operator("matches", _, _), do: false
  defp evaluate_operator(_, _, _), do: false

  defp severity_to_int(severity) when is_binary(severity) do
    Map.get(@severity_levels, String.downcase(severity), 0)
  end

  defp severity_to_int(severity) when is_atom(severity) do
    severity_to_int(Atom.to_string(severity))
  end

  defp severity_to_int(_), do: 0

  defp get_context_value(context, key) when is_atom(key) do
    Map.get(context, key) || Map.get(context, Atom.to_string(key))
  end

  defp get_context_value(context, key) when is_binary(key) do
    atom_key =
      try do
        String.to_existing_atom(key)
      rescue
        _ -> nil
      end

    Map.get(context, key) || (atom_key && Map.get(context, atom_key))
  end

  defp get_context_list(context, key) do
    case get_context_value(context, key) do
      list when is_list(list) -> list
      _ -> []
    end
  end

  defp matches_pattern?(nil, _), do: false

  defp matches_pattern?(value, pattern) when is_binary(value) and is_binary(pattern) do
    case Regex.compile(pattern) do
      {:ok, regex} -> Regex.match?(regex, value)
      _ -> value == pattern
    end
  end

  defp matches_pattern?(_, _), do: false

  defp parse_datetime(%DateTime{} = dt), do: {:ok, dt}

  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _offset} -> {:ok, dt}
      _ -> :error
    end
  end

  defp parse_datetime(_), do: :error
end
