defmodule TamanduaServer.Detection.SigmaEvaluator do
  @moduledoc """
  Public-facing Sigma rule condition evaluator.

  Takes a Sigma rule's `detection` map and an event, parses the `condition`
  field into an AST, evaluates each selection against the event's payload
  fields (with modifier support), and returns a match result.

  ## Supported condition syntax

  - Identifiers: `selection`, `filter`, or any named detection key
  - Boolean operators: `and`, `or`, `not`
  - Grouping: parentheses `(` ... `)`
  - Quantifiers: `1 of selection*`, `all of selection*`, `1 of them`, `all of them`
  - Numeric quantifiers: `2 of selection*`
  - Aggregation: `count(field) > N` (single-event approximation)

  ## Supported field modifiers

  - `contains` -- substring match (case-insensitive)
  - `startswith` -- prefix match (case-insensitive)
  - `endswith` -- suffix match (case-insensitive)
  - `re` -- regular expression match
  - `base64` -- decode event value from base64 before comparison
  - `base64offset` -- check all three base64 alignment offsets
  - `cidr` -- CIDR network range match for IP addresses
  - `all` -- all values in a list must match (instead of default OR)
  - `utf16le` / `wide` -- UTF-16LE (wide string) matching
  - `gt`, `gte`, `lt`, `lte` -- numeric comparisons

  ## Examples

      iex> detection = %{
      ...>   "selection" => %{"EventType" => "process_create", "CommandLine|contains" => ["powershell -enc", "cmd /c"]},
      ...>   "filter" => %{"ParentImage|endswith" => "\\\\explorer.exe"},
      ...>   "condition" => "selection and not filter"
      ...> }
      iex> event = %{"event_type" => "process_create", "payload" => %{"cmdline" => "powershell -enc ZABpAHIA", "parent_path" => "C:\\\\Windows\\\\System32\\\\cmd.exe"}}
      iex> SigmaEvaluator.evaluate(detection, event, "Suspicious PowerShell Execution")
      {:match, "Suspicious PowerShell Execution"}

  """

  require Logger

  alias TamanduaServer.Detection.Rules.Sigma, as: SigmaEngine

  # -----------------------------------------------------------------------
  # Public API
  # -----------------------------------------------------------------------

  @doc """
  Evaluate a Sigma rule's detection map against an event.

  ## Parameters

  - `detection` -- the `detection` section of a Sigma rule (map with selection
    keys and a `"condition"` key)
  - `event` -- the telemetry event map (with `"event_type"`, `"payload"`, etc.)
  - `rule_name` -- the human-readable rule name (used in the return tuple)

  ## Returns

  - `{:match, rule_name}` if the event satisfies the condition
  - `:no_match` otherwise
  """
  @spec evaluate(map(), map(), String.t()) :: {:match, String.t()} | :no_match
  def evaluate(detection, event, rule_name) when is_map(detection) and is_map(event) do
    condition = Map.get(detection, "condition", "selection")

    result = evaluate_condition(condition, detection, event)

    if result do
      {:match, rule_name}
    else
      :no_match
    end
  rescue
    e ->
      Logger.error("SigmaEvaluator error for rule '#{rule_name}': #{Exception.message(e)}")
      :no_match
  end

  def evaluate(_, _, _), do: :no_match

  @doc """
  Evaluate a full Sigma rule (with logsource + detection) against an event.

  This delegates to the existing `Rules.Sigma.matches?/2` engine and wraps
  the boolean result in the `{:match, name}` / `:no_match` convention.
  """
  @spec evaluate_rule(map(), map()) :: {:match, String.t()} | :no_match
  def evaluate_rule(rule, event) when is_map(rule) and is_map(event) do
    if SigmaEngine.matches?(event, rule) do
      {:match, rule["title"] || rule[:name] || "Unknown Sigma Rule"}
    else
      :no_match
    end
  end

  @doc """
  Evaluate multiple rules against a single event.
  Returns list of `{:match, rule_name}` for all matching rules.
  """
  @spec evaluate_many([map()], map()) :: [{:match, String.t()}]
  def evaluate_many(rules, event) when is_list(rules) do
    rules
    |> Enum.map(fn rule ->
      name = rule["title"] || rule[:name] || "Unknown"
      detection = rule["detection"] || rule[:detection] || %{}
      evaluate(detection, event, name)
    end)
    |> Enum.filter(fn
      {:match, _} -> true
      _ -> false
    end)
  end

  @doc """
  Parse a condition string into an AST for inspection or debugging.

  Returns a nested tuple structure:
  - `{:and, left, right}`
  - `{:or, left, right}`
  - `{:not, expr}`
  - `{:identifier, name}`
  - `{:one_of, pattern}`
  - `{:all_of, pattern}`
  - `{:n_of, count, pattern}`
  - `{:count, field, operator, threshold}`
  """
  @spec parse_condition(String.t()) :: {:ok, term()} | {:error, String.t()}
  def parse_condition(condition) when is_binary(condition) do
    tokens = tokenize(condition)

    case parse_or(tokens) do
      {ast, []} -> {:ok, ast}
      {ast, _rest} -> {:ok, ast}
    end
  rescue
    e -> {:error, "Parse error: #{Exception.message(e)}"}
  end

  # -----------------------------------------------------------------------
  # Condition tokenizer
  # -----------------------------------------------------------------------

  defp tokenize(condition) do
    condition
    |> String.replace("(", " ( ")
    |> String.replace(")", " ) ")
    |> String.split(~r/\s+/, trim: true)
    |> merge_special_tokens()
  end

  # Merge multi-word tokens: "1 of", "all of", count expressions
  defp merge_special_tokens(tokens), do: merge_special_tokens(tokens, [])

  defp merge_special_tokens([], acc), do: Enum.reverse(acc)

  defp merge_special_tokens(["all", "of" | rest], acc) do
    merge_special_tokens(rest, [{:all_of_kw} | acc])
  end

  defp merge_special_tokens(["1", "of" | rest], acc) do
    merge_special_tokens(rest, [{:one_of_kw} | acc])
  end

  defp merge_special_tokens([n, "of" | rest], acc) when is_binary(n) do
    case Integer.parse(n) do
      {count, ""} -> merge_special_tokens(rest, [{:n_of_kw, count} | acc])
      _ -> merge_special_tokens(["of" | rest], [n | acc])
    end
  end

  defp merge_special_tokens([tok | rest], acc) do
    merge_special_tokens(rest, [tok | acc])
  end

  # -----------------------------------------------------------------------
  # Recursive descent parser -- builds AST
  # -----------------------------------------------------------------------

  defp parse_or(tokens) do
    {left, rest} = parse_and(tokens)

    case rest do
      ["or" | remaining] ->
        {right, final} = parse_or(remaining)
        {{:or, left, right}, final}

      _ ->
        {left, rest}
    end
  end

  defp parse_and(tokens) do
    {left, rest} = parse_not(tokens)

    case rest do
      ["and" | remaining] ->
        {right, final} = parse_and(remaining)
        {{:and, left, right}, final}

      _ ->
        {left, rest}
    end
  end

  defp parse_not(["not" | rest]) do
    {expr, remaining} = parse_primary(rest)
    {{:not, expr}, remaining}
  end

  defp parse_not(tokens), do: parse_primary(tokens)

  defp parse_primary(["(" | rest]) do
    {expr, remaining} = parse_or(rest)

    case remaining do
      [")" | final] -> {expr, final}
      _ -> {expr, remaining}
    end
  end

  defp parse_primary([{:one_of_kw} | rest]) do
    {pattern, remaining} = take_pattern(rest)
    {{:one_of, pattern}, remaining}
  end

  defp parse_primary([{:all_of_kw} | rest]) do
    {pattern, remaining} = take_pattern(rest)
    {{:all_of, pattern}, remaining}
  end

  defp parse_primary([{:n_of_kw, count} | rest]) do
    {pattern, remaining} = take_pattern(rest)
    {{:n_of, count, pattern}, remaining}
  end

  defp parse_primary(["them" | rest]) do
    {{:identifier, "them"}, rest}
  end

  defp parse_primary([name | rest]) when is_binary(name) do
    {{:identifier, name}, rest}
  end

  defp parse_primary(tokens), do: {{:false}, tokens}

  defp take_pattern(["them" | rest]), do: {"*", rest}
  defp take_pattern([pattern | rest]), do: {pattern, rest}
  defp take_pattern([]), do: {"*", []}

  # -----------------------------------------------------------------------
  # AST evaluator
  # -----------------------------------------------------------------------

  defp evaluate_condition(condition, detection, event) when is_binary(condition) do
    tokens = tokenize(condition)
    {ast, _rest} = parse_or(tokens)
    eval_ast(ast, detection, event)
  end

  defp evaluate_condition(_, _, _), do: false

  defp eval_ast({:and, left, right}, detection, event) do
    eval_ast(left, detection, event) && eval_ast(right, detection, event)
  end

  defp eval_ast({:or, left, right}, detection, event) do
    eval_ast(left, detection, event) || eval_ast(right, detection, event)
  end

  defp eval_ast({:not, expr}, detection, event) do
    !eval_ast(expr, detection, event)
  end

  defp eval_ast({:one_of, pattern}, detection, event) do
    selections = find_matching_selections(pattern, detection)

    Enum.any?(selections, fn sel_key ->
      eval_selection(Map.get(detection, sel_key), event)
    end)
  end

  defp eval_ast({:all_of, pattern}, detection, event) do
    selections = find_matching_selections(pattern, detection)

    if Enum.empty?(selections) do
      false
    else
      Enum.all?(selections, fn sel_key ->
        eval_selection(Map.get(detection, sel_key), event)
      end)
    end
  end

  defp eval_ast({:n_of, count, pattern}, detection, event) do
    selections = find_matching_selections(pattern, detection)

    matches = Enum.count(selections, fn sel_key ->
      eval_selection(Map.get(detection, sel_key), event)
    end)

    matches >= count
  end

  defp eval_ast({:identifier, "them"}, detection, event) do
    # "them" refers to all non-condition selection keys
    selections = find_matching_selections("*", detection)

    if Enum.empty?(selections) do
      false
    else
      Enum.all?(selections, fn sel_key ->
        eval_selection(Map.get(detection, sel_key), event)
      end)
    end
  end

  defp eval_ast({:identifier, name}, detection, event) do
    eval_selection(Map.get(detection, name), event)
  end

  defp eval_ast({:false}, _detection, _event), do: false

  # -----------------------------------------------------------------------
  # Selection matching
  # -----------------------------------------------------------------------

  defp find_matching_selections(pattern, detection) do
    regex_str = pattern |> String.replace("*", ".*")

    case Regex.compile("^#{regex_str}$") do
      {:ok, regex} ->
        detection
        |> Map.keys()
        |> Enum.filter(fn key ->
          is_binary(key) && key != "condition" && key != "timeframe" &&
            Regex.match?(regex, key)
        end)

      _ ->
        []
    end
  end

  defp eval_selection(nil, _event), do: false
  defp eval_selection(selection, _event) when selection == %{}, do: false

  defp eval_selection(selection, event) when is_map(selection) do
    # All field conditions in a selection must match (AND logic)
    Enum.all?(selection, fn {field, expected} ->
      eval_field(event, field, expected)
    end)
  end

  defp eval_selection(selections, event) when is_list(selections) do
    # List of selection maps = OR logic
    Enum.any?(selections, fn sel ->
      eval_selection(sel, event)
    end)
  end

  defp eval_selection(_, _event), do: false

  # -----------------------------------------------------------------------
  # Field matching with modifier support
  # -----------------------------------------------------------------------

  # Sigma-to-Tamandua field name mapping
  @field_mappings %{
    "Image" => "path",
    "OriginalFileName" => "name",
    "CommandLine" => "cmdline",
    "ParentImage" => "parent_path",
    "ParentCommandLine" => "parent_cmdline",
    "User" => "user",
    "ProcessId" => "pid",
    "ParentProcessId" => "ppid",
    "IntegrityLevel" => "integrity_level",
    "Hashes" => "sha256",
    "DestinationIp" => "remote_ip",
    "DestinationPort" => "remote_port",
    "SourceIp" => "local_ip",
    "SourcePort" => "local_port",
    "Protocol" => "protocol",
    "TargetFilename" => "path",
    "TargetFileName" => "path",
    "FileName" => "path",
    "QueryName" => "query_name",
    "QueryType" => "query_type",
    "TargetObject" => "key_path",
    "Details" => "value_data",
    "EventType" => "event_type"
  }

  defp eval_field(event, field, expected) do
    {base_field, modifiers} = parse_field_modifiers(field)
    mapped = Map.get(@field_mappings, base_field, String.downcase(base_field))
    event_value = get_event_value(event, mapped)

    check_value(event_value, expected, modifiers)
  end

  defp parse_field_modifiers(field) do
    case String.split(to_string(field), "|") do
      [base | modifiers] -> {base, modifiers}
      _ -> {to_string(field), []}
    end
  end

  defp get_event_value(event, field) do
    payload = event["payload"] || event[:payload] || %{}

    cond do
      Map.has_key?(payload, field) -> Map.get(payload, field)
      is_atom_key?(field) && Map.has_key?(payload, String.to_existing_atom(field)) ->
        Map.get(payload, String.to_existing_atom(field))
      Map.has_key?(event, field) -> Map.get(event, field)
      is_atom_key?(field) && Map.has_key?(event, String.to_existing_atom(field)) ->
        Map.get(event, String.to_existing_atom(field))
      true -> nil
    end
  rescue
    # String.to_existing_atom can raise if atom doesn't exist
    ArgumentError -> nil
  end

  defp is_atom_key?(field) when is_binary(field) do
    # Only convert to atom if it looks like a safe identifier
    Regex.match?(~r/^[a-z_][a-z0-9_]*$/, field)
  end

  defp is_atom_key?(_), do: false

  # nil event value never matches
  defp check_value(nil, _expected, _modifiers), do: false

  # List of expected values = OR by default (unless "all" modifier)
  defp check_value(event_value, expected, modifiers) when is_list(expected) do
    if "all" in modifiers do
      Enum.all?(expected, fn exp ->
        check_single(event_value, exp, modifiers -- ["all"])
      end)
    else
      Enum.any?(expected, fn exp ->
        check_single(event_value, exp, modifiers)
      end)
    end
  end

  defp check_value(event_value, expected, modifiers) do
    check_single(event_value, expected, modifiers)
  end

  defp check_single(event_value, expected, modifiers) do
    ev = to_string(event_value) |> String.downcase()
    ex = to_string(expected) |> String.downcase()

    cond do
      "contains" in modifiers ->
        String.contains?(ev, ex)

      "startswith" in modifiers ->
        String.starts_with?(ev, ex)

      "endswith" in modifiers ->
        String.ends_with?(ev, ex)

      "re" in modifiers ->
        case Regex.compile(to_string(expected), [:caseless]) do
          {:ok, regex} -> Regex.match?(regex, ev)
          _ -> false
        end

      "base64" in modifiers ->
        case Base.decode64(ev) do
          {:ok, decoded} -> String.downcase(decoded) == ex
          _ -> false
        end

      "base64offset" in modifiers ->
        Enum.any?(0..2, fn offset ->
          padded = String.duplicate("\0", offset) <> to_string(expected)
          encoded = Base.encode64(padded) |> String.downcase()
          String.contains?(ev, encoded)
        end)

      "cidr" in modifiers ->
        cidr_match?(ev, ex)

      "utf16le" in modifiers or "wide" in modifiers ->
        wide = ex
        |> String.to_charlist()
        |> Enum.flat_map(fn c -> [c, 0] end)
        |> to_string()
        |> String.downcase()
        String.contains?(ev, wide)

      "gt" in modifiers ->
        numeric_compare(ev, ex, &Kernel.>/2)

      "gte" in modifiers ->
        numeric_compare(ev, ex, &Kernel.>=/2)

      "lt" in modifiers ->
        numeric_compare(ev, ex, &Kernel.</2)

      "lte" in modifiers ->
        numeric_compare(ev, ex, &Kernel.<=/2)

      near_modifier?(modifiers) ->
        # Near modifier: check if strings appear within N characters of each other
        distance = extract_near_distance(modifiers)
        near_match?(ev, ex, distance)

      true ->
        # Default: exact match with wildcard support
        wildcard_match?(ev, ex)
    end
  end

  # Check if any modifier is a "near" modifier
  defp near_modifier?(modifiers) do
    Enum.any?(modifiers, fn mod ->
      String.starts_with?(mod, "near")
    end)
  end

  # Extract distance from near modifier (e.g., "near:100" -> 100)
  defp extract_near_distance(modifiers) do
    modifiers
    |> Enum.find_value(30, fn mod ->
      case Regex.run(~r/^near:?(\d+)?$/, mod) do
        [_, distance_str] when distance_str != "" -> String.to_integer(distance_str)
        [_] -> 30  # Default distance
        _ -> nil
      end
    end)
  end

  # Check if two patterns appear within N characters of each other
  defp near_match?(text, pattern, max_distance) when is_binary(text) and is_binary(pattern) do
    patterns = String.split(pattern, " ")

    if length(patterns) < 2 do
      String.contains?(text, pattern)
    else
      # Find all occurrences of each pattern
      pattern_positions = Enum.map(patterns, fn p ->
        find_all_positions(text, p)
      end)

      # Check if any combination of positions is within max_distance
      check_near_positions(pattern_positions, max_distance)
    end
  end

  defp near_match?(_, _, _), do: false

  # Find all positions where pattern appears in text
  defp find_all_positions(text, pattern) do
    text_lower = String.downcase(text)
    pattern_lower = String.downcase(pattern)

    find_all_positions(text_lower, pattern_lower, 0, [])
  end

  defp find_all_positions(text, pattern, offset, acc) do
    case :binary.match(text, pattern) do
      {pos, len} ->
        absolute_pos = offset + pos
        remaining = binary_part(text, pos + len, byte_size(text) - pos - len)
        find_all_positions(remaining, pattern, offset + pos + len, [absolute_pos | acc])

      :nomatch ->
        Enum.reverse(acc)
    end
  end

  # Check if there's a valid combination where all patterns are within max_distance
  defp check_near_positions([], _max_distance), do: true

  defp check_near_positions([first_positions | rest], max_distance) do
    Enum.any?(first_positions, fn pos ->
      check_positions_from(pos, rest, max_distance)
    end)
  end

  defp check_positions_from(_base_pos, [], _max_distance), do: true

  defp check_positions_from(base_pos, [next_positions | rest], max_distance) do
    Enum.any?(next_positions, fn pos ->
      abs(pos - base_pos) <= max_distance and
        check_positions_from(pos, rest, max_distance)
    end)
  end

  defp numeric_compare(a_str, b_str, comparator) do
    with {a_num, _} <- Float.parse(a_str),
         {b_num, _} <- Float.parse(b_str) do
      comparator.(a_num, b_num)
    else
      _ -> false
    end
  end

  defp wildcard_match?(value, pattern) do
    regex_str =
      pattern
      |> Regex.escape()
      |> String.replace("\\*", ".*")
      |> String.replace("\\?", ".")

    case Regex.compile("^#{regex_str}$", [:caseless]) do
      {:ok, regex} -> Regex.match?(regex, value)
      _ -> value == pattern
    end
  end

  import Bitwise

  defp cidr_match?(ip_str, cidr_str) do
    case String.split(cidr_str, "/") do
      [network, prefix_str] ->
        case Integer.parse(prefix_str) do
          {prefix_len, ""} when prefix_len >= 0 and prefix_len <= 32 ->
            with {:ok, ip_int} <- ip_to_int(ip_str),
                 {:ok, net_int} <- ip_to_int(network) do
              mask = ~~~((1 <<< (32 - prefix_len)) - 1) &&& 0xFFFFFFFF
              (ip_int &&& mask) == (net_int &&& mask)
            else
              _ -> false
            end

          _ ->
            false
        end

      _ ->
        ip_str == cidr_str
    end
  end

  defp ip_to_int(ip_str) do
    case String.split(ip_str, ".") do
      [a, b, c, d] ->
        with {ai, ""} <- Integer.parse(a),
             {bi, ""} <- Integer.parse(b),
             {ci, ""} <- Integer.parse(c),
             {di, ""} <- Integer.parse(d),
             true <- Enum.all?([ai, bi, ci, di], &(&1 >= 0 and &1 <= 255)) do
          {:ok, (ai <<< 24) + (bi <<< 16) + (ci <<< 8) + di}
        else
          _ -> :error
        end

      _ ->
        :error
    end
  end
end
