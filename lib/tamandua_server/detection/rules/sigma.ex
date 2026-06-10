defmodule TamanduaServer.Detection.Rules.Sigma do
  @moduledoc """
  Sigma rule parser and matcher.

  Implements the Sigma rule specification for log event matching.
  Supports:
  - Logsource filtering (category, product, service)
  - Selection conditions with field matching
  - Value modifiers (contains, startswith, endswith, re, base64, etc.)
  - Condition logic (and, or, not, 1 of, all of)
  - Timeframe aggregations (basic support)

  Reference: https://github.com/SigmaHQ/sigma-specification
  """

  require Logger
  import Bitwise

  @type rule :: map()
  @type event :: map()

  # Common field mappings from Sigma to Tamandua event schema
  @field_mappings %{
    # Process fields
    "Image" => "path",
    "TargetImage" => "target_image",
    "SourceImage" => "source_image",
    "ImageLoaded" => "module_path",
    "OriginalFileName" => "name",
    "CommandLine" => "cmdline",
    "ParentImage" => "parent_path",
    "ParentCommandLine" => "parent_cmdline",
    "User" => "user",
    "ProcessId" => "pid",
    "ParentProcessId" => "ppid",
    "GrantedAccess" => "granted_access",
    "CallTrace" => "call_trace",
    "EventID" => "event_id",
    "IntegrityLevel" => "integrity_level",
    "Hashes" => "sha256",
    # Network fields
    "DestinationIp" => "remote_ip",
    "DestinationHostname" => "domain",
    "DestinationPort" => "remote_port",
    "SourceIp" => "local_ip",
    "SourcePort" => "local_port",
    "Initiated" => "initiated",
    "Protocol" => "protocol",
    # File fields
    "TargetFilename" => "path",
    "TargetFileName" => "path",
    "FileName" => "path",
    # DNS fields
    "QueryName" => "query_name",
    "QueryType" => "query_type",
    # Registry fields
    "TargetObject" => "key_path",
    "Details" => "value_data",
    # Windows service / pipe / module aliases
    "ServiceName" => "service_name",
    "ServiceFileName" => "service_file_name",
    "PipeName" => "pipe_name",
    "module_path" => "module_path",
    "registry_key" => "key_path",
    # LLM request fields
    "Provider" => "api_provider",
    "Endpoint" => "api_endpoint",
    "PromptPreview" => "prompt_preview",
    "PromptHash" => "full_prompt_hash",
    "Model" => "model",
    "ProcessName" => "process_name",
    "ProcessPath" => "process_path",
    "PID" => "pid",
    # AI/devtool inventory fields
    "ArtifactType" => "artifact_type",
    "MatchedPatterns" => "matched_patterns",
    "AIDiscovery" => "ai_discovery"
  }

  @event_field_aliases %{
    "path" => ["path", "exe_path", "image_path", "process_path", "process.path", "name", "process_name"],
    "target_image" => ["target_image", "target_process_path", "target_path", "target_name"],
    "source_image" => ["source_image", "source_process_path", "source_path", "source_name"],
    "module_path" => ["module_path", "image_path", "path", "module.path"],
    "cmdline" => ["cmdline", "command_line", "process_command_line", "command", "process.command_line"],
    "parent_path" => ["parent_path", "parent_image", "parent_process_path", "parent_name", "parent_process_name"],
    "parent_cmdline" => ["parent_cmdline", "parent_command_line", "parent_process_command_line"],
    "key_path" => ["key_path", "registry_key", "registry_path", "target_object", "target_name", "object_name"],
    "value_data" => ["value_data", "registry_value", "registry_value_data", "details"],
    "query_name" => ["query_name", "query", "domain", "dns_query", "dns.query"],
    "remote_ip" => ["remote_ip", "dst_ip", "destination_ip", "network.remote_ip"],
    "remote_port" => ["remote_port", "dst_port", "destination_port", "network.remote_port"],
    "local_ip" => ["local_ip", "src_ip", "source_ip", "network.local_ip"],
    "local_port" => ["local_port", "src_port", "source_port", "network.local_port"],
    "process_name" => ["process_name", "name", "image_name", "process.name"],
    "process_path" => ["process_path", "path", "exe_path", "image_path", "process.path"]
  }

  # Logsource category to event_type mapping
  @category_mappings %{
    "process_creation" => ["process_create"],
    "process_access" => ["process_access", "process_inject"],
    "process_termination" => ["process_terminate"],
    "file_event" => ["file_create", "file_modify", "file_delete", "file_read", "module_load"],
    "file_access" => ["file_read"],
    "file_change" => ["file_modify"],
    "file_delete" => ["file_delete"],
    "file_rename" => ["file_rename"],
    "network_connection" => ["network_connect"],
    "dns_query" => ["dns_query"],
    "registry_event" => ["registry_create", "registry_modify", "registry_delete"],
    "registry_add" => ["registry_create"],
    "registry_delete" => ["registry_delete"],
    "registry_set" => ["registry_modify", "registry_set_value"],
    "image_load" => ["module_load"],
    "pipe_created" => ["pipe_create"],
    "llm_request" => ["llm_request", "llm_api_request"],
    "software_inventory" => ["software_inventory"]
  }

  @doc """
  Checks if a given event matches a Sigma rule.

  ## Parameters
  - event: The telemetry event to check
  - rule: The parsed Sigma rule

  ## Returns
  - true if the event matches the rule
  - false otherwise
  """
  @spec matches?(event(), rule()) :: boolean()
  def matches?(event, rule) do
    with true <- matches_logsource?(event, rule),
         true <- matches_detection?(event, rule) do
      true
    else
      _ -> false
    end
  end

  @doc """
  Parses a Sigma rule from YAML string.
  """
  @spec parse(String.t()) :: {:ok, rule()} | {:error, String.t()}
  def parse(yaml_content) do
    case YamlElixir.read_from_string(yaml_content) do
      {:ok, rule} when is_map(rule) ->
        validate_rule(rule)

      {:ok, _} ->
        {:error, "Invalid rule format: expected a map"}

      {:error, reason} ->
        {:error, "YAML parse error: #{inspect(reason)}"}
    end
  rescue
    e -> {:error, "Parse error: #{Exception.message(e)}"}
  end

  @doc """
  Parses a Sigma rule from YAML string without validation.
  Returns a simplified map structure.
  """
  @spec from_yaml(String.t()) :: {:ok, map()} | {:error, any()}
  def from_yaml(yaml_content) when is_binary(yaml_content) do
    case YamlElixir.read_from_string(yaml_content) do
      {:ok, parsed} -> {:ok, parse_sigma_rule(parsed)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp parse_sigma_rule(yaml_map) do
    %{
      title: yaml_map["title"],
      description: yaml_map["description"],
      status: yaml_map["status"],
      level: yaml_map["level"],
      logsource: yaml_map["logsource"],
      detection: yaml_map["detection"],
      tags: yaml_map["tags"] || [],
      references: yaml_map["references"] || [],
      # Solana base58 public key for bounty payments
      author_pubkey: yaml_map["author_pubkey"]
    }
  end

  @doc """
  Validates a parsed Sigma rule has required fields.
  """
  @spec validate_rule(rule()) :: {:ok, rule()} | {:error, String.t()}
  def validate_rule(rule) do
    required = ["title", "logsource", "detection"]

    missing = Enum.filter(required, fn field -> !Map.has_key?(rule, field) end)

    if Enum.empty?(missing) do
      {:ok, normalize_rule(rule)}
    else
      {:error, "Missing required fields: #{Enum.join(missing, ", ")}"}
    end
  end

  # Normalize rule for easier processing
  defp normalize_rule(rule) do
    rule
    |> Map.update("logsource", %{}, &normalize_logsource/1)
    |> Map.update("detection", %{}, &normalize_detection/1)
  end

  defp normalize_logsource(logsource) when is_map(logsource) do
    logsource
    |> Enum.map(fn {k, v} -> {String.downcase(to_string(k)), v} end)
    |> Map.new()
  end

  defp normalize_logsource(_), do: %{}

  defp normalize_detection(detection) when is_map(detection) do
    detection
    |> Enum.map(fn {k, v} ->
      {to_string(k), normalize_detection_value(v)}
    end)
    |> Map.new()
  end

  defp normalize_detection(_), do: %{}

  defp normalize_detection_value(value) when is_map(value), do: value
  defp normalize_detection_value(value) when is_list(value), do: value
  defp normalize_detection_value(value), do: value

  # Check if event matches the logsource
  defp matches_logsource?(event, %{"logsource" => logsource}) do
    event_type = event["event_type"] || event[:event_type]

    category = logsource["category"]
    product = logsource["product"]
    service = logsource["service"]

    # Check category mapping
    category_match =
      if category do
        expected_types = Map.get(@category_mappings, category, [])
        event_type_str = to_string(event_type)
        Enum.any?(expected_types, &(&1 == event_type_str))
      else
        true
      end

    # Check product (OS)
    product_match =
      if product do
        os_type = event["os_type"] || event[:os_type]

        case String.downcase(product) do
          "windows" -> os_type in ["windows", nil]
          "linux" -> os_type in ["linux", nil]
          "macos" -> os_type in ["macos", "darwin", nil]
          _ -> true
        end
      else
        true
      end

    # Service is typically for specific log sources, skip for now
    _ = service

    category_match && product_match
  end

  defp matches_logsource?(_, _), do: true

  # Check if event matches the detection section
  defp matches_detection?(event, %{"detection" => detection}) do
    condition = Map.get(detection, "condition", "selection")
    evaluate_condition(condition, detection, event)
  end

  defp matches_detection?(_, _), do: false

  # Evaluate the condition expression
  defp evaluate_condition(condition, detection, event) when is_binary(condition) do
    # Parse and evaluate the condition
    condition
    |> tokenize_condition()
    |> parse_condition_tokens(detection, event)
  end

  defp evaluate_condition(_, _, _), do: false

  # Tokenize condition string
  defp tokenize_condition(condition) do
    # Comprehensive tokenizer for Sigma conditions
    # Handles: and, or, not, (, ), 1 of, all of, them, |, >, <, =, count(), selection names
    condition
    |> String.replace("(", " ( ")
    |> String.replace(")", " ) ")
    |> String.replace("|", " | ")
    |> String.replace(">", " > ")
    |> String.replace("<", " < ")
    |> String.replace(">=", " >= ")
    |> String.replace("<=", " <= ")
    |> String.replace("==", " == ")
    |> String.split(~r/\s+/, trim: true)
    |> merge_count_tokens()
  end

  # Merge "count", "(", ")", ">", "N" into a single token
  defp merge_count_tokens(tokens) do
    merge_count_tokens(tokens, [])
  end

  defp merge_count_tokens([], acc), do: Enum.reverse(acc)

  defp merge_count_tokens(["count" | rest], acc) do
    # Find the full count expression: count(field) > N
    case rest do
      ["(" | more] ->
        # Find closing paren and comparison
        {field, after_paren} = extract_count_expression(more, [])
        case after_paren do
          [op, num | remaining] when op in [">", "<", ">=", "<=", "==", "="] ->
            merge_count_tokens(remaining, [{:count, field, op, num} | acc])
          _ ->
            merge_count_tokens(after_paren, [{:count, field, ">", "0"} | acc])
        end
      _ ->
        merge_count_tokens(rest, ["count" | acc])
    end
  end

  defp merge_count_tokens([token | rest], acc) do
    merge_count_tokens(rest, [token | acc])
  end

  defp extract_count_expression([")" | rest], acc) do
    {Enum.reverse(acc) |> Enum.join(""), rest}
  end

  defp extract_count_expression([token | rest], acc) do
    extract_count_expression(rest, [token | acc])
  end

  defp extract_count_expression([], acc) do
    {Enum.reverse(acc) |> Enum.join(""), []}
  end

  # Parse and evaluate condition tokens
  defp parse_condition_tokens(tokens, detection, event) do
    {result, _} = parse_or_expression(tokens, detection, event)
    result
  end

  # OR has lowest precedence
  defp parse_or_expression(tokens, detection, event) do
    {left, rest} = parse_and_expression(tokens, detection, event)

    case rest do
      ["or" | remaining] ->
        {right, final_rest} = parse_or_expression(remaining, detection, event)
        {left || right, final_rest}

      _ ->
        {left, rest}
    end
  end

  # AND has higher precedence
  defp parse_and_expression(tokens, detection, event) do
    {left, rest} = parse_not_expression(tokens, detection, event)

    case rest do
      ["and" | remaining] ->
        {right, final_rest} = parse_and_expression(remaining, detection, event)
        {left && right, final_rest}

      _ ->
        {left, rest}
    end
  end

  # NOT has highest precedence
  defp parse_not_expression(["not" | rest], detection, event) do
    {value, remaining} = parse_primary_expression(rest, detection, event)
    {!value, remaining}
  end

  defp parse_not_expression(tokens, detection, event) do
    parse_primary_expression(tokens, detection, event)
  end

  # Primary expressions: parentheses, aggregations, or selection names
  defp parse_primary_expression(["(" | rest], detection, event) do
    {value, remaining} = parse_or_expression(rest, detection, event)

    case remaining do
      [")" | final_rest] -> {value, final_rest}
      _ -> {value, remaining}
    end
  end

  # Handle pipe operator for filter conditions (e.g., "selection | filter filter_name")
  # This is actually handled in post-processing, so we just parse it normally

  # "1 of selection*" or "all of selection*"
  defp parse_primary_expression(["1", "of" | rest], detection, event) do
    {pattern, remaining} = parse_selection_pattern(rest)
    selections = find_matching_selections(pattern, detection)

    result = Enum.any?(selections, fn sel ->
      selection_data = Map.get(detection, sel)
      matches_selection?(event, selection_data)
    end)

    {result, remaining}
  end

  defp parse_primary_expression(["all", "of" | rest], detection, event) do
    {pattern, remaining} = parse_selection_pattern(rest)
    selections = find_matching_selections(pattern, detection)

    result =
      if Enum.empty?(selections) do
        false
      else
        Enum.all?(selections, fn sel ->
          selection_data = Map.get(detection, sel)
          matches_selection?(event, selection_data)
        end)
      end

    {result, remaining}
  end

  # "them" keyword - matches all non-condition selections
  defp parse_primary_expression(["them" | rest], detection, event) do
    selections = find_matching_selections("*", detection)
    |> Enum.filter(fn sel -> !String.starts_with?(sel, "filter") end)

    result =
      if Enum.empty?(selections) do
        false
      else
        Enum.all?(selections, fn sel ->
          selection_data = Map.get(detection, sel)
          matches_selection?(event, selection_data)
        end)
      end

    {result, rest}
  end

  # Count expression: {:count, field, op, num}
  defp parse_primary_expression([{:count, field, op, num_str} | rest], _detection, event) do
    # Count aggregation - for single events, count is 1
    # This would need external state for proper aggregation
    # For now, implement simple check: if field matches, count as 1
    count =
      if field == "" do
        1 # count() with no field = count of matching events
      else
        # Count occurrences of field value
        case get_event_value(event, field) do
          nil -> 0
          val when is_list(val) -> length(val)
          _ -> 1
        end
      end

    num = String.to_integer(num_str)

    result = case op do
      ">" -> count > num
      ">=" -> count >= num
      "<" -> count < num
      "<=" -> count <= num
      "==" -> count == num
      "=" -> count == num
      _ -> false
    end

    {result, rest}
  end

  # Handle numeric "X of selection*" patterns (e.g., "2 of them")
  defp parse_primary_expression([count_str, "of" | rest], detection, event)
       when is_binary(count_str) do
    case Integer.parse(count_str) do
      {count, ""} ->
        {pattern, remaining} = parse_selection_pattern(rest)
        selections = find_matching_selections(pattern, detection)

        matches = Enum.count(selections, fn sel ->
          selection_data = Map.get(detection, sel)
          matches_selection?(event, selection_data)
        end)

        {matches >= count, remaining}

      _ ->
        # Not a number, treat as selection name
        selection_data = Map.get(detection, count_str)
        result = matches_selection?(event, selection_data)
        {result, ["of" | rest]}
    end
  end

  # Selection name (e.g., "selection", "filter")
  defp parse_primary_expression([name | rest], detection, event) do
    # Check for pipe filter pattern: result | filter filter_name
    case rest do
      ["|", "filter", filter_name | after_filter] ->
        selection_data = Map.get(detection, name)
        filter_data = Map.get(detection, filter_name)

        # Selection matches AND filter does NOT match (filter is exclusion)
        result = matches_selection?(event, selection_data) && !matches_selection?(event, filter_data)
        {result, after_filter}

      _ ->
        selection_data = Map.get(detection, name)
        result = matches_selection?(event, selection_data)
        {result, rest}
    end
  end

  defp parse_primary_expression([], _detection, _event), do: {false, []}

  defp parse_selection_pattern([pattern | rest]) do
    {pattern, rest}
  end

  defp parse_selection_pattern([]), do: {"*", []}

  # Find selections matching a pattern (e.g., "selection*" matches "selection", "selection_1")
  defp find_matching_selections(pattern, detection) do
    pattern_regex =
      pattern
      |> String.replace("*", ".*")
      |> Regex.compile!()

    detection
    |> Map.keys()
    |> Enum.filter(fn key ->
      key != "condition" && Regex.match?(pattern_regex, key)
    end)
  end

  # Check if event matches a selection
  defp matches_selection?(_event, nil), do: false
  defp matches_selection?(_event, selection) when selection == %{}, do: false

  defp matches_selection?(event, selection) when is_map(selection) do
    Enum.all?(selection, fn {field, expected} ->
      matches_field?(event, field, expected)
    end)
  end

  defp matches_selection?(event, selections) when is_list(selections) do
    # List of selections = OR logic
    Enum.any?(selections, fn selection ->
      matches_selection?(event, selection)
    end)
  end

  defp matches_selection?(_, _), do: false

  # Check if a field matches the expected value(s)
  defp matches_field?(event, field, expected) do
    # Parse field for modifiers (e.g., "Image|contains")
    {base_field, modifiers} = parse_field_modifiers(field)

    # Map Sigma field to Tamandua field
    mapped_field = Map.get(@field_mappings, base_field, String.downcase(base_field))

    # Get event value (try both string and atom keys)
    event_value = get_event_value(event, mapped_field)

    # Apply modifiers and check
    check_value_with_modifiers(event_value, expected, modifiers)
  end

  defp parse_field_modifiers(field) do
    case String.split(field, "|") do
      [base | modifiers] -> {base, modifiers}
      _ -> {field, []}
    end
  end

  defp get_event_value(event, field) do
    payload = event["payload"] || event[:payload] || %{}

    case fetch_field_value(payload, field) do
      {:ok, value} ->
        value

      :error ->
        case fetch_first_alias_value(payload, field) do
          {:ok, value} -> value

          :error ->
            case fetch_field_value(event, field) do
              {:ok, value} ->
                value

              :error ->
                case fetch_first_alias_value(event, field) do
                  {:ok, value} -> value
                  :error -> collect_component_field_values(payload, field)
                end
            end
        end
    end
  end

  defp fetch_first_alias_value(source, field) do
    field
    |> field_aliases()
    |> Enum.reduce_while(:error, fn alias, _acc ->
      case fetch_field_value(source, alias) do
        {:ok, value} when value not in [nil, "", []] -> {:halt, {:ok, value}}
        _ -> {:cont, :error}
      end
    end)
  end

  defp field_aliases(field) do
    field = to_string(field)

    @event_field_aliases
    |> Map.get(field, [])
    |> Enum.reject(&(&1 == field))
  end

  defp fetch_field_value(source, field) when is_map(source) do
    cond do
      Map.has_key?(source, field) ->
        {:ok, Map.get(source, field)}

      is_atom_key?(field) && Map.has_key?(source, String.to_existing_atom(field)) ->
        {:ok, Map.get(source, String.to_existing_atom(field))}

      String.contains?(field, ".") ->
        fetch_path_value(source, String.split(field, "."))

      true ->
        :error
    end
  rescue
    ArgumentError -> :error
  end

  defp fetch_field_value(_source, _field), do: :error

  defp fetch_path_value(source, path) do
    case fetch_path_values([source], path) do
      [] -> :error
      [value] -> {:ok, value}
      values -> {:ok, values}
    end
  end

  defp fetch_path_values(values, []), do: values

  defp fetch_path_values(values, [field | rest]) do
    values
    |> Enum.flat_map(fn
      value when is_map(value) ->
        case fetch_field_value(value, field) do
          {:ok, nested} when is_list(nested) -> nested
          {:ok, nested} -> [nested]
          :error -> []
        end

      values when is_list(values) ->
        values

      _ ->
        []
    end)
    |> fetch_path_values(rest)
  end

  defp collect_component_field_values(payload, field) do
    components =
      case fetch_field_value(payload, "components") do
        {:ok, components} when is_list(components) -> components
        _ -> []
      end

    values =
      components
      |> Enum.flat_map(fn component ->
        case fetch_field_value(component, field) do
          {:ok, value} when is_list(value) -> value
          {:ok, value} -> [value]
          :error -> []
        end
      end)
      |> Enum.reject(&is_nil/1)

    case values do
      [] -> nil
      [value] -> value
      values -> values
    end
  end

  defp is_atom_key?(field) when is_binary(field) do
    Regex.match?(~r/^[a-z_][a-z0-9_]*$/, field)
  end

  defp is_atom_key?(_), do: false

  # Check value with modifiers
  defp check_value_with_modifiers(nil, _, _), do: false

  defp check_value_with_modifiers(event_value, expected, modifiers) when is_list(event_value) do
    if "all" in modifiers and is_list(expected) do
      Enum.all?(expected, fn exp ->
        Enum.any?(event_value, fn value ->
          check_single_value(value, exp, modifiers -- ["all"])
        end)
      end)
    else
      Enum.any?(event_value, fn value ->
        check_value_with_modifiers(value, expected, modifiers)
      end)
    end
  end

  defp check_value_with_modifiers(event_value, expected, modifiers) when is_list(expected) do
    # List of values = OR logic
    Enum.any?(expected, fn exp ->
      check_single_value(event_value, exp, modifiers)
    end)
  end

  defp check_value_with_modifiers(event_value, expected, modifiers) do
    check_single_value(event_value, expected, modifiers)
  end

  defp check_single_value(event_value, expected, modifiers) do
    event_str = value_to_string(event_value) |> String.downcase()
    expected_str = value_to_string(expected) |> String.downcase()

    cond do
      "contains" in modifiers ->
        String.contains?(event_str, expected_str)

      "startswith" in modifiers ->
        String.starts_with?(event_str, expected_str)

      "endswith" in modifiers ->
        String.ends_with?(event_str, expected_str) ||
          basename_endswith_match?(event_str, expected_str)

      "re" in modifiers ->
        case Regex.compile(expected_str, [:caseless]) do
          {:ok, regex} -> Regex.match?(regex, event_str)
          _ -> false
        end

      "base64" in modifiers ->
        case Base.decode64(event_str) do
          {:ok, decoded} -> String.downcase(decoded) == expected_str
          _ -> false
        end

      "base64offset" in modifiers ->
        # Check all possible base64 offsets
        Enum.any?(0..2, fn offset ->
          padded = String.duplicate(" ", offset) <> expected_str
          case Base.encode64(padded) do
            encoded -> String.contains?(event_str, String.downcase(encoded))
          end
        end)

      "utf16le" in modifiers or "wide" in modifiers ->
        # Convert expected to UTF-16LE (wide chars) and check
        # UTF-16LE adds a null byte after each ASCII char
        wide_expected = expected_str
        |> String.to_charlist()
        |> Enum.flat_map(fn c -> [c, 0] end)
        |> to_string()
        |> String.downcase()

        String.contains?(event_str, wide_expected)

      "cidr" in modifiers ->
        # Check if IP address is in CIDR range
        cidr_match?(event_str, expected_str)

      "all" in modifiers ->
        # All values in list must match
        if is_list(expected) do
          Enum.all?(expected, fn exp ->
            String.contains?(event_str, String.downcase(to_string(exp)))
          end)
        else
          event_str == expected_str
        end

      "gt" in modifiers ->
        # Greater than comparison
        with {event_num, _} <- Float.parse(event_str),
             {expected_num, _} <- Float.parse(expected_str) do
          event_num > expected_num
        else
          _ -> false
        end

      "gte" in modifiers ->
        # Greater than or equal comparison
        with {event_num, _} <- Float.parse(event_str),
             {expected_num, _} <- Float.parse(expected_str) do
          event_num >= expected_num
        else
          _ -> false
        end

      "lt" in modifiers ->
        # Less than comparison
        with {event_num, _} <- Float.parse(event_str),
             {expected_num, _} <- Float.parse(expected_str) do
          event_num < expected_num
        else
          _ -> false
        end

      "lte" in modifiers ->
        # Less than or equal comparison
        with {event_num, _} <- Float.parse(event_str),
             {expected_num, _} <- Float.parse(expected_str) do
          event_num <= expected_num
        else
          _ -> false
        end

      true ->
        # Default: wildcard matching
        wildcard_match?(event_str, expected_str)
    end
  end

  defp value_to_string(value) when is_binary(value), do: value
  defp value_to_string(value) when is_atom(value), do: Atom.to_string(value)
  defp value_to_string(value) when is_number(value), do: to_string(value)
  defp value_to_string(value) when is_boolean(value), do: to_string(value)
  defp value_to_string(value), do: inspect(value)

  defp basename_endswith_match?(event_str, expected_str) do
    expected_basename =
      expected_str
      |> String.replace("/", "\\")
      |> String.split("\\", trim: true)
      |> List.last()

    expected_basename not in [nil, ""] and event_str == expected_basename
  end

  # CIDR matching for IP addresses
  defp cidr_match?(ip_str, cidr_str) do
    case String.split(cidr_str, "/") do
      [network, prefix_len_str] ->
        case Integer.parse(prefix_len_str) do
          {prefix_len, ""} when prefix_len >= 0 and prefix_len <= 32 ->
            ip_to_int(ip_str)
            |> case do
              {:ok, ip_int} ->
                case ip_to_int(network) do
                  {:ok, network_int} ->
                    mask = ~~~((1 <<< (32 - prefix_len)) - 1) &&& 0xFFFFFFFF
                    (ip_int &&& mask) == (network_int &&& mask)
                  _ -> false
                end
              _ -> false
            end
          _ -> false
        end
      _ -> ip_str == cidr_str
    end
  end

  defp ip_to_int(ip_str) do
    case String.split(ip_str, ".") do
      [a, b, c, d] ->
        with {a_int, ""} <- Integer.parse(a),
             {b_int, ""} <- Integer.parse(b),
             {c_int, ""} <- Integer.parse(c),
             {d_int, ""} <- Integer.parse(d),
             true <- Enum.all?([a_int, b_int, c_int, d_int], &(&1 >= 0 and &1 <= 255)) do
          {:ok, (a_int <<< 24) + (b_int <<< 16) + (c_int <<< 8) + d_int}
        else
          _ -> :error
        end
      _ -> :error
    end
  end

  # Wildcard matching (* and ?)
  defp wildcard_match?(value, pattern) do
    regex_pattern =
      pattern
      |> Regex.escape()
      |> String.replace("\\*", ".*")
      |> String.replace("\\?", ".")

    case Regex.compile("^#{regex_pattern}$", [:caseless]) do
      {:ok, regex} -> Regex.match?(regex, value)
      _ -> value == pattern
    end
  end

  @doc """
  Loads Sigma rules from database.
  """
  @spec load_rules() :: {:ok, list(rule())} | {:error, any()}
  def load_rules() do
    case TamanduaServer.Detection.list_sigma_rules() do
      rules when is_list(rules) ->
        parsed_rules =
          rules
          |> Enum.map(fn rule ->
            case parse(rule.source) do
              {:ok, parsed} ->
                Map.merge(parsed, %{
                  "id" => rule.id,
                  "enabled" => rule.enabled
                })

              {:error, _} ->
                nil
            end
          end)
          |> Enum.reject(&is_nil/1)
          |> Enum.filter(& &1["enabled"])

        {:ok, parsed_rules}

      _ ->
        {:ok, []}
    end
  rescue
    e ->
      Logger.error("Failed to load Sigma rules: #{inspect(e)}")
      {:ok, []}
  end

  @doc """
  Evaluates all Sigma rules against an event.
  Returns list of matching rules.
  """
  @spec evaluate(event()) :: list(rule())
  def evaluate(event) do
    case load_rules() do
      {:ok, rules} ->
        Enum.filter(rules, fn rule ->
          matches?(event, rule)
        end)

      _ ->
        []
    end
  end

  @doc """
  Evaluates all Sigma rules against an event, including timeframe-based
  aggregation rules via the SigmaAggregator.

  Returns `{instant_matches, aggregation_triggers}` where:
  - `instant_matches` are rules that matched without aggregation
  - `aggregation_triggers` are rules whose aggregation threshold was exceeded
  """
  @spec evaluate_with_aggregation(event()) :: {list(rule()), list({rule(), non_neg_integer()})}
  def evaluate_with_aggregation(event) do
    case load_rules() do
      {:ok, rules} ->
        {instant, aggregated} =
          Enum.reduce(rules, {[], []}, fn rule, {inst_acc, agg_acc} ->
            case classify_rule(rule) do
              :instant ->
                if matches?(event, rule) do
                  {[rule | inst_acc], agg_acc}
                else
                  {inst_acc, agg_acc}
                end

              {:aggregation, agg_config} ->
                # For aggregation rules, check if selection matches first
                if matches_selection_only?(event, rule) do
                  rule_id = to_string(rule["id"] || rule["title"] || "unknown")
                  agent_id = to_string(event["agent_id"] || event[:agent_id] || "unknown")

                  case TamanduaServer.Detection.Rules.SigmaAggregator.record_match(
                    rule_id, agent_id, event, agg_config
                  ) do
                    {:trigger, count} ->
                      {inst_acc, [{rule, count} | agg_acc]}
                    :buffered ->
                      {inst_acc, agg_acc}
                  end
                else
                  {inst_acc, agg_acc}
                end
            end
          end)

        {Enum.reverse(instant), Enum.reverse(aggregated)}

      _ ->
        {[], []}
    end
  end

  @doc """
  Classify a rule as instant (no timeframe) or aggregation (has timeframe + count condition).
  """
  @spec classify_rule(rule()) :: :instant | {:aggregation, map()}
  def classify_rule(rule) do
    detection = rule["detection"] || %{}
    timeframe = detection["timeframe"]
    condition = detection["condition"] || ""

    cond do
      timeframe != nil && has_count_condition?(condition) ->
        agg_config = extract_aggregation_config(condition, timeframe)
        {:aggregation, agg_config}

      true ->
        :instant
    end
  end

  defp has_count_condition?(condition) when is_binary(condition) do
    String.contains?(condition, "count")
  end
  defp has_count_condition?(_), do: false

  defp extract_aggregation_config(condition, timeframe) do
    # Parse "count(field) > N" or "count() > N" from condition
    case Regex.run(~r/count\(([^)]*)\)\s*([><=!]+)\s*(\d+)/, condition) do
      [_, field, operator, threshold_str] ->
        {threshold, _} = Integer.parse(threshold_str)
        %{
          field: if(field == "", do: nil, else: field),
          operator: operator,
          threshold: threshold,
          timeframe: timeframe
        }

      nil ->
        # Default: count() > 0 with the given timeframe
        %{field: nil, operator: ">", threshold: 0, timeframe: timeframe}
    end
  end

  @doc """
  Check if event matches the selection part of a rule (ignoring condition logic).
  Used for aggregation rules where we buffer selection matches.
  """
  @spec matches_selection_only?(event(), rule()) :: boolean()
  def matches_selection_only?(event, rule) do
    with true <- matches_logsource?(event, rule) do
      detection = rule["detection"] || %{}

      # Find all selection keys (non-condition, non-timeframe keys)
      selections = detection
      |> Map.drop(["condition", "timeframe"])
      |> Map.keys()
      |> Enum.filter(&String.starts_with?(&1, "selection"))

      if Enum.empty?(selections) do
        # If no explicit selection, check all non-meta keys
        detection
        |> Map.drop(["condition", "timeframe"])
        |> Enum.any?(fn {_key, sel_data} ->
          matches_selection?(event, sel_data)
        end)
      else
        # At least one selection must match
        Enum.any?(selections, fn sel_key ->
          matches_selection?(event, Map.get(detection, sel_key))
        end)
      end
    else
      _ -> false
    end
  end
end
