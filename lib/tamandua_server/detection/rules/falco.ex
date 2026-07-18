defmodule TamanduaServer.Detection.Rules.Falco do
  @moduledoc """
  Parser for Falco YAML rules with macro and list expansion.

  Falco rules syntax supports:
  - rule: rule_name
    desc: description
    condition: (macro1 and macro2) or list1
    output: "Alert: %container.name"
    priority: WARNING
    tags: [mitre_t1611]

  - macro: macro1
    condition: fd.name = "/etc/shadow"

  - list: sensitive_files
    items: [/etc/shadow, /etc/passwd]

  This module parses Falco YAML, expands macros/lists at import time,
  and converts rules to an internal format compatible with the detection engine.
  """

  require Logger

  @type parsed_rule :: %{
    name: String.t(),
    description: String.t(),
    condition: String.t(),
    output: String.t(),
    priority: atom(),
    tags: [String.t()],
    source: String.t()
  }

  @doc """
  Parse Falco rules from a file path.

  ## Example

      {:ok, rules} = Falco.parse_file("priv/falco_rules/k8s_audit.yaml")
  """
  @spec parse_file(String.t()) :: {:ok, [parsed_rule()]} | {:error, any()}
  def parse_file(path) do
    with {:ok, content} <- File.read(path),
         {:ok, rules} <- parse_string(content) do
      {:ok, rules}
    end
  end

  @doc """
  Parse Falco rules from a YAML string.

  ## Example

      yaml = \"\"\"
      - list: shells
        items: [/bin/bash, /bin/sh]
      - macro: spawned_process
        condition: evt.type = execve
      - rule: shell_in_container
        desc: Shell spawned in container
        condition: spawned_process and container and proc.name in (shells)
        output: "Shell spawned (user=%user.name command=%proc.cmdline)"
        priority: WARNING
        tags: [container, shell]
      \"\"\"
      {:ok, rules} = Falco.parse_string(yaml)
  """
  @spec parse_string(String.t()) :: {:ok, [parsed_rule()]} | {:error, any()}
  def parse_string(yaml_content) do
    case YamlElixir.read_from_string(yaml_content) do
      {:ok, entries} when is_list(entries) ->
        parse_entries(entries)

      {:ok, _} ->
        {:error, "Expected YAML list at top level"}

      {:error, reason} ->
        {:error, {:yaml_parse_error, reason}}
    end
  rescue
    e -> {:error, {:parse_exception, Exception.message(e)}}
  end

  @doc """
  Convert a parsed Falco rule to Sigma-compatible format for the detection engine.
  """
  @spec to_sigma_format(parsed_rule()) :: map()
  def to_sigma_format(rule) do
    %{
      "title" => rule.name,
      "description" => rule.description,
      "status" => "experimental",
      "level" => priority_to_level(rule.priority),
      "logsource" => %{
        "category" => "process_creation",
        "product" => "linux"
      },
      "detection" => %{
        "condition" => rule.condition,
        "selection" => parse_falco_condition_to_selection(rule.condition)
      },
      "tags" => rule.tags,
      "source" => "falco"
    }
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp parse_entries(entries) do
    # First pass: categorize entries into lists, macros, and rules
    {lists, macros, rules} = categorize_entries(entries)

    # Second pass: detect circular dependencies in macros
    case detect_circular_macros(macros) do
      {:ok, _} ->
        # Third pass: expand macros (recursive)
        expanded_macros = expand_macros(macros, lists)

        # Fourth pass: parse rules with expanded macros
        parsed_rules =
          rules
          |> Enum.map(fn rule -> expand_rule(rule, expanded_macros, lists) end)
          |> Enum.filter(&(&1 != nil))

        {:ok, parsed_rules}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp categorize_entries(entries) do
    Enum.reduce(entries, {%{}, %{}, []}, fn entry, {lists, macros, rules} ->
      cond do
        is_map(entry) && Map.has_key?(entry, "list") ->
          list_name = entry["list"]
          list_items = entry["items"] || []
          {Map.put(lists, list_name, list_items), macros, rules}

        is_map(entry) && Map.has_key?(entry, "macro") ->
          macro_name = entry["macro"]
          macro_condition = entry["condition"] || ""
          {lists, Map.put(macros, macro_name, macro_condition), rules}

        is_map(entry) && Map.has_key?(entry, "rule") ->
          {lists, macros, [entry | rules]}

        true ->
          # Skip unknown entry types (comments, etc.)
          {lists, macros, rules}
      end
    end)
  end

  defp detect_circular_macros(macros) do
    # Build dependency graph and check for cycles
    macro_names = Map.keys(macros)

    try do
      Enum.each(macro_names, fn name ->
        check_macro_cycle(name, macros, MapSet.new())
      end)
      {:ok, :no_cycles}
    catch
      {:circular_dependency, cycle} ->
        {:error, {:circular_dependency, cycle}}
    end
  end

  defp check_macro_cycle(name, macros, visited) do
    if MapSet.member?(visited, name) do
      throw({:circular_dependency, MapSet.to_list(visited) ++ [name]})
    end

    condition = Map.get(macros, name, "")
    referenced = extract_macro_references(condition, Map.keys(macros))

    new_visited = MapSet.put(visited, name)
    Enum.each(referenced, fn ref ->
      check_macro_cycle(ref, macros, new_visited)
    end)
  end

  defp extract_macro_references(condition, macro_names) do
    # Extract macro names referenced in condition
    # Macros are referenced as bare identifiers
    Enum.filter(macro_names, fn name ->
      String.match?(condition, macro_reference_regex(name))
    end)
  end

  defp macro_reference_regex(name) do
    ~r/(?<![\w.])#{Regex.escape(name)}(?![\w.])/
  end

  defp expand_macros(macros, lists) do
    # Recursively expand macro references within macros
    _macro_names = Map.keys(macros)

    Enum.reduce(macros, %{}, fn {name, condition}, acc ->
      expanded = expand_condition(condition, acc, macros, lists, MapSet.new([name]))
      Map.put(acc, name, expanded)
    end)
  end

  defp expand_condition(condition, expanded_macros, all_macros, lists, visited) do
    # First, expand any macro references
    condition_with_macros =
      Enum.reduce(Map.keys(all_macros), condition, fn macro_name, acc ->
        if MapSet.member?(visited, macro_name) do
          acc
        else
          macro_value = Map.get(expanded_macros, macro_name) ||
                        expand_condition(
                          Map.get(all_macros, macro_name, ""),
                          expanded_macros,
                          all_macros,
                          lists,
                          MapSet.put(visited, macro_name)
                        )

          # Replace macro references with parenthesized expansion
          String.replace(acc, macro_reference_regex(macro_name), "(#{macro_value})")
        end
      end)

    # Then, expand list references: "field in (list_name)" -> "field in (item1, item2, ...)"
    Enum.reduce(lists, condition_with_macros, fn {list_name, items}, acc ->
      # Pattern: "field in (list_name)" or "field in list_name"
      pattern = ~r/(\w+\.?\w*)\s+in\s+\(?#{Regex.escape(list_name)}\)?/

      Regex.replace(pattern, acc, fn _, field ->
        items_str = Enum.map_join(items, ", ", &inspect/1)
        "#{field} in (#{items_str})"
      end)
    end)
  end

  defp expand_rule(rule, macros, lists) do
    condition = rule["condition"] || ""
    expanded_condition = expand_condition(condition, macros, macros, lists, MapSet.new())

    %{
      name: rule["rule"],
      description: rule["desc"] || rule["description"] || "",
      condition: expanded_condition,
      output: rule["output"] || "",
      priority: map_priority(rule["priority"]),
      tags: (rule["tags"] || []) |> Enum.map(&normalize_tag/1),
      source: "falco"
    }
  end

  defp normalize_tag(tag) when is_binary(tag) do
    tag
    |> String.downcase()
    |> String.replace("_", "-")
  end
  defp normalize_tag(tag), do: to_string(tag)

  defp map_priority("EMERGENCY"), do: :critical
  defp map_priority("ALERT"), do: :critical
  defp map_priority("CRITICAL"), do: :critical
  defp map_priority("ERROR"), do: :high
  defp map_priority("WARNING"), do: :medium
  defp map_priority("NOTICE"), do: :low
  defp map_priority("INFORMATIONAL"), do: :info
  defp map_priority("INFO"), do: :info
  defp map_priority("DEBUG"), do: :info
  defp map_priority(_), do: :medium

  defp priority_to_level(:critical), do: "critical"
  defp priority_to_level(:high), do: "high"
  defp priority_to_level(:medium), do: "medium"
  defp priority_to_level(:low), do: "low"
  defp priority_to_level(:info), do: "informational"
  defp priority_to_level(_), do: "medium"

  defp parse_falco_condition_to_selection(condition) do
    # Convert Falco condition to a basic selection map
    # This is a simplified conversion - full Falco condition parsing is complex
    # For now, extract key field comparisons

    selections = %{}

    # Extract "field = value" patterns
    ~r/(\w+\.?\w*)\s*=\s*["']?([^"'\s\)]+)["']?/
    |> Regex.scan(condition)
    |> Enum.reduce(selections, fn [_, field, value], acc ->
      Map.put(acc, field, value)
    end)
  end
end
