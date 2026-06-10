defmodule TamanduaServer.Integrations.FieldMapper do
  @moduledoc """
  Field mapping engine for transforming alert fields across integration platforms.

  Provides:
  - `apply_mapping/2` - Transform alert fields using a mapping template
  - `default_mappings/1` - Default field mappings per target platform
  - `validate_mapping/1` - Validate mapping template syntax

  Mapping templates are lists of rules with the shape:
      %{
        "source" => "alert.severity",
        "target" => "event.priority",
        "transform" => "severity_to_number"   # optional
      }

  Dot-notation paths are supported for nested access. The optional `transform`
  field can be one of: "upcase", "downcase", "to_string", "to_integer",
  "severity_to_number", "severity_to_splunk", "severity_to_sentinel",
  "join", "json_encode", "identity".
  """

  @known_transforms ~w(
    upcase downcase to_string to_integer
    severity_to_number severity_to_splunk severity_to_sentinel
    join json_encode identity
  )

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Apply a mapping template to transform alert/event fields.

  ## Parameters

  - `data` - Source data map (alert, event, etc.)
  - `mapping` - List of mapping rules (list of maps with "source", "target", optional "transform")

  ## Returns

  A new map with fields remapped according to the template. Fields not mentioned
  in the mapping are not included in the output; use a `"*"` source for pass-through.
  """
  @spec apply_mapping(map(), list(map())) :: map()
  def apply_mapping(data, mapping) when is_map(data) and is_list(mapping) do
    Enum.reduce(mapping, %{}, fn rule, acc ->
      source_path = rule["source"] || rule[:source]
      target_path = rule["target"] || rule[:target]
      transform = rule["transform"] || rule[:transform]

      value =
        if source_path == "*" do
          data
        else
          get_nested(data, parse_path(source_path))
        end

      transformed = apply_transform(value, transform)

      if target_path && transformed != nil do
        put_nested(acc, parse_path(target_path), transformed)
      else
        acc
      end
    end)
  end

  def apply_mapping(data, _mapping), do: data

  @doc """
  Get default field mappings for a target platform.

  ## Parameters

  - `platform` - Target platform atom or string: `:splunk`, `:sentinel`, `:qradar`, `:elastic`, `:generic`

  ## Returns

  A list of mapping rules suitable for `apply_mapping/2`.
  """
  @spec default_mappings(atom() | String.t()) :: list(map())
  def default_mappings(platform) do
    platform = normalize_platform(platform)

    case platform do
      :splunk -> splunk_mappings()
      :sentinel -> sentinel_mappings()
      :qradar -> qradar_mappings()
      :elastic -> elastic_mappings()
      _ -> generic_mappings()
    end
  end

  @doc """
  Validate a mapping template for syntax correctness.

  ## Parameters

  - `mapping` - List of mapping rules

  ## Returns

  `:ok` if valid, `{:error, errors}` with a list of error strings.
  """
  @spec validate_mapping(list(map())) :: :ok | {:error, list(String.t())}
  def validate_mapping(mapping) when is_list(mapping) do
    errors =
      mapping
      |> Enum.with_index()
      |> Enum.flat_map(fn {rule, idx} ->
        validate_rule(rule, idx)
      end)

    if errors == [] do
      :ok
    else
      {:error, errors}
    end
  end

  def validate_mapping(_), do: {:error, ["Mapping must be a list of rules"]}

  # ============================================================================
  # Private: Default Mappings
  # ============================================================================

  defp splunk_mappings do
    [
      %{"source" => "id", "target" => "event.alert_id"},
      %{"source" => "title", "target" => "event.alert_name"},
      %{"source" => "description", "target" => "event.description"},
      %{"source" => "severity", "target" => "event.severity", "transform" => "severity_to_splunk"},
      %{"source" => "hostname", "target" => "host"},
      %{"source" => "agent_id", "target" => "event.agent_id"},
      %{"source" => "mitre_tactics", "target" => "event.mitre_tactics", "transform" => "join"},
      %{"source" => "mitre_techniques", "target" => "event.mitre_techniques", "transform" => "join"},
      %{"source" => "threat_score", "target" => "event.threat_score"},
      %{"source" => "created_at", "target" => "time"}
    ]
  end

  defp sentinel_mappings do
    [
      %{"source" => "id", "target" => "ExtendedProperties.alert_id"},
      %{"source" => "title", "target" => "AlertName"},
      %{"source" => "description", "target" => "Description"},
      %{"source" => "severity", "target" => "Severity", "transform" => "severity_to_sentinel"},
      %{"source" => "hostname", "target" => "CompromisedEntity"},
      %{"source" => "agent_id", "target" => "ExtendedProperties.agent_id"},
      %{"source" => "mitre_tactics", "target" => "Tactics", "transform" => "join"},
      %{"source" => "mitre_techniques", "target" => "Techniques", "transform" => "join"},
      %{"source" => "created_at", "target" => "TimeGenerated"}
    ]
  end

  defp qradar_mappings do
    [
      %{"source" => "id", "target" => "externalId"},
      %{"source" => "title", "target" => "name"},
      %{"source" => "description", "target" => "description"},
      %{"source" => "severity", "target" => "severity", "transform" => "severity_to_number"},
      %{"source" => "hostname", "target" => "sourceAddress"},
      %{"source" => "agent_id", "target" => "customFields.agent_id"},
      %{"source" => "mitre_tactics", "target" => "categories", "transform" => "join"},
      %{"source" => "created_at", "target" => "startTime"}
    ]
  end

  defp elastic_mappings do
    [
      %{"source" => "id", "target" => "alert_id"},
      %{"source" => "title", "target" => "alert.name"},
      %{"source" => "description", "target" => "alert.description"},
      %{"source" => "severity", "target" => "alert.severity", "transform" => "downcase"},
      %{"source" => "hostname", "target" => "host.name"},
      %{"source" => "agent_id", "target" => "agent.id"},
      %{"source" => "mitre_tactics", "target" => "threat.tactic.name"},
      %{"source" => "mitre_techniques", "target" => "threat.technique.name"},
      %{"source" => "created_at", "target" => "@timestamp"}
    ]
  end

  defp generic_mappings do
    [
      %{"source" => "id", "target" => "alert_id"},
      %{"source" => "title", "target" => "title"},
      %{"source" => "description", "target" => "description"},
      %{"source" => "severity", "target" => "severity"},
      %{"source" => "hostname", "target" => "hostname"},
      %{"source" => "agent_id", "target" => "agent_id"},
      %{"source" => "mitre_tactics", "target" => "mitre_tactics"},
      %{"source" => "mitre_techniques", "target" => "mitre_techniques"},
      %{"source" => "created_at", "target" => "timestamp"}
    ]
  end

  # ============================================================================
  # Private: Transforms
  # ============================================================================

  defp apply_transform(value, nil), do: value
  defp apply_transform(value, "identity"), do: value
  defp apply_transform(nil, _), do: nil

  defp apply_transform(value, "upcase") when is_binary(value), do: String.upcase(value)
  defp apply_transform(value, "downcase") when is_binary(value), do: String.downcase(value)
  defp apply_transform(value, "to_string"), do: to_string(value)

  defp apply_transform(value, "to_integer") when is_binary(value) do
    case Integer.parse(value) do
      {n, _} -> n
      :error -> value
    end
  end

  defp apply_transform(value, "to_integer") when is_integer(value), do: value
  defp apply_transform(value, "to_integer"), do: value

  defp apply_transform(value, "severity_to_number") do
    case to_string(value) do
      "critical" -> 10
      "high" -> 7
      "medium" -> 5
      "low" -> 3
      "info" -> 1
      _ -> 0
    end
  end

  defp apply_transform(value, "severity_to_splunk") do
    case to_string(value) do
      "critical" -> "critical"
      "high" -> "high"
      "medium" -> "medium"
      "low" -> "low"
      "info" -> "informational"
      other -> other
    end
  end

  defp apply_transform(value, "severity_to_sentinel") do
    case to_string(value) do
      "critical" -> "High"
      "high" -> "High"
      "medium" -> "Medium"
      "low" -> "Low"
      "info" -> "Informational"
      other -> other
    end
  end

  defp apply_transform(value, "join") when is_list(value), do: Enum.join(value, ",")
  defp apply_transform(value, "join"), do: to_string(value)

  defp apply_transform(value, "json_encode") do
    case Jason.encode(value) do
      {:ok, json} -> json
      _ -> inspect(value)
    end
  end

  defp apply_transform(value, _unknown), do: value

  # ============================================================================
  # Private: Nested Map Access
  # ============================================================================

  defp parse_path(path) when is_binary(path), do: String.split(path, ".")
  defp parse_path(path) when is_atom(path), do: [to_string(path)]
  defp parse_path(path) when is_list(path), do: path

  defp get_nested(data, []), do: data

  defp get_nested(data, [key | rest]) when is_map(data) do
    value =
      Map.get(data, key) ||
        Map.get(data, safe_to_atom(key))

    get_nested(value, rest)
  end

  defp get_nested(_data, _path), do: nil

  defp put_nested(data, [key], value) when is_map(data) do
    Map.put(data, key, value)
  end

  defp put_nested(data, [key | rest], value) when is_map(data) do
    child = Map.get(data, key, %{})
    child = if is_map(child), do: child, else: %{}
    Map.put(data, key, put_nested(child, rest, value))
  end

  defp put_nested(_data, _path, _value), do: %{}

  defp safe_to_atom(str) when is_binary(str) do
    String.to_existing_atom(str)
  rescue
    ArgumentError -> nil
  end

  # ============================================================================
  # Private: Validation
  # ============================================================================

  defp validate_rule(rule, idx) when is_map(rule) do
    errors = []

    source = rule["source"] || rule[:source]
    target = rule["target"] || rule[:target]
    transform = rule["transform"] || rule[:transform]

    errors =
      if is_nil(source) or source == "" do
        ["Rule #{idx}: missing 'source' field" | errors]
      else
        errors
      end

    errors =
      if is_nil(target) or target == "" do
        ["Rule #{idx}: missing 'target' field" | errors]
      else
        errors
      end

    errors =
      if transform && transform not in @known_transforms do
        ["Rule #{idx}: unknown transform '#{transform}', valid: #{Enum.join(@known_transforms, ", ")}" | errors]
      else
        errors
      end

    errors
  end

  defp validate_rule(_rule, idx) do
    ["Rule #{idx}: must be a map with 'source' and 'target' keys"]
  end

  defp normalize_platform(p) when is_atom(p), do: p
  defp normalize_platform("splunk"), do: :splunk
  defp normalize_platform("sentinel"), do: :sentinel
  defp normalize_platform("qradar"), do: :qradar
  defp normalize_platform("elastic"), do: :elastic
  defp normalize_platform(_), do: :generic
end
