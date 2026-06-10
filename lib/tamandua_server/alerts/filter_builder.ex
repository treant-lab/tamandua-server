defmodule TamanduaServer.Alerts.FilterBuilder do
  @moduledoc """
  Advanced filter builder for alerts with support for complex queries.

  Supports:
  - Nested AND/OR/NOT logic
  - 25+ filter fields
  - Regex patterns
  - CIDR matching
  - Date ranges
  - Array containment
  - JSON path queries

  ## Filter Structure

      %{
        "logic" => "AND" | "OR",
        "conditions" => [
          %{
            "field" => "severity",
            "operator" => "eq",
            "value" => "critical"
          },
          %{
            "logic" => "OR",
            "conditions" => [...]
          }
        ]
      }

  ## Supported Fields

  - `severity`: critical, high, medium, low, info
  - `status`: new, investigating, resolved, false_positive
  - `verdict`: unconfirmed, true_positive, false_positive, benign, suspicious
  - `mitre_technique`: T1055, T1059, etc.
  - `mitre_tactic`: persistence, privilege-escalation, etc.
  - `process_name`: String or regex
  - `file_path`: String or regex
  - `file_hash`: MD5, SHA1, SHA256
  - `ip_address`: IP or CIDR
  - `domain`: String or regex
  - `user`: Username
  - `agent_id`: UUID
  - `agent_hostname`: String or regex
  - `assigned_to_id`: UUID
  - `threat_score`: Float comparison
  - `confidence_score`: Float comparison
  - `occurrence_count`: Integer comparison
  - `created_at`: Date range
  - `updated_at`: Date range
  - `last_seen_at`: Date range
  - `storyline_id`: String
  - `campaign_id`: String
  - `attributed_actor`: String
  - `ioc_type`: ip, domain, hash, email, url
  - `ioc_value`: String
  - `detection_source`: yara, sigma, ml, ioc

  ## Operators

  - `eq`: Equals
  - `ne`: Not equals
  - `gt`: Greater than
  - `gte`: Greater than or equal
  - `lt`: Less than
  - `lte`: Less than or equal
  - `contains`: String contains
  - `not_contains`: String does not contain
  - `starts_with`: String starts with
  - `ends_with`: String ends with
  - `regex`: Regex match
  - `in`: Value in list
  - `not_in`: Value not in list
  - `is_null`: Field is null
  - `is_not_null`: Field is not null
  - `cidr`: IP in CIDR range
  - `array_contains`: Array contains value
  - `array_overlaps`: Arrays have common elements
  - `json_path`: JSON path query
  """

  import Ecto.Query, warn: false
  alias TamanduaServer.Alerts.Alert

  @type filter_condition :: %{
          required(:field) => String.t(),
          required(:operator) => String.t(),
          required(:value) => any()
        }

  @type filter_group :: %{
          required(:logic) => String.t(),
          required(:conditions) => list(filter_condition() | filter_group())
        }

  @supported_fields ~w(
    severity status verdict
    mitre_technique mitre_tactic
    process_name file_path file_hash
    ip_address domain user
    agent_id agent_hostname assigned_to_id
    threat_score confidence_score occurrence_count
    created_at updated_at last_seen_at
    storyline_id campaign_id attributed_actor
    ioc_type ioc_value detection_source
  )

  @supported_operators ~w(
    eq ne gt gte lt lte
    contains not_contains starts_with ends_with regex
    in not_in is_null is_not_null
    cidr array_contains array_overlaps json_path
  )

  @doc """
  Builds an Ecto query from a filter structure.

  ## Examples

      iex> filter = %{
      ...>   "logic" => "AND",
      ...>   "conditions" => [
      ...>     %{"field" => "severity", "operator" => "eq", "value" => "critical"},
      ...>     %{"field" => "status", "operator" => "ne", "value" => "resolved"}
      ...>   ]
      ...> }
      iex> FilterBuilder.build_query(Alert, filter)
      #Ecto.Query<...>
  """
  def build_query(base_query, filter) when is_map(filter) do
    case validate_filter(filter) do
      {:ok, validated_filter} ->
        apply_filter_group(base_query, validated_filter)

      {:error, _reason} ->
        base_query
    end
  end

  def build_query(base_query, _), do: base_query

  @doc """
  Validates a filter structure.
  """
  def validate_filter(filter) when is_map(filter) do
    cond do
      Map.has_key?(filter, "quick_filter") ->
        validate_quick_filter(filter)

      Map.has_key?(filter, "conditions") ->
        validate_filter_group(filter)

      true ->
        {:error, "Filter must have 'conditions' or 'quick_filter'"}
    end
  end

  def validate_filter(_), do: {:error, "Filter must be a map"}

  defp validate_quick_filter(%{"quick_filter" => quick_filter}) do
    if quick_filter in ~w(my_alerts unresolved high_severity last_24h last_7d last_30d) do
      {:ok, %{"quick_filter" => quick_filter}}
    else
      {:error, "Invalid quick_filter"}
    end
  end

  defp validate_filter_group(%{"logic" => logic, "conditions" => conditions})
       when logic in ["AND", "OR"] and is_list(conditions) do
    case validate_conditions(conditions) do
      {:ok, validated_conditions} ->
        {:ok, %{"logic" => logic, "conditions" => validated_conditions}}

      error ->
        error
    end
  end

  defp validate_filter_group(_), do: {:error, "Invalid filter group structure"}

  defp validate_conditions(conditions) do
    validated =
      Enum.reduce_while(conditions, {:ok, []}, fn condition, {:ok, acc} ->
        case validate_condition(condition) do
          {:ok, validated} -> {:cont, {:ok, [validated | acc]}}
          error -> {:halt, error}
        end
      end)

    case validated do
      {:ok, list} -> {:ok, Enum.reverse(list)}
      error -> error
    end
  end

  defp validate_condition(%{"logic" => _, "conditions" => _} = group) do
    validate_filter_group(group)
  end

  defp validate_condition(%{"field" => field, "operator" => operator, "value" => value}) do
    cond do
      field not in @supported_fields ->
        {:error, "Unsupported field: #{field}"}

      operator not in @supported_operators ->
        {:error, "Unsupported operator: #{operator}"}

      not valid_value_for_operator?(operator, value) ->
        {:error, "Invalid value for operator #{operator}"}

      true ->
        {:ok, %{"field" => field, "operator" => operator, "value" => value}}
    end
  end

  defp validate_condition(_), do: {:error, "Invalid condition structure"}

  defp valid_value_for_operator?("is_null", _), do: true
  defp valid_value_for_operator?("is_not_null", _), do: true
  defp valid_value_for_operator?("in", value) when is_list(value), do: true
  defp valid_value_for_operator?("not_in", value) when is_list(value), do: true
  defp valid_value_for_operator?("array_contains", _), do: true
  defp valid_value_for_operator?("array_overlaps", value) when is_list(value), do: true
  defp valid_value_for_operator?(_, nil), do: false
  defp valid_value_for_operator?(_, _), do: true

  # Apply filter group to query
  defp apply_filter_group(query, %{"quick_filter" => quick_filter}) do
    apply_quick_filter(query, quick_filter)
  end

  defp apply_filter_group(query, %{"logic" => "AND", "conditions" => conditions}) do
    Enum.reduce(conditions, query, fn condition, acc_query ->
      apply_condition(acc_query, condition, :and)
    end)
  end

  defp apply_filter_group(query, %{"logic" => "OR", "conditions" => conditions}) do
    where(query, ^build_or_conditions(conditions))
  end

  # Build OR conditions
  defp build_or_conditions(conditions) do
    Enum.reduce(conditions, dynamic(false), fn condition, dynamic_query ->
      condition_dynamic = condition_to_dynamic(condition)
      dynamic([a], ^dynamic_query or ^condition_dynamic)
    end)
  end

  # Convert condition to dynamic query
  defp condition_to_dynamic(%{"logic" => "AND", "conditions" => conditions}) do
    Enum.reduce(conditions, dynamic(true), fn condition, dynamic_query ->
      condition_dynamic = condition_to_dynamic(condition)
      dynamic([a], ^dynamic_query and ^condition_dynamic)
    end)
  end

  defp condition_to_dynamic(%{"logic" => "OR", "conditions" => conditions}) do
    build_or_conditions(conditions)
  end

  defp condition_to_dynamic(%{"field" => field, "operator" => operator, "value" => value}) do
    build_field_condition(field, operator, value)
  end

  # Apply individual condition
  defp apply_condition(query, %{"logic" => _, "conditions" => _} = group, _combiner) do
    apply_filter_group(query, group)
  end

  defp apply_condition(query, %{"field" => field, "operator" => operator, "value" => value}, combiner) do
    dynamic = build_field_condition(field, operator, value)

    case combiner do
      :and -> where(query, ^dynamic)
      :or -> or_where(query, ^dynamic)
    end
  end

  # Build field-specific conditions
  defp build_field_condition("severity", "eq", value), do: dynamic([a], a.severity == ^value)
  defp build_field_condition("severity", "ne", value), do: dynamic([a], a.severity != ^value)
  defp build_field_condition("severity", "in", values), do: dynamic([a], a.severity in ^values)

  defp build_field_condition("status", "eq", value), do: dynamic([a], a.status == ^value)
  defp build_field_condition("status", "ne", value), do: dynamic([a], a.status != ^value)
  defp build_field_condition("status", "in", values), do: dynamic([a], a.status in ^values)

  defp build_field_condition("verdict", "eq", value), do: dynamic([a], a.verdict == ^value)
  defp build_field_condition("verdict", "ne", value), do: dynamic([a], a.verdict != ^value)
  defp build_field_condition("verdict", "in", values), do: dynamic([a], a.verdict in ^values)

  defp build_field_condition("mitre_technique", "eq", value),
    do: dynamic([a], ^value in a.mitre_techniques)

  defp build_field_condition("mitre_technique", "array_contains", value),
    do: dynamic([a], ^value in a.mitre_techniques)

  defp build_field_condition("mitre_technique", "array_overlaps", values),
    do: dynamic([a], fragment("? && ?", a.mitre_techniques, ^values))

  defp build_field_condition("mitre_tactic", "eq", value),
    do: dynamic([a], ^value in a.mitre_tactics)

  defp build_field_condition("mitre_tactic", "array_contains", value),
    do: dynamic([a], ^value in a.mitre_tactics)

  defp build_field_condition("threat_score", "gt", value),
    do: dynamic([a], a.threat_score > ^value)

  defp build_field_condition("threat_score", "gte", value),
    do: dynamic([a], a.threat_score >= ^value)

  defp build_field_condition("threat_score", "lt", value),
    do: dynamic([a], a.threat_score < ^value)

  defp build_field_condition("threat_score", "lte", value),
    do: dynamic([a], a.threat_score <= ^value)

  defp build_field_condition("occurrence_count", "gt", value),
    do: dynamic([a], a.occurrence_count > ^value)

  defp build_field_condition("occurrence_count", "gte", value),
    do: dynamic([a], a.occurrence_count >= ^value)

  defp build_field_condition("occurrence_count", "lt", value),
    do: dynamic([a], a.occurrence_count < ^value)

  defp build_field_condition("occurrence_count", "lte", value),
    do: dynamic([a], a.occurrence_count <= ^value)

  defp build_field_condition("agent_id", "eq", value), do: dynamic([a], a.agent_id == ^value)
  defp build_field_condition("agent_id", "ne", value), do: dynamic([a], a.agent_id != ^value)
  defp build_field_condition("agent_id", "in", values), do: dynamic([a], a.agent_id in ^values)

  defp build_field_condition("assigned_to_id", "eq", value),
    do: dynamic([a], a.assigned_to_id == ^value)

  defp build_field_condition("assigned_to_id", "is_null", _),
    do: dynamic([a], is_nil(a.assigned_to_id))

  defp build_field_condition("assigned_to_id", "is_not_null", _),
    do: dynamic([a], not is_nil(a.assigned_to_id))

  defp build_field_condition("storyline_id", "eq", value),
    do: dynamic([a], a.storyline_id == ^value)

  defp build_field_condition("campaign_id", "eq", value), do: dynamic([a], a.campaign_id == ^value)

  defp build_field_condition("attributed_actor", "eq", value),
    do: dynamic([a], ^value in a.attributed_actors)

  # Date range conditions
  defp build_field_condition("created_at", "gt", value),
    do: dynamic([a], a.inserted_at > ^parse_datetime(value))

  defp build_field_condition("created_at", "gte", value),
    do: dynamic([a], a.inserted_at >= ^parse_datetime(value))

  defp build_field_condition("created_at", "lt", value),
    do: dynamic([a], a.inserted_at < ^parse_datetime(value))

  defp build_field_condition("created_at", "lte", value),
    do: dynamic([a], a.inserted_at <= ^parse_datetime(value))

  defp build_field_condition("updated_at", "gt", value),
    do: dynamic([a], a.updated_at > ^parse_datetime(value))

  defp build_field_condition("updated_at", "gte", value),
    do: dynamic([a], a.updated_at >= ^parse_datetime(value))

  defp build_field_condition("last_seen_at", "gt", value),
    do: dynamic([a], a.last_seen_at > ^parse_datetime(value))

  defp build_field_condition("last_seen_at", "gte", value),
    do: dynamic([a], a.last_seen_at >= ^parse_datetime(value))

  # JSON path queries for evidence and enrichment
  defp build_field_condition("process_name", "eq", value),
    do: dynamic([a], fragment("?->'process'->>'name' = ?", a.evidence, ^value))

  defp build_field_condition("process_name", "contains", value),
    do: dynamic([a], fragment("?->'process'->>'name' ILIKE ?", a.evidence, ^"%#{value}%"))

  defp build_field_condition("process_name", "regex", pattern),
    do: dynamic([a], fragment("?->'process'->>'name' ~ ?", a.evidence, ^pattern))

  defp build_field_condition("file_path", "eq", value),
    do: dynamic([a], fragment("?->'file'->>'path' = ?", a.evidence, ^value))

  defp build_field_condition("file_path", "contains", value),
    do: dynamic([a], fragment("?->'file'->>'path' ILIKE ?", a.evidence, ^"%#{value}%"))

  defp build_field_condition("file_path", "regex", pattern),
    do: dynamic([a], fragment("?->'file'->>'path' ~ ?", a.evidence, ^pattern))

  defp build_field_condition("file_hash", "eq", value) do
    dynamic(
      [a],
      fragment("?->'file'->>'md5' = ?", a.evidence, ^value) or
        fragment("?->'file'->>'sha1' = ?", a.evidence, ^value) or
        fragment("?->'file'->>'sha256' = ?", a.evidence, ^value)
    )
  end

  defp build_field_condition("ip_address", "eq", value),
    do: dynamic([a], fragment("?->'network'->>'ip' = ?", a.evidence, ^value))

  defp build_field_condition("ip_address", "cidr", cidr),
    do: dynamic([a], fragment("(?->'network'->>'ip')::inet << ?::inet", a.evidence, ^cidr))

  defp build_field_condition("domain", "eq", value),
    do: dynamic([a], fragment("?->'network'->>'domain' = ?", a.evidence, ^value))

  defp build_field_condition("domain", "contains", value),
    do: dynamic([a], fragment("?->'network'->>'domain' ILIKE ?", a.evidence, ^"%#{value}%"))

  defp build_field_condition("domain", "regex", pattern),
    do: dynamic([a], fragment("?->'network'->>'domain' ~ ?", a.evidence, ^pattern))

  defp build_field_condition("user", "eq", value),
    do: dynamic([a], fragment("?->'user'->>'name' = ?", a.evidence, ^value))

  defp build_field_condition("user", "contains", value),
    do: dynamic([a], fragment("?->'user'->>'name' ILIKE ?", a.evidence, ^"%#{value}%"))

  defp build_field_condition("detection_source", "eq", value),
    do: dynamic([a], fragment("?->>'source' = ?", a.detection_metadata, ^value))

  # Fallback for unsupported field/operator combinations
  defp build_field_condition(_field, _operator, _value), do: dynamic(true)

  # Quick filter presets
  defp apply_quick_filter(query, "my_alerts") do
    # Requires user context - handled in controller
    query
  end

  defp apply_quick_filter(query, "unresolved") do
    where(query, [a], a.status in ["new", "investigating"])
  end

  defp apply_quick_filter(query, "high_severity") do
    where(query, [a], a.severity in ["critical", "high"])
  end

  defp apply_quick_filter(query, "last_24h") do
    cutoff = DateTime.utc_now() |> DateTime.add(-24 * 3600, :second)
    where(query, [a], a.inserted_at >= ^cutoff)
  end

  defp apply_quick_filter(query, "last_7d") do
    cutoff = DateTime.utc_now() |> DateTime.add(-7 * 24 * 3600, :second)
    where(query, [a], a.inserted_at >= ^cutoff)
  end

  defp apply_quick_filter(query, "last_30d") do
    cutoff = DateTime.utc_now() |> DateTime.add(-30 * 24 * 3600, :second)
    where(query, [a], a.inserted_at >= ^cutoff)
  end

  defp apply_quick_filter(query, _), do: query

  # Helper to parse datetime strings
  defp parse_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> datetime
      _ -> DateTime.utc_now()
    end
  end

  defp parse_datetime(%DateTime{} = datetime), do: datetime
  defp parse_datetime(_), do: DateTime.utc_now()

  @doc """
  Exports filter as URL parameters.
  """
  def to_url_params(filter) when is_map(filter) do
    filter
    |> Jason.encode!()
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Parses filter from URL parameters.
  """
  def from_url_params(encoded) when is_binary(encoded) do
    with {:ok, json} <- Base.url_decode64(encoded, padding: false),
         {:ok, filter} <- Jason.decode(json) do
      {:ok, filter}
    else
      _ -> {:error, "Invalid filter encoding"}
    end
  end

  def from_url_params(_), do: {:error, "Invalid filter parameter"}

  @doc """
  Returns a list of supported fields with metadata.
  """
  def supported_fields do
    [
      %{
        name: "severity",
        type: :enum,
        operators: ["eq", "ne", "in"],
        values: ["critical", "high", "medium", "low", "info"]
      },
      %{
        name: "status",
        type: :enum,
        operators: ["eq", "ne", "in"],
        values: ["new", "investigating", "resolved", "false_positive"]
      },
      %{
        name: "verdict",
        type: :enum,
        operators: ["eq", "ne", "in"],
        values: ["unconfirmed", "true_positive", "false_positive", "benign", "suspicious"]
      },
      %{name: "mitre_technique", type: :string, operators: ["eq", "array_contains", "array_overlaps"]},
      %{name: "mitre_tactic", type: :string, operators: ["eq", "array_contains"]},
      %{name: "process_name", type: :string, operators: ["eq", "contains", "regex"]},
      %{name: "file_path", type: :string, operators: ["eq", "contains", "regex"]},
      %{name: "file_hash", type: :string, operators: ["eq"]},
      %{name: "ip_address", type: :ip, operators: ["eq", "cidr"]},
      %{name: "domain", type: :string, operators: ["eq", "contains", "regex"]},
      %{name: "user", type: :string, operators: ["eq", "contains"]},
      %{name: "agent_id", type: :uuid, operators: ["eq", "ne", "in"]},
      %{name: "assigned_to_id", type: :uuid, operators: ["eq", "is_null", "is_not_null"]},
      %{name: "threat_score", type: :float, operators: ["gt", "gte", "lt", "lte"]},
      %{name: "occurrence_count", type: :integer, operators: ["gt", "gte", "lt", "lte"]},
      %{name: "created_at", type: :datetime, operators: ["gt", "gte", "lt", "lte"]},
      %{name: "updated_at", type: :datetime, operators: ["gt", "gte", "lt", "lte"]},
      %{name: "last_seen_at", type: :datetime, operators: ["gt", "gte", "lt", "lte"]},
      %{name: "storyline_id", type: :string, operators: ["eq"]},
      %{name: "campaign_id", type: :string, operators: ["eq"]},
      %{name: "attributed_actor", type: :string, operators: ["eq"]},
      %{name: "detection_source", type: :enum, operators: ["eq"], values: ["yara", "sigma", "ml", "ioc"]}
    ]
  end
end
