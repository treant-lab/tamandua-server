defmodule TamanduaServer.Filtering.FilterParser do
  @moduledoc """
  Advanced filter DSL parser supporting 30+ operators and complex nested logic.

  ## Supported Operators

  ### Comparison Operators
  - `eq`: Equals (=)
  - `ne`: Not equals (!=)
  - `gt`: Greater than (>)
  - `gte`: Greater than or equal (>=)
  - `lt`: Less than (<)
  - `lte`: Less than or equal (<=)

  ### String Operators
  - `contains`: String contains substring
  - `not_contains`: String does not contain substring
  - `starts_with`: String starts with prefix
  - `ends_with`: String ends with suffix
  - `regex`: Regular expression match
  - `in`: Value in list
  - `not_in`: Value not in list

  ### Numeric Operators
  - `between`: Value between min and max (inclusive)
  - `in_range`: Value in numeric range
  - `modulo`: Value modulo N equals result

  ### Date/Time Operators
  - `before`: Date before specified date
  - `after`: Date after specified date
  - `date_between`: Date between two dates
  - `last_n_days`: Date within last N days
  - `last_n_hours`: Date within last N hours
  - `last_n_minutes`: Date within last N minutes

  ### Array Operators
  - `array_contains`: Array contains value
  - `array_contains_all`: Array contains all values
  - `array_contains_any`: Array contains any value
  - `array_overlaps`: Arrays have common elements
  - `array_empty`: Array is empty
  - `array_not_empty`: Array is not empty

  ### Geospatial Operators
  - `within_radius`: Point within radius (lat, lon, radius_km)
  - `in_polygon`: Point within polygon
  - `bbox`: Point within bounding box

  ### Null Operators
  - `is_null`: Field is null
  - `is_not_null`: Field is not null

  ### Network Operators
  - `cidr`: IP in CIDR range
  - `ip_range`: IP in range

  ### Special Operators
  - `exists`: Field exists in document
  - `json_path`: JSONPath query
  - `fuzzy`: Fuzzy string match (Levenshtein distance)

  ## Filter Structure

      %{
        "logic" => "AND" | "OR" | "NOT",
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

  ## Examples

      # Simple condition
      %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"}
        ]
      }

      # Nested logic
      %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "in", "value" => ["critical", "high"]},
          %{
            "logic" => "OR",
            "conditions" => [
              %{"field" => "status", "operator" => "eq", "value" => "new"},
              %{"field" => "assigned_to_id", "operator" => "is_null"}
            ]
          }
        ]
      }

      # Date range
      %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "created_at", "operator" => "last_n_days", "value" => 7}
        ]
      }

      # Geospatial
      %{
        "logic" => "AND",
        "conditions" => [
          %{
            "field" => "location",
            "operator" => "within_radius",
            "value" => %{"lat" => 37.7749, "lon" => -122.4194, "radius_km" => 50}
          }
        ]
      }
  """

  @type operator ::
          :eq
          | :ne
          | :gt
          | :gte
          | :lt
          | :lte
          | :contains
          | :not_contains
          | :starts_with
          | :ends_with
          | :regex
          | :in
          | :not_in
          | :between
          | :in_range
          | :before
          | :after
          | :date_between
          | :last_n_days
          | :last_n_hours
          | :last_n_minutes
          | :array_contains
          | :array_contains_all
          | :array_contains_any
          | :array_overlaps
          | :array_empty
          | :array_not_empty
          | :within_radius
          | :in_polygon
          | :bbox
          | :is_null
          | :is_not_null
          | :cidr
          | :ip_range
          | :exists
          | :json_path
          | :fuzzy
          | :modulo

  @type logic :: :and | :or | :not

  @type condition :: %{
          required(:field) => String.t(),
          required(:operator) => String.t(),
          optional(:value) => any()
        }

  @type filter_group :: %{
          required(:logic) => String.t(),
          required(:conditions) => list(condition() | filter_group())
        }

  @supported_operators [
    # Comparison
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    # String
    "contains",
    "not_contains",
    "starts_with",
    "ends_with",
    "regex",
    "in",
    "not_in",
    # Numeric
    "between",
    "in_range",
    "modulo",
    # Date/Time
    "before",
    "after",
    "date_between",
    "last_n_days",
    "last_n_hours",
    "last_n_minutes",
    # Array
    "array_contains",
    "array_contains_all",
    "array_contains_any",
    "array_overlaps",
    "array_empty",
    "array_not_empty",
    # Geospatial
    "within_radius",
    "in_polygon",
    "bbox",
    # Null
    "is_null",
    "is_not_null",
    # Network
    "cidr",
    "ip_range",
    # Special
    "exists",
    "json_path",
    "fuzzy"
  ]

  @doc """
  Validates a filter structure.

  ## Examples

      iex> FilterParser.validate(%{
      ...>   "logic" => "AND",
      ...>   "conditions" => [
      ...>     %{"field" => "severity", "operator" => "eq", "value" => "critical"}
      ...>   ]
      ...> })
      {:ok, %{...}}

      iex> FilterParser.validate(%{"invalid" => "filter"})
      {:error, "Filter must have 'logic' and 'conditions'"}
  """
  def validate(filter) when is_map(filter) do
    cond do
      Map.has_key?(filter, "logic") and Map.has_key?(filter, "conditions") ->
        validate_filter_group(filter)

      Map.has_key?(filter, "field") and Map.has_key?(filter, "operator") ->
        validate_condition(filter)

      true ->
        {:error, "Filter must have 'logic' and 'conditions' or 'field' and 'operator'"}
    end
  end

  def validate(_), do: {:error, "Filter must be a map"}

  @doc """
  Validates a filter group (AND/OR/NOT with conditions).
  """
  def validate_filter_group(%{"logic" => logic, "conditions" => conditions})
      when logic in ["AND", "OR", "NOT"] and is_list(conditions) do
    if logic == "NOT" and length(conditions) > 1 do
      {:error, "NOT logic can only have one condition"}
    else
      case validate_conditions(conditions) do
        {:ok, validated_conditions} ->
          {:ok, %{"logic" => logic, "conditions" => validated_conditions}}

        error ->
          error
      end
    end
  end

  def validate_filter_group(_), do: {:error, "Invalid filter group structure"}

  defp validate_conditions(conditions) do
    validated =
      Enum.reduce_while(conditions, {:ok, []}, fn condition, {:ok, acc} ->
        case validate(condition) do
          {:ok, validated} -> {:cont, {:ok, [validated | acc]}}
          error -> {:halt, error}
        end
      end)

    case validated do
      {:ok, list} -> {:ok, Enum.reverse(list)}
      error -> error
    end
  end

  @doc """
  Validates a single filter condition.
  """
  def validate_condition(%{"field" => field, "operator" => operator} = condition)
      when is_binary(field) and is_binary(operator) do
    cond do
      operator not in @supported_operators ->
        {:error, "Unsupported operator: #{operator}"}

      not valid_value_for_operator?(operator, Map.get(condition, "value")) ->
        {:error, "Invalid value for operator #{operator}"}

      true ->
        {:ok, condition}
    end
  end

  def validate_condition(_), do: {:error, "Invalid condition structure"}

  # Validate value based on operator
  defp valid_value_for_operator?("is_null", _), do: true
  defp valid_value_for_operator?("is_not_null", _), do: true
  defp valid_value_for_operator?("array_empty", _), do: true
  defp valid_value_for_operator?("array_not_empty", _), do: true
  defp valid_value_for_operator?("exists", _), do: true

  defp valid_value_for_operator?("in", value) when is_list(value), do: true
  defp valid_value_for_operator?("not_in", value) when is_list(value), do: true
  defp valid_value_for_operator?("array_contains_all", value) when is_list(value), do: true
  defp valid_value_for_operator?("array_contains_any", value) when is_list(value), do: true
  defp valid_value_for_operator?("array_overlaps", value) when is_list(value), do: true

  defp valid_value_for_operator?("between", %{"min" => _, "max" => _}), do: true
  defp valid_value_for_operator?("in_range", %{"min" => _, "max" => _}), do: true
  defp valid_value_for_operator?("date_between", %{"start" => _, "end" => _}), do: true

  defp valid_value_for_operator?("within_radius", %{"lat" => _, "lon" => _, "radius_km" => _}),
    do: true

  defp valid_value_for_operator?("in_polygon", points) when is_list(points), do: true

  defp valid_value_for_operator?("bbox", %{
         "min_lat" => _,
         "min_lon" => _,
         "max_lat" => _,
         "max_lon" => _
       }),
       do: true

  defp valid_value_for_operator?("modulo", %{"divisor" => _, "result" => _}), do: true
  defp valid_value_for_operator?("fuzzy", %{"value" => _, "distance" => _}), do: true

  defp valid_value_for_operator?("last_n_days", value) when is_integer(value) and value > 0,
    do: true

  defp valid_value_for_operator?("last_n_hours", value) when is_integer(value) and value > 0,
    do: true

  defp valid_value_for_operator?("last_n_minutes", value) when is_integer(value) and value > 0,
    do: true

  defp valid_value_for_operator?("ip_range", %{"start" => _, "end" => _}), do: true

  defp valid_value_for_operator?(_, nil), do: false
  defp valid_value_for_operator?(_, _), do: true

  @doc """
  Returns list of all supported operators.
  """
  def supported_operators, do: @supported_operators

  @doc """
  Returns operator metadata including display name and expected value type.
  """
  def operator_metadata do
    %{
      # Comparison
      "eq" => %{name: "Equals", value_type: :single, symbol: "="},
      "ne" => %{name: "Not Equals", value_type: :single, symbol: "!="},
      "gt" => %{name: "Greater Than", value_type: :single, symbol: ">"},
      "gte" => %{name: "Greater Than or Equal", value_type: :single, symbol: ">="},
      "lt" => %{name: "Less Than", value_type: :single, symbol: "<"},
      "lte" => %{name: "Less Than or Equal", value_type: :single, symbol: "<="},
      # String
      "contains" => %{name: "Contains", value_type: :single},
      "not_contains" => %{name: "Does Not Contain", value_type: :single},
      "starts_with" => %{name: "Starts With", value_type: :single},
      "ends_with" => %{name: "Ends With", value_type: :single},
      "regex" => %{name: "Matches Regex", value_type: :single},
      "in" => %{name: "In List", value_type: :list},
      "not_in" => %{name: "Not In List", value_type: :list},
      # Numeric
      "between" => %{name: "Between", value_type: :range},
      "in_range" => %{name: "In Range", value_type: :range},
      "modulo" => %{name: "Modulo", value_type: :modulo},
      # Date/Time
      "before" => %{name: "Before", value_type: :datetime},
      "after" => %{name: "After", value_type: :datetime},
      "date_between" => %{name: "Between Dates", value_type: :date_range},
      "last_n_days" => %{name: "Last N Days", value_type: :number},
      "last_n_hours" => %{name: "Last N Hours", value_type: :number},
      "last_n_minutes" => %{name: "Last N Minutes", value_type: :number},
      # Array
      "array_contains" => %{name: "Contains", value_type: :single},
      "array_contains_all" => %{name: "Contains All", value_type: :list},
      "array_contains_any" => %{name: "Contains Any", value_type: :list},
      "array_overlaps" => %{name: "Overlaps", value_type: :list},
      "array_empty" => %{name: "Is Empty", value_type: :none},
      "array_not_empty" => %{name: "Is Not Empty", value_type: :none},
      # Geospatial
      "within_radius" => %{name: "Within Radius", value_type: :geo_radius},
      "in_polygon" => %{name: "In Polygon", value_type: :geo_polygon},
      "bbox" => %{name: "In Bounding Box", value_type: :geo_bbox},
      # Null
      "is_null" => %{name: "Is Empty", value_type: :none},
      "is_not_null" => %{name: "Is Not Empty", value_type: :none},
      # Network
      "cidr" => %{name: "In CIDR Range", value_type: :single},
      "ip_range" => %{name: "In IP Range", value_type: :ip_range},
      # Special
      "exists" => %{name: "Exists", value_type: :none},
      "json_path" => %{name: "JSONPath", value_type: :single},
      "fuzzy" => %{name: "Fuzzy Match", value_type: :fuzzy}
    }
  end

  @doc """
  Converts filter to human-readable description.

  ## Examples

      iex> FilterParser.to_description(%{
      ...>   "logic" => "AND",
      ...>   "conditions" => [
      ...>     %{"field" => "severity", "operator" => "eq", "value" => "critical"}
      ...>   ]
      ...> })
      "severity equals critical"
  """
  def to_description(filter) when is_map(filter) do
    cond do
      Map.has_key?(filter, "logic") and Map.has_key?(filter, "conditions") ->
        describe_group(filter)

      Map.has_key?(filter, "field") and Map.has_key?(filter, "operator") ->
        describe_condition(filter)

      true ->
        "Invalid filter"
    end
  end

  defp describe_group(%{"logic" => logic, "conditions" => conditions}) do
    descriptions =
      conditions
      |> Enum.map(&to_description/1)
      |> Enum.join(" #{String.downcase(logic)} ")

    "(#{descriptions})"
  end

  defp describe_condition(%{"field" => field, "operator" => operator, "value" => value}) do
    metadata = operator_metadata()[operator]
    op_name = if metadata, do: String.downcase(metadata.name), else: operator

    formatted_field = field |> String.replace("_", " ")
    formatted_value = format_value_for_description(value)

    "#{formatted_field} #{op_name} #{formatted_value}"
  end

  defp describe_condition(%{"field" => field, "operator" => operator}) do
    metadata = operator_metadata()[operator]
    op_name = if metadata, do: String.downcase(metadata.name), else: operator
    formatted_field = field |> String.replace("_", " ")

    "#{formatted_field} #{op_name}"
  end

  defp format_value_for_description(value) when is_list(value), do: Enum.join(value, ", ")
  defp format_value_for_description(value) when is_map(value), do: inspect(value)
  defp format_value_for_description(value), do: to_string(value)
end
