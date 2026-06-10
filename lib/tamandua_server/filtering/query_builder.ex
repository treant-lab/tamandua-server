defmodule TamanduaServer.Filtering.QueryBuilder do
  @moduledoc """
  Converts filter DSL to Ecto queries.

  Supports all 30+ operators from FilterParser and generates optimized
  PostgreSQL queries with proper indexing hints.
  """

  import Ecto.Query, warn: false
  alias TamanduaServer.Filtering.FilterParser

  @doc """
  Builds an Ecto query from a filter structure.

  ## Examples

      iex> filter = %{
      ...>   "logic" => "AND",
      ...>   "conditions" => [
      ...>     %{"field" => "severity", "operator" => "eq", "value" => "critical"}
      ...>   ]
      ...> }
      iex> QueryBuilder.build(Alert, filter)
      #Ecto.Query<...>
  """
  def build(base_query, filter) when is_map(filter) do
    case FilterParser.validate(filter) do
      {:ok, validated_filter} ->
        apply_filter(base_query, validated_filter)

      {:error, _reason} ->
        base_query
    end
  end

  def build(base_query, _), do: base_query

  @doc """
  Applies a validated filter to a query.
  """
  def apply_filter(query, %{"logic" => logic, "conditions" => conditions}) do
    case logic do
      "AND" -> apply_and_conditions(query, conditions)
      "OR" -> apply_or_conditions(query, conditions)
      "NOT" -> apply_not_conditions(query, conditions)
    end
  end

  def apply_filter(query, %{"field" => _, "operator" => _} = condition) do
    dynamic = build_condition_dynamic(condition)
    where(query, ^dynamic)
  end

  def apply_filter(query, _), do: query

  # AND conditions
  defp apply_and_conditions(query, conditions) do
    Enum.reduce(conditions, query, fn condition, acc_query ->
      dynamic = build_condition_dynamic(condition)
      where(acc_query, ^dynamic)
    end)
  end

  # OR conditions
  defp apply_or_conditions(query, conditions) do
    dynamic =
      Enum.reduce(conditions, dynamic(false), fn condition, acc_dynamic ->
        condition_dynamic = build_condition_dynamic(condition)
        dynamic([q], ^acc_dynamic or ^condition_dynamic)
      end)

    where(query, ^dynamic)
  end

  # NOT conditions
  defp apply_not_conditions(query, [condition]) do
    dynamic = build_condition_dynamic(condition)
    where(query, [q], not (^dynamic))
  end

  defp apply_not_conditions(query, _), do: query

  # Build dynamic query for a condition
  defp build_condition_dynamic(%{"logic" => logic, "conditions" => conditions}) do
    case logic do
      "AND" -> build_and_dynamic(conditions)
      "OR" -> build_or_dynamic(conditions)
      "NOT" -> build_not_dynamic(conditions)
    end
  end

  defp build_condition_dynamic(%{"field" => field, "operator" => operator, "value" => value}) do
    build_field_condition(field, operator, value)
  end

  defp build_condition_dynamic(%{"field" => field, "operator" => operator}) do
    build_field_condition(field, operator, nil)
  end

  defp build_and_dynamic(conditions) do
    Enum.reduce(conditions, dynamic(true), fn condition, acc_dynamic ->
      condition_dynamic = build_condition_dynamic(condition)
      dynamic([q], ^acc_dynamic and ^condition_dynamic)
    end)
  end

  defp build_or_dynamic(conditions) do
    Enum.reduce(conditions, dynamic(false), fn condition, acc_dynamic ->
      condition_dynamic = build_condition_dynamic(condition)
      dynamic([q], ^acc_dynamic or ^condition_dynamic)
    end)
  end

  defp build_not_dynamic([condition]) do
    condition_dynamic = build_condition_dynamic(condition)
    dynamic([q], not (^condition_dynamic))
  end

  defp build_not_dynamic(_), do: dynamic(true)

  # Build field-specific conditions
  # Comparison operators
  defp build_field_condition(field, "eq", value) do
    dynamic([q], field(q, ^String.to_atom(field)) == ^value)
  end

  defp build_field_condition(field, "ne", value) do
    dynamic([q], field(q, ^String.to_atom(field)) != ^value)
  end

  defp build_field_condition(field, "gt", value) do
    dynamic([q], field(q, ^String.to_atom(field)) > ^value)
  end

  defp build_field_condition(field, "gte", value) do
    dynamic([q], field(q, ^String.to_atom(field)) >= ^value)
  end

  defp build_field_condition(field, "lt", value) do
    dynamic([q], field(q, ^String.to_atom(field)) < ^value)
  end

  defp build_field_condition(field, "lte", value) do
    dynamic([q], field(q, ^String.to_atom(field)) <= ^value)
  end

  # String operators
  defp build_field_condition(field, "contains", value) do
    pattern = "%#{value}%"
    dynamic([q], ilike(field(q, ^String.to_atom(field)), ^pattern))
  end

  defp build_field_condition(field, "not_contains", value) do
    pattern = "%#{value}%"
    dynamic([q], not ilike(field(q, ^String.to_atom(field)), ^pattern))
  end

  defp build_field_condition(field, "starts_with", value) do
    pattern = "#{value}%"
    dynamic([q], ilike(field(q, ^String.to_atom(field)), ^pattern))
  end

  defp build_field_condition(field, "ends_with", value) do
    pattern = "%#{value}"
    dynamic([q], ilike(field(q, ^String.to_atom(field)), ^pattern))
  end

  defp build_field_condition(field, "regex", pattern) do
    dynamic([q], fragment("? ~ ?", field(q, ^String.to_atom(field)), ^pattern))
  end

  defp build_field_condition(field, "in", values) when is_list(values) do
    dynamic([q], field(q, ^String.to_atom(field)) in ^values)
  end

  defp build_field_condition(field, "not_in", values) when is_list(values) do
    dynamic([q], field(q, ^String.to_atom(field)) not in ^values)
  end

  # Numeric operators
  defp build_field_condition(field, "between", %{"min" => min, "max" => max}) do
    dynamic(
      [q],
      field(q, ^String.to_atom(field)) >= ^min and field(q, ^String.to_atom(field)) <= ^max
    )
  end

  defp build_field_condition(field, "in_range", %{"min" => min, "max" => max}) do
    dynamic(
      [q],
      field(q, ^String.to_atom(field)) >= ^min and field(q, ^String.to_atom(field)) <= ^max
    )
  end

  defp build_field_condition(field, "modulo", %{"divisor" => divisor, "result" => result}) do
    dynamic([q], fragment("? % ? = ?", field(q, ^String.to_atom(field)), ^divisor, ^result))
  end

  # Date/Time operators
  defp build_field_condition(field, "before", value) do
    datetime = parse_datetime(value)
    dynamic([q], field(q, ^String.to_atom(field)) < ^datetime)
  end

  defp build_field_condition(field, "after", value) do
    datetime = parse_datetime(value)
    dynamic([q], field(q, ^String.to_atom(field)) > ^datetime)
  end

  defp build_field_condition(field, "date_between", %{"start" => start_val, "end" => end_val}) do
    start_datetime = parse_datetime(start_val)
    end_datetime = parse_datetime(end_val)

    dynamic(
      [q],
      field(q, ^String.to_atom(field)) >= ^start_datetime and
        field(q, ^String.to_atom(field)) <= ^end_datetime
    )
  end

  defp build_field_condition(field, "last_n_days", n) when is_integer(n) do
    cutoff = DateTime.utc_now() |> DateTime.add(-n * 24 * 3600, :second)
    dynamic([q], field(q, ^String.to_atom(field)) >= ^cutoff)
  end

  defp build_field_condition(field, "last_n_hours", n) when is_integer(n) do
    cutoff = DateTime.utc_now() |> DateTime.add(-n * 3600, :second)
    dynamic([q], field(q, ^String.to_atom(field)) >= ^cutoff)
  end

  defp build_field_condition(field, "last_n_minutes", n) when is_integer(n) do
    cutoff = DateTime.utc_now() |> DateTime.add(-n * 60, :second)
    dynamic([q], field(q, ^String.to_atom(field)) >= ^cutoff)
  end

  # Array operators
  defp build_field_condition(field, "array_contains", value) do
    dynamic([q], ^value in field(q, ^String.to_atom(field)))
  end

  defp build_field_condition(field, "array_contains_all", values) when is_list(values) do
    dynamic([q], fragment("? @> ?::jsonb", field(q, ^String.to_atom(field)), ^values))
  end

  defp build_field_condition(field, "array_contains_any", values) when is_list(values) do
    dynamic([q], fragment("? && ?", field(q, ^String.to_atom(field)), ^values))
  end

  defp build_field_condition(field, "array_overlaps", values) when is_list(values) do
    dynamic([q], fragment("? && ?", field(q, ^String.to_atom(field)), ^values))
  end

  defp build_field_condition(field, "array_empty", _) do
    dynamic(
      [q],
      is_nil(field(q, ^String.to_atom(field))) or
        fragment("array_length(?, 1) IS NULL", field(q, ^String.to_atom(field)))
    )
  end

  defp build_field_condition(field, "array_not_empty", _) do
    dynamic(
      [q],
      not is_nil(field(q, ^String.to_atom(field))) and
        fragment("array_length(?, 1) > 0", field(q, ^String.to_atom(field)))
    )
  end

  # Geospatial operators (requires PostGIS extension)
  defp build_field_condition(field, "within_radius", %{
         "lat" => lat,
         "lon" => lon,
         "radius_km" => radius
       }) do
    # Convert to meters for PostGIS
    radius_meters = radius * 1000

    dynamic(
      [q],
      fragment(
        "ST_DWithin(?::geography, ST_MakePoint(?, ?)::geography, ?)",
        field(q, ^String.to_atom(field)),
        ^lon,
        ^lat,
        ^radius_meters
      )
    )
  end

  defp build_field_condition(field, "in_polygon", points) when is_list(points) do
    # Convert points to WKT polygon format
    wkt_points = Enum.map_join(points, ", ", fn %{"lat" => lat, "lon" => lon} -> "#{lon} #{lat}" end)
    wkt = "POLYGON((#{wkt_points}))"

    dynamic(
      [q],
      fragment("ST_Within(?::geography, ST_GeogFromText(?))", field(q, ^String.to_atom(field)), ^wkt)
    )
  end

  defp build_field_condition(field, "bbox", %{
         "min_lat" => min_lat,
         "min_lon" => min_lon,
         "max_lat" => max_lat,
         "max_lon" => max_lon
       }) do
    dynamic(
      [q],
      fragment(
        "? && ST_MakeEnvelope(?, ?, ?, ?, 4326)",
        field(q, ^String.to_atom(field)),
        ^min_lon,
        ^min_lat,
        ^max_lon,
        ^max_lat
      )
    )
  end

  # Null operators
  defp build_field_condition(field, "is_null", _) do
    dynamic([q], is_nil(field(q, ^String.to_atom(field))))
  end

  defp build_field_condition(field, "is_not_null", _) do
    dynamic([q], not is_nil(field(q, ^String.to_atom(field))))
  end

  # Network operators
  defp build_field_condition(field, "cidr", cidr) do
    dynamic([q], fragment("?::inet << ?::inet", field(q, ^String.to_atom(field)), ^cidr))
  end

  defp build_field_condition(field, "ip_range", %{"start" => start_ip, "end" => end_ip}) do
    dynamic(
      [q],
      fragment(
        "?::inet >= ?::inet AND ?::inet <= ?::inet",
        field(q, ^String.to_atom(field)),
        ^start_ip,
        field(q, ^String.to_atom(field)),
        ^end_ip
      )
    )
  end

  # Special operators
  defp build_field_condition(field, "exists", _) do
    dynamic([q], not is_nil(field(q, ^String.to_atom(field))))
  end

  defp build_field_condition(field, "json_path", path) do
    dynamic([q], fragment("jsonb_path_exists(?, ?)", field(q, ^String.to_atom(field)), ^path))
  end

  defp build_field_condition(field, "fuzzy", %{"value" => value, "distance" => distance}) do
    dynamic(
      [q],
      fragment("levenshtein(?, ?) <= ?", field(q, ^String.to_atom(field)), ^value, ^distance)
    )
  end

  # Fallback for unsupported operators
  defp build_field_condition(_field, _operator, _value) do
    dynamic(true)
  end

  # Helper functions
  defp parse_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> datetime
      _ -> DateTime.utc_now()
    end
  end

  defp parse_datetime(%DateTime{} = datetime), do: datetime
  defp parse_datetime(_), do: DateTime.utc_now()

  @doc """
  Extracts filter conditions as a flat list for display.

  ## Examples

      iex> QueryBuilder.extract_conditions(%{
      ...>   "logic" => "AND",
      ...>   "conditions" => [
      ...>     %{"field" => "severity", "operator" => "eq", "value" => "critical"}
      ...>   ]
      ...> })
      [%{"field" => "severity", "operator" => "eq", "value" => "critical", "path" => [0]}]
  """
  def extract_conditions(filter, path \\ []) do
    cond do
      Map.has_key?(filter, "logic") and Map.has_key?(filter, "conditions") ->
        filter["conditions"]
        |> Enum.with_index()
        |> Enum.flat_map(fn {condition, idx} ->
          extract_conditions(condition, path ++ [idx])
        end)

      Map.has_key?(filter, "field") and Map.has_key?(filter, "operator") ->
        [Map.put(filter, "path", path)]

      true ->
        []
    end
  end

  @doc """
  Counts the number of conditions in a filter.
  """
  def count_conditions(filter) do
    filter
    |> extract_conditions()
    |> length()
  end

  @doc """
  Validates filter against a schema.

  Ensures that all referenced fields exist in the schema and operators
  are compatible with field types.
  """
  def validate_against_schema(filter, field_definitions) do
    conditions = extract_conditions(filter)

    Enum.reduce_while(conditions, {:ok, filter}, fn condition, {:ok, _acc} ->
      field_name = condition["field"]
      operator = condition["operator"]

      case find_field_definition(field_definitions, field_name) do
        nil ->
          {:halt, {:error, "Unknown field: #{field_name}"}}

        field_def ->
          if operator in field_def.operators do
            {:cont, {:ok, filter}}
          else
            {:halt,
             {:error, "Operator '#{operator}' not supported for field '#{field_name}'"}}
          end
      end
    end)
  end

  defp find_field_definition(field_definitions, field_name) do
    Enum.find(field_definitions, fn def -> def.name == field_name end)
  end
end
