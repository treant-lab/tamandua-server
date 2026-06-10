defmodule TamanduaServer.Connectors.ConfigValidator do
  @moduledoc """
  Configuration validator using JSON Schema.

  Validates connector configuration against provided schema.
  """

  @doc """
  Validate configuration against a JSON schema.

  ## Schema format (simplified):
      %{
        required: [:url, :api_key],
        properties: %{
          url: %{type: :string, format: :url},
          api_key: %{type: :string, min_length: 10},
          timeout: %{type: :integer, default: 30}
        }
      }
  """
  def validate(config, schema) do
    with :ok <- validate_required(config, schema),
         :ok <- validate_properties(config, schema) do
      :ok
    end
  end

  defp validate_required(config, schema) do
    required = Map.get(schema, :required, [])
    missing = Enum.filter(required, fn key ->
      not Map.has_key?(config, key)
    end)

    if Enum.empty?(missing) do
      :ok
    else
      {:error, {:missing_required_fields, missing}}
    end
  end

  defp validate_properties(config, schema) do
    properties = Map.get(schema, :properties, %{})

    errors = Enum.flat_map(config, fn {key, value} ->
      case Map.get(properties, key) do
        nil -> []
        prop_schema -> validate_property(key, value, prop_schema)
      end
    end)

    if Enum.empty?(errors) do
      :ok
    else
      {:error, {:validation_failed, errors}}
    end
  end

  defp validate_property(key, value, prop_schema) do
    type = Map.get(prop_schema, :type)
    errors = []

    # Type validation
    errors = if type && !valid_type?(value, type) do
      [{key, "expected type #{type}, got #{typeof(value)}"} | errors]
    else
      errors
    end

    # Format validation
    errors = case Map.get(prop_schema, :format) do
      :url -> if !valid_url?(value), do: [{key, "invalid URL"} | errors], else: errors
      :email -> if !valid_email?(value), do: [{key, "invalid email"} | errors], else: errors
      _ -> errors
    end

    # Length validation
    errors = case Map.get(prop_schema, :min_length) do
      nil -> errors
      min -> if String.length(to_string(value)) < min,
               do: [{key, "minimum length is #{min}"} | errors],
               else: errors
    end

    errors
  end

  defp valid_type?(value, :string) when is_binary(value), do: true
  defp valid_type?(value, :integer) when is_integer(value), do: true
  defp valid_type?(value, :number) when is_number(value), do: true
  defp valid_type?(value, :boolean) when is_boolean(value), do: true
  defp valid_type?(value, :map) when is_map(value), do: true
  defp valid_type?(value, :list) when is_list(value), do: true
  defp valid_type?(_, _), do: false

  defp typeof(value) when is_binary(value), do: :string
  defp typeof(value) when is_integer(value), do: :integer
  defp typeof(value) when is_float(value), do: :number
  defp typeof(value) when is_boolean(value), do: :boolean
  defp typeof(value) when is_map(value), do: :map
  defp typeof(value) when is_list(value), do: :list
  defp typeof(_), do: :unknown

  defp valid_url?(url) when is_binary(url) do
    uri = URI.parse(url)
    uri.scheme in ["http", "https"] && uri.host != nil
  end
  defp valid_url?(_), do: false

  defp valid_email?(email) when is_binary(email) do
    Regex.match?(~r/^[^\s@]+@[^\s@]+\.[^\s@]+$/, email)
  end
  defp valid_email?(_), do: false
end
