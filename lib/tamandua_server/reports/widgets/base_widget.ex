defmodule TamanduaServer.Reports.Widgets.BaseWidget do
  @moduledoc """
  Base behaviour for report widgets.

  Widgets are building blocks for custom report templates that can be
  arranged in a drag-and-drop designer. Each widget renders a specific
  type of content (chart, table, text, image, etc.).
  """

  @type widget_config :: %{
    id: String.t(),
    type: String.t(),
    title: String.t(),
    position: %{x: integer(), y: integer()},
    size: %{width: integer(), height: integer()},
    params: map()
  }

  @type render_context :: %{
    date_from: String.t(),
    date_to: String.t(),
    organization_id: binary() | nil,
    user: map() | nil
  }

  @callback widget_type() :: String.t()
  @callback widget_name() :: String.t()
  @callback widget_description() :: String.t()
  @callback widget_icon() :: String.t()
  @callback default_params() :: map()
  @callback param_schema() :: [map()]
  @callback render(widget_config(), render_context()) :: {:ok, map()} | {:error, term()}
  @callback validate_params(map()) :: {:ok, map()} | {:error, String.t()}

  @doc """
  Helper to validate common parameter types.
  """
  def validate_param(value, :string) when is_binary(value), do: {:ok, value}
  def validate_param(value, :integer) when is_integer(value), do: {:ok, value}
  def validate_param(value, :boolean) when is_boolean(value), do: {:ok, value}
  def validate_param(value, :color) when is_binary(value) do
    if String.match?(value, ~r/^#[0-9a-fA-F]{6}$/), do: {:ok, value}, else: {:error, "Invalid color format"}
  end
  def validate_param(value, {:enum, allowed}) do
    if value in allowed, do: {:ok, value}, else: {:error, "Value must be one of: #{inspect(allowed)}"}
  end
  def validate_param(value, {:range, min, max}) when is_number(value) do
    if value >= min and value <= max, do: {:ok, value}, else: {:error, "Value must be between #{min} and #{max}"}
  end
  def validate_param(_value, _type), do: {:error, "Invalid value"}

  defmacro __using__(_opts) do
    quote do
      @behaviour TamanduaServer.Reports.Widgets.BaseWidget
      import TamanduaServer.Reports.Widgets.BaseWidget

      @impl true
      def validate_params(params) do
        schema = param_schema()

        validated = Enum.reduce_while(schema, {:ok, %{}}, fn param_def, {:ok, acc} ->
          param_name = param_def.name
          param_type = param_def.type
          value = Map.get(params, param_name, param_def[:default])

          case validate_param(value, param_type) do
            {:ok, validated_value} -> {:cont, {:ok, Map.put(acc, param_name, validated_value)}}
            {:error, reason} -> {:halt, {:error, "#{param_name}: #{reason}"}}
          end
        end)

        case validated do
          {:ok, validated_params} -> {:ok, Map.merge(default_params(), validated_params)}
          error -> error
        end
      end

      defoverridable validate_params: 1
    end
  end
end
