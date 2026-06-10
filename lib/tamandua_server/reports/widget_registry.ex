defmodule TamanduaServer.Reports.WidgetRegistry do
  @moduledoc """
  Central registry for all available report widgets.

  Provides discovery, validation, and rendering capabilities for widgets
  used in custom report templates.
  """

  alias TamanduaServer.Reports.Widgets.{
    TextWidget,
    ChartWidget,
    TableWidget,
    StatsWidget,
    ImageWidget
  }

  @widgets %{
    "text" => TextWidget,
    "chart" => ChartWidget,
    "table" => TableWidget,
    "stats" => StatsWidget,
    "image" => ImageWidget
  }

  @doc """
  List all available widgets with their metadata.
  """
  def list_widgets do
    @widgets
    |> Enum.map(fn {_type, module} ->
      %{
        type: module.widget_type(),
        name: module.widget_name(),
        description: module.widget_description(),
        icon: module.widget_icon(),
        params: module.param_schema()
      }
    end)
    |> Enum.sort_by(& &1.name)
  end

  @doc """
  Get widget module by type.
  """
  def get_widget(type) do
    case Map.get(@widgets, type) do
      nil -> {:error, :unknown_widget}
      module -> {:ok, module}
    end
  end

  @doc """
  Validate widget configuration.
  """
  def validate_widget(widget_config) do
    with {:ok, type} <- validate_required(widget_config, "type"),
         {:ok, module} <- get_widget(type),
         {:ok, params} <- module.validate_params(widget_config["params"] || %{}) do
      {:ok, Map.put(widget_config, "params", params)}
    end
  end

  @doc """
  Render a widget with the given configuration and context.
  """
  def render_widget(widget_config, context) do
    with {:ok, validated_config} <- validate_widget(widget_config),
         {:ok, module} <- get_widget(validated_config["type"]) do
      # Convert string keys to atoms for easier access
      config = %{
        id: validated_config["id"],
        type: validated_config["type"],
        title: validated_config["title"] || module.widget_name(),
        position: validated_config["position"] || %{"x" => 0, "y" => 0},
        size: validated_config["size"] || %{"width" => 4, "height" => 3},
        params: validated_config["params"]
      }

      module.render(config, context)
    end
  end

  @doc """
  Render multiple widgets for a template.
  """
  def render_widgets(widget_configs, context) when is_list(widget_configs) do
    results = Enum.map(widget_configs, fn config ->
      case render_widget(config, context) do
        {:ok, rendered} -> rendered
        {:error, reason} ->
          %{
            "type" => "error",
            "title" => config["title"] || "Error",
            "content" => "Failed to render widget: #{inspect(reason)}"
          }
      end
    end)

    {:ok, results}
  end

  @doc """
  Get default configuration for a widget type.
  """
  def get_default_config(widget_type) do
    with {:ok, module} <- get_widget(widget_type) do
      {:ok, %{
        "id" => Ecto.UUID.generate(),
        "type" => widget_type,
        "title" => module.widget_name(),
        "position" => %{"x" => 0, "y" => 0},
        "size" => %{"width" => 4, "height" => 3},
        "params" => module.default_params()
      }}
    end
  end

  defp validate_required(map, key) do
    case Map.get(map, key) do
      nil -> {:error, "Missing required field: #{key}"}
      value -> {:ok, value}
    end
  end
end
