defmodule TamanduaServer.Reports.Widgets.TextWidget do
  @moduledoc """
  Text/Markdown widget for displaying custom text content in reports.

  Supports:
  - Plain text
  - Markdown formatting
  - Dynamic variables ({{agent_count}}, {{alert_count}}, etc.)
  - Custom styling
  """

  use TamanduaServer.Reports.Widgets.BaseWidget

  alias TamanduaServer.{Agents, Alerts}

  @impl true
  def widget_type, do: "text"

  @impl true
  def widget_name, do: "Text Block"

  @impl true
  def widget_description, do: "Display custom text with optional Markdown formatting and dynamic variables"

  @impl true
  def widget_icon, do: "document-text"

  @impl true
  def default_params do
    %{
      "content" => "Enter your text here...",
      "format" => "markdown",
      "font_size" => 14,
      "alignment" => "left",
      "color" => "#1a1a2e"
    }
  end

  @impl true
  def param_schema do
    [
      %{name: "content", type: :string, default: "Enter your text here..."},
      %{name: "format", type: {:enum, ["plain", "markdown"]}, default: "markdown"},
      %{name: "font_size", type: {:range, 8, 48}, default: 14},
      %{name: "alignment", type: {:enum, ["left", "center", "right", "justify"]}, default: "left"},
      %{name: "color", type: :color, default: "#1a1a2e"}
    ]
  end

  @impl true
  def render(widget_config, context) do
    params = widget_config.params
    content = params["content"] || default_params()["content"]

    # Replace dynamic variables
    content = replace_variables(content, context)

    # Format content
    formatted_content = case params["format"] do
      "markdown" -> render_markdown(content)
      _ -> content
    end

    {:ok, %{
      "type" => "text",
      "title" => widget_config.title,
      "content" => formatted_content,
      "style" => %{
        "fontSize" => params["font_size"],
        "textAlign" => params["alignment"],
        "color" => params["color"]
      }
    }}
  end

  defp replace_variables(content, context) do
    variables = %{
      "{{agent_count}}" => to_string(safe_call(fn -> Agents.count_all() end, 0)),
      "{{online_agents}}" => to_string(safe_call(fn -> Agents.count_online() end, 0)),
      "{{alert_count}}" => to_string(safe_call(fn -> Alerts.count_open() end, 0)),
      "{{date_from}}" => context.date_from,
      "{{date_to}}" => context.date_to,
      "{{current_date}}" => Date.utc_today() |> Date.to_iso8601()
    }

    Enum.reduce(variables, content, fn {var, value}, acc ->
      String.replace(acc, var, value)
    end)
  end

  defp render_markdown(content) do
    # Simple markdown-to-HTML conversion (in production, use Earmark or similar)
    content
    |> String.replace(~r/\*\*(.*?)\*\*/, "<strong>\\1</strong>")
    |> String.replace(~r/\*(.*?)\*/, "<em>\\1</em>")
    |> String.replace(~r/^# (.*)$/m, "<h1>\\1</h1>")
    |> String.replace(~r/^## (.*)$/m, "<h2>\\1</h2>")
    |> String.replace(~r/^### (.*)$/m, "<h3>\\1</h3>")
    |> String.replace(~r/\n\n/, "</p><p>")
    |> then(&"<p>#{&1}</p>")
  end

  defp safe_call(fun, default) do
    try do
      fun.()
    rescue
      _ -> default
    catch
      _, _ -> default
    end
  end
end
