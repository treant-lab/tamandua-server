defmodule TamanduaServer.Reports.Widgets.ImageWidget do
  @moduledoc """
  Image widget for displaying logos, diagrams, or screenshots in reports.

  Supports:
  - URL-based images
  - Base64-encoded images
  - Company logo/branding
  - Alignment and sizing
  """

  use TamanduaServer.Reports.Widgets.BaseWidget

  @impl true
  def widget_type, do: "image"

  @impl true
  def widget_name, do: "Image"

  @impl true
  def widget_description, do: "Display logos, diagrams, or custom images"

  @impl true
  def widget_icon, do: "photograph"

  @impl true
  def default_params do
    %{
      "source" => "url",
      "url" => "",
      "base64" => "",
      "alt_text" => "Image",
      "width" => 300,
      "alignment" => "center",
      "caption" => ""
    }
  end

  @impl true
  def param_schema do
    [
      %{name: "source", type: {:enum, ["url", "base64", "logo"]}, default: "url"},
      %{name: "url", type: :string, default: ""},
      %{name: "base64", type: :string, default: ""},
      %{name: "alt_text", type: :string, default: "Image"},
      %{name: "width", type: {:range, 50, 800}, default: 300},
      %{name: "alignment", type: {:enum, ["left", "center", "right"]}, default: "center"},
      %{name: "caption", type: :string, default: ""}
    ]
  end

  @impl true
  def render(widget_config, _context) do
    params = widget_config.params

    image_src = case params["source"] do
      "url" -> params["url"]
      "base64" -> "data:image/png;base64,#{params["base64"]}"
      "logo" -> get_company_logo()
      _ -> ""
    end

    {:ok, %{
      "type" => "image",
      "title" => widget_config.title,
      "content" => %{
        "src" => image_src,
        "alt" => params["alt_text"],
        "caption" => params["caption"],
        "style" => %{
          "width" => params["width"],
          "textAlign" => params["alignment"]
        }
      }
    }}
  end

  defp get_company_logo do
    # Return default Tamandua logo as SVG data URI
    """
    data:image/svg+xml,%3Csvg viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath fill='%230066cc' d='M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z'/%3E%3C/svg%3E
    """
  end
end
