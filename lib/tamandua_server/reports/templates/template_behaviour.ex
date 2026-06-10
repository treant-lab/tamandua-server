defmodule TamanduaServer.Reports.Templates.TemplateBehaviour do
  @moduledoc """
  Behaviour definition for report templates.

  All report templates must implement these callbacks to be used
  by the Report Engine.
  """

  @doc "Returns the human-readable name of the report."
  @callback name() :: String.t()

  @doc "Returns a description of what the report contains."
  @callback description() :: String.t()

  @doc "Returns the category for grouping (e.g., 'security', 'compliance', 'operations')."
  @callback category() :: String.t()

  @doc "Returns a list of section names included in the report."
  @callback sections() :: [String.t()]

  @doc "Returns configurable parameters for the template."
  @callback parameters() :: [map()]

  @doc "Returns supported output formats for this template."
  @callback supported_formats() :: [:pdf | :html | :csv | :json]

  @doc """
  Generates the report data.

  ## Arguments
  - `date_from` - Start date (ISO8601 string)
  - `date_to` - End date (ISO8601 string)
  - `params` - Additional template-specific parameters

  ## Returns
  A map with the following structure:
  ```
  %{
    "title" => "Report Title",
    "sections" => [
      %{
        "title" => "Section Title",
        "type" => "summary" | "stats" | "table" | "list" | "chart",
        "content" => ...
      }
    ]
  }
  ```
  """
  @callback generate(date_from :: String.t(), date_to :: String.t(), params :: map()) :: map()

  @doc """
  Optional callback for custom PDF rendering.
  Return nil to use default HTML-to-PDF conversion.
  """
  @callback render_pdf(report_data :: map()) :: binary() | nil

  @optional_callbacks [render_pdf: 1]
end
