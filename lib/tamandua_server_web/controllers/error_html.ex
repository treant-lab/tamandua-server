defmodule TamanduaServerWeb.ErrorHTML do
  @moduledoc """
  HTML error pages for the Tamandua Server.

  For non-API routes, renders minimal HTML error pages.
  In production, the SPA frontend handles most routing,
  so these are fallback pages.
  """

  use TamanduaServerWeb, :html

  # Catch-all render that returns a simple HTML error page
  def render(template, _assigns) do
    status = template |> String.split(".") |> List.first()

    {title, message} =
      case status do
        "404" -> {"Page Not Found", "The page you're looking for doesn't exist."}
        "500" -> {"Internal Server Error", "Something went wrong. Please try again later."}
        "403" -> {"Forbidden", "You don't have permission to access this resource."}
        "401" -> {"Unauthorized", "Please log in to continue."}
        _ -> {"Error", "An unexpected error occurred."}
      end

    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>#{title} — Tamandua</title>
      <style>
        body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
        .container { text-align: center; max-width: 480px; padding: 2rem; }
        h1 { font-size: 4rem; margin: 0; color: #f97316; }
        h2 { font-size: 1.5rem; margin: 0.5rem 0; }
        p { color: #94a3b8; margin: 1rem 0; }
        a { color: #38bdf8; text-decoration: none; }
        a:hover { text-decoration: underline; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>#{status}</h1>
        <h2>#{title}</h2>
        <p>#{message}</p>
        <a href="/app">← Back to Dashboard</a>
      </div>
    </body>
    </html>
    """
    |> Phoenix.HTML.raw()
  end
end
