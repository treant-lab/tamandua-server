defmodule TamanduaServerWeb.API.V1.DocsController do
  @moduledoc """
  Controller for serving API documentation.

  Provides:
  - Swagger UI interface at /api/docs
  - OpenAPI specification at /api/docs/openapi.yaml
  - ReDoc alternative at /api/docs/redoc
  """
  use TamanduaServerWeb, :controller

  @doc """
  Serve the Swagger UI HTML page.

  GET /api/docs
  """
  def index(conn, _params) do
    html = swagger_ui_html()

    conn
    |> put_resp_content_type("text/html")
    |> send_resp(200, html)
  end

  @doc """
  Serve the OpenAPI specification file.

  GET /api/docs/openapi.yaml
  """
  def spec(conn, _params) do
    spec_path = Application.app_dir(:tamandua_server, "priv/static/openapi.yaml")

    case File.read(spec_path) do
      {:ok, content} ->
        conn
        |> put_resp_content_type("application/x-yaml")
        |> put_resp_header("access-control-allow-origin", "*")
        |> send_resp(200, content)

      {:error, _reason} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "OpenAPI specification not found"})
    end
  end

  @doc """
  Serve the OpenAPI specification as JSON.

  GET /api/docs/openapi.json
  """
  def spec_json(conn, _params) do
    spec_path = Application.app_dir(:tamandua_server, "priv/static/openapi.yaml")

    case File.read(spec_path) do
      {:ok, yaml_content} ->
        # Parse YAML and convert to JSON
        case YamlElixir.read_from_string(yaml_content) do
          {:ok, parsed} ->
            conn
            |> put_resp_content_type("application/json")
            |> put_resp_header("access-control-allow-origin", "*")
            |> json(parsed)

          {:error, _} ->
            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "Failed to parse OpenAPI specification"})
        end

      {:error, _reason} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "OpenAPI specification not found"})
    end
  rescue
    # If YamlElixir is not available, return a friendly error
    UndefinedFunctionError ->
      conn
      |> put_status(:not_implemented)
      |> json(%{error: "JSON format not available. Use /api/docs/openapi.yaml instead."})
  end

  @doc """
  Serve the ReDoc documentation page.

  GET /api/docs/redoc
  """
  def redoc(conn, _params) do
    html = redoc_html()

    conn
    |> put_resp_content_type("text/html")
    |> send_resp(200, html)
  end

  # Generate Swagger UI HTML
  defp swagger_ui_html do
    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Tamandua EDR API Documentation</title>
      <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
      <link rel="icon" type="image/png" href="https://unpkg.com/swagger-ui-dist@5/favicon-32x32.png" sizes="32x32">
      <style>
        html {
          box-sizing: border-box;
          overflow: -moz-scrollbars-vertical;
          overflow-y: scroll;
        }
        *,
        *:before,
        *:after {
          box-sizing: inherit;
        }
        body {
          margin: 0;
          background: #fafafa;
        }
        .topbar {
          background-color: #1a1a2e !important;
        }
        .topbar-wrapper img {
          content: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 30"><text x="0" y="22" fill="white" font-size="18" font-family="system-ui">Tamandua EDR</text></svg>');
        }
        .swagger-ui .info .title {
          color: #1a1a2e;
        }
        .swagger-ui .opblock.opblock-get .opblock-summary-method {
          background: #61affe;
        }
        .swagger-ui .opblock.opblock-post .opblock-summary-method {
          background: #49cc90;
        }
        .swagger-ui .opblock.opblock-put .opblock-summary-method {
          background: #fca130;
        }
        .swagger-ui .opblock.opblock-delete .opblock-summary-method {
          background: #f93e3e;
        }
        .swagger-ui .opblock.opblock-patch .opblock-summary-method {
          background: #50e3c2;
        }
        /* Custom header banner */
        .api-header {
          background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
          color: white;
          padding: 20px;
          text-align: center;
          margin-bottom: 0;
        }
        .api-header h1 {
          margin: 0 0 10px 0;
          font-size: 28px;
          font-weight: 600;
        }
        .api-header p {
          margin: 0;
          opacity: 0.8;
          font-size: 14px;
        }
        .api-header .links {
          margin-top: 15px;
        }
        .api-header .links a {
          color: #61affe;
          text-decoration: none;
          margin: 0 15px;
          font-size: 13px;
        }
        .api-header .links a:hover {
          text-decoration: underline;
        }
      </style>
    </head>
    <body>
      <div class="api-header">
        <h1>Tamandua EDR API</h1>
        <p>Endpoint Detection and Response Platform API Documentation</p>
        <div class="links">
          <a href="/api/docs/openapi.yaml" target="_blank">Download OpenAPI Spec (YAML)</a>
          <a href="/api/docs/redoc">View in ReDoc</a>
          <a href="https://docs.treantlab.org" target="_blank">Full Documentation</a>
        </div>
      </div>
      <div id="swagger-ui"></div>
      <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
      <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
      <script>
        window.onload = function() {
          window.ui = SwaggerUIBundle({
            url: "/api/docs/openapi.yaml",
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
              SwaggerUIBundle.presets.apis,
              SwaggerUIStandalonePreset
            ],
            plugins: [
              SwaggerUIBundle.plugins.DownloadUrl
            ],
            layout: "StandaloneLayout",
            persistAuthorization: true,
            tagsSorter: "alpha",
            operationsSorter: "alpha",
            docExpansion: "list",
            filter: true,
            showExtensions: true,
            showCommonExtensions: true,
            syntaxHighlight: {
              activate: true,
              theme: "nord"
            },
            requestInterceptor: function(request) {
              // Add any default headers here if needed
              return request;
            }
          });
        };
      </script>
    </body>
    </html>
    """
  end

  # Generate ReDoc HTML
  defp redoc_html do
    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Tamandua EDR API Documentation - ReDoc</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono&display=swap" rel="stylesheet">
      <style>
        body {
          margin: 0;
          padding: 0;
        }
        /* Custom ReDoc theming */
        .menu-content {
          background-color: #1a1a2e !important;
        }
        .api-header {
          background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
          color: white;
          padding: 15px 20px;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .api-header h1 {
          margin: 0;
          font-size: 20px;
          font-weight: 600;
          font-family: Inter, system-ui, sans-serif;
        }
        .api-header .links a {
          color: #61affe;
          text-decoration: none;
          margin-left: 20px;
          font-size: 13px;
          font-family: Inter, system-ui, sans-serif;
        }
        .api-header .links a:hover {
          text-decoration: underline;
        }
      </style>
    </head>
    <body>
      <div class="api-header">
        <h1>Tamandua EDR API</h1>
        <div class="links">
          <a href="/api/docs">Swagger UI</a>
          <a href="/api/docs/openapi.yaml" target="_blank">Download Spec</a>
        </div>
      </div>
      <redoc spec-url="/api/docs/openapi.yaml"
             hide-hostname="true"
             theme='{
               "colors": {
                 "primary": { "main": "#1a1a2e" },
                 "success": { "main": "#49cc90" },
                 "warning": { "main": "#fca130" },
                 "error": { "main": "#f93e3e" },
                 "text": { "primary": "#1a1a2e" }
               },
               "typography": {
                 "fontSize": "15px",
                 "fontFamily": "Inter, system-ui, -apple-system, sans-serif",
                 "headings": { "fontFamily": "Inter, system-ui, -apple-system, sans-serif" },
                 "code": { "fontFamily": "JetBrains Mono, Consolas, monospace" }
               },
               "sidebar": {
                 "backgroundColor": "#1a1a2e",
                 "textColor": "#ffffff"
               },
               "rightPanel": {
                 "backgroundColor": "#263238"
               }
             }'>
      </redoc>
      <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
    </body>
    </html>
    """
  end
end
