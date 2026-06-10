defmodule TamanduaServerWeb.Plugs.SecurityHeaders do
  @moduledoc """
  Plug that adds comprehensive security headers to responses.

  ## Headers Added

  - **Content-Security-Policy (CSP)**: Restricts resource loading to prevent XSS attacks
  - **X-Frame-Options**: Prevents clickjacking by disallowing iframe embedding
  - **X-Content-Type-Options**: Prevents MIME-sniffing attacks
  - **X-XSS-Protection**: Legacy XSS protection for older browsers
  - **Referrer-Policy**: Controls referrer information leakage
  - **Permissions-Policy**: Restricts browser features (camera, mic, etc.)
  - **Strict-Transport-Security**: Enforces HTTPS (production only)

  ## Usage

  Add to your router pipeline:

      pipeline :browser do
        plug TamanduaServerWeb.Plugs.SecurityHeaders
      end

  ## Configuration

  CSP can be customized via application config:

      config :tamandua_server, TamanduaServerWeb.Plugs.SecurityHeaders,
        csp_report_uri: "/api/v1/csp-report",
        csp_report_only: false
  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    env = Application.get_env(:tamandua_server, :env, :prod)

    conn
    |> put_csp_header(env)
    |> put_frame_options()
    |> put_content_type_options()
    |> put_xss_protection()
    |> put_referrer_policy()
    |> put_permissions_policy()
    |> maybe_put_hsts(env)
  end

  # Content-Security-Policy
  # Restricts where resources can be loaded from to prevent XSS
  defp put_csp_header(conn, env) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    report_uri = Keyword.get(config, :csp_report_uri)
    report_only = Keyword.get(config, :csp_report_only, false)

    # Base CSP policy
    # - default-src 'self': Only allow resources from same origin
    # - script-src: Allow inline scripts (needed for React/Inertia hydration)
    # - style-src: Allow inline styles (for UI components)
    # - img-src: Allow data URIs for embedded images
    # - connect-src: Allow WebSocket and API connections
    # - font-src: Allow Google Fonts (optional)
    # - frame-ancestors 'none': Prevent embedding in iframes
    csp_directives = [
      "default-src 'self'",
      script_src_directive(env),
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "img-src 'self' data: https: blob:",
      connect_src_directive(env),
      "font-src 'self' https://fonts.gstatic.com",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'"
    ]

    # Add report-uri if configured
    csp_directives =
      if report_uri do
        csp_directives ++ ["report-uri #{report_uri}"]
      else
        csp_directives
      end

    csp_value = Enum.join(csp_directives, "; ")

    header_name =
      if report_only do
        "content-security-policy-report-only"
      else
        "content-security-policy"
      end

    put_resp_header(conn, header_name, csp_value)
  end

  # In development, allow eval for HMR; in production, be strict
  defp script_src_directive(:dev) do
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
  end

  defp script_src_directive(_env) do
    # Production: Allow inline for React hydration, but no eval
    # Consider using nonces for stricter CSP in future
    "script-src 'self' 'unsafe-inline'"
  end

  # Allow WebSocket connections to same origin and configured URLs
  defp connect_src_directive(:dev) do
    # Dev allows localhost connections for HMR
    "connect-src 'self' ws://localhost:* wss://localhost:* http://localhost:* https://localhost:*"
  end

  defp connect_src_directive(_env) do
    # Production: Only same-origin WebSocket and HTTPS
    "connect-src 'self' wss:"
  end

  # X-Frame-Options: DENY
  # Prevents the page from being embedded in iframes (clickjacking protection)
  # Superseded by CSP frame-ancestors but still needed for older browsers
  defp put_frame_options(conn) do
    put_resp_header(conn, "x-frame-options", "DENY")
  end

  # X-Content-Type-Options: nosniff
  # Prevents browsers from MIME-sniffing a response away from declared content-type
  defp put_content_type_options(conn) do
    put_resp_header(conn, "x-content-type-options", "nosniff")
  end

  # X-XSS-Protection: 1; mode=block
  # Legacy XSS protection for older browsers (IE, older Chrome)
  # Modern browsers have this built-in, but it doesn't hurt
  defp put_xss_protection(conn) do
    put_resp_header(conn, "x-xss-protection", "1; mode=block")
  end

  # Referrer-Policy: strict-origin-when-cross-origin
  # Controls how much referrer information is sent with requests
  defp put_referrer_policy(conn) do
    put_resp_header(conn, "referrer-policy", "strict-origin-when-cross-origin")
  end

  # Permissions-Policy (formerly Feature-Policy)
  # Restricts which browser features the page can use
  defp put_permissions_policy(conn) do
    policy = [
      "camera=()",           # Disable camera access
      "microphone=()",       # Disable microphone access
      "geolocation=()",      # Disable geolocation
      "payment=()",          # Disable payment APIs
      "usb=()",              # Disable USB access
      "accelerometer=()",    # Disable accelerometer
      "gyroscope=()",        # Disable gyroscope
      "magnetometer=()"      # Disable magnetometer
    ]

    put_resp_header(conn, "permissions-policy", Enum.join(policy, ", "))
  end

  # Strict-Transport-Security (HSTS)
  # Forces HTTPS connections. Only added in production.
  defp maybe_put_hsts(conn, :prod) do
    # max-age=31536000 (1 year)
    # includeSubDomains: Apply to all subdomains
    # preload: Allow inclusion in browser preload lists
    put_resp_header(
      conn,
      "strict-transport-security",
      "max-age=31536000; includeSubDomains; preload"
    )
  end

  defp maybe_put_hsts(conn, _env), do: conn
end
