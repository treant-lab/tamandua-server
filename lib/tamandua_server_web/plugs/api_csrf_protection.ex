defmodule TamanduaServerWeb.Plugs.APICSRFProtection do
  @moduledoc """
  CSRF protection for API endpoints that use session-based authentication.

  When an API request is authenticated via session cookie (not Bearer token),
  this plug validates the CSRF token to prevent cross-site request forgery.

  The CSRF token can be provided via:
  - `X-CSRF-Token` header (preferred)
  - `X-XSRF-TOKEN` header (for compatibility with some JS frameworks)
  - `_csrf_token` parameter in the request body

  This plug should be placed AFTER `APIAuth` in the pipeline so it can check
  if session authentication was used.

  ## Usage

      pipeline :api_with_csrf do
        plug :accepts, ["json"]
        plug :fetch_session
        plug TamanduaServerWeb.Plugs.APIAuth
        plug TamanduaServerWeb.Plugs.APICSRFProtection
      end

  ## Security Notes

  - GET/HEAD/OPTIONS requests are skipped (safe methods)
  - Bearer token authenticated requests are skipped (token is secret)
  - Only session-authenticated requests require CSRF validation
  """

  import Plug.Conn
  require Logger

  @safe_methods ["GET", "HEAD", "OPTIONS"]

  def init(opts), do: opts

  def call(%{method: method} = conn, _opts) when method in @safe_methods do
    # Safe methods don't need CSRF protection
    conn
  end

  def call(conn, _opts) do
    # Check if this is a session-authenticated request (not Bearer token)
    if session_authenticated?(conn) do
      validate_csrf_token(conn)
    else
      # Bearer token auth or unauthenticated - skip CSRF check
      conn
    end
  end

  defp session_authenticated?(conn) do
    # If current_user is set but no Bearer token was used, it's session auth
    has_user = conn.assigns[:current_user] != nil
    has_bearer = has_bearer_token?(conn)

    has_user and not has_bearer
  end

  defp has_bearer_token?(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> _token] -> true
      _ -> false
    end
  end

  defp validate_csrf_token(conn) do
    csrf_token = get_csrf_token_from_request(conn)
    session_token = get_session(conn, "_csrf_token")

    cond do
      is_nil(session_token) ->
        # No session CSRF token - session may not be properly initialized
        Logger.warning("[APICSRFProtection] No CSRF token in session for session-authenticated request")
        csrf_error(conn)

      is_nil(csrf_token) ->
        Logger.warning("[APICSRFProtection] Missing CSRF token in request")
        csrf_error(conn)

      not valid_csrf_token?(session_token, csrf_token) ->
        Logger.warning("[APICSRFProtection] Invalid CSRF token")
        csrf_error(conn)

      true ->
        conn
    end
  end

  defp valid_csrf_token?(session_token, request_token) do
    session_token
    |> Plug.CSRFProtection.dump_state_from_session()
    |> Plug.CSRFProtection.valid_state_and_csrf_token?(request_token)
  end

  defp get_csrf_token_from_request(conn) do
    # Check headers first (preferred)
    case get_req_header(conn, "x-csrf-token") do
      [token | _] -> token
      [] ->
        # Try alternative header name
        case get_req_header(conn, "x-xsrf-token") do
          [token | _] -> token
          [] ->
            # Fall back to body parameter
            conn.body_params["_csrf_token"]
        end
    end
  end

  defp csrf_error(conn) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(403, Jason.encode!(%{
      error: "CSRF token validation failed",
      hint: "Include X-CSRF-Token header with valid token for session-authenticated requests"
    }))
    |> halt()
  end
end
