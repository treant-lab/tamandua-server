defmodule TamanduaServerWeb.Plugs.CachePlug do
  @moduledoc """
  Plug for automatic HTTP caching with ETag and Last-Modified support.

  Implements conditional requests (RFC 7232) for efficient bandwidth usage
  and reduced server load.

  ## Usage

      # In router or controller
      plug CachePlug, ttl: 300, vary: ["Accept", "Authorization"]

      # In specific action
      defmodule MyController do
        use TamanduaServerWeb, :controller

        plug CachePlug, [ttl: 60] when action in [:index, :show]

        def index(conn, _params) do
          # Response will be cached with ETag
          json(conn, data)
        end
      end

  ## Options

  - `:ttl` - Cache TTL in seconds (default: 0, no caching)
  - `:vary` - List of headers to vary on (default: ["Accept"])
  - `:private` - Private cache (default: false, public)
  - `:enabled` - Enable caching (default: true)
  - `:cache_control` - Custom Cache-Control directives
  """

  import Plug.Conn
  require Logger

  alias TamanduaServer.Cache.HTTPCache

  @default_opts [
    ttl: 0,
    vary: ["Accept"],
    private: false,
    enabled: true
  ]

  def init(opts) do
    Keyword.merge(@default_opts, opts)
  end

  def call(conn, opts) do
    enabled = Keyword.get(opts, :enabled, true)

    if enabled do
      apply_caching(conn, opts)
    else
      conn
    end
  end

  defp apply_caching(conn, opts) do
    ttl = Keyword.get(opts, :ttl)
    private = Keyword.get(opts, :private)
    vary = Keyword.get(opts, :vary)

    conn
    |> register_before_send(fn conn ->
      case conn.status do
        200 ->
          add_cache_headers(conn, ttl, private, vary)

        304 ->
          # Already cached response
          conn

        _ ->
          # Don't cache error responses
          conn
      end
    end)
    |> maybe_handle_conditional_request(opts)
  end

  defp maybe_handle_conditional_request(conn, _opts) do
    # Check if client sent conditional request headers
    if_none_match = get_req_header(conn, "if-none-match")
    if_modified_since = get_req_header(conn, "if-modified-since")

    if if_none_match != [] or if_modified_since != [] do
      # Store conditional request markers for before_send callback
      conn
      |> put_private(:conditional_request, true)
      |> put_private(:if_none_match, if_none_match)
      |> put_private(:if_modified_since, if_modified_since)
    else
      conn
    end
  end

  defp add_cache_headers(conn, ttl, private, vary) do
    conn = HTTPCache.put_vary(conn, vary)

    # Generate ETag from response body
    case conn.resp_body do
      nil ->
        conn

      "" ->
        conn

      body ->
        etag = HTTPCache.generate_etag(body)

        # Check if request was conditional
        if conn.private[:conditional_request] do
          case HTTPCache.validate_conditional_request(conn, etag) do
            :not_modified ->
              Logger.debug("[CachePlug] Returning 304 Not Modified")

              conn
              |> put_resp_header("etag", etag)
              |> send_resp(304, "")
              |> halt()

            :proceed ->
              add_cache_control_and_etag(conn, etag, ttl, private)
          end
        else
          add_cache_control_and_etag(conn, etag, ttl, private)
        end
    end
  end

  defp add_cache_control_and_etag(conn, etag, ttl, private) do
    conn = put_resp_header(conn, "etag", etag)

    if ttl > 0 do
      cache_type = if private, do: :private, else: :public
      HTTPCache.put_cache_control(conn, cache_type, max_age: ttl)
    else
      conn
    end
  end
end
