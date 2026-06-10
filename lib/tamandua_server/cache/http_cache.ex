defmodule TamanduaServer.Cache.HTTPCache do
  @moduledoc """
  HTTP caching utilities for ETags, Last-Modified, and Cache-Control headers.

  Implements RFC 7232 (Conditional Requests) and RFC 7234 (HTTP Caching).

  ## Features

  - ETag generation (MD5-based content hashing)
  - Last-Modified timestamp tracking
  - Cache-Control header generation
  - Conditional request validation (If-None-Match, If-Modified-Since)
  - Vary header support
  - Private/public cache control

  ## Usage in Controllers

      # Basic ETag support
      def show(conn, %{"id" => id}) do
        alert = Alerts.get_alert!(id)
        etag = HTTPCache.generate_etag(alert)

        case HTTPCache.validate_conditional_request(conn, etag) do
          :not_modified ->
            conn
            |> put_resp_header("etag", etag)
            |> send_resp(304, "")

          :proceed ->
            conn
            |> put_resp_header("etag", etag)
            |> put_cache_control(:public, max_age: 300)
            |> json(alert)
        end
      end

      # With Last-Modified
      def index(conn, _params) do
        alerts = Alerts.list_alerts()
        last_modified = HTTPCache.get_last_modified(alerts)

        case HTTPCache.validate_if_modified_since(conn, last_modified) do
          :not_modified ->
            send_resp(conn, 304, "")

          :proceed ->
            conn
            |> put_resp_header("last-modified", HTTPCache.format_http_date(last_modified))
            |> json(alerts)
        end
      end
  """

  import Plug.Conn

  @doc """
  Generates an ETag from content.
  Uses MD5 hash wrapped in quotes for HTTP header format.
  """
  def generate_etag(content) when is_binary(content) do
    hash =
      :crypto.hash(:md5, content)
      |> Base.encode16(case: :lower)

    ~s("#{hash}")
  end

  def generate_etag(content) do
    content
    |> Jason.encode!()
    |> generate_etag()
  end

  @doc """
  Generates a weak ETag (prefixed with W/).
  Useful for dynamically generated content that may vary slightly.
  """
  def generate_weak_etag(content) do
    "W/" <> generate_etag(content)
  end

  @doc """
  Validates a conditional request using If-None-Match header.
  Returns `:not_modified` if ETag matches, `:proceed` otherwise.
  """
  def validate_conditional_request(conn, etag) do
    case get_req_header(conn, "if-none-match") do
      [client_etag | _] when client_etag == etag ->
        :not_modified

      [client_etags | _] ->
        # Handle multiple ETags (rare but valid)
        etags = String.split(client_etags, ",") |> Enum.map(&String.trim/1)

        if etag in etags do
          :not_modified
        else
          :proceed
        end

      [] ->
        :proceed
    end
  end

  @doc """
  Validates If-Modified-Since header.
  Returns `:not_modified` if resource hasn't been modified, `:proceed` otherwise.
  """
  def validate_if_modified_since(conn, last_modified) when is_struct(last_modified, DateTime) do
    case get_req_header(conn, "if-modified-since") do
      [if_modified_since | _] ->
        case parse_http_date(if_modified_since) do
          {:ok, client_date} ->
            if DateTime.compare(last_modified, client_date) == :gt do
              :proceed
            else
              :not_modified
            end

          {:error, _} ->
            :proceed
        end

      [] ->
        :proceed
    end
  end

  def validate_if_modified_since(conn, last_modified) when is_struct(last_modified, NaiveDateTime) do
    validate_if_modified_since(conn, DateTime.from_naive!(last_modified, "Etc/UTC"))
  end

  @doc """
  Gets the most recent updated_at timestamp from a list of records.
  """
  def get_last_modified(records) when is_list(records) do
    records
    |> Enum.map(& &1.updated_at)
    |> Enum.max(DateTime, fn -> DateTime.utc_now() end)
  end

  def get_last_modified(%{updated_at: updated_at}), do: updated_at
  def get_last_modified(_), do: DateTime.utc_now()

  @doc """
  Formats a DateTime as an HTTP date string (RFC 7231 format).

  ## Examples

      iex> dt = ~U[2024-01-01 12:00:00Z]
      iex> HTTPCache.format_http_date(dt)
      "Mon, 01 Jan 2024 12:00:00 GMT"
  """
  def format_http_date(datetime) when is_struct(datetime, DateTime) do
    datetime
    |> Calendar.strftime("%a, %d %b %Y %H:%M:%S GMT")
  end

  def format_http_date(naive_datetime) when is_struct(naive_datetime, NaiveDateTime) do
    naive_datetime
    |> DateTime.from_naive!("Etc/UTC")
    |> format_http_date()
  end

  @doc """
  Parses an HTTP date string into a DateTime.
  """
  def parse_http_date(date_string) when is_binary(date_string) do
    # Support multiple date formats (RFC 7231, RFC 850, ANSI C)
    formats = [
      "{WDshort}, {0D} {Mshort} {YYYY} {h24}:{m}:{s} GMT",
      "{WDfull}, {0D}-{Mshort}-{YY} {h24}:{m}:{s} GMT",
      "{WDshort} {Mshort} {D} {h24}:{m}:{s} {YYYY}"
    ]

    Enum.find_value(formats, fn format ->
      case Timex.parse(date_string, format) do
        {:ok, datetime} -> {:ok, datetime}
        {:error, _} -> nil
      end
    end) || {:error, :invalid_date}
  end

  @doc """
  Adds Cache-Control header to a connection.

  ## Options

  - `:public` - Cache can be stored by any cache (default: false)
  - `:private` - Cache only for single user
  - `:no_cache` - Must revalidate with origin server
  - `:no_store` - Don't cache at all
  - `:max_age` - Maximum age in seconds
  - `:s_maxage` - Shared cache max age
  - `:must_revalidate` - Must check with origin when stale

  ## Examples

      conn
      |> put_cache_control(:public, max_age: 300)

      conn
      |> put_cache_control(:private, no_store: true)
  """
  def put_cache_control(conn, type, opts \\ []) do
    directives =
      [cache_type(type) | build_directives(opts)]
      |> Enum.filter(& &1)
      |> Enum.join(", ")

    put_resp_header(conn, "cache-control", directives)
  end

  @doc """
  Adds Vary header to indicate response varies by specific headers.

  ## Examples

      conn |> put_vary(["Accept-Encoding", "Authorization"])
  """
  def put_vary(conn, headers) when is_list(headers) do
    vary = Enum.join(headers, ", ")
    put_resp_header(conn, "vary", vary)
  end

  def put_vary(conn, header) when is_binary(header) do
    put_resp_header(conn, "vary", header)
  end

  @doc """
  Disables all caching (useful for sensitive data).
  """
  def disable_cache(conn) do
    conn
    |> put_resp_header("cache-control", "no-store, no-cache, must-revalidate, private")
    |> put_resp_header("pragma", "no-cache")
    |> put_resp_header("expires", "0")
  end

  @doc """
  Standard cache configuration for API responses.
  """
  def cache_api_response(conn, opts \\ []) do
    max_age = Keyword.get(opts, :max_age, 60)
    public = Keyword.get(opts, :public, false)

    conn
    |> put_cache_control(if(public, do: :public, else: :private), max_age: max_age)
    |> put_vary(["Accept", "Authorization"])
  end

  # Private Functions

  defp cache_type(:public), do: "public"
  defp cache_type(:private), do: "private"
  defp cache_type(_), do: "private"

  defp build_directives(opts) do
    [
      build_directive(:no_cache, opts),
      build_directive(:no_store, opts),
      build_directive(:must_revalidate, opts),
      build_max_age(opts),
      build_s_maxage(opts)
    ]
  end

  defp build_directive(key, opts) do
    if Keyword.get(opts, key, false), do: Atom.to_string(key), else: nil
  end

  defp build_max_age(opts) do
    case Keyword.get(opts, :max_age) do
      nil -> nil
      age -> "max-age=#{age}"
    end
  end

  defp build_s_maxage(opts) do
    case Keyword.get(opts, :s_maxage) do
      nil -> nil
      age -> "s-maxage=#{age}"
    end
  end
end
