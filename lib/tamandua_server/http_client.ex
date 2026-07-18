defmodule TamanduaServer.HttpClient do
  @moduledoc """
  Simple HTTP client wrapper using Erlang's :httpc.

  Provides a consistent interface for HTTP requests that can work
  without external dependencies like HTTPoison.
  """

  require Logger

  @default_timeout 30_000
  @default_recv_timeout 30_000

  @doc """
  Make an HTTP GET request.

  ## Options
  - `:timeout` - Connection timeout in ms (default: 30000)
  - `:recv_timeout` - Receive timeout in ms (default: 30000)
  - `:headers` - List of {header_name, header_value} tuples

  ## Returns
  - `{:ok, %{status_code: integer, body: binary, headers: list}}`
  - `{:error, reason}`
  """
  def get(url, headers \\ [], opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    _recv_timeout = Keyword.get(opts, :recv_timeout, @default_recv_timeout)

    request_headers = to_charlist_headers(headers)

    http_opts = [
      timeout: timeout,
      connect_timeout: timeout,
      autoredirect: true,
      ssl: ssl_options()
    ]

    request = {String.to_charlist(url), request_headers}

    case :httpc.request(:get, request, http_opts, body_format: :binary) do
      {:ok, {{_version, status_code, _reason}, resp_headers, body}} ->
        {:ok, %{status_code: status_code, body: body, headers: resp_headers}}

      {:error, reason} ->
        Logger.error("HTTP GET failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Make an HTTP POST request.

  ## Options
  - `:timeout` - Connection timeout in ms (default: 30000)
  - `:recv_timeout` - Receive timeout in ms (default: 30000)

  ## Returns
  - `{:ok, %{status_code: integer, body: binary, headers: list}}`
  - `{:error, reason}`
  """
  def post(url, body, headers \\ [], opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    _recv_timeout = Keyword.get(opts, :recv_timeout, @default_recv_timeout)

    request_headers = to_charlist_headers(headers)
    content_type = get_content_type(headers)

    http_opts = [
      timeout: timeout,
      connect_timeout: timeout,
      autoredirect: true,
      ssl: ssl_options()
    ]

    request = {
      String.to_charlist(url),
      request_headers,
      String.to_charlist(content_type),
      body
    }

    case :httpc.request(:post, request, http_opts, body_format: :binary) do
      {:ok, {{_version, status_code, _reason}, resp_headers, resp_body}} ->
        {:ok, %{status_code: status_code, body: resp_body, headers: resp_headers}}

      {:error, reason} ->
        Logger.error("HTTP POST failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Make an HTTP PUT request.
  """
  def put(url, body, headers \\ [], opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    request_headers = to_charlist_headers(headers)
    content_type = get_content_type(headers)

    http_opts = [
      timeout: timeout,
      connect_timeout: timeout,
      autoredirect: true,
      ssl: ssl_options()
    ]

    request = {
      String.to_charlist(url),
      request_headers,
      String.to_charlist(content_type),
      body
    }

    case :httpc.request(:put, request, http_opts, body_format: :binary) do
      {:ok, {{_version, status_code, _reason}, resp_headers, resp_body}} ->
        {:ok, %{status_code: status_code, body: resp_body, headers: resp_headers}}

      {:error, reason} ->
        Logger.error("HTTP PUT failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Make an HTTP DELETE request.
  """
  def delete(url, headers \\ [], opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    request_headers = to_charlist_headers(headers)

    http_opts = [
      timeout: timeout,
      connect_timeout: timeout,
      autoredirect: true,
      ssl: ssl_options()
    ]

    request = {String.to_charlist(url), request_headers}

    case :httpc.request(:delete, request, http_opts, body_format: :binary) do
      {:ok, {{_version, status_code, _reason}, resp_headers, body}} ->
        {:ok, %{status_code: status_code, body: body, headers: resp_headers}}

      {:error, reason} ->
        Logger.error("HTTP DELETE failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # Private helpers

  defp to_charlist_headers(headers) do
    Enum.map(headers, fn
      {key, value} when is_binary(key) and is_binary(value) ->
        {String.to_charlist(key), String.to_charlist(value)}

      {key, value} when is_list(key) and is_list(value) ->
        {key, value}

      {key, value} ->
        {to_charlist(key), to_charlist(value)}
    end)
  end

  defp get_content_type(headers) do
    headers
    |> Enum.find(fn
      {"Content-Type", _} -> true
      {"content-type", _} -> true
      {key, _} when is_list(key) -> List.to_string(key) |> String.downcase() == "content-type"
      _ -> false
    end)
    |> case do
      {_, value} when is_binary(value) -> value
      {_, value} when is_list(value) -> List.to_string(value)
      nil -> "application/octet-stream"
    end
  end

  defp ssl_options do
    [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      depth: 3,
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ]
    ]
  rescue
    # Fallback if cacerts_get is not available
    _ -> [verify: :verify_none]
  end
end
