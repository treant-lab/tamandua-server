defmodule TamanduaServer.Utils.SafeJSON do
  @moduledoc """
  Safe JSON parsing utilities that prevent crashes on invalid input.

  Use these functions instead of `Jason.decode!/1` when parsing:
  - External webhook payloads
  - User-provided JSON data
  - HTTP responses from external services

  Internal service responses (e.g., ML service) can use `Jason.decode!/1`
  if they're within a try/rescue block or if a crash is acceptable.
  """

  require Logger

  @doc """
  Safely decode JSON, returning {:ok, data} or {:error, reason}.

  This is just an alias for Jason.decode/1 for consistency.
  """
  @spec decode(binary()) :: {:ok, term()} | {:error, Jason.DecodeError.t()}
  def decode(json) when is_binary(json), do: Jason.decode(json)

  @doc """
  Decode JSON or return a default value on error.

  ## Examples

      iex> SafeJSON.decode_or_default("{\"foo\": 1}", %{})
      %{"foo" => 1}

      iex> SafeJSON.decode_or_default("invalid", %{})
      %{}
  """
  @spec decode_or_default(binary(), term()) :: term()
  def decode_or_default(json, default) when is_binary(json) do
    case Jason.decode(json) do
      {:ok, data} -> data
      {:error, _} -> default
    end
  end

  @doc """
  Decode JSON and log a warning on error.

  Returns {:ok, data} or {:error, :invalid_json} with a warning logged.

  ## Options

  - `:context` - Additional context for the log message (e.g., "Slack webhook")
  """
  @spec decode_with_log(binary(), keyword()) :: {:ok, term()} | {:error, :invalid_json}
  def decode_with_log(json, opts \\ []) when is_binary(json) do
    case Jason.decode(json) do
      {:ok, data} ->
        {:ok, data}

      {:error, error} ->
        context = Keyword.get(opts, :context, "JSON parsing")
        Logger.warning("[#{context}] Invalid JSON: #{inspect(error)}")
        {:error, :invalid_json}
    end
  end

  @doc """
  Decode an HTTP response body safely.

  Returns {:ok, decoded} for successful JSON, {:ok, body} for non-JSON 2xx,
  or {:error, reason} for failures.
  """
  @spec decode_http_response({:ok, map()} | {:error, term()}) ::
          {:ok, term()} | {:error, term()}
  def decode_http_response({:ok, %{status_code: status, body: body}})
      when status >= 200 and status < 300 do
    case Jason.decode(body) do
      {:ok, data} -> {:ok, data}
      {:error, _} -> {:ok, body}  # Return raw body if not JSON
    end
  end

  def decode_http_response({:ok, %{status_code: status, body: body}}) do
    # Non-2xx response
    error_data =
      case Jason.decode(body) do
        {:ok, data} -> data
        {:error, _} -> %{"raw" => body}
      end

    {:error, {:http_error, status, error_data}}
  end

  def decode_http_response({:error, reason}) do
    {:error, reason}
  end
end
