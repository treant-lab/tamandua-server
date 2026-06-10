defmodule TamanduaServer.MlRules.HttpClient do
  @moduledoc """
  HTTP client for ML service communication.
  """

  require Logger

  alias TamanduaServer.HttpClient

  def post(url, payload) do
    headers = [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    body = Jason.encode!(payload)

    case HttpClient.post(url, body, headers, timeout: 60_000, recv_timeout: 60_000) do
      {:ok, %{status_code: status, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, decoded} ->
            {:ok, %{status: status, body: decoded}}

          {:error, _} ->
            {:ok, %{status: status, body: %{"detail" => response_body}}}
        end

      {:error, reason} ->
        Logger.error("HTTP request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  def get(url) do
    headers = [
      {"Accept", "application/json"}
    ]

    case HttpClient.get(url, headers, timeout: 30_000, recv_timeout: 30_000) do
      {:ok, %{status_code: status, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, decoded} ->
            {:ok, %{status: status, body: decoded}}

          {:error, _} ->
            {:ok, %{status: status, body: %{"detail" => response_body}}}
        end

      {:error, reason} ->
        Logger.error("HTTP request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end
end
