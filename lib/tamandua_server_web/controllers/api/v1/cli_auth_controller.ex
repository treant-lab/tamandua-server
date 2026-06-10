defmodule TamanduaServerWeb.API.V1.CLIAuthController do
  @moduledoc """
  Public endpoints for tamandua-ctl browser/device authorization.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.CLIAuth

  def device(conn, params) do
    client_name = Map.get(params, "client_name") || Map.get(params, "client") || "tamandua-ctl"
    scopes = Map.get(params, "scopes") || ["live_response:shell"]

    with {:ok, device} <- CLIAuth.create_device(client_name, scopes) do
      verification_uri = default_server_url(conn) <> "/cli/auth"
      verification_uri_complete = verification_uri <> "?code=" <> URI.encode(device.user_code)

      json(conn, %{
        device_code: device.device_code,
        user_code: device.user_code,
        verification_uri: verification_uri,
        verification_uri_complete: verification_uri_complete,
        expires_at: DateTime.to_iso8601(device.expires_at),
        expires_in: device.expires_in,
        interval: device.interval,
        scopes: device.scopes
      })
    end
  end

  def token(conn, %{"device_code" => device_code}) do
    case CLIAuth.poll(device_code) do
      {:ok, token} ->
        json(conn, token)

      {:error, :authorization_pending} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "authorization_pending"})

      {:error, :expired} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "expired_token"})

      {:error, :already_consumed} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "already_consumed"})

      {:error, :not_found} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_device_code"})
    end
  end

  def token(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "device_code_required"})
  end

  defp default_server_url(conn) do
    forwarded_scheme = forwarded_header(conn, "x-forwarded-proto")
    forwarded_host = forwarded_header(conn, "x-forwarded-host")
    scheme = forwarded_scheme || to_string(conn.scheme)
    host = forwarded_host || conn.host

    cond do
      forwarded_scheme || forwarded_host ->
        "#{scheme}://#{host}"

      String.contains?(host, ":") ->
        "#{scheme}://#{host}"

      (scheme == "http" and conn.port == 80) or (scheme == "https" and conn.port == 443) ->
        "#{scheme}://#{host}"

      true ->
        "#{scheme}://#{host}:#{conn.port}"
    end
  end

  defp forwarded_header(conn, name) do
    conn
    |> get_req_header(name)
    |> List.first()
    |> case do
      nil ->
        nil

      value ->
        value
        |> String.split(",", parts: 2)
        |> List.first()
        |> String.trim()
        |> empty_to_nil()
    end
  end

  defp empty_to_nil(""), do: nil
  defp empty_to_nil(value), do: value
end
