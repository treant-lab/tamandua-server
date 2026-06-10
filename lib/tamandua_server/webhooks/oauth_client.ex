defmodule TamanduaServer.Webhooks.OAuthClient do
  @moduledoc """
  OAuth 2.0 client for webhook authentication.

  Implements the Client Credentials Grant flow (RFC 6749 Section 4.4).
  Features:
  - Automatic token refresh
  - Token caching to avoid unnecessary requests
  - Support for various token endpoint formats
  """

  require Logger

  alias TamanduaServer.Webhooks.Webhook
  alias TamanduaServer.Repo

  @doc """
  Gets a valid OAuth 2.0 access token for a webhook.

  Returns cached token if still valid, otherwise fetches a new token.
  """
  def get_access_token(%Webhook{auth_type: "oauth2"} = webhook) do
    if token_valid?(webhook) do
      {:ok, webhook.oauth_token_cache["access_token"]}
    else
      fetch_and_cache_token(webhook)
    end
  end

  def get_access_token(_webhook), do: {:error, :not_oauth2}

  defp token_valid?(%Webhook{oauth_token_cache: nil}), do: false
  defp token_valid?(%Webhook{oauth_token_expires_at: nil}), do: false

  defp token_valid?(%Webhook{oauth_token_expires_at: expires_at}) do
    # Token is valid if it expires more than 60 seconds from now
    buffer_time = DateTime.add(DateTime.utc_now(), 60, :second)
    DateTime.compare(expires_at, buffer_time) == :gt
  end

  defp fetch_and_cache_token(webhook) do
    Logger.info("[OAuthClient] Fetching new access token for webhook #{webhook.id}")

    case request_token(webhook) do
      {:ok, token_response} ->
        cache_token(webhook, token_response)

      {:error, error} ->
        Logger.error("[OAuthClient] Failed to fetch token: #{inspect(error)}")
        {:error, error}
    end
  end

  defp request_token(webhook) do
    body = %{
      grant_type: "client_credentials",
      client_id: webhook.oauth_client_id,
      client_secret: webhook.oauth_client_secret
    }

    body =
      if webhook.oauth_scope do
        Map.put(body, :scope, webhook.oauth_scope)
      else
        body
      end

    headers = [
      {"content-type", "application/x-www-form-urlencoded"},
      {"accept", "application/json"}
    ]

    result =
      Req.post(webhook.oauth_token_url,
        form: body,
        headers: headers,
        receive_timeout: 30_000
      )

    case result do
      {:ok, %Req.Response{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %Req.Response{status: status, body: body}} ->
        {:error, "OAuth token request failed with status #{status}: #{inspect(body)}"}

      {:error, exception} ->
        {:error, Exception.message(exception)}
    end
  end

  defp cache_token(webhook, token_response) do
    access_token = Map.get(token_response, "access_token")
    expires_in = Map.get(token_response, "expires_in", 3600)

    if is_nil(access_token) do
      {:error, "No access_token in OAuth response"}
    else
      expires_at = DateTime.add(DateTime.utc_now(), expires_in, :second)

      webhook
      |> Ecto.Changeset.change(%{
        oauth_token_cache: token_response,
        oauth_token_expires_at: expires_at
      })
      |> Repo.update()

      {:ok, access_token}
    end
  end

  @doc """
  Clears the cached OAuth token for a webhook.

  Useful when token is revoked or needs to be refreshed immediately.
  """
  def clear_token_cache(webhook) do
    webhook
    |> Ecto.Changeset.change(%{
      oauth_token_cache: nil,
      oauth_token_expires_at: nil
    })
    |> Repo.update()
  end
end
