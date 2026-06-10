defmodule TamanduaServer.Connectors.Helpers.Auth do
  @moduledoc """
  Authentication helpers for connectors.

  Supports:
  - API Key authentication
  - OAuth 2.0 flows
  - mTLS certificate management
  - Bearer token handling
  """

  @doc """
  Build Authorization header for API key authentication.

  ## Examples:
      build_api_key_header("my-secret-key")
      # => {"Authorization", "Bearer my-secret-key"}

      build_api_key_header("key123", prefix: "ApiKey")
      # => {"Authorization", "ApiKey key123"}
  """
  def build_api_key_header(api_key, opts \\ []) do
    prefix = Keyword.get(opts, :prefix, "Bearer")
    {"Authorization", "#{prefix} #{api_key}"}
  end

  @doc """
  Build Basic Auth header.

  ## Example:
      build_basic_auth("user", "pass")
      # => {"Authorization", "Basic dXNlcjpwYXNz"}
  """
  def build_basic_auth(username, password) do
    credentials = Base.encode64("#{username}:#{password}")
    {"Authorization", "Basic #{credentials}"}
  end

  @doc """
  OAuth 2.0 client credentials flow.

  Exchanges client_id and client_secret for access token.
  """
  def oauth_client_credentials(token_url, client_id, client_secret, opts \\ []) do
    scope = Keyword.get(opts, :scope, "")

    body = URI.encode_query(%{
      grant_type: "client_credentials",
      client_id: client_id,
      client_secret: client_secret,
      scope: scope
    })

    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case Req.post(token_url, body: body, headers: headers) do
      {:ok, %{status: 200, body: response}} ->
        {:ok, %{
          access_token: response["access_token"],
          token_type: response["token_type"] || "Bearer",
          expires_in: response["expires_in"],
          expires_at: calculate_expiry(response["expires_in"])
        }}

      {:ok, %{status: status, body: body}} ->
        {:error, {:oauth_failed, status, body}}

      {:error, exception} ->
        {:error, {:request_failed, Exception.message(exception)}}
    end
  end

  @doc """
  Check if OAuth token is expired or expiring soon.
  """
  def token_expired?(token_info, buffer_seconds \\ 300) do
    case token_info[:expires_at] do
      nil -> false
      expires_at ->
        DateTime.diff(expires_at, DateTime.utc_now()) < buffer_seconds
    end
  end

  @doc """
  Refresh OAuth token if needed.

  Checks expiry and refreshes if within buffer window.
  """
  def ensure_valid_token(current_token, refresh_fn) do
    if token_expired?(current_token) do
      refresh_fn.()
    else
      {:ok, current_token}
    end
  end

  defp calculate_expiry(nil), do: nil
  defp calculate_expiry(expires_in) when is_integer(expires_in) do
    DateTime.utc_now() |> DateTime.add(expires_in, :second)
  end
end
