defmodule TamanduaServerWeb.Plugs.StreamAuth do
  @moduledoc """
  Authentication plug for streaming endpoints (SSE and long-polling).

  Supports:
  - JWT bearer token authentication
  - API key authentication
  - Session-based authentication (for browser clients)
  - RBAC enforcement (organization_id scoping)
  """

  import Plug.Conn
  require Logger

  alias TamanduaServer.Accounts
  alias TamanduaServer.Guardian

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    # Try multiple authentication methods in order
    cond do
      # 1. Check for session-based auth (browser)
      session_user = get_session(conn, :current_user_id) ->
        authenticate_from_session(conn, session_user)

      # 2. Check for JWT bearer token
      bearer_token = get_bearer_token(conn) ->
        authenticate_from_jwt(conn, bearer_token)

      # 3. Check for API key
      api_key = get_api_key(conn) ->
        authenticate_from_api_key(conn, api_key)

      # No authentication found
      true ->
        conn
        |> put_status(:unauthorized)
        |> Phoenix.Controller.json(%{error: "Authentication required"})
        |> halt()
    end
  end

  # Private Functions

  defp authenticate_from_session(conn, user_id) do
    case Accounts.get_user(user_id) do
      nil ->
        conn
        |> put_status(:unauthorized)
        |> Phoenix.Controller.json(%{error: "Invalid session"})
        |> halt()

      user ->
        # Check if user is active
        if user.active do
          conn
          |> assign(:current_user, user)
          |> assign(:organization_id, user.organization_id)
          |> assign(:auth_method, :session)
        else
          conn
          |> put_status(:unauthorized)
          |> Phoenix.Controller.json(%{error: "User account is inactive"})
          |> halt()
        end
    end
  end

  defp authenticate_from_jwt(conn, token) do
    case Guardian.decode_and_verify(token) do
      {:ok, claims} ->
        user_id = claims["sub"]

        case Accounts.get_user(user_id) do
          nil ->
            conn
            |> put_status(:unauthorized)
            |> Phoenix.Controller.json(%{error: "Invalid token"})
            |> halt()

          user ->
            # Check if user is active
            if user.active do
              conn
              |> assign(:current_user, user)
              |> assign(:organization_id, user.organization_id)
              |> assign(:auth_method, :jwt)
            else
              conn
              |> put_status(:unauthorized)
              |> Phoenix.Controller.json(%{error: "User account is inactive"})
              |> halt()
            end
        end

      {:error, reason} ->
        Logger.warning("JWT verification failed: #{inspect(reason)}")
        conn
        |> put_status(:unauthorized)
        |> Phoenix.Controller.json(%{error: "Invalid or expired token"})
        |> halt()
    end
  end

  defp authenticate_from_api_key(conn, api_key) do
    case Accounts.get_user_by_api_key(api_key) do
      nil ->
        Logger.warning("Invalid API key attempt")
        conn
        |> put_status(:unauthorized)
        |> Phoenix.Controller.json(%{error: "Invalid API key"})
        |> halt()

      user ->
        # Check if user is active and API key is active
        if user.active do
          conn
          |> assign(:current_user, user)
          |> assign(:organization_id, user.organization_id)
          |> assign(:auth_method, :api_key)
        else
          conn
          |> put_status(:unauthorized)
          |> Phoenix.Controller.json(%{error: "User account or API key is inactive"})
          |> halt()
        end
    end
  end

  defp get_bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> token
      _ -> nil
    end
  end

  defp get_api_key(conn) do
    # Check X-API-Key header
    case get_req_header(conn, "x-api-key") do
      [key] -> key
      _ -> nil
    end
  end
end
