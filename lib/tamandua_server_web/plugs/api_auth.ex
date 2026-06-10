defmodule TamanduaServerWeb.Plugs.APIAuth do
  @moduledoc """
  Authentication plug for API endpoints.

  Supports two authentication methods:
  1. Bearer token (for external API clients)
  2. Session-based authentication (for internal frontend requests)
  """

  import Plug.Conn

  alias TamanduaServer.Accounts

  def init(opts), do: opts

  def call(conn, _opts) do
    # First try Bearer token authentication
    case get_bearer_token(conn) do
      nil ->
        # Fall back to session-based authentication for internal frontend
        case get_session_user(conn) do
          nil ->
            unauthorized(conn, "Missing authorization header or session")

          user ->
            assign_user_context(conn, user)
        end

      token ->
        case verify_token(token) do
          {:ok, user} ->
            assign_user_context(conn, user)

          {:error, reason} ->
            unauthorized(conn, reason)
        end
    end
  end

  defp assign_user_context(conn, user) do
    conn
    |> assign(:current_user, user)
    |> assign(:organization_id, Map.get(user, :organization_id))
    |> assign(:current_organization_id, Map.get(user, :organization_id))
  end

  defp get_bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> token
      _ -> nil
    end
  end

  defp verify_token(token) do
    case Accounts.get_user_by_api_token(token) do
      nil -> verify_cli_or_guardian_token(token)
      user -> {:ok, user}
    end
  end

  defp verify_cli_or_guardian_token(token) do
    case TamanduaServer.CLIAuth.verify_token(token) do
      {:ok, user} -> {:ok, user}
      {:error, _reason} -> verify_guardian_user_token(token)
    end
  end

  defp verify_guardian_user_token(token) do
    with {:ok, claims} <- TamanduaServer.Guardian.decode_and_verify(token),
         user_id when is_binary(user_id) <- claims["sub"],
         user when not is_nil(user) <- Accounts.get_user(user_id) do
      {:ok, user}
    else
      _ -> {:error, "Invalid or expired token"}
    end
  end

  defp get_session_user(conn) do
    # Check if there's an authenticated user in the session
    # This allows the React frontend to make API calls using session auth
    user_token = get_session(conn, :user_token)

    if user_token do
      Accounts.get_user_by_session_token(user_token)
    else
      nil
    end
  end

  defp unauthorized(conn, message) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, Jason.encode!(%{error: message}))
    |> halt()
  end
end
