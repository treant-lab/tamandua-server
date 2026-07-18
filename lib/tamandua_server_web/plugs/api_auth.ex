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

  @doc false
  def normalize_organization_id(value)
  def normalize_organization_id(nil), do: nil

  def normalize_organization_id(value) when is_binary(value) do
    case String.trim(value) do
      "" -> nil
      normalized -> normalized
    end
  end

  def normalize_organization_id(value), do: value

  def call(conn, _opts) do
    # First try Bearer token authentication
    case bearer_credentials(conn) do
      :absent ->
        # Fall back to session-based authentication for internal frontend
        case get_session_user(conn) do
          nil ->
            unauthorized(conn, "Missing authorization header or session")

          {:ok, user, session_ref} ->
            assign_user_context(conn, user, session_ref)
        end

      {:ok, token} ->
        case verify_token(token) do
          {:ok, user} ->
            assign_user_context(conn, user, nil)

          {:error, reason} ->
            unauthorized(conn, reason)
        end

      {:error, reason} ->
        unauthorized(conn, reason)
    end
  end

  defp assign_user_context(conn, user, persistent_session_ref) do
    organization_id = request_organization_id(conn, user)

    conn
    |> assign(:current_user, user)
    |> assign(:organization_id, organization_id)
    |> assign(:current_organization_id, organization_id)
    |> assign(:persistent_session_ref, persistent_session_ref)
  end

  defp request_organization_id(conn, user) do
    user_organization_id =
      user
      |> user_organization_id()
      |> valid_organization_id()

    requested_organization_id =
      conn
      |> get_req_header("x-tenant-id")
      |> List.first()
      |> valid_organization_id()

    cond do
      is_nil(requested_organization_id) -> user_organization_id
      requested_organization_id == user_organization_id -> user_organization_id
      super_admin?(user) -> requested_organization_id
      true -> user_organization_id
    end
  end

  defp valid_organization_id(value) when is_binary(value) do
    value = String.trim(value)

    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> uuid
      :error -> nil
    end
  end

  defp valid_organization_id(_value), do: nil

  defp super_admin?(user) do
    Map.get(user, :role) == "super_admin" or Map.get(user, :is_super_admin) == true
  end

  defp user_organization_id(user) when is_map(user) do
    Map.get(user, :organization_id) || Map.get(user, "organization_id")
  end

  defp user_organization_id(_user), do: nil

  defp bearer_credentials(conn) do
    case get_req_header(conn, "authorization") do
      [] -> :absent
      ["Bearer " <> token] when byte_size(token) > 0 -> {:ok, token}
      _ -> {:error, "Malformed authorization header"}
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
      binding = get_session(conn, :persistent_session_binding)

      if is_binary(binding) do
        case Accounts.get_user_by_persistent_session(user_token, binding) do
          {:ok, user, session_ref} -> {:ok, user, session_ref}
          _ -> nil
        end
      else
        if TamanduaServer.Accounts.PersistentUserSessionStore.enabled?() do
          nil
        else
          case Accounts.get_user_by_session_token(user_token) do
            nil -> nil
            user -> {:ok, user, nil}
          end
        end
      end
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
