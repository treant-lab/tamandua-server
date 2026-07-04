defmodule TamanduaServerWeb.GraphQL.UserSocket do
  @moduledoc """
  WebSocket endpoint for GraphQL subscriptions.

  Supports authentication via:
  - Token in connection params: { "token": "jwt_or_session_token" }
  - Token in query string: ?token=jwt_or_session_token
  """

  use Phoenix.Socket, log: false
  use Absinthe.Phoenix.Socket, schema: TamanduaServerWeb.GraphQL.Schema

  alias TamanduaServer.Accounts

  @impl true
  def connect(params, socket, _connect_info) do
    token = params["token"] || params["authToken"]

    case authenticate(token) do
      {:ok, context} ->
        socket = Absinthe.Phoenix.Socket.put_options(socket, context: context)
        {:ok, socket}

      {:error, _reason} ->
        # Allow connection but with empty context (some queries might be public)
        {:ok, socket}
    end
  end

  @impl true
  def id(socket) do
    case socket.assigns[:absinthe][:opts][:context] do
      %{current_user_id: user_id} when not is_nil(user_id) ->
        "graphql_socket:#{user_id}"

      _ ->
        nil
    end
  end

  defp authenticate(nil), do: {:error, :no_token}

  defp authenticate(token) do
    # Try session token first
    case Accounts.get_user_by_session_token(token) do
      nil ->
        # Try JWT
        case TamanduaServer.Guardian.decode_and_verify(token) do
          {:ok, claims} ->
            user_id = claims["sub"]
            user = Accounts.get_user(user_id)

            if user do
              {:ok, %{
                current_user_id: user_id,
                organization_id: user.organization_id,
                auth_method: :jwt
              }}
            else
              {:error, :user_not_found}
            end

          {:error, reason} ->
            {:error, reason}
        end

      user ->
        {:ok, %{
          current_user_id: user.id,
          organization_id: user.organization_id,
          auth_method: :session
        }}
    end
  end
end
