defmodule TamanduaServerWeb.GraphQL.UserSocket do
  @moduledoc """
  WebSocket endpoint for GraphQL subscriptions.

  Supports authentication via:
  - Token in connection params: { "token": "jwt_or_session_token" }
  - Token in query string: ?token=jwt_or_session_token

  Guardian JWTs must be minted specifically for this socket with
  `aud=tamandua_graphql` and `scope=graphql_socket`. Narrow capability tokens
  (CLI, dashboard socket, live response, agent-bound, or permission-bearing)
  are rejected. This module secures subscription admission only; currently
  only `alert_created` has an Absinthe delivery trigger.
  """

  use Phoenix.Socket, log: false
  use Absinthe.Phoenix.Socket, schema: TamanduaServerWeb.GraphQL.Schema

  alias TamanduaServer.Accounts

  @graphql_audience "tamandua_graphql"
  @graphql_scope "graphql_socket"
  @capability_claims ~w(agent_id session_id command_id permissions capabilities)

  @impl true
  def connect(params, socket, _connect_info) do
    token = params["token"] || params["authToken"]

    case authenticate(token) do
      {:ok, context} ->
        socket = Absinthe.Phoenix.Socket.put_options(socket, context: context)
        {:ok, socket}

      {:error, _reason} ->
        :error
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
            with true <- graphql_claims?(claims),
                 user_id when is_binary(user_id) <- claims["sub"],
                 user when not is_nil(user) <- Accounts.get_user(user_id),
                 true <- active_tenant_user?(user) do
              {:ok,
               %{
                 current_user_id: user_id,
                 organization_id: user.organization_id,
                 auth_method: :graphql_jwt
               }}
            else
              _ -> {:error, :invalid_graphql_token}
            end

          {:error, reason} ->
            {:error, reason}
        end

      user when not is_nil(user) ->
        if active_tenant_user?(user) do
          {:ok,
           %{
             current_user_id: user.id,
             organization_id: user.organization_id,
             auth_method: :session
           }}
        else
          {:error, :inactive_or_unscoped_user}
        end
    end
  end

  @doc false
  def graphql_claims?(claims) when is_map(claims) do
    claims["aud"] == @graphql_audience &&
      claims["scope"] == @graphql_scope &&
      claims["cli"] not in [true, "true"] &&
      Enum.all?(@capability_claims, &(not Map.has_key?(claims, &1)))
  end

  def graphql_claims?(_claims), do: false

  defp active_tenant_user?(%{is_active: true, organization_id: organization_id})
       when not is_nil(organization_id),
       do: true

  defp active_tenant_user?(_user), do: false
end
