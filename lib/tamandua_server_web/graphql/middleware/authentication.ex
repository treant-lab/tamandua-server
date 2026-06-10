defmodule TamanduaServerWeb.GraphQL.Middleware.Authentication do
  @moduledoc """
  Middleware for enforcing authentication on GraphQL queries.
  """

  @behaviour Absinthe.Middleware

  @impl true
  def call(resolution, _config) do
    case resolution.context do
      %{current_user_id: user_id} when not is_nil(user_id) ->
        resolution

      _ ->
        resolution
        |> Absinthe.Resolution.put_result({:error, "Authentication required"})
    end
  end
end

defmodule TamanduaServerWeb.GraphQL.Middleware.Authorization do
  @moduledoc """
  Middleware for enforcing authorization on GraphQL operations.
  """

  @behaviour Absinthe.Middleware

  @impl true
  def call(resolution, required_permission) do
    case resolution.context do
      %{current_user_id: user_id} when not is_nil(user_id) ->
        user = TamanduaServer.Accounts.get_user(user_id)

        if user && TamanduaServer.Accounts.user_can?(user, required_permission) do
          resolution
        else
          resolution
          |> Absinthe.Resolution.put_result({:error, "Insufficient permissions"})
        end

      _ ->
        resolution
        |> Absinthe.Resolution.put_result({:error, "Authentication required"})
    end
  end
end
