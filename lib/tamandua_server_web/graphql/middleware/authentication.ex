defmodule TamanduaServerWeb.GraphQL.Middleware.Authentication do
  @moduledoc """
  Middleware for enforcing authentication on GraphQL queries.
  """

  @behaviour Absinthe.Middleware

  @impl true
  def call(resolution, _config) do
    case resolution.context do
      %{auth_error: _reason} ->
        resolution
        |> Absinthe.Resolution.put_result({:error, "Authentication failed"})

      %{current_user_id: user_id} = context when not is_nil(user_id) ->
        if context[:api_key_present] == true and
             not authorization_guarded?(resolution.middleware) do
          resolution
          |> Absinthe.Resolution.put_result(
            {:error, "API key scope is not configured for this operation"}
          )
        else
          resolution
        end

      _ ->
        resolution
        |> Absinthe.Resolution.put_result({:error, "Authentication required"})
    end
  end

  @doc false
  def authorization_guarded?(middleware) when is_list(middleware) do
    Enum.any?(middleware, fn
      {TamanduaServerWeb.GraphQL.Middleware.Authorization, _permission} -> true
      {TamanduaServerWeb.GraphQL.Middleware.SystemOperatorAuthorization, _permission} -> true
      TamanduaServerWeb.GraphQL.Middleware.Authorization -> true
      TamanduaServerWeb.GraphQL.Middleware.SystemOperatorAuthorization -> true
      {{TamanduaServerWeb.GraphQL.Middleware.Authorization, :call}, _permission} -> true
      {{TamanduaServerWeb.GraphQL.Middleware.SystemOperatorAuthorization, :call}, _permission} ->
        true

      _other -> false
    end)
  end

  def authorization_guarded?(_middleware), do: false
end

defmodule TamanduaServerWeb.GraphQL.Middleware.Authorization do
  @moduledoc """
  Middleware for enforcing authorization on GraphQL operations.
  """

  @behaviour Absinthe.Middleware

  @impl true
  def call(resolution, required_permission) do
    case resolution.context do
      %{auth_error: _reason} ->
        resolution
        |> Absinthe.Resolution.put_result({:error, "Authentication failed"})

      %{current_user_id: user_id} when not is_nil(user_id) ->
        user = TamanduaServer.Accounts.get_user(user_id)

        if user && TamanduaServer.Accounts.user_can?(user, required_permission) &&
             api_key_allows?(resolution.context, required_permission) do
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

  @doc false
  def api_key_allows?(%{api_key_present: true} = context, permission) do
    permission = to_string(permission)

    case context[:api_key_scope] do
      "full" ->
        true

      "read_only" ->
        String.ends_with?(permission, "_read") || String.ends_with?(permission, "_list")

      "custom" ->
        permission in Enum.map(context[:api_key_permissions] || [], &to_string/1)

      _ ->
        permission in Enum.map(context[:api_key_scopes] || [], &to_string/1) ||
          "*" in (context[:api_key_scopes] || [])
    end
  end

  def api_key_allows?(_context, _permission), do: true
end
