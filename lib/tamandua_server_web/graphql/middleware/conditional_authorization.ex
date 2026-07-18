defmodule TamanduaServerWeb.GraphQL.Middleware.ConditionalAuthorization do
  @moduledoc """
  Requires a permission only when a nested GraphQL argument is present.

  Authorization is delegated to the standard GraphQL authorization middleware,
  so user RBAC and API-key permission narrowing remain an intersection.
  """

  @behaviour Absinthe.Middleware

  alias TamanduaServerWeb.GraphQL.Middleware.Authorization

  @impl true
  def call(resolution, {permission, argument_path}) when is_list(argument_path) do
    if argument_present?(resolution.arguments, argument_path) do
      Authorization.call(resolution, permission)
    else
      resolution
    end
  end

  @doc false
  def argument_present?(arguments, argument_path)
      when is_map(arguments) and is_list(argument_path) do
    argument_path_present?(arguments, argument_path)
  end

  defp argument_path_present?(arguments, [key]) when is_map(arguments) do
    case Map.fetch(arguments, key) do
      {:ok, []} -> false
      {:ok, _value} -> true
      :error -> false
    end
  end

  defp argument_path_present?(arguments, [key | rest]) when is_map(arguments) do
    case Map.fetch(arguments, key) do
      {:ok, nested} -> argument_path_present?(nested, rest)
      :error -> false
    end
  end

  defp argument_path_present?(_arguments, _path), do: false
end
