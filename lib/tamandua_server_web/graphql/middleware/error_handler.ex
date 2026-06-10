defmodule TamanduaServerWeb.GraphQL.Middleware.ErrorHandler do
  @moduledoc """
  Middleware for handling and formatting GraphQL errors.
  """

  @behaviour Absinthe.Middleware

  @impl true
  def call(resolution, _config) do
    case resolution.errors do
      [] ->
        resolution

      errors ->
        %{resolution | errors: Enum.map(errors, &format_error/1)}
    end
  end

  defp format_error(%Ecto.Changeset{} = changeset) do
    errors = Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)

    %{
      message: "Validation error",
      extensions: %{
        code: "VALIDATION_ERROR",
        errors: errors
      }
    }
  end

  defp format_error({:error, reason}) when is_binary(reason) do
    %{
      message: reason,
      extensions: %{code: "ERROR"}
    }
  end

  defp format_error({:error, reason}) do
    %{
      message: inspect(reason),
      extensions: %{code: "ERROR"}
    }
  end

  defp format_error(error) when is_binary(error) do
    %{
      message: error,
      extensions: %{code: "ERROR"}
    }
  end

  defp format_error(error) when is_atom(error) do
    message = error
    |> Atom.to_string()
    |> String.replace("_", " ")
    |> String.capitalize()

    %{
      message: message,
      extensions: %{code: Atom.to_string(error) |> String.upcase()}
    }
  end

  defp format_error(%{message: _} = error) do
    error
  end

  defp format_error(error) do
    %{
      message: inspect(error),
      extensions: %{code: "UNKNOWN_ERROR"}
    }
  end
end
