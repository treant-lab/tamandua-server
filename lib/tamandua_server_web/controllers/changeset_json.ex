defmodule TamanduaServerWeb.ChangesetJSON do
  @doc """
  Renders changeset errors.
  """
  def error(%{changeset: changeset}) do
    %{errors: Ecto.Changeset.traverse_errors(changeset, &translate_error/1)}
  end

  defp translate_error({msg, opts}) do
    Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
      opts |> get_error_option(key) |> to_string()
    end)
  end

  defp get_error_option(opts, key) when is_binary(key) do
    case safe_existing_atom(key) do
      nil -> key
      atom_key -> Keyword.get(opts, atom_key, key)
    end
  end

  defp safe_existing_atom(key) do
    String.to_existing_atom(key)
  rescue
    ArgumentError -> nil
  end
end
