defmodule TamanduaServerWeb.AtomHelpers do
  @moduledoc """
  Safe atom conversion helpers for controller parameters.

  These functions protect against:
  - ArgumentError from `String.to_existing_atom/1` on unknown strings (500 errors)
  - Atom table exhaustion from `String.to_atom/1` on user-controlled input (DoS)

  All functions validate input against an allowlist before conversion, or use
  try/rescue as a safety net when an allowlist is not practical.
  """

  @doc """
  Safely converts a binary string to an existing atom, only if the string is
  in the provided list of allowed values.

  Returns the atom if the string is in the allowlist and the atom exists,
  otherwise returns `nil`.

  ## Examples

      iex> safe_to_existing_atom("active", ~w(active inactive))
      :active

      iex> safe_to_existing_atom("malicious_input", ~w(active inactive))
      nil

      iex> safe_to_existing_atom(nil, ~w(active inactive))
      nil
  """
  @spec safe_to_existing_atom(binary() | nil, list(binary())) :: atom() | nil
  def safe_to_existing_atom(nil, _allowed), do: nil
  def safe_to_existing_atom(str, allowed) when is_binary(str) and is_list(allowed) do
    if str in allowed do
      String.to_existing_atom(str)
    else
      nil
    end
  rescue
    ArgumentError -> nil
  end
  def safe_to_existing_atom(_str, _allowed), do: nil

  @doc """
  Safely converts a binary string to an existing atom without an allowlist.

  This is a fallback for cases where the full set of valid values is not known
  at compile time (e.g., dynamically registered atoms). Wraps the conversion
  in a try/rescue to prevent 500 errors.

  Prefer `safe_to_existing_atom/2` with an allowlist when possible.

  Returns the atom if it already exists in the atom table, otherwise `nil`.

  ## Examples

      iex> safe_to_existing_atom_unguarded("ok")
      :ok

      iex> safe_to_existing_atom_unguarded("never_existed_as_atom_xyz")
      nil
  """
  @spec safe_to_existing_atom_unguarded(binary() | nil) :: atom() | nil
  def safe_to_existing_atom_unguarded(nil), do: nil
  def safe_to_existing_atom_unguarded(str) when is_binary(str) do
    String.to_existing_atom(str)
  rescue
    ArgumentError -> nil
  end
  def safe_to_existing_atom_unguarded(_), do: nil

  @doc """
  Safely atomizes map keys, converting only keys that already exist as atoms.

  Keys that cannot be converted are kept as strings. This prevents atom table
  exhaustion from user-controlled map keys.

  ## Options
  - `allowed_keys` - If provided, only these string keys will be converted
    to atoms. All other keys are kept as strings.

  ## Examples

      iex> safe_atomize_keys(%{"name" => "foo", "evil_key" => "bar"}, allowed_keys: ~w(name))
      %{name: "foo", "evil_key" => "bar"}

      iex> safe_atomize_keys(%{"name" => "foo", "status" => "ok"})
      %{name: "foo", status: "ok"}  # only if :name and :status already exist
  """
  @spec safe_atomize_keys(map(), keyword()) :: map()
  def safe_atomize_keys(map, opts \\ []) when is_map(map) do
    allowed = Keyword.get(opts, :allowed_keys)

    Map.new(map, fn {k, v} ->
      key = cond do
        not is_binary(k) -> k
        is_list(allowed) and k in allowed -> String.to_existing_atom(k)
        is_nil(allowed) -> safe_to_existing_atom_unguarded(k) || k
        true -> k
      end
      {key, v}
    end)
  rescue
    ArgumentError -> map
  end
end
