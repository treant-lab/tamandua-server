defmodule TamanduaServer.AISecurity.KnownGood.HashEntry do
  @moduledoc """
  Ecto schema for known-good model hash entries.

  Stores verified model file SHA-256 hashes that can be trusted without
  performing expensive deep security scans. When a model's hash matches
  an entry in this table, the scanner immediately returns "verified" status.

  ## Fields

    * `:sha256` - The SHA-256 hash of the model file (64 hex characters)
    * `:name` - Human-readable name for the model (e.g., "llama-7b")
    * `:source` - How this entry was created: "custom", "import", or "verified_scan"
    * `:model_type` - Optional model format: "pickle", "gguf", "safetensors", or "onnx"
    * `:notes` - Optional administrator notes
    * `:created_by` - User ID who added this entry
    * `:organization_id` - Tenant ID for multi-tenant support
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_sources ["custom", "import", "verified_scan"]
  @valid_model_types ["pickle", "gguf", "safetensors", "onnx"]
  @sha256_regex ~r/^[a-fA-F0-9]{64}$/

  schema "known_good_hashes" do
    field :sha256, :string
    field :name, :string
    field :source, :string
    field :model_type, :string
    field :notes, :string
    field :created_by, :string
    field :organization_id, :binary_id

    timestamps()
  end

  @required_fields [:sha256, :source]
  @optional_fields [:name, :model_type, :notes, :created_by, :organization_id]

  @doc """
  Creates a changeset for inserting or updating a hash entry.

  ## Validations

    * `:sha256` - Required, must be exactly 64 hexadecimal characters
    * `:source` - Required, must be one of "custom", "import", "verified_scan"
    * `:model_type` - Optional, must be one of "pickle", "gguf", "safetensors", "onnx"

  ## Examples

      iex> changeset(%HashEntry{}, %{sha256: "a" |> String.duplicate(64), source: "custom"})
      #Ecto.Changeset<...>
  """
  @spec changeset(t() | Ecto.Changeset.t(), map()) :: Ecto.Changeset.t()
  def changeset(entry, attrs) do
    entry
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_sha256_format()
    |> validate_inclusion(:source, @valid_sources,
      message: "must be one of: #{Enum.join(@valid_sources, ", ")}"
    )
    |> validate_model_type()
    |> downcase_sha256()
  end

  @type t :: %__MODULE__{
    id: binary() | nil,
    sha256: String.t() | nil,
    name: String.t() | nil,
    source: String.t() | nil,
    model_type: String.t() | nil,
    notes: String.t() | nil,
    created_by: String.t() | nil,
    organization_id: binary() | nil,
    inserted_at: DateTime.t() | nil,
    updated_at: DateTime.t() | nil
  }

  # Private validation helpers

  defp validate_sha256_format(changeset) do
    validate_change(changeset, :sha256, fn :sha256, sha256 ->
      if Regex.match?(@sha256_regex, sha256) do
        []
      else
        [sha256: "must be exactly 64 hexadecimal characters"]
      end
    end)
  end

  defp validate_model_type(changeset) do
    case get_field(changeset, :model_type) do
      nil ->
        changeset

      model_type when model_type in @valid_model_types ->
        changeset

      _invalid ->
        add_error(changeset, :model_type, "must be one of: #{Enum.join(@valid_model_types, ", ")}")
    end
  end

  defp downcase_sha256(changeset) do
    case get_change(changeset, :sha256) do
      nil -> changeset
      sha256 -> put_change(changeset, :sha256, String.downcase(sha256))
    end
  end
end
