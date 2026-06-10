defmodule TamanduaServer.Registries.ProvenanceEntry do
  @moduledoc """
  Ecto schema for provenance chain entries.

  Represents a single entry in a model's provenance chain, following
  the SLSA (Supply-chain Levels for Software Artifacts) specification.

  ## Fields

  - `event_type` - Type of provenance event
  - `previous_hash` - Hash of previous entry (nil for genesis)
  - `entry_hash` - SHA256 hash of this entry's content
  - `signature` - Ed25519 signature (base64 encoded)
  - `signer_public_key` - Public key used for signing (hex encoded)
  - `subject` - Model being tracked {name, digest, uri}
  - `builder` - Build system info {id, version}
  - `materials` - Input artifacts [{uri, digest}, ...]
  - `metadata` - Additional context

  ## Event Types

  - `training_started` - Training job initiated
  - `dataset_loaded` - Training data loaded
  - `checkpoint_saved` - Model checkpoint created
  - `training_completed` - Training finished
  - `model_converted` - Format conversion
  - `model_published` - Published to registry
  - `model_deployed` - Deployed to production
  - `scan_completed` - Security scan completed

  ## Example

      entry = %ProvenanceEntry{
        event_type: "training_completed",
        entry_hash: "sha256:abc123...",
        subject: %{"name" => "my-model", "digest" => "sha256:..."},
        metadata: %{"accuracy" => 0.95}
      }
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Registries.ModelProvenance

  @valid_event_types ~w(
    training_started
    dataset_loaded
    checkpoint_saved
    training_completed
    model_converted
    model_published
    model_deployed
    scan_completed
  )

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "provenance_entries" do
    field :event_type, :string
    field :previous_hash, :string
    field :entry_hash, :string
    field :signature, :string
    field :signer_public_key, :string
    field :subject, :map
    field :builder, :map, default: %{}
    field :materials, {:array, :map}, default: []
    field :metadata, :map, default: %{}

    belongs_to :model_provenance, ModelProvenance

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @doc """
  Create a changeset for a provenance entry.

  ## Required Fields

  - `event_type` - Must be one of the valid event types
  - `entry_hash` - SHA256 hash of entry content
  - `subject` - Model information map

  ## Optional Fields

  - `previous_hash` - Hash of previous entry (nil for genesis)
  - `signature` - Ed25519 signature
  - `signer_public_key` - Public key for signature verification
  - `builder` - Build system information
  - `materials` - Input artifacts
  - `metadata` - Additional context
  """
  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(entry, attrs) do
    entry
    |> cast(attrs, [
      :event_type,
      :previous_hash,
      :entry_hash,
      :signature,
      :signer_public_key,
      :subject,
      :builder,
      :materials,
      :metadata,
      :model_provenance_id
    ])
    |> validate_required([:event_type, :entry_hash, :subject])
    |> validate_inclusion(:event_type, @valid_event_types)
    |> foreign_key_constraint(:model_provenance_id)
    |> unique_constraint([:model_provenance_id, :previous_hash], name: :provenance_entries_chain_index)
  end

  @doc """
  Returns the list of valid event types.
  """
  @spec valid_event_types() :: [String.t()]
  def valid_event_types, do: @valid_event_types
end
