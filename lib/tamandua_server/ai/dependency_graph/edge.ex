defmodule TamanduaServer.AI.DependencyGraph.Edge do
  @moduledoc """
  Schema for AI model dependency graph edges.

  Stores relationships between:
  - Processes and models (process loads model)
  - Models and their parent models (fine-tuning/distillation lineage)
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_dependency_types ~w(loads derived_from distilled_from)

  schema "ai_dependency_edges" do
    # Source node (process_id for loads, model_id for derivation)
    field :source_id, :string

    # Target node (model_id being loaded or parent model)
    field :target_id, :string

    # Relationship type
    field :dependency_type, :string

    # Additional attributes (JSON)
    # For :loads - libraries used, loaded_at timestamp
    # For :derived_from - method (fine_tune, lora), dataset
    # For :distilled_from - compression_ratio, teacher_model
    field :attributes, :map, default: %{}

    # Optional: agent_id if this edge came from agent telemetry
    field :agent_id, :binary_id

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(source_id target_id dependency_type)a
  @optional_fields ~w(attributes agent_id)a

  @doc """
  Creates a changeset for a dependency edge.
  """
  @spec changeset(t() | Ecto.Changeset.t(), map()) :: Ecto.Changeset.t()
  def changeset(edge, attrs) do
    edge
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:dependency_type, @valid_dependency_types)
    |> unique_constraint([:source_id, :target_id, :dependency_type],
         name: :ai_dependency_edges_source_target_type_idx)
  end

  @type t :: %__MODULE__{
    id: binary() | nil,
    source_id: String.t() | nil,
    target_id: String.t() | nil,
    dependency_type: String.t() | nil,
    attributes: map(),
    agent_id: binary() | nil,
    inserted_at: DateTime.t() | nil,
    updated_at: DateTime.t() | nil
  }
end
