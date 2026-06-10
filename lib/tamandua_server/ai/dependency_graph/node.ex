defmodule TamanduaServer.AI.DependencyGraph.Node do
  @moduledoc """
  Schema for AI model dependency graph nodes.

  Stores metadata about nodes in the dependency graph:
  - Process nodes (processes that load AI models)
  - Model nodes (AI/ML model files)
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_node_types ~w(process model)

  schema "ai_dependency_nodes" do
    # Node identifier (process_id or model_id)
    field :node_id, :string

    # Node type
    field :node_type, :string

    # Additional metadata (JSON)
    # For processes: agent_id, hostname, process_name, path
    # For models: format, architecture, parameters, hash
    field :metadata, :map, default: %{}

    # Risk score (0.0 to 1.0)
    field :risk_score, :float, default: 0.0

    # Optional: last seen timestamp
    field :last_seen_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(node_id node_type)a
  @optional_fields ~w(metadata risk_score last_seen_at)a

  @doc """
  Creates a changeset for a dependency node.
  """
  @spec changeset(t() | Ecto.Changeset.t(), map()) :: Ecto.Changeset.t()
  def changeset(node, attrs) do
    node
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:node_type, @valid_node_types)
    |> validate_number(:risk_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> unique_constraint(:node_id, name: :ai_dependency_nodes_node_id_idx)
  end

  @type t :: %__MODULE__{
    id: binary() | nil,
    node_id: String.t() | nil,
    node_type: String.t() | nil,
    metadata: map(),
    risk_score: float(),
    last_seen_at: DateTime.t() | nil,
    inserted_at: DateTime.t() | nil,
    updated_at: DateTime.t() | nil
  }
end
