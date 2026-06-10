defmodule TamanduaServer.Repo.Migrations.CreateAIDependencyGraphTables do
  @moduledoc """
  Creates tables for AI model dependency graph storage.

  The dependency graph tracks:
  - Which processes load which AI models
  - Model lineage (fine-tuning and distillation relationships)

  This enables:
  - Supply chain risk analysis
  - Impact assessment when a base model is compromised
  - Critical model identification (single points of failure)
  """

  use Ecto.Migration

  def change do
    # Nodes table - processes and models in the graph
    create table(:ai_dependency_nodes, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :node_id, :string, null: false
      add :node_type, :string, null: false
      add :metadata, :map, default: %{}
      add :risk_score, :float, default: 0.0
      add :last_seen_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:ai_dependency_nodes, [:node_id], name: :ai_dependency_nodes_node_id_idx)
    create index(:ai_dependency_nodes, [:node_type])
    create index(:ai_dependency_nodes, [:risk_score])

    # Edges table - relationships between nodes
    create table(:ai_dependency_edges, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :source_id, :string, null: false
      add :target_id, :string, null: false
      add :dependency_type, :string, null: false
      add :attributes, :map, default: %{}
      add :agent_id, :binary_id

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:ai_dependency_edges, [:source_id, :target_id, :dependency_type],
             name: :ai_dependency_edges_source_target_type_idx)
    create index(:ai_dependency_edges, [:source_id])
    create index(:ai_dependency_edges, [:target_id])
    create index(:ai_dependency_edges, [:dependency_type])
    create index(:ai_dependency_edges, [:agent_id])

    # Create a partial index for quick lookups of :loads relationships
    execute(
      "CREATE INDEX ai_dependency_edges_loads_idx ON ai_dependency_edges (source_id, target_id) WHERE dependency_type = 'loads'",
      "DROP INDEX IF EXISTS ai_dependency_edges_loads_idx"
    )

    # Create a partial index for derivation relationships
    execute(
      "CREATE INDEX ai_dependency_edges_derivation_idx ON ai_dependency_edges (source_id, target_id) WHERE dependency_type IN ('derived_from', 'distilled_from')",
      "DROP INDEX IF EXISTS ai_dependency_edges_derivation_idx"
    )
  end
end
