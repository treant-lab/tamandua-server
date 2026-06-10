defmodule TamanduaServer.AISecurity.ModelBlock.BlockEntry do
  @moduledoc """
  Ecto schema for tracking blocked AI models.

  When a model is blocked, it cannot be loaded or executed by AI runtimes.
  The block list is synchronized to agents for enforcement via file permissions
  and access control.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "ai_model_blocks" do
    field :model_id, :string           # Reference to AI model
    field :file_hash, :string          # SHA-256 hash for verification
    field :file_path, :string          # Original file path
    field :agent_id, :string           # Agent where model resides
    field :reason, :string             # User-provided reason for blocking
    field :blocked_by_id, :binary_id   # User who blocked
    field :status, :string, default: "active"  # active, removed
    field :organization_id, :binary_id

    timestamps()
  end

  @doc """
  Creates a changeset for a block entry.

  ## Required fields
    * `:model_id` - Unique identifier for the AI model
    * `:file_hash` - SHA-256 hash of the model file
    * `:agent_id` - ID of the agent hosting the model
    * `:blocked_by_id` - ID of the user creating the block
    * `:organization_id` - Organization this block belongs to

  ## Optional fields
    * `:file_path` - Full path to the model file
    * `:reason` - User-provided justification for blocking
    * `:status` - Block status (default: "active")
  """
  def changeset(block_entry, attrs) do
    block_entry
    |> cast(attrs, [:model_id, :file_hash, :file_path, :agent_id, :reason,
                    :blocked_by_id, :status, :organization_id])
    |> validate_required([:model_id, :file_hash, :agent_id, :blocked_by_id, :organization_id])
    |> validate_inclusion(:status, ["active", "removed"])
    |> unique_constraint([:model_id, :organization_id], name: :ai_model_blocks_model_org_idx)
  end
end
