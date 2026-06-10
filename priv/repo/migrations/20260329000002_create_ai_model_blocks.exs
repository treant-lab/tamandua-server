defmodule TamanduaServer.Repo.Migrations.CreateAIModelBlocks do
  @moduledoc """
  Creates the ai_model_blocks table for tracking blocked AI models.

  Blocked models cannot be loaded or executed by AI runtimes. The block list
  is synchronized to agents for enforcement via file permissions and access control.
  """
  use Ecto.Migration

  def change do
    create table(:ai_model_blocks, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :model_id, :string, null: false
      add :file_hash, :string, null: false
      add :file_path, :string
      add :agent_id, :string, null: false
      add :reason, :text
      add :blocked_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :status, :string, null: false, default: "active"
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      timestamps()
    end

    create index(:ai_model_blocks, [:organization_id])
    create index(:ai_model_blocks, [:agent_id])
    create index(:ai_model_blocks, [:file_hash])
    create index(:ai_model_blocks, [:status])
    create unique_index(:ai_model_blocks, [:model_id, :organization_id], name: :ai_model_blocks_model_org_idx)
  end
end
