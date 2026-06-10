defmodule TamanduaServer.Repo.Migrations.CreateSavedQueries do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:saved_queries, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :query, :text, null: false
      add :query_type, :string, default: "hunt"  # hunt, sigma, yara, nl
      add :category, :string  # MITRE tactic or custom category
      add :tags, {:array, :string}, default: []
      add :is_template, :boolean, default: false
      add :is_public, :boolean, default: false
      add :use_count, :integer, default: 0
      add :last_used_at, :utc_datetime
      add :created_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists index(:saved_queries, [:query_type])
    create_if_not_exists index(:saved_queries, [:category])
    create_if_not_exists index(:saved_queries, [:is_template])
    create_if_not_exists index(:saved_queries, [:is_public])
    create_if_not_exists index(:saved_queries, [:created_by])
    create_if_not_exists index(:saved_queries, [:organization_id])
    create_if_not_exists index(:saved_queries, [:tags], using: "gin")

    # Query history for tracking recent searches
    create_if_not_exists table(:query_history, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :query, :text, null: false
      add :query_type, :string, default: "hunt"
      add :result_count, :integer
      add :execution_time_ms, :integer
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all)
      add :agent_id, references(:agents, type: :binary_id, on_delete: :nilify_all)

      timestamps(updated_at: false)
    end

    create_if_not_exists index(:query_history, [:user_id])
    create_if_not_exists index(:query_history, [:query_type])
    create_if_not_exists index(:query_history, [:inserted_at])
  end
end
