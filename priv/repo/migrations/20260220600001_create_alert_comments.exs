defmodule TamanduaServer.Repo.Migrations.CreateAlertComments do
  use Ecto.Migration

  def change do
    create table(:alert_comments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :parent_id, references(:alert_comments, type: :binary_id, on_delete: :delete_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :content, :text, null: false
      add :content_type, :string, default: "markdown", null: false
      add :is_pinned, :boolean, default: false, null: false
      add :is_deleted, :boolean, default: false, null: false
      add :deleted_at, :utc_datetime_usec
      add :deleted_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      # Edit history tracking
      add :edited_at, :utc_datetime_usec
      add :edit_count, :integer, default: 0, null: false

      # Mentions tracking (user IDs that were @mentioned)
      add :mentioned_user_ids, {:array, :binary_id}, default: []

      # Metadata for extensibility
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create index(:alert_comments, [:alert_id])
    create index(:alert_comments, [:user_id])
    create index(:alert_comments, [:parent_id])
    create index(:alert_comments, [:organization_id])
    create index(:alert_comments, [:is_pinned])
    create index(:alert_comments, [:is_deleted])
    create index(:alert_comments, [:inserted_at])

    # Full-text search on content (requires pg_trgm extension)
    execute(
      """
      DO $$
      BEGIN
        -- Create extension if not exists
        CREATE EXTENSION IF NOT EXISTS pg_trgm;
        -- Create trigram index
        CREATE INDEX IF NOT EXISTS alert_comments_content_trgm_idx ON alert_comments USING gin (content gin_trgm_ops);
      EXCEPTION
        WHEN OTHERS THEN NULL;
      END $$;
      """,
      "DROP INDEX IF EXISTS alert_comments_content_trgm_idx"
    )
  end
end
