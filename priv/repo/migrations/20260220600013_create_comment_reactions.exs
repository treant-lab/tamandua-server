defmodule TamanduaServer.Repo.Migrations.CreateCommentReactions do
  use Ecto.Migration

  def change do
    create table(:comment_reactions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :comment_id, references(:alert_comments, type: :binary_id, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Reaction type: thumbs_up, thumbs_down, eyes, heart, check, etc.
      add :reaction_type, :string, null: false

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:comment_reactions, [:comment_id])
    create index(:comment_reactions, [:user_id])
    create index(:comment_reactions, [:organization_id])

    # A user can only react once per comment with the same reaction type
    create unique_index(:comment_reactions, [:comment_id, :user_id, :reaction_type])
  end
end
