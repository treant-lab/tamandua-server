defmodule TamanduaServer.Repo.Migrations.CreateCommentEditHistory do
  use Ecto.Migration

  def change do
    create table(:comment_edit_history, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :comment_id, references(:alert_comments, type: :binary_id, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :previous_content, :text, null: false
      add :new_content, :text, null: false
      add :edit_reason, :string

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:comment_edit_history, [:comment_id])
    create index(:comment_edit_history, [:user_id])
    create index(:comment_edit_history, [:organization_id])
    create index(:comment_edit_history, [:inserted_at])
  end
end
