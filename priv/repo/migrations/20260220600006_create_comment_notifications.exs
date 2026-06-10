defmodule TamanduaServer.Repo.Migrations.CreateCommentNotifications do
  use Ecto.Migration

  def change do
    create table(:comment_notifications, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :comment_id, references(:alert_comments, type: :binary_id, on_delete: :delete_all), null: false
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Notification type: mention, reply, reaction
      add :notification_type, :string, null: false

      add :is_read, :boolean, default: false, null: false
      add :read_at, :utc_datetime_usec

      # Who triggered the notification
      add :triggered_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:comment_notifications, [:user_id])
    create index(:comment_notifications, [:comment_id])
    create index(:comment_notifications, [:alert_id])
    create index(:comment_notifications, [:organization_id])
    create index(:comment_notifications, [:is_read])
    create index(:comment_notifications, [:inserted_at])
  end
end
