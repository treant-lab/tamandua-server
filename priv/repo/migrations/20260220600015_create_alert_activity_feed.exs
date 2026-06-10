defmodule TamanduaServer.Repo.Migrations.CreateAlertActivityFeed do
  use Ecto.Migration

  def change do
    create table(:alert_activity_feed, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Activity type: comment_added, comment_edited, comment_deleted,
      # status_changed, assignment_changed, verdict_changed, etc.
      add :activity_type, :string, null: false

      # Related entity (comment_id, etc.)
      add :related_id, :binary_id
      add :related_type, :string

      # Activity details
      add :details, :map, default: %{}

      # Human-readable summary
      add :summary, :text

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:alert_activity_feed, [:alert_id])
    create index(:alert_activity_feed, [:user_id])
    create index(:alert_activity_feed, [:organization_id])
    create index(:alert_activity_feed, [:activity_type])
    create index(:alert_activity_feed, [:inserted_at])
    create index(:alert_activity_feed, [:related_id, :related_type])
  end
end
