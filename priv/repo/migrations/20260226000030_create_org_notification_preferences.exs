defmodule TamanduaServer.Repo.Migrations.CreateOrgNotificationPreferences do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:notification_preferences, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      add :notification_type, :string, null: false
      add :enabled, :boolean, default: true, null: false
      add :delivery_method, :string, default: "email", null: false
      add :frequency, :string, default: "immediate", null: false

      # Quiet hours (e.g., no notifications from 10 PM to 8 AM)
      add :quiet_hours_start, :time
      add :quiet_hours_end, :time

      timestamps(type: :utc_datetime_usec)
    end

    # Add any missing columns to existing table
    execute """
    DO $$
    BEGIN
      ALTER TABLE notification_preferences ADD COLUMN IF NOT EXISTS organization_id UUID;
      ALTER TABLE notification_preferences ADD COLUMN IF NOT EXISTS notification_type VARCHAR;
      ALTER TABLE notification_preferences ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT TRUE;
      ALTER TABLE notification_preferences ADD COLUMN IF NOT EXISTS delivery_method VARCHAR DEFAULT 'email';
      ALTER TABLE notification_preferences ADD COLUMN IF NOT EXISTS frequency VARCHAR DEFAULT 'immediate';
      ALTER TABLE notification_preferences ADD COLUMN IF NOT EXISTS quiet_hours_start TIME;
      ALTER TABLE notification_preferences ADD COLUMN IF NOT EXISTS quiet_hours_end TIME;
    END $$;
    """, ""

    execute "CREATE UNIQUE INDEX IF NOT EXISTS notification_preferences_user_id_notification_type_index ON notification_preferences(user_id, notification_type)", ""
    execute "CREATE INDEX IF NOT EXISTS notification_preferences_user_id_index ON notification_preferences(user_id)", ""
    execute "CREATE INDEX IF NOT EXISTS notification_preferences_organization_id_index ON notification_preferences(organization_id)", ""
    execute "CREATE INDEX IF NOT EXISTS notification_preferences_notification_type_index ON notification_preferences(notification_type)", ""
  end
end
