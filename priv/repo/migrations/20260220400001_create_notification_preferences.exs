defmodule TamanduaServer.Repo.Migrations.CreateNotificationPreferences do
  use Ecto.Migration

  def change do
    create table(:notification_preferences, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false

      # Global toggle
      add :enabled, :boolean, default: true, null: false

      # Channel toggles
      add :email_enabled, :boolean, default: true, null: false
      add :sms_enabled, :boolean, default: false, null: false
      add :slack_enabled, :boolean, default: false, null: false

      # Contact details
      add :phone_number, :string
      add :slack_webhook_url, :string

      # Filtering
      add :severity_filter, {:array, :string}, default: []

      # Quiet hours
      add :quiet_hours_start, :time
      add :quiet_hours_end, :time

      # Digest mode
      add :digest_enabled, :boolean, default: false, null: false

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:notification_preferences, [:user_id])
    create index(:notification_preferences, [:enabled])
    create index(:notification_preferences, [:digest_enabled])
  end
end
