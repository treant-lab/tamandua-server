defmodule TamanduaServer.Repo.Migrations.AddSourceEventIdToAlerts do
  use Ecto.Migration

  def change do
    execute(
      "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source_event_id uuid",
      "ALTER TABLE alerts DROP COLUMN IF EXISTS source_event_id"
    )

    create_if_not_exists index(:alerts, [:source_event_id])
  end
end
