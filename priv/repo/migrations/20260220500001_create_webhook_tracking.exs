defmodule TamanduaServer.Repo.Migrations.CreateWebhookTracking do
  use Ecto.Migration

  def change do
    # Note: webhook_deliveries may already exist from an earlier migration
    # This migration ensures the table has the expected columns

    # Add missing columns to webhook_deliveries if table exists
    execute """
    DO $$
    BEGIN
      -- Add integration_id if not exists
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'webhook_deliveries' AND column_name = 'integration_id') THEN
        ALTER TABLE webhook_deliveries ADD COLUMN integration_id uuid REFERENCES integrations(id) ON DELETE CASCADE;
      END IF;

      -- Add integration_type if not exists
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'webhook_deliveries' AND column_name = 'integration_type') THEN
        ALTER TABLE webhook_deliveries ADD COLUMN integration_type varchar NOT NULL DEFAULT 'webhook';
      END IF;

      -- Add direction if not exists
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'webhook_deliveries' AND column_name = 'direction') THEN
        ALTER TABLE webhook_deliveries ADD COLUMN direction varchar NOT NULL DEFAULT 'outbound';
      END IF;

      -- Add source if not exists
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'webhook_deliveries' AND column_name = 'source') THEN
        ALTER TABLE webhook_deliveries ADD COLUMN source varchar;
      END IF;
    END
    $$;
    """, ""

    # Create indexes only if the columns exist
    execute "CREATE INDEX IF NOT EXISTS webhook_deliveries_integration_id_index ON webhook_deliveries(integration_id) WHERE integration_id IS NOT NULL", ""
    execute "CREATE INDEX IF NOT EXISTS webhook_deliveries_integration_type_index ON webhook_deliveries(integration_type) WHERE integration_type IS NOT NULL", ""
    execute "CREATE INDEX IF NOT EXISTS webhook_deliveries_direction_index ON webhook_deliveries(direction) WHERE direction IS NOT NULL", ""

    # Create table for tracking sync state between Tamandua and external systems
    create_if_not_exists table(:integration_sync_states, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :integration_id, references(:integrations, type: :binary_id, on_delete: :delete_all), null: false
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false
      add :external_id, :string, null: false
      add :external_url, :string
      add :external_status, :string
      add :last_synced_at, :utc_datetime
      add :sync_direction, :string
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:integration_sync_states, [:integration_id])
    create_if_not_exists index(:integration_sync_states, [:alert_id])
    create_if_not_exists index(:integration_sync_states, [:external_id])
    create_if_not_exists unique_index(:integration_sync_states, [:integration_id, :alert_id])
    create_if_not_exists unique_index(:integration_sync_states, [:integration_id, :external_id])
  end
end
