defmodule TamanduaServer.Repo.Migrations.AddAlertDeduplication do
  use Ecto.Migration

  def change do
    # Use raw SQL with IF NOT EXISTS to avoid duplicate column errors
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='occurrence_count') THEN
        ALTER TABLE alerts ADD COLUMN occurrence_count integer DEFAULT 1 NOT NULL;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='last_seen_at') THEN
        ALTER TABLE alerts ADD COLUMN last_seen_at timestamp;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='dedup_key') THEN
        ALTER TABLE alerts ADD COLUMN dedup_key varchar(255);
      END IF;
    END $$;
    """, ""

    create_if_not_exists index(:alerts, [:dedup_key])

    # Composite index for fast dedup lookups within a time window
    create_if_not_exists index(:alerts, [:dedup_key, :inserted_at])
  end
end
