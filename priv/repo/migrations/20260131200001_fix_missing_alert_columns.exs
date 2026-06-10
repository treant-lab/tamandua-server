defmodule TamanduaServer.Repo.Migrations.FixMissingAlertColumns do
  use Ecto.Migration

  def change do
    # Fix columns that were missed due to duplicate migration timestamps
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='storyline_id') THEN
        ALTER TABLE alerts ADD COLUMN storyline_id varchar(255);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='correlation_data') THEN
        ALTER TABLE alerts ADD COLUMN correlation_data jsonb DEFAULT '{}'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='attributed_actors') THEN
        ALTER TABLE alerts ADD COLUMN attributed_actors varchar(255)[] DEFAULT ARRAY[]::varchar[];
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='campaign_id') THEN
        ALTER TABLE alerts ADD COLUMN campaign_id varchar(255);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='attribution_confidence') THEN
        ALTER TABLE alerts ADD COLUMN attribution_confidence double precision;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='attribution_details') THEN
        ALTER TABLE alerts ADD COLUMN attribution_details jsonb DEFAULT '{}'::jsonb;
      END IF;
    END $$;
    """, ""

    create_if_not_exists index(:alerts, [:storyline_id])
    create_if_not_exists index(:alerts, [:campaign_id], where: "campaign_id IS NOT NULL")
    create_if_not_exists index(:alerts, [:attribution_confidence], where: "attribution_confidence IS NOT NULL")
  end
end
