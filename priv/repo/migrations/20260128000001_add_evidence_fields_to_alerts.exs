defmodule TamanduaServer.Repo.Migrations.AddEvidenceFieldsToAlerts do
  use Ecto.Migration

  def change do
    # Use raw SQL with IF NOT EXISTS to avoid duplicate column errors
    # These columns may already exist if migration ran partially or was re-applied
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='evidence') THEN
        ALTER TABLE alerts ADD COLUMN evidence jsonb DEFAULT '{}'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='process_chain') THEN
        ALTER TABLE alerts ADD COLUMN process_chain jsonb DEFAULT '[]'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='raw_event') THEN
        ALTER TABLE alerts ADD COLUMN raw_event jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='detection_metadata') THEN
        ALTER TABLE alerts ADD COLUMN detection_metadata jsonb DEFAULT '{}'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='contributing_events') THEN
        ALTER TABLE alerts ADD COLUMN contributing_events varchar(255)[] DEFAULT '{}';
      END IF;
    END $$;
    """, ""

    # GIN index for efficient JSONB queries on evidence
    execute(
      "CREATE INDEX IF NOT EXISTS alerts_evidence_idx ON alerts USING GIN (evidence)",
      "DROP INDEX IF EXISTS alerts_evidence_idx"
    )

    # GIN index for detection_metadata queries
    execute(
      "CREATE INDEX IF NOT EXISTS alerts_detection_metadata_idx ON alerts USING GIN (detection_metadata)",
      "DROP INDEX IF EXISTS alerts_detection_metadata_idx"
    )
  end
end
