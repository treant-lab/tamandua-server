defmodule TamanduaServer.Repo.Migrations.AddMissingIocFields do
  use Ecto.Migration

  @moduledoc """
  Adds missing fields to the iocs table that are required by the
  ThreatIntel.Aggregator and STIX converter.

  - confidence: changed from integer (0-100) to double precision (0.0-1.0)
  - first_seen / last_seen: timestamps for IOC observation window
  - source_ref, expires_at, malware_family, threat_actor, campaign,
    mitre_tactics, mitre_techniques: ensured present (IF NOT EXISTS)

  Uses IF NOT EXISTS / IF EXISTS patterns so this migration is safe to run
  against databases that already have some of these columns from the original
  CreateIocs migration.
  """

  def change do
    execute """
    DO $$
    BEGIN
      -- Alter confidence from integer to double precision if it exists as integer
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'confidence' AND data_type = 'integer'
      ) THEN
        ALTER TABLE iocs ALTER COLUMN confidence TYPE double precision USING confidence / 100.0;
        ALTER TABLE iocs ALTER COLUMN confidence DROP DEFAULT;
      END IF;

      -- Add confidence as double precision if it does not exist at all
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'confidence'
      ) THEN
        ALTER TABLE iocs ADD COLUMN confidence double precision;
      END IF;

      -- Add first_seen and last_seen timestamp columns
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'first_seen'
      ) THEN
        ALTER TABLE iocs ADD COLUMN first_seen timestamptz;
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'last_seen'
      ) THEN
        ALTER TABLE iocs ADD COLUMN last_seen timestamptz;
      END IF;

      -- Ensure other context fields exist (from original migration, but may be missing)
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'source_ref'
      ) THEN
        ALTER TABLE iocs ADD COLUMN source_ref varchar(255);
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'expires_at'
      ) THEN
        ALTER TABLE iocs ADD COLUMN expires_at timestamptz;
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'malware_family'
      ) THEN
        ALTER TABLE iocs ADD COLUMN malware_family varchar(255);
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'threat_actor'
      ) THEN
        ALTER TABLE iocs ADD COLUMN threat_actor varchar(255);
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'campaign'
      ) THEN
        ALTER TABLE iocs ADD COLUMN campaign varchar(255);
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'mitre_tactics'
      ) THEN
        ALTER TABLE iocs ADD COLUMN mitre_tactics varchar(255)[] DEFAULT ARRAY[]::varchar[];
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'mitre_techniques'
      ) THEN
        ALTER TABLE iocs ADD COLUMN mitre_techniques varchar(255)[] DEFAULT ARRAY[]::varchar[];
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      -- Rollback: convert confidence back to integer if it is double precision
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'confidence' AND data_type = 'double precision'
      ) THEN
        ALTER TABLE iocs ALTER COLUMN confidence TYPE integer USING ROUND(confidence * 100)::integer;
        ALTER TABLE iocs ALTER COLUMN confidence SET DEFAULT 50;
      END IF;

      -- Drop first_seen and last_seen if they exist
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'first_seen'
      ) THEN
        ALTER TABLE iocs DROP COLUMN first_seen;
      END IF;

      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'iocs' AND column_name = 'last_seen'
      ) THEN
        ALTER TABLE iocs DROP COLUMN last_seen;
      END IF;
    END $$;
    """

    # Add indexes for new columns
    create_if_not_exists index(:iocs, [:confidence], where: "confidence IS NOT NULL")
    create_if_not_exists index(:iocs, [:first_seen], where: "first_seen IS NOT NULL")
    create_if_not_exists index(:iocs, [:last_seen], where: "last_seen IS NOT NULL")
  end
end
