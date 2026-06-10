defmodule TamanduaServer.Repo.Migrations.AddEnrichmentIndex do
  use Ecto.Migration

  def up do
    # Add GIN index on enrichment column for efficient JSONB queries
    # This allows fast lookups for threat intel matches, geo data, etc.
    execute """
    CREATE INDEX  IF NOT EXISTS events_enrichment_gin_idx
    ON events USING GIN (enrichment jsonb_path_ops)
    """

    # Add functional indexes for common enrichment queries
    execute """
    CREATE INDEX  IF NOT EXISTS events_enrichment_threat_intel_idx
    ON events ((enrichment->'threat_intel'))
    WHERE enrichment ? 'threat_intel'
    """

    execute """
    CREATE INDEX  IF NOT EXISTS events_enrichment_geo_idx
    ON events ((enrichment->'geo'))
    WHERE enrichment ? 'geo'
    """
  end

  def down do
    execute "DROP INDEX  IF EXISTS events_enrichment_gin_idx"
    execute "DROP INDEX  IF EXISTS events_enrichment_threat_intel_idx"
    execute "DROP INDEX  IF EXISTS events_enrichment_geo_idx"
  end
end
