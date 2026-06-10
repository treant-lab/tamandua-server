defmodule TamanduaServer.Repo.Migrations.AddDataResidencyToOrganizations do
  use Ecto.Migration

  def up do
    # Add region enum type
    execute """
    CREATE TYPE organization_region AS ENUM (
      'eu', 'us', 'apac', 'ca', 'uk', 'au', 'jp', 'in'
    )
    """

    # Add region column to organizations table
    alter table(:organizations) do
      add :region, :organization_region, default: "us", null: true
    end

    # Add index on region for efficient queries
    create index(:organizations, [:region])

    # The settings JSONB field already exists and will store:
    # - replication_enabled (boolean)
    # - secondary_region (string)
    # - replication_mode (string: "async", "sync", "none")
    # - conflict_resolution (string: "last_write_wins", "primary_wins", etc.)
    # - compliance_frameworks (array of strings: ["gdpr", "ccpa", "sox", etc.])
    # - approved_transfer_regions (array of strings)
    # - encryption_enabled (boolean)
    # - data_retention_days (integer)
    # - audit_retention_years (integer)
    # - breach_notification_enabled (boolean)
    # - last_replicated_at (timestamp)

    # Add comment explaining the settings schema
    execute """
    COMMENT ON COLUMN organizations.settings IS 'JSONB field storing multi-tenancy settings including:
    - replication_enabled: Enable cross-region replication
    - secondary_region: Target region for replication
    - replication_mode: async|sync|none
    - conflict_resolution: last_write_wins|primary_wins|secondary_wins|manual
    - compliance_frameworks: ["gdpr", "ccpa", "sox", "hipaa", "pci_dss", "soc2"]
    - approved_transfer_regions: Regions allowed for data transfer
    - encryption_enabled: Enable at-rest encryption
    - data_retention_days: Data retention period
    - audit_retention_years: Audit log retention period
    - breach_notification_enabled: Enable breach notification
    - last_replicated_at: Last successful replication timestamp
    - failover_at: Last failover timestamp
    - failover_reason: Reason for last failover'
    """

    execute """
    COMMENT ON COLUMN organizations.region IS 'Primary data residency region for the organization.
    Determines which regional database, S3 bucket, Redis, and RabbitMQ instances are used.
    Must comply with data sovereignty regulations (GDPR, CCPA, etc.)'
    """
  end

  def down do
    # Remove index
    drop index(:organizations, [:region])

    # Remove column
    alter table(:organizations) do
      remove :region
    end

    # Drop enum type
    execute "DROP TYPE organization_region"

    # Remove comments
    execute "COMMENT ON COLUMN organizations.settings IS NULL"
  end
end
