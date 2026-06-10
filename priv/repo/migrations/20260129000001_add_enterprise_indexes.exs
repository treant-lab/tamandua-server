defmodule TamanduaServer.Repo.Migrations.AddEnterpriseIndexes do
  @moduledoc """
  Performance optimization indexes for enterprise scale (100,000+ agents).

  These indexes are designed to optimize:
  - Event queries by agent and time range
  - Alert queries by status and severity
  - Agent lookups by organization
  - Detection correlation queries
  - Timeline and investigation queries
  """

  use Ecto.Migration

  @disable_ddl_transaction true
  @disable_migration_lock true

  def up do
    # ==========================================================================
    # Events Table Indexes
    # Note: events is a TimescaleDB hypertable - CONCURRENTLY not supported
    # ==========================================================================

    # Composite index for agent + time range queries (most common query pattern)
    create_if_not_exists index(:events, [:agent_id, :timestamp],
      name: :events_agent_timestamp_idx
    )

    # Index for event type filtering
    create_if_not_exists index(:events, [:event_type, :timestamp],
      name: :events_type_timestamp_idx
    )

    # Partial index for SHA256 lookups (only when not null)
    execute """
    CREATE INDEX IF NOT EXISTS events_sha256_partial_idx
    ON events (sha256)
    WHERE sha256 IS NOT NULL
    """

    # BRIN index for timestamp (efficient for time-series data)
    execute """
    CREATE INDEX IF NOT EXISTS events_timestamp_brin_idx
    ON events USING BRIN (timestamp)
    WITH (pages_per_range = 128)
    """

    # GIN index for payload JSONB queries
    execute """
    CREATE INDEX IF NOT EXISTS events_payload_gin_idx
    ON events USING GIN (payload jsonb_path_ops)
    """

    # ==========================================================================
    # Alerts Table Indexes
    # ==========================================================================

    # Composite index for status + severity (dashboard queries)
    create_if_not_exists index(:alerts, [:status, :severity, :inserted_at],
      name: :alerts_status_severity_idx,
      concurrently: true
    )

    # Index for agent-based alert queries
    create_if_not_exists index(:alerts, [:agent_id, :inserted_at],
      name: :alerts_agent_time_idx,
      concurrently: true
    )

    # Partial index for open alerts (most common filter)
    execute """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS alerts_open_partial_idx
    ON alerts (inserted_at DESC)
    WHERE status NOT IN ('resolved', 'closed', 'dismissed')
    """

    # Index for MITRE techniques queries (array column - use GIN)
    # Note: alerts_mitre_techniques_idx already created in original migration
    # Skipping to avoid duplicate index

    # Note: fingerprint column does not exist on alerts table
    # Removed fingerprint unique index

    # ==========================================================================
    # Agents Table Indexes
    # ==========================================================================

    # Index for organization lookups
    create_if_not_exists index(:agents, [:organization_id, :status],
      name: :agents_org_status_idx,
      concurrently: true
    )

    # Index for machine_id lookups (agent registration)
    create_if_not_exists unique_index(:agents, [:machine_id],
      name: :agents_machine_id_unique_idx,
      concurrently: true
    )

    # Index for hostname searches
    create_if_not_exists index(:agents, [:hostname],
      name: :agents_hostname_idx,
      concurrently: true
    )

    # Index for IP address lookups
    create_if_not_exists index(:agents, [:ip_address],
      name: :agents_ip_address_idx,
      concurrently: true
    )

    # Partial index for online agents
    execute """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS agents_online_partial_idx
    ON agents (last_seen_at DESC)
    WHERE status = 'online'
    """

    # ==========================================================================
    # Users Table Indexes (if not exists)
    # ==========================================================================

    create_if_not_exists index(:users, [:organization_id],
      name: :users_organization_idx,
      concurrently: true
    )

    create_if_not_exists unique_index(:users, [:email],
      name: :users_email_unique_idx,
      concurrently: true
    )

    # ==========================================================================
    # Investigation Support Indexes
    # Note: events is a TimescaleDB hypertable - CONCURRENTLY not supported
    # ==========================================================================

    # Events correlation by source_event_id
    execute """
    CREATE INDEX IF NOT EXISTS events_source_event_idx
    ON events ((payload->>'source_event_id'))
    WHERE payload->>'source_event_id' IS NOT NULL
    """

    # Process tree lookups
    execute """
    CREATE INDEX IF NOT EXISTS events_parent_pid_idx
    ON events ((payload->>'parent_pid'))
    WHERE event_type IN ('process_create', 'process_exit')
    """

    execute """
    CREATE INDEX IF NOT EXISTS events_process_pid_idx
    ON events ((payload->>'pid'))
    WHERE event_type IN ('process_create', 'process_exit')
    """

    # Network correlation
    execute """
    CREATE INDEX IF NOT EXISTS events_remote_ip_idx
    ON events ((payload->>'remote_ip'))
    WHERE event_type IN ('network_connect', 'network_listen', 'dns_query')
    """

    # ==========================================================================
    # Threat Intel Indexes
    # ==========================================================================

    # IOC hash lookups (column is 'value', not 'hash_value')
    execute """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS iocs_hash_idx
    ON iocs (value)
    WHERE type IN ('sha256', 'sha1', 'md5')
    """

    # IOC IP lookups
    execute """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS iocs_ip_idx
    ON iocs (value)
    WHERE type = 'ip'
    """

    # IOC domain lookups
    execute """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS iocs_domain_idx
    ON iocs (value)
    WHERE type = 'domain'
    """

    # ==========================================================================
    # TimescaleDB Hypertable (if using TimescaleDB)
    # ==========================================================================

    # Convert events table to hypertable for time-series optimization
    # This is commented out - enable only if using TimescaleDB
    # execute """
    # SELECT create_hypertable('events', 'timestamp',
    #   chunk_time_interval => INTERVAL '1 day',
    #   if_not_exists => TRUE
    # );
    # """

    # Add compression policy (keep recent data uncompressed)
    # execute """
    # SELECT add_compression_policy('events', INTERVAL '7 days', if_not_exists => TRUE);
    # """

    # Add retention policy
    # execute """
    # SELECT add_retention_policy('events', INTERVAL '90 days', if_not_exists => TRUE);
    # """
  end

  def down do
    # Events indexes (hypertable - no CONCURRENTLY)
    execute "DROP INDEX IF EXISTS events_agent_timestamp_idx"
    execute "DROP INDEX IF EXISTS events_type_timestamp_idx"
    execute "DROP INDEX IF EXISTS events_sha256_partial_idx"
    execute "DROP INDEX IF EXISTS events_timestamp_brin_idx"
    execute "DROP INDEX IF EXISTS events_payload_gin_idx"
    execute "DROP INDEX IF EXISTS events_source_event_idx"
    execute "DROP INDEX IF EXISTS events_parent_pid_idx"
    execute "DROP INDEX IF EXISTS events_process_pid_idx"
    execute "DROP INDEX IF EXISTS events_remote_ip_idx"

    # Alerts indexes
    execute "DROP INDEX CONCURRENTLY IF EXISTS alerts_status_severity_idx"
    execute "DROP INDEX CONCURRENTLY IF EXISTS alerts_agent_time_idx"
    execute "DROP INDEX CONCURRENTLY IF EXISTS alerts_open_partial_idx"
    # alerts_mitre_techniques_idx is from original migration, not dropped here
    # alerts_fingerprint_unique_idx removed - column does not exist

    # Agents indexes
    execute "DROP INDEX CONCURRENTLY IF EXISTS agents_org_status_idx"
    execute "DROP INDEX CONCURRENTLY IF EXISTS agents_machine_id_unique_idx"
    execute "DROP INDEX CONCURRENTLY IF EXISTS agents_hostname_idx"
    execute "DROP INDEX CONCURRENTLY IF EXISTS agents_ip_address_idx"
    execute "DROP INDEX CONCURRENTLY IF EXISTS agents_online_partial_idx"

    # Users indexes
    execute "DROP INDEX CONCURRENTLY IF EXISTS users_organization_idx"
    execute "DROP INDEX CONCURRENTLY IF EXISTS users_email_unique_idx"

    # IOC indexes
    execute "DROP INDEX CONCURRENTLY IF EXISTS iocs_hash_idx"
    execute "DROP INDEX CONCURRENTLY IF EXISTS iocs_ip_idx"
    execute "DROP INDEX CONCURRENTLY IF EXISTS iocs_domain_idx"
  end
end
