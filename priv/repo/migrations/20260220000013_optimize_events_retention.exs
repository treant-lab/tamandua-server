defmodule TamanduaServer.Repo.Migrations.OptimizeEventsRetention do
  use Ecto.Migration

  def up do
    # Add archived flag to events table
    alter table(:events) do
      add :archived, :boolean, default: false, null: false
      add :sampled, :boolean, default: false, null: false
    end

    # Create events_archive table for long-term storage
    create table(:events_archive, primary_key: false) do
      add :id, :binary_id, null: false
      add :event_type, :string, null: false
      add :timestamp, :utc_datetime_usec, null: false
      add :payload, :map, default: %{}
      add :sha256, :binary
      add :severity, :string, default: "info"
      add :enrichment, :map, default: %{}
      add :detections, {:array, :map}, default: []
      add :agent_id, :binary_id, null: false
      add :created_at, :utc_datetime_usec, null: false
      add :archived_at, :utc_datetime_usec, null: false, default: fragment("NOW()")
    end

    # Add composite primary key for archive table
    execute "ALTER TABLE events_archive ADD PRIMARY KEY (id, timestamp)"

    # Add indexes for archive table
    create index(:events_archive, [:agent_id])
    create index(:events_archive, [:event_type])
    create index(:events_archive, [:timestamp])
    create index(:events_archive, [:archived_at])

    # Add index for archived flag on events table
    create index(:events, [:archived], where: "archived = true")
    create index(:events, [:sampled], where: "sampled = true")

    # Optimize existing indexes - add covering indexes for common queries
    # Compound index for agent+type+time queries (hot path)
    create index(:events, [:agent_id, :event_type, :timestamp])

    # Note: Partial index with NOW() is not supported in PostgreSQL
    # Use a regular index on timestamp for recent event queries
    execute """
    CREATE INDEX IF NOT EXISTS events_timestamp_desc_idx
    ON events (timestamp DESC)
    """

    # Update TimescaleDB retention policy to 30 days (from default 90)
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        -- Remove old retention policy if exists
        BEGIN
          PERFORM remove_retention_policy('events', if_exists => true);
        EXCEPTION
          WHEN OTHERS THEN NULL;
        END;

        -- Add new 30-day retention policy
        PERFORM add_retention_policy('events', INTERVAL '30 days', if_not_exists => true);
      END IF;
    END
    $$;
    """

    # Create materialized view for event analytics (hourly aggregates)
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        -- Create continuous aggregate for analytics
        CREATE MATERIALIZED VIEW IF NOT EXISTS events_hourly
        WITH (timescaledb.continuous) AS
        SELECT
          time_bucket('1 hour', timestamp) AS hour,
          agent_id,
          event_type,
          severity,
          COUNT(*) as event_count,
          COUNT(DISTINCT agent_id) as agent_count
        FROM events
        GROUP BY hour, agent_id, event_type, severity
        WITH NO DATA;

        -- Add refresh policy
        BEGIN
          PERFORM add_continuous_aggregate_policy('events_hourly',
            start_offset => INTERVAL '3 hours',
            end_offset => INTERVAL '1 hour',
            schedule_interval => INTERVAL '1 hour',
            if_not_exists => true
          );
        EXCEPTION
          WHEN OTHERS THEN NULL;
        END;
      END IF;
    END
    $$;
    """

    # Create daily aggregates view
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        CREATE MATERIALIZED VIEW IF NOT EXISTS events_daily
        WITH (timescaledb.continuous) AS
        SELECT
          time_bucket('1 day', timestamp) AS day,
          agent_id,
          event_type,
          COUNT(*) as event_count
        FROM events
        GROUP BY day, agent_id, event_type
        WITH NO DATA;

        -- Add refresh policy for daily view
        BEGIN
          PERFORM add_continuous_aggregate_policy('events_daily',
            start_offset => INTERVAL '3 days',
            end_offset => INTERVAL '1 day',
            schedule_interval => INTERVAL '1 day',
            if_not_exists => true
          );
        EXCEPTION
          WHEN OTHERS THEN NULL;
        END;
      END IF;
    END
    $$;
    """
  end

  def down do
    # Drop materialized views
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        BEGIN
          PERFORM remove_continuous_aggregate_policy('events_hourly', if_exists => true);
          DROP MATERIALIZED VIEW IF EXISTS events_hourly CASCADE;
        EXCEPTION
          WHEN OTHERS THEN NULL;
        END;

        BEGIN
          PERFORM remove_continuous_aggregate_policy('events_daily', if_exists => true);
          DROP MATERIALIZED VIEW IF EXISTS events_daily CASCADE;
        EXCEPTION
          WHEN OTHERS THEN NULL;
        END;
      END IF;
    END
    $$;
    """

    # Drop indexes
    drop_if_exists index(:events, [:agent_id, :event_type, :timestamp])
    execute "DROP INDEX IF EXISTS events_recent_timestamp_idx"
    drop_if_exists index(:events, [:archived], where: "archived = true")
    drop_if_exists index(:events, [:sampled], where: "sampled = true")

    drop_if_exists index(:events_archive, [:agent_id])
    drop_if_exists index(:events_archive, [:event_type])
    drop_if_exists index(:events_archive, [:timestamp])
    drop_if_exists index(:events_archive, [:archived_at])

    # Drop archive table
    drop_if_exists table(:events_archive)

    # Remove columns from events
    alter table(:events) do
      remove :archived
      remove :sampled
    end

    # Restore 90-day retention policy
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        BEGIN
          PERFORM remove_retention_policy('events', if_exists => true);
          PERFORM add_retention_policy('events', INTERVAL '90 days', if_not_exists => true);
        EXCEPTION
          WHEN OTHERS THEN NULL;
        END;
      END IF;
    END
    $$;
    """
  end
end
