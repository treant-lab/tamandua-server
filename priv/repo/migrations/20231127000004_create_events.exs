defmodule TamanduaServer.Repo.Migrations.CreateEvents do
  use Ecto.Migration

  def up do
    # Create events table for telemetry
    # Using composite primary key (id, timestamp) for TimescaleDB compatibility
    create table(:events, primary_key: false) do
      add :id, :binary_id, null: false
      add :event_type, :string, null: false
      add :timestamp, :utc_datetime_usec, null: false
      add :payload, :map, default: %{}
      add :sha256, :binary
      add :severity, :string, default: "info"
      add :enrichment, :map, default: %{}
      add :detections, {:array, :map}, default: []

      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false

      add :created_at, :utc_datetime_usec, null: false, default: fragment("NOW()")
    end

    # Add composite primary key for TimescaleDB compatibility
    execute "ALTER TABLE events ADD PRIMARY KEY (id, timestamp)"

    create index(:events, [:agent_id])
    create index(:events, [:event_type])
    create index(:events, [:severity])
    create index(:events, [:sha256], where: "sha256 IS NOT NULL")
    create index(:events, [:timestamp])

    # Create TimescaleDB hypertable for efficient time-series queries
    # This requires TimescaleDB extension to be installed
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable('events', 'timestamp',
          chunk_time_interval => INTERVAL '1 day',
          if_not_exists => TRUE
        );
      END IF;
    END
    $$;
    """

    # Create compression policy for old data (if TimescaleDB is available)
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        ALTER TABLE events SET (
          timescaledb.compress,
          timescaledb.compress_segmentby = 'agent_id',
          timescaledb.compress_orderby = 'timestamp DESC'
        );

        -- Compress chunks older than 7 days
        SELECT add_compression_policy('events', INTERVAL '7 days');
      END IF;
    EXCEPTION
      WHEN OTHERS THEN
        -- Ignore errors if compression policy already exists
        NULL;
    END
    $$;
    """

    # Create retention policy (if TimescaleDB is available)
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        -- Keep data for 90 days by default
        SELECT add_retention_policy('events', INTERVAL '90 days');
      END IF;
    EXCEPTION
      WHEN OTHERS THEN
        -- Ignore errors if retention policy already exists
        NULL;
    END
    $$;
    """
  end

  def down do
    # Drop TimescaleDB policies first
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        SELECT remove_retention_policy('events', if_exists => true);
        SELECT remove_compression_policy('events', if_exists => true);
      END IF;
    EXCEPTION
      WHEN OTHERS THEN NULL;
    END
    $$;
    """

    drop table(:events)
  end
end
