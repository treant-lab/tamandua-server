# Event Archival and Retention System

## Overview

The event archival system prevents unbounded PostgreSQL growth by implementing a multi-tier retention strategy with TimescaleDB integration, intelligent sampling, and automatic archival.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Event Lifecycle                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  0-7 days:     HOT TIER                                     │
│                ├─ 100% retention                            │
│                ├─ Uncompressed                              │
│                └─ All events kept                           │
│                                                             │
│  7-30 days:    WARM TIER                                    │
│                ├─ TimescaleDB compression                   │
│                ├─ High-value: 100% retention                │
│                └─ Low-value: 10% sampled                    │
│                                                             │
│  30+ days:     COLD TIER                                    │
│                ├─ Archived to events_archive table          │
│                └─ Original events dropped by retention      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. TimescaleDB Hypertable

The `events` table is a TimescaleDB hypertable partitioned by timestamp:

- **Chunk interval**: 1 day
- **Compression**: Enabled for chunks older than 7 days
- **Compression segmentby**: agent_id, event_type
- **Retention policy**: Drop chunks older than 30 days

### 2. Archive Table

The `events_archive` table stores long-term historical data:

- Same schema as `events` table
- Also a TimescaleDB hypertable
- Can have longer retention (90+ days)
- Used for compliance and historical analysis

### 3. Event Sampler

`TamanduaServer.Telemetry.EventSampler` classifies events:

**High-value (always keep):**
- Process creation/termination/injection
- Network connections/listening
- File modifications/creation/deletion
- Registry modifications (Windows)
- Privilege escalation
- Any event with detections or alerts
- High/critical severity events

**Low-value (candidates for sampling):**
- DNS queries (to benign domains)
- File reads (without modifications)
- Registry reads (without modifications)
- System health metrics
- Heartbeats

**Sampling strategy:**
- Deterministic hash-based sampling (same event always gets same decision)
- Configurable sampling rate (default: 10%)
- Runs during warm tier (7-30 days)

### 4. Archive Worker

`TamanduaServer.Workers.ArchiveEventsWorker` runs daily at 4:00 AM UTC:

1. **Archive old events** (30+ days):
   - Copy to `events_archive` table
   - Mark as `archived = true`
   - TimescaleDB retention drops them automatically

2. **Sample medium-age events** (7-30 days):
   - Classify into high-value vs low-value
   - Keep 100% of high-value
   - Sample low-value at configured rate
   - Mark processed events as `sampled = true`

## Configuration

### config/config.exs

```elixir
config :tamandua_server, TamanduaServer.Telemetry,
  # Archive events older than 30 days
  event_retention_days: 30,
  # Compress chunks older than 7 days
  event_compression_days: 7,
  # Enable sampling
  event_sampling_enabled: true,
  # Keep 10% of low-value events
  event_sampling_rate: 0.1,
  # Enable archival
  archive_enabled: true,
  # Batch size for archival operations
  archive_batch_size: 5000
```

### Oban Cron Schedule

```elixir
# Daily event archival at 4:00 AM UTC
{"0 4 * * *", TamanduaServer.Workers.ArchiveEventsWorker}
```

## Database Schema

### Events Table (Hot/Warm Tier)

```sql
CREATE TABLE events (
  id UUID NOT NULL,
  agent_id UUID NOT NULL,
  event_type VARCHAR NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL,
  severity VARCHAR DEFAULT 'info',
  payload JSONB DEFAULT '{}',
  enrichment JSONB DEFAULT '{}',
  sha256 BYTEA,
  archived BOOLEAN DEFAULT false,
  sampled BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (id, timestamp)
);

-- Convert to hypertable
SELECT create_hypertable('events', 'timestamp',
  chunk_time_interval => INTERVAL '1 day'
);

-- Compression policy
ALTER TABLE events SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'agent_id,event_type'
);

SELECT add_compression_policy('events', INTERVAL '7 days');

-- Retention policy
SELECT add_retention_policy('events', INTERVAL '30 days');
```

### Events Archive Table (Cold Tier)

```sql
CREATE TABLE events_archive (
  id UUID NOT NULL,
  agent_id UUID NOT NULL,
  event_type VARCHAR NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL,
  severity VARCHAR DEFAULT 'info',
  payload JSONB DEFAULT '{}',
  enrichment JSONB DEFAULT '{}',
  sha256 BYTEA,
  created_at TIMESTAMPTZ NOT NULL,
  archived_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (id, timestamp)
);

-- Convert to hypertable
SELECT create_hypertable('events_archive', 'timestamp',
  chunk_time_interval => INTERVAL '7 days'
);
```

## Indexes

### Optimized for Query Performance

```sql
-- Compound index for agent+type+time queries (hot path)
CREATE INDEX events_agent_type_time_idx
  ON events (agent_id, event_type, timestamp);

-- Partial index for recent events (7 days)
CREATE INDEX events_recent_timestamp_idx
  ON events (timestamp DESC)
  WHERE timestamp > NOW() - INTERVAL '7 days';

-- Index for archival status
CREATE INDEX events_archived_idx
  ON events (archived)
  WHERE archived = true;

-- Index for sampling status
CREATE INDEX events_sampled_idx
  ON events (sampled)
  WHERE sampled = true;
```

## Continuous Aggregates

### Hourly Metrics

```sql
CREATE MATERIALIZED VIEW events_hourly
WITH (timescaledb.continuous) AS
SELECT
  time_bucket('1 hour', timestamp) AS hour,
  agent_id,
  event_type,
  severity,
  COUNT(*) as event_count,
  COUNT(DISTINCT agent_id) as agent_count
FROM events
GROUP BY hour, agent_id, event_type, severity;

-- Refresh policy
SELECT add_continuous_aggregate_policy('events_hourly',
  start_offset => INTERVAL '3 hours',
  end_offset => INTERVAL '1 hour',
  schedule_interval => INTERVAL '1 hour'
);
```

### Daily Metrics

```sql
CREATE MATERIALIZED VIEW events_daily
WITH (timescaledb.continuous) AS
SELECT
  time_bucket('1 day', timestamp) AS day,
  agent_id,
  event_type,
  COUNT(*) as event_count
FROM events
GROUP BY day, agent_id, event_type;
```

## Usage

### Manual Archival

Trigger archival manually via IEx:

```elixir
# Trigger immediate archival
{:ok, job} = TamanduaServer.Workers.ArchiveEventsWorker.enqueue_archival()

# Dry run to see what would be archived
{:ok, job} = TamanduaServer.Workers.ArchiveEventsWorker.enqueue_archival(dry_run: true)

# Custom retention period
{:ok, job} = TamanduaServer.Workers.ArchiveEventsWorker.enqueue_archival(
  retention_days: 60,
  sampling_age_days: 14
)
```

### Get Archival Statistics

```elixir
# Get current archival stats
stats = TamanduaServer.Workers.ArchiveEventsWorker.archival_stats()

# Returns:
# %{
#   total_events: 1_234_567,
#   events_to_archive: 45_000,
#   events_to_sample: 123_000,
#   recent_events: 567_000,
#   archived_events: 890_000,
#   retention_days: 30,
#   archive_enabled: true,
#   sampling_enabled: true,
#   sampling_rate: 0.1
# }
```

### Query Archive Data

```elixir
# Query events from archive
import Ecto.Query
alias TamanduaServer.Repo

# Get archived events for an agent
from("events_archive",
  where: [agent_id: ^agent_id],
  where: fragment("timestamp > ?", ^cutoff),
  select: [:id, :event_type, :timestamp, :payload]
)
|> Repo.all()

# Count archived events by type
from("events_archive",
  group_by: [:event_type],
  select: {fragment("event_type"), count()}
)
|> Repo.all()
```

## Monitoring

### PubSub Events

The archival worker broadcasts statistics via PubSub:

```elixir
# Subscribe to archival events
Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "event_archival")

# Receive:
# {:archival_stats, %{
#   archived: 45000,
#   sampled: 12300,
#   deleted: 0,
#   kept: 110700,
#   errors: 0,
#   elapsed_ms: 12345
# }}
```

### Metrics

Key metrics to monitor:

- **Events archived per day**: Should match events older than retention period
- **Sampling rate effectiveness**: Ratio of sampled to kept events
- **Archival job duration**: Should complete in <5 minutes
- **Database size**: Should stabilize after retention policy is active

### Logs

```
[ArchiveEventsWorker] Starting event archival and sampling
[ArchiveEventsWorker] Archiving events older than 30 days (cutoff: 2026-01-21 04:00:00Z)
[ArchiveEventsWorker] Archived batch of 5000 events
[ArchiveEventsWorker] Sampling events between 7-30 days old
[ArchiveEventsWorker] Sampled batch: kept=4500, dropped=500
[ArchiveEventsWorker] Completed in 12345ms: archived=45000, sampled=12300, deleted=0, kept=110700, errors=0, dry_run=false
```

## Performance Optimizations

### 1. Null Byte Sanitization

Optimized to only process strings that contain null bytes:

```elixir
defp sanitize_null_bytes(data) when is_binary(data) do
  # Fast path: only replace if null byte is present
  if String.contains?(data, <<0>>) do
    String.replace(data, <<0>>, "")
  else
    data
  end
end
```

### 2. Batch Processing

Archival and sampling operate in configurable batches (default: 5000) to avoid overwhelming the database.

### 3. Index Optimization

- Compound indexes for common query patterns
- Partial indexes for hot data (recent 7 days)
- Conditional indexes for archived/sampled flags

### 4. Compression

TimescaleDB compression reduces storage by ~70-90% for older data:
- Compression kicks in at 7 days
- Segmented by agent_id and event_type
- Ordered by timestamp DESC

## Troubleshooting

### Events Not Being Archived

1. Check if TimescaleDB extension is installed:
   ```sql
   SELECT * FROM pg_extension WHERE extname = 'timescaledb';
   ```

2. Verify retention policy exists:
   ```sql
   SELECT * FROM timescaledb_information.jobs
   WHERE proc_name = 'policy_retention';
   ```

3. Check archival worker is scheduled:
   ```elixir
   Oban.config() |> Map.get(:plugins) |> Enum.find(&match?({Oban.Plugins.Cron, _}, &1))
   ```

### High Database Size

1. Check compression is working:
   ```sql
   SELECT * FROM timescaledb_information.chunks
   WHERE is_compressed = true;
   ```

2. Force compression:
   ```sql
   SELECT compress_chunk(chunk)
   FROM show_chunks('events', older_than => INTERVAL '7 days') AS chunk;
   ```

3. Check retention policy execution:
   ```sql
   SELECT * FROM timescaledb_information.job_stats
   WHERE job_id IN (
     SELECT job_id FROM timescaledb_information.jobs
     WHERE proc_name = 'policy_retention'
   );
   ```

### Sampling Not Working

1. Verify sampling is enabled:
   ```elixir
   Application.get_env(:tamandua_server, TamanduaServer.Telemetry)[:event_sampling_enabled]
   ```

2. Check sampled flag is being set:
   ```sql
   SELECT COUNT(*) FROM events WHERE sampled = true;
   ```

3. Review sampling rate:
   ```elixir
   Application.get_env(:tamandua_server, TamanduaServer.Telemetry)[:event_sampling_rate]
   ```

## Migration Path

### From Existing System

1. **Run migration**: `mix ecto.migrate`
2. **Verify hypertable**: Check TimescaleDB extension and policies
3. **Monitor initial archival**: First run may take longer
4. **Adjust parameters**: Tune retention and sampling based on volume

### Rollback

If needed to roll back:

```bash
# Roll back migration
mix ecto.rollback --step 1

# This will:
# - Drop events_archive table
# - Remove archived/sampled columns
# - Restore 90-day retention policy
# - Drop continuous aggregates
```

## Best Practices

1. **Start conservative**: Use 30-day retention initially, adjust based on needs
2. **Monitor metrics**: Track database size, archival duration, sampling effectiveness
3. **Test queries**: Ensure analytics queries work with continuous aggregates
4. **Plan capacity**: Archive table can grow large, consider S3 export for very old data
5. **Regular reviews**: Review high-value event classification quarterly
6. **Backup strategy**: Include both events and events_archive in backups

## Future Enhancements

- [ ] S3/Azure export for very old archive data (>90 days)
- [ ] Per-organization retention policies
- [ ] Machine learning-based event value classification
- [ ] Real-time compression for very high-volume deployments
- [ ] Archive data encryption at rest
- [ ] Cross-region archive replication
