-- ClickHouse schema for agent logs storage
-- High-performance columnar storage for log data

-- Create database
CREATE DATABASE IF NOT EXISTS tamandua;

-- Create agent_logs table
CREATE TABLE IF NOT EXISTS tamandua.agent_logs
(
    -- Primary fields
    timestamp UInt64 COMMENT 'Log timestamp in milliseconds since epoch',
    agent_id String COMMENT 'Agent identifier',
    level LowCardinality(String) COMMENT 'Log level: trace, debug, info, warn, error',
    component LowCardinality(String) COMMENT 'Component name: collectors, transport, response, etc.',
    message String COMMENT 'Log message',

    -- Optional fields
    fields String COMMENT 'JSON-encoded structured fields',
    file Nullable(String) COMMENT 'Source file name',
    line Nullable(UInt32) COMMENT 'Source line number',
    thread Nullable(String) COMMENT 'Thread name',

    -- Computed fields
    date Date DEFAULT toDate(timestamp / 1000) COMMENT 'Date for partitioning',
    hour UInt8 DEFAULT toHour(toDateTime(timestamp / 1000)) COMMENT 'Hour for time-based queries'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (agent_id, timestamp)
TTL date + INTERVAL 90 DAY  -- Retain logs for 90 days
SETTINGS index_granularity = 8192;

-- Create materialized view for log statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS tamandua.agent_logs_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (agent_id, level, component, hour, date)
AS
SELECT
    agent_id,
    level,
    component,
    hour,
    date,
    count() AS log_count,
    countIf(level = 'error') AS error_count,
    countIf(level = 'warn') AS warn_count
FROM tamandua.agent_logs
GROUP BY agent_id, level, component, hour, date;

-- Create materialized view for error pattern tracking
CREATE MATERIALIZED VIEW IF NOT EXISTS tamandua.agent_logs_errors
ENGINE = MergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (agent_id, timestamp)
AS
SELECT
    timestamp,
    agent_id,
    level,
    component,
    message,
    file,
    line,
    date
FROM tamandua.agent_logs
WHERE level IN ('error', 'warn');

-- Indexes for faster queries
-- Full-text search index on message
ALTER TABLE tamandua.agent_logs ADD INDEX idx_message_tokens message TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4;

-- Agent ID index
ALTER TABLE tamandua.agent_logs ADD INDEX idx_agent_id agent_id TYPE bloom_filter GRANULARITY 4;

-- Component index
ALTER TABLE tamandua.agent_logs ADD INDEX idx_component component TYPE bloom_filter GRANULARITY 4;

-- Comments
COMMENT ON COLUMN tamandua.agent_logs.timestamp IS 'Log timestamp in milliseconds since Unix epoch';
COMMENT ON COLUMN tamandua.agent_logs.agent_id IS 'Unique identifier of the agent that generated this log';
COMMENT ON COLUMN tamandua.agent_logs.level IS 'Log severity level';
COMMENT ON COLUMN tamandua.agent_logs.component IS 'Agent component that generated the log';
COMMENT ON COLUMN tamandua.agent_logs.message IS 'Human-readable log message';
COMMENT ON COLUMN tamandua.agent_logs.fields IS 'Additional structured data in JSON format';

-- Sample queries for reference:

-- Query 1: Get recent logs for a specific agent
-- SELECT * FROM tamandua.agent_logs
-- WHERE agent_id = 'agent-123'
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Query 2: Count errors by component in the last hour
-- SELECT component, count() as error_count
-- FROM tamandua.agent_logs
-- WHERE level = 'error'
--   AND timestamp >= now() - INTERVAL 1 HOUR
-- GROUP BY component
-- ORDER BY error_count DESC;

-- Query 3: Search logs by keyword
-- SELECT timestamp, agent_id, level, message
-- FROM tamandua.agent_logs
-- WHERE positionCaseInsensitive(message, 'timeout') > 0
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Query 4: Get log statistics by agent and level
-- SELECT agent_id, level, count() as log_count
-- FROM tamandua.agent_logs
-- WHERE date = today()
-- GROUP BY agent_id, level;
