# SQL-Like Query DSL for Threat Hunting

## Overview

The Tamandua EDR platform now supports a SQL-like Domain-Specific Language (DSL) for querying telemetry events. This provides an intuitive, familiar syntax for security analysts to hunt for threats across endpoint data.

## Architecture

```
┌─────────────────┐
│  SQL-like Query │
│  "SELECT ..."   │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ QueryBuilder    │
│ - Parse SQL     │
│ - Build Ecto    │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Ecto Query      │
│ (PostgreSQL)    │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Event Results   │
└─────────────────┘
```

## Files

- **`query_builder.ex`**: Main module for SQL-like query parsing and execution
- **`saved_queries.ex`**: Enhanced with `execute_saved_query/2` and `execute_query/2`
- **`saved_query.ex`**: Schema updated to include "sql" query type
- **`query_builder_test.exs`**: Comprehensive test suite

## Syntax Reference

### Basic SELECT

```sql
SELECT * FROM events LIMIT 100
```

```sql
SELECT event_type, timestamp, severity FROM events LIMIT 50
```

### WHERE Clauses

#### Comparison Operators

```sql
SELECT * FROM events WHERE event_type = 'process_create'
SELECT * FROM events WHERE severity != 'low'
SELECT * FROM events WHERE timestamp > NOW() - INTERVAL '1 hour'
```

Supported operators: `=`, `!=`, `<>`, `>`, `<`, `>=`, `<=`

#### Logical Operators

```sql
SELECT * FROM events
WHERE event_type = 'process_create' AND severity = 'high'
```

```sql
SELECT * FROM events
WHERE severity = 'high' OR severity = 'critical'
```

Supported: `AND`, `OR`

#### IN / NOT IN

```sql
SELECT * FROM events
WHERE event_type IN ('process_create', 'file_write', 'network_connect')
```

```sql
SELECT * FROM events
WHERE severity NOT IN ('low', 'info')
```

#### LIKE (Pattern Matching)

```sql
SELECT * FROM events WHERE event_type LIKE '%process%'
```

#### REGEX (Regular Expressions)

```sql
SELECT * FROM events WHERE event_type REGEX '^process_.*'
```

#### BETWEEN

```sql
SELECT * FROM events
WHERE timestamp BETWEEN '2024-01-01' AND '2024-12-31'
```

### Time Functions

#### NOW()

```sql
SELECT * FROM events WHERE timestamp > NOW() - INTERVAL '24 hours'
```

Supported intervals:
- `INTERVAL 'N seconds'`
- `INTERVAL 'N minutes'`
- `INTERVAL 'N hours'`
- `INTERVAL 'N days'`
- `INTERVAL 'N weeks'`
- `INTERVAL 'N months'`

### Aggregations

#### COUNT(*)

```sql
SELECT COUNT(*) as total FROM events
WHERE event_type = 'process_create'
```

#### COUNT(DISTINCT field)

```sql
SELECT COUNT(DISTINCT event_type) as unique_types FROM events
```

#### Other Aggregations

```sql
-- SUM
SELECT SUM(payload->>'size') as total_bytes FROM events

-- AVG
SELECT AVG(payload->>'duration') as avg_duration FROM events

-- MIN / MAX
SELECT MIN(timestamp) as first_seen, MAX(timestamp) as last_seen FROM events
```

### GROUP BY

```sql
SELECT event_type, COUNT(*) as count
FROM events
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY event_type
ORDER BY count DESC
```

```sql
SELECT severity, event_type, COUNT(*) as count
FROM events
GROUP BY severity, event_type
ORDER BY count DESC
LIMIT 20
```

### ORDER BY

```sql
SELECT * FROM events ORDER BY timestamp DESC LIMIT 100
```

```sql
SELECT event_type, COUNT(*) as count
FROM events
GROUP BY event_type
ORDER BY count DESC, event_type ASC
```

### DISTINCT

```sql
SELECT DISTINCT event_type FROM events
WHERE timestamp > NOW() - INTERVAL '7 days'
```

### LIMIT

```sql
SELECT * FROM events LIMIT 1000
```

Default limit: 1000 rows
Maximum limit: 10000 rows

## Field Mappings

### Top-Level Event Schema Fields

These fields map directly to the `events` table:

- `id` - Event UUID
- `event_type` - Type of event (process_create, file_write, etc.)
- `timestamp` - Event occurrence time (UTC)
- `severity` - Severity level (low, medium, high, critical)
- `agent_id` - UUID of the agent that generated the event
- `created_at` - Event ingestion time
- `sha256` - File hash (if applicable)
- `enrichment` - JSONB enrichment data

### Payload Fields

Event-specific data is stored in the `payload` JSONB field. Access via field name:

```sql
-- These are automatically mapped to payload->>'field_name'
SELECT process_name, pid FROM events WHERE event_type = 'process_create'
```

Common payload fields:
- **Process events**: `process_name`, `pid`, `ppid`, `cmdline`, `user`
- **File events**: `file_path`, `file_name`, `operation`, `size`
- **Network events**: `dst_ip`, `dst_port`, `src_ip`, `src_port`, `protocol`
- **DNS events**: `query`, `query_type`, `answer`
- **Registry events**: `key`, `value`, `operation`

## Example Queries

### Top 10 Most Common Processes

```sql
SELECT COUNT(*) as count, event_type
FROM events
WHERE event_type = 'process_create'
  AND timestamp > NOW() - INTERVAL '24 hours'
GROUP BY event_type
ORDER BY count DESC
LIMIT 10
```

### Recent High-Severity Events

```sql
SELECT * FROM events
WHERE severity IN ('high', 'critical')
  AND timestamp > NOW() - INTERVAL '1 hour'
ORDER BY timestamp DESC
LIMIT 50
```

### Event Type Distribution

```sql
SELECT event_type, COUNT(*) as count
FROM events
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY event_type
ORDER BY count DESC
```

### Find Suspicious PowerShell Execution

```sql
SELECT * FROM events
WHERE event_type = 'process_create'
  AND payload->>'process_name' LIKE '%powershell%'
  AND timestamp > NOW() - INTERVAL '7 days'
ORDER BY timestamp DESC
LIMIT 100
```

### Network Connections to External IPs

```sql
SELECT DISTINCT payload->>'dst_ip' as destination
FROM events
WHERE event_type = 'network_connect'
  AND timestamp > NOW() - INTERVAL '1 hour'
ORDER BY destination
```

### Events by Agent

```sql
SELECT agent_id, COUNT(*) as event_count
FROM events
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY agent_id
ORDER BY event_count DESC
```

## API Usage

### Execute Query Directly

```elixir
alias TamanduaServer.Hunting.QueryBuilder

query = "SELECT * FROM events WHERE event_type = 'process_create' LIMIT 10"

{:ok, result} = QueryBuilder.execute(query)

# Result structure:
%{
  data: [...],  # List of event records
  meta: %{
    query_dsl: "SELECT ...",
    sql: "SELECT ...",  # Generated PostgreSQL
    total: 10,
    execution_time_ms: 42
  }
}
```

### Execute Saved Query

```elixir
alias TamanduaServer.Hunting.SavedQueries

# Execute by ID
{:ok, result} = SavedQueries.execute_saved_query(query_id, user_id: current_user.id)

# Execute arbitrary query string (auto-detects SQL vs TQL)
{:ok, result} = SavedQueries.execute_query(
  "SELECT COUNT(*) FROM events WHERE severity = 'high'",
  user_id: current_user.id
)
```

### Create and Save SQL Query

```elixir
{:ok, query} = SavedQueries.create_saved_query(%{
  name: "My Custom Query",
  description: "Find all high-severity events",
  query: "SELECT * FROM events WHERE severity = 'high' LIMIT 100",
  query_type: "sql",
  created_by: user.id,
  organization_id: org.id
})
```

## Query Type Detection

The system automatically detects query types:

1. **SQL-like** - Starts with `SELECT` → Uses `QueryBuilder`
2. **TQL pipe** - Contains `|` → Uses `QueryCompiler`
3. **Custom** - Other syntax → Falls back to custom handling

## Limitations

### Current Limitations

1. **No Subqueries**: Nested SELECT statements are not supported
2. **No JOINs**: Only single-table queries (events)
3. **Limited Functions**: Only basic aggregations (COUNT, SUM, AVG, MIN, MAX)
4. **No HAVING**: Post-aggregation filtering not yet implemented
5. **Simple WHERE Parsing**: Complex parenthesized logic may not work

### Performance Considerations

1. **LIMIT Queries**: Always use LIMIT to avoid loading excessive data
2. **Time Filters**: Include timestamp filters to reduce dataset size
3. **Indexed Fields**: Queries on `event_type`, `timestamp`, `agent_id` are optimized
4. **Payload Queries**: JSON field access is slower than schema fields

## Future Enhancements

- [ ] Support for `HAVING` clause
- [ ] Subquery support
- [ ] More scalar functions (UPPER, LOWER, LENGTH, etc.)
- [ ] Date/time functions (DATE_TRUNC, EXTRACT, etc.)
- [ ] Window functions (ROW_NUMBER, RANK, etc.)
- [ ] JOIN support for alerts, agents tables
- [ ] Query optimization hints
- [ ] Parameterized queries
- [ ] Query caching

## Testing

Run the test suite:

```bash
mix test test/tamandua_server/hunting/query_builder_test.exs
```

## Related Documentation

- **TQL (Pipe Syntax)**: See `query_language.ex` for the original pipe-based syntax
- **Query Compiler**: See `query_compiler.ex` for TQL compilation
- **Saved Queries**: See `saved_queries.ex` for query management

## Security Notes

- All queries are executed with the permissions of the authenticated user
- Query results are limited by organization/tenant boundaries
- SQL injection is prevented through Ecto parameterized queries
- Maximum query result size is enforced (10,000 rows)

## Examples in Production

### Threat Hunting Scenarios

1. **Lateral Movement Detection**
```sql
SELECT * FROM events
WHERE event_type IN ('network_connect', 'smb_access')
  AND timestamp > NOW() - INTERVAL '24 hours'
ORDER BY timestamp DESC
```

2. **Ransomware Indicators**
```sql
SELECT COUNT(*) as file_ops, agent_id
FROM events
WHERE event_type = 'file_modify'
  AND timestamp > NOW() - INTERVAL '5 minutes'
GROUP BY agent_id
HAVING COUNT(*) > 100
```

3. **Privileged Escalation**
```sql
SELECT * FROM events
WHERE event_type = 'process_create'
  AND payload->>'is_elevated' = 'true'
  AND timestamp > NOW() - INTERVAL '1 hour'
```
