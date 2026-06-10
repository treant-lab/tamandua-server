# Query Migration Guide: TQL to SQL

## Overview

Tamandua now supports two query syntaxes for threat hunting:

1. **TQL (Tamandua Query Language)** - Pipe-based syntax inspired by KQL/Splunk
2. **SQL-like DSL** - Familiar SQL syntax with SELECT/FROM/WHERE

This guide helps you migrate between syntaxes and choose the right one for your use case.

## When to Use Each Syntax

### Use TQL (Pipe Syntax) When:
- You're familiar with KQL, Splunk SPL, or other pipe-based query languages
- You need advanced pipe operators (extend, summarize, join)
- You want to chain operations in a readable pipeline
- You're working with ClickHouse backend (future)

### Use SQL-like DSL When:
- You're familiar with SQL and prefer traditional SELECT syntax
- You want simple aggregations and grouping
- You need standard WHERE clause logic
- You're querying the PostgreSQL backend

## Syntax Comparison

### Basic Selection

**TQL:**
```
events | where event_type == "process_create" | limit 100
```

**SQL:**
```sql
SELECT * FROM events WHERE event_type = 'process_create' LIMIT 100
```

### Field Selection

**TQL:**
```
events | where event_type == "process_create" | project event_type, timestamp, severity
```

**SQL:**
```sql
SELECT event_type, timestamp, severity FROM events WHERE event_type = 'process_create'
```

### Time Filtering

**TQL:**
```
events | where timestamp > ago(24h)
```

**SQL:**
```sql
SELECT * FROM events WHERE timestamp > NOW() - INTERVAL '24 hours'
```

### Aggregation

**TQL:**
```
events | where event_type == "process_create" | summarize count() by process_name | sort count_ desc
```

**SQL:**
```sql
SELECT COUNT(*) as count
FROM events
WHERE event_type = 'process_create'
GROUP BY process_name
ORDER BY count DESC
```

### Multiple Conditions

**TQL:**
```
events | where event_type == "process_create" and severity == "high"
```

**SQL:**
```sql
SELECT * FROM events WHERE event_type = 'process_create' AND severity = 'high'
```

### IN Operator

**TQL:**
```
events | where event_type in ("process_create", "file_write", "network_connect")
```

**SQL:**
```sql
SELECT * FROM events WHERE event_type IN ('process_create', 'file_write', 'network_connect')
```

### String Matching

**TQL:**
```
events | where process_name contains "powershell"
```

**SQL:**
```sql
SELECT * FROM events WHERE process_name LIKE '%powershell%'
```

**TQL:**
```
events | where process_name startswith "cmd"
```

**SQL:**
```sql
SELECT * FROM events WHERE process_name LIKE 'cmd%'
```

### Distinct Values

**TQL:**
```
events | summarize dcount(event_type)
```

**SQL:**
```sql
SELECT COUNT(DISTINCT event_type) FROM events
```

### Sorting

**TQL:**
```
events | sort timestamp desc | limit 100
```

**SQL:**
```sql
SELECT * FROM events ORDER BY timestamp DESC LIMIT 100
```

## Migration Examples

### Example 1: Top Processes

**TQL:**
```
events
| where event_type == "process_create"
| where timestamp > ago(24h)
| summarize count() by process_name
| sort count_ desc
| limit 10
```

**SQL:**
```sql
SELECT process_name, COUNT(*) as count
FROM events
WHERE event_type = 'process_create'
  AND timestamp > NOW() - INTERVAL '24 hours'
GROUP BY process_name
ORDER BY count DESC
LIMIT 10
```

### Example 2: High Severity Events

**TQL:**
```
events
| where severity in ("high", "critical")
| where timestamp > ago(1h)
| project timestamp, event_type, severity, agent_id
| sort timestamp desc
```

**SQL:**
```sql
SELECT timestamp, event_type, severity, agent_id
FROM events
WHERE severity IN ('high', 'critical')
  AND timestamp > NOW() - INTERVAL '1 hour'
ORDER BY timestamp DESC
```

### Example 3: Network Activity

**TQL:**
```
events
| where event_type == "network_connect"
| where dst_port in (443, 8443, 4444)
| summarize count() by dst_ip, dst_port
| sort count_ desc
```

**SQL:**
```sql
SELECT dst_ip, dst_port, COUNT(*) as count
FROM events
WHERE event_type = 'network_connect'
  AND dst_port IN (443, 8443, 4444)
GROUP BY dst_ip, dst_port
ORDER BY count DESC
```

## Feature Comparison Matrix

| Feature | TQL | SQL | Notes |
|---------|-----|-----|-------|
| Basic filtering | ✅ | ✅ | Both support WHERE/where |
| Field selection | ✅ | ✅ | project vs SELECT |
| Aggregations | ✅ | ✅ | Both support COUNT, SUM, etc. |
| GROUP BY | ✅ | ✅ | summarize...by vs GROUP BY |
| ORDER BY | ✅ | ✅ | sort vs ORDER BY |
| LIMIT | ✅ | ✅ | limit/take vs LIMIT |
| DISTINCT | ✅ | ✅ | dcount vs DISTINCT |
| Joins | ✅ | ❌ | TQL supports join operator |
| Extend | ✅ | ❌ | TQL can add computed fields |
| Has operator | ✅ | ❌ | TQL has text search |
| Subqueries | ❌ | ❌ | Neither supports yet |
| HAVING | ❌ | ❌ | Neither supports yet |

## Automatic Detection

The system automatically detects query type:

```elixir
# This will use SQL parser
SavedQueries.execute_query("SELECT * FROM events LIMIT 10")

# This will use TQL parser
SavedQueries.execute_query("events | where event_type == 'process_create'")
```

Detection rules:
1. If query starts with `SELECT` → SQL parser
2. If query contains `|` → TQL parser
3. Otherwise → Custom handler

## Best Practices

### For SQL Queries:
1. Always include timestamp filters to limit dataset
2. Use LIMIT to prevent excessive results
3. Leverage GROUP BY for aggregations
4. Use indexed fields (event_type, timestamp, agent_id) in WHERE

### For TQL Queries:
1. Put where operators early in the pipeline
2. Use project to reduce field count before aggregations
3. Chain operators for readable queries
4. Use ago() for relative time ranges

## Performance Tips

### Optimization for Both Syntaxes:

1. **Filter Early**
   - Apply WHERE/where clauses as early as possible
   - Filter by indexed fields (event_type, timestamp)

2. **Limit Results**
   - Always include LIMIT/limit
   - Default: 1000, Maximum: 10,000

3. **Use Time Windows**
   - Avoid querying all historical data
   - Use NOW() - INTERVAL or ago()

4. **Avoid Wildcard Searches**
   - `LIKE '%pattern%'` is slow
   - Use specific patterns when possible

5. **Payload Field Access**
   - Top-level fields are faster than payload fields
   - Cache frequently accessed payload values

## Common Pitfalls

### SQL Pitfalls:

1. **Forgetting Quotes**
   ```sql
   -- Wrong
   SELECT * FROM events WHERE event_type = process_create

   -- Correct
   SELECT * FROM events WHERE event_type = 'process_create'
   ```

2. **Case Sensitivity**
   - Keywords can be uppercase or lowercase
   - String values are case-sensitive

3. **Interval Syntax**
   ```sql
   -- Wrong
   WHERE timestamp > NOW() - 1 hour

   -- Correct
   WHERE timestamp > NOW() - INTERVAL '1 hour'
   ```

### TQL Pitfalls:

1. **Operator vs Keyword**
   ```
   # Wrong
   events | where event_type = "process"

   # Correct
   events | where event_type == "process"
   ```

2. **String Literals**
   ```
   # Wrong
   events | where process_name == powershell

   # Correct
   events | where process_name == "powershell"
   ```

## Examples Library

### Reconnaissance Detection

**SQL:**
```sql
SELECT event_type, COUNT(*) as count
FROM events
WHERE event_type IN ('process_create', 'network_connect')
  AND timestamp > NOW() - INTERVAL '10 minutes'
  AND agent_id = 'specific-agent-id'
GROUP BY event_type
```

**TQL:**
```
events
| where agent_id == "specific-agent-id"
| where timestamp > ago(10m)
| where event_type in ("process_create", "network_connect")
| summarize count() by event_type
```

### Suspicious PowerShell

**SQL:**
```sql
SELECT * FROM events
WHERE event_type = 'process_create'
  AND process_name LIKE '%powershell%'
  AND cmdline LIKE '%-enc%'
  AND timestamp > NOW() - INTERVAL '24 hours'
ORDER BY timestamp DESC
```

**TQL:**
```
events
| where event_type == "process_create"
| where process_name contains "powershell"
| where cmdline contains "-enc"
| where timestamp > ago(24h)
| sort timestamp desc
```

### Event Timeline

**SQL:**
```sql
SELECT timestamp, event_type, severity
FROM events
WHERE agent_id = 'agent-123'
  AND timestamp BETWEEN '2024-01-01' AND '2024-01-02'
ORDER BY timestamp ASC
```

**TQL:**
```
events
| where agent_id == "agent-123"
| where timestamp between (datetime(2024-01-01) .. datetime(2024-01-02))
| project timestamp, event_type, severity
| sort timestamp asc
```

## Mixing Syntaxes

You can use both syntaxes in the same application:

```elixir
# SQL for simple queries
{:ok, result1} = SavedQueries.execute_query(
  "SELECT * FROM events WHERE severity = 'high' LIMIT 100"
)

# TQL for complex pipelines
{:ok, result2} = SavedQueries.execute_query(
  "events | where severity == 'high' | summarize count() by event_type | top 10 by count_"
)
```

## Getting Help

- SQL Reference: See `README_SQL_QUERY_DSL.md`
- TQL Reference: See `query_language.ex` module documentation
- Examples: Check `saved_queries.ex` default templates

## Future Roadmap

- [ ] Unified parser supporting both syntaxes
- [ ] Query optimizer for both formats
- [ ] Automatic query conversion (TQL ↔ SQL)
- [ ] Query builder UI with visual query construction
- [ ] Query explanation/EXPLAIN support
