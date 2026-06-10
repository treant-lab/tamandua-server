# SQL Query DSL - Practical Usage Examples

## Quick Start

### Execute a Simple Query

```elixir
alias TamanduaServer.Hunting.SavedQueries

# Execute SQL query directly
{:ok, result} = SavedQueries.execute_query(
  "SELECT * FROM events WHERE event_type = 'process_create' LIMIT 10",
  user_id: current_user.id
)

# Access results
result.data                    # List of event maps
result.meta.total              # Number of results
result.meta.execution_time_ms  # Query execution time
result.meta.sql                # Generated PostgreSQL
```

### Save and Execute a Query

```elixir
# Create a saved query
{:ok, saved_query} = SavedQueries.create_saved_query(%{
  name: "Suspicious PowerShell",
  description: "Find encoded PowerShell execution",
  query: """
    SELECT * FROM events
    WHERE event_type = 'process_create'
      AND payload->>'process_name' LIKE '%powershell%'
      AND payload->>'cmdline' LIKE '%-enc%'
      AND timestamp > NOW() - INTERVAL '24 hours'
    ORDER BY timestamp DESC
    LIMIT 100
  """,
  query_type: "sql",
  category: "Execution",
  created_by: user.id,
  organization_id: org.id
})

# Execute the saved query
{:ok, result} = SavedQueries.execute_saved_query(
  saved_query.id,
  user_id: user.id
)
```

## Common Threat Hunting Scenarios

### 1. Lateral Movement Detection

```elixir
query = """
  SELECT
    agent_id,
    timestamp,
    event_type,
    payload->>'dst_ip' as destination,
    payload->>'dst_port' as port
  FROM events
  WHERE event_type IN ('network_connect', 'smb_connect', 'rdp_connect')
    AND timestamp > NOW() - INTERVAL '1 hour'
    AND payload->>'dst_port' IN ('445', '3389', '5985')
  ORDER BY timestamp DESC
  LIMIT 200
"""

{:ok, result} = SavedQueries.execute_query(query, user_id: user.id)

# Analyze results
suspicious_connections = Enum.filter(result.data, fn event ->
  event.severity in ["high", "critical"]
end)
```

### 2. Ransomware Indicators

```elixir
# Find mass file modifications (potential ransomware)
query = """
  SELECT
    agent_id,
    COUNT(*) as file_changes,
    COUNT(DISTINCT payload->>'file_extension') as unique_extensions
  FROM events
  WHERE event_type = 'file_modify'
    AND timestamp > NOW() - INTERVAL '5 minutes'
  GROUP BY agent_id
  ORDER BY file_changes DESC
"""

{:ok, result} = SavedQueries.execute_query(query, user_id: user.id)

# Alert on high activity
Enum.each(result.data, fn %{agent_id: agent_id, file_changes: count} ->
  if count > 100 do
    # Trigger alert for potential ransomware
    Alerts.create_alert(%{
      title: "Potential Ransomware Activity",
      description: "Mass file modification detected: #{count} files",
      severity: "critical",
      agent_id: agent_id
    })
  end
end)
```

### 3. Privilege Escalation Hunting

```elixir
query = """
  SELECT * FROM events
  WHERE event_type = 'process_create'
    AND payload->>'is_elevated' = 'true'
    AND payload->>'parent_is_elevated' = 'false'
    AND timestamp > NOW() - INTERVAL '24 hours'
  ORDER BY timestamp DESC
"""

{:ok, result} = SavedQueries.execute_query(query, user_id: user.id)

# Investigate elevation events
elevated_processes = Enum.map(result.data, fn event ->
  %{
    process: event.payload["process_name"],
    parent: event.payload["parent_name"],
    user: event.payload["user"],
    timestamp: event.timestamp
  }
end)
```

### 4. Data Exfiltration Detection

```elixir
query = """
  SELECT
    agent_id,
    payload->>'dst_ip' as destination,
    SUM((payload->>'bytes_sent')::bigint) as total_bytes,
    COUNT(*) as connection_count
  FROM events
  WHERE event_type = 'network_connect'
    AND timestamp > NOW() - INTERVAL '1 hour'
    AND payload->>'dst_port' NOT IN ('80', '443')
  GROUP BY agent_id, payload->>'dst_ip'
  HAVING SUM((payload->>'bytes_sent')::bigint) > 10485760
  ORDER BY total_bytes DESC
"""

# Note: HAVING not yet implemented, use post-processing
query_without_having = """
  SELECT
    agent_id,
    payload->>'dst_ip' as destination,
    SUM((payload->>'bytes_sent')::bigint) as total_bytes,
    COUNT(*) as connection_count
  FROM events
  WHERE event_type = 'network_connect'
    AND timestamp > NOW() - INTERVAL '1 hour'
    AND payload->>'dst_port' NOT IN ('80', '443')
  GROUP BY agent_id, payload->>'dst_ip'
  ORDER BY total_bytes DESC
"""

{:ok, result} = SavedQueries.execute_query(query_without_having, user_id: user.id)

# Filter in Elixir (HAVING substitute)
large_transfers = Enum.filter(result.data, fn row ->
  row.total_bytes > 10_485_760  # 10 MB
end)
```

### 5. Reconnaissance Activity

```elixir
query = """
  SELECT
    agent_id,
    payload->>'process_name' as tool,
    COUNT(*) as execution_count
  FROM events
  WHERE event_type = 'process_create'
    AND timestamp > NOW() - INTERVAL '24 hours'
    AND payload->>'process_name' IN (
      'whoami.exe',
      'ipconfig.exe',
      'net.exe',
      'netstat.exe',
      'systeminfo.exe',
      'tasklist.exe',
      'arp.exe',
      'nslookup.exe'
    )
  GROUP BY agent_id, payload->>'process_name'
  ORDER BY execution_count DESC
"""

{:ok, result} = SavedQueries.execute_query(query, user_id: user.id)

# Identify agents with multiple recon tools
agents_by_tool_count = result.data
|> Enum.group_by(& &1.agent_id)
|> Enum.map(fn {agent_id, tools} ->
  {agent_id, length(tools)}
end)
|> Enum.filter(fn {_agent_id, tool_count} -> tool_count >= 3 end)
```

### 6. Credential Access Attempts

```elixir
query = """
  SELECT * FROM events
  WHERE event_type = 'process_create'
    AND (
      payload->>'process_name' LIKE '%mimikatz%'
      OR payload->>'cmdline' LIKE '%sekurlsa%'
      OR payload->>'cmdline' LIKE '%lsass%'
      OR payload->>'file_path' LIKE '%SAM%'
      OR payload->>'file_path' LIKE '%ntds.dit%'
    )
    AND timestamp > NOW() - INTERVAL '7 days'
  ORDER BY timestamp DESC
"""

{:ok, result} = SavedQueries.execute_query(query, user_id: user.id)
```

## Scheduled Queries

### Setup Daily Security Report

```elixir
defmodule MyApp.SecurityReports do
  alias TamanduaServer.Hunting.SavedQueries

  def daily_security_summary do
    queries = [
      high_severity_events(),
      new_process_activity(),
      network_anomalies(),
      file_system_changes()
    ]

    results = Enum.map(queries, fn {name, query} ->
      case SavedQueries.execute_query(query) do
        {:ok, result} ->
          {name, result.data}

        {:error, reason} ->
          {name, {:error, reason}}
      end
    end)

    # Generate report
    generate_pdf_report(results)
  end

  defp high_severity_events do
    {"High Severity Events", """
      SELECT severity, event_type, COUNT(*) as count
      FROM events
      WHERE severity IN ('high', 'critical')
        AND timestamp > NOW() - INTERVAL '24 hours'
      GROUP BY severity, event_type
      ORDER BY count DESC
    """}
  end

  defp new_process_activity do
    {"New Processes", """
      SELECT DISTINCT payload->>'process_name' as process
      FROM events
      WHERE event_type = 'process_create'
        AND timestamp > NOW() - INTERVAL '24 hours'
      ORDER BY process
    """}
  end

  defp network_anomalies do
    {"Network Anomalies", """
      SELECT
        payload->>'dst_ip' as destination,
        COUNT(*) as connection_count
      FROM events
      WHERE event_type = 'network_connect'
        AND timestamp > NOW() - INTERVAL '24 hours'
        AND payload->>'dst_port' NOT IN ('80', '443', '53')
      GROUP BY payload->>'dst_ip'
      ORDER BY connection_count DESC
      LIMIT 20
    """}
  end

  defp file_system_changes do
    {"File System Changes", """
      SELECT event_type, COUNT(*) as count
      FROM events
      WHERE event_type IN ('file_create', 'file_modify', 'file_delete')
        AND timestamp > NOW() - INTERVAL '24 hours'
      GROUP BY event_type
    """}
  end
end
```

## Real-Time Alerting

### Monitor for Specific Patterns

```elixir
defmodule MyApp.ThreatMonitor do
  use GenServer
  alias TamanduaServer.Hunting.SavedQueries

  def start_link(_) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(state) do
    # Check every 5 minutes
    schedule_check()
    {:ok, state}
  end

  def handle_info(:check_threats, state) do
    check_suspicious_powershell()
    check_privilege_escalation()
    check_lateral_movement()

    schedule_check()
    {:noreply, state}
  end

  defp schedule_check do
    Process.send_after(self(), :check_threats, :timer.minutes(5))
  end

  defp check_suspicious_powershell do
    query = """
      SELECT COUNT(*) as count
      FROM events
      WHERE event_type = 'process_create'
        AND payload->>'process_name' LIKE '%powershell%'
        AND payload->>'cmdline' LIKE '%-enc%'
        AND timestamp > NOW() - INTERVAL '5 minutes'
    """

    case SavedQueries.execute_query(query) do
      {:ok, %{data: [%{count: count}]}} when count > 0 ->
        # Alert
        create_alert("Suspicious PowerShell", count)

      _ ->
        :ok
    end
  end

  defp check_privilege_escalation do
    query = """
      SELECT agent_id, COUNT(*) as count
      FROM events
      WHERE event_type = 'process_create'
        AND payload->>'is_elevated' = 'true'
        AND timestamp > NOW() - INTERVAL '5 minutes'
      GROUP BY agent_id
    """

    case SavedQueries.execute_query(query) do
      {:ok, %{data: agents}} ->
        Enum.each(agents, fn %{agent_id: agent_id, count: count} ->
          if count > 10 do
            create_alert("Multiple privilege escalations on #{agent_id}", count)
          end
        end)

      _ ->
        :ok
    end
  end

  defp check_lateral_movement do
    # Similar pattern for lateral movement detection
    :ok
  end

  defp create_alert(title, count) do
    # Create alert in system
    IO.puts("ALERT: #{title} (#{count} events)")
  end
end
```

## Query Performance Optimization

### Before (Slow)

```elixir
# Don't do this - no time filter, no limit
query = """
  SELECT * FROM events WHERE event_type = 'process_create'
"""
```

### After (Optimized)

```elixir
# Always include time filters and limits
query = """
  SELECT * FROM events
  WHERE event_type = 'process_create'
    AND timestamp > NOW() - INTERVAL '24 hours'
  ORDER BY timestamp DESC
  LIMIT 1000
"""
```

### Using Indexed Fields

```elixir
# Good - filters on indexed fields
query = """
  SELECT * FROM events
  WHERE event_type = 'process_create'
    AND agent_id = 'specific-agent-id'
    AND timestamp > NOW() - INTERVAL '1 hour'
"""

# Slow - filters on non-indexed JSON fields
query = """
  SELECT * FROM events
  WHERE payload->>'process_name' = 'powershell.exe'
"""

# Better - combine indexed and non-indexed
query = """
  SELECT * FROM events
  WHERE event_type = 'process_create'
    AND timestamp > NOW() - INTERVAL '1 hour'
    AND payload->>'process_name' = 'powershell.exe'
"""
```

## Integration with Phoenix LiveView

### Real-Time Query Dashboard

```elixir
defmodule MyAppWeb.QueryLive do
  use MyAppWeb, :live_view
  alias TamanduaServer.Hunting.SavedQueries

  def mount(_params, _session, socket) do
    socket = assign(socket,
      query: "",
      results: [],
      loading: false,
      error: nil
    )

    {:ok, socket}
  end

  def handle_event("execute_query", %{"query" => query}, socket) do
    send(self(), {:run_query, query})

    {:noreply, assign(socket, loading: true, error: nil)}
  end

  def handle_info({:run_query, query}, socket) do
    case SavedQueries.execute_query(query, user_id: socket.assigns.current_user.id) do
      {:ok, result} ->
        {:noreply, assign(socket,
          results: result.data,
          loading: false,
          query: query
        )}

      {:error, reason} ->
        {:noreply, assign(socket,
          error: reason,
          loading: false
        )}
    end
  end

  def render(assigns) do
    ~H"""
    <div class="query-interface">
      <form phx-submit="execute_query">
        <textarea name="query" placeholder="SELECT * FROM events..." />
        <button type="submit">Execute</button>
      </form>

      <%= if @loading do %>
        <div class="loading">Executing query...</div>
      <% end %>

      <%= if @error do %>
        <div class="error"><%= @error %></div>
      <% end %>

      <table>
        <%= for row <- @results do %>
          <tr>
            <td><%= row.event_type %></td>
            <td><%= row.timestamp %></td>
            <td><%= row.severity %></td>
          </tr>
        <% end %>
      </table>
    </div>
    """
  end
end
```

## Advanced Patterns

### Parameterized Query Function

```elixir
defmodule MyApp.Queries do
  alias TamanduaServer.Hunting.SavedQueries

  def find_process_by_name(process_name, hours_ago \\ 24) do
    query = """
      SELECT * FROM events
      WHERE event_type = 'process_create'
        AND payload->>'process_name' = '#{escape(process_name)}'
        AND timestamp > NOW() - INTERVAL '#{hours_ago} hours'
      ORDER BY timestamp DESC
      LIMIT 100
    """

    SavedQueries.execute_query(query)
  end

  def find_high_severity(limit \\ 50) do
    query = """
      SELECT * FROM events
      WHERE severity IN ('high', 'critical')
        AND timestamp > NOW() - INTERVAL '24 hours'
      ORDER BY timestamp DESC
      LIMIT #{limit}
    """

    SavedQueries.execute_query(query)
  end

  defp escape(str) do
    String.replace(str, "'", "''")
  end
end
```

### Query Result Processing Pipeline

```elixir
alias TamanduaServer.Hunting.SavedQueries

query = "SELECT * FROM events WHERE event_type = 'process_create' LIMIT 100"

{:ok, result} = SavedQueries.execute_query(query, user_id: user.id)

# Pipeline processing
enriched_data = result.data
|> Enum.map(&enrich_with_threat_intel/1)
|> Enum.filter(&is_suspicious?/1)
|> Enum.sort_by(& &1.risk_score, :desc)
|> Enum.take(10)

defp enrich_with_threat_intel(event) do
  # Look up process hash, IP, etc.
  threat_score = ThreatIntel.lookup(event.payload["process_hash"])

  Map.put(event, :risk_score, threat_score)
end

defp is_suspicious?(event) do
  event.risk_score > 70
end
```

## Tips & Tricks

### 1. Testing Queries in IEx

```elixir
# Start IEx
iex -S mix

# Test a query
alias TamanduaServer.Hunting.SavedQueries

query = "SELECT DISTINCT event_type FROM events LIMIT 10"

{:ok, result} = SavedQueries.execute_query(query)

result.data |> Enum.map(& &1.event_type)
```

### 2. Query Builder for Complex Queries

```elixir
defmodule QueryHelper do
  def build_threat_hunt_query(opts) do
    base = "SELECT * FROM events"

    where_clauses = []

    where_clauses = if opts[:event_types] do
      ["event_type IN ('#{Enum.join(opts[:event_types], "', '")}')"] ++ where_clauses
    else
      where_clauses
    end

    where_clauses = if opts[:severity] do
      ["severity = '#{opts[:severity]}'"] ++ where_clauses
    else
      where_clauses
    end

    where_clauses = if opts[:hours_ago] do
      ["timestamp > NOW() - INTERVAL '#{opts[:hours_ago]} hours'"] ++ where_clauses
    else
      where_clauses
    end

    where_clause = if where_clauses != [] do
      " WHERE " <> Enum.join(where_clauses, " AND ")
    else
      ""
    end

    limit = " LIMIT #{opts[:limit] || 100}"

    base <> where_clause <> limit
  end
end

# Use it
query = QueryHelper.build_threat_hunt_query(
  event_types: ["process_create", "file_write"],
  severity: "high",
  hours_ago: 24,
  limit: 50
)
```

### 3. Batch Query Execution

```elixir
queries = [
  {"Process Creation", "SELECT COUNT(*) FROM events WHERE event_type = 'process_create'"},
  {"File Operations", "SELECT COUNT(*) FROM events WHERE event_type LIKE 'file_%'"},
  {"Network Activity", "SELECT COUNT(*) FROM events WHERE event_type LIKE 'network_%'"}
]

results = Enum.map(queries, fn {name, query} ->
  case SavedQueries.execute_query(query) do
    {:ok, result} ->
      count = hd(result.data).count
      {name, count}

    {:error, _} ->
      {name, 0}
  end
end)

# Output: [{"Process Creation", 1234}, {"File Operations", 567}, ...]
```

---

**For more examples, see:**
- `README_SQL_QUERY_DSL.md` - Complete syntax reference
- `QUERY_MIGRATION_GUIDE.md` - TQL to SQL conversion examples
- `test/tamandua_server/hunting/query_builder_test.exs` - Test cases
