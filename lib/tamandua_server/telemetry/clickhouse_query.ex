defmodule TamanduaServer.Telemetry.ClickHouseQuery do
  @moduledoc """
  Query interface for ClickHouse telemetry data.

  Provides parameterized query functions for common EDR access patterns:
  - Full-text event search
  - Agent timelines
  - Process activity rankings
  - Network connection summaries
  - DNS query pattern analysis
  - Storage usage statistics

  All queries use escaped/parameterized inputs to prevent SQL injection.
  Queries have a configurable timeout (default 30s).
  """

  require Logger

  @finch_name TamanduaServer.Finch
  @default_query_timeout 30_000

  # ── Event Search ────────────────────────────────────────────────────

  @doc """
  Search telemetry events with flexible filters.

  ## Options
    - `:agent_id`        - Filter by agent ID
    - `:event_type`      - Filter by event type
    - `:severity`        - Filter by severity (info, low, medium, high, critical)
    - `:from`            - Start time (DateTime, ISO8601 string, or unix ms)
    - `:to`              - End time (DateTime, ISO8601 string, or unix ms)
    - `:keyword`         - Full-text search in payload JSON
    - `:mitre_technique` - Filter by MITRE ATT&CK technique ID
    - `:limit`           - Max results (default 100, max 10000)
    - `:offset`          - Pagination offset (default 0)
  """
  @spec search_events(keyword()) :: {:ok, list(map())} | {:error, term()}
  def search_events(filters \\ []) do
    {where_clauses, _params} = build_where_clauses(filters)
    limit = min(Keyword.get(filters, :limit, 100), 10_000)
    offset = Keyword.get(filters, :offset, 0)

    sql = """
    SELECT
      event_id, timestamp, agent_id, event_type, severity,
      process_name, process_id, command_line, user_name,
      file_path, file_hash, dns_query,
      rule_name, mitre_technique, mitre_tactic, threat_score,
      payload
    FROM tamandua.telemetry_events
    #{where_sql(where_clauses)}
    ORDER BY timestamp DESC
    LIMIT #{limit} OFFSET #{offset}
    FORMAT JSON
    """

    execute(sql)
  end

  # ── Timeline ────────────────────────────────────────────────────────

  @doc """
  Retrieve a chronological timeline of events for an agent within a time range.

  Returns events ordered by timestamp ascending for timeline display.
  """
  @spec timeline(String.t(), DateTime.t() | String.t(), DateTime.t() | String.t(), keyword()) ::
          {:ok, list(map())} | {:error, term()}
  def timeline(agent_id, start_time, end_time, opts \\ []) do
    limit = min(Keyword.get(opts, :limit, 1000), 50_000)

    sql = """
    SELECT
      event_id, timestamp, event_type, severity,
      process_name, process_id, command_line,
      mitre_technique, mitre_tactic, threat_score,
      payload
    FROM tamandua.telemetry_events
    WHERE agent_id = '#{escape(agent_id)}'
      AND timestamp >= '#{format_dt(start_time)}'
      AND timestamp <= '#{format_dt(end_time)}'
    ORDER BY timestamp ASC
    LIMIT #{limit}
    FORMAT JSON
    """

    execute(sql)
  end

  # ── Top Processes ───────────────────────────────────────────────────

  @doc """
  Return the most active processes for an agent within the last N hours.

  Results are ordered by event count descending.
  """
  @spec top_processes(String.t(), pos_integer(), keyword()) ::
          {:ok, list(map())} | {:error, term()}
  def top_processes(agent_id, hours \\ 24, opts \\ []) do
    limit = min(Keyword.get(opts, :limit, 50), 1000)

    sql = """
    SELECT
      process_name,
      count() AS event_count,
      min(timestamp) AS first_seen,
      max(timestamp) AS last_seen,
      groupUniqArray(10)(command_line) AS sample_commands,
      countIf(is_elevated = 1) AS elevated_count
    FROM tamandua.process_events
    WHERE agent_id = '#{escape(agent_id)}'
      AND timestamp >= now() - INTERVAL #{max(hours, 1)} HOUR
    GROUP BY process_name
    ORDER BY event_count DESC
    LIMIT #{limit}
    FORMAT JSON
    """

    execute(sql)
  end

  # ── Network Summary ─────────────────────────────────────────────────

  @doc """
  Summarize network connection statistics for an agent.

  Returns top destination IPs, ports, and byte counts.
  """
  @spec network_summary(String.t(), pos_integer(), keyword()) ::
          {:ok, list(map())} | {:error, term()}
  def network_summary(agent_id, hours \\ 24, opts \\ []) do
    limit = min(Keyword.get(opts, :limit, 50), 1000)

    sql = """
    SELECT
      dest_ip,
      dest_port,
      protocol,
      count() AS connection_count,
      sum(bytes_sent) AS total_bytes_sent,
      sum(bytes_received) AS total_bytes_received,
      groupUniqArray(5)(process_name) AS processes,
      min(timestamp) AS first_seen,
      max(timestamp) AS last_seen
    FROM tamandua.network_flows
    WHERE agent_id = '#{escape(agent_id)}'
      AND timestamp >= now() - INTERVAL #{max(hours, 1)} HOUR
    GROUP BY dest_ip, dest_port, protocol
    ORDER BY connection_count DESC
    LIMIT #{limit}
    FORMAT JSON
    """

    execute(sql)
  end

  # ── DNS Summary ─────────────────────────────────────────────────────

  @doc """
  Summarize DNS query patterns for an agent.

  Returns top queried domains with frequency counts.
  """
  @spec dns_summary(String.t(), pos_integer(), keyword()) ::
          {:ok, list(map())} | {:error, term()}
  def dns_summary(agent_id, hours \\ 24, opts \\ []) do
    limit = min(Keyword.get(opts, :limit, 100), 5000)

    sql = """
    SELECT
      query_name,
      count() AS query_count,
      groupUniqArray(5)(query_type) AS query_types,
      countIf(is_suspicious = 1) AS suspicious_count,
      groupUniqArray(5)(process_name) AS querying_processes,
      min(timestamp) AS first_seen,
      max(timestamp) AS last_seen
    FROM tamandua.dns_queries
    WHERE agent_id = '#{escape(agent_id)}'
      AND timestamp >= now() - INTERVAL #{max(hours, 1)} HOUR
    GROUP BY query_name
    ORDER BY query_count DESC
    LIMIT #{limit}
    FORMAT JSON
    """

    execute(sql)
  end

  # ── File Events ───────────────────────────────────────────────────

  @doc """
  Query file events for an agent within the last N hours.

  Returns file activity (create, modify, delete, rename) ordered by timestamp.
  """
  @spec file_events(String.t(), pos_integer(), keyword()) ::
          {:ok, list(map())} | {:error, term()}
  def file_events(agent_id, hours \\ 24, opts \\ []) do
    limit = min(Keyword.get(opts, :limit, 100), 10_000)

    sql = """
    SELECT
      event_id, timestamp, file_path, file_action, file_hash,
      file_size, process_id, process_name, user_name, is_suspicious
    FROM tamandua.file_events
    WHERE agent_id = '#{escape(agent_id)}'
      AND timestamp >= now() - INTERVAL #{max(hours, 1)} HOUR
    ORDER BY timestamp DESC
    LIMIT #{limit}
    FORMAT JSON
    """

    execute(sql)
  end

  # ── Registry Events ─────────────────────────────────────────────────

  @doc """
  Query registry events for an agent within the last N hours.

  Returns registry activity (create, modify, delete) ordered by timestamp.
  Windows-specific: returns empty results for non-Windows agents.
  """
  @spec registry_events(String.t(), pos_integer(), keyword()) ::
          {:ok, list(map())} | {:error, term()}
  def registry_events(agent_id, hours \\ 24, opts \\ []) do
    limit = min(Keyword.get(opts, :limit, 100), 10_000)

    sql = """
    SELECT
      event_id, timestamp, registry_key, registry_value,
      registry_action, registry_data, registry_type,
      process_id, process_name, user_name, is_suspicious
    FROM tamandua.registry_events
    WHERE agent_id = '#{escape(agent_id)}'
      AND timestamp >= now() - INTERVAL #{max(hours, 1)} HOUR
    ORDER BY timestamp DESC
    LIMIT #{limit}
    FORMAT JSON
    """

    execute(sql)
  end

  # ── Alert Events ─────────────────────────────────────────────────────

  @doc """
  Query alert events with optional filters.

  ## Options
    - `:agent_id`        - Filter by agent ID
    - `:severity`        - Filter by severity (info, low, medium, high, critical)
    - `:rule_name`       - Filter by detection rule name
    - `:mitre_technique` - Filter by MITRE ATT&CK technique ID
    - `:from`            - Start time (DateTime, ISO8601 string, or unix ms)
    - `:to`              - End time (DateTime, ISO8601 string, or unix ms)
    - `:limit`           - Max results (default 100, max 10000)
    - `:offset`          - Pagination offset (default 0)
  """
  @spec alert_events(keyword()) :: {:ok, list(map())} | {:error, term()}
  def alert_events(filters \\ []) do
    clauses = []

    clauses =
      if id = Keyword.get(filters, :agent_id) do
        clauses ++ ["agent_id = '#{escape(id)}'"]
      else
        clauses
      end

    clauses =
      if sev = Keyword.get(filters, :severity) do
        clauses ++ ["severity = '#{escape(sev)}'"]
      else
        clauses
      end

    clauses =
      if rule = Keyword.get(filters, :rule_name) do
        clauses ++ ["rule_name = '#{escape(rule)}'"]
      else
        clauses
      end

    clauses =
      if technique = Keyword.get(filters, :mitre_technique) do
        clauses ++ ["mitre_technique = '#{escape(technique)}'"]
      else
        clauses
      end

    clauses =
      if from = Keyword.get(filters, :from) do
        clauses ++ ["timestamp >= '#{format_dt(from)}'"]
      else
        clauses
      end

    clauses =
      if to = Keyword.get(filters, :to) do
        clauses ++ ["timestamp <= '#{format_dt(to)}'"]
      else
        clauses
      end

    limit = min(Keyword.get(filters, :limit, 100), 10_000)
    offset = Keyword.get(filters, :offset, 0)

    sql = """
    SELECT
      event_id, timestamp, agent_id, alert_id, rule_name,
      severity, mitre_technique, mitre_tactic, details,
      source_event_id, process_name, process_id,
      command_line, file_path, file_hash, source_ip, dest_ip, verdict
    FROM tamandua.alert_events
    #{where_sql(clauses)}
    ORDER BY timestamp DESC
    LIMIT #{limit} OFFSET #{offset}
    FORMAT JSON
    """

    execute(sql)
  end

  # ── Event Count Aggregation ─────────────────────────────────────────

  @doc """
  Aggregate event counts using the materialized hourly view.

  Efficient for dashboard charts that need per-hour or per-day counts.
  """
  @spec event_counts(keyword()) :: {:ok, list(map())} | {:error, term()}
  def event_counts(filters \\ []) do
    agent_filter =
      case Keyword.get(filters, :agent_id) do
        nil -> ""
        id -> "AND agent_id = '#{escape(id)}'"
      end

    hours = Keyword.get(filters, :hours, 24)

    sql = """
    SELECT
      hour,
      event_type,
      sum(event_count) AS total_events,
      sum(critical_count) AS total_critical
    FROM tamandua.event_counts_hourly
    WHERE hour >= now() - INTERVAL #{max(hours, 1)} HOUR
      #{agent_filter}
    GROUP BY hour, event_type
    ORDER BY hour ASC
    FORMAT JSON
    """

    execute(sql)
  end

  # ── Storage Statistics ──────────────────────────────────────────────

  @doc """
  Return ClickHouse storage usage statistics for health monitoring.

  Reports total rows, disk bytes, and partition counts per table.
  """
  @spec storage_stats() :: {:ok, list(map())} | {:error, term()}
  def storage_stats do
    sql = """
    SELECT
      table,
      sum(rows) AS total_rows,
      sum(bytes_on_disk) AS disk_bytes,
      formatReadableSize(sum(bytes_on_disk)) AS disk_size_human,
      count() AS partition_count,
      min(min_date) AS oldest_data,
      max(max_date) AS newest_data
    FROM system.parts
    WHERE database = 'tamandua'
      AND active = 1
    GROUP BY table
    ORDER BY disk_bytes DESC
    FORMAT JSON
    """

    execute(sql)
  end

  # ── IOC Search (cross-table) ────────────────────────────────────────

  @doc """
  Search across all ClickHouse tables for an indicator of compromise.

  Searches telemetry payload, process hashes/commands, DNS domains,
  and network IPs concurrently.
  """
  @spec search_ioc(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def search_ioc(ioc_value, opts \\ []) do
    limit = min(Keyword.get(opts, :limit, 100), 1000)
    escaped = escape(ioc_value)

    queries = %{
      telemetry: """
        SELECT 'telemetry' AS source, event_id, agent_id, event_type, timestamp, payload
        FROM tamandua.telemetry_events
        WHERE payload LIKE '%#{escaped}%'
        ORDER BY timestamp DESC LIMIT #{limit}
        FORMAT JSON
      """,
      process: """
        SELECT 'process' AS source, event_id, agent_id, process_name, command_line, file_hash, timestamp
        FROM tamandua.process_events
        WHERE file_hash = '#{escaped}' OR command_line LIKE '%#{escaped}%'
        ORDER BY timestamp DESC LIMIT #{limit}
        FORMAT JSON
      """,
      file: """
        SELECT 'file' AS source, event_id, agent_id, file_path, file_action, file_hash, timestamp
        FROM tamandua.file_events
        WHERE file_hash = '#{escaped}' OR file_path LIKE '%#{escaped}%'
        ORDER BY timestamp DESC LIMIT #{limit}
        FORMAT JSON
      """,
      dns: """
        SELECT 'dns' AS source, event_id, agent_id, query_name, response_data, timestamp
        FROM tamandua.dns_queries
        WHERE query_name LIKE '%#{escaped}%' OR has(response_data, '#{escaped}')
        ORDER BY timestamp DESC LIMIT #{limit}
        FORMAT JSON
      """,
      network: """
        SELECT 'network' AS source, event_id, agent_id, source_ip, dest_ip, dest_port, protocol, timestamp
        FROM tamandua.network_flows
        WHERE source_ip = '#{escaped}' OR dest_ip = '#{escaped}'
        ORDER BY timestamp DESC LIMIT #{limit}
        FORMAT JSON
      """,
      registry: """
        SELECT 'registry' AS source, event_id, agent_id, registry_key, registry_value, registry_action, timestamp
        FROM tamandua.registry_events
        WHERE registry_key LIKE '%#{escaped}%' OR registry_value LIKE '%#{escaped}%' OR registry_data LIKE '%#{escaped}%'
        ORDER BY timestamp DESC LIMIT #{limit}
        FORMAT JSON
      """,
      alert: """
        SELECT 'alert' AS source, event_id, agent_id, rule_name, severity, mitre_technique, details, timestamp
        FROM tamandua.alert_events
        WHERE details LIKE '%#{escaped}%' OR rule_name LIKE '%#{escaped}%'
        ORDER BY timestamp DESC LIMIT #{limit}
        FORMAT JSON
      """
    }

    results =
      queries
      |> Task.async_stream(
        fn {source, sql} ->
          case execute(sql) do
            {:ok, rows} -> {source, rows}
            {:error, _} -> {source, []}
          end
        end,
        max_concurrency: 4,
        timeout: 15_000
      )
      |> Enum.reduce(%{}, fn
        {:ok, {source, rows}}, acc -> Map.put(acc, source, rows)
        {:exit, _}, acc -> acc
      end)

    {:ok, results}
  end

  # ── Helpers ─────────────────────────────────────────────────────────

  defp execute(sql) do
    config = Application.get_env(:tamandua_server, TamanduaServer.Telemetry.ClickHouse, [])

    unless Keyword.get(config, :enabled, false) do
      {:error, :clickhouse_disabled}
    else
      url = Keyword.get(config, :url, "http://localhost:8123")
      database = Keyword.get(config, :database, "tamandua")
      username = Keyword.get(config, :username, "default")
      password = Keyword.get(config, :password, "")
      timeout = Keyword.get(config, :query_timeout, @default_query_timeout)

      full_url = "#{url}/?database=#{database}"

      headers =
        [{"content-type", "text/plain"}] ++
          if(username != "", do: [{"X-ClickHouse-User", username}], else: []) ++
          if(password != "", do: [{"X-ClickHouse-Key", password}], else: [])

      request = Finch.build(:post, full_url, headers, sql)

      case Finch.request(request, @finch_name, receive_timeout: timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          case Jason.decode(body) do
            {:ok, %{"data" => data}} -> {:ok, data}
            {:ok, other} -> {:ok, other}
            {:error, _} -> {:ok, body}
          end

        {:ok, %Finch.Response{status: status, body: body}} ->
          {:error, "ClickHouse HTTP #{status}: #{String.slice(body, 0, 500)}"}

        {:error, reason} ->
          {:error, reason}
      end
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp build_where_clauses(filters) do
    clauses = []

    clauses =
      if id = Keyword.get(filters, :agent_id) do
        clauses ++ ["agent_id = '#{escape(id)}'"]
      else
        clauses
      end

    clauses =
      if type = Keyword.get(filters, :event_type) do
        clauses ++ ["event_type = '#{escape(type)}'"]
      else
        clauses
      end

    clauses =
      if sev = Keyword.get(filters, :severity) do
        clauses ++ ["severity = '#{escape(sev)}'"]
      else
        clauses
      end

    clauses =
      if from = Keyword.get(filters, :from) do
        clauses ++ ["timestamp >= '#{format_dt(from)}'"]
      else
        clauses
      end

    clauses =
      if to = Keyword.get(filters, :to) do
        clauses ++ ["timestamp <= '#{format_dt(to)}'"]
      else
        clauses
      end

    clauses =
      if kw = Keyword.get(filters, :keyword) do
        clauses ++ ["payload LIKE '%#{escape(kw)}%'"]
      else
        clauses
      end

    clauses =
      if technique = Keyword.get(filters, :mitre_technique) do
        clauses ++ ["mitre_technique = '#{escape(technique)}'"]
      else
        clauses
      end

    {clauses, []}
  end

  defp where_sql([]), do: ""
  defp where_sql(clauses), do: "WHERE " <> Enum.join(clauses, " AND ")

  defp escape(value) when is_binary(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("'", "\\'")
    |> String.replace("\n", "")
    |> String.replace("\r", "")
  end

  defp escape(value), do: escape(to_string(value))

  defp format_dt(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S.") <>
      String.pad_leading(
        to_string(rem(dt.microsecond |> elem(0), 1_000_000) |> div(1_000)),
        3,
        "0"
      )
  end

  defp format_dt(ms) when is_integer(ms) and ms > 1_000_000_000_000 do
    case DateTime.from_unix(ms, :millisecond) do
      {:ok, dt} -> format_dt(dt)
      _ -> format_dt(DateTime.utc_now())
    end
  end

  defp format_dt(s) when is_integer(s) and s > 0 do
    case DateTime.from_unix(s) do
      {:ok, dt} -> format_dt(dt)
      _ -> format_dt(DateTime.utc_now())
    end
  end

  defp format_dt(s) when is_binary(s) do
    case DateTime.from_iso8601(s) do
      {:ok, dt, _} -> format_dt(dt)
      _ -> format_dt(DateTime.utc_now())
    end
  end

  defp format_dt(_), do: format_dt(DateTime.utc_now())
end
