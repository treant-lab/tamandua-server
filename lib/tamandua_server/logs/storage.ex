defmodule TamanduaServer.Logs.Storage do
  @moduledoc """
  Log storage backend using ClickHouse for high-volume log storage.

  Provides:
  - Batch log insertion
  - Efficient querying with filters
  - Log retention management
  - Full-text search capabilities
  """

  require Logger

  @clickhouse_url Application.compile_env(:tamandua_server, :clickhouse_url, "http://localhost:8123")
  @database "tamandua"
  @table "agent_logs"

  ## Public API

  @doc """
  Store a single log entry.
  """
  def store_log(log_entry) do
    store_log_batch([log_entry])
  end

  @doc """
  Store a batch of log entries.
  """
  def store_log_batch(log_entries) when is_list(log_entries) do
    if Enum.empty?(log_entries) do
      {:ok, 0}
    else
      rows = Enum.map(log_entries, &format_log_for_insert/1)

      query = """
      INSERT INTO #{@database}.#{@table} FORMAT JSONEachRow
      """

      body = rows |> Enum.map(&Jason.encode!/1) |> Enum.join("\n")

      case execute_query(query, body) do
        {:ok, _response} ->
          {:ok, length(log_entries)}

        {:error, reason} ->
          Logger.error("Failed to insert logs into ClickHouse: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end

  @doc """
  Fetch logs matching filters.
  """
  def fetch_logs(filters, limit \\ 1000) do
    where_clauses = build_where_clauses(filters)
    limit = min(limit, 10_000) # Max 10k logs

    query = """
    SELECT
      timestamp,
      agent_id,
      level,
      component,
      message,
      fields,
      file,
      line,
      thread
    FROM #{@database}.#{@table}
    #{if where_clauses != "", do: "WHERE #{where_clauses}", else: ""}
    ORDER BY timestamp DESC
    LIMIT #{limit}
    FORMAT JSON
    """

    case execute_query(query) do
      {:ok, response} ->
        parse_query_response(response)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Fetch log context (lines before and after a specific log).
  """
  def fetch_log_context(log_id, context_lines \\ 10) do
    # Parse log_id to extract timestamp and agent_id
    # Format: agent_id:timestamp:hash
    case String.split(log_id, ":", parts: 3) do
      [agent_id, timestamp_str, _hash] ->
        case Integer.parse(timestamp_str) do
          {timestamp, ""} ->
            fetch_context_by_timestamp(agent_id, timestamp, context_lines)

          _ ->
            {:error, :invalid_log_id}
        end

      _ ->
        {:error, :invalid_log_id}
    end
  end

  @doc """
  Get log statistics for the given filters.
  """
  def get_log_stats(filters) do
    where_clauses = build_where_clauses(filters)

    query = """
    SELECT
      count(*) as total_count,
      countIf(level = 'error') as error_count,
      countIf(level = 'warn') as warn_count,
      countIf(level = 'info') as info_count,
      countIf(level = 'debug') as debug_count,
      uniq(agent_id) as agent_count,
      uniq(component) as component_count,
      min(timestamp) as earliest,
      max(timestamp) as latest
    FROM #{@database}.#{@table}
    #{if where_clauses != "", do: "WHERE #{where_clauses}", else: ""}
    FORMAT JSON
    """

    case execute_query(query) do
      {:ok, response} ->
        parse_stats_response(response)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Search logs using full-text search.
  """
  def search_logs(search_term, filters, limit \\ 1000) do
    where_clauses = build_where_clauses(filters)

    # Add full-text search condition
    search_condition = "positionCaseInsensitive(message, '#{escape_string(search_term)}') > 0"

    where_clauses =
      if where_clauses != "" do
        "#{where_clauses} AND #{search_condition}"
      else
        search_condition
      end

    query = """
    SELECT
      timestamp,
      agent_id,
      level,
      component,
      message,
      fields,
      file,
      line,
      thread
    FROM #{@database}.#{@table}
    WHERE #{where_clauses}
    ORDER BY timestamp DESC
    LIMIT #{min(limit, 10_000)}
    FORMAT JSON
    """

    case execute_query(query) do
      {:ok, response} ->
        parse_query_response(response)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Initialize ClickHouse schema.
  """
  def init_schema do
    # Create database
    create_db_query = "CREATE DATABASE IF NOT EXISTS #{@database}"
    execute_query(create_db_query)

    # Create table
    create_table_query = """
    CREATE TABLE IF NOT EXISTS #{@database}.#{@table}
    (
      timestamp UInt64,
      agent_id String,
      level LowCardinality(String),
      component LowCardinality(String),
      message String,
      fields String,
      file Nullable(String),
      line Nullable(UInt32),
      thread Nullable(String),
      date Date DEFAULT toDate(timestamp / 1000)
    )
    ENGINE = MergeTree()
    PARTITION BY toYYYYMM(date)
    ORDER BY (agent_id, timestamp)
    TTL date + INTERVAL 90 DAY
    SETTINGS index_granularity = 8192
    """

    case execute_query(create_table_query) do
      {:ok, _} ->
        Logger.info("ClickHouse schema initialized for agent logs")
        :ok

      {:error, reason} ->
        Logger.error("Failed to initialize ClickHouse schema: #{inspect(reason)}")
        {:error, reason}
    end
  end

  ## Private Functions

  defp format_log_for_insert(log) do
    %{
      "timestamp" => log.timestamp || System.system_time(:millisecond),
      "agent_id" => log.agent_id || "unknown",
      "level" => log.level || "info",
      "component" => log.component || "unknown",
      "message" => log.message || "",
      "fields" => Jason.encode!(log.fields || %{}),
      "file" => log.file,
      "line" => log.line,
      "thread" => log.thread
    }
  end

  defp build_where_clauses(filters) do
    clauses = []

    # Agent IDs
    clauses =
      if not Enum.empty?(filters.agent_ids) do
        agent_list = filters.agent_ids |> Enum.map(&"'#{escape_string(&1)}'") |> Enum.join(", ")
        ["agent_id IN (#{agent_list})" | clauses]
      else
        clauses
      end

    # Levels
    clauses =
      if not Enum.empty?(filters.levels) do
        level_list = filters.levels |> Enum.map(&"'#{escape_string(&1)}'") |> Enum.join(", ")
        ["level IN (#{level_list})" | clauses]
      else
        clauses
      end

    # Components
    clauses =
      if not Enum.empty?(filters.components) do
        component_list = filters.components |> Enum.map(&"'#{escape_string(&1)}'") |> Enum.join(", ")
        ["component IN (#{component_list})" | clauses]
      else
        clauses
      end

    # Keyword
    clauses =
      if filters.keyword do
        ["positionCaseInsensitive(message, '#{escape_string(filters.keyword)}') > 0" | clauses]
      else
        clauses
      end

    # Regex (ClickHouse regex)
    clauses =
      if filters.regex do
        ["match(message, '#{escape_string(filters.regex)}')" | clauses]
      else
        clauses
      end

    # Time range
    clauses =
      if filters.time_start do
        ["timestamp >= #{filters.time_start}" | clauses]
      else
        clauses
      end

    clauses =
      if filters.time_end do
        ["timestamp <= #{filters.time_end}" | clauses]
      else
        clauses
      end

    Enum.join(clauses, " AND ")
  end

  defp fetch_context_by_timestamp(agent_id, timestamp, context_lines) do
    # Fetch lines before
    before_query = """
    SELECT
      timestamp,
      agent_id,
      level,
      component,
      message,
      fields,
      file,
      line,
      thread
    FROM #{@database}.#{@table}
    WHERE agent_id = '#{escape_string(agent_id)}'
      AND timestamp < #{timestamp}
    ORDER BY timestamp DESC
    LIMIT #{context_lines}
    FORMAT JSON
    """

    # Fetch target line
    target_query = """
    SELECT
      timestamp,
      agent_id,
      level,
      component,
      message,
      fields,
      file,
      line,
      thread
    FROM #{@database}.#{@table}
    WHERE agent_id = '#{escape_string(agent_id)}'
      AND timestamp = #{timestamp}
    LIMIT 1
    FORMAT JSON
    """

    # Fetch lines after
    after_query = """
    SELECT
      timestamp,
      agent_id,
      level,
      component,
      message,
      fields,
      file,
      line,
      thread
    FROM #{@database}.#{@table}
    WHERE agent_id = '#{escape_string(agent_id)}'
      AND timestamp > #{timestamp}
    ORDER BY timestamp ASC
    LIMIT #{context_lines}
    FORMAT JSON
    """

    with {:ok, before_response} <- execute_query(before_query),
         {:ok, before_logs} <- parse_query_response(before_response),
         {:ok, target_response} <- execute_query(target_query),
         {:ok, target_logs} <- parse_query_response(target_response),
         {:ok, after_response} <- execute_query(after_query),
         {:ok, after_logs} <- parse_query_response(after_response) do
      {:ok, %{
        before: Enum.reverse(before_logs),
        target: List.first(target_logs),
        after: after_logs
      }}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp execute_query(query, body \\ "") do
    url = "#{@clickhouse_url}/?database=#{@database}"
    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case HTTPoison.post(url, body <> query, headers) do
      {:ok, %{status_code: 200, body: response_body}} ->
        {:ok, response_body}

      {:ok, %{status_code: status, body: error_body}} ->
        Logger.error("ClickHouse query failed (#{status}): #{error_body}")
        {:error, {:clickhouse_error, status, error_body}}

      {:error, reason} ->
        Logger.error("ClickHouse connection failed: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("ClickHouse query exception: #{inspect(e)}")
      {:error, :clickhouse_exception}
  end

  defp parse_query_response(response_body) do
    case Jason.decode(response_body) do
      {:ok, %{"data" => data}} ->
        logs = Enum.map(data, &parse_log_row/1)
        {:ok, logs}

      {:ok, _} ->
        {:ok, []}

      {:error, reason} ->
        {:error, {:json_decode_error, reason}}
    end
  end

  defp parse_stats_response(response_body) do
    case Jason.decode(response_body) do
      {:ok, %{"data" => [stats]}} ->
        {:ok, %{
          total: stats["total_count"] || 0,
          error: stats["error_count"] || 0,
          warn: stats["warn_count"] || 0,
          info: stats["info_count"] || 0,
          debug: stats["debug_count"] || 0,
          agents: stats["agent_count"] || 0,
          components: stats["component_count"] || 0,
          earliest: stats["earliest"],
          latest: stats["latest"]
        }}

      {:ok, _} ->
        {:ok, %{total: 0}}

      {:error, reason} ->
        {:error, {:json_decode_error, reason}}
    end
  end

  defp parse_log_row(row) do
    %{
      timestamp: row["timestamp"],
      agent_id: row["agent_id"],
      level: row["level"],
      component: row["component"],
      message: row["message"],
      fields: parse_json_field(row["fields"]),
      file: row["file"],
      line: row["line"],
      thread: row["thread"]
    }
  end

  defp parse_json_field(nil), do: nil
  defp parse_json_field(""), do: nil
  defp parse_json_field(json_string) do
    case Jason.decode(json_string) do
      {:ok, data} -> data
      {:error, _} -> nil
    end
  end

  defp escape_string(str) do
    str
    |> String.replace("\\", "\\\\")
    |> String.replace("'", "\\'")
  end
end
