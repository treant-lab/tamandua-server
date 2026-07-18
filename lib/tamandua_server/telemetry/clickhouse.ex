defmodule TamanduaServer.Telemetry.ClickHouse do
  @moduledoc """
  ClickHouse client for high-volume telemetry storage.

  ClickHouse handles raw telemetry events, DNS queries, network flows,
  and process events. PostgreSQL continues to handle relational data
  (users, agents, alerts, configs).

  Architecture:
  - Broadway Ingestor dual-writes: PostgreSQL (alerts/events) + ClickHouse (all events)
  - Query interface reads from ClickHouse for event search/timeline/aggregation
  - Async batch inserts for performance (buffer events, flush every 1s or 1000 events)

  Uses Finch (already in the project) for HTTP requests to the ClickHouse HTTP interface
  on port 8123. No additional HTTP libraries required.
  """

  use GenServer
  require Logger

  @default_batch_size 1000
  @default_flush_interval_ms 1_000
  @ets_table :clickhouse_event_buffer
  @finch_name TamanduaServer.Finch

  # ── Public API ──────────────────────────────────────────────────────

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Buffer a single telemetry event for batch insertion into ClickHouse.
  Returns immediately; the event will be flushed asynchronously.
  """
  @spec insert_event(map()) :: :ok
  def insert_event(event) do
    insert_events([event])
  end

  @doc """
  Buffer multiple telemetry events for batch insertion into ClickHouse.
  Returns immediately; events will be flushed asynchronously.
  """
  @spec insert_events([map()]) :: :ok
  def insert_events(events) when is_list(events) do
    if enabled?() do
      GenServer.cast(__MODULE__, {:buffer_events, events})
    end

    :ok
  end

  @doc """
  Check whether the ClickHouse connection is healthy.
  """
  @spec healthy?() :: boolean()
  def healthy? do
    GenServer.call(__MODULE__, :health_check, 5_000)
  catch
    :exit, _ -> false
  end

  @doc """
  Returns whether ClickHouse integration is enabled.
  """
  @spec enabled?() :: boolean()
  def enabled? do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    Keyword.get(config, :enabled, false)
  end

  @doc """
  Query telemetry events from ClickHouse with filters.

  ## Options
    - `:agent_id` - Filter by agent ID
    - `:organization_id` - Filter by organization
    - `:event_type` - Filter by event type
    - `:severity` - Filter by severity level
    - `:from` - Start of time range (DateTime or unix ms)
    - `:to` - End of time range (DateTime or unix ms)
    - `:keyword` - Full-text search in payload
    - `:limit` - Maximum number of results (default 100)
    - `:offset` - Offset for pagination (default 0)
  """
  @spec query_events(keyword()) :: {:ok, [map()]} | {:error, term()}
  def query_events(filters \\ []) do
    {where_clauses, params} = build_event_filters(filters)
    limit = Keyword.get(filters, :limit, 100)
    offset = Keyword.get(filters, :offset, 0)

    sql = """
    SELECT *
    FROM tamandua.telemetry_events
    #{where_clause_sql(where_clauses)}
    ORDER BY timestamp DESC
    LIMIT #{limit} OFFSET #{offset}
    FORMAT JSON
    """

    execute_query(sql, params)
  end

  @doc """
  Query a timeline of events for a specific agent within a time range.

  Returns events ordered by timestamp ascending for chronological display.
  """
  @spec query_timeline(String.t(), DateTime.t(), DateTime.t(), keyword()) ::
          {:ok, [map()]} | {:error, term()}
  def query_timeline(agent_id, from, to, opts \\ []) do
    limit = Keyword.get(opts, :limit, 1000)

    sql = """
    SELECT event_id, event_type, severity, timestamp, payload, mitre_technique, mitre_tactic
    FROM tamandua.telemetry_events
    WHERE agent_id = '#{escape(agent_id)}'
      AND timestamp >= '#{format_datetime(from)}'
      AND timestamp <= '#{format_datetime(to)}'
    ORDER BY timestamp ASC
    LIMIT #{limit}
    FORMAT JSON
    """

    execute_query(sql)
  end

  @doc """
  Aggregate event counts grouped by a specified dimension.

  ## Supported group_by values
    - `:event_type` - Count by event type
    - `:severity` - Count by severity level
    - `:agent_id` - Count by agent
    - `:hour` - Count by hour
    - `:day` - Count by day
  """
  @spec aggregate_events(atom(), DateTime.t(), DateTime.t(), keyword()) ::
          {:ok, [map()]} | {:error, term()}
  def aggregate_events(group_by, from, to, opts \\ []) do
    org_id = Keyword.get(opts, :organization_id)

    group_expr =
      case group_by do
        :event_type -> "event_type"
        :severity -> "severity"
        :agent_id -> "agent_id"
        :hour -> "toStartOfHour(timestamp)"
        :day -> "toStartOfDay(timestamp)"
        _ -> "event_type"
      end

    org_filter =
      if org_id,
        do: "AND organization_id = '#{escape(org_id)}'",
        else: ""

    sql = """
    SELECT #{group_expr} AS group_key, count() AS event_count
    FROM tamandua.telemetry_events
    WHERE timestamp >= '#{format_datetime(from)}'
      AND timestamp <= '#{format_datetime(to)}'
      #{org_filter}
    GROUP BY group_key
    ORDER BY event_count DESC
    LIMIT 1000
    FORMAT JSON
    """

    execute_query(sql)
  end

  @doc """
  Search across all ClickHouse tables for an IOC (IP address, hash, or domain).

  Searches:
  - telemetry_events payload for the IOC string
  - process_events for matching SHA-256 hashes
  - dns_events for matching domain queries
  - network_flows for matching IP addresses
  """
  @spec search_ioc(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def search_ioc(ioc_value, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    escaped = escape(ioc_value)

    queries = %{
      telemetry:
        "SELECT 'telemetry' AS source, event_id, agent_id, event_type, timestamp, payload FROM tamandua.telemetry_events WHERE payload LIKE '%#{escaped}%' ORDER BY timestamp DESC LIMIT #{limit} FORMAT JSON",
      process:
        "SELECT 'process' AS source, event_id, agent_id, process_name, command_line, hash_sha256, timestamp FROM tamandua.process_events WHERE hash_sha256 = '#{escaped}' OR command_line LIKE '%#{escaped}%' ORDER BY timestamp DESC LIMIT #{limit} FORMAT JSON",
      dns:
        "SELECT 'dns' AS source, event_id, agent_id, query_name, response_data, timestamp FROM tamandua.dns_queries WHERE query_name LIKE '%#{escaped}%' OR has(response_data, '#{escaped}') ORDER BY timestamp DESC LIMIT #{limit} FORMAT JSON",
      network:
        "SELECT 'network' AS source, event_id, agent_id, source_ip, dest_ip, dest_port, protocol, timestamp FROM tamandua.network_flows WHERE source_ip = '#{escaped}' OR dest_ip = '#{escaped}' ORDER BY timestamp DESC LIMIT #{limit} FORMAT JSON"
    }

    results =
      queries
      |> Task.async_stream(
        fn {source, sql} ->
          case execute_query(sql) do
            {:ok, rows} -> {source, rows}
            {:error, _} -> {source, []}
          end
        end,
        max_concurrency: 4,
        timeout: 10_000
      )
      |> Enum.reduce(%{}, fn
        {:ok, {source, rows}}, acc -> Map.put(acc, source, rows)
        {:exit, _}, acc -> acc
      end)

    {:ok, results}
  end

  # ── GenServer Callbacks ─────────────────────────────────────────────

  @impl true
  def init(_opts) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    enabled = Keyword.get(config, :enabled, false)

    if enabled do
      # Create ETS buffer table
      :ets.new(@ets_table, [:named_table, :public, :set])

      state = %{
        url: Keyword.get(config, :url, "http://localhost:8123"),
        database: Keyword.get(config, :database, "tamandua"),
        username: Keyword.get(config, :username, "default"),
        password: Keyword.get(config, :password, ""),
        batch_size: Keyword.get(config, :batch_size, @default_batch_size),
        flush_interval_ms: Keyword.get(config, :flush_interval_ms, @default_flush_interval_ms),
        buffer: [],
        buffer_count: 0,
        healthy: false
      }

      # Schedule schema initialization after a brief delay to let Finch start
      Process.send_after(self(), :init_schema, 2_000)

      # Schedule periodic flush
      schedule_flush(state.flush_interval_ms)

      Logger.info("[ClickHouse] Client started — url=#{state.url} database=#{state.database}")
      {:ok, state}
    else
      Logger.info("[ClickHouse] Integration disabled — skipping startup")
      {:ok, %{enabled: false}}
    end
  end

  @impl true
  def handle_cast({:buffer_events, _events}, %{enabled: false} = state) do
    {:noreply, state}
  end

  @impl true
  def handle_cast({:buffer_events, events}, state) do
    new_buffer = state.buffer ++ events
    new_count = state.buffer_count + length(events)

    if new_count >= state.batch_size do
      flush_buffer(%{state | buffer: new_buffer, buffer_count: new_count})
    else
      {:noreply, %{state | buffer: new_buffer, buffer_count: new_count}}
    end
  end

  @impl true
  def handle_call(:health_check, _from, %{enabled: false} = state) do
    {:reply, false, state}
  end

  @impl true
  def handle_call(:health_check, _from, state) do
    healthy = do_health_check(state)
    {:reply, healthy, %{state | healthy: healthy}}
  end

  @impl true
  def handle_info(:flush, %{enabled: false} = state) do
    {:noreply, state}
  end

  @impl true
  def handle_info(:flush, state) do
    schedule_flush(state.flush_interval_ms)

    if state.buffer_count > 0 do
      flush_buffer(state)
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(:init_schema, %{enabled: false} = state) do
    {:noreply, state}
  end

  @impl true
  def handle_info(:init_schema, state) do
    case init_schema(state) do
      :ok ->
        Logger.info("[ClickHouse] Schema initialized successfully")
        {:noreply, %{state | healthy: true}}

      {:error, reason} ->
        Logger.warning("[ClickHouse] Schema init failed: #{inspect(reason)} — retrying in 10s")
        Process.send_after(self(), :init_schema, 10_000)
        {:noreply, %{state | healthy: false}}
    end
  end

  @impl true
  def handle_info(msg, state) do
    Logger.debug("[ClickHouse] Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  # ── Schema Initialization ──────────────────────────────────────────

  defp init_schema(state) do
    # Create the database first, then all tables and materialized views.
    # These DDLs are kept in sync with deploy/clickhouse/init.sql.
    # The Docker init.sql runs on first container start; these serve as
    # a fallback for environments without Docker (bare-metal, dev, etc.).
    with :ok <- execute_ddl(state, "CREATE DATABASE IF NOT EXISTS tamandua"),
         :ok <- execute_ddl(state, telemetry_events_ddl()),
         :ok <- execute_ddl(state, process_events_ddl()),
         :ok <- execute_ddl(state, file_events_ddl()),
         :ok <- execute_ddl(state, dns_queries_ddl()),
         :ok <- execute_ddl(state, network_flows_ddl()),
         :ok <- execute_ddl(state, registry_events_ddl()),
         :ok <- execute_ddl(state, alert_events_ddl()),
         :ok <- execute_ddl(state, event_counts_hourly_ddl()),
         :ok <- execute_ddl(state, event_counts_daily_ddl()) do
      :ok
    end
  end

  defp telemetry_events_ddl do
    """
    CREATE TABLE IF NOT EXISTS tamandua.telemetry_events (
        event_id UUID,
        timestamp DateTime('UTC'),
        agent_id String,
        organization_id String DEFAULT '',
        event_type String,
        severity Enum8('info' = 0, 'low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
        process_name String DEFAULT '',
        process_id UInt32 DEFAULT 0,
        parent_process_id UInt32 DEFAULT 0,
        command_line String DEFAULT '',
        user_name String DEFAULT '',
        file_path String DEFAULT '',
        file_hash String DEFAULT '',
        source_ip IPv4 DEFAULT toIPv4('0.0.0.0'),
        dest_ip IPv4 DEFAULT toIPv4('0.0.0.0'),
        source_port UInt16 DEFAULT 0,
        dest_port UInt16 DEFAULT 0,
        dns_query String DEFAULT '',
        dns_response String DEFAULT '',
        rule_name String DEFAULT '',
        mitre_technique String DEFAULT '',
        mitre_tactic String DEFAULT '',
        threat_score Float32 DEFAULT 0,
        source_ip_str String DEFAULT '',
        hostname String DEFAULT '',
        received_at DateTime64(3, 'UTC') DEFAULT now64(3),
        payload String DEFAULT '{}',
        metadata String DEFAULT '{}',
        INDEX idx_event_type event_type TYPE set(100) GRANULARITY 4,
        INDEX idx_severity severity TYPE set(10) GRANULARITY 4,
        INDEX idx_agent agent_id TYPE bloom_filter(0.01) GRANULARITY 4,
        INDEX idx_mitre mitre_technique TYPE set(500) GRANULARITY 4,
        INDEX idx_payload payload TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(timestamp)
    ORDER BY (agent_id, timestamp)
    TTL timestamp + INTERVAL 90 DAY DELETE
    SETTINGS index_granularity = 8192
    """
  end

  defp process_events_ddl do
    """
    CREATE TABLE IF NOT EXISTS tamandua.process_events (
        event_id UUID,
        timestamp DateTime('UTC'),
        agent_id String,
        organization_id String DEFAULT '',
        event_type Enum8('create' = 1, 'exit' = 2, 'exec' = 3),
        process_id UInt32,
        parent_process_id UInt32,
        process_name String,
        command_line String DEFAULT '',
        executable_path String DEFAULT '',
        user_name String DEFAULT '',
        is_elevated UInt8 DEFAULT 0,
        is_signed UInt8 DEFAULT 0,
        signer String DEFAULT '',
        file_hash String DEFAULT '',
        exit_code Int32 DEFAULT 0,
        INDEX idx_process process_name TYPE set(1000) GRANULARITY 4,
        INDEX idx_hash file_hash TYPE bloom_filter(0.01) GRANULARITY 4,
        INDEX idx_cmdline command_line TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(timestamp)
    ORDER BY (agent_id, process_id, timestamp)
    TTL timestamp + INTERVAL 30 DAY DELETE
    SETTINGS index_granularity = 8192
    """
  end

  defp file_events_ddl do
    """
    CREATE TABLE IF NOT EXISTS tamandua.file_events (
        event_id UUID,
        timestamp DateTime('UTC'),
        agent_id String,
        organization_id String DEFAULT '',
        file_path String,
        file_action Enum8('create' = 1, 'modify' = 2, 'delete' = 3, 'rename' = 4, 'read' = 5, 'write' = 6, 'other' = 0),
        file_hash String DEFAULT '',
        file_size UInt64 DEFAULT 0,
        process_id UInt32 DEFAULT 0,
        process_name String DEFAULT '',
        user_name String DEFAULT '',
        is_suspicious UInt8 DEFAULT 0,
        INDEX idx_file_path file_path TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
        INDEX idx_file_hash file_hash TYPE bloom_filter(0.01) GRANULARITY 4,
        INDEX idx_file_action file_action TYPE set(10) GRANULARITY 4
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(timestamp)
    ORDER BY (agent_id, file_path, timestamp)
    TTL timestamp + INTERVAL 30 DAY DELETE
    SETTINGS index_granularity = 8192
    """
  end

  defp dns_queries_ddl do
    """
    CREATE TABLE IF NOT EXISTS tamandua.dns_queries (
        event_id UUID,
        timestamp DateTime('UTC'),
        agent_id String,
        organization_id String DEFAULT '',
        process_id UInt32 DEFAULT 0,
        process_name String DEFAULT '',
        query_name String,
        query_type String DEFAULT '',
        response_code UInt16 DEFAULT 0,
        response_data Array(String) DEFAULT [],
        is_suspicious UInt8 DEFAULT 0,
        INDEX idx_domain query_name TYPE set(10000) GRANULARITY 4,
        INDEX idx_domain_ngram query_name TYPE ngrambf_v1(3, 256, 2, 0) GRANULARITY 4
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(timestamp)
    ORDER BY (query_name, timestamp)
    TTL timestamp + INTERVAL 30 DAY DELETE
    SETTINGS index_granularity = 8192
    """
  end

  defp network_flows_ddl do
    """
    CREATE TABLE IF NOT EXISTS tamandua.network_flows (
        event_id UUID,
        timestamp DateTime('UTC'),
        agent_id String,
        organization_id String DEFAULT '',
        process_id UInt32 DEFAULT 0,
        process_name String DEFAULT '',
        direction Enum8('outbound' = 0, 'inbound' = 1),
        protocol Enum8('tcp' = 6, 'udp' = 17, 'other' = 0),
        source_ip String DEFAULT '',
        dest_ip String DEFAULT '',
        source_port UInt16 DEFAULT 0,
        dest_port UInt16 DEFAULT 0,
        bytes_sent UInt64 DEFAULT 0,
        bytes_received UInt64 DEFAULT 0,
        duration_ms UInt32 DEFAULT 0,
        country_code FixedString(2) DEFAULT '--',
        asn UInt32 DEFAULT 0,
        INDEX idx_dest_ip dest_ip TYPE bloom_filter(0.01) GRANULARITY 4,
        INDEX idx_source_ip source_ip TYPE bloom_filter(0.01) GRANULARITY 4
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(timestamp)
    ORDER BY (agent_id, dest_ip, timestamp)
    TTL timestamp + INTERVAL 30 DAY DELETE
    SETTINGS index_granularity = 8192
    """
  end

  defp registry_events_ddl do
    """
    CREATE TABLE IF NOT EXISTS tamandua.registry_events (
        event_id UUID,
        timestamp DateTime('UTC'),
        agent_id String,
        organization_id String DEFAULT '',
        registry_key String,
        registry_value String DEFAULT '',
        registry_action Enum8('create' = 1, 'modify' = 2, 'delete' = 3, 'rename' = 4, 'other' = 0),
        registry_data String DEFAULT '',
        registry_type String DEFAULT '',
        process_id UInt32 DEFAULT 0,
        process_name String DEFAULT '',
        user_name String DEFAULT '',
        is_suspicious UInt8 DEFAULT 0,
        INDEX idx_reg_key registry_key TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
        INDEX idx_reg_action registry_action TYPE set(10) GRANULARITY 4
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(timestamp)
    ORDER BY (agent_id, registry_key, timestamp)
    TTL timestamp + INTERVAL 30 DAY DELETE
    SETTINGS index_granularity = 8192
    """
  end

  defp alert_events_ddl do
    """
    CREATE TABLE IF NOT EXISTS tamandua.alert_events (
        event_id UUID,
        timestamp DateTime('UTC'),
        agent_id String,
        organization_id String DEFAULT '',
        alert_id String DEFAULT '',
        rule_name String,
        severity Enum8('info' = 0, 'low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
        mitre_technique String DEFAULT '',
        mitre_tactic String DEFAULT '',
        details String DEFAULT '{}',
        source_event_id String DEFAULT '',
        process_name String DEFAULT '',
        process_id UInt32 DEFAULT 0,
        command_line String DEFAULT '',
        file_path String DEFAULT '',
        file_hash String DEFAULT '',
        source_ip String DEFAULT '',
        dest_ip String DEFAULT '',
        verdict String DEFAULT '',
        INDEX idx_alert_rule rule_name TYPE set(1000) GRANULARITY 4,
        INDEX idx_alert_severity severity TYPE set(10) GRANULARITY 4,
        INDEX idx_alert_mitre mitre_technique TYPE set(500) GRANULARITY 4,
        INDEX idx_alert_details details TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(timestamp)
    ORDER BY (agent_id, rule_name, timestamp)
    TTL timestamp + INTERVAL 90 DAY DELETE
    SETTINGS index_granularity = 8192
    """
  end

  defp event_counts_hourly_ddl do
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS tamandua.event_counts_hourly
    ENGINE = SummingMergeTree()
    PARTITION BY toYYYYMM(hour)
    ORDER BY (agent_id, event_type, hour)
    AS SELECT
        agent_id,
        event_type,
        toStartOfHour(timestamp) AS hour,
        count() AS event_count,
        countIf(severity IN ('high', 'critical')) AS critical_count
    FROM tamandua.telemetry_events
    GROUP BY agent_id, event_type, hour
    """
  end

  defp event_counts_daily_ddl do
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS tamandua.event_counts_daily
    ENGINE = SummingMergeTree()
    PARTITION BY toYYYYMM(day)
    ORDER BY (agent_id, day)
    AS SELECT
        agent_id,
        toStartOfDay(timestamp) AS day,
        count() AS event_count,
        countIf(severity IN ('high', 'critical')) AS critical_count,
        uniqExact(event_type) AS distinct_event_types
    FROM tamandua.telemetry_events
    GROUP BY agent_id, day
    """
  end

  # ── Buffer Flush ────────────────────────────────────────────────────

  defp flush_buffer(state) do
    events = state.buffer
    count = state.buffer_count

    # Reset buffer immediately so new events are not blocked
    new_state = %{state | buffer: [], buffer_count: 0}

    # Perform the actual HTTP inserts asynchronously via Task.Supervisor
    # so the GenServer is not blocked while waiting for ClickHouse.
    Task.Supervisor.start_child(
      TamanduaServer.TaskSupervisor,
      fn -> do_flush(events, state) end
    )

    Logger.debug("[ClickHouse] Flushing #{count} events asynchronously")
    {:noreply, new_state}
  rescue
    e ->
      # If Task.Supervisor is not available, fall back to a bare spawn
      Logger.warning(
        "[ClickHouse] Task.Supervisor unavailable (#{Exception.message(e)}), using spawn"
      )

      spawn(fn -> do_flush(state.buffer, state) end)
      {:noreply, %{state | buffer: [], buffer_count: 0}}
  end

  defp do_flush(events, state) do
    # Group events by target table based on event_type
    grouped = group_events_by_table(events)

    Enum.each(grouped, fn {table, rows} ->
      json_rows =
        rows
        |> Enum.map(&Jason.encode!/1)
        |> Enum.join("\n")

      url = "#{state.url}/?database=#{state.database}&query=INSERT+INTO+#{table}+FORMAT+JSONEachRow"

      headers = auth_headers(state)

      request =
        Finch.build(:post, url, headers, json_rows)

      case Finch.request(request, @finch_name, receive_timeout: 30_000) do
        {:ok, %Finch.Response{status: status}} when status in 200..299 ->
          Logger.debug("[ClickHouse] Inserted #{length(rows)} rows into #{table}")

        {:ok, %Finch.Response{status: status, body: body}} ->
          Logger.error("[ClickHouse] Insert failed for #{table}: HTTP #{status} — #{body}")

        {:error, reason} ->
          Logger.error("[ClickHouse] Insert request failed for #{table}: #{inspect(reason)}")
      end
    end)
  rescue
    e ->
      Logger.error("[ClickHouse] Flush error: #{Exception.message(e)}")
  end

  # ── Event Routing ───────────────────────────────────────────────────

  defp group_events_by_table(events) do
    events
    |> Enum.group_by(&target_table/1)
    |> Enum.map(fn {table, evts} -> {table, Enum.map(evts, &format_for_table(table, &1))} end)
  end

  defp target_table(event) do
    event_type = event["event_type"] || event[:event_type] || ""
    type_str = to_string(event_type)

    cond do
      type_str in ["process_create", "process_terminate", "process_start", "process_exec"] ->
        "process_events"

      type_str in ["file_create", "file_modify", "file_delete", "file_rename", "file_read", "file_write", "file_event"] ->
        "file_events"

      type_str in ["dns_query", "dns_response", "dns"] ->
        "dns_queries"

      type_str in [
        "network_connect",
        "network_listen",
        "network_flow",
        "network_accept",
        "network_close"
      ] ->
        "network_flows"

      type_str in ["registry_create", "registry_modify", "registry_delete", "registry_rename", "registry_event", "registry_set_value"] ->
        "registry_events"

      type_str in ["alert", "alert_created", "detection_alert"] ->
        "alert_events"

      true ->
        "telemetry_events"
    end
  end

  defp format_for_table("process_events", event) do
    payload = event["payload"] || event[:payload] || %{}
    ts = format_event_timestamp(event)

    event_type_raw = event["event_type"] || event[:event_type] || "create"
    event_type_enum =
      case to_string(event_type_raw) do
        "process_terminate" -> "exit"
        "process_exec" -> "exec"
        _ -> "create"
      end

    %{
      event_id: event_id(event),
      agent_id: to_string(event["agent_id"] || event[:agent_id] || ""),
      organization_id: to_string(event["organization_id"] || event[:organization_id] || ""),
      timestamp: ts,
      event_type: event_type_enum,
      process_id: to_integer(payload["pid"] || payload[:pid], 0),
      parent_process_id: to_integer(payload["ppid"] || payload[:ppid], 0),
      process_name:
        to_string(
          payload["process_name"] || payload[:process_name] ||
            payload["name"] || payload[:name] ||
            payload["image"] || payload[:image] ||
            payload["exe"] || payload[:exe] || ""
        ),
      command_line:
        to_string(
          payload["command_line"] || payload[:command_line] ||
            payload["cmdline"] || payload[:cmdline] ||
            payload["commandline"] || payload[:commandline] || ""
        ),
      executable_path:
        to_string(
          payload["executable_path"] || payload[:executable_path] ||
            payload["path"] || payload[:path] ||
            payload["image_path"] || payload[:image_path] || ""
        ),
      user_name:
        to_string(
          payload["username"] || payload[:username] ||
            payload["user"] || payload[:user] ||
            payload["user_name"] || payload[:user_name] || ""
        ),
      is_elevated: if((payload["is_elevated"] || payload[:is_elevated]) in [true, 1], do: 1, else: 0),
      is_signed: if((payload["is_signed"] || payload[:is_signed]) in [true, 1], do: 1, else: 0),
      signer: to_string(payload["signer"] || payload[:signer] || ""),
      file_hash: to_string(payload["sha256"] || payload[:sha256] || payload["hash_sha256"] || payload[:hash_sha256] || "")
    }
  end

  defp format_for_table("dns_queries", event) do
    payload = event["payload"] || event[:payload] || %{}
    ts = format_event_timestamp(event)

    response_data_raw =
      payload["response_data"] ||
        payload[:response_data] ||
        payload["responses"] ||
        payload[:responses] ||
        payload["answers"] ||
        payload[:answers] ||
        payload["resolved_ips"] ||
        payload[:resolved_ips] ||
        []
    response_data =
      cond do
        is_list(response_data_raw) -> response_data_raw
        is_binary(response_data_raw) -> [response_data_raw]
        true -> []
      end

    %{
      event_id: event_id(event),
      agent_id: to_string(event["agent_id"] || event[:agent_id] || ""),
      organization_id: to_string(event["organization_id"] || event[:organization_id] || ""),
      timestamp: ts,
      process_id: to_integer(payload["pid"] || payload[:pid] || payload["process_id"] || payload[:process_id], 0),
      process_name: to_string(payload["process_name"] || payload[:process_name] || ""),
      query_name:
        to_string(
          payload["query_name"] ||
            payload[:query_name] ||
            payload["query"] ||
            payload[:query] ||
            payload["domain"] ||
            payload[:domain] ||
            payload["dns_query"] ||
            payload[:dns_query] ||
            ""
        ),
      query_type: to_string(payload["query_type"] || payload[:query_type] || ""),
      response_code: to_integer(payload["response_code"] || payload[:response_code], 0),
      response_data: response_data,
      is_suspicious: if((payload["is_suspicious"] || payload[:is_suspicious]) in [true, 1], do: 1, else: 0)
    }
  end

  defp format_for_table("network_flows", event) do
    payload = event["payload"] || event[:payload] || %{}
    ts = format_event_timestamp(event)

    %{
      event_id: event_id(event),
      agent_id: to_string(event["agent_id"] || event[:agent_id] || ""),
      organization_id: to_string(event["organization_id"] || event[:organization_id] || ""),
      timestamp: ts,
      source_ip: to_string(payload["source_ip"] || payload[:source_ip] || payload["local_ip"] || payload[:local_ip] || ""),
      source_port: to_integer(payload["source_port"] || payload[:source_port] || payload["local_port"] || payload[:local_port], 0),
      dest_ip: to_string(payload["dest_ip"] || payload[:dest_ip] || payload["remote_ip"] || payload[:remote_ip] || ""),
      dest_port: to_integer(payload["dest_port"] || payload[:dest_port] || payload["remote_port"] || payload[:remote_port], 0),
      protocol: to_string(payload["protocol"] || payload[:protocol] || ""),
      bytes_sent: to_integer(payload["bytes_sent"] || payload[:bytes_sent], 0),
      bytes_received: to_integer(payload["bytes_received"] || payload[:bytes_received], 0),
      duration_ms: to_integer(payload["duration_ms"] || payload[:duration_ms], 0),
      process_name: to_string(payload["process_name"] || payload[:process_name] || "")
    }
  end

  defp format_for_table("file_events", event) do
    payload = event["payload"] || event[:payload] || %{}
    ts = format_event_timestamp(event)

    event_type_raw = event["event_type"] || event[:event_type] || "other"
    file_action =
      case to_string(event_type_raw) do
        "file_create" -> "create"
        "file_modify" -> "modify"
        "file_delete" -> "delete"
        "file_rename" -> "rename"
        "file_read" -> "read"
        "file_write" -> "write"
        _ -> "other"
      end

    %{
      event_id: event_id(event),
      agent_id: to_string(event["agent_id"] || event[:agent_id] || ""),
      organization_id: to_string(event["organization_id"] || event[:organization_id] || ""),
      timestamp: ts,
      file_path: to_string(payload["file_path"] || payload[:file_path] || payload["path"] || payload[:path] || ""),
      file_action: file_action,
      file_hash: to_string(payload["sha256"] || payload[:sha256] || payload["hash"] || payload[:hash] || ""),
      file_size: to_integer(payload["file_size"] || payload[:file_size] || payload["size"] || payload[:size], 0),
      process_id: to_integer(payload["pid"] || payload[:pid], 0),
      process_name: to_string(payload["process_name"] || payload[:process_name] || ""),
      user_name: to_string(payload["username"] || payload[:username] || ""),
      is_suspicious: if((payload["is_suspicious"] || payload[:is_suspicious]) in [true, 1], do: 1, else: 0)
    }
  end

  defp format_for_table("registry_events", event) do
    payload = event["payload"] || event[:payload] || %{}
    ts = format_event_timestamp(event)

    event_type_raw = event["event_type"] || event[:event_type] || "other"
    registry_action =
      case to_string(event_type_raw) do
        "registry_create" -> "create"
        "registry_modify" -> "modify"
        "registry_set_value" -> "modify"
        "registry_delete" -> "delete"
        "registry_rename" -> "rename"
        _ -> "other"
      end

    %{
      event_id: event_id(event),
      agent_id: to_string(event["agent_id"] || event[:agent_id] || ""),
      organization_id: to_string(event["organization_id"] || event[:organization_id] || ""),
      timestamp: ts,
      registry_key: to_string(payload["key"] || payload[:key] || payload["registry_key"] || payload[:registry_key] || ""),
      registry_value: to_string(payload["value_name"] || payload[:value_name] || payload["value"] || payload[:value] || ""),
      registry_action: registry_action,
      registry_data: to_string(payload["data"] || payload[:data] || payload["registry_data"] || payload[:registry_data] || ""),
      registry_type: to_string(payload["value_type"] || payload[:value_type] || payload["registry_type"] || payload[:registry_type] || ""),
      process_id: to_integer(payload["pid"] || payload[:pid], 0),
      process_name: to_string(payload["process_name"] || payload[:process_name] || ""),
      user_name: to_string(payload["username"] || payload[:username] || ""),
      is_suspicious: if((payload["is_suspicious"] || payload[:is_suspicious]) in [true, 1], do: 1, else: 0)
    }
  end

  defp format_for_table("alert_events", event) do
    payload = event["payload"] || event[:payload] || %{}
    analysis = event["analysis"] || event[:analysis] || %{}
    ts = format_event_timestamp(event)

    severity_raw = event["severity"] || event[:severity] || payload["severity"] || payload[:severity] || "info"
    severity =
      case to_string(severity_raw) do
        s when s in ["info", "low", "medium", "high", "critical"] -> s
        _ -> "info"
      end

    %{
      event_id: event_id(event),
      agent_id: to_string(event["agent_id"] || event[:agent_id] || ""),
      organization_id: to_string(event["organization_id"] || event[:organization_id] || ""),
      timestamp: ts,
      alert_id: to_string(event["alert_id"] || event[:alert_id] || payload["alert_id"] || payload[:alert_id] || ""),
      rule_name: to_string(payload["rule_name"] || payload[:rule_name] || analysis["rule_name"] || analysis[:rule_name] || event["rule"] || event[:rule] || ""),
      severity: severity,
      mitre_technique: to_string(analysis["mitre_technique"] || analysis[:mitre_technique] || payload["mitre_technique"] || payload[:mitre_technique] || ""),
      mitre_tactic: to_string(analysis["mitre_tactic"] || analysis[:mitre_tactic] || payload["mitre_tactic"] || payload[:mitre_tactic] || ""),
      details: safe_json_encode(payload),
      source_event_id: to_string(payload["source_event_id"] || payload[:source_event_id] || ""),
      process_name: to_string(payload["process_name"] || payload[:process_name] || ""),
      process_id: to_integer(payload["pid"] || payload[:pid], 0),
      command_line: to_string(payload["command_line"] || payload[:command_line] || ""),
      file_path: to_string(payload["file_path"] || payload[:file_path] || ""),
      file_hash: to_string(payload["sha256"] || payload[:sha256] || payload["hash"] || payload[:hash] || ""),
      source_ip: to_string(payload["source_ip"] || payload[:source_ip] || ""),
      dest_ip: to_string(payload["dest_ip"] || payload[:dest_ip] || ""),
      verdict: to_string(payload["verdict"] || payload[:verdict] || "")
    }
  end

  defp format_for_table("telemetry_events", event) do
    payload = event["payload"] || event[:payload] || %{}
    analysis = event["analysis"] || event[:analysis] || %{}
    ts = format_event_timestamp(event)

    %{
      event_id: event_id(event),
      agent_id: to_string(event["agent_id"] || event[:agent_id] || ""),
      organization_id: to_string(event["organization_id"] || event[:organization_id] || ""),
      event_type: to_string(event["event_type"] || event[:event_type] || "unknown"),
      severity: to_string(event["severity"] || event[:severity] || "info"),
      timestamp: ts,
      received_at: format_datetime(DateTime.utc_now()),
      payload: safe_json_encode(payload),
      metadata: safe_json_encode(event["metadata"] || event[:metadata] || %{}),
      source_ip: normalize_ip(event["source_ip"] || event[:source_ip]),
      hostname: to_string(event["hostname"] || event[:hostname] || ""),
      mitre_technique: to_string(analysis["mitre_technique"] || analysis[:mitre_technique] || get_in(analysis, [:mitre, :technique]) || ""),
      mitre_tactic: to_string(analysis["mitre_tactic"] || analysis[:mitre_tactic] || get_in(analysis, [:mitre, :tactic]) || "")
    }
  end

  # ── HTTP Helpers ────────────────────────────────────────────────────

  defp execute_query(sql, _params \\ []) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    url = Keyword.get(config, :url, "http://localhost:8123")
    database = Keyword.get(config, :database, "tamandua")
    username = Keyword.get(config, :username, "default")
    password = Keyword.get(config, :password, "")

    full_url = "#{url}/?database=#{database}"

    headers =
      [{"content-type", "text/plain"}] ++
        if(username != "", do: [{"X-ClickHouse-User", username}], else: []) ++
        if(password != "", do: [{"X-ClickHouse-Key", password}], else: [])

    request = Finch.build(:post, full_url, headers, sql)

    case Finch.request(request, @finch_name, receive_timeout: 30_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"data" => data}} -> {:ok, data}
          {:ok, other} -> {:ok, other}
          {:error, _} -> {:ok, body}
        end

      {:ok, %Finch.Response{status: status, body: body}} ->
        {:error, "HTTP #{status}: #{body}"}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp execute_ddl(state, sql) do
    headers = auth_headers(state)
    request = Finch.build(:post, state.url, headers, sql)

    case Finch.request(request, @finch_name, receive_timeout: 30_000) do
      {:ok, %Finch.Response{status: status}} when status in 200..299 ->
        :ok

      {:ok, %Finch.Response{status: status, body: body}} ->
        {:error, "DDL failed HTTP #{status}: #{body}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_health_check(state) do
    url = "#{state.url}/?query=SELECT+1"
    headers = auth_headers(state)
    request = Finch.build(:get, url, headers)

    case Finch.request(request, @finch_name, receive_timeout: 5_000) do
      {:ok, %Finch.Response{status: 200}} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  defp auth_headers(state) do
    headers = [{"content-type", "text/plain"}]

    headers =
      if state.username != "",
        do: headers ++ [{"X-ClickHouse-User", state.username}],
        else: headers

    if state.password != "",
      do: headers ++ [{"X-ClickHouse-Key", state.password}],
      else: headers
  end

  # ── Formatting Helpers ──────────────────────────────────────────────

  defp schedule_flush(interval_ms) do
    Process.send_after(self(), :flush, interval_ms)
  end

  defp event_id(event) do
    id = event["event_id"] || event[:event_id] || event["id"] || event[:id]

    case id do
      nil -> UUID.uuid4()
      id when is_binary(id) -> id
      _ -> to_string(id)
    end
  end

  defp format_event_timestamp(event) do
    ts = event["timestamp"] || event[:timestamp]

    case ts do
      %DateTime{} = dt ->
        format_datetime(dt)

      ms when is_integer(ms) and ms > 1_000_000_000_000 ->
        # Milliseconds since epoch
        case DateTime.from_unix(ms, :millisecond) do
          {:ok, dt} -> format_datetime(dt)
          _ -> format_datetime(DateTime.utc_now())
        end

      ms when is_integer(ms) and ms > 0 ->
        # Seconds since epoch
        case DateTime.from_unix(ms) do
          {:ok, dt} -> format_datetime(dt)
          _ -> format_datetime(DateTime.utc_now())
        end

      f when is_float(f) and f > 0 ->
        # Float timestamps (e.g. 1738358453.794)
        ms = trunc(f * 1_000)
        case DateTime.from_unix(ms, :millisecond) do
          {:ok, dt} -> format_datetime(dt)
          _ -> format_datetime(DateTime.utc_now())
        end

      s when is_binary(s) ->
        case DateTime.from_iso8601(s) do
          {:ok, dt, _} -> format_datetime(dt)
          _ -> format_datetime(DateTime.utc_now())
        end

      _ ->
        format_datetime(DateTime.utc_now())
    end
  end

  # ClickHouse DateTime('UTC') has second precision only — omit subseconds.
  defp format_datetime(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  end

  defp format_datetime(_), do: format_datetime(DateTime.utc_now())

  # Return "0.0.0.0" for nil/empty/non-parseable IPs so ClickHouse IPv4 column
  # doesn't choke on empty strings.
  defp normalize_ip(nil), do: "0.0.0.0"
  defp normalize_ip(""), do: "0.0.0.0"
  defp normalize_ip(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, _} -> ip
      _ -> "0.0.0.0"
    end
  end
  defp normalize_ip(_), do: "0.0.0.0"

  defp to_integer(nil, default), do: default
  defp to_integer(v, _default) when is_integer(v), do: v

  defp to_integer(v, default) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> default
    end
  end

  defp to_integer(v, _default) when is_float(v), do: trunc(v)
  defp to_integer(_, default), do: default

  defp safe_json_encode(data) when is_map(data) do
    case Jason.encode(data) do
      {:ok, json} -> json
      _ -> "{}"
    end
  end

  defp safe_json_encode(data) when is_binary(data), do: data
  defp safe_json_encode(_), do: "{}"

  defp escape(value) when is_binary(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("'", "\\'")
  end

  defp escape(value), do: escape(to_string(value))

  defp build_event_filters(filters) do
    clauses = []
    params = []

    clauses =
      if agent_id = Keyword.get(filters, :agent_id) do
        clauses ++ ["agent_id = '#{escape(agent_id)}'"]
      else
        clauses
      end

    clauses =
      if org_id = Keyword.get(filters, :organization_id) do
        clauses ++ ["organization_id = '#{escape(org_id)}'"]
      else
        clauses
      end

    clauses =
      if event_type = Keyword.get(filters, :event_type) do
        clauses ++ ["event_type = '#{escape(event_type)}'"]
      else
        clauses
      end

    clauses =
      if severity = Keyword.get(filters, :severity) do
        clauses ++ ["severity = '#{escape(severity)}'"]
      else
        clauses
      end

    clauses =
      if from = Keyword.get(filters, :from) do
        clauses ++ ["timestamp >= '#{format_datetime(normalize_datetime(from))}'"]
      else
        clauses
      end

    clauses =
      if to = Keyword.get(filters, :to) do
        clauses ++ ["timestamp <= '#{format_datetime(normalize_datetime(to))}'"]
      else
        clauses
      end

    clauses =
      if keyword = Keyword.get(filters, :keyword) do
        clauses ++ ["payload LIKE '%#{escape(keyword)}%'"]
      else
        clauses
      end

    {clauses, params}
  end

  defp where_clause_sql([]), do: ""
  defp where_clause_sql(clauses), do: "WHERE " <> Enum.join(clauses, " AND ")

  defp normalize_datetime(%DateTime{} = dt), do: dt

  defp normalize_datetime(ms) when is_integer(ms) do
    case DateTime.from_unix(ms, :millisecond) do
      {:ok, dt} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp normalize_datetime(s) when is_binary(s) do
    case DateTime.from_iso8601(s) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp normalize_datetime(_), do: DateTime.utc_now()
end
