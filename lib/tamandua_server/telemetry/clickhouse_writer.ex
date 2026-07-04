defmodule TamanduaServer.Telemetry.ClickHouseWriter do
  @moduledoc """
  Batched, fault-tolerant writer for ClickHouse telemetry storage with
  compression, circuit breaker, and comprehensive metrics.

  Events are buffered in memory and flushed either when the batch size
  threshold is reached or when the flush interval timer fires, whichever
  comes first.

  ## Features

  ### Batching
  - Configurable batch size (default 1000 events)
  - Automatic flush on interval (default 5000ms)
  - Non-blocking writes (returns immediately, flushes async)

  ### Compression
  - Automatic gzip compression of all batches before transmission
  - Compression ratio tracking (typically 70-90% size reduction for JSON)
  - Content-Encoding: gzip header for transparent decompression

  ### Circuit Breaker
  - If ClickHouse becomes unreachable, the writer enters an "open" circuit
    state after `max_consecutive_failures` (default 5) consecutive failures
  - While open, all incoming events are silently dropped for
    `circuit_open_duration_ms` (default 60 000 ms)
  - After cooldown, circuit transitions to "half-open" for probe writes
  - Automatic recovery when probe succeeds

  ### Retry Logic
  - Exponential backoff: 500ms, 1000ms, 2000ms (up to 10s max)
  - Configurable retry count (default 3)
  - Per-table error tracking

  ## Prometheus Metrics

  The writer emits comprehensive metrics via `TamanduaServer.Observability.Metrics`:

  ### Counters
  - `clickhouse_events_written_total{table}` -- successfully written events
  - `clickhouse_write_success_total{table}` -- successful batch writes
  - `clickhouse_write_errors_total{table,reason}` -- failed writes by reason
  - `clickhouse_write_retries_total{table,attempt}` -- retry attempts
  - `clickhouse_events_dropped_total{reason}` -- events dropped (circuit_open, etc.)
  - `clickhouse_circuit_state_changes_total{state}` -- circuit state transitions

  ### Gauges
  - `clickhouse_circuit_state` -- current circuit state (1=open, 0.5=half-open, 0=closed)

  ### Histograms
  - `clickhouse_batch_size_bytes{table}` -- uncompressed batch sizes
  - `clickhouse_compressed_batch_bytes{table}` -- compressed batch sizes
  - `clickhouse_compression_ratio{table}` -- compression effectiveness (0.0-1.0)
  - `clickhouse_batch_event_count{table}` -- events per batch

  ### Internal Stats (via `get_stats/0`)
  - `events_written` -- total events successfully flushed
  - `events_dropped` -- events dropped due to circuit breaker or errors
  - `flush_count`    -- total flush attempts
  - `flush_errors`   -- total failed flushes
  - `last_flush_ms`  -- latency of the most recent flush (ms)
  - `queue_depth`    -- current buffer size

  These internal stats are exposed via `get_stats/0` for the health endpoint.

  ## Configuration

  ```elixir
  config :tamandua_server, TamanduaServer.Telemetry.ClickHouse,
    enabled: true,
    url: "http://localhost:8123",
    database: "tamandua",
    username: "default",
    password: "",
    batch_size: 1000,
    flush_interval_ms: 5000,
    retry_count: 3,
    max_consecutive_failures: 5,
    circuit_open_duration_ms: 60_000
  ```
  """

  use GenServer
  require Logger

  @default_batch_size 1_000
  @default_flush_interval_ms 5_000
  @default_retry_count 3
  @default_max_consecutive_failures 5
  @default_circuit_open_duration_ms 60_000
  @finch_name TamanduaServer.Finch

  # ── Public API ──────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Buffer events for batch insertion. Non-blocking (cast).
  Returns :ok immediately; events are flushed asynchronously.
  """
  @spec write(list(map())) :: :ok
  def write(events) when is_list(events) do
    GenServer.cast(__MODULE__, {:write, events})
    :ok
  catch
    :exit, _ -> :ok
  end

  @doc """
  Return current writer statistics for health monitoring.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats, 5_000)
  catch
    :exit, _ ->
      %{status: "unavailable"}
  end

  @doc """
  Force an immediate flush of the buffer. Used for graceful shutdown
  and testing.
  """
  @spec flush_now() :: :ok
  def flush_now do
    GenServer.call(__MODULE__, :flush_now, 30_000)
  catch
    :exit, _ -> :ok
  end

  # ── GenServer Callbacks ─────────────────────────────────────────────

  @impl true
  def init(_opts) do
    config = Application.get_env(:tamandua_server, TamanduaServer.Telemetry.ClickHouse, [])
    enabled = Keyword.get(config, :enabled, false)

    if enabled do
      state = %{
        enabled: true,
        url: Keyword.get(config, :url, "http://localhost:8123"),
        database: Keyword.get(config, :database, "tamandua"),
        username: Keyword.get(config, :username, "default"),
        password: Keyword.get(config, :password, ""),
        batch_size: Keyword.get(config, :batch_size, @default_batch_size),
        flush_interval_ms: Keyword.get(config, :flush_interval_ms, @default_flush_interval_ms),
        retry_count: Keyword.get(config, :retry_count, @default_retry_count),
        # Buffer
        buffer: [],
        buffer_count: 0,
        # Circuit breaker
        circuit: :closed,
        consecutive_failures: 0,
        max_consecutive_failures:
          Keyword.get(config, :max_consecutive_failures, @default_max_consecutive_failures),
        circuit_open_duration_ms:
          Keyword.get(config, :circuit_open_duration_ms, @default_circuit_open_duration_ms),
        circuit_opened_at: nil,
        # Stats
        events_written: 0,
        events_dropped: 0,
        flush_count: 0,
        flush_errors: 0,
        last_flush_ms: 0
      }

      schedule_flush(state.flush_interval_ms)

      Logger.info(
        "[ClickHouseWriter] Started -- batch_size=#{state.batch_size} " <>
          "flush_interval=#{state.flush_interval_ms}ms url=#{state.url}"
      )

      {:ok, state}
    else
      Logger.info("[ClickHouseWriter] Disabled -- ClickHouse integration is off")
      {:ok, %{enabled: false}}
    end
  end

  # ── Cast: buffer events ─────────────────────────────────────────────

  @impl true
  def handle_cast({:write, _events}, %{enabled: false} = state) do
    {:noreply, state}
  end

  @impl true
  def handle_cast({:write, events}, state) do
    case state.circuit do
      :open ->
        # Circuit is open -- check if cooldown has elapsed
        if circuit_cooldown_elapsed?(state) do
          # Transition to half-open and attempt to buffer
          Logger.info("[ClickHouseWriter] Circuit transitioning to HALF-OPEN for probe write")
          record_circuit_state_change(:half_open)

          new_state =
            state
            |> Map.put(:circuit, :half_open)
            |> buffer_events(events)

          {:noreply, maybe_flush(new_state)}
        else
          # Still in cooldown -- drop events
          dropped = length(events)

          # Record dropped events in metrics
          record_events_dropped(dropped, "circuit_open")

          {:noreply,
           %{state | events_dropped: state.events_dropped + dropped}}
        end

      _ ->
        # :closed or :half_open -- buffer normally
        new_state = buffer_events(state, events)
        {:noreply, maybe_flush(new_state)}
    end
  end

  # ── Call: stats ─────────────────────────────────────────────────────

  @impl true
  def handle_call(:get_stats, _from, %{enabled: false} = state) do
    {:reply, %{status: "disabled"}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = %{
      status: "active",
      circuit: state.circuit,
      queue_depth: state.buffer_count,
      events_written: state.events_written,
      events_dropped: state.events_dropped,
      flush_count: state.flush_count,
      flush_errors: state.flush_errors,
      last_flush_ms: state.last_flush_ms,
      consecutive_failures: state.consecutive_failures,
      batch_size: state.batch_size,
      flush_interval_ms: state.flush_interval_ms,
      # Additional observability stats
      compression_enabled: true,
      retry_count: state.retry_count,
      max_consecutive_failures: state.max_consecutive_failures,
      circuit_open_duration_ms: state.circuit_open_duration_ms
    }

    {:reply, stats, state}
  end

  # ── Call: flush now ─────────────────────────────────────────────────

  @impl true
  def handle_call(:flush_now, _from, %{enabled: false} = state) do
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:flush_now, _from, state) do
    new_state = do_flush(state)
    {:reply, :ok, new_state}
  end

  # ── Timer: periodic flush ───────────────────────────────────────────

  @impl true
  def handle_info(:flush, %{enabled: false} = state) do
    {:noreply, state}
  end

  @impl true
  def handle_info(:flush, state) do
    schedule_flush(state.flush_interval_ms)

    if state.buffer_count > 0 do
      {:noreply, do_flush(state)}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(msg, state) do
    Logger.debug("[ClickHouseWriter] Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  # ── Buffer Management ───────────────────────────────────────────────

  defp buffer_events(state, events) do
    %{
      state
      | buffer: state.buffer ++ events,
        buffer_count: state.buffer_count + length(events)
    }
  end

  defp maybe_flush(%{buffer_count: count, batch_size: batch_size} = state)
       when count >= batch_size do
    do_flush(state)
  end

  defp maybe_flush(state), do: state

  # ── Flush Logic ─────────────────────────────────────────────────────

  defp do_flush(%{buffer_count: 0} = state), do: state

  defp do_flush(state) do
    events = state.buffer
    count = state.buffer_count

    # Reset buffer before sending so new events are not blocked
    state = %{state | buffer: [], buffer_count: 0}

    start_time = System.monotonic_time(:millisecond)

    result =
      try do
        send_batch(events, state)
      rescue
        e ->
          Logger.error("[ClickHouseWriter] Flush exception: #{Exception.message(e)}")
          {:error, Exception.message(e)}
      end

    elapsed = System.monotonic_time(:millisecond) - start_time

    case result do
      :ok ->
        state
        |> Map.put(:events_written, state.events_written + count)
        |> Map.put(:flush_count, state.flush_count + 1)
        |> Map.put(:last_flush_ms, elapsed)
        |> Map.put(:consecutive_failures, 0)
        |> close_circuit_if_half_open()

      {:error, reason} ->
        Logger.error(
          "[ClickHouseWriter] Flush failed (#{count} events, #{elapsed}ms): #{inspect(reason)}"
        )

        failures = state.consecutive_failures + 1

        state
        |> Map.put(:flush_errors, state.flush_errors + 1)
        |> Map.put(:events_dropped, state.events_dropped + count)
        |> Map.put(:last_flush_ms, elapsed)
        |> Map.put(:consecutive_failures, failures)
        |> maybe_open_circuit(failures)
    end
  end

  # ── HTTP Batch Insert ───────────────────────────────────────────────

  defp send_batch(events, state) do
    # Group events by target table
    grouped = group_events_by_table(events)

    errors =
      Enum.reduce(grouped, [], fn {table, rows}, acc ->
        case insert_rows(table, rows, state) do
          :ok -> acc
          {:error, reason} -> [{table, reason} | acc]
        end
      end)

    if errors == [] do
      :ok
    else
      {:error, errors}
    end
  end

  defp insert_rows(table, rows, state, attempt \\ 1) do
    json_body =
      rows
      |> Enum.map(&Jason.encode!/1)
      |> Enum.join("\n")

    # Compress the JSON body with gzip for efficient transport
    compressed_body = :zlib.gzip(json_body)
    uncompressed_size = byte_size(json_body)
    compressed_size = byte_size(compressed_body)

    # Track compression ratio for observability
    compression_ratio = if uncompressed_size > 0 do
      compressed_size / uncompressed_size
    else
      1.0
    end

    # Emit metrics for batch size and compression
    record_batch_metrics(table, length(rows), uncompressed_size, compressed_size, compression_ratio)

    query = "INSERT INTO #{table} FORMAT JSONEachRow"
    url = "#{state.url}/?database=#{state.database}&query=#{URI.encode(query)}"
    headers = auth_headers(state) ++ [{"Content-Encoding", "gzip"}]

    request = Finch.build(:post, url, headers, compressed_body)

    case Finch.request(request, @finch_name, receive_timeout: 30_000) do
      {:ok, %Finch.Response{status: status}} when status in 200..299 ->
        Logger.debug("[ClickHouseWriter] Inserted #{length(rows)} rows into #{table}")
        record_write_success(table, length(rows))
        :ok

      {:ok, %Finch.Response{status: status, body: body}} ->
        if attempt < state.retry_count do
          backoff = retry_backoff(attempt)
          Logger.warning("[ClickHouseWriter] Retry #{attempt} for #{table} in #{backoff}ms (HTTP #{status})")
          record_write_retry(table, attempt)
          Process.sleep(backoff)
          insert_rows(table, rows, state, attempt + 1)
        else
          record_write_error(table, "http_#{status}")
          {:error, "HTTP #{status}: #{String.slice(body, 0, 500)}"}
        end

      {:error, reason} ->
        if attempt < state.retry_count do
          backoff = retry_backoff(attempt)
          Logger.warning("[ClickHouseWriter] Retry #{attempt} for #{table} in #{backoff}ms")
          record_write_retry(table, attempt)
          Process.sleep(backoff)
          insert_rows(table, rows, state, attempt + 1)
        else
          record_write_error(table, "request_failed")
          {:error, inspect(reason)}
        end
    end
  end

  defp retry_backoff(attempt) do
    # Exponential backoff: 500ms, 1000ms, 2000ms ...
    min(500 * :math.pow(2, attempt - 1) |> trunc(), 10_000)
  end

  # ── Circuit Breaker ─────────────────────────────────────────────────

  defp maybe_open_circuit(state, failures)
       when failures >= state.max_consecutive_failures do
    Logger.error(
      "[ClickHouseWriter] Circuit OPEN after #{failures} consecutive failures. " <>
        "Writes disabled for #{state.circuit_open_duration_ms}ms."
    )

    # Record circuit breaker opening in metrics
    record_circuit_state_change(:open)

    %{
      state
      | circuit: :open,
        circuit_opened_at: System.monotonic_time(:millisecond)
    }
  end

  defp maybe_open_circuit(state, _failures), do: state

  defp circuit_cooldown_elapsed?(state) do
    now = System.monotonic_time(:millisecond)
    elapsed = now - (state.circuit_opened_at || now)
    elapsed >= state.circuit_open_duration_ms
  end

  defp close_circuit_if_half_open(%{circuit: :half_open} = state) do
    Logger.info("[ClickHouseWriter] Circuit CLOSED -- probe write succeeded")
    record_circuit_state_change(:closed)
    %{state | circuit: :closed, circuit_opened_at: nil}
  end

  defp close_circuit_if_half_open(state), do: state

  # ── Event Routing ───────────────────────────────────────────────────

  defp group_events_by_table(events) do
    events
    |> Enum.group_by(&target_table/1)
    |> Enum.map(fn {table, evts} ->
      {table, Enum.map(evts, &format_for_table(table, &1))}
    end)
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

    event_type_raw = event["event_type"] || event[:event_type] || "create"
    event_type_enum =
      case to_string(event_type_raw) do
        "process_terminate" -> "exit"
        "process_exec" -> "exec"
        _ -> "create"
      end

    %{
      event_id: event_id(event),
      timestamp: format_event_timestamp(event),
      agent_id: to_str(event, "agent_id"),
      organization_id: to_str(event, "organization_id"),
      event_type: event_type_enum,
      process_id: to_uint(payload, "pid", 0),
      parent_process_id: to_uint(payload, "ppid", 0),
      process_name:
        to_str(payload, "process_name")
        |> fallback(to_str(payload, "name"))
        |> fallback(to_str(payload, "image"))
        |> fallback(to_str(payload, "exe")),
      command_line:
        to_str(payload, "command_line")
        |> fallback(to_str(payload, "cmdline"))
        |> fallback(to_str(payload, "commandline")),
      executable_path:
        to_str(payload, "executable_path")
        |> fallback(to_str(payload, "path"))
        |> fallback(to_str(payload, "image_path")),
      user_name:
        to_str(payload, "username")
        |> fallback(to_str(payload, "user"))
        |> fallback(to_str(payload, "user_name")),
      is_elevated: bool_to_uint8(payload, "is_elevated"),
      is_signed: bool_to_uint8(payload, "is_signed"),
      signer: to_str(payload, "signer"),
      file_hash:
        to_str(payload, "sha256") |> fallback(to_str(payload, "hash_sha256")),
      exit_code: to_int(payload, "exit_code", 0)
    }
  end

  defp format_for_table("dns_queries", event) do
    payload = event["payload"] || event[:payload] || %{}

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
      timestamp: format_event_timestamp(event),
      agent_id: to_str(event, "agent_id"),
      organization_id: to_str(event, "organization_id"),
      process_id: to_uint(payload, "pid", 0) |> fallback_uint(to_uint(payload, "process_id", 0)),
      process_name: to_str(payload, "process_name"),
      query_name:
        to_str(payload, "query_name")
        |> fallback(to_str(payload, "query"))
        |> fallback(to_str(payload, "domain"))
        |> fallback(to_str(payload, "dns_query")),
      query_type: to_str(payload, "query_type"),
      response_code: to_uint(payload, "response_code", 0),
      response_data: response_data,
      is_suspicious: bool_to_uint8(payload, "is_suspicious")
    }
  end

  defp format_for_table("network_flows", event) do
    payload = event["payload"] || event[:payload] || %{}

    direction_raw = payload["direction"] || payload[:direction] || "outbound"
    direction = if to_string(direction_raw) == "inbound", do: "inbound", else: "outbound"

    protocol_raw = payload["protocol"] || payload[:protocol] || "tcp"
    protocol =
      case to_string(protocol_raw) |> String.downcase() do
        "udp" -> "udp"
        "tcp" -> "tcp"
        _ -> "other"
      end

    %{
      event_id: event_id(event),
      timestamp: format_event_timestamp(event),
      agent_id: to_str(event, "agent_id"),
      organization_id: to_str(event, "organization_id"),
      process_id: to_uint(payload, "pid", 0),
      process_name: to_str(payload, "process_name"),
      direction: direction,
      protocol: protocol,
      source_ip:
        to_str(payload, "source_ip") |> fallback(to_str(payload, "local_ip")),
      dest_ip:
        to_str(payload, "dest_ip") |> fallback(to_str(payload, "remote_ip")),
      source_port:
        to_uint(payload, "source_port", 0) |> fallback_uint(to_uint(payload, "local_port", 0)),
      dest_port:
        to_uint(payload, "dest_port", 0) |> fallback_uint(to_uint(payload, "remote_port", 0)),
      bytes_sent: to_uint(payload, "bytes_sent", 0),
      bytes_received: to_uint(payload, "bytes_received", 0),
      duration_ms: to_uint(payload, "duration_ms", 0),
      country_code: String.slice(to_str(payload, "country_code") |> fallback("--"), 0, 2),
      asn: to_uint(payload, "asn", 0)
    }
  end

  defp format_for_table("file_events", event) do
    payload = event["payload"] || event[:payload] || %{}

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
      timestamp: format_event_timestamp(event),
      agent_id: to_str(event, "agent_id"),
      organization_id: to_str(event, "organization_id"),
      file_path: to_str(payload, "file_path") |> fallback(to_str(payload, "path")),
      file_action: file_action,
      file_hash: to_str(payload, "sha256") |> fallback(to_str(payload, "hash")),
      file_size: to_uint(payload, "file_size", 0) |> fallback_uint(to_uint(payload, "size", 0)),
      process_id: to_uint(payload, "pid", 0),
      process_name: to_str(payload, "process_name"),
      user_name: to_str(payload, "username"),
      is_suspicious: bool_to_uint8(payload, "is_suspicious")
    }
  end

  defp format_for_table("registry_events", event) do
    payload = event["payload"] || event[:payload] || %{}

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
      timestamp: format_event_timestamp(event),
      agent_id: to_str(event, "agent_id"),
      organization_id: to_str(event, "organization_id"),
      registry_key: to_str(payload, "key") |> fallback(to_str(payload, "registry_key")),
      registry_value: to_str(payload, "value_name") |> fallback(to_str(payload, "value")),
      registry_action: registry_action,
      registry_data: to_str(payload, "data") |> fallback(to_str(payload, "registry_data")),
      registry_type: to_str(payload, "value_type") |> fallback(to_str(payload, "registry_type")),
      process_id: to_uint(payload, "pid", 0),
      process_name: to_str(payload, "process_name"),
      user_name: to_str(payload, "username"),
      is_suspicious: bool_to_uint8(payload, "is_suspicious")
    }
  end

  defp format_for_table("alert_events", event) do
    payload = event["payload"] || event[:payload] || %{}
    analysis = event["analysis"] || event[:analysis] || %{}

    severity_raw = event["severity"] || event[:severity] || payload["severity"] || payload[:severity] || "info"
    severity =
      case to_string(severity_raw) do
        s when s in ["info", "low", "medium", "high", "critical"] -> s
        _ -> "info"
      end

    %{
      event_id: event_id(event),
      timestamp: format_event_timestamp(event),
      agent_id: to_str(event, "agent_id"),
      organization_id: to_str(event, "organization_id"),
      alert_id: to_str(event, "alert_id") |> fallback(to_str(payload, "alert_id")),
      rule_name: to_str(payload, "rule_name") |> fallback(to_str(analysis, "rule_name")) |> fallback(to_str(event, "rule")),
      severity: severity,
      mitre_technique: to_str(analysis, "mitre_technique") |> fallback(to_str(payload, "mitre_technique")),
      mitre_tactic: to_str(analysis, "mitre_tactic") |> fallback(to_str(payload, "mitre_tactic")),
      details: safe_json(payload),
      source_event_id: to_str(payload, "source_event_id"),
      process_name: to_str(payload, "process_name"),
      process_id: to_uint(payload, "pid", 0),
      command_line: to_str(payload, "command_line"),
      file_path: to_str(payload, "file_path"),
      file_hash: to_str(payload, "sha256") |> fallback(to_str(payload, "hash")),
      source_ip: to_str(payload, "source_ip"),
      dest_ip: to_str(payload, "dest_ip"),
      verdict: to_str(payload, "verdict")
    }
  end

  defp format_for_table("telemetry_events", event) do
    payload = event["payload"] || event[:payload] || %{}
    analysis = event["analysis"] || event[:analysis] || %{}

    severity_raw = event["severity"] || event[:severity] || "info"
    severity =
      case to_string(severity_raw) do
        s when s in ["info", "low", "medium", "high", "critical"] -> s
        _ -> "info"
      end

    %{
      event_id: event_id(event),
      timestamp: format_event_timestamp(event),
      agent_id: to_str(event, "agent_id"),
      organization_id: to_str(event, "organization_id"),
      event_type: to_string(event["event_type"] || event[:event_type] || "unknown"),
      severity: severity,
      process_name: to_str(payload, "process_name"),
      process_id: to_uint(payload, "pid", 0),
      parent_process_id: to_uint(payload, "ppid", 0),
      command_line: to_str(payload, "command_line"),
      user_name: to_str(payload, "username"),
      file_path: to_str(payload, "file_path"),
      file_hash: to_str(payload, "sha256") |> fallback(to_str(payload, "hash")),
      dns_query: to_str(payload, "query_name") |> fallback(to_str(payload, "domain")),
      dns_response: to_str(payload, "response_data"),
      rule_name: to_str(analysis, "rule_name"),
      mitre_technique:
        to_str(analysis, "mitre_technique") |> fallback(deep_str(analysis, [:mitre, :technique])),
      mitre_tactic:
        to_str(analysis, "mitre_tactic") |> fallback(deep_str(analysis, [:mitre, :tactic])),
      threat_score: to_float(analysis, "threat_score", 0.0),
      source_ip_str: to_str(event, "source_ip"),
      hostname: to_str(event, "hostname"),
      payload: safe_json(payload),
      metadata: safe_json(event["metadata"] || event[:metadata] || %{})
    }
  end

  # ── Formatting Helpers ──────────────────────────────────────────────

  defp schedule_flush(interval_ms) do
    Process.send_after(self(), :flush, interval_ms)
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
        case DateTime.from_unix(ms, :millisecond) do
          {:ok, dt} -> format_datetime(dt)
          _ -> format_datetime(DateTime.utc_now())
        end

      s when is_integer(s) and s > 0 ->
        case DateTime.from_unix(s) do
          {:ok, dt} -> format_datetime(dt)
          _ -> format_datetime(DateTime.utc_now())
        end

      f when is_float(f) and f > 0 ->
        # Float timestamps (e.g. 1738358453.794) — convert to ms integer
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

  # Flexible field access supporting both string and atom keys
  defp to_str(map, key) when is_map(map) do
    val = map[key] || map[String.to_atom(key)]
    if is_binary(val), do: val, else: to_string(val || "")
  rescue
    _ -> ""
  end

  defp to_str(_, _), do: ""

  defp deep_str(map, keys) when is_map(map) and is_list(keys) do
    result = get_in(map, keys)
    if result, do: to_string(result), else: ""
  rescue
    _ -> ""
  end

  defp deep_str(_, _), do: ""

  defp to_uint(map, key, default) when is_map(map) do
    val = map[key] || map[String.to_atom(key)]

    case val do
      nil -> default
      v when is_integer(v) and v >= 0 -> v
      v when is_integer(v) -> 0
      v when is_float(v) -> max(trunc(v), 0)
      v when is_binary(v) ->
        case Integer.parse(v) do
          {n, _} -> max(n, 0)
          :error -> default
        end
      _ -> default
    end
  rescue
    _ -> default
  end

  defp to_uint(_, _, default), do: default

  defp to_int(map, key, default) when is_map(map) do
    val = map[key] || map[String.to_atom(key)]

    case val do
      nil -> default
      v when is_integer(v) -> v
      v when is_float(v) -> trunc(v)
      v when is_binary(v) ->
        case Integer.parse(v) do
          {n, _} -> n
          :error -> default
        end
      _ -> default
    end
  rescue
    _ -> default
  end

  defp to_int(_, _, default), do: default

  defp to_float(map, key, default) when is_map(map) do
    val = map[key] || map[String.to_atom(key)]

    case val do
      nil -> default
      v when is_float(v) -> v
      v when is_integer(v) -> v * 1.0
      v when is_binary(v) ->
        case Float.parse(v) do
          {f, _} -> f
          :error -> default
        end
      _ -> default
    end
  rescue
    _ -> default
  end

  defp to_float(_, _, default), do: default

  defp bool_to_uint8(map, key) when is_map(map) do
    val = map[key] || map[String.to_atom(key)]
    if val in [true, 1, "1", "true"], do: 1, else: 0
  rescue
    _ -> 0
  end

  defp bool_to_uint8(_, _), do: 0

  defp fallback("", replacement), do: replacement
  defp fallback(value, _replacement), do: value

  defp fallback_uint(0, replacement), do: replacement
  defp fallback_uint(value, _replacement), do: value

  defp safe_json(data) when is_map(data) do
    case Jason.encode(data) do
      {:ok, json} -> json
      _ -> "{}"
    end
  end

  defp safe_json(data) when is_binary(data), do: data
  defp safe_json(_), do: "{}"

  # ── Metrics Integration ─────────────────────────────────────────────

  defp record_batch_metrics(table, row_count, uncompressed_bytes, compressed_bytes, compression_ratio) do
    try do
      # Record batch size in bytes (histogram for distribution tracking)
      TamanduaServer.Observability.Metrics.observe(
        :clickhouse_batch_size_bytes,
        uncompressed_bytes,
        table: table
      )

      # Record compressed batch size
      TamanduaServer.Observability.Metrics.observe(
        :clickhouse_compressed_batch_bytes,
        compressed_bytes,
        table: table
      )

      # Record compression ratio (histogram to track effectiveness)
      TamanduaServer.Observability.Metrics.observe(
        :clickhouse_compression_ratio,
        compression_ratio,
        table: table
      )

      # Record event count per batch
      TamanduaServer.Observability.Metrics.observe(
        :clickhouse_batch_event_count,
        row_count,
        table: table
      )
    rescue
      e ->
        Logger.debug("[ClickHouseWriter] Metrics recording failed: #{Exception.message(e)}")
    end
  end

  defp record_write_success(table, row_count) do
    try do
      TamanduaServer.Observability.Metrics.increment(
        :clickhouse_events_written_total,
        row_count,
        table: table
      )

      TamanduaServer.Observability.Metrics.increment(
        :clickhouse_write_success_total,
        1,
        table: table
      )
    rescue
      e ->
        Logger.debug("[ClickHouseWriter] Metrics recording failed: #{Exception.message(e)}")
    end
  end

  defp record_write_error(table, reason) do
    try do
      TamanduaServer.Observability.Metrics.increment(
        :clickhouse_write_errors_total,
        1,
        table: table, reason: reason
      )
    rescue
      e ->
        Logger.debug("[ClickHouseWriter] Metrics recording failed: #{Exception.message(e)}")
    end
  end

  defp record_write_retry(table, attempt) do
    try do
      TamanduaServer.Observability.Metrics.increment(
        :clickhouse_write_retries_total,
        1,
        table: table, attempt: to_string(attempt)
      )
    rescue
      e ->
        Logger.debug("[ClickHouseWriter] Metrics recording failed: #{Exception.message(e)}")
    end
  end

  defp record_circuit_state_change(new_state) do
    try do
      # Increment circuit state transition counter
      TamanduaServer.Observability.Metrics.increment(
        :clickhouse_circuit_state_changes_total,
        1,
        state: to_string(new_state)
      )

      # Set current circuit state gauge (1 = open, 0 = closed)
      state_value = case new_state do
        :open -> 1
        :closed -> 0
        :half_open -> 0.5
      end

      TamanduaServer.Observability.Metrics.set_gauge(
        :clickhouse_circuit_state,
        state_value,
        []
      )
    rescue
      e ->
        Logger.debug("[ClickHouseWriter] Circuit metrics recording failed: #{Exception.message(e)}")
    end
  end

  defp record_events_dropped(count, reason) do
    try do
      TamanduaServer.Observability.Metrics.increment(
        :clickhouse_events_dropped_total,
        count,
        reason: reason
      )
    rescue
      e ->
        Logger.debug("[ClickHouseWriter] Dropped events metrics recording failed: #{Exception.message(e)}")
    end
  end
end
