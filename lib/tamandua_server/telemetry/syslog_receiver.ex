defmodule TamanduaServer.Telemetry.SyslogReceiver do
  @moduledoc """
  High-throughput syslog receiver that listens for third-party log sources
  over UDP and TCP, transforming Tamandua into a mini-SIEM.

  Supports:
  - RFC 5424 syslog over UDP (default port 1514) and TCP (default port 1515)
  - RFC 3164 (BSD) syslog
  - CEF (Common Event Format) embedded in syslog - firewalls, IDS/IPS
  - LEEF (Log Event Extended Format) embedded in syslog - QRadar

  Events are parsed, normalized to a common schema, and forwarded in batches
  to the ClickHouseWriter for high-volume storage. Rate limiting per source IP
  prevents any single log source from overwhelming the receiver.

  ## Configuration

      config :tamandua_server, TamanduaServer.Telemetry.SyslogReceiver,
        enabled: true,
        udp_port: 1514,
        tcp_port: 1515,
        rate_limit_per_source: 10_000,    # events/sec per source IP
        rate_limit_window_ms: 1_000,
        batch_size: 500,
        flush_interval_ms: 2_000,
        max_message_size: 65_536,
        max_tcp_connections: 500

  ## Architecture

  The GenServer owns a UDP socket (`:gen_udp`) and a TCP listener (`:gen_tcp`).
  TCP connections are accepted in a spawned acceptor loop, each connection handled
  by a dedicated process that reads newline-delimited messages. Parsed events are
  buffered in the GenServer state and flushed in batches to ClickHouseWriter.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Telemetry.LogNormalizer
  alias TamanduaServer.Telemetry.ClickHouseWriter

  @default_udp_port 1514
  @default_tcp_port 1515
  @default_rate_limit 10_000
  @default_rate_window_ms 1_000
  @default_batch_size 500
  @default_flush_interval_ms 2_000
  @default_max_message_size 65_536
  @default_max_tcp_connections 500

  # ── Public API ──────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Return current receiver statistics for health monitoring.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats, 5_000)
  catch
    :exit, _ -> %{status: "unavailable"}
  end

  @doc """
  Inject a raw syslog message for parsing and ingestion.
  Useful for testing and for the HTTP log ingestion controller.
  """
  @spec ingest_raw(String.t(), String.t()) :: :ok
  def ingest_raw(raw_message, source_ip \\ "api") do
    GenServer.cast(__MODULE__, {:ingest_raw, raw_message, source_ip})
  end

  @doc """
  Inject a list of already-normalized events for batched storage.
  Used by the log ingestion controller to bypass parsing.
  """
  @spec ingest_normalized(list(map())) :: :ok
  def ingest_normalized(events) when is_list(events) do
    GenServer.cast(__MODULE__, {:ingest_normalized, events})
  end

  # ── GenServer Callbacks ─────────────────────────────────────────────

  @impl true
  def init(_opts) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    enabled = Keyword.get(config, :enabled, false)

    if enabled do
      udp_port = Keyword.get(config, :udp_port, @default_udp_port)
      tcp_port = Keyword.get(config, :tcp_port, @default_tcp_port)
      rate_limit = Keyword.get(config, :rate_limit_per_source, @default_rate_limit)
      rate_window = Keyword.get(config, :rate_limit_window_ms, @default_rate_window_ms)
      batch_size = Keyword.get(config, :batch_size, @default_batch_size)
      flush_interval = Keyword.get(config, :flush_interval_ms, @default_flush_interval_ms)
      max_msg_size = Keyword.get(config, :max_message_size, @default_max_message_size)
      max_tcp_conns = Keyword.get(config, :max_tcp_connections, @default_max_tcp_connections)

      # Create ETS table for rate limiting
      :ets.new(:syslog_rate_limits, [:named_table, :public, :set])

      # Open UDP socket
      udp_socket =
        case :gen_udp.open(udp_port, [:binary, active: true, recbuf: 1_048_576]) do
          {:ok, sock} ->
            Logger.info("[SyslogReceiver] UDP listening on port #{udp_port}")
            sock

          {:error, reason} ->
            Logger.error("[SyslogReceiver] Failed to open UDP port #{udp_port}: #{inspect(reason)}")
            nil
        end

      # Open TCP listener
      tcp_listener =
        case :gen_tcp.listen(tcp_port, [
               :binary,
               active: false,
               reuseaddr: true,
               packet: :line,
               buffer: max_msg_size,
               backlog: 128
             ]) do
          {:ok, listener} ->
            Logger.info("[SyslogReceiver] TCP listening on port #{tcp_port}")
            # Start acceptor loop
            spawn_tcp_acceptor(listener, self(), max_tcp_conns)
            listener

          {:error, reason} ->
            Logger.error("[SyslogReceiver] Failed to open TCP port #{tcp_port}: #{inspect(reason)}")
            nil
        end

      # Schedule periodic flush
      schedule_flush(flush_interval)

      # Schedule periodic rate limit cleanup
      schedule_rate_cleanup()

      state = %{
        enabled: true,
        udp_socket: udp_socket,
        tcp_listener: tcp_listener,
        udp_port: udp_port,
        tcp_port: tcp_port,
        rate_limit: rate_limit,
        rate_window_ms: rate_window,
        batch_size: batch_size,
        flush_interval_ms: flush_interval,
        max_message_size: max_msg_size,
        max_tcp_connections: max_tcp_conns,
        # Event buffer
        buffer: [],
        buffer_count: 0,
        # Stats
        events_received: 0,
        events_parsed: 0,
        events_dropped_rate_limit: 0,
        events_dropped_parse_error: 0,
        events_forwarded: 0,
        tcp_connections_active: 0,
        tcp_connections_total: 0,
        last_event_at: nil
      }

      Logger.info(
        "[SyslogReceiver] Started -- UDP=#{udp_port} TCP=#{tcp_port} " <>
          "rate_limit=#{rate_limit}/s batch_size=#{batch_size}"
      )

      {:ok, state}
    else
      Logger.info("[SyslogReceiver] Disabled -- syslog ingestion is off")
      {:ok, %{enabled: false}}
    end
  end

  # ── UDP Messages ──────────────────────────────────────────────────

  @impl true
  def handle_info({:udp, _socket, src_ip, _src_port, data}, %{enabled: true} = state) do
    source_ip = format_ip(src_ip)
    state = %{state | events_received: state.events_received + 1, last_event_at: System.system_time(:second)}

    if rate_limited?(source_ip, state) do
      {:noreply, %{state | events_dropped_rate_limit: state.events_dropped_rate_limit + 1}}
    else
      record_event(source_ip)
      state = process_raw_message(data, source_ip, state)
      {:noreply, maybe_flush(state)}
    end
  end

  # ── TCP Connection Notifications ───────────────────────────────────

  @impl true
  def handle_info({:tcp_connection, :accepted, client_ip}, %{enabled: true} = state) do
    state = %{
      state
      | tcp_connections_active: state.tcp_connections_active + 1,
        tcp_connections_total: state.tcp_connections_total + 1
    }

    Logger.debug("[SyslogReceiver] TCP connection from #{client_ip} (active: #{state.tcp_connections_active})")
    {:noreply, state}
  end

  @impl true
  def handle_info({:tcp_connection, :closed, client_ip}, %{enabled: true} = state) do
    state = %{state | tcp_connections_active: max(state.tcp_connections_active - 1, 0)}
    Logger.debug("[SyslogReceiver] TCP connection closed from #{client_ip} (active: #{state.tcp_connections_active})")
    {:noreply, state}
  end

  @impl true
  def handle_info({:tcp_data, data, source_ip}, %{enabled: true} = state) do
    state = %{state | events_received: state.events_received + 1, last_event_at: System.system_time(:second)}

    if rate_limited?(source_ip, state) do
      {:noreply, %{state | events_dropped_rate_limit: state.events_dropped_rate_limit + 1}}
    else
      record_event(source_ip)
      state = process_raw_message(data, source_ip, state)
      {:noreply, maybe_flush(state)}
    end
  end

  # ── Periodic Flush ─────────────────────────────────────────────────

  @impl true
  def handle_info(:flush, %{enabled: false} = state) do
    {:noreply, state}
  end

  @impl true
  def handle_info(:flush, %{enabled: true} = state) do
    schedule_flush(state.flush_interval_ms)

    if state.buffer_count > 0 do
      {:noreply, do_flush(state)}
    else
      {:noreply, state}
    end
  end

  # ── Rate Limit Cleanup ────────────────────────────────────────────

  @impl true
  def handle_info(:cleanup_rate_limits, %{enabled: true} = state) do
    cleanup_rate_limits(state.rate_window_ms)
    schedule_rate_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_rate_limits, state) do
    {:noreply, state}
  end

  # ── Catch-all ──────────────────────────────────────────────────────

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ── Casts: Programmatic Ingestion ──────────────────────────────────

  @impl true
  def handle_cast({:ingest_raw, raw_message, source_ip}, %{enabled: true} = state) do
    state = %{state | events_received: state.events_received + 1, last_event_at: System.system_time(:second)}

    if rate_limited?(source_ip, state) do
      {:noreply, %{state | events_dropped_rate_limit: state.events_dropped_rate_limit + 1}}
    else
      record_event(source_ip)
      state = process_raw_message(raw_message, source_ip, state)
      {:noreply, maybe_flush(state)}
    end
  end

  @impl true
  def handle_cast({:ingest_normalized, events}, %{enabled: true} = state) do
    clickhouse_events = Enum.map(events, &to_clickhouse_event/1)

    state = %{
      state
      | buffer: state.buffer ++ clickhouse_events,
        buffer_count: state.buffer_count + length(clickhouse_events),
        events_parsed: state.events_parsed + length(events),
        last_event_at: System.system_time(:second)
    }

    {:noreply, maybe_flush(state)}
  end

  @impl true
  def handle_cast(_msg, %{enabled: false} = state) do
    {:noreply, state}
  end

  # ── Stats ──────────────────────────────────────────────────────────

  @impl true
  def handle_call(:get_stats, _from, %{enabled: false} = state) do
    {:reply, %{status: "disabled"}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = %{
      status: "active",
      udp_port: state.udp_port,
      tcp_port: state.tcp_port,
      events_received: state.events_received,
      events_parsed: state.events_parsed,
      events_dropped_rate_limit: state.events_dropped_rate_limit,
      events_dropped_parse_error: state.events_dropped_parse_error,
      events_forwarded: state.events_forwarded,
      buffer_depth: state.buffer_count,
      tcp_connections_active: state.tcp_connections_active,
      tcp_connections_total: state.tcp_connections_total,
      last_event_at: state.last_event_at
    }

    {:reply, stats, state}
  end

  # ── Terminate ──────────────────────────────────────────────────────

  @impl true
  def terminate(_reason, %{enabled: true} = state) do
    # Flush remaining buffer
    if state.buffer_count > 0 do
      do_flush(state)
    end

    # Close sockets
    if state.udp_socket, do: :gen_udp.close(state.udp_socket)
    if state.tcp_listener, do: :gen_tcp.close(state.tcp_listener)

    # Clean up ETS
    try do
      :ets.delete(:syslog_rate_limits)
    rescue
      _ -> :ok
    end

    Logger.info("[SyslogReceiver] Stopped -- flushed remaining events")
    :ok
  end

  @impl true
  def terminate(_reason, _state), do: :ok

  # ── Private: Message Processing ────────────────────────────────────

  defp process_raw_message(data, source_ip, state) do
    raw = sanitize_message(data)

    case LogNormalizer.auto_parse(raw) do
      {:ok, parsed} ->
        normalized =
          parsed
          |> LogNormalizer.normalize()
          |> Map.put(:source_ip, source_ip)

        # Optionally extract IOCs for detection engine matching
        iocs = LogNormalizer.extract_iocs(normalized)
        normalized = Map.put(normalized, :iocs, iocs)

        event = to_clickhouse_event(normalized)

        # If IOCs were found, also notify the detection engine asynchronously
        if iocs.total_count > 0 do
          notify_detection_engine(normalized, iocs)
        end

        %{
          state
          | buffer: [event | state.buffer],
            buffer_count: state.buffer_count + 1,
            events_parsed: state.events_parsed + 1
        }

      {:error, reason} ->
        Logger.debug("[SyslogReceiver] Parse error from #{source_ip}: #{reason}")
        %{state | events_dropped_parse_error: state.events_dropped_parse_error + 1}
    end
  end

  defp sanitize_message(data) when is_binary(data) do
    data
    |> String.replace(<<0>>, "")
    |> String.trim()
  end

  defp sanitize_message(_), do: ""

  # ── Private: ClickHouse Event Format ───────────────────────────────

  defp to_clickhouse_event(normalized) do
    extracted = normalized[:extracted] || %{}

    timestamp =
      case normalized[:timestamp] do
        %DateTime{} = dt -> Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
        _ -> Calendar.strftime(DateTime.utc_now(), "%Y-%m-%d %H:%M:%S")
      end

    %{
      "event_id" => UUID.uuid4(),
      "event_type" => "third_party_log",
      "timestamp" => timestamp,
      "agent_id" => "siem-ingest",
      "organization_id" => "",
      "severity" => severity_to_string(normalized[:severity]),
      "source_ip" => normalized[:source_ip] || "",
      "hostname" => normalized[:hostname] || "",
      "payload" =>
        Jason.encode!(%{
          source_type: normalized[:source_type] || "syslog",
          facility: normalized[:facility] || "",
          app_name: normalized[:app_name] || "",
          message: normalized[:message] || "",
          extracted: stringify_extracted(extracted),
          raw: truncate(normalized[:raw] || "", 8192)
        }),
      "metadata" =>
        Jason.encode!(%{
          ingestion_source: "syslog_receiver",
          source_format: normalized[:source_type] || "syslog",
          ingested_at: DateTime.to_iso8601(DateTime.utc_now())
        })
    }
  end

  defp severity_to_string(sev) when is_integer(sev) do
    case sev do
      s when s <= 2 -> "critical"
      3 -> "high"
      4 -> "medium"
      5 -> "low"
      _ -> "info"
    end
  end

  defp severity_to_string(_), do: "info"

  defp stringify_extracted(extracted) when is_map(extracted) do
    Map.new(extracted, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end

  defp stringify_extracted(_), do: %{}

  defp truncate(str, max_len) when byte_size(str) > max_len do
    String.slice(str, 0, max_len)
  end

  defp truncate(str, _max_len), do: str

  # ── Private: Buffer Flush ──────────────────────────────────────────

  defp maybe_flush(%{buffer_count: count, batch_size: batch_size} = state)
       when count >= batch_size do
    do_flush(state)
  end

  defp maybe_flush(state), do: state

  defp do_flush(%{buffer_count: 0} = state), do: state

  defp do_flush(state) do
    events = state.buffer
    count = state.buffer_count

    # Reset buffer immediately
    state = %{state | buffer: [], buffer_count: 0}

    # Forward to ClickHouseWriter asynchronously
    try do
      ClickHouseWriter.write(events)

      Logger.debug("[SyslogReceiver] Flushed #{count} events to ClickHouseWriter")

      %{state | events_forwarded: state.events_forwarded + count}
    rescue
      e ->
        Logger.error("[SyslogReceiver] Flush error: #{Exception.message(e)}")
        state
    catch
      :exit, reason ->
        Logger.error("[SyslogReceiver] ClickHouseWriter unavailable: #{inspect(reason)}")
        state
    end
  end

  # ── Private: Rate Limiting ─────────────────────────────────────────

  defp rate_limited?(source_ip, state) do
    now_ms = System.system_time(:millisecond)

    case :ets.lookup(:syslog_rate_limits, source_ip) do
      [{^source_ip, count, window_start}] ->
        if now_ms - window_start < state.rate_window_ms do
          count >= state.rate_limit
        else
          # Window expired, reset
          :ets.insert(:syslog_rate_limits, {source_ip, 0, now_ms})
          false
        end

      [] ->
        :ets.insert(:syslog_rate_limits, {source_ip, 0, now_ms})
        false
    end
  rescue
    _ -> false
  end

  defp record_event(source_ip) do
    :ets.update_counter(:syslog_rate_limits, source_ip, {2, 1})
  rescue
    _ ->
      :ets.insert(:syslog_rate_limits, {source_ip, 1, System.system_time(:millisecond)})
  end

  defp cleanup_rate_limits(window_ms) do
    now_ms = System.system_time(:millisecond)
    cutoff = now_ms - window_ms * 10

    :ets.foldl(
      fn {ip, _count, window_start}, acc ->
        if window_start < cutoff do
          :ets.delete(:syslog_rate_limits, ip)
        end

        acc
      end,
      :ok,
      :syslog_rate_limits
    )
  rescue
    _ -> :ok
  end

  # ── Private: TCP Acceptor ──────────────────────────────────────────

  defp spawn_tcp_acceptor(listener, parent, max_connections) do
    spawn_link(fn -> tcp_accept_loop(listener, parent, max_connections) end)
  end

  defp tcp_accept_loop(listener, parent, max_connections) do
    case :gen_tcp.accept(listener, 5_000) do
      {:ok, client_socket} ->
        case :inet.peername(client_socket) do
          {:ok, {ip, _port}} ->
            client_ip = format_ip(ip)
            send(parent, {:tcp_connection, :accepted, client_ip})

            # Spawn a handler for this connection
            spawn(fn -> tcp_client_loop(client_socket, parent, client_ip) end)

          {:error, _} ->
            :gen_tcp.close(client_socket)
        end

        tcp_accept_loop(listener, parent, max_connections)

      {:error, :timeout} ->
        tcp_accept_loop(listener, parent, max_connections)

      {:error, :closed} ->
        Logger.info("[SyslogReceiver] TCP listener closed")
        :ok

      {:error, reason} ->
        Logger.error("[SyslogReceiver] TCP accept error: #{inspect(reason)}")
        Process.sleep(1_000)
        tcp_accept_loop(listener, parent, max_connections)
    end
  end

  defp tcp_client_loop(socket, parent, client_ip) do
    # Set the socket to active mode for line-based reading
    :inet.setopts(socket, [active: false, packet: :line])

    tcp_read_loop(socket, parent, client_ip, "")
  after
    send(parent, {:tcp_connection, :closed, client_ip})
    :gen_tcp.close(socket)
  end

  defp tcp_read_loop(socket, parent, client_ip, partial) do
    case :gen_tcp.recv(socket, 0, 30_000) do
      {:ok, data} ->
        # data may contain a partial or complete line
        full = partial <> data

        # Process complete lines
        {lines, remainder} = split_lines(full)

        Enum.each(lines, fn line ->
          line = String.trim(line)

          if byte_size(line) > 0 do
            send(parent, {:tcp_data, line, client_ip})
          end
        end)

        tcp_read_loop(socket, parent, client_ip, remainder)

      {:error, :timeout} ->
        # Keep connection alive, wait for more data
        tcp_read_loop(socket, parent, client_ip, partial)

      {:error, :closed} ->
        # Process any remaining partial data
        if byte_size(partial) > 0 do
          send(parent, {:tcp_data, String.trim(partial), client_ip})
        end

        :ok

      {:error, _reason} ->
        :ok
    end
  end

  defp split_lines(data) do
    parts = String.split(data, "\n")

    case parts do
      [] ->
        {[], ""}

      [single] ->
        # No newline found -- all partial
        {[], single}

      parts ->
        # Last element is the remainder (empty string if data ends with \n)
        {lines, [remainder]} = Enum.split(parts, -1)
        {lines, remainder}
    end
  end

  # ── Private: Detection Engine Notification ─────────────────────────

  defp notify_detection_engine(normalized, iocs) do
    # Fire-and-forget: notify the detection engine about IOCs found in
    # third-party logs. This enables cross-correlation between agent telemetry
    # and external log sources.
    Task.Supervisor.start_child(
      TamanduaServer.TaskSupervisor,
      fn ->
        Enum.each(iocs.ips, fn ip ->
          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "ioc:sighting",
            {:ioc_sighting, :ip, ip, %{
              source: "syslog",
              hostname: normalized[:hostname],
              app_name: normalized[:app_name],
              timestamp: normalized[:timestamp]
            }}
          )
        end)

        Enum.each(iocs.domains, fn domain ->
          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "ioc:sighting",
            {:ioc_sighting, :domain, domain, %{
              source: "syslog",
              hostname: normalized[:hostname],
              app_name: normalized[:app_name],
              timestamp: normalized[:timestamp]
            }}
          )
        end)

        Enum.each(iocs.hashes.sha256, fn hash ->
          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "ioc:sighting",
            {:ioc_sighting, :hash, hash, %{
              source: "syslog",
              hostname: normalized[:hostname],
              app_name: normalized[:app_name],
              timestamp: normalized[:timestamp]
            }}
          )
        end)
      end
    )
  rescue
    _ -> :ok
  catch
    :exit, _ -> :ok
  end

  # ── Private: Utilities ─────────────────────────────────────────────

  defp format_ip({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"

  defp format_ip({a, b, c, d, e, f, g, h}) do
    [a, b, c, d, e, f, g, h]
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.join(":")
  end

  defp format_ip(ip) when is_binary(ip), do: ip
  defp format_ip(ip), do: inspect(ip)

  defp schedule_flush(interval_ms) do
    Process.send_after(self(), :flush, interval_ms)
  end

  defp schedule_rate_cleanup do
    # Clean up stale rate limit entries every 30 seconds
    Process.send_after(self(), :cleanup_rate_limits, 30_000)
  end
end
