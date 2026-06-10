defmodule TamanduaServer.NDR.FlowAnalyzer do
  @moduledoc """
  Network Detection and Response (NDR) Flow Analyzer.

  Provides comprehensive network flow analysis capabilities:

  1. **Flow Aggregation**: Aggregates network connections into flows with
     statistics (bytes, packets, duration)

  2. **NetFlow/IPFIX Ingestion**: Parses and processes network flow data
     from agents or network devices

  3. **Traffic Baselining**: Learns normal traffic patterns per host/subnet
     to detect anomalies

  4. **Bandwidth Analysis**: Tracks bandwidth utilization and detects
     unusual data transfers

  5. **Top Talkers**: Identifies hosts with highest traffic volumes

  MITRE ATT&CK Coverage:
  - T1071: Application Layer Protocol
  - T1048: Exfiltration Over Alternative Protocol
  - T1041: Exfiltration Over C2 Channel
  - T1095: Non-Application Layer Protocol
  """

  use GenServer
  import Ecto.Query, warn: false
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Agents.OrgLookup
  alias TamanduaServer.NDR.{EventNormalizer, IP}
  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.ClickHouse

  # ETS tables for flow tracking
  @flows_table :ndr_flows
  @flow_stats_table :ndr_flow_stats
  @baselines_table :ndr_baselines
  @top_talkers_table :ndr_top_talkers

  # Flow aggregation window (5 minutes)
  @flow_window_ms 300_000

  # Baseline learning period (7 days)
  @baseline_learning_days 7

  # Anomaly detection thresholds
  @bandwidth_anomaly_multiplier 3.0
  @connection_burst_threshold 100
  @large_transfer_threshold_bytes 100_000_000  # 100 MB

  defstruct [
    :stats,
    :last_cleanup,
    :baseline_mode
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Process a network event and aggregate into flows.

  Called from the detection engine or telemetry ingestor for each
  network connection event.
  """
  @spec process_event(map()) :: :ok
  def process_event(event) do
    GenServer.cast(__MODULE__, {:process_event, event})
  end

  @doc """
  Get active flows for an agent or across all agents.
  """
  @spec get_flows(keyword()) :: [map()]
  def get_flows(opts \\ []) do
    GenServer.call(__MODULE__, {:get_flows, opts})
  end

  @doc """
  Get flow statistics (aggregated metrics).
  """
  @spec get_flow_stats(keyword()) :: map()
  def get_flow_stats(opts \\ []) do
    GenServer.call(__MODULE__, {:get_flow_stats, opts})
  end

  @doc """
  Get top talkers (hosts with highest traffic).
  """
  @spec get_top_talkers(keyword()) :: [map()]
  def get_top_talkers(opts \\ []) do
    GenServer.call(__MODULE__, {:get_top_talkers, opts})
  end

  @doc """
  Get traffic baseline for a host or subnet.
  """
  @spec get_baseline(String.t()) :: map() | nil
  def get_baseline(host_or_subnet) do
    GenServer.call(__MODULE__, {:get_baseline, host_or_subnet})
  end

  @doc """
  Get overall NDR statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Detect anomalies in recent traffic patterns.
  """
  @spec detect_anomalies(keyword()) :: [map()]
  def detect_anomalies(opts \\ []) do
    GenServer.call(__MODULE__, {:detect_anomalies, opts})
  end

  @doc """
  Get network topology based on flow data.
  """
  @spec get_topology(keyword()) :: map()
  def get_topology(opts \\ []) do
    GenServer.call(__MODULE__, {:get_topology, opts})
  end

  @doc """
  Get protocol distribution statistics.
  """
  @spec get_protocol_distribution(keyword()) :: [map()]
  def get_protocol_distribution(opts \\ []) do
    GenServer.call(__MODULE__, {:get_protocol_distribution, opts})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@flows_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@flow_stats_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@baselines_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@top_talkers_table, [:named_table, :set, :public, read_concurrency: true])

    schedule_cleanup()
    schedule_baseline_update()

    state = %__MODULE__{
      stats: %{
        flows_processed: 0,
        active_flows: 0,
        anomalies_detected: 0,
        bytes_analyzed: 0,
        alerts_created: 0
      },
      last_cleanup: DateTime.utc_now(),
      baseline_mode: :learning
    }

    Logger.info("NDR Flow Analyzer started")
    {:ok, state}
  end

  @impl true
  def handle_cast({:process_event, event}, state) do
    new_state = do_process_event(event, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_call({:get_flows, opts}, _from, state) do
    flows = fetch_flows(opts)
    {:reply, flows, state}
  end

  @impl true
  def handle_call({:get_flow_stats, opts}, _from, state) do
    stats = calculate_flow_stats(opts)
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:get_top_talkers, opts}, _from, state) do
    talkers = fetch_top_talkers(opts)
    {:reply, talkers, state}
  end

  @impl true
  def handle_call({:get_baseline, host}, _from, state) do
    baseline = case :ets.lookup(@baselines_table, host) do
      [{^host, data}] -> data
      [] -> nil
    end
    {:reply, baseline, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:detect_anomalies, opts}, _from, state) do
    anomalies = find_anomalies(opts)
    {:reply, anomalies, state}
  end

  @impl true
  def handle_call({:get_topology, opts}, _from, state) do
    topology = build_topology(opts)
    {:reply, topology, state}
  end

  @impl true
  def handle_call({:get_protocol_distribution, opts}, _from, state) do
    distribution = calculate_protocol_distribution(opts)
    {:reply, distribution, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_flows()
    schedule_cleanup()
    {:noreply, %{state | last_cleanup: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:update_baselines, state) do
    update_baselines()
    schedule_baseline_update()

    # Transition from learning to detection mode after initial period
    new_mode = if state.baseline_mode == :learning do
      :detection
    else
      state.baseline_mode
    end

    {:noreply, %{state | baseline_mode: new_mode}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Core Processing Logic
  # ============================================================================

  defp do_process_event(event, state) do
    event = EventNormalizer.normalize_event(event)
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    timestamp = event[:timestamp] || event["timestamp"] || DateTime.utc_now()

    # Extract flow 5-tuple
    src_ip = payload[:local_ip] || payload["local_ip"] || payload[:source_ip] || payload["source_ip"]
    dst_ip = payload[:remote_ip] || payload["remote_ip"] || payload[:dest_ip] || payload["dest_ip"]
    src_port = payload[:local_port] || payload["local_port"] || payload[:source_port] || payload["source_port"] || 0
    dst_port = payload[:remote_port] || payload["remote_port"] || payload[:dest_port] || payload["dest_port"] || 0
    protocol = (payload[:protocol] || payload["protocol"] || "TCP") |> to_string() |> String.upcase()

    bytes_sent = payload[:bytes_sent] || payload["bytes_sent"] || 0
    bytes_received = payload[:bytes_received] || payload["bytes_received"] || 0
    total_bytes = bytes_sent + bytes_received

    process_name = payload[:process_name] || payload["process_name"]
    process_pid = payload[:process_pid] || payload["process_pid"] || payload[:pid] || payload["pid"]

    # Skip if missing critical fields
    if is_nil(src_ip) or is_nil(dst_ip) do
      state
    else
      src_ip = IP.canonical(src_ip)
      dst_ip = IP.canonical(dst_ip)

      # Create flow key
      flow_key = create_flow_key(agent_id, src_ip, src_port, dst_ip, dst_port, protocol)

      # Update or create flow
      update_flow(flow_key, %{
        organization_id: event[:organization_id] || event["organization_id"] || OrgLookup.get_org_id(agent_id),
        agent_id: agent_id,
        src_ip: src_ip,
        src_port: src_port,
        dst_ip: dst_ip,
        dst_port: dst_port,
        protocol: protocol,
        bytes_sent: bytes_sent,
        bytes_received: bytes_received,
        total_bytes: total_bytes,
        process_name: process_name,
        process_pid: process_pid,
        timestamp: timestamp
      })

      # Update top talkers
      update_top_talkers(agent_id, src_ip, dst_ip, total_bytes)

      # Check for anomalies in detection mode
      new_state = if state.baseline_mode == :detection do
        check_flow_anomalies(event, flow_key, total_bytes, state)
      else
        state
      end

      # Update stats
      %{new_state | stats: %{
        new_state.stats |
        flows_processed: new_state.stats.flows_processed + 1,
        bytes_analyzed: new_state.stats.bytes_analyzed + total_bytes
      }}
    end
  end

  defp create_flow_key(agent_id, src_ip, src_port, dst_ip, dst_port, protocol) do
    # Normalize to bidirectional flow using parsed address ordering so IPv6
    # compression/case variants do not create separate flow keys.
    {ip1, port1, ip2, port2} = if IP.sort_key(src_ip) <= IP.sort_key(dst_ip) do
      {src_ip, src_port, dst_ip, dst_port}
    else
      {dst_ip, dst_port, src_ip, src_port}
    end

    [agent_id || "global", ip1, port1, ip2, port2, protocol]
    |> Enum.map(&to_string/1)
    |> Enum.join("|")
  end

  defp update_flow(flow_key, flow_data) do
    now = System.system_time(:millisecond)

    case :ets.lookup(@flows_table, flow_key) do
      [{^flow_key, existing}] ->
        # Update existing flow
        updated = %{existing |
          bytes_sent: existing.bytes_sent + flow_data.bytes_sent,
          bytes_received: existing.bytes_received + flow_data.bytes_received,
          total_bytes: existing.total_bytes + flow_data.total_bytes,
          packet_count: existing.packet_count + 1,
          last_seen: now,
          last_timestamp: flow_data.timestamp
        }
        :ets.insert(@flows_table, {flow_key, updated})

      [] ->
        # Create new flow
        new_flow = %{
          flow_key: flow_key,
          organization_id: flow_data.organization_id,
          agent_id: flow_data.agent_id,
          src_ip: flow_data.src_ip,
          src_port: flow_data.src_port,
          dst_ip: flow_data.dst_ip,
          dst_port: flow_data.dst_port,
          protocol: flow_data.protocol,
          bytes_sent: flow_data.bytes_sent,
          bytes_received: flow_data.bytes_received,
          total_bytes: flow_data.total_bytes,
          packet_count: 1,
          first_seen: now,
          last_seen: now,
          first_timestamp: flow_data.timestamp,
          last_timestamp: flow_data.timestamp,
          process_name: flow_data.process_name,
          process_pid: flow_data.process_pid
        }
        :ets.insert(@flows_table, {flow_key, new_flow})
    end

    persist_flow(flow_key, flow_data, now)
  end

  defp update_top_talkers(agent_id, src_ip, dst_ip, bytes) do
    now = DateTime.utc_now()

    # Update source IP stats
    update_talker_stats({agent_id, src_ip}, bytes, :outbound, now)

    # Update destination IP stats
    update_talker_stats({agent_id, dst_ip}, bytes, :inbound, now)
  end

  defp update_talker_stats(key, bytes, direction, timestamp) do
    case :ets.lookup(@top_talkers_table, key) do
      [{^key, stats}] ->
        updated = case direction do
          :outbound ->
            %{stats |
              bytes_sent: stats.bytes_sent + bytes,
              total_bytes: stats.total_bytes + bytes,
              connection_count: stats.connection_count + 1,
              last_seen: timestamp
            }
          :inbound ->
            %{stats |
              bytes_received: stats.bytes_received + bytes,
              total_bytes: stats.total_bytes + bytes,
              last_seen: timestamp
            }
        end
        :ets.insert(@top_talkers_table, {key, updated})

      [] ->
        {agent_id, ip} = key
        new_stats = %{
          agent_id: agent_id,
          ip: ip,
          bytes_sent: if(direction == :outbound, do: bytes, else: 0),
          bytes_received: if(direction == :inbound, do: bytes, else: 0),
          total_bytes: bytes,
          connection_count: if(direction == :outbound, do: 1, else: 0),
          first_seen: timestamp,
          last_seen: timestamp
        }
        :ets.insert(@top_talkers_table, {key, new_stats})
    end
  end

  # ============================================================================
  # Anomaly Detection
  # ============================================================================

  defp check_flow_anomalies(event, flow_key, bytes, state) do
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    src_ip = payload[:local_ip] || payload["local_ip"] || payload[:source_ip] || payload["source_ip"]
    dst_ip = payload[:remote_ip] || payload["remote_ip"]

    anomalies = []

    # Check for bandwidth anomaly
    anomalies = anomalies ++ check_bandwidth_anomaly(agent_id, src_ip, bytes)

    # Check for large data transfer
    anomalies = anomalies ++ check_large_transfer(event, flow_key, bytes)

    # Check for connection burst
    anomalies = anomalies ++ check_connection_burst(agent_id, src_ip)

    # Create alerts for detected anomalies
    new_state = Enum.reduce(anomalies, state, fn anomaly, acc ->
      acc =
        if anomaly.confidence >= 0.6 do
          case create_ndr_alert(event, anomaly) do
            :ok ->
              %{acc | stats: %{acc.stats | alerts_created: acc.stats.alerts_created + 1}}

            :error ->
              acc
          end
        else
          acc
        end

      %{acc | stats: %{acc.stats | anomalies_detected: acc.stats.anomalies_detected + 1}}
    end)

    new_state
  end

  defp check_bandwidth_anomaly(agent_id, ip, bytes) do
    key = "#{agent_id}:#{ip}"

    case :ets.lookup(@baselines_table, key) do
      [{^key, baseline}] ->
        avg_bytes_per_window = baseline[:avg_bytes_per_window] || 0
        threshold = avg_bytes_per_window * @bandwidth_anomaly_multiplier

        if bytes > threshold and threshold > 0 do
          [%{
            type: :bandwidth_anomaly,
            confidence: min(0.9, 0.5 + (bytes / threshold - 1) * 0.2),
            description: "Bandwidth anomaly: #{format_bytes(bytes)} transferred, " <>
              "baseline is #{format_bytes(round(avg_bytes_per_window))}",
            mitre_techniques: ["T1048", "T1041"],
            metadata: %{
              ip: ip,
              bytes: bytes,
              baseline: round(avg_bytes_per_window),
              multiplier: Float.round(bytes / avg_bytes_per_window, 2)
            }
          }]
        else
          []
        end

      [] ->
        []
    end
  end

  defp check_large_transfer(event, _flow_key, bytes) do
    if bytes > @large_transfer_threshold_bytes do
      payload = event[:payload] || event["payload"] || %{}
      dst_ip = payload[:remote_ip] || payload["remote_ip"]

      [%{
        type: :large_data_transfer,
        confidence: min(0.8, 0.5 + (bytes / @large_transfer_threshold_bytes - 1) * 0.1),
        description: "Large data transfer detected: #{format_bytes(bytes)} to #{dst_ip}",
        mitre_techniques: ["T1048", "T1041", "T1030"],
        metadata: %{
          bytes: bytes,
          destination: dst_ip,
          threshold: @large_transfer_threshold_bytes
        }
      }]
    else
      []
    end
  end

  defp check_connection_burst(agent_id, ip) do
    key = {agent_id, ip}

    case :ets.lookup(@top_talkers_table, key) do
      [{^key, stats}] ->
        # Check connections in recent window
        if stats.connection_count > @connection_burst_threshold do
          duration_seconds = DateTime.diff(stats.last_seen, stats.first_seen, :second)
          rate = if duration_seconds > 0, do: stats.connection_count / duration_seconds, else: stats.connection_count

          if rate > 5.0 do  # More than 5 connections per second
            [%{
              type: :connection_burst,
              confidence: min(0.85, 0.5 + rate * 0.05),
              description: "Connection burst detected from #{ip}: #{stats.connection_count} connections, " <>
                "#{Float.round(rate, 1)} conn/sec",
              mitre_techniques: ["T1046", "T1595"],
              metadata: %{
                ip: ip,
                connection_count: stats.connection_count,
                rate_per_second: Float.round(rate, 2)
              }
            }]
          else
            []
          end
        else
          []
        end

      [] ->
        []
    end
  end

  # ============================================================================
  # Query Functions
  # ============================================================================

  defp fetch_flows(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    limit = Keyword.get(opts, :limit, 100)
    protocol = Keyword.get(opts, :protocol)
    mode = Keyword.get(opts, :mode, :combined)

    ets_flows =
      if mode in [:live, :combined] do
        :ets.tab2list(@flows_table)
        |> Enum.map(fn {_key, flow} -> flow end)
      else
        []
      end

    persisted =
      if mode in [:historical, :combined] do
        persisted_flows(agent_id, protocol, limit)
      else
        []
      end

    persisted
    |> merge_flows(ets_flows, limit)
    |> Enum.filter(fn flow ->
      (is_nil(agent_id) or flow.agent_id == agent_id) and
      (is_nil(protocol) or flow.protocol == String.upcase(to_string(protocol)))
    end)
    |> Enum.sort_by(&flow_sort_time/1, :desc)
    |> Enum.take(limit)
  end

  defp calculate_flow_stats(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    protocol = Keyword.get(opts, :protocol)
    time_range = Keyword.get(opts, :time_range, :hour)

    flows =
      [agent_id: agent_id, protocol: protocol, limit: 10000, mode: Keyword.get(opts, :mode, :combined)]
      |> Enum.reject(fn {_, value} -> is_nil(value) end)
      |> fetch_flows()

    cutoff = case time_range do
      :minute -> System.system_time(:millisecond) - 60_000
      :hour -> System.system_time(:millisecond) - 3_600_000
      :day -> System.system_time(:millisecond) - 86_400_000
      _ -> System.system_time(:millisecond) - 3_600_000
    end

    recent_flows = Enum.filter(flows, &(flow_sort_time(&1) >= cutoff))

    total_bytes = Enum.reduce(recent_flows, 0, & &1.total_bytes + &2)
    total_packets = Enum.reduce(recent_flows, 0, & &1.packet_count + &2)
    unique_sources = recent_flows |> Enum.map(& &1.src_ip) |> Enum.uniq() |> length()
    unique_destinations = recent_flows |> Enum.map(& &1.dst_ip) |> Enum.uniq() |> length()

    %{
      total_flows: length(recent_flows),
      total_bytes: total_bytes,
      total_packets: total_packets,
      bytes_per_second: if(length(recent_flows) > 0, do: total_bytes / time_range_seconds(time_range), else: 0),
      unique_sources: unique_sources,
      unique_destinations: unique_destinations,
      avg_flow_duration: calculate_avg_flow_duration(recent_flows),
      time_range: time_range
    }
  end

  defp time_range_seconds(:minute), do: 60
  defp time_range_seconds(:hour), do: 3600
  defp time_range_seconds(:day), do: 86400
  defp time_range_seconds(_), do: 3600

  defp calculate_avg_flow_duration(flows) when length(flows) == 0, do: 0
  defp calculate_avg_flow_duration(flows) do
    total_duration = Enum.reduce(flows, 0, fn flow, acc ->
      acc + flow_duration_ms(flow)
    end)
    total_duration / length(flows) / 1000  # Convert to seconds
  end

  defp fetch_top_talkers(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    limit = Keyword.get(opts, :limit, 20)
    sort_by = Keyword.get(opts, :sort_by, :total_bytes)
    mode = Keyword.get(opts, :mode, :combined)

    ets_talkers =
      if mode in [:live, :combined] do
        :ets.tab2list(@top_talkers_table)
        |> Enum.map(fn {_key, stats} -> stats end)
      else
        []
      end

    persisted =
      if mode in [:historical, :combined] do
        persisted_top_talkers(agent_id, limit)
      else
        []
      end

    persisted
    |> merge_talkers(ets_talkers, limit)
    |> Enum.filter(fn stats ->
      is_nil(agent_id) or stats.agent_id == agent_id
    end)
    |> Enum.sort_by(&Map.get(&1, sort_by), :desc)
    |> Enum.take(limit)
  end

  defp find_anomalies(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    limit = Keyword.get(opts, :limit, 50)

    flows = fetch_flows(agent_id: agent_id, limit: 1000)

    anomalies = Enum.flat_map(flows, fn flow ->
      check_flow_for_anomalies(flow)
    end)

    anomalies
    |> Enum.sort_by(& &1[:confidence], :desc)
    |> Enum.take(limit)
  end

  defp check_flow_for_anomalies(flow) do
    anomalies = []

    # Check for unusual port usage
    anomalies = anomalies ++ check_unusual_port(flow)

    # Check for data asymmetry (potential exfiltration)
    anomalies = anomalies ++ check_data_asymmetry(flow)

    anomalies
  end

  defp check_unusual_port(flow) do
    unusual_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337]

    if flow.dst_port in unusual_ports do
      [%{
        type: :unusual_port,
        flow_key: flow.flow_key,
        confidence: 0.6,
        description: "Connection to unusual port #{flow.dst_port}",
        mitre_techniques: ["T1571"]
      }]
    else
      []
    end
  end

  defp check_data_asymmetry(flow) do
    # Check for significant upload vs download imbalance (potential exfil)
    if flow.bytes_sent > 0 and flow.bytes_received > 0 do
      ratio = flow.bytes_sent / flow.bytes_received

      if ratio > 10 and flow.bytes_sent > 1_000_000 do
        [%{
          type: :data_exfiltration_pattern,
          flow_key: flow.flow_key,
          confidence: min(0.7, 0.4 + ratio * 0.02),
          description: "High upload ratio (#{Float.round(ratio, 1)}:1) to #{flow.dst_ip}",
          mitre_techniques: ["T1048", "T1041"]
        }]
      else
        []
      end
    else
      []
    end
  end

  defp build_topology(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    mode = Keyword.get(opts, :mode, :combined)

    flows = fetch_flows(agent_id: agent_id, limit: 5000, mode: mode)
    node_bytes = topology_node_bytes(flows)

    # Build nodes
    all_ips = flows
    |> Enum.flat_map(fn f -> [f.src_ip, f.dst_ip] end)
    |> Enum.uniq()

    nodes = Enum.map(all_ips, fn ip ->
      %{
        id: ip,
        label: ip,
        type: classify_ip_type(ip),
        total_bytes: Map.get(node_bytes, ip, 0),
        is_internal: is_private_ip?(ip)
      }
    end)

    # Build edges
    edges = flows
    |> Enum.map(fn f ->
      %{
        source: f.src_ip,
        target: f.dst_ip,
        protocol: f.protocol,
        bytes: f.total_bytes,
        packet_count: f.packet_count
      }
    end)
    |> Enum.uniq_by(fn e -> {e.source, e.target, e.protocol} end)

    %{
      nodes: nodes,
      edges: edges,
      summary: %{
        total_nodes: length(nodes),
        total_edges: length(edges),
        internal_nodes: Enum.count(nodes, & &1.is_internal),
        external_nodes: Enum.count(nodes, &(not &1.is_internal))
      }
    }
  end

  defp topology_node_bytes(flows) do
    Enum.reduce(flows, %{}, fn flow, acc ->
      acc
      |> Map.update(flow.src_ip, flow.bytes_sent || flow.total_bytes || 0, &(&1 + (flow.bytes_sent || flow.total_bytes || 0)))
      |> Map.update(flow.dst_ip, flow.bytes_received || 0, &(&1 + (flow.bytes_received || 0)))
    end)
  end

  defp calculate_protocol_distribution(opts) do
    agent_id = Keyword.get(opts, :agent_id)

    flows =
      [agent_id: agent_id, limit: 10000, mode: Keyword.get(opts, :mode, :combined)]
      |> Enum.reject(fn {_, value} -> is_nil(value) end)
      |> fetch_flows()

    flows
    |> Enum.group_by(& &1.protocol)
    |> Enum.map(fn {protocol, protocol_flows} ->
      total_bytes = Enum.reduce(protocol_flows, 0, & &1.total_bytes + &2)
      total_connections = length(protocol_flows)

      %{
        protocol: protocol,
        flow_count: total_connections,
        total_bytes: total_bytes,
        percentage: 0  # Will be calculated after
      }
    end)
    |> calculate_percentages()
  end

  defp calculate_percentages(distributions) do
    total = Enum.reduce(distributions, 0, & &1.total_bytes + &2)

    Enum.map(distributions, fn d ->
      pct = if total > 0, do: d.total_bytes / total * 100, else: 0.0
      %{d | percentage: Float.round(pct, 1)}
    end)
    |> Enum.sort_by(& &1.total_bytes, :desc)
  end

  # ============================================================================
  # Baseline Management
  # ============================================================================

  defp update_baselines do
    # Update baselines for all tracked hosts
    :ets.tab2list(@top_talkers_table)
    |> Enum.each(fn {{agent_id, ip}, stats} ->
      key = "#{agent_id}:#{ip}"
      duration_hours = DateTime.diff(stats.last_seen, stats.first_seen, :hour)
      window_hours = max(@flow_window_ms / 3_600_000, 1.0 / 60.0)
      observed_hours = max(duration_hours, window_hours)
      windows = max(1.0, observed_hours / window_hours)

      baseline = %{
        avg_bytes_per_window: stats.total_bytes / windows,
        avg_connections_per_window: stats.connection_count / windows,
        total_bytes_observed: stats.total_bytes,
        observation_hours: duration_hours,
        last_updated: DateTime.utc_now()
      }

      :ets.insert(@baselines_table, {key, baseline})
    end)

    Logger.debug("NDR baselines updated for #{:ets.info(@baselines_table, :size)} hosts")
  end

  # ============================================================================
  # Persistence
  # ============================================================================

  defp persist_flow(flow_key, flow_data, now_ms) do
    now = DateTime.utc_now() |> DateTime.truncate(:second) |> ensure_usec()
    observed_at = normalize_timestamp(flow_data.timestamp, now_ms)

    Repo.insert_all("ndr_flows", [
      %{
        id: Ecto.UUID.generate(),
        organization_id: dump_uuid(flow_data.organization_id),
        agent_id: dump_uuid(flow_data.agent_id),
        flow_key: flow_key,
        src_ip: to_string(flow_data.src_ip),
        src_port: normalize_int(flow_data.src_port),
        dst_ip: to_string(flow_data.dst_ip),
        dst_port: normalize_int(flow_data.dst_port),
        protocol: to_string(flow_data.protocol),
        bytes_sent: normalize_int(flow_data.bytes_sent),
        bytes_received: normalize_int(flow_data.bytes_received),
        total_bytes: normalize_int(flow_data.total_bytes),
        packet_count: 1,
        process_name: flow_data.process_name,
        process_pid: normalize_int(flow_data.process_pid),
        first_seen: observed_at,
        last_seen: observed_at,
        metadata: %{},
        inserted_at: now,
        updated_at: now
      }
    ],
      on_conflict: [
        inc: [
          bytes_sent: normalize_int(flow_data.bytes_sent),
          bytes_received: normalize_int(flow_data.bytes_received),
          total_bytes: normalize_int(flow_data.total_bytes),
          packet_count: 1
        ],
        set: [
          last_seen: observed_at,
          process_name: flow_data.process_name,
          process_pid: normalize_int(flow_data.process_pid),
          updated_at: now
        ]
      ],
      conflict_target: [:flow_key]
    )
  rescue
    e -> Logger.debug("NDR flow persistence unavailable: #{Exception.message(e)}")
  end

  defp persisted_flows(agent_id, protocol, limit) do
    postgres_flows(agent_id, protocol, limit)
    |> merge_flows(clickhouse_flows(agent_id, protocol, limit), limit)
  end

  defp postgres_flows(agent_id, protocol, limit) do
    query =
      from(f in "ndr_flows",
        order_by: [desc: field(f, :last_seen)],
        limit: ^limit,
        select: %{
          flow_key: field(f, :flow_key),
          organization_id: field(f, :organization_id),
          agent_id: field(f, :agent_id),
          src_ip: field(f, :src_ip),
          src_port: field(f, :src_port),
          dst_ip: field(f, :dst_ip),
          dst_port: field(f, :dst_port),
          protocol: field(f, :protocol),
          bytes_sent: field(f, :bytes_sent),
          bytes_received: field(f, :bytes_received),
          total_bytes: field(f, :total_bytes),
          packet_count: field(f, :packet_count),
          first_seen: field(f, :first_seen),
          last_seen: field(f, :last_seen),
          first_timestamp: field(f, :first_seen),
          last_timestamp: field(f, :last_seen),
          process_name: field(f, :process_name),
          process_pid: field(f, :process_pid)
        }
      )

    query =
      if is_nil(agent_id) do
        query
      else
        from(f in query, where: field(f, :agent_id) == ^dump_uuid(agent_id))
      end

    query =
      if is_nil(protocol) do
        query
      else
        from(f in query, where: field(f, :protocol) == ^String.upcase(to_string(protocol)))
      end

    Repo.all(query)
    |> Enum.map(&load_flow_ids/1)
  rescue
    _ -> []
  end

  defp clickhouse_flows(agent_id, protocol, limit) do
    if ClickHouse.enabled?() and ClickHouse.healthy?() do
      sql = clickhouse_flow_sql(agent_id, protocol, limit)

      case clickhouse_query(sql) do
        {:ok, rows} when is_list(rows) -> Enum.map(rows, &normalize_clickhouse_flow/1)
        _ -> []
      end
    else
      []
    end
  rescue
    _ -> []
  catch
    :exit, _ -> []
  end

  defp persisted_top_talkers(agent_id, limit) do
    flows = persisted_flows(agent_id, nil, 10_000)
    now = DateTime.utc_now()

    flows
    |> Enum.flat_map(fn flow ->
      [
        {{flow.agent_id, flow.src_ip}, :outbound, flow.bytes_sent || flow.total_bytes || 0, flow},
        {{flow.agent_id, flow.dst_ip}, :inbound, flow.bytes_received || 0, flow}
      ]
    end)
    |> Enum.reduce(%{}, fn {{aid, ip}, direction, bytes, flow}, acc ->
      key = {aid, ip}
      existing =
        Map.get(acc, key, %{
          agent_id: aid,
          ip: ip,
          bytes_sent: 0,
          bytes_received: 0,
          total_bytes: 0,
          connection_count: 0,
          first_seen: flow.first_timestamp || now,
          last_seen: flow.last_timestamp || now
        })

      updated =
        case direction do
          :outbound ->
            %{existing |
              bytes_sent: existing.bytes_sent + bytes,
              total_bytes: existing.total_bytes + bytes,
              connection_count: existing.connection_count + (flow.packet_count || 0),
              last_seen: max_datetime(existing.last_seen, flow.last_timestamp)
            }

          :inbound ->
            %{existing |
              bytes_received: existing.bytes_received + bytes,
              total_bytes: existing.total_bytes + bytes,
              last_seen: max_datetime(existing.last_seen, flow.last_timestamp)
            }
        end

      Map.put(acc, key, updated)
    end)
    |> Map.values()
    |> Enum.sort_by(& &1.total_bytes, :desc)
    |> Enum.take(limit)
  end

  defp merge_flows(persisted, ets_flows, limit) do
    (ets_flows ++ persisted)
    |> Enum.uniq_by(& &1.flow_key)
    |> Enum.sort_by(&flow_sort_time/1, :desc)
    |> Enum.take(limit)
  end

  defp merge_talkers(persisted, ets_talkers, limit) do
    (ets_talkers ++ persisted)
    |> Enum.group_by(fn talker -> {talker.agent_id, talker.ip} end)
    |> Enum.map(fn {_key, rows} ->
      Enum.reduce(rows, fn row, acc ->
        %{
          acc |
          bytes_sent: max(acc.bytes_sent || 0, row.bytes_sent || 0),
          bytes_received: max(acc.bytes_received || 0, row.bytes_received || 0),
          total_bytes: max(acc.total_bytes || 0, row.total_bytes || 0),
          connection_count: max(acc.connection_count || 0, row.connection_count || 0),
          first_seen: min_datetime(acc.first_seen, row.first_seen),
          last_seen: max_datetime(acc.last_seen, row.last_seen)
        }
      end)
    end)
    |> Enum.sort_by(& &1.total_bytes, :desc)
    |> Enum.take(limit)
  end

  defp flow_sort_time(flow) do
    case flow[:last_seen] || flow[:last_timestamp] do
      value when is_integer(value) -> value
      %DateTime{} = dt -> DateTime.to_unix(dt, :millisecond)
      %NaiveDateTime{} = ndt -> ndt |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_unix(:millisecond)
      _ -> 0
    end
  end

  defp flow_duration_ms(flow) do
    first = flow[:first_seen] || flow[:first_timestamp]
    last = flow[:last_seen] || flow[:last_timestamp]
    max(flow_sort_time(%{last_seen: last}) - flow_sort_time(%{last_seen: first}), 0)
  end

  defp normalize_timestamp(%DateTime{} = dt, _now_ms), do: ensure_usec(dt)
  defp normalize_timestamp(ts, _now_ms) when is_integer(ts) do
    unit = if ts > 10_000_000_000, do: :millisecond, else: :second

    case DateTime.from_unix(ts, unit) do
      {:ok, dt} -> ensure_usec(dt)
      _ -> ensure_usec(DateTime.utc_now())
    end
  end
  defp normalize_timestamp(ts, _now_ms) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> ensure_usec(dt)
      _ -> ensure_usec(DateTime.utc_now())
    end
  end
  defp normalize_timestamp(_ts, now_ms) do
    case DateTime.from_unix(now_ms, :millisecond) do
      {:ok, dt} -> ensure_usec(dt)
      _ -> ensure_usec(DateTime.utc_now())
    end
  end

  defp ensure_usec(%DateTime{microsecond: {value, precision}} = dt) when precision < 6 do
    %{dt | microsecond: {value, 6}}
  end
  defp ensure_usec(%DateTime{} = dt), do: dt

  defp dump_uuid(nil), do: nil
  defp dump_uuid(value) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> uuid
      :error -> nil
    end
  end
  defp dump_uuid(_), do: nil

  defp load_uuid(nil), do: nil
  defp load_uuid(<<_::128>> = uuid) do
    case Ecto.UUID.load(uuid) do
      {:ok, loaded} -> loaded
      :error -> uuid
    end
  end
  defp load_uuid(uuid), do: uuid

  defp load_flow_ids(flow) do
    flow
    |> Map.update(:agent_id, nil, &load_uuid/1)
    |> Map.update(:organization_id, nil, &load_uuid/1)
  end

  defp normalize_clickhouse_flow(row) do
    src_ip = IP.canonical(row["source_ip"] || row[:source_ip] || "")
    dst_ip = IP.canonical(row["dest_ip"] || row[:dest_ip] || "")
    protocol = row["protocol"] || row[:protocol] || "other"
    first_seen = parse_clickhouse_datetime(row["first_seen"] || row[:first_seen])
    last_seen = parse_clickhouse_datetime(row["last_seen"] || row[:last_seen])
    agent_id = row["agent_id"] || row[:agent_id]
    src_port = normalize_int(row["source_port"] || row[:source_port])
    dst_port = normalize_int(row["dest_port"] || row[:dest_port])
    bytes_sent = normalize_int(row["bytes_sent"] || row[:bytes_sent])
    bytes_received = normalize_int(row["bytes_received"] || row[:bytes_received])

    %{
      flow_key:
        row["flow_key"] || row[:flow_key] ||
          create_flow_key(agent_id, src_ip, src_port, dst_ip, dst_port, protocol),
      organization_id: row["organization_id"] || row[:organization_id],
      agent_id: agent_id,
      src_ip: src_ip,
      src_port: src_port,
      dst_ip: dst_ip,
      dst_port: dst_port,
      protocol: protocol |> to_string() |> String.upcase(),
      bytes_sent: bytes_sent,
      bytes_received: bytes_received,
      total_bytes: normalize_int(row["total_bytes"] || row[:total_bytes] || bytes_sent + bytes_received),
      packet_count: normalize_int(row["packet_count"] || row[:packet_count]),
      first_seen: first_seen,
      last_seen: last_seen,
      first_timestamp: first_seen,
      last_timestamp: last_seen,
      process_name: row["process_name"] || row[:process_name],
      process_pid: normalize_int(row["process_id"] || row[:process_id])
    }
  end

  defp clickhouse_flow_sql(agent_id, protocol, limit) do
    filters =
      []
      |> maybe_clickhouse_filter("agent_id", agent_id)
      |> maybe_clickhouse_filter("protocol", clickhouse_protocol(protocol))

    where =
      case filters do
        [] -> ""
        clauses -> "WHERE " <> Enum.join(clauses, " AND ")
      end

    """
    SELECT
      any(event_id) AS flow_key,
      agent_id,
      any(organization_id) AS organization_id,
      source_ip,
      source_port,
      dest_ip,
      dest_port,
      protocol,
      sum(bytes_sent) AS bytes_sent,
      sum(bytes_received) AS bytes_received,
      sum(bytes_sent + bytes_received) AS total_bytes,
      count() AS packet_count,
      any(process_name) AS process_name,
      any(process_id) AS process_id,
      min(timestamp) AS first_seen,
      max(timestamp) AS last_seen
    FROM tamandua.network_flows
    #{where}
    GROUP BY agent_id, source_ip, source_port, dest_ip, dest_port, protocol
    ORDER BY last_seen DESC
    LIMIT #{min(max(limit, 1), 10_000)}
    FORMAT JSON
    """
  end

  defp maybe_clickhouse_filter(filters, _field, nil), do: filters
  defp maybe_clickhouse_filter(filters, field, value), do: filters ++ ["#{field} = '#{clickhouse_escape(value)}'"]

  defp clickhouse_protocol(nil), do: nil
  defp clickhouse_protocol(protocol), do: protocol |> to_string() |> String.downcase()

  defp clickhouse_query(sql) do
    config = Application.get_env(:tamandua_server, ClickHouse, [])
    url = Keyword.get(config, :url, "http://localhost:8123")
    database = Keyword.get(config, :database, "tamandua")
    username = Keyword.get(config, :username, "default")
    password = Keyword.get(config, :password, "")

    headers =
      [{"content-type", "text/plain"}] ++
        if(username != "", do: [{"X-ClickHouse-User", username}], else: []) ++
        if(password != "", do: [{"X-ClickHouse-Key", password}], else: [])

    request = Finch.build(:post, "#{url}/?database=#{database}", headers, sql)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 30_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"data" => data}} -> {:ok, data}
          {:ok, data} when is_list(data) -> {:ok, data}
          _ -> {:error, :invalid_response}
        end

      {:ok, %Finch.Response{status: status, body: body}} ->
        {:error, {status, body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp clickhouse_escape(value) do
    value
    |> to_string()
    |> String.replace("\\", "\\\\")
    |> String.replace("'", "\\'")
    |> String.replace("\n", "")
    |> String.replace("\r", "")
  end

  defp parse_clickhouse_datetime(nil), do: nil
  defp parse_clickhouse_datetime(%DateTime{} = dt), do: dt
  defp parse_clickhouse_datetime(value) when is_binary(value) do
    cond do
      String.contains?(value, "T") ->
        case DateTime.from_iso8601(value) do
          {:ok, dt, _} -> dt
          _ -> nil
        end

      true ->
        case NaiveDateTime.from_iso8601(String.replace(value, " ", "T")) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ -> nil
        end
    end
  end
  defp parse_clickhouse_datetime(_), do: nil

  defp normalize_int(value) when is_integer(value), do: value
  defp normalize_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, _} -> parsed
      :error -> 0
    end
  end
  defp normalize_int(value) when is_float(value), do: trunc(value)
  defp normalize_int(_), do: 0

  defp max_datetime(nil, value), do: value
  defp max_datetime(value, nil), do: value
  defp max_datetime(%DateTime{} = a, %DateTime{} = b) do
    if DateTime.compare(a, b) == :lt, do: b, else: a
  end
  defp max_datetime(a, b), do: if(flow_sort_time(%{last_seen: a}) < flow_sort_time(%{last_seen: b}), do: b, else: a)

  defp min_datetime(nil, value), do: value
  defp min_datetime(value, nil), do: value
  defp min_datetime(%DateTime{} = a, %DateTime{} = b) do
    if DateTime.compare(a, b) == :gt, do: b, else: a
  end
  defp min_datetime(a, b), do: if(flow_sort_time(%{last_seen: a}) > flow_sort_time(%{last_seen: b}), do: b, else: a)

  # ============================================================================
  # Alert Creation
  # ============================================================================

  defp create_ndr_alert(event, anomaly) do
    agent_id = event[:agent_id] || event["agent_id"]

    severity = case anomaly.confidence do
      c when c >= 0.8 -> "high"
      c when c >= 0.6 -> "medium"
      _ -> "low"
    end

    title = case anomaly.type do
      :bandwidth_anomaly -> "NDR: Bandwidth Anomaly Detected"
      :large_data_transfer -> "NDR: Large Data Transfer"
      :connection_burst -> "NDR: Connection Burst Detected"
      :data_exfiltration_pattern -> "NDR: Potential Data Exfiltration"
      :unusual_port -> "NDR: Connection to Unusual Port"
      _ -> "NDR: Network Anomaly"
    end

    case Alerts.create_alert(%{
           agent_id: agent_id,
           organization_id: event[:organization_id] || OrgLookup.get_org_id(agent_id),
           severity: severity,
           title: title,
           description: anomaly.description,
           source_event_id: EventNormalizer.source_event_uuid(event),
           event_ids: EventNormalizer.source_event_ids(event),
           evidence: EventNormalizer.alert_evidence(event, anomaly, :ndr_metadata),
           raw_event: event,
           detection_metadata: anomaly.metadata || %{},
           mitre_tactics: ["exfiltration", "command-and-control"],
           mitre_techniques: anomaly.mitre_techniques || [],
           threat_score: anomaly.confidence
         }) do
      {:ok, _alert} ->
        :ok

      {:error, reason} ->
        Logger.warning("Failed to create NDR alert (#{anomaly.type}): #{inspect(reason)}")
        :error
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp classify_ip_type(ip) do
    case IP.classification(ip) do
      :loopback -> :localhost
      :unspecified -> :localhost
      :invalid -> :unknown
      value when value in [:private, :link_local, :unique_local] -> :internal
      _ -> :external
    end
  end

  defp is_private_ip?(ip), do: IP.internal?(ip)

  defp format_bytes(bytes) when is_number(bytes) do
    cond do
      bytes >= 1_000_000_000 -> "#{Float.round(bytes / 1_000_000_000, 2)} GB"
      bytes >= 1_000_000 -> "#{Float.round(bytes / 1_000_000, 2)} MB"
      bytes >= 1_000 -> "#{Float.round(bytes / 1_000, 2)} KB"
      true -> "#{bytes} B"
    end
  end

  defp format_bytes(_), do: "0 B"

  defp cleanup_old_flows do
    cutoff = System.system_time(:millisecond) - @flow_window_ms * 12  # Keep 12 windows (1 hour)

    :ets.tab2list(@flows_table)
    |> Enum.each(fn {key, flow} ->
      if flow.last_seen < cutoff do
        :ets.delete(@flows_table, key)
      end
    end)

    Logger.debug("NDR flow cleanup completed, #{:ets.info(@flows_table, :size)} flows remaining")
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, :timer.minutes(5))
  end

  defp schedule_baseline_update do
    Process.send_after(self(), :update_baselines, :timer.minutes(15))
  end
end
