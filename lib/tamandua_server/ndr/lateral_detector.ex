defmodule TamanduaServer.NDR.LateralDetector do
  @moduledoc """
  NDR Lateral Movement Detection Module.

  Detects lateral movement patterns within the network:

  1. **Internal Reconnaissance**: Detects port scanning, network enumeration,
     and service discovery within the internal network

  2. **Port Scanning Detection**: Identifies hosts performing horizontal or
     vertical port scans

  3. **Service Enumeration**: Detects attempts to enumerate services across
     multiple hosts

  4. **Credential Movement**: Tracks authentication attempts and credential
     use across multiple hosts

  5. **SMB Lateral Movement**: Specialized detection for SMB-based movement
     (PsExec, WMI, etc.)

  6. **RDP/SSH Lateral Movement**: Tracks remote access protocol usage
     patterns across hosts

  MITRE ATT&CK Coverage:
  - T1021: Remote Services
  - T1021.001: Remote Desktop Protocol
  - T1021.002: SMB/Windows Admin Shares
  - T1021.004: SSH
  - T1046: Network Service Discovery
  - T1570: Lateral Tool Transfer
  - T1550: Use Alternate Authentication Material
  """

  use GenServer
  import Ecto.Query, warn: false
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Agents.OrgLookup
  alias TamanduaServer.NDR.EventNormalizer
  alias TamanduaServer.NDR.IP
  alias TamanduaServer.Repo

  # ETS tables
  @scan_tracking_table :ndr_scan_tracking
  @lateral_movement_table :ndr_lateral_movement
  @credential_tracking_table :ndr_credential_tracking
  @host_connections_table :ndr_host_connections

  # Detection thresholds
  @port_scan_threshold 10  # Unique ports to same host
  @host_scan_threshold 5   # Unique hosts on same port
  @rapid_connection_threshold 20  # Connections per minute
  @credential_spread_threshold 3  # Same creds on different hosts

  # Common lateral movement ports
  @lateral_movement_ports [
    445,   # SMB
    135,   # RPC
    3389,  # RDP
    22,    # SSH
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
    139,   # NetBIOS
    23,    # Telnet
    3306,  # MySQL
    1433,  # MSSQL
    5432,  # PostgreSQL
    6379,  # Redis
    27017  # MongoDB
  ]

  defstruct [
    :stats,
    :last_cleanup
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyze a network event for lateral movement indicators.
  """
  @spec analyze_event(map()) :: [map()]
  def analyze_event(event) do
    GenServer.call(__MODULE__, {:analyze, event})
  end

  @doc """
  Get detected lateral movement patterns.
  """
  @spec get_lateral_movement(keyword()) :: [map()]
  def get_lateral_movement(opts \\ []) do
    GenServer.call(__MODULE__, {:get_lateral_movement, opts})
  end

  @doc """
  Get port scan detections.
  """
  @spec get_scan_activity(keyword()) :: [map()]
  def get_scan_activity(opts \\ []) do
    GenServer.call(__MODULE__, {:get_scan_activity, opts})
  end

  @doc """
  Get credential spread tracking.
  """
  @spec get_credential_activity(keyword()) :: [map()]
  def get_credential_activity(opts \\ []) do
    GenServer.call(__MODULE__, {:get_credential_activity, opts})
  end

  @doc """
  Get host connection graph for visualization.
  """
  @spec get_connection_graph(keyword()) :: map()
  def get_connection_graph(opts \\ []) do
    GenServer.call(__MODULE__, {:get_connection_graph, opts})
  end

  @doc """
  Get lateral movement risk score for a host.
  """
  @spec get_host_risk_score(String.t()) :: map()
  def get_host_risk_score(host_ip) do
    GenServer.call(__MODULE__, {:get_host_risk, host_ip})
  end

  @doc """
  Get overall statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    :ets.new(@scan_tracking_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@lateral_movement_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@credential_tracking_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@host_connections_table, [:named_table, :set, :public, read_concurrency: true])

    schedule_cleanup()
    schedule_pattern_analysis()

    state = %__MODULE__{
      stats: %{
        events_analyzed: 0,
        port_scans_detected: 0,
        host_scans_detected: 0,
        lateral_movements_detected: 0,
        credential_spreads_detected: 0,
        alerts_created: 0
      },
      last_cleanup: DateTime.utc_now()
    }

    Logger.info("NDR Lateral Movement Detector started")
    {:ok, state}
  end

  @impl true
  def handle_call({:analyze, event}, _from, state) do
    {detections, new_state} = do_analyze(event, state)
    {:reply, detections, new_state}
  end

  @impl true
  def handle_call({:get_lateral_movement, opts}, _from, state) do
    movements = fetch_lateral_movement(opts)
    {:reply, movements, state}
  end

  @impl true
  def handle_call({:get_scan_activity, opts}, _from, state) do
    activity = fetch_scan_activity(opts)
    {:reply, activity, state}
  end

  @impl true
  def handle_call({:get_credential_activity, opts}, _from, state) do
    activity = fetch_credential_activity(opts)
    {:reply, activity, state}
  end

  @impl true
  def handle_call({:get_connection_graph, opts}, _from, state) do
    graph = build_connection_graph(opts)
    {:reply, graph, state}
  end

  @impl true
  def handle_call({:get_host_risk, host_ip}, _from, state) do
    risk = calculate_host_risk(host_ip)
    {:reply, risk, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_data()
    schedule_cleanup()
    {:noreply, %{state | last_cleanup: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:analyze_patterns, state) do
    # Periodic pattern analysis for complex lateral movement
    analyze_movement_patterns()
    schedule_pattern_analysis()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Core Analysis Logic
  # ============================================================================

  defp do_analyze(event, state) do
    event = EventNormalizer.normalize_event(event)
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]

    src_ip =
      payload[:local_ip] || payload["local_ip"] || payload[:source_ip] || payload["source_ip"]

    dst_ip =
      payload[:remote_ip] || payload["remote_ip"] || payload[:dest_ip] || payload["dest_ip"]
    dst_port = payload[:remote_port] || payload["remote_port"] || payload[:dest_port] || payload["dest_port"] || 0
    protocol = (payload[:protocol] || payload["protocol"] || "TCP") |> to_string() |> String.upcase()

    process_name = payload[:process_name] || payload["process_name"]
    username = payload[:username] || payload["username"]

    new_state = update_stats(state, :events_analyzed)
    detections = []

    # Skip if missing critical fields or external traffic
    if is_nil(src_ip) or is_nil(dst_ip) or not is_internal_traffic?(src_ip, dst_ip) do
      {[], new_state}
    else
      src_ip = IP.canonical(src_ip)
      dst_ip = IP.canonical(dst_ip)

      # Track connection for analysis
      track_connection(agent_id, src_ip, dst_ip, dst_port, protocol, process_name, username)

      # 1. Port scan detection
      {port_scan_detections, new_state} = detect_port_scanning(agent_id, src_ip, dst_ip, dst_port, new_state)
      detections = detections ++ port_scan_detections

      # 2. Host scan detection
      {host_scan_detections, new_state} = detect_host_scanning(agent_id, src_ip, dst_ip, dst_port, new_state)
      detections = detections ++ host_scan_detections

      # 3. Lateral movement pattern detection
      {lateral_detections, new_state} = detect_lateral_movement(event, agent_id, src_ip, dst_ip, dst_port, process_name, new_state)
      detections = detections ++ lateral_detections

      # 4. Credential spread detection
      {cred_detections, new_state} = detect_credential_spread(agent_id, src_ip, dst_ip, username, new_state)
      detections = detections ++ cred_detections

      # 5. Rapid connection detection
      {rapid_detections, new_state} = detect_rapid_connections(agent_id, src_ip, dst_ip, dst_port, process_name, new_state)
      detections = detections ++ rapid_detections

      # Create alerts for high-confidence detections
      final_state = Enum.reduce(detections, new_state, fn detection, acc ->
        if detection.confidence >= 0.6 do
          case create_lateral_alert(event, detection) do
            :ok -> update_stats(acc, :alerts_created)
            :error -> acc
          end
        else
          acc
        end
      end)

      {detections, final_state}
    end
  end

  # --------------------------------------------------------------------------
  # Port Scanning Detection
  # --------------------------------------------------------------------------

  defp detect_port_scanning(agent_id, src_ip, dst_ip, dst_port, state) do
    key = {agent_id, src_ip, dst_ip, :ports}
    now = System.system_time(:millisecond)
    window = 60_000  # 1 minute window

    # Track port
    {unique_ports, connection_count} = case :ets.lookup(@scan_tracking_table, key) do
      [{^key, data}] ->
        # Filter to recent ports only
        recent_ports = data.ports
        |> Enum.filter(fn {_port, ts} -> ts > now - window end)
        |> Map.new()
        |> Map.put(dst_port, now)

        updated = %{data |
          ports: recent_ports,
          connection_count: data.connection_count + 1,
          last_seen: now
        }
        :ets.insert(@scan_tracking_table, {key, updated})
        {map_size(recent_ports), updated.connection_count}

      [] ->
        data = %{
          ports: %{dst_port => now},
          connection_count: 1,
          first_seen: now,
          last_seen: now
        }
        :ets.insert(@scan_tracking_table, {key, data})
        {1, 1}
    end

    if unique_ports >= @port_scan_threshold do
      detection = %{
        type: :port_scan,
        confidence: min(0.9, 0.5 + unique_ports * 0.04),
        description: "Port scan detected: #{src_ip} scanning #{unique_ports} ports on #{dst_ip}",
        mitre_techniques: ["T1046"],
        metadata: %{
          source_ip: src_ip,
          target_ip: dst_ip,
          unique_ports: unique_ports,
          connection_count: connection_count
        }
      }

      # Record lateral movement
      record_lateral_movement(agent_id, %{
        type: :port_scan,
        src_ip: src_ip,
        dst_ip: dst_ip,
        ports_scanned: unique_ports,
        timestamp: DateTime.utc_now()
      })

      {[detection], update_stats(state, :port_scans_detected)}
    else
      {[], state}
    end
  end

  # --------------------------------------------------------------------------
  # Host Scanning Detection
  # --------------------------------------------------------------------------

  defp detect_host_scanning(agent_id, src_ip, dst_ip, dst_port, state) do
    key = {agent_id, src_ip, dst_port, :hosts}
    now = System.system_time(:millisecond)
    window = 60_000

    # Track hosts
    {unique_hosts, _} = case :ets.lookup(@scan_tracking_table, key) do
      [{^key, data}] ->
        recent_hosts = data.hosts
        |> Enum.filter(fn {_host, ts} -> ts > now - window end)
        |> Map.new()
        |> Map.put(dst_ip, now)

        updated = %{data |
          hosts: recent_hosts,
          last_seen: now
        }
        :ets.insert(@scan_tracking_table, {key, updated})
        {map_size(recent_hosts), 0}

      [] ->
        data = %{
          hosts: %{dst_ip => now},
          first_seen: now,
          last_seen: now
        }
        :ets.insert(@scan_tracking_table, {key, data})
        {1, 0}
    end

    if unique_hosts >= @host_scan_threshold do
      detection = %{
        type: :host_scan,
        confidence: min(0.85, 0.5 + unique_hosts * 0.07),
        description: "Host scan detected: #{src_ip} scanning #{unique_hosts} hosts on port #{dst_port}",
        mitre_techniques: ["T1046", "T1018"],
        metadata: %{
          source_ip: src_ip,
          target_port: dst_port,
          unique_hosts: unique_hosts
        }
      }

      record_lateral_movement(agent_id, %{
        type: :host_scan,
        src_ip: src_ip,
        port: dst_port,
        hosts_scanned: unique_hosts,
        timestamp: DateTime.utc_now()
      })

      {[detection], update_stats(state, :host_scans_detected)}
    else
      {[], state}
    end
  end

  # --------------------------------------------------------------------------
  # Lateral Movement Pattern Detection
  # --------------------------------------------------------------------------

  defp detect_lateral_movement(event, agent_id, src_ip, dst_ip, dst_port, process_name, state) do
    detections = []

    # Check if this is a lateral movement port
    detections = if dst_port in @lateral_movement_ports do
      protocol_name = port_to_protocol_name(dst_port)

      # Check for suspicious process using lateral movement
      suspicious = is_suspicious_lateral_process?(process_name)

      if suspicious do
        [%{
          type: :lateral_movement,
          confidence: 0.75,
          description: "Potential lateral movement: #{process_name} connecting to #{dst_ip}:#{dst_port} (#{protocol_name})",
          mitre_techniques: lateral_mitre_for_port(dst_port),
          metadata: %{
            source_ip: src_ip,
            target_ip: dst_ip,
            target_port: dst_port,
            protocol: protocol_name,
            process: process_name
          }
        } | detections]
      else
        detections
      end
    else
      detections
    end

    # SMB-specific lateral movement detection
    payload = event[:payload] || event["payload"] || %{}
    smb_command = payload[:smb_command] || payload["smb_command"]
    smb_share = payload[:smb_share] || payload["smb_share"]

    detections = if dst_port in [445, 139] and smb_command do
      check_smb_lateral_movement(src_ip, dst_ip, smb_command, smb_share, detections)
    else
      detections
    end

    if length(detections) > 0 do
      Enum.each(detections, fn detection ->
        record_lateral_movement(agent_id, movement_from_detection(detection))
      end)

      {detections, update_stats(state, :lateral_movements_detected)}
    else
      {detections, state}
    end
  end

  defp is_suspicious_lateral_process?(nil), do: false
  defp is_suspicious_lateral_process?(process_name) do
    suspicious_processes = [
      "psexec", "psexesvc", "wmic", "wmiprvse",
      "powershell", "pwsh", "cmd.exe",
      "mstsc", "ssh", "putty", "plink",
      "winrs", "mmc", "net.exe", "net1.exe",
      "schtasks", "at.exe", "bitsadmin"
    ]

    process_lower = String.downcase(process_name)
    Enum.any?(suspicious_processes, &String.contains?(process_lower, &1))
  end

  defp check_smb_lateral_movement(src_ip, dst_ip, smb_command, smb_share, detections) do
    # Detect PsExec-style lateral movement
    suspicious_commands = ["CREATE_NAMED_PIPE", "WRITE_ANDX", "CREATE_REQUEST"]

    if smb_command in suspicious_commands do
      admin_shares = ["C$", "ADMIN$", "IPC$"]
      is_admin_share = smb_share && String.upcase(smb_share) in admin_shares

      if is_admin_share do
        [%{
          type: :smb_lateral_movement,
          confidence: 0.8,
          description: "SMB lateral movement pattern: #{smb_command} to #{dst_ip}\\#{smb_share}",
          mitre_techniques: ["T1021.002", "T1570"],
          metadata: %{
            source_ip: src_ip,
            target_ip: dst_ip,
            smb_command: smb_command,
            share: smb_share
          }
        } | detections]
      else
        detections
      end
    else
      detections
    end
  end

  # --------------------------------------------------------------------------
  # Credential Spread Detection
  # --------------------------------------------------------------------------

  defp detect_credential_spread(agent_id, src_ip, dst_ip, username, state) do
    if is_nil(username) or username == "" do
      {[], state}
    else
      key = {agent_id, username}
      now = DateTime.utc_now()

      # Track hosts this credential has been used on
      {unique_hosts, hosts_list} = case :ets.lookup(@credential_tracking_table, key) do
        [{^key, data}] ->
          updated_hosts = Map.put(data.hosts, dst_ip, now)
          updated = %{data |
            hosts: updated_hosts,
            last_seen: now
          }
          :ets.insert(@credential_tracking_table, {key, updated})
          {map_size(updated_hosts), Map.keys(updated_hosts)}

        [] ->
          data = %{
            username: username,
            hosts: %{dst_ip => now},
            source_ip: src_ip,
            first_seen: now,
            last_seen: now
          }
          :ets.insert(@credential_tracking_table, {key, data})
          {1, [dst_ip]}
      end

      if unique_hosts >= @credential_spread_threshold do
        detection = %{
          type: :credential_spread,
          confidence: min(0.85, 0.5 + unique_hosts * 0.1),
          description: "Credential spreading: '#{username}' used on #{unique_hosts} hosts from #{src_ip}",
          mitre_techniques: ["T1550", "T1078"],
          metadata: %{
            username: username,
            source_ip: src_ip,
            target_hosts: hosts_list,
            unique_hosts: unique_hosts
          }
        }

        record_lateral_movement(agent_id, %{
          type: :credential_spread,
          username: username,
          src_ip: src_ip,
          target_hosts: hosts_list,
          timestamp: now
        })

        {[detection], update_stats(state, :credential_spreads_detected)}
      else
        {[], state}
      end
    end
  end

  # --------------------------------------------------------------------------
  # Rapid Connection Detection
  # --------------------------------------------------------------------------

  defp detect_rapid_connections(agent_id, src_ip, dst_ip, dst_port, process_name, state) do
    key = {agent_id, src_ip, dst_ip, dst_port, normalize_process_name(process_name), :rapid}
    now = System.system_time(:millisecond)
    window = 60_000

    # Track connections
    connection_count = case :ets.lookup(@scan_tracking_table, key) do
      [{^key, data}] ->
        recent = Enum.filter(data.timestamps, &(&1 > now - window))
        updated = %{data |
          timestamps: [now | Enum.take(recent, 99)],
          last_seen: now
        }
        :ets.insert(@scan_tracking_table, {key, updated})
        length(updated.timestamps)

      [] ->
        data = %{timestamps: [now], first_seen: now, last_seen: now}
        :ets.insert(@scan_tracking_table, {key, data})
        1
    end

    cond do
      benign_rapid_connection?(process_name, dst_port) ->
        {[], state}

      connection_count >= @rapid_connection_threshold and
          (connection_count == @rapid_connection_threshold or rem(connection_count, @rapid_connection_threshold) == 0) ->
        detection = %{
          type: :rapid_connections,
          confidence: min(0.7, 0.4 + connection_count * 0.015),
          description: "Rapid internal connections: #{src_ip} made #{connection_count} connections to #{dst_ip}:#{dst_port} in 1 minute",
          mitre_techniques: ["T1046", "T1018"],
          metadata: %{
            source_ip: src_ip,
            target_ip: dst_ip,
            target_port: dst_port,
            process: process_name,
            connection_count: connection_count,
            window_seconds: 60
          }
        }

        {[detection], state}

      true ->
        {[], state}
    end
  end

  defp benign_rapid_connection?(process_name, dst_port) do
    normalize_port(dst_port) == 24800 &&
      normalize_process_name(process_name) in [
        "synergy",
        "synergy.exe",
        "synergy-core",
        "synergy-core.exe",
        "synergys",
        "synergys.exe",
        "synergyc",
        "synergyc.exe",
        "barrier",
        "barrier.exe"
      ]
  end

  defp normalize_process_name(nil), do: ""
  defp normalize_process_name(process_name) do
    process_name
    |> to_string()
    |> String.replace("\\", "/")
    |> Path.basename()
    |> String.downcase()
  end

  defp normalize_port(port) when is_integer(port), do: port
  defp normalize_port(port) when is_binary(port) do
    case Integer.parse(port) do
      {value, _} -> value
      :error -> nil
    end
  end
  defp normalize_port(_), do: nil

  # ============================================================================
  # Data Recording and Tracking
  # ============================================================================

  defp track_connection(agent_id, src_ip, dst_ip, dst_port, protocol, process_name, username) do
    key = {agent_id, src_ip, dst_ip}
    now = DateTime.utc_now()

    case :ets.lookup(@host_connections_table, key) do
      [{^key, data}] ->
        updated = %{data |
          connection_count: data.connection_count + 1,
          ports: MapSet.put(data.ports, dst_port),
          protocols: MapSet.put(data.protocols, protocol),
          processes: if(process_name, do: MapSet.put(data.processes, process_name), else: data.processes),
          usernames: if(username, do: MapSet.put(data.usernames, username), else: data.usernames),
          last_seen: now
        }
        :ets.insert(@host_connections_table, {key, updated})

      [] ->
        data = %{
          agent_id: agent_id,
          src_ip: src_ip,
          dst_ip: dst_ip,
          connection_count: 1,
          ports: MapSet.new([dst_port]),
          protocols: MapSet.new([protocol]),
          processes: if(process_name, do: MapSet.new([process_name]), else: MapSet.new()),
          usernames: if(username, do: MapSet.new([username]), else: MapSet.new()),
          first_seen: now,
          last_seen: now
        }
        :ets.insert(@host_connections_table, {key, data})
    end
  end

  defp record_lateral_movement(agent_id, movement) do
    :ets.insert(@lateral_movement_table, {agent_id, movement})
    persist_lateral_movement(agent_id, movement)
  end

  defp movement_from_detection(detection) do
    metadata = detection[:metadata] || %{}

    %{
      type: detection[:type],
      src_ip: metadata[:source_ip],
      dst_ip: metadata[:target_ip],
      port: metadata[:target_port],
      username: metadata[:username],
      target_hosts: metadata[:target_hosts],
      timestamp: DateTime.utc_now(),
      metadata: metadata
    }
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  # ============================================================================
  # Query Functions
  # ============================================================================

  defp fetch_lateral_movement(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    limit = Keyword.get(opts, :limit, 100)
    type = Keyword.get(opts, :type)

    ets_movements =
      :ets.tab2list(@lateral_movement_table)
      |> Enum.filter(fn {aid, movement} ->
        (is_nil(agent_id) or aid == agent_id) and
        (is_nil(type) or movement.type == type)
      end)
      |> Enum.map(fn {aid, movement} -> Map.put(movement, :agent_id, aid) end)

    persisted_lateral_movement(agent_id, type, limit)
    |> merge_lateral_movements(ets_movements, limit)
    |> Enum.map(&Map.delete(&1, :agent_id))
  end

  defp fetch_scan_activity(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    limit = Keyword.get(opts, :limit, 50)

    :ets.tab2list(@scan_tracking_table)
    |> Enum.filter(fn {{aid, _, _, type}, _} ->
      (is_nil(agent_id) or aid == agent_id) and
      type in [:ports, :hosts]
    end)
    |> Enum.map(fn {{aid, src_ip, target, type}, data} ->
      %{
        agent_id: aid,
        source_ip: src_ip,
        target: target,
        type: type,
        count: if(type == :ports, do: map_size(data.ports || %{}), else: map_size(data.hosts || %{})),
        first_seen: data.first_seen,
        last_seen: data.last_seen
      }
    end)
    |> Enum.sort_by(& &1.last_seen, :desc)
    |> Enum.take(limit)
  end

  defp fetch_credential_activity(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    limit = Keyword.get(opts, :limit, 50)

    :ets.tab2list(@credential_tracking_table)
    |> Enum.filter(fn {{aid, _}, _} ->
      is_nil(agent_id) or aid == agent_id
    end)
    |> Enum.map(fn {{_, username}, data} ->
      %{
        username: username,
        source_ip: data.source_ip,
        target_hosts: Map.keys(data.hosts),
        host_count: map_size(data.hosts),
        first_seen: data.first_seen,
        last_seen: data.last_seen
      }
    end)
    |> Enum.sort_by(& &1.host_count, :desc)
    |> Enum.take(limit)
  end

  defp build_connection_graph(opts) do
    agent_id = Keyword.get(opts, :agent_id)

    connections = :ets.tab2list(@host_connections_table)
    |> Enum.filter(fn {{aid, _, _}, _} ->
      is_nil(agent_id) or aid == agent_id
    end)
    |> Enum.map(fn {{_, src, dst}, data} ->
      %{
        source: src,
        target: dst,
        connection_count: data.connection_count,
        ports: MapSet.to_list(data.ports),
        protocols: MapSet.to_list(data.protocols),
        processes: MapSet.to_list(data.processes),
        usernames: MapSet.to_list(data.usernames),
        first_seen: data.first_seen,
        last_seen: data.last_seen
      }
    end)

    # Build nodes
    all_ips = connections
    |> Enum.flat_map(fn c -> [c.source, c.target] end)
    |> Enum.uniq()

    nodes = Enum.map(all_ips, fn ip ->
      risk = calculate_host_risk(ip)
      %{
        id: ip,
        label: ip,
        risk_score: risk.overall_score,
        is_internal: is_private_ip?(ip),
        outbound_connections: Enum.count(connections, & &1.source == ip),
        inbound_connections: Enum.count(connections, & &1.target == ip)
      }
    end)

    # Build edges
    edges = Enum.map(connections, fn c ->
      %{
        source: c.source,
        target: c.target,
        weight: c.connection_count,
        ports: c.ports,
        is_lateral: has_lateral_movement_port?(c.ports)
      }
    end)

    %{
      nodes: nodes,
      edges: edges,
      summary: %{
        total_nodes: length(nodes),
        total_edges: length(edges),
        lateral_edges: Enum.count(edges, & &1.is_lateral)
      }
    }
  end

  defp calculate_host_risk(host_ip) do
    # Calculate risk based on various factors
    connections = :ets.tab2list(@host_connections_table)
    |> Enum.filter(fn {{_, src, _}, _} -> src == host_ip end)

    lateral_movements =
      persisted_lateral_movement(nil, nil, 10_000)
      |> merge_lateral_movements(
        :ets.tab2list(@lateral_movement_table)
        |> Enum.map(fn {aid, movement} -> Map.put(movement, :agent_id, aid) end),
        10_000
      )
      |> Enum.filter(fn m -> m[:src_ip] == host_ip end)

    outbound_count = length(connections)
    unique_targets = connections |> Enum.map(fn {{_, _, dst}, _} -> dst end) |> Enum.uniq() |> length()
    lateral_count = length(lateral_movements)

    # Calculate component scores
    scan_score = min(1.0, outbound_count / 100)
    spread_score = min(1.0, unique_targets / 20)
    lateral_score = min(1.0, lateral_count / 5)

    overall_score = (scan_score * 0.3 + spread_score * 0.3 + lateral_score * 0.4)
    |> Float.round(2)

    %{
      host_ip: host_ip,
      overall_score: overall_score,
      outbound_connections: outbound_count,
      unique_targets: unique_targets,
      lateral_movements: lateral_count,
      risk_factors: %{
        scan_activity: scan_score,
        target_spread: spread_score,
        lateral_movement: lateral_score
      }
    }
  end

  defp has_lateral_movement_port?(ports) when is_list(ports) do
    Enum.any?(ports, &(&1 in @lateral_movement_ports))
  end
  defp has_lateral_movement_port?(_), do: false

  # ============================================================================
  # Persistence
  # ============================================================================

  defp persist_lateral_movement(agent_id, movement) do
    now = DateTime.utc_now() |> DateTime.truncate(:second) |> ensure_usec()
    observed_at = movement[:timestamp] |> normalize_timestamp() |> ensure_usec()

    metadata =
      (movement[:metadata] || %{})
      |> Map.merge(
        Map.drop(movement, [
          :type,
          :src_ip,
          :dst_ip,
          :port,
          :ports_scanned,
          :hosts_scanned,
          :username,
          :target_hosts,
          :timestamp,
          :metadata
        ])
      )

    Repo.insert_all("ndr_lateral_movements", [
      %{
        id: Ecto.UUID.generate(),
        organization_id: agent_id |> OrgLookup.get_org_id() |> dump_uuid(),
        agent_id: dump_uuid(agent_id),
        type: movement[:type] |> type_to_string(),
        src_ip: movement[:src_ip],
        dst_ip: movement[:dst_ip],
        port: normalize_nullable_int(movement[:port]),
        ports_scanned: normalize_nullable_int(movement[:ports_scanned]),
        hosts_scanned: normalize_nullable_int(movement[:hosts_scanned]),
        username: movement[:username],
        target_hosts: normalize_string_list(movement[:target_hosts]),
        metadata: metadata,
        timestamp: observed_at,
        inserted_at: now,
        updated_at: now
      }
    ])
  rescue
    e -> Logger.debug("NDR lateral movement persistence unavailable: #{Exception.message(e)}")
  end

  defp persisted_lateral_movement(agent_id, type, limit) do
    query =
      from(m in "ndr_lateral_movements",
        order_by: [desc: field(m, :timestamp)],
        limit: ^limit,
        select: %{
          agent_id: field(m, :agent_id),
          type: field(m, :type),
          src_ip: field(m, :src_ip),
          dst_ip: field(m, :dst_ip),
          port: field(m, :port),
          ports_scanned: field(m, :ports_scanned),
          hosts_scanned: field(m, :hosts_scanned),
          username: field(m, :username),
          target_hosts: field(m, :target_hosts),
          timestamp: field(m, :timestamp),
          metadata: field(m, :metadata)
        }
      )

    query =
      if is_nil(agent_id) do
        query
      else
        from(m in query, where: field(m, :agent_id) == ^dump_uuid(agent_id))
      end

    query =
      if is_nil(type) do
        query
      else
        from(m in query, where: field(m, :type) == ^type_to_string(type))
      end

    Repo.all(query)
    |> Enum.map(&load_lateral_movement/1)
  rescue
    _ -> []
  end

  defp merge_lateral_movements(persisted, ets_movements, limit) do
    (ets_movements ++ persisted)
    |> Enum.uniq_by(&lateral_movement_key/1)
    |> Enum.sort_by(&movement_sort_time/1, :desc)
    |> Enum.take(limit)
  end

  defp lateral_movement_key(movement) do
    {
      movement[:agent_id],
      movement[:type],
      movement[:src_ip],
      movement[:dst_ip],
      movement[:port],
      movement[:username],
      movement_sort_time(movement)
    }
  end

  defp movement_sort_time(movement) do
    case movement[:timestamp] do
      %DateTime{} = dt -> DateTime.to_unix(dt, :millisecond)
      %NaiveDateTime{} = ndt -> ndt |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_unix(:millisecond)
      value when is_integer(value) -> value
      value when is_binary(value) ->
        case DateTime.from_iso8601(value) do
          {:ok, dt, _} -> DateTime.to_unix(dt, :millisecond)
          _ -> 0
        end
      _ -> 0
    end
  end

  defp normalize_timestamp(%DateTime{} = dt), do: dt
  defp normalize_timestamp(%NaiveDateTime{} = ndt), do: DateTime.from_naive!(ndt, "Etc/UTC")
  defp normalize_timestamp(ts) when is_integer(ts) do
    unit = if ts > 10_000_000_000, do: :millisecond, else: :second

    case DateTime.from_unix(ts, unit) do
      {:ok, dt} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp normalize_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp normalize_timestamp(_), do: DateTime.utc_now()

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

  defp load_lateral_movement(movement) do
    movement
    |> Map.update(:agent_id, nil, &load_uuid/1)
    |> Map.update(:type, nil, &string_to_type/1)
  end

  defp type_to_string(nil), do: nil
  defp type_to_string(type) when is_atom(type), do: Atom.to_string(type)
  defp type_to_string(type), do: to_string(type)

  defp string_to_type(nil), do: nil
  defp string_to_type(type) when is_atom(type), do: type
  defp string_to_type("port_scan"), do: :port_scan
  defp string_to_type("host_scan"), do: :host_scan
  defp string_to_type("credential_spread"), do: :credential_spread
  defp string_to_type("lateral_movement"), do: :lateral_movement
  defp string_to_type("smb_lateral_movement"), do: :smb_lateral_movement
  defp string_to_type("rapid_connections"), do: :rapid_connections
  defp string_to_type(type), do: type

  defp normalize_nullable_int(nil), do: nil
  defp normalize_nullable_int(value) when is_integer(value), do: value
  defp normalize_nullable_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, _} -> parsed
      :error -> nil
    end
  end
  defp normalize_nullable_int(value) when is_float(value), do: trunc(value)
  defp normalize_nullable_int(_), do: nil

  defp normalize_string_list(nil), do: []
  defp normalize_string_list(values) when is_list(values), do: Enum.map(values, &to_string/1)
  defp normalize_string_list(value), do: [to_string(value)]

  # ============================================================================
  # Pattern Analysis (Periodic)
  # ============================================================================

  defp analyze_movement_patterns do
    # Analyze for complex multi-hop lateral movement patterns
    connections = :ets.tab2list(@host_connections_table)
    |> Enum.map(fn {{_, src, dst}, data} -> {src, dst, data} end)

    # Build adjacency map
    adjacency = Enum.reduce(connections, %{}, fn {src, dst, _data}, acc ->
      Map.update(acc, src, [dst], fn existing -> [dst | existing] end)
    end)

    # Find hosts with high fan-out that connect to other high fan-out hosts
    # This can indicate multi-hop lateral movement
    high_fanout_hosts = adjacency
    |> Enum.filter(fn {_src, targets} -> length(targets) >= 3 end)
    |> Enum.map(fn {src, _} -> src end)

    # Log findings for now (could create alerts for significant patterns)
    if length(high_fanout_hosts) > 0 do
      Logger.debug("NDR: Found #{length(high_fanout_hosts)} hosts with high fan-out connections")
    end
  end

  # ============================================================================
  # Alert Creation
  # ============================================================================

  defp create_lateral_alert(event, detection) do
    agent_id = event[:agent_id] || event["agent_id"]

    severity = case detection.confidence do
      c when c >= 0.8 -> "high"
      c when c >= 0.6 -> "medium"
      _ -> "low"
    end

    title = case detection.type do
      :port_scan -> "NDR: Port Scan Detected"
      :host_scan -> "NDR: Host Scan Detected"
      :lateral_movement -> "NDR: Lateral Movement Detected"
      :smb_lateral_movement -> "NDR: SMB Lateral Movement"
      :credential_spread -> "NDR: Credential Spreading"
      :rapid_connections -> "NDR: Rapid Internal Connections"
      _ -> "NDR: Lateral Movement Indicator"
    end

    case Alerts.create_alert(%{
           agent_id: agent_id,
           organization_id: event[:organization_id] || OrgLookup.get_org_id(agent_id),
           severity: severity,
           title: title,
           description: detection.description,
           source_event_id: EventNormalizer.source_event_uuid(event),
           event_ids: EventNormalizer.source_event_ids(event),
           evidence: EventNormalizer.alert_evidence(event, detection, :lateral_metadata),
           raw_event: event,
           detection_metadata: detection.metadata || %{},
           mitre_tactics: ["lateral-movement", "discovery"],
           mitre_techniques: detection.mitre_techniques || [],
           threat_score: detection.confidence
         }) do
      {:ok, _alert} ->
        :ok

      {:error, reason} ->
        Logger.warning("Failed to create lateral movement alert (#{detection.type}): #{inspect(reason)}")
        :error
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp is_internal_traffic?(src_ip, dst_ip) do
    IP.internal?(src_ip) and IP.internal?(dst_ip)
  end

  defp is_private_ip?(ip), do: IP.internal?(ip)

  defp port_to_protocol_name(445), do: "SMB"
  defp port_to_protocol_name(139), do: "NetBIOS"
  defp port_to_protocol_name(135), do: "RPC"
  defp port_to_protocol_name(3389), do: "RDP"
  defp port_to_protocol_name(22), do: "SSH"
  defp port_to_protocol_name(5985), do: "WinRM-HTTP"
  defp port_to_protocol_name(5986), do: "WinRM-HTTPS"
  defp port_to_protocol_name(23), do: "Telnet"
  defp port_to_protocol_name(port), do: "Port #{port}"

  defp lateral_mitre_for_port(445), do: ["T1021.002"]
  defp lateral_mitre_for_port(139), do: ["T1021.002"]
  defp lateral_mitre_for_port(135), do: ["T1021.003"]
  defp lateral_mitre_for_port(3389), do: ["T1021.001"]
  defp lateral_mitre_for_port(22), do: ["T1021.004"]
  defp lateral_mitre_for_port(5985), do: ["T1021.006"]
  defp lateral_mitre_for_port(5986), do: ["T1021.006"]
  defp lateral_mitre_for_port(_), do: ["T1021"]

  defp update_stats(state, key) do
    %{state | stats: Map.update(state.stats, key, 1, &(&1 + 1))}
  end

  defp cleanup_old_data do
    cutoff = System.system_time(:millisecond) - 3_600_000  # 1 hour

    # Clean scan tracking
    :ets.tab2list(@scan_tracking_table)
    |> Enum.each(fn {key, data} ->
      if data.last_seen < cutoff do
        :ets.delete(@scan_tracking_table, key)
      end
    end)

    # Clean lateral movement records (keep for longer - 24 hours)
    lateral_cutoff = DateTime.utc_now() |> DateTime.add(-86400, :second)
    :ets.tab2list(@lateral_movement_table)
    |> Enum.each(fn {key, movement} ->
      if DateTime.compare(movement.timestamp, lateral_cutoff) == :lt do
        :ets.delete_object(@lateral_movement_table, {key, movement})
      end
    end)

    Logger.debug("NDR Lateral Detector cleanup completed")
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, :timer.minutes(5))
  end

  defp schedule_pattern_analysis do
    Process.send_after(self(), :analyze_patterns, :timer.minutes(15))
  end
end
