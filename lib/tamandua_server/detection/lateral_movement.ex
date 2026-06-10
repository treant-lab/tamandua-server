defmodule TamanduaServer.Detection.LateralMovement do
  @moduledoc """
  Lateral Movement Detection and Path Analysis Engine.

  Maintains a directed graph of host-to-host connections and detects lateral
  movement patterns consistent with MITRE ATT&CK Technique T1021.* and related
  techniques. Provides BFS/DFS path analysis, blast radius computation,
  choke-point identification, and anomaly scoring.

  ## Architecture

  Three ETS tables back the engine:

  - `:lateral_movement_graph` -- directed edges `{source_ip, dest_ip}` with
    protocol, port, timestamp, agent_id, and credential metadata.
  - `:lateral_movement_baselines` -- historical connection baselines per host
    pair used for first-time-seen and protocol anomaly detection.
  - `:lateral_movement_anomalies` -- detected anomalies awaiting retrieval.

  The engine is fed by `Detection.Engine` which routes authentication and
  network-connect events here.  Anomalies that exceed the configured alert
  threshold are promoted to alerts via `TamanduaServer.Alerts`.

  ## Scoring

  Each lateral movement hop receives a risk score computed from:

  - **Protocol risk**: RDP=3, SMB=4, WMI=5, WinRM=5, DCOM=6, PsExec=7,
    ScheduledTask=5, ServiceExec=6
  - **Time-of-day factor**: business hours (0800-1800 UTC) = 1.0x,
    outside hours = 1.5x, weekends = 1.8x
  - **Historical baseline deviation**: first-time connection = 2.0x,
    unusual protocol = 1.6x, normal = 1.0x
  - **Asset criticality**: fetched from `TamanduaServer.Assets.Criticality`

  Path risk equals the sum of individual hop scores.  Alert threshold is
  configurable (default 15).
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Agents.OrgLookup

  # ---------------------------------------------------------------------------
  # ETS table names
  # ---------------------------------------------------------------------------

  @graph_table :lateral_movement_graph
  @baseline_table :lateral_movement_baselines
  @anomaly_table :lateral_movement_anomalies

  # ---------------------------------------------------------------------------
  # Limits and defaults
  # ---------------------------------------------------------------------------

  @max_edges 500_000
  @max_anomalies 50_000
  @retention_hours 168  # 7 days
  @cleanup_interval_ms :timer.minutes(15)
  @default_alert_threshold 15
  @max_bfs_depth 12

  # ---------------------------------------------------------------------------
  # Protocol risk weights (MITRE T1021.*)
  # ---------------------------------------------------------------------------

  @protocol_risk %{
    "rdp"            => 3,   # T1021.001
    "smb"            => 4,   # T1021.002
    "dcom"           => 6,   # T1021.003
    "ssh"            => 3,   # T1021.004
    "winrm"          => 5,   # T1021.006
    "wmi"            => 5,   # T1047
    "psexec"         => 7,   # T1569.002 (PsExec is service execution)
    "service_exec"   => 6,   # T1569.002
    "scheduled_task" => 5,   # T1053.005
    "wmic"           => 5,   # T1047 alternate name
    "smbexec"        => 7,   # Impacket smbexec
    "atexec"         => 5    # Impacket atexec
  }

  @mitre_map %{
    "rdp"            => %{technique: "T1021.001", tactic: "lateral-movement", name: "Remote Desktop Protocol"},
    "smb"            => %{technique: "T1021.002", tactic: "lateral-movement", name: "SMB/Windows Admin Shares"},
    "dcom"           => %{technique: "T1021.003", tactic: "lateral-movement", name: "Distributed COM"},
    "ssh"            => %{technique: "T1021.004", tactic: "lateral-movement", name: "SSH"},
    "winrm"          => %{technique: "T1021.006", tactic: "lateral-movement", name: "Windows Remote Management"},
    "wmi"            => %{technique: "T1047",     tactic: "execution",        name: "WMI"},
    "psexec"         => %{technique: "T1569.002", tactic: "execution",        name: "Service Execution (PsExec)"},
    "service_exec"   => %{technique: "T1569.002", tactic: "execution",        name: "Service Execution"},
    "scheduled_task" => %{technique: "T1053.005", tactic: "execution",        name: "Scheduled Task"},
    "wmic"           => %{technique: "T1047",     tactic: "execution",        name: "WMI (wmic)"},
    "smbexec"        => %{technique: "T1569.002", tactic: "execution",        name: "Service Execution (smbexec)"},
    "atexec"         => %{technique: "T1053.005", tactic: "execution",        name: "Scheduled Task (atexec)"}
  }

  # Ports that hint at lateral movement protocols
  @port_to_protocol %{
    3389 => "rdp",
    445  => "smb",
    139  => "smb",
    135  => "dcom",
    22   => "ssh",
    5985 => "winrm",
    5986 => "winrm"
  }

  # ===========================================================================
  # Client API
  # ===========================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record a lateral movement event (authentication, remote service creation, etc.).

  `attrs` is a map with at least `:source_ip`, `:dest_ip`, `:protocol`.
  Optional keys: `:port`, `:agent_id`, `:username`, `:credential_type`,
  `:event_type`, `:timestamp`.
  """
  @spec record_hop(map()) :: :ok
  def record_hop(attrs) do
    GenServer.cast(__MODULE__, {:record_hop, attrs})
  end

  @doc """
  Process a raw telemetry event and extract lateral movement signals.
  Called by Detection.Engine for relevant event types.
  """
  @spec process_event(map()) :: :ok
  def process_event(event) do
    GenServer.cast(__MODULE__, {:process_event, event})
  end

  @doc "Return the full movement graph as a list of edge maps."
  @spec get_graph(keyword()) :: [map()]
  def get_graph(opts \\ []) do
    GenServer.call(__MODULE__, {:get_graph, opts})
  end

  @doc "BFS/DFS paths from `source_ip` up to `max_depth` hops."
  @spec find_paths(String.t(), keyword()) :: [map()]
  def find_paths(source_ip, opts \\ []) do
    GenServer.call(__MODULE__, {:find_paths, source_ip, opts}, 15_000)
  end

  @doc "Compute blast radius (reachable hosts) from `host_ip`."
  @spec blast_radius(String.t()) :: map()
  def blast_radius(host_ip) do
    GenServer.call(__MODULE__, {:blast_radius, host_ip}, 15_000)
  end

  @doc "Identify choke points (hosts that bridge network segments)."
  @spec choke_points() :: [map()]
  def choke_points do
    GenServer.call(__MODULE__, :choke_points, 15_000)
  end

  @doc "Return all detected anomalies, newest first."
  @spec get_anomalies(keyword()) :: [map()]
  def get_anomalies(opts \\ []) do
    GenServer.call(__MODULE__, {:get_anomalies, opts})
  end

  @doc "Summary statistics."
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  @doc "Simulate an attack path from `source_ip` towards `targets`."
  @spec simulate(String.t(), [String.t()], keyword()) :: map()
  def simulate(source_ip, targets, opts \\ []) do
    GenServer.call(__MODULE__, {:simulate, source_ip, targets, opts}, 30_000)
  end

  # ===========================================================================
  # Server callbacks
  # ===========================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@graph_table, [:bag, :named_table, :public, read_concurrency: true])
    :ets.new(@baseline_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@anomaly_table, [:ordered_set, :named_table, :public, read_concurrency: true])

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)

    Logger.info("Lateral Movement Detection Engine started")

    state = %{
      edge_count: 0,
      anomaly_count: 0,
      total_hops_recorded: 0,
      alerts_created: 0,
      alert_threshold: @default_alert_threshold
    }

    {:ok, state}
  end

  # -- casts ------------------------------------------------------------------

  @impl true
  def handle_cast({:record_hop, attrs}, state) do
    new_state = do_record_hop(attrs, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_cast({:process_event, event}, state) do
    case extract_lateral_movement(event) do
      nil ->
        {:noreply, state}

      attrs ->
        new_state = do_record_hop(attrs, state)
        {:noreply, new_state}
    end
  end

  # -- calls ------------------------------------------------------------------

  @impl true
  def handle_call({:get_graph, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 1000)
    since = Keyword.get(opts, :since, nil)
    protocol = Keyword.get(opts, :protocol, nil)

    edges = ets_all_edges()
    |> maybe_filter_since(since)
    |> maybe_filter_protocol(protocol)
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(limit)

    {:reply, edges, state}
  end

  @impl true
  def handle_call({:find_paths, source_ip, opts}, _from, state) do
    max_depth = Keyword.get(opts, :max_depth, @max_bfs_depth)
    target_ip = Keyword.get(opts, :target_ip, nil)

    paths = bfs_paths(source_ip, max_depth, target_ip)

    result = %{
      source: source_ip,
      target: target_ip,
      max_depth: max_depth,
      paths: paths,
      path_count: length(paths),
      highest_risk_path: Enum.max_by(paths, & &1.risk_score, fn -> nil end)
    }

    {:reply, result, state}
  end

  @impl true
  def handle_call({:blast_radius, host_ip}, _from, state) do
    reachable = bfs_reachable(host_ip, @max_bfs_depth)

    reachable_with_details = Enum.map(reachable, fn ip ->
      hops = shortest_hop_count(host_ip, ip)
      criticality = get_asset_criticality(ip)
      %{
        ip: ip,
        hops: hops,
        criticality: criticality,
        risk: hops_to_risk(hops, criticality)
      }
    end)

    result = %{
      source: host_ip,
      reachable_count: length(reachable),
      reachable_hosts: Enum.sort_by(reachable_with_details, & &1.hops),
      critical_hosts_reachable: Enum.count(reachable_with_details, & &1.criticality >= 8),
      max_depth: Enum.reduce(reachable_with_details, 0, fn h, acc -> max(h.hops, acc) end)
    }

    {:reply, result, state}
  end

  @impl true
  def handle_call(:choke_points, _from, state) do
    points = compute_choke_points()
    {:reply, points, state}
  end

  @impl true
  def handle_call({:get_anomalies, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 200)
    severity = Keyword.get(opts, :severity, nil)

    anomalies = ets_all_anomalies()
    |> maybe_filter_severity(severity)
    |> Enum.sort_by(& &1.detected_at, {:desc, DateTime})
    |> Enum.take(limit)

    {:reply, anomalies, state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    unique_hosts = count_unique_hosts()
    unique_edges = :ets.info(@graph_table, :size)
    anomaly_count = :ets.info(@anomaly_table, :size)

    protocol_breakdown = ets_all_edges()
    |> Enum.group_by(& &1.protocol)
    |> Map.new(fn {proto, edges} -> {proto, length(edges)} end)

    result = %{
      unique_hosts: unique_hosts,
      unique_edges: unique_edges,
      anomaly_count: anomaly_count,
      total_hops_recorded: state.total_hops_recorded,
      alerts_created: state.alerts_created,
      alert_threshold: state.alert_threshold,
      protocol_breakdown: protocol_breakdown,
      retention_hours: @retention_hours
    }

    {:reply, result, state}
  end

  @impl true
  def handle_call({:simulate, source_ip, targets, opts}, _from, state) do
    max_depth = Keyword.get(opts, :max_depth, @max_bfs_depth)
    protocol_filter = Keyword.get(opts, :protocol, nil)

    # Build adjacency from current graph, optionally filtered by protocol
    edges = ets_all_edges()
    |> maybe_filter_protocol(protocol_filter)

    adjacency = build_adjacency(edges)

    results = Enum.map(targets, fn target ->
      path = dijkstra_path(adjacency, source_ip, target)
      %{
        target: target,
        reachable: path != nil,
        path: path || [],
        hop_count: if(path, do: length(path) - 1, else: nil),
        risk_score: if(path, do: compute_path_risk(path, edges), else: 0),
        protocols_used: if(path, do: extract_path_protocols(path, edges), else: []),
        criticality: get_asset_criticality(target)
      }
    end)

    overall_risk = results
    |> Enum.filter(& &1.reachable)
    |> Enum.map(& &1.risk_score)
    |> case do
      [] -> 0
      scores -> Enum.sum(scores) / length(scores)
    end

    result = %{
      source: source_ip,
      targets: results,
      reachable_count: Enum.count(results, & &1.reachable),
      total_targets: length(targets),
      overall_risk: Float.round(overall_risk * 1.0, 2),
      max_depth: max_depth,
      simulated_at: DateTime.utc_now()
    }

    {:reply, result, state}
  end

  # -- info -------------------------------------------------------------------

  @impl true
  def handle_info(:cleanup, state) do
    cleaned = cleanup_stale_data()
    Logger.debug("Lateral movement cleanup: removed #{cleaned} stale entries")
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  # ===========================================================================
  # Event extraction
  # ===========================================================================

  @doc false
  def extract_lateral_movement(event) do
    event_type = to_string(event[:event_type] || event["event_type"] || "")
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    timestamp = event[:timestamp] || event["timestamp"] || DateTime.utc_now()

    cond do
      # Authentication events (logon type 10 = RDP, type 3 = network, etc.)
      event_type in ["authentication", "logon", "auth_event", "logon_event"] ->
        extract_auth_event(payload, agent_id, timestamp)

      # Network connections on lateral movement ports
      event_type in ["network_connect", "network_connection"] ->
        extract_network_event(payload, agent_id, timestamp)

      # Remote service creation (PsExec pattern)
      event_type in ["service_create", "service_created", "service_install"] ->
        extract_service_event(payload, agent_id, timestamp)

      # Scheduled task creation
      event_type in ["scheduled_task", "task_create", "scheduled_task_create"] ->
        extract_task_event(payload, agent_id, timestamp)

      # WMI event (process creation via WMI)
      event_type in ["wmi_event", "wmi_exec", "wmi_process"] ->
        extract_wmi_event(payload, agent_id, timestamp)

      # Named pipe connections (often used by PsExec, SMB)
      event_type in ["named_pipe", "pipe_connect"] ->
        extract_pipe_event(payload, agent_id, timestamp)

      true ->
        nil
    end
  end

  defp extract_auth_event(payload, agent_id, timestamp) do
    source_ip = payload[:source_ip] || payload["source_ip"] || payload[:src_ip] || payload["src_ip"]
    dest_ip = payload[:dest_ip] || payload["dest_ip"] || payload[:dst_ip] || payload["dst_ip"] || payload[:local_ip] || payload["local_ip"]
    username = payload[:username] || payload["username"] || payload[:user] || payload["user"]
    logon_type = payload[:logon_type] || payload["logon_type"]
    protocol = payload[:protocol] || payload["protocol"]

    # Determine protocol from logon type if not explicit
    protocol = protocol || case logon_type do
      10 -> "rdp"
      3  -> "smb"
      7  -> "rdp"   # Reconnection
      _  -> "smb"   # Default to SMB for network logons
    end

    if source_ip && dest_ip && source_ip != dest_ip do
      %{
        source_ip: normalize_ip(source_ip),
        dest_ip: normalize_ip(dest_ip),
        protocol: to_string(protocol),
        port: port_for_protocol(protocol),
        agent_id: agent_id,
        timestamp: parse_timestamp(timestamp),
        username: username,
        credential_type: payload[:credential_type] || payload["credential_type"] || "password",
        event_type: "authentication"
      }
    else
      nil
    end
  end

  defp extract_network_event(payload, agent_id, timestamp) do
    source_ip = payload[:local_ip] || payload["local_ip"] || payload[:source_ip] || payload["source_ip"]
    dest_ip = payload[:remote_ip] || payload["remote_ip"] || payload[:dest_ip] || payload["dest_ip"]
    dest_port = payload[:remote_port] || payload["remote_port"] || payload[:dest_port] || payload["dest_port"]

    protocol = @port_to_protocol[dest_port]

    if source_ip && dest_ip && protocol && source_ip != dest_ip do
      %{
        source_ip: normalize_ip(source_ip),
        dest_ip: normalize_ip(dest_ip),
        protocol: protocol,
        port: dest_port,
        agent_id: agent_id,
        timestamp: parse_timestamp(timestamp),
        username: payload[:username] || payload["username"],
        credential_type: nil,
        event_type: "network_connect"
      }
    else
      nil
    end
  end

  defp extract_service_event(payload, agent_id, timestamp) do
    source_ip = payload[:source_ip] || payload["source_ip"]
    dest_ip = payload[:dest_ip] || payload["dest_ip"] || payload[:local_ip] || payload["local_ip"]
    service_name = payload[:service_name] || payload["service_name"]

    protocol = cond do
      service_name && String.contains?(String.downcase(to_string(service_name)), "psexe") -> "psexec"
      true -> "service_exec"
    end

    if source_ip && dest_ip do
      %{
        source_ip: normalize_ip(source_ip),
        dest_ip: normalize_ip(dest_ip),
        protocol: protocol,
        port: 445,
        agent_id: agent_id,
        timestamp: parse_timestamp(timestamp),
        username: payload[:username] || payload["username"],
        credential_type: payload[:credential_type] || payload["credential_type"],
        event_type: "service_create",
        service_name: service_name
      }
    else
      nil
    end
  end

  defp extract_task_event(payload, agent_id, timestamp) do
    source_ip = payload[:source_ip] || payload["source_ip"]
    dest_ip = payload[:dest_ip] || payload["dest_ip"] || payload[:local_ip] || payload["local_ip"]

    if source_ip && dest_ip do
      %{
        source_ip: normalize_ip(source_ip),
        dest_ip: normalize_ip(dest_ip),
        protocol: "scheduled_task",
        port: 135,
        agent_id: agent_id,
        timestamp: parse_timestamp(timestamp),
        username: payload[:username] || payload["username"],
        credential_type: payload[:credential_type] || payload["credential_type"],
        event_type: "scheduled_task"
      }
    else
      nil
    end
  end

  defp extract_wmi_event(payload, agent_id, timestamp) do
    source_ip = payload[:source_ip] || payload["source_ip"]
    dest_ip = payload[:dest_ip] || payload["dest_ip"] || payload[:local_ip] || payload["local_ip"]

    if source_ip && dest_ip do
      %{
        source_ip: normalize_ip(source_ip),
        dest_ip: normalize_ip(dest_ip),
        protocol: "wmi",
        port: 135,
        agent_id: agent_id,
        timestamp: parse_timestamp(timestamp),
        username: payload[:username] || payload["username"],
        credential_type: payload[:credential_type] || payload["credential_type"],
        event_type: "wmi_exec"
      }
    else
      nil
    end
  end

  defp extract_pipe_event(payload, agent_id, timestamp) do
    source_ip = payload[:source_ip] || payload["source_ip"]
    dest_ip = payload[:dest_ip] || payload["dest_ip"] || payload[:local_ip] || payload["local_ip"]
    pipe_name = payload[:pipe_name] || payload["pipe_name"]

    protocol = cond do
      pipe_name && String.contains?(String.downcase(to_string(pipe_name)), "psexe") -> "psexec"
      pipe_name && String.contains?(String.downcase(to_string(pipe_name)), "svcctl") -> "service_exec"
      true -> "smb"
    end

    if source_ip && dest_ip && source_ip != dest_ip do
      %{
        source_ip: normalize_ip(source_ip),
        dest_ip: normalize_ip(dest_ip),
        protocol: protocol,
        port: 445,
        agent_id: agent_id,
        timestamp: parse_timestamp(timestamp),
        username: payload[:username] || payload["username"],
        credential_type: nil,
        event_type: "pipe_connect"
      }
    else
      nil
    end
  end

  # ===========================================================================
  # Core hop recording + anomaly detection
  # ===========================================================================

  defp do_record_hop(attrs, state) do
    source_ip = attrs[:source_ip] || attrs["source_ip"]
    dest_ip = attrs[:dest_ip] || attrs["dest_ip"]
    protocol = to_string(attrs[:protocol] || attrs["protocol"] || "unknown")
    port = attrs[:port] || attrs["port"] || 0
    agent_id = attrs[:agent_id] || attrs["agent_id"]
    timestamp = attrs[:timestamp] || DateTime.utc_now()
    username = attrs[:username] || attrs["username"]
    credential_type = attrs[:credential_type] || attrs["credential_type"]
    event_type = attrs[:event_type] || attrs["event_type"]

    unless source_ip && dest_ip do
      state
    else
      # Insert edge into graph
      edge = %{
        source_ip: source_ip,
        dest_ip: dest_ip,
        protocol: protocol,
        port: port,
        agent_id: agent_id,
        timestamp: timestamp,
        username: username,
        credential_type: credential_type,
        event_type: event_type
      }

      if state.edge_count < @max_edges do
        :ets.insert(@graph_table, {{source_ip, dest_ip}, edge})
      end

      # Run anomaly checks
      anomalies = detect_anomalies(edge)

      anomaly_count = state.anomaly_count
      anomaly_count = Enum.reduce(anomalies, anomaly_count, fn anomaly, acc ->
        if acc < @max_anomalies do
          anomaly_id = :erlang.unique_integer([:positive, :monotonic])
          :ets.insert(@anomaly_table, {anomaly_id, anomaly})
          acc + 1
        else
          acc
        end
      end)

      # Score the hop and check alert threshold
      hop_score = score_hop(edge)
      alerts_created = state.alerts_created

      alerts_created = if hop_score >= state.alert_threshold do
        create_lateral_movement_alert(edge, anomalies, hop_score)
        alerts_created + 1
      else
        # Check if there is a rapid pivoting pattern (3+ hops in 5 min from same source)
        recent = recent_hops_from(source_ip, 300)
        if length(recent) >= 3 do
          path_score = Enum.reduce(recent, 0, fn e, acc -> acc + score_hop(e) end)
          if path_score >= state.alert_threshold do
            create_pivoting_alert(source_ip, recent, path_score)
            alerts_created + 1
          else
            alerts_created
          end
        else
          alerts_created
        end
      end

      # Update baseline
      update_baseline(source_ip, dest_ip, protocol, timestamp)

      %{state |
        edge_count: state.edge_count + 1,
        anomaly_count: anomaly_count,
        total_hops_recorded: state.total_hops_recorded + 1,
        alerts_created: alerts_created
      }
    end
  end

  # ===========================================================================
  # Anomaly Detection
  # ===========================================================================

  defp detect_anomalies(edge) do
    anomalies = []

    # 1. First-time connection between hosts
    anomalies = if first_time_connection?(edge.source_ip, edge.dest_ip) do
      [%{
        type: :first_time_connection,
        severity: :medium,
        description: "First observed connection from #{edge.source_ip} to #{edge.dest_ip} via #{edge.protocol}",
        source_ip: edge.source_ip,
        dest_ip: edge.dest_ip,
        protocol: edge.protocol,
        port: edge.port,
        username: edge.username,
        agent_id: edge.agent_id,
        detected_at: DateTime.utc_now(),
        mitre_technique: Map.get(@mitre_map, edge.protocol, %{})[:technique]
      } | anomalies]
    else
      anomalies
    end

    # 2. Unusual protocol for host pair
    anomalies = if unusual_protocol?(edge.source_ip, edge.dest_ip, edge.protocol) do
      [%{
        type: :unusual_protocol,
        severity: :high,
        description: "Unusual protocol #{edge.protocol} between #{edge.source_ip} and #{edge.dest_ip} (not in baseline)",
        source_ip: edge.source_ip,
        dest_ip: edge.dest_ip,
        protocol: edge.protocol,
        port: edge.port,
        username: edge.username,
        agent_id: edge.agent_id,
        detected_at: DateTime.utc_now(),
        mitre_technique: Map.get(@mitre_map, edge.protocol, %{})[:technique]
      } | anomalies]
    else
      anomalies
    end

    # 3. After-hours lateral movement
    anomalies = if after_hours?(edge.timestamp) do
      [%{
        type: :after_hours,
        severity: :medium,
        description: "Lateral movement detected outside business hours: #{edge.source_ip} -> #{edge.dest_ip} via #{edge.protocol}",
        source_ip: edge.source_ip,
        dest_ip: edge.dest_ip,
        protocol: edge.protocol,
        port: edge.port,
        username: edge.username,
        agent_id: edge.agent_id,
        detected_at: DateTime.utc_now(),
        mitre_technique: Map.get(@mitre_map, edge.protocol, %{})[:technique]
      } | anomalies]
    else
      anomalies
    end

    # 4. Rapid sequential connections (pivoting) - 3+ unique destinations in 5 minutes
    recent = recent_hops_from(edge.source_ip, 300)
    unique_dests = recent |> Enum.map(& &1.dest_ip) |> Enum.uniq() |> length()

    anomalies = if unique_dests >= 3 do
      [%{
        type: :rapid_pivoting,
        severity: :high,
        description: "Rapid pivoting detected: #{edge.source_ip} connected to #{unique_dests} hosts in 5 minutes",
        source_ip: edge.source_ip,
        dest_ip: edge.dest_ip,
        protocol: edge.protocol,
        port: edge.port,
        username: edge.username,
        agent_id: edge.agent_id,
        detected_at: DateTime.utc_now(),
        unique_destinations: unique_dests,
        mitre_technique: "T1021"
      } | anomalies]
    else
      anomalies
    end

    # 5. Service account used interactively (logon type 10 or RDP with service account)
    anomalies = if service_account_interactive?(edge) do
      [%{
        type: :service_account_interactive,
        severity: :high,
        description: "Service account '#{edge.username}' used for interactive #{edge.protocol} session to #{edge.dest_ip}",
        source_ip: edge.source_ip,
        dest_ip: edge.dest_ip,
        protocol: edge.protocol,
        port: edge.port,
        username: edge.username,
        agent_id: edge.agent_id,
        detected_at: DateTime.utc_now(),
        mitre_technique: "T1078"
      } | anomalies]
    else
      anomalies
    end

    # 6. Credential usage from unexpected source
    anomalies = if credential_source_anomaly?(edge) do
      [%{
        type: :credential_source_anomaly,
        severity: :high,
        description: "Credentials for '#{edge.username}' used from unexpected source #{edge.source_ip}",
        source_ip: edge.source_ip,
        dest_ip: edge.dest_ip,
        protocol: edge.protocol,
        port: edge.port,
        username: edge.username,
        agent_id: edge.agent_id,
        detected_at: DateTime.utc_now(),
        mitre_technique: "T1078"
      } | anomalies]
    else
      anomalies
    end

    anomalies
  end

  # ===========================================================================
  # Anomaly detection helpers
  # ===========================================================================

  defp first_time_connection?(source_ip, dest_ip) do
    case :ets.lookup(@baseline_table, {source_ip, dest_ip}) do
      [] -> true
      _ -> false
    end
  end

  defp unusual_protocol?(source_ip, dest_ip, protocol) do
    case :ets.lookup(@baseline_table, {source_ip, dest_ip}) do
      [{_, baseline}] ->
        known_protocols = baseline[:protocols] || []
        protocol not in known_protocols and length(known_protocols) > 0

      [] ->
        # No baseline -- not unusual (handled by first_time_connection?)
        false
    end
  end

  defp after_hours?(timestamp) do
    dt = case timestamp do
      %DateTime{} = d -> d
      _ -> DateTime.utc_now()
    end

    hour = dt.hour
    day_of_week = Date.day_of_week(DateTime.to_date(dt))

    # Weekend
    if day_of_week in [6, 7] do
      true
    else
      # Outside 0800-1800 UTC
      hour < 8 or hour >= 18
    end
  end

  defp service_account_interactive?(edge) do
    username = to_string(edge.username || "")
    protocol = edge.protocol

    is_service_account = String.starts_with?(String.downcase(username), "svc") or
                         String.starts_with?(String.downcase(username), "service") or
                         String.starts_with?(String.downcase(username), "sa_") or
                         String.contains?(String.downcase(username), "$") or
                         String.starts_with?(String.downcase(username), "task_")

    is_interactive = protocol in ["rdp", "winrm", "ssh"]

    is_service_account and is_interactive and username != ""
  end

  defp credential_source_anomaly?(edge) do
    username = edge.username
    source_ip = edge.source_ip

    if username && username != "" do
      # Look for this user's typical source IPs
      typical_sources = ets_all_edges()
      |> Enum.filter(fn e -> e.username == username end)
      |> Enum.map(& &1.source_ip)
      |> Enum.uniq()

      # If we have a baseline of sources and this one is new
      length(typical_sources) >= 3 and source_ip not in typical_sources
    else
      false
    end
  end

  # ===========================================================================
  # Scoring
  # ===========================================================================

  @doc false
  def score_hop(edge) do
    protocol_score = Map.get(@protocol_risk, edge.protocol, 3)
    time_factor = time_of_day_factor(edge.timestamp)
    baseline_factor = baseline_deviation_factor(edge.source_ip, edge.dest_ip, edge.protocol)
    criticality = get_asset_criticality(edge.dest_ip)
    criticality_factor = criticality_multiplier(criticality)

    raw = protocol_score * time_factor * baseline_factor * criticality_factor
    Float.round(raw, 2)
  end

  defp time_of_day_factor(timestamp) do
    dt = case timestamp do
      %DateTime{} = d -> d
      _ -> DateTime.utc_now()
    end

    day_of_week = Date.day_of_week(DateTime.to_date(dt))
    hour = dt.hour

    cond do
      day_of_week in [6, 7] -> 1.8    # Weekend
      hour < 8 or hour >= 18 -> 1.5   # After hours
      true -> 1.0                      # Business hours
    end
  end

  defp baseline_deviation_factor(source_ip, dest_ip, protocol) do
    case :ets.lookup(@baseline_table, {source_ip, dest_ip}) do
      [] ->
        # Never seen before
        2.0

      [{_, baseline}] ->
        known_protocols = baseline[:protocols] || []
        if protocol in known_protocols do
          1.0   # Normal
        else
          1.6   # Known pair, unknown protocol
        end
    end
  end

  defp criticality_multiplier(criticality) when criticality >= 9, do: 2.0
  defp criticality_multiplier(criticality) when criticality >= 7, do: 1.5
  defp criticality_multiplier(criticality) when criticality >= 5, do: 1.2
  defp criticality_multiplier(_), do: 1.0

  defp get_asset_criticality(ip) do
    try do
      TamanduaServer.Assets.Criticality.get_score(ip)
    rescue
      _ -> 5
    catch
      :exit, _ -> 5
    end
  end

  # ===========================================================================
  # Path analysis (BFS / Dijkstra)
  # ===========================================================================

  defp bfs_paths(source_ip, max_depth, target_ip) do
    edges = ets_all_edges()
    adjacency = build_adjacency(edges)

    # BFS collecting all paths
    queue = :queue.in({source_ip, [source_ip], 0, 0.0}, :queue.new())
    visited_paths = []

    do_bfs(queue, adjacency, edges, max_depth, target_ip, visited_paths, MapSet.new())
    |> Enum.map(fn {path, risk} ->
      hops = build_hop_details(path, edges)
      %{
        path: path,
        hop_count: length(path) - 1,
        risk_score: Float.round(risk, 2),
        hops: hops,
        protocols: hops |> Enum.map(& &1.protocol) |> Enum.uniq(),
        island_hopping: length(path) > 3
      }
    end)
    |> Enum.sort_by(& &1.risk_score, :desc)
    |> Enum.take(50)
  end

  defp do_bfs(queue, adjacency, edges, max_depth, target_ip, found_paths, _global_visited) do
    case :queue.out(queue) do
      {:empty, _} ->
        found_paths

      {{:value, {current, path, depth, risk}}, rest_queue} ->
        if depth >= max_depth do
          # Record if we reached target or if no target specified
          found_paths = if target_ip == nil or current == target_ip do
            if length(path) > 1 do
              [{path, risk} | found_paths]
            else
              found_paths
            end
          else
            found_paths
          end

          do_bfs(rest_queue, adjacency, edges, max_depth, target_ip, found_paths, MapSet.new())
        else
          neighbors = Map.get(adjacency, current, [])

          {new_queue, new_found} = Enum.reduce(neighbors, {rest_queue, found_paths}, fn neighbor, {q_acc, f_acc} ->
            if neighbor in path do
              # Avoid cycles
              {q_acc, f_acc}
            else
              new_path = path ++ [neighbor]
              hop_edge = find_edge(edges, current, neighbor)
              hop_risk = if hop_edge, do: score_hop(hop_edge), else: 3.0
              new_risk = risk + hop_risk

              # If this is the target, record the path
              f_acc = if target_ip && neighbor == target_ip do
                [{new_path, new_risk} | f_acc]
              else
                f_acc
              end

              # Continue BFS
              q_acc = :queue.in({neighbor, new_path, depth + 1, new_risk}, q_acc)
              {q_acc, f_acc}
            end
          end)

          # If no target specified, record paths of length > 1
          new_found = if target_ip == nil and length(path) > 1 do
            [{path, risk} | new_found]
          else
            new_found
          end

          do_bfs(new_queue, adjacency, edges, max_depth, target_ip, new_found, MapSet.new())
        end
    end
  end

  defp bfs_reachable(source_ip, max_depth) do
    edges = ets_all_edges()
    adjacency = build_adjacency(edges)

    do_bfs_reachable([source_ip], adjacency, MapSet.new([source_ip]), 0, max_depth)
    |> MapSet.delete(source_ip)
    |> MapSet.to_list()
  end

  defp do_bfs_reachable([], _adjacency, visited, _depth, _max_depth), do: visited
  defp do_bfs_reachable(_frontier, _adjacency, visited, depth, max_depth) when depth >= max_depth, do: visited
  defp do_bfs_reachable(frontier, adjacency, visited, depth, max_depth) do
    next_frontier = frontier
    |> Enum.flat_map(fn node -> Map.get(adjacency, node, []) end)
    |> Enum.reject(fn node -> MapSet.member?(visited, node) end)
    |> Enum.uniq()

    new_visited = Enum.reduce(next_frontier, visited, &MapSet.put(&2, &1))
    do_bfs_reachable(next_frontier, adjacency, new_visited, depth + 1, max_depth)
  end

  defp dijkstra_path(adjacency, source, target) do
    # Simplified Dijkstra -- returns the shortest path (fewest hops)
    dist = %{source => 0}
    prev = %{}
    queue = [{0, source}]

    {_dist, prev} = do_dijkstra(queue, adjacency, dist, prev, target)

    # Reconstruct path
    reconstruct_path(prev, source, target)
  end

  defp do_dijkstra([], _adjacency, dist, prev, _target), do: {dist, prev}
  defp do_dijkstra([{_d, current} | rest], adjacency, dist, prev, target) do
    if current == target do
      {dist, prev}
    else
      neighbors = Map.get(adjacency, current, [])
      current_dist = Map.get(dist, current, :infinity)

      {new_dist, new_prev, new_queue} = Enum.reduce(neighbors, {dist, prev, rest}, fn neighbor, {d_acc, p_acc, q_acc} ->
        alt = current_dist + 1
        existing = Map.get(d_acc, neighbor, :infinity)

        if alt < existing do
          {Map.put(d_acc, neighbor, alt), Map.put(p_acc, neighbor, current), [{alt, neighbor} | q_acc]}
        else
          {d_acc, p_acc, q_acc}
        end
      end)

      sorted_queue = Enum.sort_by(new_queue, &elem(&1, 0))
      do_dijkstra(sorted_queue, adjacency, new_dist, new_prev, target)
    end
  end

  defp reconstruct_path(prev, source, target) do
    do_reconstruct(prev, source, target, [target])
  end

  defp do_reconstruct(_prev, source, source, path), do: path
  defp do_reconstruct(prev, source, current, path) do
    case Map.get(prev, current) do
      nil -> nil  # No path
      previous -> do_reconstruct(prev, source, previous, [previous | path])
    end
  end

  # ===========================================================================
  # Choke point analysis
  # ===========================================================================

  defp compute_choke_points do
    edges = ets_all_edges()
    adjacency = build_adjacency(edges)
    hosts = Map.keys(adjacency) |> Enum.uniq()

    # Calculate betweenness centrality approximation
    # A host is a choke point if removing it disconnects parts of the graph
    Enum.map(hosts, fn host ->
      # Count how many paths go through this host
      in_degree = edges |> Enum.count(fn e -> e.dest_ip == host end)
      out_degree = edges |> Enum.count(fn e -> e.source_ip == host end)

      # Neighbors that only connect through this host
      in_neighbors = edges |> Enum.filter(fn e -> e.dest_ip == host end) |> Enum.map(& &1.source_ip) |> Enum.uniq()
      out_neighbors = Map.get(adjacency, host, []) |> Enum.uniq()

      # Calculate bridge score: hosts that connect otherwise disconnected segments
      bridge_score = calculate_bridge_score(host, adjacency, hosts)

      protocols_seen = edges
      |> Enum.filter(fn e -> e.source_ip == host or e.dest_ip == host end)
      |> Enum.map(& &1.protocol)
      |> Enum.uniq()

      criticality = get_asset_criticality(host)

      %{
        host: host,
        in_degree: in_degree,
        out_degree: out_degree,
        total_degree: in_degree + out_degree,
        in_neighbors: in_neighbors,
        out_neighbors: out_neighbors,
        bridge_score: Float.round(bridge_score, 3),
        protocols: protocols_seen,
        criticality: criticality,
        choke_score: Float.round(bridge_score * (in_degree + out_degree) * criticality_multiplier(criticality), 2)
      }
    end)
    |> Enum.filter(fn cp -> cp.total_degree >= 2 end)
    |> Enum.sort_by(& &1.choke_score, :desc)
    |> Enum.take(20)
  end

  defp calculate_bridge_score(host, adjacency, all_hosts) do
    # Simplified betweenness: what fraction of host pairs are disconnected
    # if we remove this host
    other_hosts = Enum.reject(all_hosts, &(&1 == host))
    adj_without = Map.delete(adjacency, host)
    |> Map.new(fn {k, v} -> {k, Enum.reject(v, &(&1 == host))} end)

    if length(other_hosts) < 2 do
      0.0
    else
      # Sample pairs for efficiency
      pairs = for a <- Enum.take(other_hosts, 20), b <- Enum.take(other_hosts, 20), a != b, do: {a, b}
      pairs = Enum.take(pairs, 100)

      total = length(pairs)
      if total == 0 do
        0.0
      else
        disconnected = Enum.count(pairs, fn {a, b} ->
          reachable = do_bfs_reachable([a], adj_without, MapSet.new([a]), 0, 6)
          not MapSet.member?(reachable, b)
        end)

        disconnected / total
      end
    end
  end

  # ===========================================================================
  # Alert creation
  # ===========================================================================

  defp create_lateral_movement_alert(edge, anomalies, score) do
    agent_id = edge.agent_id
    mitre_info = Map.get(@mitre_map, edge.protocol, %{technique: "T1021", tactic: "lateral-movement", name: "Lateral Movement"})

    anomaly_descriptions = anomalies
    |> Enum.map(& &1.description)
    |> Enum.join("; ")

    try do
      Alerts.create_alert(%{
        agent_id: agent_id,
        organization_id: OrgLookup.get_org_id(agent_id),
        severity: severity_from_score(score),
        title: "Lateral Movement: #{edge.protocol |> String.upcase()} #{edge.source_ip} -> #{edge.dest_ip}",
        description: """
        Lateral movement detected via #{mitre_info.name}.
        Source: #{edge.source_ip} | Destination: #{edge.dest_ip}
        Protocol: #{edge.protocol} (port #{edge.port})
        Username: #{edge.username || "unknown"}
        Risk Score: #{score}
        Anomalies: #{anomaly_descriptions}
        """,
        source_event_id: nil,
        event_ids: [],
        evidence: %{
          lateral_movement: %{
            source_ip: edge.source_ip,
            dest_ip: edge.dest_ip,
            protocol: edge.protocol,
            port: edge.port,
            username: edge.username,
            anomalies: Enum.map(anomalies, & &1.type)
          },
          network: [%{source_ip: edge.source_ip, dest_ip: edge.dest_ip, port: edge.port}]
        },
        process_chain: [],
        raw_event: edge,
        mitre_tactics: [mitre_info.tactic],
        mitre_techniques: [mitre_info.technique],
        threat_score: min(score / 20.0, 1.0)
      })
    rescue
      e ->
        Logger.warning("Failed to create lateral movement alert: #{inspect(e)}")
    end
  end

  defp create_pivoting_alert(source_ip, recent_hops, path_score) do
    destinations = recent_hops |> Enum.map(& &1.dest_ip) |> Enum.uniq()
    protocols = recent_hops |> Enum.map(& &1.protocol) |> Enum.uniq()
    agent_id = List.first(recent_hops)[:agent_id]

    try do
      Alerts.create_alert(%{
        agent_id: agent_id,
        organization_id: OrgLookup.get_org_id(agent_id),
        severity: severity_from_score(path_score),
        title: "Lateral Movement Pivot Chain: #{source_ip} -> #{length(destinations)} hosts",
        description: """
        Rapid lateral movement pivot chain detected.
        Source: #{source_ip}
        Destinations: #{Enum.join(destinations, ", ")}
        Protocols: #{Enum.join(protocols, ", ")}
        Hops in 5 minutes: #{length(recent_hops)}
        Path Risk Score: #{path_score}
        Pattern: Island hopping / credential harvesting
        """,
        source_event_id: nil,
        event_ids: [],
        evidence: %{
          lateral_movement: %{
            source_ip: source_ip,
            destinations: destinations,
            protocols: protocols,
            hop_count: length(recent_hops),
            pattern: "rapid_pivoting"
          },
          network: Enum.map(recent_hops, fn h -> %{source_ip: h.source_ip, dest_ip: h.dest_ip, port: h.port} end)
        },
        process_chain: [],
        raw_event: %{source_ip: source_ip, hops: length(recent_hops)},
        mitre_tactics: ["lateral-movement"],
        mitre_techniques: ["T1021"],
        threat_score: min(path_score / 20.0, 1.0)
      })
    rescue
      e ->
        Logger.warning("Failed to create pivoting alert: #{inspect(e)}")
    end
  end

  defp severity_from_score(score) when score >= 25, do: :critical
  defp severity_from_score(score) when score >= 18, do: :high
  defp severity_from_score(score) when score >= 12, do: :medium
  defp severity_from_score(_), do: :low

  # ===========================================================================
  # Baseline management
  # ===========================================================================

  defp update_baseline(source_ip, dest_ip, protocol, timestamp) do
    key = {source_ip, dest_ip}
    now = DateTime.utc_now()

    case :ets.lookup(@baseline_table, key) do
      [] ->
        baseline = %{
          first_seen: timestamp,
          last_seen: now,
          protocols: [protocol],
          connection_count: 1,
          source_ips_for_user: %{}
        }
        :ets.insert(@baseline_table, {key, baseline})

      [{^key, existing}] ->
        updated = %{existing |
          last_seen: now,
          protocols: Enum.uniq([protocol | existing[:protocols] || []]),
          connection_count: (existing[:connection_count] || 0) + 1
        }
        :ets.insert(@baseline_table, {key, updated})
    end
  end

  # ===========================================================================
  # ETS helpers
  # ===========================================================================

  defp ets_all_edges do
    try do
      :ets.tab2list(@graph_table)
      |> Enum.map(fn {_key, edge} -> edge end)
    rescue
      _ -> []
    catch
      :error, :badarg -> []
    end
  end

  defp ets_all_anomalies do
    try do
      :ets.tab2list(@anomaly_table)
      |> Enum.map(fn {_id, anomaly} -> anomaly end)
    rescue
      _ -> []
    catch
      :error, :badarg -> []
    end
  end

  defp recent_hops_from(source_ip, seconds_ago) do
    cutoff = DateTime.add(DateTime.utc_now(), -seconds_ago, :second)

    ets_all_edges()
    |> Enum.filter(fn edge ->
      edge.source_ip == source_ip and
        DateTime.compare(edge.timestamp, cutoff) == :gt
    end)
  end

  defp count_unique_hosts do
    ets_all_edges()
    |> Enum.flat_map(fn e -> [e.source_ip, e.dest_ip] end)
    |> Enum.uniq()
    |> length()
  end

  defp shortest_hop_count(source, target) do
    edges = ets_all_edges()
    adjacency = build_adjacency(edges)
    case dijkstra_path(adjacency, source, target) do
      nil -> @max_bfs_depth
      path -> length(path) - 1
    end
  end

  # ===========================================================================
  # Graph utilities
  # ===========================================================================

  defp build_adjacency(edges) do
    Enum.reduce(edges, %{}, fn edge, acc ->
      Map.update(acc, edge.source_ip, [edge.dest_ip], fn existing ->
        [edge.dest_ip | existing] |> Enum.uniq()
      end)
    end)
  end

  defp find_edge(edges, source, dest) do
    Enum.find(edges, fn e -> e.source_ip == source and e.dest_ip == dest end)
  end

  defp build_hop_details(path, edges) do
    path
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.map(fn [src, dst] ->
      edge = find_edge(edges, src, dst)
      if edge do
        %{
          source: src,
          destination: dst,
          protocol: edge.protocol,
          port: edge.port,
          username: edge.username,
          timestamp: edge.timestamp,
          risk_score: score_hop(edge),
          mitre: Map.get(@mitre_map, edge.protocol, %{})
        }
      else
        %{source: src, destination: dst, protocol: "unknown", port: 0, risk_score: 3.0}
      end
    end)
  end

  defp compute_path_risk(path, edges) do
    path
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.reduce(0, fn [src, dst], acc ->
      edge = find_edge(edges, src, dst)
      if edge, do: acc + score_hop(edge), else: acc + 3.0
    end)
  end

  defp extract_path_protocols(path, edges) do
    path
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.map(fn [src, dst] ->
      edge = find_edge(edges, src, dst)
      if edge, do: edge.protocol, else: "unknown"
    end)
    |> Enum.uniq()
  end

  defp hops_to_risk(hops, criticality) do
    base = max(1, @max_bfs_depth - hops + 1)
    Float.round(base * criticality_multiplier(criticality), 2)
  end

  # ===========================================================================
  # Filtering
  # ===========================================================================

  defp maybe_filter_since(edges, nil), do: edges
  defp maybe_filter_since(edges, since) do
    cutoff = case since do
      %DateTime{} = dt -> dt
      seconds when is_integer(seconds) -> DateTime.add(DateTime.utc_now(), -seconds, :second)
      _ -> DateTime.add(DateTime.utc_now(), -3600, :second)
    end
    Enum.filter(edges, fn e -> DateTime.compare(e.timestamp, cutoff) != :lt end)
  end

  defp maybe_filter_protocol(edges, nil), do: edges
  defp maybe_filter_protocol(edges, protocol) do
    Enum.filter(edges, fn e -> e.protocol == protocol end)
  end

  defp maybe_filter_severity(anomalies, nil), do: anomalies
  defp maybe_filter_severity(anomalies, severity) do
    severity_atom = if is_binary(severity), do: String.to_existing_atom(severity), else: severity
    Enum.filter(anomalies, fn a -> a.severity == severity_atom end)
  rescue
    _ -> anomalies
  end

  # ===========================================================================
  # Cleanup
  # ===========================================================================

  defp cleanup_stale_data do
    cutoff = DateTime.add(DateTime.utc_now(), -@retention_hours * 3600, :second)
    cutoff_unix = DateTime.to_unix(cutoff)

    # Clean graph edges
    edge_count = :ets.tab2list(@graph_table)
    |> Enum.count(fn {key, edge} ->
      ts = case edge.timestamp do
        %DateTime{} = dt -> DateTime.to_unix(dt)
        _ -> DateTime.to_unix(DateTime.utc_now())
      end

      if ts < cutoff_unix do
        :ets.delete_object(@graph_table, {key, edge})
        true
      else
        false
      end
    end)

    # Clean anomalies
    anomaly_count = :ets.tab2list(@anomaly_table)
    |> Enum.count(fn {id, anomaly} ->
      ts = case anomaly.detected_at do
        %DateTime{} = dt -> DateTime.to_unix(dt)
        _ -> DateTime.to_unix(DateTime.utc_now())
      end

      if ts < cutoff_unix do
        :ets.delete(@anomaly_table, id)
        true
      else
        false
      end
    end)

    edge_count + anomaly_count
  end

  # ===========================================================================
  # Utility
  # ===========================================================================

  defp normalize_ip(ip) when is_binary(ip), do: String.trim(ip)
  defp normalize_ip(ip), do: to_string(ip)

  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(_), do: DateTime.utc_now()

  defp port_for_protocol(protocol) do
    case to_string(protocol) do
      "rdp" -> 3389
      "smb" -> 445
      "ssh" -> 22
      "dcom" -> 135
      "winrm" -> 5985
      "wmi" -> 135
      "psexec" -> 445
      "service_exec" -> 445
      "scheduled_task" -> 135
      _ -> 0
    end
  end
end
