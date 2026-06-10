defmodule TamanduaServer.NDR.ProtocolAnalyzer do
  @moduledoc """
  NDR Protocol Analysis Module.

  Provides deep protocol inspection and analysis:

  1. **HTTP/HTTPS Analysis**: Analyzes HTTP traffic patterns, unusual methods,
     suspicious headers, and URL patterns

  2. **DNS Analysis**: Integrates with existing DNS Analyzer for DGA detection,
     tunneling, and exfiltration

  3. **SMB/CIFS Analysis**: Detects lateral movement patterns, unusual shares,
     and reconnaissance activity

  4. **RDP/SSH Detection**: Monitors remote access protocols for unauthorized
     access and brute force attempts

  5. **Protocol Anomalies**: Detects protocol misuse, non-standard ports,
     and tunneling

  MITRE ATT&CK Coverage:
  - T1021: Remote Services (RDP, SSH, SMB)
  - T1071: Application Layer Protocol
  - T1071.001: Web Protocols
  - T1071.004: DNS
  - T1090: Proxy (HTTP tunneling)
  - T1572: Protocol Tunneling
  """

  use GenServer
  require Logger

  import Ecto.Query, warn: false

  alias TamanduaServer.Alerts
  alias TamanduaServer.Agents.OrgLookup
  alias TamanduaServer.NDR.EventNormalizer
  alias TamanduaServer.NDR.IP
  alias TamanduaServer.Detection.DNSAnalyzer
  alias TamanduaServer.Repo

  # ETS tables
  @protocol_stats_table :ndr_protocol_stats
  @smb_activity_table :ndr_smb_activity
  @rdp_sessions_table :ndr_rdp_sessions
  @ssh_sessions_table :ndr_ssh_sessions
  @http_requests_table :ndr_http_requests

  # Known protocol ports
  @http_ports [80, 8080, 8000, 8888, 3000, 5000]
  @https_ports [443, 8443, 9443, 4443]
  @smb_ports [445, 139]
  @rdp_ports [3389, 3390, 3391]
  @ssh_ports [22, 2222]
  @dns_ports [53, 5353]
  @ftp_ports [20, 21]
  @telnet_ports [23]
  @mysql_ports [3306]
  @mssql_ports [1433, 1434]
  @postgres_ports [5432]
  @ldap_ports [389, 636]

  # Suspicious HTTP patterns
  @suspicious_user_agents [
    ~r/python-requests/i,
    ~r/curl\//i,
    ~r/wget\//i,
    ~r/powershell/i,
    ~r/java\//i,
    ~r/go-http-client/i,
    ~r/nmap/i,
    ~r/nikto/i,
    ~r/sqlmap/i,
    ~r/dirbuster/i,
    ~r/gobuster/i
  ]

  @suspicious_http_paths [
    ~r/\.\.\/|\.\.\\/, # Path traversal
    ~r/\/wp-admin/i,
    ~r/\/phpmyadmin/i,
    ~r/\/admin/i,
    ~r/\/\.env/i,
    ~r/\/\.git/i,
    ~r/\/config\./i,
    ~r/\/backup/i,
    ~r/cmd\.exe|powershell|bash/i,
    ~r/select.*from|union.*select|insert.*into/i  # SQL injection
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
  Analyze a network event for protocol-specific detections.
  """
  @spec analyze_event(map()) :: [map()]
  def analyze_event(event) do
    GenServer.call(__MODULE__, {:analyze, event})
  end

  @doc """
  Get protocol statistics.
  """
  @spec get_protocol_stats(keyword()) :: map()
  def get_protocol_stats(opts \\ []) do
    GenServer.call(__MODULE__, {:get_protocol_stats, opts})
  end

  @doc """
  Get SMB activity for lateral movement analysis.
  """
  @spec get_smb_activity(keyword()) :: [map()]
  def get_smb_activity(opts \\ []) do
    GenServer.call(__MODULE__, {:get_smb_activity, opts})
  end

  @doc """
  Get RDP session information.
  """
  @spec get_rdp_sessions(keyword()) :: [map()]
  def get_rdp_sessions(opts \\ []) do
    GenServer.call(__MODULE__, {:get_rdp_sessions, opts})
  end

  @doc """
  Get SSH session information.
  """
  @spec get_ssh_sessions(keyword()) :: [map()]
  def get_ssh_sessions(opts \\ []) do
    GenServer.call(__MODULE__, {:get_ssh_sessions, opts})
  end

  @doc """
  Get HTTP request analysis.
  """
  @spec get_http_analysis(keyword()) :: [map()]
  def get_http_analysis(opts \\ []) do
    GenServer.call(__MODULE__, {:get_http_analysis, opts})
  end

  @doc """
  Get overall NDR protocol analyzer stats.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Identify protocol from port number.
  """
  @spec identify_protocol(integer()) :: atom()
  def identify_protocol(port) do
    cond do
      port in @http_ports -> :http
      port in @https_ports -> :https
      port in @smb_ports -> :smb
      port in @rdp_ports -> :rdp
      port in @ssh_ports -> :ssh
      port in @dns_ports -> :dns
      port in @ftp_ports -> :ftp
      port in @telnet_ports -> :telnet
      port in @mysql_ports -> :mysql
      port in @mssql_ports -> :mssql
      port in @postgres_ports -> :postgres
      port in @ldap_ports -> :ldap
      true -> :unknown
    end
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    :ets.new(@protocol_stats_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@smb_activity_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@rdp_sessions_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ssh_sessions_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@http_requests_table, [:named_table, :bag, :public, read_concurrency: true])

    schedule_cleanup()

    state = %__MODULE__{
      stats: %{
        events_analyzed: 0,
        http_analyzed: 0,
        smb_analyzed: 0,
        rdp_sessions: 0,
        ssh_sessions: 0,
        dns_analyzed: 0,
        detections: 0,
        alerts_created: 0
      },
      last_cleanup: DateTime.utc_now()
    }

    Logger.info("NDR Protocol Analyzer started")
    {:ok, state}
  end

  @impl true
  def handle_call({:analyze, event}, _from, state) do
    {detections, new_state} = do_analyze(event, state)
    {:reply, detections, new_state}
  end

  @impl true
  def handle_call({:get_protocol_stats, opts}, _from, state) do
    stats = fetch_protocol_stats(opts)
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:get_smb_activity, opts}, _from, state) do
    activity = fetch_smb_activity(opts)
    {:reply, activity, state}
  end

  @impl true
  def handle_call({:get_rdp_sessions, opts}, _from, state) do
    sessions = fetch_rdp_sessions(opts)
    {:reply, sessions, state}
  end

  @impl true
  def handle_call({:get_ssh_sessions, opts}, _from, state) do
    sessions = fetch_ssh_sessions(opts)
    {:reply, sessions, state}
  end

  @impl true
  def handle_call({:get_http_analysis, opts}, _from, state) do
    analysis = fetch_http_analysis(opts)
    {:reply, analysis, state}
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

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Core Analysis Logic
  # ============================================================================

  defp do_analyze(event, state) do
    event = EventNormalizer.normalize_event(event)
    payload = event[:payload] || event["payload"] || %{}
    dst_port = payload[:remote_port] || payload["remote_port"] || payload[:dest_port] || payload["dest_port"] || 0

    protocol = identify_protocol(dst_port)

    detections = []
    new_state = update_stats(state, :events_analyzed)

    # Protocol-specific analysis
    {protocol_detections, new_state} = case protocol do
      :http -> analyze_http(event, new_state)
      :https -> analyze_https(event, new_state)
      :smb -> analyze_smb(event, new_state)
      :rdp -> analyze_rdp(event, new_state)
      :ssh -> analyze_ssh(event, new_state)
      :dns -> analyze_dns(event, new_state)
      :telnet -> analyze_insecure_protocol(event, :telnet, new_state)
      :ftp -> analyze_insecure_protocol(event, :ftp, new_state)
      _ -> analyze_unknown_protocol(event, dst_port, new_state)
    end

    detections = detections ++ protocol_detections

    # Check for protocol tunneling (non-standard ports)
    tunnel_detections = detect_tunneling(event, protocol, dst_port)
    detections = detections ++ tunnel_detections

    # Update protocol statistics
    update_protocol_stats(protocol, event)

    # Create alerts for high-confidence detections
    new_state = Enum.reduce(detections, new_state, fn detection, acc ->
      if detection.confidence >= 0.6 do
        case create_protocol_alert(event, detection) do
          :ok -> update_stats(acc, :alerts_created)
          :error -> acc
        end
      else
        acc
      end
    end)

    final_state = if length(detections) > 0 do
      %{new_state | stats: %{new_state.stats | detections: new_state.stats.detections + length(detections)}}
    else
      new_state
    end

    {detections, final_state}
  end

  # --------------------------------------------------------------------------
  # HTTP Analysis
  # --------------------------------------------------------------------------

  defp analyze_http(event, state) do
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    remote_ip = payload[:remote_ip] || payload["remote_ip"]

    http_method = payload[:http_method] || payload["http_method"]
    http_path = payload[:http_path] || payload["http_path"] || payload[:uri] || payload["uri"]
    user_agent = payload[:user_agent] || payload["user_agent"]
    http_host = payload[:http_host] || payload["http_host"] || payload[:host] || payload["host"]

    detections = []

    # Record HTTP request
    record_http_request(agent_id, %{
      remote_ip: remote_ip,
      method: http_method,
      path: http_path,
      host: http_host,
      user_agent: user_agent,
      timestamp: DateTime.utc_now()
    })

    # Check suspicious user agents
    detections = if user_agent && has_suspicious_user_agent?(user_agent) do
      [%{
        type: :suspicious_user_agent,
        confidence: 0.6,
        description: "Suspicious HTTP User-Agent detected: #{String.slice(user_agent, 0, 50)}",
        mitre_techniques: ["T1071.001"],
        metadata: %{user_agent: user_agent, host: http_host}
      } | detections]
    else
      detections
    end

    # Check suspicious paths
    detections = if http_path && has_suspicious_path?(http_path) do
      [%{
        type: :suspicious_http_path,
        confidence: 0.7,
        description: "Suspicious HTTP path accessed: #{String.slice(http_path, 0, 100)}",
        mitre_techniques: ["T1190", "T1071.001"],
        metadata: %{path: http_path, host: http_host, method: http_method}
      } | detections]
    else
      detections
    end

    # Check for unusual HTTP methods
    detections = if http_method in ["CONNECT", "TRACE", "DEBUG", "PROPFIND"] do
      [%{
        type: :unusual_http_method,
        confidence: 0.5,
        description: "Unusual HTTP method used: #{http_method}",
        mitre_techniques: ["T1071.001"],
        metadata: %{method: http_method, host: http_host}
      } | detections]
    else
      detections
    end

    new_state = update_stats(state, :http_analyzed)
    {detections, new_state}
  end

  defp has_suspicious_user_agent?(user_agent) do
    Enum.any?(@suspicious_user_agents, &Regex.match?(&1, user_agent))
  end

  defp has_suspicious_path?(path) do
    Enum.any?(@suspicious_http_paths, &Regex.match?(&1, path))
  end

  # --------------------------------------------------------------------------
  # HTTPS/TLS Analysis
  # --------------------------------------------------------------------------

  defp analyze_https(event, state) do
    payload = event[:payload] || event["payload"] || %{}

    sni = payload[:sni] || payload["sni"] || payload[:hostname] || payload["hostname"]
    ja3 = payload[:ja3] || payload["ja3"]
    cert_info = payload[:certificate] || payload["certificate"]

    detections = []

    # Check for suspicious SNI
    detections = if sni && is_suspicious_domain?(sni) do
      [%{
        type: :suspicious_sni,
        confidence: 0.6,
        description: "Connection to suspicious domain: #{sni}",
        mitre_techniques: ["T1071.001", "T1573"],
        metadata: %{sni: sni}
      } | detections]
    else
      detections
    end

    # JA3 fingerprint analysis is handled by C2Detector
    # Certificate analysis is handled by C2Detector

    {detections, state}
  end

  defp is_suspicious_domain?(domain) do
    suspicious_tlds = [".xyz", ".top", ".buzz", ".club", ".gq", ".cf", ".ga", ".ml", ".tk"]
    Enum.any?(suspicious_tlds, &String.ends_with?(domain, &1))
  end

  # --------------------------------------------------------------------------
  # SMB Analysis
  # --------------------------------------------------------------------------

  defp analyze_smb(event, state) do
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    remote_ip = payload[:remote_ip] || payload["remote_ip"]
    src_ip = payload[:local_ip] || payload["local_ip"] || payload[:source_ip] || payload["source_ip"]

    smb_command = payload[:smb_command] || payload["smb_command"]
    smb_share = payload[:smb_share] || payload["smb_share"]
    smb_file = payload[:smb_file] || payload["smb_file"]

    detections = []

    # Record SMB activity
    record_smb_activity(agent_id, %{
      src_ip: src_ip,
      dst_ip: remote_ip,
      command: smb_command,
      share: smb_share,
      file: smb_file,
      timestamp: DateTime.utc_now()
    })

    # Check for administrative share access
    admin_shares = ["C$", "ADMIN$", "IPC$", "PRINT$"]
    detections = if smb_share && String.upcase(smb_share) in admin_shares do
      [%{
        type: :admin_share_access,
        confidence: 0.7,
        description: "Administrative share accessed: #{smb_share} on #{remote_ip}",
        mitre_techniques: ["T1021.002", "T1077"],
        metadata: %{share: smb_share, target: remote_ip}
      } | detections]
    else
      detections
    end

    # Check for suspicious file operations
    suspicious_extensions = [".exe", ".dll", ".ps1", ".bat", ".vbs", ".js"]
    detections = if smb_file && Enum.any?(suspicious_extensions, &String.ends_with?(smb_file, &1)) do
      [%{
        type: :suspicious_smb_file,
        confidence: 0.65,
        description: "Suspicious file transferred via SMB: #{Path.basename(smb_file)}",
        mitre_techniques: ["T1021.002", "T1570"],
        metadata: %{file: smb_file, target: remote_ip}
      } | detections]
    else
      detections
    end

    new_state = update_stats(state, :smb_analyzed)
    {detections, new_state}
  end

  # --------------------------------------------------------------------------
  # RDP Analysis
  # --------------------------------------------------------------------------

  defp analyze_rdp(event, state) do
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    remote_ip = payload[:remote_ip] || payload["remote_ip"]
    src_ip = payload[:local_ip] || payload["local_ip"]
    direction = payload[:direction] || payload["direction"]
    process_name = payload[:process_name] || payload["process_name"] || payload[:name] || payload["name"]

    detections = []

    # Record RDP session
    session_key = {agent_id, src_ip, remote_ip}
    record_rdp_session(session_key, %{
      agent_id: agent_id,
      src_ip: src_ip,
      dst_ip: remote_ip,
      timestamp: DateTime.utc_now()
    })

    # Check for RDP from external IP
    detections = if remote_ip && not is_private_ip?(remote_ip) do
      [%{
        type: :external_rdp,
        confidence: 0.7,
        description: "RDP connection from external IP: #{remote_ip}",
        mitre_techniques: ["T1021.001", "T1133"],
        metadata: %{source_ip: remote_ip, target: src_ip}
      } | detections]
    else
      detections
    end

    # Check for unusual RDP hours (outside business hours)
    current_hour = DateTime.utc_now().hour
    detections = if current_hour < 6 or current_hour > 22 do
      [%{
        type: :off_hours_rdp,
        confidence: 0.5,
        description: "RDP connection during off-hours (#{current_hour}:00 UTC)",
        mitre_techniques: ["T1021.001"],
        metadata: %{hour: current_hour, source_ip: remote_ip}
      } | detections]
    else
      detections
    end

    new_state = update_stats(state, :rdp_sessions)
    {detections, new_state}
  end

  # --------------------------------------------------------------------------
  # SSH Analysis
  # --------------------------------------------------------------------------

  defp analyze_ssh(event, state) do
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    remote_ip = payload[:remote_ip] || payload["remote_ip"]
    src_ip = payload[:local_ip] || payload["local_ip"]
    direction = payload[:direction] || payload["direction"]
    process_name = payload[:process_name] || payload["process_name"] || payload[:name] || payload["name"]

    detections = []

    # Record SSH session
    session_key = {agent_id, src_ip, remote_ip}
    record_ssh_session(session_key, %{
      agent_id: agent_id,
      src_ip: src_ip,
      dst_ip: remote_ip,
      timestamp: DateTime.utc_now()
    })

    # Check for SSH from external IP (unusual for servers)
    detections = if external_ssh_alertable?(remote_ip, direction, process_name) do
      [%{
        type: :external_ssh,
        confidence: external_ssh_confidence(direction, process_name),
        description: external_ssh_description(remote_ip, direction, process_name),
        mitre_techniques: ["T1021.004", "T1133"],
        metadata: %{source_ip: remote_ip, direction: direction, process: process_name}
      } | detections]
    else
      detections
    end

    new_state = update_stats(state, :ssh_sessions)
    {detections, new_state}
  end

  # --------------------------------------------------------------------------
  # DNS Analysis
  # --------------------------------------------------------------------------

  defp analyze_dns(event, state) do
    # Delegate to the existing DNS Analyzer
    try do
      detections = DNSAnalyzer.analyze_dns_event(event)
      new_state = update_stats(state, :dns_analyzed)
      {detections, new_state}
    rescue
      _ -> {[], state}
    catch
      _, _ -> {[], state}
    end
  end

  # --------------------------------------------------------------------------
  # Insecure Protocol Analysis
  # --------------------------------------------------------------------------

  defp analyze_insecure_protocol(event, protocol, state) do
    payload = event[:payload] || event["payload"] || %{}
    remote_ip = payload[:remote_ip] || payload["remote_ip"]

    detections = [%{
      type: :insecure_protocol,
      confidence: 0.6,
      description: "Insecure protocol detected: #{protocol} to #{remote_ip}",
      mitre_techniques: ["T1040", "T1552"],
      metadata: %{protocol: protocol, target: remote_ip}
    }]

    {detections, state}
  end

  # --------------------------------------------------------------------------
  # Unknown Protocol Analysis
  # --------------------------------------------------------------------------

  defp analyze_unknown_protocol(event, port, state) do
    payload = event[:payload] || event["payload"] || %{}
    remote_ip = payload[:remote_ip] || payload["remote_ip"]

    detections = []

    # Check for high ports with significant traffic (potential C2)
    bytes = (payload[:bytes_sent] || payload["bytes_sent"] || 0) +
            (payload[:bytes_received] || payload["bytes_received"] || 0)

    detections = if port > 10000 and bytes > 100_000 do
      [%{
        type: :high_port_traffic,
        confidence: 0.5,
        description: "Significant traffic on high port #{port} to #{remote_ip}",
        mitre_techniques: ["T1571", "T1095"],
        metadata: %{port: port, bytes: bytes, target: remote_ip}
      } | detections]
    else
      detections
    end

    {detections, state}
  end

  # --------------------------------------------------------------------------
  # Protocol Tunneling Detection
  # --------------------------------------------------------------------------

  defp detect_tunneling(event, detected_protocol, port) do
    payload = event[:payload] || event["payload"] || %{}

    # Check if traffic on standard port doesn't match expected protocol
    expected_protocol = identify_protocol(port)

    if expected_protocol != :unknown and detected_protocol != expected_protocol do
      [%{
        type: :protocol_tunneling,
        confidence: 0.7,
        description: "Possible #{detected_protocol} tunneling over #{expected_protocol} port (#{port})",
        mitre_techniques: ["T1572", "T1090"],
        metadata: %{
          detected_protocol: detected_protocol,
          expected_protocol: expected_protocol,
          port: port
        }
      }]
    else
      []
    end
  end

  # ============================================================================
  # Data Recording Functions
  # ============================================================================

  defp record_http_request(agent_id, request) do
    :ets.insert(@http_requests_table, {agent_id, request})
  end

  defp record_smb_activity(agent_id, activity) do
    :ets.insert(@smb_activity_table, {agent_id, activity})
    persist_smb_activity(agent_id, activity)
  end

  defp record_rdp_session(session_key, session) do
    case :ets.lookup(@rdp_sessions_table, session_key) do
      [{^session_key, existing}] ->
        updated = %{existing |
          connection_count: existing.connection_count + 1,
          last_seen: session.timestamp
        }
        :ets.insert(@rdp_sessions_table, {session_key, updated})

      [] ->
        new_session = Map.merge(session, %{
          connection_count: 1,
          first_seen: session.timestamp,
          last_seen: session.timestamp
        })
        :ets.insert(@rdp_sessions_table, {session_key, new_session})
    end

    persist_remote_session(:rdp, session_key, session)
  end

  defp record_ssh_session(session_key, session) do
    case :ets.lookup(@ssh_sessions_table, session_key) do
      [{^session_key, existing}] ->
        updated = %{existing |
          connection_count: existing.connection_count + 1,
          last_seen: session.timestamp
        }
        :ets.insert(@ssh_sessions_table, {session_key, updated})

      [] ->
        new_session = Map.merge(session, %{
          connection_count: 1,
          first_seen: session.timestamp,
          last_seen: session.timestamp
        })
        :ets.insert(@ssh_sessions_table, {session_key, new_session})
    end

    persist_remote_session(:ssh, session_key, session)
  end

  defp update_protocol_stats(protocol, event) do
    payload = event[:payload] || event["payload"] || %{}
    bytes = (payload[:bytes_sent] || payload["bytes_sent"] || 0) +
            (payload[:bytes_received] || payload["bytes_received"] || 0)

    key = protocol

    case :ets.lookup(@protocol_stats_table, key) do
      [{^key, stats}] ->
        updated = %{stats |
          connection_count: stats.connection_count + 1,
          total_bytes: stats.total_bytes + bytes,
          last_seen: DateTime.utc_now()
        }
        :ets.insert(@protocol_stats_table, {key, updated})

      [] ->
        new_stats = %{
          protocol: protocol,
          connection_count: 1,
          total_bytes: bytes,
          first_seen: DateTime.utc_now(),
          last_seen: DateTime.utc_now()
        }
        :ets.insert(@protocol_stats_table, {key, new_stats})
    end

    persist_protocol_stats(protocol, event, bytes)
  end

  # ============================================================================
  # Query Functions
  # ============================================================================

  defp fetch_protocol_stats(opts) do
    live =
      :ets.tab2list(@protocol_stats_table)
      |> Enum.map(fn {_key, stats} -> stats end)

    persisted_protocol_stats(opts)
    |> merge_protocol_stats(live)
    |> Enum.sort_by(& &1.connection_count, :desc)
  end

  defp fetch_smb_activity(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    limit = Keyword.get(opts, :limit, 100)

    live =
      :ets.tab2list(@smb_activity_table)
      |> Enum.filter(fn {aid, _} -> is_nil(agent_id) or aid == agent_id end)
      |> Enum.map(fn {_, activity} -> activity end)

    persisted_smb_activity(agent_id, limit)
    |> merge_recent_observations(live, :timestamp, limit)
  end

  defp fetch_rdp_sessions(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    limit = Keyword.get(opts, :limit, 50)

    live =
      :ets.tab2list(@rdp_sessions_table)
      |> Enum.map(fn {_key, session} -> session end)
      |> Enum.filter(fn s -> is_nil(agent_id) or s.agent_id == agent_id end)

    persisted_remote_sessions(:rdp, agent_id, limit)
    |> merge_remote_sessions(live, limit)
  end

  defp fetch_ssh_sessions(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    limit = Keyword.get(opts, :limit, 50)

    live =
      :ets.tab2list(@ssh_sessions_table)
      |> Enum.map(fn {_key, session} -> session end)
      |> Enum.filter(fn s -> is_nil(agent_id) or s.agent_id == agent_id end)

    persisted_remote_sessions(:ssh, agent_id, limit)
    |> merge_remote_sessions(live, limit)
  end

  defp fetch_http_analysis(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    limit = Keyword.get(opts, :limit, 100)

    :ets.tab2list(@http_requests_table)
    |> Enum.filter(fn {aid, _} -> is_nil(agent_id) or aid == agent_id end)
    |> Enum.map(fn {_key, request} -> request end)
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(limit)
  end

  # ============================================================================
  # Persistence
  # ============================================================================

  defp persist_protocol_stats(protocol, event, bytes) do
    payload = event[:payload] || event["payload"] || %{}
    now = DateTime.utc_now() |> DateTime.truncate(:second) |> ensure_usec()
    agent_id = event[:agent_id] || event["agent_id"]
    organization_id =
      event[:organization_id] || event["organization_id"] || OrgLookup.get_org_id(agent_id)

    protocol_name = to_string(protocol)
    stats_key = Enum.join([organization_id || "global", agent_id || "global", protocol_name], ":")

    Repo.insert_all("ndr_protocol_stats", [
      %{
        id: Ecto.UUID.generate(),
        stats_key: stats_key,
        organization_id: dump_uuid(organization_id),
        agent_id: dump_uuid(agent_id),
        protocol: protocol_name,
        connection_count: 1,
        total_bytes: normalize_int(bytes),
        first_seen: now,
        last_seen: now,
        metadata: %{
          "remote_port" =>
            payload[:remote_port] || payload["remote_port"] || payload[:dest_port] ||
              payload["dest_port"]
        },
        inserted_at: now,
        updated_at: now
      }
    ],
      on_conflict: [
        inc: [connection_count: 1, total_bytes: normalize_int(bytes)],
        set: [last_seen: now, updated_at: now]
      ],
      conflict_target: [:stats_key]
    )
  rescue
    e -> Logger.debug("NDR protocol stats persistence unavailable: #{Exception.message(e)}")
  end

  defp persist_smb_activity(agent_id, activity) do
    now = DateTime.utc_now() |> DateTime.truncate(:second) |> ensure_usec()
    organization_id = OrgLookup.get_org_id(agent_id)

    Repo.insert_all("ndr_protocol_observations", [
      %{
        id: Ecto.UUID.generate(),
        observation_type: "smb_activity",
        observation_key: Ecto.UUID.generate(),
        organization_id: dump_uuid(organization_id),
        agent_id: dump_uuid(agent_id),
        src_ip: activity[:src_ip],
        dst_ip: activity[:dst_ip],
        command: activity[:command],
        share: activity[:share],
        file: activity[:file],
        connection_count: 1,
        first_seen: ensure_usec(activity[:timestamp] || now),
        last_seen: ensure_usec(activity[:timestamp] || now),
        metadata: %{},
        inserted_at: now,
        updated_at: now
      }
    ])
  rescue
    e -> Logger.debug("NDR SMB persistence unavailable: #{Exception.message(e)}")
  end

  defp persist_remote_session(type, {agent_id, src_ip, dst_ip}, session) do
    now = DateTime.utc_now() |> DateTime.truncate(:second) |> ensure_usec()
    organization_id = OrgLookup.get_org_id(agent_id)
    observation_type = "#{type}_session"

    observation_key =
      Enum.join(
        [observation_type, agent_id || "unknown", src_ip || "unknown", dst_ip || "unknown"],
        ":"
      )

    Repo.insert_all("ndr_protocol_observations", [
      %{
        id: Ecto.UUID.generate(),
        observation_type: observation_type,
        observation_key: observation_key,
        organization_id: dump_uuid(organization_id),
        agent_id: dump_uuid(agent_id),
        src_ip: src_ip,
        dst_ip: dst_ip,
        connection_count: 1,
        first_seen: ensure_usec(session[:timestamp] || now),
        last_seen: ensure_usec(session[:timestamp] || now),
        metadata: %{},
        inserted_at: now,
        updated_at: now
      }
    ],
      on_conflict: [
        inc: [connection_count: 1],
        set: [last_seen: ensure_usec(session[:timestamp] || now), updated_at: now]
      ],
      conflict_target: [:observation_key]
    )
  rescue
    e -> Logger.debug("NDR #{type} persistence unavailable: #{Exception.message(e)}")
  end

  defp persisted_protocol_stats(opts) do
    agent_id = Keyword.get(opts, :agent_id)

    query =
      from(s in "ndr_protocol_stats",
        group_by: field(s, :protocol),
        order_by: [desc: sum(field(s, :connection_count))],
        select: %{
          protocol: field(s, :protocol),
          connection_count: sum(field(s, :connection_count)),
          total_bytes: sum(field(s, :total_bytes)),
          first_seen: min(field(s, :first_seen)),
          last_seen: max(field(s, :last_seen))
        }
      )

    query =
      if is_nil(agent_id) do
        query
      else
        from(s in query, where: field(s, :agent_id) == ^dump_uuid(agent_id))
      end

    Repo.all(query)
    |> Enum.map(&normalize_protocol_stat/1)
  rescue
    _ -> []
  end

  defp persisted_smb_activity(agent_id, limit) do
    persisted_observations("smb_activity", agent_id, limit)
    |> Enum.map(fn row ->
      %{
        src_ip: row.src_ip,
        dst_ip: row.dst_ip,
        command: row.command,
        share: row.share,
        file: row.file,
        timestamp: row.last_seen
      }
    end)
  end

  defp persisted_remote_sessions(type, agent_id, limit) do
    persisted_observations("#{type}_session", agent_id, limit)
    |> Enum.map(fn row ->
      %{
        agent_id: load_uuid(row.agent_id),
        src_ip: row.src_ip,
        dst_ip: row.dst_ip,
        connection_count: row.connection_count,
        first_seen: row.first_seen,
        last_seen: row.last_seen
      }
    end)
  end

  defp persisted_observations(type, agent_id, limit) do
    query =
      from(o in "ndr_protocol_observations",
        where: field(o, :observation_type) == ^type,
        order_by: [desc: field(o, :last_seen)],
        limit: ^limit,
        select: %{
          agent_id: field(o, :agent_id),
          src_ip: field(o, :src_ip),
          dst_ip: field(o, :dst_ip),
          command: field(o, :command),
          share: field(o, :share),
          file: field(o, :file),
          connection_count: field(o, :connection_count),
          first_seen: field(o, :first_seen),
          last_seen: field(o, :last_seen)
        }
      )

    query =
      if is_nil(agent_id) do
        query
      else
        from(o in query, where: field(o, :agent_id) == ^dump_uuid(agent_id))
      end

    Repo.all(query)
  rescue
    _ -> []
  end

  defp merge_protocol_stats(persisted, live) do
    Enum.reduce(persisted ++ live, %{}, fn stats, acc ->
      protocol = normalize_protocol_name(stats[:protocol])

      Map.update(acc, protocol, %{stats | protocol: protocol}, fn existing ->
        %{
          protocol: protocol,
          connection_count: max(existing[:connection_count] || 0, stats[:connection_count] || 0),
          total_bytes: max(existing[:total_bytes] || 0, stats[:total_bytes] || 0),
          first_seen: min_datetime(existing[:first_seen], stats[:first_seen]),
          last_seen: max_datetime(existing[:last_seen], stats[:last_seen])
        }
      end)
    end)
    |> Map.values()
  end

  defp merge_recent_observations(persisted, live, timestamp_field, limit) do
    (persisted ++ live)
    |> Enum.uniq_by(fn item ->
      {item[:src_ip], item[:dst_ip], item[:command], item[:share], item[:file], item[timestamp_field]}
    end)
    |> Enum.sort_by(& &1[timestamp_field], {:desc, DateTime})
    |> Enum.take(limit)
  end

  defp merge_remote_sessions(persisted, live, limit) do
    Enum.reduce(persisted ++ live, %{}, fn session, acc ->
      key = {session[:agent_id], session[:src_ip], session[:dst_ip]}

      Map.update(acc, key, session, fn existing ->
        %{
          agent_id: session[:agent_id] || existing[:agent_id],
          src_ip: session[:src_ip] || existing[:src_ip],
          dst_ip: session[:dst_ip] || existing[:dst_ip],
          connection_count: max(existing[:connection_count] || 0, session[:connection_count] || 0),
          first_seen: min_datetime(existing[:first_seen], session[:first_seen]),
          last_seen: max_datetime(existing[:last_seen], session[:last_seen])
        }
      end)
    end)
    |> Map.values()
    |> Enum.sort_by(& &1.last_seen, {:desc, DateTime})
    |> Enum.take(limit)
  end

  # ============================================================================
  # Alert Creation
  # ============================================================================

  defp create_protocol_alert(event, detection) do
    agent_id = event[:agent_id] || event["agent_id"]

    severity = case detection.confidence do
      c when c >= 0.8 -> "high"
      c when c >= 0.6 -> "medium"
      _ -> "low"
    end

    title = case detection.type do
      :suspicious_user_agent -> "NDR: Suspicious HTTP User-Agent"
      :suspicious_http_path -> "NDR: Suspicious HTTP Path Access"
      :admin_share_access -> "NDR: Administrative Share Access"
      :suspicious_smb_file -> "NDR: Suspicious SMB File Transfer"
      :external_rdp -> "NDR: External RDP Connection"
      :external_ssh -> "NDR: External SSH Connection"
      :protocol_tunneling -> "NDR: Protocol Tunneling Detected"
      :insecure_protocol -> "NDR: Insecure Protocol Usage"
      _ -> "NDR: Protocol Anomaly"
    end

    case Alerts.create_alert(%{
           agent_id: agent_id,
           organization_id: event[:organization_id] || OrgLookup.get_org_id(agent_id),
           severity: severity,
           title: title,
           description: detection.description,
           source_event_id: EventNormalizer.source_event_uuid(event),
           event_ids: EventNormalizer.source_event_ids(event),
           evidence: EventNormalizer.alert_evidence(event, detection, :protocol_metadata),
           raw_event: event,
           detection_metadata: detection.metadata || %{},
           mitre_tactics: ["lateral-movement", "command-and-control"],
           mitre_techniques: detection.mitre_techniques || [],
           threat_score: detection.confidence
         }) do
      {:ok, _alert} ->
        :ok

      {:error, reason} ->
        Logger.warning("Failed to create protocol alert (#{detection.type}): #{inspect(reason)}")
        :error
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp is_private_ip?(ip), do: IP.internal?(ip)

  defp external_ssh_alertable?(remote_ip, direction, process_name) do
    remote_ip && not is_private_ip?(remote_ip) &&
      not benign_outbound_ssh?(direction, process_name)
  end

  defp benign_outbound_ssh?(direction, process_name) do
    to_string(direction) == "outbound" &&
      normalize_process_name(process_name) in ["ssh", "ssh.exe", "plink", "plink.exe"]
  end

  defp external_ssh_confidence(direction, process_name) do
    if to_string(direction) == "inbound" or not benign_outbound_ssh?(direction, process_name), do: 0.7, else: 0.4
  end

  defp external_ssh_description(remote_ip, "inbound", _process_name), do: "Inbound SSH connection from external IP: #{remote_ip}"
  defp external_ssh_description(remote_ip, direction, process_name) do
    "External SSH connection #{direction || "unknown direction"} with #{process_name || "unknown process"} to #{remote_ip}"
  end

  defp normalize_process_name(nil), do: ""
  defp normalize_process_name(process_name) do
    process_name
    |> to_string()
    |> String.replace("\\", "/")
    |> Path.basename()
    |> String.downcase()
  end

  defp normalize_protocol_stat(stats) do
    %{stats | protocol: normalize_protocol_name(stats[:protocol])}
  end

  defp normalize_protocol_name(protocol) when is_atom(protocol), do: protocol

  defp normalize_protocol_name("http"), do: :http
  defp normalize_protocol_name("https"), do: :https
  defp normalize_protocol_name("smb"), do: :smb
  defp normalize_protocol_name("rdp"), do: :rdp
  defp normalize_protocol_name("ssh"), do: :ssh
  defp normalize_protocol_name("dns"), do: :dns
  defp normalize_protocol_name("ftp"), do: :ftp
  defp normalize_protocol_name("telnet"), do: :telnet
  defp normalize_protocol_name("mysql"), do: :mysql
  defp normalize_protocol_name("mssql"), do: :mssql
  defp normalize_protocol_name("postgres"), do: :postgres
  defp normalize_protocol_name("ldap"), do: :ldap
  defp normalize_protocol_name("unknown"), do: :unknown

  defp normalize_protocol_name(_), do: :unknown

  defp ensure_usec(%DateTime{microsecond: {value, precision}} = dt) when precision < 6 do
    %{dt | microsecond: {value, 6}}
  end

  defp ensure_usec(%DateTime{} = dt), do: dt
  defp ensure_usec(_), do: DateTime.utc_now() |> DateTime.truncate(:second) |> ensure_usec()

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

  defp normalize_int(value) when is_integer(value), do: value

  defp normalize_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, _} -> parsed
      :error -> 0
    end
  end

  defp normalize_int(value) when is_float(value), do: trunc(value)
  defp normalize_int(_), do: 0

  defp min_datetime(nil, value), do: value
  defp min_datetime(value, nil), do: value

  defp min_datetime(%DateTime{} = a, %DateTime{} = b) do
    if DateTime.compare(a, b) == :gt, do: b, else: a
  end

  defp min_datetime(a, _b), do: a

  defp max_datetime(nil, value), do: value
  defp max_datetime(value, nil), do: value

  defp max_datetime(%DateTime{} = a, %DateTime{} = b) do
    if DateTime.compare(a, b) == :lt, do: b, else: a
  end

  defp max_datetime(a, _b), do: a

  defp update_stats(state, key) do
    %{state | stats: Map.update(state.stats, key, 1, &(&1 + 1))}
  end

  defp cleanup_old_data do
    cutoff = DateTime.utc_now() |> DateTime.add(-3600, :second)  # 1 hour

    # Clean HTTP requests
    :ets.tab2list(@http_requests_table)
    |> Enum.each(fn {key, request} ->
      if DateTime.compare(request.timestamp, cutoff) == :lt do
        :ets.delete_object(@http_requests_table, {key, request})
      end
    end)

    # Clean SMB activity
    :ets.tab2list(@smb_activity_table)
    |> Enum.each(fn {key, activity} ->
      if DateTime.compare(activity.timestamp, cutoff) == :lt do
        :ets.delete_object(@smb_activity_table, {key, activity})
      end
    end)

    Logger.debug("NDR Protocol Analyzer cleanup completed")
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, :timer.minutes(5))
  end
end
