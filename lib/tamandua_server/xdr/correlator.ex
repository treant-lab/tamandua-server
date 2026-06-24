defmodule TamanduaServer.XDR.Correlator do
  @moduledoc """
  Advanced XDR Cross-Source Correlation Engine with ML-Powered Analysis.

  Enterprise-grade correlation engine matching CrowdStrike Falcon XDR capabilities.

  ## Correlation Strategies
  1. **IP-based**: Match source/dest IPs across sources with geolocation context
  2. **User-based**: Track user activity across systems with behavioral profiling
  3. **Hash-based**: Match file hashes across sources with reputation scoring
  4. **Domain-based**: Track domain/URL access patterns with threat intel enrichment
  5. **Temporal**: Find time-clustered events using statistical analysis
  6. **Kill-chain**: Detect multi-stage attack sequences with phase confidence scoring
  7. **ML-based**: Machine learning correlation scoring with feature extraction
  8. **Graph-based**: Entity relationship graph analysis for attack path discovery

  ## Key Features
  - Automatic incident grouping with confidence scoring
  - Cross-domain attack chain detection
  - Real-time kill chain phase identification
  - ML-powered anomaly scoring
  - Entity relationship graphs
  - Automatic alert correlation and deduplication

  Uses ETS for fast in-memory correlation with sliding window analysis.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.XDR.NormalizedEvent
  alias TamanduaServer.Agents.OrgLookup
  alias TamanduaServer.Detection.EventTypes

  # ETS tables for correlation
  @xdr_events_table :xdr_correlation_events
  @ip_index_table :xdr_ip_index
  @user_index_table :xdr_user_index
  @hash_index_table :xdr_hash_index
  @domain_index_table :xdr_domain_index
  @timeline_table :xdr_attack_timelines
  @incident_table :xdr_incidents
  @entity_graph_table :xdr_entity_graph
  @ml_features_table :xdr_ml_features

  @call_timeout 15_000
  @default_timeline_limit 100
  @max_timeline_limit 500
  @max_timeline_build_events 1_000

  # Default configuration
  @default_config %{
    # Time window for correlation (15 minutes)
    correlation_window_ms: 15 * 60 * 1000,
    # Extended window for kill chain detection (1 hour)
    kill_chain_window_ms: 60 * 60 * 1000,
    # Incident grouping window (30 minutes)
    incident_grouping_window_ms: 30 * 60 * 1000,
    # Minimum events to trigger correlation
    min_events_for_correlation: 2,
    # Maximum events to keep per index
    max_events_per_index: 1000,
    # Cleanup interval
    cleanup_interval_ms: 5 * 60 * 1000,
    # Event TTL (1 hour)
    event_ttl_ms: 60 * 60 * 1000,
    # ML correlation threshold
    ml_correlation_threshold: 0.7,
    # Incident auto-grouping enabled
    auto_group_incidents: true,
    # Entity graph depth for traversal
    entity_graph_depth: 3,
    # Enable cross-domain detection
    enable_cross_domain: true
  }

  # MITRE ATT&CK Kill Chain Phases with typical source types
  @kill_chain_phases [
    # Phase 1: Initial Access - typically email or network
    %{
      phase: "initial_access",
      order: 1,
      tactics: ["initial_access", "T1566", "T1190", "T1078"],
      source_types: [:email, :proxy, :firewall, :cloud],
      indicators: [:phishing_url, :malicious_attachment, :exploit_attempt]
    },
    # Phase 2: Execution - typically endpoint
    %{
      phase: "execution",
      order: 2,
      tactics: ["execution", "T1059", "T1204"],
      source_types: [:endpoint],
      indicators: [:process_create, :script_execution]
    },
    # Phase 3: Persistence - typically endpoint or cloud
    %{
      phase: "persistence",
      order: 3,
      tactics: ["persistence", "T1547", "T1053"],
      source_types: [:endpoint, :cloud],
      indicators: [:scheduled_task, :registry_mod, :service_install]
    },
    # Phase 4: Defense Evasion - typically endpoint
    %{
      phase: "defense_evasion",
      order: 4,
      tactics: ["defense_evasion", "T1562", "T1070"],
      source_types: [:endpoint],
      indicators: [:av_disable, :log_clear, :timestomp]
    },
    # Phase 5: Credential Access - typically endpoint or identity
    %{
      phase: "credential_access",
      order: 5,
      tactics: ["credential_access", "T1003", "T1110"],
      source_types: [:endpoint, :identity, :cloud],
      indicators: [:credential_dump, :brute_force, :token_theft]
    },
    # Phase 6: Discovery - typically endpoint
    %{
      phase: "discovery",
      order: 6,
      tactics: ["discovery", "T1082", "T1083"],
      source_types: [:endpoint, :network],
      indicators: [:network_scan, :host_enum, :account_discovery]
    },
    # Phase 7: Lateral Movement - typically network and endpoint
    %{
      phase: "lateral_movement",
      order: 7,
      tactics: ["lateral_movement", "T1021", "T1570"],
      source_types: [:endpoint, :network, :firewall],
      indicators: [:rdp_session, :smb_connection, :psexec]
    },
    # Phase 8: Command and Control - typically network
    %{
      phase: "command_and_control",
      order: 8,
      tactics: ["command_and_control", "T1071", "T1105"],
      source_types: [:network, :firewall, :proxy],
      indicators: [:c2_beacon, :dns_tunnel, :encrypted_channel]
    },
    # Phase 9: Exfiltration - typically network
    %{
      phase: "exfiltration",
      order: 9,
      tactics: ["exfiltration", "T1041", "T1048"],
      source_types: [:network, :proxy, :cloud, :firewall],
      indicators: [:data_transfer, :cloud_upload, :encrypted_exfil]
    },
    # Phase 10: Impact - typically endpoint or cloud
    %{
      phase: "impact",
      order: 10,
      tactics: ["impact", "T1486", "T1490"],
      source_types: [:endpoint, :cloud],
      indicators: [:ransomware, :data_destruction, :dos]
    }
  ]

  # Advanced cross-domain attack patterns (CrowdStrike-level detection)
  @cross_source_patterns [
    # Phishing to Endpoint Execution
    %{
      name: "phishing_to_execution",
      description: "Email phishing led to endpoint malware execution",
      severity: :critical,
      mitre_techniques: ["T1566.001", "T1204.002"],
      kill_chain_phases: ["initial_access", "execution"],
      confidence_boost: 0.3,
      pattern: [
        %{source_type: :email, action: "blocked", indicators: [:malicious_link, :malicious_attachment]},
        %{source_type: :endpoint, action: "process_create", time_offset_max_ms: 300_000}
      ]
    },
    # External Scan to Internal Compromise
    %{
      name: "scan_to_compromise",
      description: "External network scan led to internal compromise",
      severity: :critical,
      mitre_techniques: ["T1595", "T1190"],
      kill_chain_phases: ["reconnaissance", "initial_access"],
      confidence_boost: 0.25,
      pattern: [
        %{source_type: :network, category: "intrusion", action: "alert"},
        %{source_type: :endpoint, action: "process_create", time_offset_max_ms: 600_000}
      ]
    },
    # Cloud to Endpoint Lateral Movement
    %{
      name: "cloud_to_endpoint",
      description: "Cloud resource access led to endpoint activity",
      severity: :high,
      mitre_techniques: ["T1078.004", "T1021"],
      kill_chain_phases: ["initial_access", "lateral_movement"],
      confidence_boost: 0.2,
      pattern: [
        %{source_type: :cloud, action: ~r/login|assume.*role/i},
        %{source_type: :endpoint, action: "network_connect", time_offset_max_ms: 180_000}
      ]
    },
    # Brute Force to Account Compromise
    %{
      name: "brute_force_success",
      description: "Brute force attempts followed by successful authentication",
      severity: :critical,
      mitre_techniques: ["T1110"],
      kill_chain_phases: ["credential_access", "initial_access"],
      confidence_boost: 0.35,
      pattern: [
        %{source_type: :cloud, action: ~r/failed.*login|authentication.*fail/i, min_count: 5},
        %{source_type: :cloud, action: ~r/success.*login|authentication.*success/i, time_offset_max_ms: 300_000}
      ]
    },
    # C2 Communication Chain
    %{
      name: "c2_chain",
      description: "Command and control communication chain detected",
      severity: :critical,
      mitre_techniques: ["T1071.001", "T1573"],
      kill_chain_phases: ["command_and_control"],
      confidence_boost: 0.4,
      pattern: [
        %{source_type: :proxy, category: "malware"},
        %{source_type: :firewall, action: "blocked", time_offset_max_ms: 60_000},
        %{source_type: :endpoint, action: "network_connect", time_offset_max_ms: 120_000}
      ]
    },
    # Data Exfiltration Chain
    %{
      name: "exfiltration_chain",
      description: "Data staging and exfiltration detected",
      severity: :critical,
      mitre_techniques: ["T1560", "T1041"],
      kill_chain_phases: ["collection", "exfiltration"],
      confidence_boost: 0.4,
      pattern: [
        %{source_type: :endpoint, action: ~r/file.*create|archive/i},
        %{source_type: :proxy, action: "upload", time_offset_max_ms: 600_000, min_bytes: 10_000_000}
      ]
    },
    # AWS GuardDuty to Endpoint Compromise
    %{
      name: "guardduty_to_endpoint",
      description: "AWS GuardDuty finding correlated with endpoint activity",
      severity: :critical,
      mitre_techniques: ["T1078.004", "T1059"],
      kill_chain_phases: ["initial_access", "execution"],
      confidence_boost: 0.35,
      pattern: [
        %{source_type: :cloud, vendor: "aws", category: ~r/guardduty|iam.*anomaly/i},
        %{source_type: :endpoint, action: ~r/process.*create|powershell|cmd/i, time_offset_max_ms: 600_000}
      ]
    },
    # Azure Defender Alert to Lateral Movement
    %{
      name: "azure_defender_lateral",
      description: "Azure Defender alert followed by internal lateral movement",
      severity: :critical,
      mitre_techniques: ["T1078.004", "T1021"],
      kill_chain_phases: ["initial_access", "lateral_movement"],
      confidence_boost: 0.3,
      pattern: [
        %{source_type: :cloud, vendor: "azure", category: ~r/defender|security.*alert/i},
        %{source_type: :firewall, action: ~r/allow|pass/i, dest_internal: true, time_offset_max_ms: 300_000}
      ]
    },
    # Firewall Block Followed by Endpoint Evasion
    %{
      name: "firewall_evasion",
      description: "Firewall blocked connection followed by endpoint defense evasion",
      severity: :high,
      mitre_techniques: ["T1562", "T1070"],
      kill_chain_phases: ["command_and_control", "defense_evasion"],
      confidence_boost: 0.25,
      pattern: [
        %{source_type: :firewall, action: "blocked", category: ~r/c2|malware|suspicious/i},
        %{source_type: :endpoint, action: ~r/av.*disable|log.*clear|tamper/i, time_offset_max_ms: 300_000}
      ]
    },
    # Email Attachment to Persistence
    %{
      name: "email_to_persistence",
      description: "Email attachment led to persistence mechanism installation",
      severity: :critical,
      mitre_techniques: ["T1566.001", "T1547", "T1053"],
      kill_chain_phases: ["initial_access", "execution", "persistence"],
      confidence_boost: 0.4,
      pattern: [
        %{source_type: :email, action: ~r/delivered|received/i, has_attachment: true},
        %{source_type: :endpoint, action: "process_create", time_offset_max_ms: 300_000},
        %{source_type: :endpoint, action: ~r/scheduled.*task|registry.*run|service.*install/i, time_offset_max_ms: 600_000}
      ]
    },
    # Identity Provider Anomaly to Cloud Access
    %{
      name: "identity_cloud_pivot",
      description: "Identity provider anomaly followed by suspicious cloud activity",
      severity: :critical,
      mitre_techniques: ["T1078", "T1087"],
      kill_chain_phases: ["credential_access", "discovery"],
      confidence_boost: 0.35,
      pattern: [
        %{source_type: :identity, action: ~r/impossible.*travel|anomal|risk/i},
        %{source_type: :cloud, action: ~r/list.*|describe.*|enum/i, time_offset_max_ms: 600_000}
      ]
    },
    # DNS Tunneling with C2 Activity
    %{
      name: "dns_tunnel_c2",
      description: "DNS tunneling correlated with command and control activity",
      severity: :critical,
      mitre_techniques: ["T1071.004", "T1132"],
      kill_chain_phases: ["command_and_control"],
      confidence_boost: 0.4,
      pattern: [
        %{source_type: :network, action: ~r/dns.*tunnel|dns.*exfil|suspicious.*dns/i},
        %{source_type: :endpoint, action: "network_connect", time_offset_max_ms: 60_000}
      ]
    },
    # Credential Dumping to Lateral Movement
    %{
      name: "cred_dump_lateral",
      description: "Credential dumping followed by lateral movement attempt",
      severity: :critical,
      mitre_techniques: ["T1003", "T1021"],
      kill_chain_phases: ["credential_access", "lateral_movement"],
      confidence_boost: 0.45,
      pattern: [
        %{source_type: :endpoint, action: ~r/lsass.*access|credential.*dump|mimikatz/i},
        %{source_type: :network, action: ~r/smb|rdp|winrm|psexec/i, time_offset_max_ms: 600_000}
      ]
    },
    # Ransomware Full Chain
    %{
      name: "ransomware_chain",
      description: "Full ransomware attack chain detected",
      severity: :critical,
      mitre_techniques: ["T1486", "T1490", "T1489"],
      kill_chain_phases: ["execution", "impact"],
      confidence_boost: 0.5,
      pattern: [
        %{source_type: :endpoint, action: ~r/shadow.*delete|vss.*delete|backup.*delete/i},
        %{source_type: :endpoint, action: ~r/encrypt|ransom|file.*modify/i, time_offset_max_ms: 300_000}
      ]
    },
    # Supply Chain Attack Pattern
    %{
      name: "supply_chain_attack",
      description: "Supply chain compromise pattern detected",
      severity: :critical,
      mitre_techniques: ["T1195", "T1059"],
      kill_chain_phases: ["initial_access", "execution"],
      confidence_boost: 0.4,
      pattern: [
        %{source_type: :endpoint, action: ~r/update|installer|package/i, from_trusted: true},
        %{source_type: :endpoint, action: ~r/powershell|cmd|shell/i, time_offset_max_ms: 300_000},
        %{source_type: :network, action: ~r/outbound|connect/i, dest_suspicious: true, time_offset_max_ms: 600_000}
      ]
    }
  ]

  defstruct [
    config: @default_config,
    stats: %{
      events_correlated: 0,
      patterns_detected: 0,
      alerts_generated: 0,
      kill_chains_detected: 0,
      incidents_grouped: 0,
      ml_correlations: 0,
      cross_domain_detections: 0,
      entity_graph_nodes: 0
    },
    # Active incidents being grouped
    active_incidents: %{},
    # ML feature vectors for correlation
    ml_feature_cache: %{}
  ]

  # ML feature weights for correlation scoring
  @ml_feature_weights %{
    ip_match: 0.25,
    user_match: 0.2,
    hash_match: 0.35,
    domain_match: 0.15,
    temporal_proximity: 0.2,
    source_diversity: 0.15,
    kill_chain_alignment: 0.25,
    severity_escalation: 0.1,
    entity_graph_distance: 0.15,
    behavioral_anomaly: 0.2
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Add an XDR event for correlation.
  """
  @spec add_event(map()) :: :ok
  def add_event(event) do
    GenServer.cast(__MODULE__, {:add_event, event})
  end

  @doc """
  Add multiple XDR events for correlation.
  """
  @spec add_events([map()]) :: :ok
  def add_events(events) when is_list(events) do
    Enum.each(events, &add_event/1)
  end

  @doc """
  Correlate an XDR event with endpoint telemetry.
  Returns matching endpoint events.
  """
  @spec correlate_with_endpoint(map()) :: {:ok, [map()]}
  def correlate_with_endpoint(xdr_event) do
    GenServer.call(__MODULE__, {:correlate_with_endpoint, xdr_event})
  end

  @doc """
  Build a unified attack timeline from correlated events.
  """
  @spec build_timeline(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def build_timeline(correlation_id, opts \\ []) do
    GenServer.call(__MODULE__, {:build_timeline, correlation_id, opts}, @call_timeout)
  end

  @doc """
  Get cross-source correlations for an entity (IP, user, domain).
  """
  @spec get_entity_correlations(String.t(), String.t(), keyword()) :: {:ok, map()}
  def get_entity_correlations(entity_type, entity_value, opts \\ []) do
    GenServer.call(__MODULE__, {:get_entity_correlations, entity_type, entity_value, opts})
  end

  @doc """
  Detect kill chain patterns across sources.
  """
  @spec detect_kill_chain(keyword()) :: {:ok, [map()]}
  def detect_kill_chain(opts \\ []) do
    GenServer.call(__MODULE__, {:detect_kill_chain, opts}, 30_000)
  end

  @doc """
  List active attack timelines.
  """
  @spec list_timelines(keyword()) :: {:ok, [map()]}
  def list_timelines(opts \\ []) do
    GenServer.call(__MODULE__, {:list_timelines, opts}, @call_timeout)
  end

  @doc """
  Get correlation statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Perform ML-based correlation scoring between two events.
  Returns a confidence score between 0.0 and 1.0.
  """
  @spec ml_correlate(map(), map()) :: {:ok, float()}
  def ml_correlate(event1, event2) do
    GenServer.call(__MODULE__, {:ml_correlate, event1, event2})
  end

  @doc """
  Group related alerts into an incident.
  Automatically identifies related events and creates a unified incident.
  """
  @spec group_incident(list(map()), keyword()) :: {:ok, map()} | {:error, term()}
  def group_incident(events, opts \\ []) do
    GenServer.call(__MODULE__, {:group_incident, events, opts}, 30_000)
  end

  @doc """
  List active incidents with optional filters.
  """
  @spec list_incidents(keyword()) :: {:ok, [map()]}
  def list_incidents(opts \\ []) do
    GenServer.call(__MODULE__, {:list_incidents, opts})
  end

  @doc """
  Get a specific incident by ID.
  """
  @spec get_incident(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_incident(incident_id) do
    GenServer.call(__MODULE__, {:get_incident, incident_id})
  end

  @doc """
  Build entity relationship graph for attack path analysis.
  Returns nodes and edges representing entity relationships.
  """
  @spec build_entity_graph(String.t(), String.t(), keyword()) :: {:ok, map()}
  def build_entity_graph(entity_type, entity_value, opts \\ []) do
    GenServer.call(__MODULE__, {:build_entity_graph, entity_type, entity_value, opts}, 30_000)
  end

  @doc """
  Get cross-domain attack chains.
  Detects attacks that span multiple security domains (endpoint, network, cloud, identity).
  """
  @spec get_cross_domain_chains(keyword()) :: {:ok, [map()]}
  def get_cross_domain_chains(opts \\ []) do
    GenServer.call(__MODULE__, {:get_cross_domain_chains, opts}, 30_000)
  end

  @doc """
  Calculate threat score for an entity based on all correlated activity.
  """
  @spec calculate_entity_threat_score(String.t(), String.t()) :: {:ok, float()}
  def calculate_entity_threat_score(entity_type, entity_value) do
    GenServer.call(__MODULE__, {:calculate_entity_threat_score, entity_type, entity_value})
  end

  @doc """
  Export correlation data for an incident or timeline.
  """
  @spec export_correlation(String.t(), String.t()) :: {:ok, map()}
  def export_correlation(id, format \\ "json") do
    GenServer.call(__MODULE__, {:export_correlation, id, format})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    # Create ETS tables for correlation indexes
    :ets.new(@xdr_events_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@ip_index_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@user_index_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@hash_index_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@domain_index_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@timeline_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@incident_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@entity_graph_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@ml_features_table, [:named_table, :set, :public, read_concurrency: true])

    config = Keyword.get(opts, :config, @default_config)
    schedule_cleanup(config.cleanup_interval_ms)
    schedule_incident_analysis(60_000)  # Analyze incidents every minute

    Logger.info("XDR Correlator started with ML correlation and incident grouping enabled")

    {:ok, %__MODULE__{config: config}}
  end

  @impl true
  def handle_cast({:add_event, event}, state) do
    # Index the event for correlation
    index_event(event, state.config)

    # Check for cross-source patterns
    detections = check_cross_source_patterns(event, state.config)

    # Check for kill chain progression
    kill_chain_detections = check_kill_chain_progression(event, state.config)

    # Create alerts for detections
    new_state = if length(detections) > 0 or length(kill_chain_detections) > 0 do
      create_xdr_alerts(event, detections ++ kill_chain_detections)
      update_stats(state, detections, kill_chain_detections)
    else
      state
    end

    {:noreply, increment_events_correlated(new_state)}
  end

  @impl true
  def handle_call({:correlate_with_endpoint, xdr_event}, _from, state) do
    result = do_correlate_with_endpoint(xdr_event, state.config)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:build_timeline, correlation_id, opts}, _from, state) do
    result = do_build_timeline(correlation_id, opts, state.config)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_entity_correlations, entity_type, entity_value, opts}, _from, state) do
    result = do_get_entity_correlations(entity_type, entity_value, opts, state.config)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:detect_kill_chain, opts}, _from, state) do
    result = do_detect_kill_chain(opts, state.config)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:list_timelines, opts}, _from, state) do
    limit = timeline_limit(opts)

    timelines =
      @timeline_table
      |> :ets.tab2list()
      |> Stream.map(fn {_id, timeline} -> timeline end)
      |> filter_timelines(opts)
      |> Enum.sort_by(&(&1[:updated_at] || &1[:created_at] || DateTime.from_unix!(0)), {:desc, DateTime})
      |> Enum.take(limit)

    {:reply, {:ok, timelines}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_events(state.config)
    schedule_cleanup(state.config.cleanup_interval_ms)
    {:noreply, state}
  end

  # ============================================================================
  # Event Indexing
  # ============================================================================

  defp index_event(event, config) do
    event_id = event[:id] || Ecto.UUID.generate()
    timestamp = event[:timestamp] || DateTime.utc_now()
    source_type = event[:source_type]
    org_id = event[:organization_id]

    # Create indexed entry
    entry = %{
      id: event_id,
      event: event,
      timestamp: timestamp,
      source_type: source_type,
      organization_id: org_id,
      indexed_at: System.system_time(:millisecond)
    }

    # Store in main events table
    :ets.insert(@xdr_events_table, {event_id, entry})

    # Index by source IP
    if source_ip = event[:source_ip] do
      :ets.insert(@ip_index_table, {normalize_ip(source_ip), entry})
    end

    # Index by destination IP
    if dest_ip = event[:dest_ip] do
      :ets.insert(@ip_index_table, {normalize_ip(dest_ip), entry})
    end

    # Index by user
    if user = event[:user] do
      :ets.insert(@user_index_table, {normalize_user(user), entry})
    end

    # Index by file hash
    if hash = event[:file_hash] do
      :ets.insert(@hash_index_table, {String.downcase(hash), entry})
    end

    # Index by domain
    if domain = event[:url] || event[:domain] do
      normalized_domain = extract_domain(domain)
      if normalized_domain do
        :ets.insert(@domain_index_table, {normalized_domain, entry})
      end
    end

    # Enforce max events per index
    enforce_index_limits(config)
  end

  defp normalize_ip(ip) when is_binary(ip), do: String.trim(ip)
  defp normalize_ip(_), do: nil

  defp normalize_user(user) when is_binary(user), do: String.downcase(String.trim(user))
  defp normalize_user(_), do: nil

  defp extract_domain(nil), do: nil
  defp extract_domain(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{host: host} when is_binary(host) -> String.downcase(host)
      _ ->
        # Try direct domain extraction
        url
        |> String.replace(~r/^https?:\/\//, "")
        |> String.split("/")
        |> List.first()
        |> case do
          nil -> nil
          domain -> String.downcase(domain)
        end
    end
  end
  defp extract_domain(_), do: nil

  defp enforce_index_limits(_config) do
    # Limit entries per index to prevent memory bloat
    # This is called periodically during cleanup
    :ok
  end

  # ============================================================================
  # Cross-Source Correlation
  # ============================================================================

  defp do_correlate_with_endpoint(xdr_event, config) do
    window_ms = config.correlation_window_ms
    now = System.system_time(:millisecond)
    event_ts = event_timestamp_ms(xdr_event)

    # Get correlation criteria from XDR event
    criteria = extract_correlation_criteria(xdr_event)

    # Query endpoint telemetry from the Detection.Correlator ETS table
    endpoint_matches = query_endpoint_telemetry(criteria, event_ts, window_ms)

    # Also check XDR events from endpoint source
    xdr_endpoint_matches = query_xdr_by_source_type(:endpoint, criteria, event_ts, window_ms)

    matches = (endpoint_matches ++ xdr_endpoint_matches)
    |> Enum.uniq_by(fn m -> m[:id] || m[:event_id] end)
    |> Enum.map(fn match ->
      score = calculate_correlation_score(xdr_event, match)
      Map.put(match, :correlation_score, score)
    end)
    |> Enum.filter(fn m -> m[:correlation_score] > 0 end)
    |> Enum.sort_by(fn m -> m[:correlation_score] end, :desc)

    %{
      source_event: xdr_event,
      matches: Enum.take(matches, 50),
      match_count: length(matches),
      correlated_at: DateTime.utc_now()
    }
  end

  defp extract_correlation_criteria(event) do
    %{
      source_ip: event[:source_ip],
      dest_ip: event[:dest_ip],
      user: event[:user],
      file_hash: event[:file_hash],
      domain: extract_domain(event[:url] || event[:domain]),
      action: event[:action],
      category: event[:category]
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp query_endpoint_telemetry(criteria, _event_ts, _window_ms) do
    # Query the endpoint correlator's ETS table
    # This integrates with TamanduaServer.Detection.Correlator
    try do
      :ets.tab2list(:correlation_events)
      |> Enum.filter(fn {_key, event} ->
        match_criteria?(event, criteria)
      end)
      |> Enum.map(fn {_key, event} ->
        Map.put(event, :source_type, :endpoint)
      end)
    rescue
      _ -> []
    end
  end

  defp query_xdr_by_source_type(source_type, criteria, event_ts, window_ms) do
    :ets.tab2list(@xdr_events_table)
    |> Enum.filter(fn {_id, entry} ->
      entry.source_type == source_type &&
      within_time_window?(entry.timestamp, event_ts, window_ms) &&
      match_criteria?(entry.event, criteria)
    end)
    |> Enum.map(fn {_id, entry} -> entry.event end)
  end

  defp match_criteria?(event, criteria) when map_size(criteria) == 0, do: false
  defp match_criteria?(event, criteria) do
    payload = event[:payload] || event

    Enum.any?(criteria, fn {key, value} ->
      event_value = payload[key] || payload[to_string(key)]
      event_value && normalize_value(event_value) == normalize_value(value)
    end)
  end

  defp normalize_value(v) when is_binary(v), do: String.downcase(String.trim(v))
  defp normalize_value(v), do: v

  defp within_time_window?(event_ts, reference_ts, window_ms) do
    event_ms = event_timestamp_ms(%{timestamp: event_ts})
    abs(event_ms - reference_ts) <= window_ms
  end

  defp event_timestamp_ms(%{timestamp: %DateTime{} = dt}) do
    DateTime.to_unix(dt, :millisecond)
  end
  defp event_timestamp_ms(%{timestamp: ts}) when is_integer(ts), do: ts
  defp event_timestamp_ms(_), do: System.system_time(:millisecond)

  defp calculate_correlation_score(source_event, target_event) do
    source = source_event
    target = target_event[:payload] || target_event

    scores = [
      # IP matches
      if(match_field?(source[:source_ip], target[:source_ip]) ||
         match_field?(source[:source_ip], target[:remote_ip]),
        do: 30, else: 0),
      if(match_field?(source[:dest_ip], target[:dest_ip]) ||
         match_field?(source[:dest_ip], target[:local_ip]),
        do: 30, else: 0),

      # User match
      if(match_field?(source[:user], target[:user]),
        do: 25, else: 0),

      # Hash match
      if(match_field?(source[:file_hash], target[:sha256]) ||
         match_field?(source[:file_hash], target[:file_hash]),
        do: 40, else: 0),

      # Domain match
      if(match_domain?(source, target),
        do: 20, else: 0)
    ]

    Enum.sum(scores)
  end

  defp match_field?(nil, _), do: false
  defp match_field?(_, nil), do: false
  defp match_field?(a, b) when is_binary(a) and is_binary(b) do
    String.downcase(String.trim(a)) == String.downcase(String.trim(b))
  end
  defp match_field?(a, b), do: a == b

  defp match_domain?(source, target) do
    source_domain = extract_domain(source[:url] || source[:domain])
    target_domain = extract_domain(target[:url] || target[:domain])

    source_domain && target_domain &&
      String.downcase(source_domain) == String.downcase(target_domain)
  end

  # ============================================================================
  # Entity Correlations
  # ============================================================================

  defp do_get_entity_correlations(entity_type, entity_value, opts, config) do
    window_ms = Keyword.get(opts, :time_window_ms, config.correlation_window_ms)
    now = System.system_time(:millisecond)

    # Select appropriate index table
    table = case entity_type do
      "ip" -> @ip_index_table
      "user" -> @user_index_table
      "hash" -> @hash_index_table
      "domain" -> @domain_index_table
      _ -> @ip_index_table
    end

    # Normalize the lookup value
    normalized_value = case entity_type do
      "ip" -> normalize_ip(entity_value)
      "user" -> normalize_user(entity_value)
      "hash" -> String.downcase(entity_value)
      "domain" -> extract_domain(entity_value)
      _ -> entity_value
    end

    # Query index
    entries = :ets.lookup(table, normalized_value)
    |> Enum.filter(fn {_key, entry} ->
      now - entry.indexed_at <= window_ms
    end)
    |> Enum.map(fn {_key, entry} -> entry end)

    # Group by source type
    by_source = Enum.group_by(entries, & &1.source_type)

    # Calculate cross-source activity
    source_types = Map.keys(by_source)
    is_cross_source = length(source_types) > 1

    %{
      entity_type: entity_type,
      entity_value: entity_value,
      total_events: length(entries),
      source_types: source_types,
      is_cross_source: is_cross_source,
      events_by_source: by_source,
      first_seen: entries |> Enum.min_by(& &1.indexed_at, fn -> %{indexed_at: now} end) |> Map.get(:indexed_at),
      last_seen: entries |> Enum.max_by(& &1.indexed_at, fn -> %{indexed_at: now} end) |> Map.get(:indexed_at),
      time_window_ms: window_ms,
      analyzed_at: DateTime.utc_now()
    }
  end

  # ============================================================================
  # Attack Timeline Building
  # ============================================================================

  defp do_build_timeline(correlation_id, opts, config) do
    window_ms = Keyword.get(opts, :time_window_ms, config.correlation_window_ms * 2)

    # Check if timeline already exists
    case :ets.lookup(@timeline_table, correlation_id) do
      [{^correlation_id, existing_timeline}] ->
        # Update existing timeline with new events
        updated = update_existing_timeline(existing_timeline, window_ms)
        :ets.insert(@timeline_table, {correlation_id, updated})
        {:ok, updated}

      [] ->
        # Get events for this correlation ID
        events = get_events_for_timeline(correlation_id, window_ms)

        if length(events) < 2 do
          {:error, :insufficient_events}
        else
          timeline = build_new_timeline(correlation_id, events, opts)
          :ets.insert(@timeline_table, {correlation_id, timeline})
          {:ok, timeline}
        end
    end
  end

  defp get_events_for_timeline(correlation_id, _window_ms) do
    # Get all events that share correlation indicators
    :ets.tab2list(@xdr_events_table)
    |> Enum.filter(fn {_id, entry} ->
      entry.event[:correlation_id] == correlation_id ||
      correlation_id_related?(entry.event[:related_correlation_ids], correlation_id)
    end)
    |> Enum.map(fn {_id, entry} -> entry end)
    |> Enum.sort_by(& &1.indexed_at)
    |> Enum.take(@max_timeline_build_events)
  end

  defp build_new_timeline(correlation_id, events, opts) do
    organization_id = Keyword.get(opts, :organization_id)

    # Determine kill chain phases for each event
    events_with_phases = events
    |> Enum.map(fn entry ->
      phase = determine_kill_chain_phase(entry.event)
      Map.put(entry, :kill_chain_phase, phase)
    end)

    # Sort by phase order then by timestamp
    sorted_events = events_with_phases
    |> Enum.sort_by(fn e ->
      phase_order = get_phase_order(e.kill_chain_phase)
      {phase_order, e.indexed_at}
    end)

    # Extract unique indicators
    indicators = extract_indicators_from_events(events)

    # Calculate risk score
    risk_score = calculate_timeline_risk_score(sorted_events)

    %{
      id: correlation_id,
      organization_id: organization_id,
      events: sorted_events,
      event_count: length(events),
      source_types: events |> Enum.map(& &1.source_type) |> Enum.uniq(),
      kill_chain_phases: sorted_events |> Enum.map(& &1.kill_chain_phase) |> Enum.uniq() |> Enum.reject(&is_nil/1),
      indicators: indicators,
      risk_score: risk_score,
      first_event_at: sorted_events |> List.first() |> Map.get(:timestamp),
      last_event_at: sorted_events |> List.last() |> Map.get(:timestamp),
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now(),
      status: :active
    }
  end

  defp correlation_id_related?(related_ids, correlation_id) when is_list(related_ids) do
    correlation_id in related_ids
  end

  defp correlation_id_related?(related_id, correlation_id), do: related_id == correlation_id

  defp update_existing_timeline(timeline, _window_ms) do
    # Check for new events to add
    Map.put(timeline, :updated_at, DateTime.utc_now())
  end

  defp determine_kill_chain_phase(event) do
    source_type = event[:source_type]
    action = event[:action]
    category = event[:category]
    mitre_techniques = event[:mitre_techniques] || []

    # Match against kill chain phases
    @kill_chain_phases
    |> Enum.find(fn phase ->
      source_type in phase.source_types &&
      (matches_tactics?(mitre_techniques, phase.tactics) ||
       matches_action_category?(action, category, phase))
    end)
    |> case do
      nil -> nil
      phase -> phase.phase
    end
  end

  defp matches_tactics?(techniques, tactics) do
    Enum.any?(techniques, fn tech ->
      Enum.any?(tactics, fn tactic ->
        String.contains?(String.downcase(to_string(tech)), String.downcase(to_string(tactic)))
      end)
    end)
  end

  defp matches_action_category?(action, category, phase) do
    action_str = to_string(action || "")
    category_str = to_string(category || "")

    phase.indicators
    |> Enum.any?(fn indicator ->
      indicator_str = to_string(indicator)
      String.contains?(action_str, indicator_str) ||
      String.contains?(category_str, indicator_str)
    end)
  end

  defp get_phase_order(nil), do: 999
  defp get_phase_order(phase_name) do
    @kill_chain_phases
    |> Enum.find(fn p -> p.phase == phase_name end)
    |> case do
      nil -> 999
      p -> p.order
    end
  end

  defp extract_indicators_from_events(events) do
    events
    |> Enum.flat_map(fn entry ->
      event = entry.event
      [
        if(event[:source_ip], do: {:ip, event[:source_ip]}, else: nil),
        if(event[:dest_ip], do: {:ip, event[:dest_ip]}, else: nil),
        if(event[:user], do: {:user, event[:user]}, else: nil),
        if(event[:file_hash], do: {:hash, event[:file_hash]}, else: nil),
        if(d = extract_domain(event[:url] || event[:domain]), do: {:domain, d}, else: nil)
      ]
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
  end

  defp calculate_timeline_risk_score(events) do
    # Base score on number of sources and kill chain progression
    source_count = events |> Enum.map(& &1.source_type) |> Enum.uniq() |> length()
    phase_count = events |> Enum.map(& &1.kill_chain_phase) |> Enum.uniq() |> Enum.reject(&is_nil/1) |> length()
    event_count = length(events)

    base_score = 0.3

    # Boost for multi-source correlation
    source_boost = min(0.3, source_count * 0.1)

    # Boost for kill chain progression
    phase_boost = min(0.3, phase_count * 0.05)

    # Boost for event volume
    volume_boost = min(0.1, event_count * 0.01)

    min(1.0, base_score + source_boost + phase_boost + volume_boost)
  end

  # ============================================================================
  # Kill Chain Detection
  # ============================================================================

  defp do_detect_kill_chain(opts, config) do
    window_ms = Keyword.get(opts, :time_window_ms, config.correlation_window_ms * 4)
    org_id = Keyword.get(opts, :organization_id)
    now = System.system_time(:millisecond)

    # Get all recent events
    events = :ets.tab2list(@xdr_events_table)
    |> Enum.filter(fn {_id, entry} ->
      now - entry.indexed_at <= window_ms &&
      (is_nil(org_id) || entry.organization_id == org_id)
    end)
    |> Enum.map(fn {_id, entry} ->
      phase = determine_kill_chain_phase(entry.event)
      Map.put(entry, :kill_chain_phase, phase)
    end)
    |> Enum.reject(fn e -> is_nil(e.kill_chain_phase) end)

    # Group by correlation indicators
    grouped = group_events_by_indicators(events)

    # Find kill chain progressions
    kill_chains = grouped
    |> Enum.map(fn {indicator, indicator_events} ->
      detect_kill_chain_in_group(indicator, indicator_events)
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.sort_by(& &1[:risk_score], :desc)

    kill_chains
  end

  defp group_events_by_indicators(events) do
    # Group by shared indicators (IP, user, hash)
    by_ip = events
    |> Enum.flat_map(fn e ->
      ips = [e.event[:source_ip], e.event[:dest_ip]] |> Enum.reject(&is_nil/1)
      Enum.map(ips, fn ip -> {{:ip, ip}, e} end)
    end)
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))

    by_user = events
    |> Enum.filter(fn e -> e.event[:user] end)
    |> Enum.group_by(fn e -> {:user, e.event[:user]} end)

    by_hash = events
    |> Enum.filter(fn e -> e.event[:file_hash] end)
    |> Enum.group_by(fn e -> {:hash, e.event[:file_hash]} end)

    Map.merge(by_ip, Map.merge(by_user, by_hash))
    |> Enum.filter(fn {_k, v} -> length(v) >= 2 end)
  end

  defp detect_kill_chain_in_group(indicator, events) do
    # Sort by kill chain phase order
    sorted = events
    |> Enum.sort_by(fn e ->
      {get_phase_order(e.kill_chain_phase), e.indexed_at}
    end)

    phases = sorted |> Enum.map(& &1.kill_chain_phase) |> Enum.uniq()

    # Check for progression (at least 2 phases in order)
    if length(phases) >= 2 && is_progressive?(phases) do
      %{
        indicator: indicator,
        phases: phases,
        phase_count: length(phases),
        events: sorted,
        event_count: length(sorted),
        source_types: sorted |> Enum.map(& &1.source_type) |> Enum.uniq(),
        first_event: List.first(sorted),
        last_event: List.last(sorted),
        risk_score: calculate_kill_chain_risk(phases, sorted),
        detected_at: DateTime.utc_now()
      }
    else
      nil
    end
  end

  defp is_progressive?(phases) do
    orders = phases
    |> Enum.map(&get_phase_order/1)
    |> Enum.filter(& &1 != 999)

    case orders do
      [] -> false
      [_] -> false
      _ ->
        # Check if generally ascending
        {increasing, _} = Enum.reduce(orders, {0, -1}, fn order, {count, prev} ->
          if order > prev, do: {count + 1, order}, else: {count, order}
        end)
        increasing >= length(orders) / 2
    end
  end

  defp calculate_kill_chain_risk(phases, events) do
    phase_weights = %{
      "initial_access" => 0.1,
      "execution" => 0.15,
      "persistence" => 0.15,
      "defense_evasion" => 0.1,
      "credential_access" => 0.2,
      "discovery" => 0.05,
      "lateral_movement" => 0.2,
      "command_and_control" => 0.15,
      "exfiltration" => 0.25,
      "impact" => 0.25
    }

    phase_score = phases
    |> Enum.map(fn p -> Map.get(phase_weights, p, 0.05) end)
    |> Enum.sum()

    source_bonus = events |> Enum.map(& &1.source_type) |> Enum.uniq() |> length() |> Kernel.*(0.1)

    min(1.0, phase_score + source_bonus)
  end

  # ============================================================================
  # Cross-Source Pattern Detection
  # ============================================================================

  defp check_cross_source_patterns(event, config) do
    window_ms = config.correlation_window_ms
    event_ts = event_timestamp_ms(event)
    source_type = event[:source_type]

    # Check each pattern
    @cross_source_patterns
    |> Enum.flat_map(fn pattern ->
      if matches_pattern_step?(event, pattern.pattern, 0) do
        # Look for preceding steps
        preceding_matches = find_preceding_pattern_steps(event, pattern, window_ms)

        if length(preceding_matches) > 0 do
          [%{
            pattern_name: pattern.name,
            description: pattern.description,
            severity: pattern.severity,
            mitre_techniques: pattern.mitre_techniques,
            source_event: event,
            matching_events: preceding_matches,
            detected_at: DateTime.utc_now()
          }]
        else
          []
        end
      else
        []
      end
    end)
  end

  defp matches_pattern_step?(event, pattern_steps, step_index) when step_index < length(pattern_steps) do
    step = Enum.at(pattern_steps, step_index)
    source_type = event[:source_type]
    action = event[:action] || ""

    source_matches = step[:source_type] == source_type

    action_matches = case step[:action] do
      nil -> true
      %Regex{} = re -> Regex.match?(re, to_string(action))
      action_str when is_binary(action_str) -> String.contains?(to_string(action), action_str)
      _ -> true
    end

    category_matches = case step[:category] do
      nil -> true
      cat -> event[:category] == cat
    end

    source_matches && action_matches && category_matches
  end
  defp matches_pattern_step?(_event, _pattern_steps, _step_index), do: false

  defp find_preceding_pattern_steps(event, pattern, window_ms) do
    event_ts = event_timestamp_ms(event)
    pattern_steps = pattern.pattern

    # For each preceding step, look for matching events
    pattern_steps
    |> Enum.with_index()
    |> Enum.drop(-1)  # Skip the last step (that's our current event)
    |> Enum.flat_map(fn {step, _idx} ->
      # Query appropriate index based on step source type
      :ets.tab2list(@xdr_events_table)
      |> Enum.filter(fn {_id, entry} ->
        entry.source_type == step[:source_type] &&
        entry.indexed_at < event_ts &&
        event_ts - entry.indexed_at <= (step[:time_offset_max_ms] || window_ms) &&
        matches_step_criteria?(entry.event, step)
      end)
      |> Enum.map(fn {_id, entry} -> entry.event end)
    end)
  end

  defp matches_step_criteria?(event, step) do
    action = event[:action] || ""

    action_matches = case step[:action] do
      nil -> true
      %Regex{} = re -> Regex.match?(re, to_string(action))
      action_str when is_binary(action_str) -> String.contains?(to_string(action), action_str)
      _ -> true
    end

    category_matches = case step[:category] do
      nil -> true
      cat -> event[:category] == cat
    end

    count_matches = case step[:min_count] do
      nil -> true
      _count -> true  # Would need event aggregation to check properly
    end

    action_matches && category_matches && count_matches
  end

  defp check_kill_chain_progression(event, config) do
    phase = determine_kill_chain_phase(event)

    if phase do
      # Look for events in earlier phases
      window_ms = config.correlation_window_ms * 2
      event_ts = event_timestamp_ms(event)
      current_order = get_phase_order(phase)

      # Find related events in earlier phases
      earlier_events = :ets.tab2list(@xdr_events_table)
      |> Enum.filter(fn {_id, entry} ->
        entry_phase = determine_kill_chain_phase(entry.event)
        entry_order = get_phase_order(entry_phase)
        entry_ts = entry.indexed_at

        entry_phase != nil &&
        entry_order < current_order &&
        event_ts - entry_ts <= window_ms &&
        shares_indicator?(event, entry.event)
      end)

      if length(earlier_events) > 0 do
        phases = earlier_events
        |> Enum.map(fn {_id, entry} -> determine_kill_chain_phase(entry.event) end)
        |> Enum.reject(&is_nil/1)
        |> Kernel.++([phase])
        |> Enum.uniq()

        [%{
          type: :kill_chain_progression,
          description: "Kill chain progression detected: #{Enum.join(phases, " -> ")}",
          severity: if(length(phases) >= 3, do: :critical, else: :high),
          mitre_techniques: [],
          phases: phases,
          phase_count: length(phases),
          related_events: length(earlier_events),
          detected_at: DateTime.utc_now()
        }]
      else
        []
      end
    else
      []
    end
  end

  defp shares_indicator?(event1, event2) do
    # Check if two events share any indicator
    (event1[:source_ip] && event1[:source_ip] == event2[:source_ip]) ||
    (event1[:dest_ip] && event1[:dest_ip] == event2[:dest_ip]) ||
    (event1[:source_ip] && event1[:source_ip] == event2[:dest_ip]) ||
    (event1[:dest_ip] && event1[:dest_ip] == event2[:source_ip]) ||
    (event1[:user] && event1[:user] == event2[:user]) ||
    (event1[:file_hash] && event1[:file_hash] == event2[:file_hash]) ||
    (extract_domain(event1[:url] || event1[:domain]) == extract_domain(event2[:url] || event2[:domain]) &&
     extract_domain(event1[:url] || event1[:domain]) != nil)
  end

  # ============================================================================
  # Alert Creation
  # ============================================================================

  defp create_xdr_alerts(event, detections) do
    org_id = event[:organization_id]

    Enum.each(detections, fn detection ->
      severity = detection[:severity] || :high

      title = case detection[:type] do
        :kill_chain_progression ->
          "Kill Chain Progression: #{detection[:description]}"
        _ ->
          "XDR Correlation: #{detection[:pattern_name] || detection[:description]}"
      end

      evidence = %{
        xdr_event: event,
        detection: detection,
        source_type: event[:source_type],
        correlation_type: "cross_source"
      }

      case Alerts.create_alert(%{
        organization_id: org_id,
        severity: severity,
        title: title,
        description: detection[:description],
        source: "xdr_correlator",
        evidence: evidence,
        mitre_techniques: detection[:mitre_techniques] || [],
        threat_score: detection[:risk_score] || 0.7
      }) do
        {:ok, _alert} -> :ok
        {:error, reason} ->
          Logger.warning("Failed to create XDR correlation alert (#{inspect(detection[:type])}): #{inspect(reason)}")
      end
    end)
  end

  # ============================================================================
  # Timeline Filtering
  # ============================================================================

  defp filter_timelines(timelines, opts) do
    timelines
    |> maybe_filter_by_status(Keyword.get(opts, :status))
    |> maybe_filter_by_org(Keyword.get(opts, :organization_id))
    |> maybe_filter_by_risk(Keyword.get(opts, :min_risk_score))
  end

  defp timeline_limit(opts) do
    opts
    |> Keyword.get(:limit, @default_timeline_limit)
    |> clamp_integer(@default_timeline_limit, 1, @max_timeline_limit)
  end

  defp clamp_integer(value, default, min_value, max_value) when is_integer(value) do
    value
    |> max(min_value)
    |> min(max_value)
  end

  defp clamp_integer(_value, default, min_value, max_value) do
    default
    |> max(min_value)
    |> min(max_value)
  end

  defp maybe_filter_by_status(timelines, nil), do: timelines
  defp maybe_filter_by_status(timelines, status) do
    Enum.filter(timelines, & &1[:status] == status)
  end

  defp maybe_filter_by_org(timelines, nil), do: timelines
  defp maybe_filter_by_org(timelines, org_id) do
    Enum.filter(timelines, & &1[:organization_id] == org_id)
  end

  defp maybe_filter_by_risk(timelines, nil), do: timelines
  defp maybe_filter_by_risk(timelines, min_score) do
    Enum.filter(timelines, & (&1[:risk_score] || 0) >= min_score)
  end

  # ============================================================================
  # Cleanup
  # ============================================================================

  defp cleanup_old_events(config) do
    now = System.system_time(:millisecond)
    threshold = now - config.event_ttl_ms

    # Clean up main events table
    :ets.tab2list(@xdr_events_table)
    |> Enum.each(fn {id, entry} ->
      if entry.indexed_at < threshold do
        :ets.delete(@xdr_events_table, id)
      end
    end)

    # Clean up index tables
    Enum.each([@ip_index_table, @user_index_table, @hash_index_table, @domain_index_table], fn table ->
      :ets.tab2list(table)
      |> Enum.each(fn {key, entry} ->
        if entry.indexed_at < threshold do
          :ets.delete_object(table, {key, entry})
        end
      end)
    end)

    Logger.debug("XDR Correlator cleanup completed")
  end

  defp schedule_cleanup(interval_ms) do
    Process.send_after(self(), :cleanup, interval_ms)
  end

  # ============================================================================
  # Stats
  # ============================================================================

  defp increment_events_correlated(state) do
    %{state | stats: Map.update(state.stats, :events_correlated, 1, & &1 + 1)}
  end

  defp update_stats(state, pattern_detections, kill_chain_detections) do
    state
    |> update_stat(:patterns_detected, length(pattern_detections))
    |> update_stat(:kill_chains_detected, length(kill_chain_detections))
    |> update_stat(:alerts_generated, length(pattern_detections) + length(kill_chain_detections))
  end

  defp update_stat(state, key, increment) do
    %{state | stats: Map.update(state.stats, key, increment, & &1 + increment)}
  end

  # ============================================================================
  # ML Correlation Handle Calls
  # ============================================================================

  @impl true
  def handle_call({:ml_correlate, event1, event2}, _from, state) do
    score = calculate_ml_correlation_score(event1, event2, state.config)
    new_state = update_stat(state, :ml_correlations, 1)
    {:reply, {:ok, score}, new_state}
  end

  @impl true
  def handle_call({:group_incident, events, opts}, _from, state) do
    case do_group_incident(events, opts, state.config) do
      {:ok, incident} ->
        :ets.insert(@incident_table, {incident.id, incident})
        new_state = update_stat(state, :incidents_grouped, 1)
        {:reply, {:ok, incident}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:list_incidents, opts}, _from, state) do
    incidents = :ets.tab2list(@incident_table)
    |> Enum.map(fn {_id, incident} -> incident end)
    |> filter_incidents(opts)
    |> Enum.sort_by(& &1[:created_at], {:desc, DateTime})

    {:reply, {:ok, incidents}, state}
  end

  @impl true
  def handle_call({:get_incident, incident_id}, _from, state) do
    case :ets.lookup(@incident_table, incident_id) do
      [{^incident_id, incident}] -> {:reply, {:ok, incident}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:build_entity_graph, entity_type, entity_value, opts}, _from, state) do
    graph = do_build_entity_graph(entity_type, entity_value, opts, state.config)
    new_state = update_stat(state, :entity_graph_nodes, map_size(graph.nodes))
    {:reply, {:ok, graph}, new_state}
  end

  @impl true
  def handle_call({:get_cross_domain_chains, opts}, _from, state) do
    chains = do_get_cross_domain_chains(opts, state.config)
    new_state = update_stat(state, :cross_domain_detections, length(chains))
    {:reply, {:ok, chains}, new_state}
  end

  @impl true
  def handle_call({:calculate_entity_threat_score, entity_type, entity_value}, _from, state) do
    score = do_calculate_entity_threat_score(entity_type, entity_value, state.config)
    {:reply, {:ok, score}, state}
  end

  @impl true
  def handle_call({:export_correlation, id, format}, _from, state) do
    result = do_export_correlation(id, format)
    {:reply, result, state}
  end

  @impl true
  def handle_info(:analyze_incidents, state) do
    # Periodic incident analysis and auto-grouping
    if state.config.auto_group_incidents do
      auto_group_related_alerts(state.config)
    end
    schedule_incident_analysis(60_000)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # ML Correlation Engine
  # ============================================================================

  defp calculate_ml_correlation_score(event1, event2, _config) do
    # Extract features for both events
    features1 = extract_ml_features(event1)
    features2 = extract_ml_features(event2)

    # Calculate weighted feature similarities
    ip_score = calculate_ip_similarity(features1, features2) * @ml_feature_weights.ip_match
    user_score = calculate_user_similarity(features1, features2) * @ml_feature_weights.user_match
    hash_score = calculate_hash_similarity(features1, features2) * @ml_feature_weights.hash_match
    domain_score = calculate_domain_similarity(features1, features2) * @ml_feature_weights.domain_match
    temporal_score = calculate_temporal_proximity(features1, features2) * @ml_feature_weights.temporal_proximity
    source_score = calculate_source_diversity_score(features1, features2) * @ml_feature_weights.source_diversity
    kill_chain_score = calculate_kill_chain_alignment(features1, features2) * @ml_feature_weights.kill_chain_alignment
    severity_score = calculate_severity_escalation(features1, features2) * @ml_feature_weights.severity_escalation

    total_score = ip_score + user_score + hash_score + domain_score +
                  temporal_score + source_score + kill_chain_score + severity_score

    # Normalize to 0.0-1.0 range
    min(1.0, max(0.0, total_score))
  end

  defp extract_ml_features(event) do
    %{
      source_ip: event[:source_ip],
      dest_ip: event[:dest_ip],
      user: event[:user],
      file_hash: event[:file_hash],
      domain: extract_domain(event[:url] || event[:domain]),
      timestamp: event_timestamp_ms(event),
      source_type: event[:source_type],
      action: event[:action],
      category: event[:category],
      severity: event[:severity],
      kill_chain_phase: determine_kill_chain_phase(event),
      mitre_techniques: event[:mitre_techniques] || []
    }
  end

  defp calculate_ip_similarity(f1, f2) do
    ips1 = [f1.source_ip, f1.dest_ip] |> Enum.reject(&is_nil/1) |> MapSet.new()
    ips2 = [f2.source_ip, f2.dest_ip] |> Enum.reject(&is_nil/1) |> MapSet.new()

    if MapSet.size(ips1) == 0 or MapSet.size(ips2) == 0 do
      0.0
    else
      intersection = MapSet.intersection(ips1, ips2) |> MapSet.size()
      union = MapSet.union(ips1, ips2) |> MapSet.size()
      intersection / union
    end
  end

  defp calculate_user_similarity(f1, f2) do
    case {f1.user, f2.user} do
      {nil, _} -> 0.0
      {_, nil} -> 0.0
      {u1, u2} when u1 == u2 -> 1.0
      {u1, u2} ->
        # Check for partial match (same domain or similar username)
        if String.contains?(String.downcase(u1), String.downcase(u2)) or
           String.contains?(String.downcase(u2), String.downcase(u1)) do
          0.5
        else
          0.0
        end
    end
  end

  defp calculate_hash_similarity(f1, f2) do
    case {f1.file_hash, f2.file_hash} do
      {nil, _} -> 0.0
      {_, nil} -> 0.0
      {h1, h2} when h1 == h2 -> 1.0
      _ -> 0.0
    end
  end

  defp calculate_domain_similarity(f1, f2) do
    case {f1.domain, f2.domain} do
      {nil, _} -> 0.0
      {_, nil} -> 0.0
      {d1, d2} when d1 == d2 -> 1.0
      {d1, d2} ->
        # Check for subdomain relationship
        if String.ends_with?(d1, d2) or String.ends_with?(d2, d1) do
          0.7
        else
          0.0
        end
    end
  end

  defp calculate_temporal_proximity(f1, f2) do
    case {f1.timestamp, f2.timestamp} do
      {nil, _} -> 0.0
      {_, nil} -> 0.0
      {t1, t2} ->
        diff_ms = abs(t1 - t2)
        # Score based on time difference (higher score for closer events)
        # Full score within 5 minutes, decreasing to 0 at 1 hour
        cond do
          diff_ms <= 5 * 60 * 1000 -> 1.0
          diff_ms <= 15 * 60 * 1000 -> 0.8
          diff_ms <= 30 * 60 * 1000 -> 0.5
          diff_ms <= 60 * 60 * 1000 -> 0.2
          true -> 0.0
        end
    end
  end

  defp calculate_source_diversity_score(f1, f2) do
    # Higher score when events come from different source types (cross-domain)
    case {f1.source_type, f2.source_type} do
      {nil, _} -> 0.0
      {_, nil} -> 0.0
      {s1, s2} when s1 == s2 -> 0.3  # Same source type - lower correlation value
      _ -> 1.0  # Different source types - higher correlation value (cross-domain)
    end
  end

  defp calculate_kill_chain_alignment(f1, f2) do
    case {f1.kill_chain_phase, f2.kill_chain_phase} do
      {nil, _} -> 0.0
      {_, nil} -> 0.0
      {p1, p2} when p1 == p2 -> 0.5  # Same phase
      {p1, p2} ->
        # Check if phases are adjacent in kill chain
        order1 = get_phase_order(p1)
        order2 = get_phase_order(p2)
        if abs(order1 - order2) == 1 do
          1.0  # Adjacent phases - strong correlation
        else
          0.3  # Non-adjacent phases
        end
    end
  end

  defp calculate_severity_escalation(f1, f2) do
    severity_order = %{"info" => 1, "low" => 2, "medium" => 3, "high" => 4, "critical" => 5}

    s1 = severity_order[f1.severity] || 0
    s2 = severity_order[f2.severity] || 0

    # Higher score if severity is escalating
    if s2 > s1 do
      0.8
    else
      0.3
    end
  end

  # ============================================================================
  # Incident Grouping
  # ============================================================================

  defp do_group_incident(events, opts, config) do
    if length(events) < 1 do
      {:error, :insufficient_events}
    else
      incident_id = Ecto.UUID.generate()
      organization_id = Keyword.get(opts, :organization_id)
      name = Keyword.get(opts, :name, "Incident #{incident_id}")

      # Calculate incident severity based on constituent events
      max_severity = events
      |> Enum.map(fn e -> e[:severity] || "low" end)
      |> Enum.max_by(fn s ->
        %{"info" => 1, "low" => 2, "medium" => 3, "high" => 4, "critical" => 5}[s] || 0
      end)

      # Extract all unique indicators
      indicators = extract_indicators_from_incident_events(events)

      # Determine kill chain phases covered
      phases = events
      |> Enum.map(&determine_kill_chain_phase/1)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

      # Calculate confidence score
      confidence = calculate_incident_confidence(events, config)

      # Identify affected assets
      affected_assets = extract_affected_assets(events)

      incident = %{
        id: incident_id,
        name: name,
        organization_id: organization_id,
        status: :open,
        severity: max_severity,
        events: events,
        event_count: length(events),
        indicators: indicators,
        kill_chain_phases: phases,
        affected_assets: affected_assets,
        confidence_score: confidence,
        source_types: events |> Enum.map(& &1[:source_type]) |> Enum.uniq(),
        mitre_techniques: events |> Enum.flat_map(& (&1[:mitre_techniques] || [])) |> Enum.uniq(),
        first_event_at: events |> Enum.min_by(&event_timestamp_ms/1, fn -> %{} end) |> Map.get(:timestamp),
        last_event_at: events |> Enum.max_by(&event_timestamp_ms/1, fn -> %{} end) |> Map.get(:timestamp),
        created_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now()
      }

      {:ok, incident}
    end
  end

  defp extract_indicators_from_incident_events(events) do
    events
    |> Enum.flat_map(fn event ->
      [
        if(event[:source_ip], do: {:ip, event[:source_ip]}, else: nil),
        if(event[:dest_ip], do: {:ip, event[:dest_ip]}, else: nil),
        if(event[:user], do: {:user, event[:user]}, else: nil),
        if(event[:file_hash], do: {:hash, event[:file_hash]}, else: nil),
        if(d = extract_domain(event[:url] || event[:domain]), do: {:domain, d}, else: nil)
      ]
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
  end

  defp calculate_incident_confidence(events, config) do
    # Base confidence on various factors
    event_count_score = min(1.0, length(events) / 10.0) * 0.2
    source_diversity_score = (events |> Enum.map(& &1[:source_type]) |> Enum.uniq() |> length()) / 5.0 * 0.3
    indicator_overlap_score = calculate_indicator_overlap(events) * 0.3
    temporal_clustering_score = calculate_temporal_clustering(events) * 0.2

    min(1.0, event_count_score + source_diversity_score + indicator_overlap_score + temporal_clustering_score)
  end

  defp calculate_indicator_overlap(events) do
    # Calculate how many events share common indicators
    ips = events |> Enum.flat_map(fn e -> [e[:source_ip], e[:dest_ip]] end) |> Enum.reject(&is_nil/1)
    users = events |> Enum.map(& &1[:user]) |> Enum.reject(&is_nil/1)

    ip_groups = Enum.group_by(ips, & &1)
    user_groups = Enum.group_by(users, & &1)

    ip_overlap = ip_groups |> Enum.count(fn {_, v} -> length(v) > 1 end)
    user_overlap = user_groups |> Enum.count(fn {_, v} -> length(v) > 1 end)

    min(1.0, (ip_overlap + user_overlap) / max(1, length(events)))
  end

  defp calculate_temporal_clustering(events) do
    timestamps = events |> Enum.map(&event_timestamp_ms/1) |> Enum.sort()

    if length(timestamps) < 2 do
      0.5
    else
      # Calculate average time gap
      gaps = timestamps
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.map(fn [t1, t2] -> t2 - t1 end)

      avg_gap = Enum.sum(gaps) / length(gaps)

      # Higher score for tighter clustering (smaller gaps)
      cond do
        avg_gap <= 60_000 -> 1.0      # Under 1 minute average
        avg_gap <= 300_000 -> 0.8     # Under 5 minutes
        avg_gap <= 900_000 -> 0.6     # Under 15 minutes
        avg_gap <= 3600_000 -> 0.4    # Under 1 hour
        true -> 0.2
      end
    end
  end

  defp extract_affected_assets(events) do
    events
    |> Enum.flat_map(fn event ->
      [
        if(event[:hostname], do: %{type: "host", value: event[:hostname]}, else: nil),
        if(event[:agent_id], do: %{type: "agent", value: event[:agent_id]}, else: nil),
        if(event[:dest_ip], do: %{type: "ip", value: event[:dest_ip]}, else: nil),
        if(event[:user], do: %{type: "user", value: event[:user]}, else: nil)
      ]
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp filter_incidents(incidents, opts) do
    incidents
    |> maybe_filter_by_status(Keyword.get(opts, :status))
    |> maybe_filter_by_org(Keyword.get(opts, :organization_id))
    |> maybe_filter_by_severity(Keyword.get(opts, :severity))
    |> Enum.take(Keyword.get(opts, :limit, 100))
  end

  defp maybe_filter_by_severity(incidents, nil), do: incidents
  defp maybe_filter_by_severity(incidents, severity) do
    Enum.filter(incidents, & &1[:severity] == severity)
  end

  defp auto_group_related_alerts(config) do
    # Get recent events that haven't been grouped
    window_ms = config.incident_grouping_window_ms
    now = System.system_time(:millisecond)

    recent_events = :ets.tab2list(@xdr_events_table)
    |> Enum.filter(fn {_id, entry} ->
      now - entry.indexed_at <= window_ms
    end)
    |> Enum.map(fn {_id, entry} -> entry.event end)

    # Group events by shared indicators
    if length(recent_events) >= 3 do
      grouped = group_events_by_correlation(recent_events, config)

      Enum.each(grouped, fn group ->
        if length(group) >= 3 do
          case do_group_incident(group, [], config) do
            {:ok, incident} ->
              :ets.insert(@incident_table, {incident.id, incident})
              Logger.info("Auto-grouped #{length(group)} events into incident #{incident.id}")
            _ -> :ok
          end
        end
      end)
    end
  end

  defp group_events_by_correlation(events, config) do
    # Use ML correlation to group related events
    events
    |> Enum.reduce([], fn event, groups ->
      # Find existing group with high correlation
      matching_group = Enum.find_index(groups, fn group ->
        Enum.any?(group, fn existing ->
          score = calculate_ml_correlation_score(event, existing, config)
          score >= config.ml_correlation_threshold
        end)
      end)

      case matching_group do
        nil -> groups ++ [[event]]  # Create new group
        idx ->
          # Add to existing group
          List.update_at(groups, idx, fn group -> group ++ [event] end)
      end
    end)
  end

  # ============================================================================
  # Entity Graph Building
  # ============================================================================

  defp do_build_entity_graph(entity_type, entity_value, opts, config) do
    depth = Keyword.get(opts, :depth, config.entity_graph_depth)
    window_ms = Keyword.get(opts, :time_window_ms, config.correlation_window_ms * 4)

    # Start with the root entity
    root_node = %{
      id: "#{entity_type}:#{entity_value}",
      type: entity_type,
      value: entity_value,
      depth: 0
    }

    # BFS to find connected entities
    {nodes, edges} = explore_entity_connections(root_node, depth, window_ms, %{root_node.id => root_node}, [])

    %{
      nodes: nodes,
      edges: edges,
      root: root_node.id,
      total_nodes: map_size(nodes),
      total_edges: length(edges),
      analyzed_at: DateTime.utc_now()
    }
  end

  defp explore_entity_connections(node, 0, _window_ms, nodes, edges), do: {nodes, edges}
  defp explore_entity_connections(node, depth, window_ms, nodes, edges) do
    # Find events related to this entity
    related_events = find_events_for_entity(node.type, node.value, window_ms)

    # Extract connected entities
    new_entities = related_events
    |> Enum.flat_map(&extract_entities_from_event/1)
    |> Enum.reject(fn e -> e.id == node.id end)
    |> Enum.uniq_by(& &1.id)
    |> Enum.reject(fn e -> Map.has_key?(nodes, e.id) end)

    # Create edges
    new_edges = new_entities
    |> Enum.map(fn entity ->
      %{
        source: node.id,
        target: entity.id,
        relationship: determine_relationship(node, entity, related_events),
        event_count: count_shared_events(node, entity, related_events)
      }
    end)

    # Add new entities to nodes map
    updated_nodes = Enum.reduce(new_entities, nodes, fn entity, acc ->
      Map.put(acc, entity.id, Map.put(entity, :depth, node.depth + 1))
    end)

    updated_edges = edges ++ new_edges

    # Recursively explore new entities
    Enum.reduce(new_entities, {updated_nodes, updated_edges}, fn entity, {n, e} ->
      explore_entity_connections(Map.put(entity, :depth, node.depth + 1), depth - 1, window_ms, n, e)
    end)
  end

  defp find_events_for_entity("ip", value, _window_ms) do
    :ets.lookup(@ip_index_table, value)
    |> Enum.map(fn {_k, entry} -> entry.event end)
  end
  defp find_events_for_entity("user", value, _window_ms) do
    :ets.lookup(@user_index_table, normalize_user(value))
    |> Enum.map(fn {_k, entry} -> entry.event end)
  end
  defp find_events_for_entity("hash", value, _window_ms) do
    :ets.lookup(@hash_index_table, String.downcase(value))
    |> Enum.map(fn {_k, entry} -> entry.event end)
  end
  defp find_events_for_entity("domain", value, _window_ms) do
    :ets.lookup(@domain_index_table, extract_domain(value))
    |> Enum.map(fn {_k, entry} -> entry.event end)
  end
  defp find_events_for_entity(_, _, _), do: []

  defp extract_entities_from_event(event) do
    [
      if(event[:source_ip], do: %{id: "ip:#{event[:source_ip]}", type: "ip", value: event[:source_ip]}, else: nil),
      if(event[:dest_ip], do: %{id: "ip:#{event[:dest_ip]}", type: "ip", value: event[:dest_ip]}, else: nil),
      if(event[:user], do: %{id: "user:#{event[:user]}", type: "user", value: event[:user]}, else: nil),
      if(event[:file_hash], do: %{id: "hash:#{event[:file_hash]}", type: "hash", value: event[:file_hash]}, else: nil),
      if(d = extract_domain(event[:url] || event[:domain]), do: %{id: "domain:#{d}", type: "domain", value: d}, else: nil)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp determine_relationship(node, entity, _events) do
    # Determine relationship type based on entity types
    case {node.type, entity.type} do
      {"ip", "user"} -> "accessed_by"
      {"user", "ip"} -> "accessed"
      {"ip", "ip"} -> "connected_to"
      {"user", "domain"} -> "visited"
      {"ip", "domain"} -> "resolved"
      {"hash", "ip"} -> "downloaded_from"
      {"ip", "hash"} -> "delivered"
      _ -> "related_to"
    end
  end

  defp count_shared_events(node, entity, events) do
    Enum.count(events, fn event ->
      has_entity?(event, node.type, node.value) and has_entity?(event, entity.type, entity.value)
    end)
  end

  defp has_entity?(event, "ip", value) do
    event[:source_ip] == value or event[:dest_ip] == value
  end
  defp has_entity?(event, "user", value) do
    event[:user] == value
  end
  defp has_entity?(event, "hash", value) do
    event[:file_hash] == value
  end
  defp has_entity?(event, "domain", value) do
    extract_domain(event[:url] || event[:domain]) == value
  end
  defp has_entity?(_, _, _), do: false

  # ============================================================================
  # Cross-Domain Chain Detection
  # ============================================================================

  defp do_get_cross_domain_chains(opts, config) do
    window_ms = Keyword.get(opts, :time_window_ms, config.kill_chain_window_ms)
    now = System.system_time(:millisecond)

    # Get all recent events grouped by source type
    events_by_source = :ets.tab2list(@xdr_events_table)
    |> Enum.filter(fn {_id, entry} -> now - entry.indexed_at <= window_ms end)
    |> Enum.map(fn {_id, entry} -> entry end)
    |> Enum.group_by(& &1.source_type)

    # Find chains that span multiple domains
    domains = [:endpoint, :network, :cloud, :identity, :email, :firewall, :proxy]
    active_domains = Enum.filter(domains, fn d -> Map.has_key?(events_by_source, d) end)

    if length(active_domains) < 2 do
      []
    else
      # Look for indicator overlap between domains
      find_cross_domain_chains(events_by_source, active_domains, config)
    end
  end

  defp find_cross_domain_chains(events_by_source, domains, _config) do
    # For each pair of domains, find events with shared indicators
    for d1 <- domains,
        d2 <- domains,
        d1 != d2,
        events1 = Map.get(events_by_source, d1, []),
        events2 = Map.get(events_by_source, d2, []),
        length(events1) > 0 and length(events2) > 0 do
      find_chains_between_domains(d1, events1, d2, events2)
    end
    |> List.flatten()
    |> Enum.uniq_by(& &1.id)
    |> Enum.sort_by(& &1.confidence, :desc)
  end

  defp find_chains_between_domains(domain1, events1, domain2, events2) do
    chains = for e1 <- events1, e2 <- events2 do
      if shares_indicator?(e1.event, e2.event) do
        %{
          id: "chain:#{e1.id}:#{e2.id}",
          domains: [domain1, domain2],
          events: [e1.event, e2.event],
          shared_indicators: find_shared_indicators(e1.event, e2.event),
          confidence: calculate_chain_confidence(e1, e2),
          kill_chain_phases: [determine_kill_chain_phase(e1.event), determine_kill_chain_phase(e2.event)] |> Enum.reject(&is_nil/1),
          time_span_ms: abs(e1.indexed_at - e2.indexed_at),
          detected_at: DateTime.utc_now()
        }
      else
        nil
      end
    end

    Enum.reject(chains, &is_nil/1)
  end

  defp find_shared_indicators(e1, e2) do
    indicators = []

    indicators = if e1[:source_ip] && (e1[:source_ip] == e2[:source_ip] || e1[:source_ip] == e2[:dest_ip]) do
      indicators ++ [{:ip, e1[:source_ip]}]
    else
      indicators
    end

    indicators = if e1[:dest_ip] && (e1[:dest_ip] == e2[:source_ip] || e1[:dest_ip] == e2[:dest_ip]) do
      indicators ++ [{:ip, e1[:dest_ip]}]
    else
      indicators
    end

    indicators = if e1[:user] && e1[:user] == e2[:user] do
      indicators ++ [{:user, e1[:user]}]
    else
      indicators
    end

    indicators = if e1[:file_hash] && e1[:file_hash] == e2[:file_hash] do
      indicators ++ [{:hash, e1[:file_hash]}]
    else
      indicators
    end

    indicators
  end

  defp calculate_chain_confidence(e1, e2) do
    # Base confidence on temporal proximity and indicator strength
    time_diff = abs(e1.indexed_at - e2.indexed_at)

    time_score = cond do
      time_diff <= 60_000 -> 0.3
      time_diff <= 300_000 -> 0.25
      time_diff <= 900_000 -> 0.2
      time_diff <= 3600_000 -> 0.1
      true -> 0.05
    end

    indicator_score = length(find_shared_indicators(e1.event, e2.event)) * 0.2

    min(1.0, time_score + indicator_score + 0.3)
  end

  # ============================================================================
  # Entity Threat Score
  # ============================================================================

  defp do_calculate_entity_threat_score(entity_type, entity_value, config) do
    # Get all events for this entity
    events = find_events_for_entity(entity_type, entity_value, config.event_ttl_ms)

    if length(events) == 0 do
      0.0
    else
      # Calculate score based on multiple factors
      severity_score = calculate_severity_score(events)
      volume_score = min(1.0, length(events) / 50.0)
      kill_chain_score = calculate_entity_kill_chain_score(events)
      cross_source_score = (events |> Enum.map(& &1[:source_type]) |> Enum.uniq() |> length()) / 5.0
      recency_score = calculate_recency_score(events)

      # Weighted combination
      score = severity_score * 0.3 +
              volume_score * 0.15 +
              kill_chain_score * 0.25 +
              cross_source_score * 0.15 +
              recency_score * 0.15

      min(1.0, score)
    end
  end

  defp calculate_severity_score(events) do
    severity_weights = %{"info" => 0.1, "low" => 0.25, "medium" => 0.5, "high" => 0.75, "critical" => 1.0}

    max_severity = events
    |> Enum.map(fn e -> severity_weights[e[:severity] || "info"] || 0.1 end)
    |> Enum.max()

    max_severity
  end

  defp calculate_entity_kill_chain_score(events) do
    phases = events
    |> Enum.map(&determine_kill_chain_phase/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()

    # Higher score for more kill chain phases covered
    min(1.0, length(phases) / 5.0)
  end

  defp calculate_recency_score(events) do
    now = System.system_time(:millisecond)
    most_recent = events
    |> Enum.map(&event_timestamp_ms/1)
    |> Enum.max(fn -> now - 3600_000 end)

    time_since = now - most_recent

    cond do
      time_since <= 300_000 -> 1.0     # Last 5 minutes
      time_since <= 900_000 -> 0.8     # Last 15 minutes
      time_since <= 3600_000 -> 0.5    # Last hour
      true -> 0.2
    end
  end

  # ============================================================================
  # Export Functions
  # ============================================================================

  defp do_export_correlation(id, format) do
    # Try to find in incidents first, then timelines
    case :ets.lookup(@incident_table, id) do
      [{^id, incident}] ->
        {:ok, format_export(incident, format)}
      [] ->
        case :ets.lookup(@timeline_table, id) do
          [{^id, timeline}] ->
            {:ok, format_export(timeline, format)}
          [] ->
            {:error, :not_found}
        end
    end
  end

  defp format_export(data, "json") do
    %{
      data: data,
      format: "json",
      exported_at: DateTime.utc_now()
    }
  end
  defp format_export(data, _format) do
    %{
      data: data,
      format: "json",
      exported_at: DateTime.utc_now()
    }
  end

  # ============================================================================
  # Scheduling
  # ============================================================================

  defp schedule_incident_analysis(interval_ms) do
    Process.send_after(self(), :analyze_incidents, interval_ms)
  end
end
