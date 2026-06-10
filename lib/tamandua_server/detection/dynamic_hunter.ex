defmodule TamanduaServer.Detection.DynamicHunter do
  @moduledoc """
  Dynamic Threat Hunting Engine

  Implements proactive threat detection capabilities inspired by Microsoft's
  Dynamic Threat Detection Agent. This module goes beyond reactive detection
  by continuously hunting for threats that may evade traditional rules.

  Key capabilities:
  - Proactive threat hunting for detection blind spots
  - False negative detection through pattern correlation
  - Anomaly pattern learning and adaptation
  - Cross-domain correlation (process, network, file, authentication)
  - Continuous background analysis with time-series trending
  - Attack chain reconstruction

  Architecture:
  - Background GenServer performing periodic hunts
  - ETS-backed pattern library for known attack TTPs
  - Statistical anomaly detection using z-scores and entropy
  - Integration with Detection.Engine for coordinated response
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Detection.{Engine, Correlator, Evidence}
  alias TamanduaServer.Agents.OrgLookup

  import Ecto.Query

  # Configuration
  @hunt_interval :timer.minutes(5)
  @deep_hunt_interval :timer.hours(1)
  @pattern_refresh_interval :timer.hours(6)
  @event_lookback_window :timer.hours(24)
  @statistical_threshold 2.5
  @entropy_threshold 0.85
  @min_sample_size 50

  # ETS tables for pattern storage
  @ttp_patterns_table :dynamic_hunter_ttp_patterns
  @baseline_table :dynamic_hunter_baselines
  @hunt_results_table :dynamic_hunter_results

  # Known attack TTP patterns organized by MITRE ATT&CK
  @attack_patterns %{
    # T1059 - Command and Scripting Interpreter
    command_execution: [
      %{
        name: "PowerShell Download Cradle",
        pattern: ~r/(?:iex|invoke-expression).*(?:downloadstring|downloadfile|webclient)/i,
        field: :cmdline,
        severity: :high,
        mitre: ["T1059.001", "T1105"]
      },
      %{
        name: "Encoded PowerShell",
        pattern: ~r/powershell.*-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{50,}/i,
        field: :cmdline,
        severity: :high,
        mitre: ["T1059.001", "T1027"]
      },
      %{
        name: "WMIC Process Call",
        pattern: ~r/wmic.*process.*call.*create/i,
        field: :cmdline,
        severity: :high,
        mitre: ["T1047"]
      }
    ],
    # T1055 - Process Injection
    process_injection: [
      %{
        name: "CreateRemoteThread Pattern",
        pattern: ~r/(?:createremotethread|ntcreatethreadex|rtlcreateuserthread)/i,
        field: :api_calls,
        severity: :critical,
        mitre: ["T1055.001"]
      },
      %{
        name: "Process Hollowing Indicators",
        pattern: ~r/(?:ntunmapviewofsection|zwunmapviewofsection).*(?:writeprocessmemory|ntwritevirtualmemory)/i,
        field: :api_calls,
        severity: :critical,
        mitre: ["T1055.012"]
      }
    ],
    # T1003 - Credential Access
    credential_access: [
      %{
        name: "LSASS Access Pattern",
        pattern: ~r/(?:lsass\.exe|sekurlsa|logonpasswords|wdigest)/i,
        field: [:cmdline, :target_process],
        severity: :critical,
        mitre: ["T1003.001"]
      },
      %{
        name: "SAM/SECURITY Hive Access",
        pattern: ~r/(?:reg\s+save|reg\.exe.*save).*(?:sam|security|system)/i,
        field: :cmdline,
        severity: :critical,
        mitre: ["T1003.002"]
      },
      %{
        name: "NTDS.dit Access",
        pattern: ~r/(?:ntdsutil|vssadmin|ntds\.dit)/i,
        field: [:cmdline, :path],
        severity: :critical,
        mitre: ["T1003.003"]
      }
    ],
    # T1021 - Lateral Movement
    lateral_movement: [
      %{
        name: "PsExec Pattern",
        pattern: ~r/(?:psexec|psexesvc|\\\\.*\\admin\$|\\\\.*\\c\$)/i,
        field: [:cmdline, :path],
        severity: :high,
        mitre: ["T1021.002", "T1570"]
      },
      %{
        name: "WinRM Lateral Movement",
        pattern: ~r/(?:winrs|invoke-command.*-computername|enter-pssession)/i,
        field: :cmdline,
        severity: :high,
        mitre: ["T1021.006"]
      }
    ],
    # T1486 - Data Encrypted for Impact (Ransomware)
    ransomware: [
      %{
        name: "Volume Shadow Deletion",
        pattern: ~r/(?:vssadmin|wmic).*(?:delete|shadows)/i,
        field: :cmdline,
        severity: :critical,
        mitre: ["T1490"]
      },
      %{
        name: "BCDEdit Boot Config Modification",
        pattern: ~r/bcdedit.*(?:recoveryenabled.*no|safeboot)/i,
        field: :cmdline,
        severity: :critical,
        mitre: ["T1490"]
      }
    ],
    # T1070 - Defense Evasion
    defense_evasion: [
      %{
        name: "Event Log Clearing",
        pattern: ~r/(?:wevtutil|clear-eventlog).*(?:cl|clear)/i,
        field: :cmdline,
        severity: :high,
        mitre: ["T1070.001"]
      },
      %{
        name: "Timestomping Indicators",
        pattern: ~r/(?:touch|setmace|timestomp|-creationtime|-lastaccesstime)/i,
        field: :cmdline,
        severity: :medium,
        mitre: ["T1070.006"]
      }
    ],
    # T1071 - Application Layer Protocol (C2)
    command_and_control: [
      %{
        name: "DNS Tunneling Indicators",
        pattern: ~r/(?:nslookup|dns).*(?:txt|mx|cname).*[a-z0-9]{30,}/i,
        field: [:cmdline, :dns_query],
        severity: :high,
        mitre: ["T1071.004"]
      }
    ]
  }

  # State structure
  defstruct [
    :stats,
    :last_hunt,
    :last_deep_hunt,
    :hunt_cycle,
    :active_investigations
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger an immediate threat hunt across all connected agents.
  """
  @spec hunt_now(keyword()) :: {:ok, map()} | {:error, term()}
  def hunt_now(opts \\ []) do
    GenServer.call(__MODULE__, {:hunt_now, opts}, 60_000)
  end

  @doc """
  Perform a deep investigation on a specific agent.
  """
  @spec investigate_agent(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def investigate_agent(agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:investigate_agent, agent_id, opts}, 120_000)
  end

  @doc """
  Analyze an event chain for attack patterns.
  """
  @spec analyze_attack_chain(String.t(), list()) :: {:ok, map()} | {:error, term()}
  def analyze_attack_chain(agent_id, event_ids) do
    GenServer.call(__MODULE__, {:analyze_chain, agent_id, event_ids}, 30_000)
  end

  @doc """
  Get current hunting statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get hunting results from the last cycle.
  """
  @spec get_recent_findings(keyword()) :: [map()]
  def get_recent_findings(opts \\ []) do
    GenServer.call(__MODULE__, {:get_findings, opts})
  end

  @doc """
  Register a custom hunting pattern.
  """
  @spec register_pattern(atom(), map()) :: :ok | {:error, term()}
  def register_pattern(category, pattern) do
    GenServer.call(__MODULE__, {:register_pattern, category, pattern})
  end

  @doc """
  Export current baselines for analysis.
  """
  @spec export_baselines() :: map()
  def export_baselines do
    GenServer.call(__MODULE__, :export_baselines)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@ttp_patterns_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@baseline_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@hunt_results_table, [:named_table, :bag, :public, read_concurrency: true])

    # Load attack patterns into ETS
    load_patterns()

    # Schedule periodic hunts
    schedule_hunt(@hunt_interval)
    schedule_deep_hunt(@deep_hunt_interval)
    schedule_pattern_refresh(@pattern_refresh_interval)

    state = %__MODULE__{
      stats: %{
        hunts_completed: 0,
        deep_hunts_completed: 0,
        threats_found: 0,
        false_negatives_detected: 0,
        patterns_matched: 0,
        anomalies_detected: 0
      },
      last_hunt: nil,
      last_deep_hunt: nil,
      hunt_cycle: 0,
      active_investigations: %{}
    }

    Logger.info("Dynamic Threat Hunter started with #{map_size(@attack_patterns)} pattern categories")
    {:ok, state}
  end

  @impl true
  def handle_call({:hunt_now, opts}, _from, state) do
    {findings, new_state} = perform_hunt(state, opts)
    {:reply, {:ok, %{findings: findings, stats: new_state.stats}}, new_state}
  end

  @impl true
  def handle_call({:investigate_agent, agent_id, opts}, _from, state) do
    result = perform_agent_investigation(agent_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:analyze_chain, agent_id, event_ids}, _from, state) do
    result = analyze_event_chain(agent_id, event_ids)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    enhanced_stats = Map.merge(state.stats, %{
      last_hunt: state.last_hunt,
      last_deep_hunt: state.last_deep_hunt,
      hunt_cycle: state.hunt_cycle,
      active_investigations: map_size(state.active_investigations)
    })
    {:reply, enhanced_stats, state}
  end

  @impl true
  def handle_call({:get_findings, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 100)
    since = Keyword.get(opts, :since, DateTime.add(DateTime.utc_now(), -24, :hour))

    findings = :ets.tab2list(@hunt_results_table)
    |> Enum.map(fn {_key, finding} -> finding end)
    |> Enum.filter(fn f -> DateTime.compare(f.timestamp, since) != :lt end)
    |> Enum.sort_by(& &1.severity_score, :desc)
    |> Enum.take(limit)

    {:reply, findings, state}
  end

  @impl true
  def handle_call({:register_pattern, category, pattern}, _from, state) do
    existing = :ets.lookup(@ttp_patterns_table, category)
    patterns = case existing do
      [{^category, list}] -> [pattern | list]
      [] -> [pattern]
    end
    :ets.insert(@ttp_patterns_table, {category, patterns})
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:export_baselines, _from, state) do
    baselines = :ets.tab2list(@baseline_table)
    |> Enum.into(%{})
    {:reply, baselines, state}
  end

  @impl true
  def handle_call({:analyze_blind_spots, opts}, _from, state) do
    # Analyze detection coverage gaps
    result = do_analyze_blind_spots(state, opts)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:find_false_negatives, opts}, _from, state) do
    # Find potential missed detections by analyzing historical data
    result = do_find_false_negatives(state, opts)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:proactive_hunt, opts}, _from, state) do
    # Perform proactive threat hunting based on current threat landscape
    {findings, new_state} = do_proactive_hunt(state, opts)
    {:reply, {:ok, %{findings: findings, stats: new_state.stats}}, new_state}
  end

  @impl true
  def handle_call(:status, _from, state) do
    status = %{
      running: true,
      hunt_cycle: state.hunt_cycle,
      last_hunt: state.last_hunt,
      last_deep_hunt: state.last_deep_hunt,
      active_investigations: map_size(state.active_investigations),
      baseline_count: :ets.info(@baseline_table, :size) || 0,
      pattern_count: :ets.info(@ttp_patterns_table, :size) || 0,
      findings_count: :ets.info(@hunt_results_table, :size) || 0,
      stats: state.stats
    }
    {:reply, {:ok, status}, state}
  end

  @impl true
  def handle_info(:periodic_hunt, state) do
    Logger.info("Starting periodic threat hunt (cycle #{state.hunt_cycle + 1})")
    {_findings, new_state} = perform_hunt(state, [])
    schedule_hunt(@hunt_interval)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:deep_hunt, state) do
    Logger.info("Starting deep threat hunt")
    {_findings, new_state} = perform_deep_hunt(state)
    schedule_deep_hunt(@deep_hunt_interval)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:refresh_patterns, state) do
    Logger.info("Refreshing attack patterns and baselines")
    refresh_baselines()
    schedule_pattern_refresh(@pattern_refresh_interval)
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Hunt Implementation
  # ============================================================================

  defp perform_hunt(state, opts) do
    lookback = Keyword.get(opts, :lookback, @event_lookback_window)
    since = DateTime.add(DateTime.utc_now(), -div(lookback, 1000), :second)

    findings = []

    # 1. TTP Pattern Matching Hunt
    ttp_findings = hunt_ttp_patterns(since)
    findings = findings ++ ttp_findings

    # 2. Statistical Anomaly Hunt
    anomaly_findings = hunt_statistical_anomalies(since)
    findings = findings ++ anomaly_findings

    # 3. Cross-Domain Correlation Hunt
    correlation_findings = hunt_cross_domain_correlations(since)
    findings = findings ++ correlation_findings

    # 4. False Negative Detection Hunt
    false_negative_findings = hunt_false_negatives(since)
    findings = findings ++ false_negative_findings

    # Store findings
    store_findings(findings)

    # Create alerts for significant findings
    create_hunt_alerts(findings)

    # Update statistics
    new_stats = %{state.stats |
      hunts_completed: state.stats.hunts_completed + 1,
      threats_found: state.stats.threats_found + length(findings),
      patterns_matched: state.stats.patterns_matched + length(ttp_findings),
      anomalies_detected: state.stats.anomalies_detected + length(anomaly_findings),
      false_negatives_detected: state.stats.false_negatives_detected + length(false_negative_findings)
    }

    new_state = %{state |
      stats: new_stats,
      last_hunt: DateTime.utc_now(),
      hunt_cycle: state.hunt_cycle + 1
    }

    Logger.info("Hunt completed: #{length(findings)} findings")
    {findings, new_state}
  end

  defp perform_deep_hunt(state) do
    since = DateTime.add(DateTime.utc_now(), -div(@event_lookback_window * 3, 1000), :second)

    findings = []

    # 1. Attack Chain Reconstruction
    chain_findings = hunt_attack_chains(since)
    findings = findings ++ chain_findings

    # 2. Time-Series Anomaly Detection
    timeseries_findings = hunt_timeseries_anomalies(since)
    findings = findings ++ timeseries_findings

    # 3. Behavioral Drift Detection
    drift_findings = hunt_behavioral_drift(since)
    findings = findings ++ drift_findings

    # Store and alert
    store_findings(findings)
    create_hunt_alerts(findings)

    new_stats = %{state.stats |
      deep_hunts_completed: state.stats.deep_hunts_completed + 1,
      threats_found: state.stats.threats_found + length(findings)
    }

    new_state = %{state |
      stats: new_stats,
      last_deep_hunt: DateTime.utc_now()
    }

    Logger.info("Deep hunt completed: #{length(findings)} findings")
    {findings, new_state}
  end

  # ============================================================================
  # TTP Pattern Hunting
  # ============================================================================

  defp hunt_ttp_patterns(since) do
    patterns = :ets.tab2list(@ttp_patterns_table)
    |> Enum.flat_map(fn {_category, pats} -> pats end)

    events = get_recent_events(since, [:process_create, :file_create, :network_connection])

    Enum.flat_map(events, fn event ->
      match_event_against_patterns(event, patterns)
    end)
  end

  defp match_event_against_patterns(event, patterns) do
    payload = event.payload || %{}

    Enum.flat_map(patterns, fn pattern ->
      fields = List.wrap(pattern.field)
      matched = Enum.any?(fields, fn field ->
        value = get_field_value(payload, field)
        value && Regex.match?(pattern.pattern, to_string(value))
      end)

      if matched do
        [%{
          type: :ttp_match,
          pattern_name: pattern.name,
          event_id: event.id,
          agent_id: event.agent_id,
          event_type: event.event_type,
          severity: pattern.severity,
          severity_score: severity_to_score(pattern.severity),
          mitre_techniques: pattern.mitre,
          description: "TTP pattern matched: #{pattern.name}",
          evidence: extract_evidence(event, pattern),
          timestamp: DateTime.utc_now()
        }]
      else
        []
      end
    end)
  end

  defp get_field_value(payload, field) when is_atom(field) do
    Map.get(payload, Atom.to_string(field)) || Map.get(payload, field)
  end

  defp get_field_value(payload, field) when is_binary(field) do
    Map.get(payload, field) || Map.get(payload, String.to_existing_atom(field))
  rescue
    _ -> Map.get(payload, field)
  end

  # ============================================================================
  # Statistical Anomaly Hunting
  # ============================================================================

  defp hunt_statistical_anomalies(since) do
    findings = []

    # 1. Event frequency anomalies
    frequency_anomalies = detect_frequency_anomalies(since)
    findings = findings ++ frequency_anomalies

    # 2. Entropy anomalies (command lines, file names)
    entropy_anomalies = detect_entropy_anomalies(since)
    findings = findings ++ entropy_anomalies

    # 3. Process tree depth anomalies
    tree_anomalies = detect_process_tree_anomalies(since)
    findings = findings ++ tree_anomalies

    findings
  end

  defp detect_frequency_anomalies(since) do
    # Get event counts per agent per event type
    events = get_recent_events(since, :all)
    |> Enum.group_by(fn e -> {e.agent_id, e.event_type} end)
    |> Enum.map(fn {{agent_id, event_type}, evts} ->
      {agent_id, event_type, length(evts)}
    end)

    # Calculate baseline statistics
    by_type = Enum.group_by(events, fn {_, type, _} -> type end)

    Enum.flat_map(by_type, fn {event_type, type_events} ->
      counts = Enum.map(type_events, fn {_, _, count} -> count end)

      if length(counts) >= @min_sample_size do
        mean = Enum.sum(counts) / length(counts)
        variance = Enum.sum(Enum.map(counts, fn c -> :math.pow(c - mean, 2) end)) / length(counts)
        stddev = :math.sqrt(variance)

        if stddev > 0 do
          Enum.flat_map(type_events, fn {agent_id, _, count} ->
            z_score = (count - mean) / stddev
            if abs(z_score) > @statistical_threshold do
              [%{
                type: :frequency_anomaly,
                agent_id: agent_id,
                event_type: event_type,
                severity: if(z_score > 4, do: :high, else: :medium),
                severity_score: if(z_score > 4, do: 80, else: 60),
                description: "Anomalous #{event_type} frequency: #{count} events (z=#{Float.round(z_score, 2)})",
                z_score: z_score,
                observed_count: count,
                expected_mean: mean,
                mitre_techniques: infer_technique_from_anomaly(event_type),
                timestamp: DateTime.utc_now()
              }]
            else
              []
            end
          end)
        else
          []
        end
      else
        []
      end
    end)
  end

  defp detect_entropy_anomalies(since) do
    events = get_recent_events(since, [:process_create])

    Enum.flat_map(events, fn event ->
      payload = event.payload || %{}
      cmdline = payload["cmdline"] || payload[:cmdline] || ""

      entropy = calculate_shannon_entropy(cmdline)

      if entropy > @entropy_threshold and String.length(cmdline) > 50 do
        [%{
          type: :entropy_anomaly,
          agent_id: event.agent_id,
          event_id: event.id,
          severity: :medium,
          severity_score: 65,
          description: "High entropy command line detected (entropy=#{Float.round(entropy, 3)})",
          entropy: entropy,
          cmdline_preview: String.slice(cmdline, 0, 100),
          mitre_techniques: ["T1027"],
          timestamp: DateTime.utc_now()
        }]
      else
        []
      end
    end)
  end

  defp detect_process_tree_anomalies(since) do
    # Get process creation events
    events = get_recent_events(since, [:process_create])
    |> Enum.group_by(& &1.agent_id)

    Enum.flat_map(events, fn {agent_id, agent_events} ->
      # Build simple parent-child relationships
      tree = build_process_tree(agent_events)

      # Find unusually deep chains
      Enum.flat_map(tree, fn {pid, info} ->
        depth = calculate_chain_depth(tree, pid, 0)
        if depth > 5 do
          [%{
            type: :deep_process_chain,
            agent_id: agent_id,
            severity: :medium,
            severity_score: 55,
            description: "Deep process chain detected (depth=#{depth})",
            depth: depth,
            process_name: info[:name],
            mitre_techniques: ["T1059"],
            timestamp: DateTime.utc_now()
          }]
        else
          []
        end
      end)
    end)
  end

  # ============================================================================
  # Cross-Domain Correlation Hunting
  # ============================================================================

  defp hunt_cross_domain_correlations(since) do
    findings = []

    # 1. Process spawned network connection to rare destination
    network_findings = correlate_process_network(since)
    findings = findings ++ network_findings

    # 2. File dropped then executed
    drop_exec_findings = correlate_file_execution(since)
    findings = findings ++ drop_exec_findings

    findings
  end

  defp correlate_process_network(since) do
    # Get processes that made network connections
    network_events = get_recent_events(since, [:network_connection])
    process_events = get_recent_events(since, [:process_create])

    network_by_agent_pid = Enum.group_by(network_events, fn e ->
      payload = e.payload || %{}
      {e.agent_id, payload["pid"] || payload[:pid]}
    end)

    Enum.flat_map(process_events, fn proc_event ->
      payload = proc_event.payload || %{}
      pid = payload["pid"] || payload[:pid]
      key = {proc_event.agent_id, pid}

      case Map.get(network_by_agent_pid, key) do
        nil -> []
        net_events ->
          # Check for suspicious network patterns after process creation
          rare_connections = Enum.filter(net_events, fn ne ->
            np = ne.payload || %{}
            port = np["remote_port"] || np[:remote_port]
            # Suspicious ports
            port in [4444, 5555, 8443, 1337, 31337, 6666, 6667]
          end)

          if length(rare_connections) > 0 do
            [%{
              type: :process_network_correlation,
              agent_id: proc_event.agent_id,
              severity: :high,
              severity_score: 75,
              description: "Process #{payload["name"]} made suspicious network connections",
              process_event_id: proc_event.id,
              network_event_ids: Enum.map(rare_connections, & &1.id),
              mitre_techniques: ["T1071", "T1059"],
              timestamp: DateTime.utc_now()
            }]
          else
            []
          end
      end
    end)
  end

  defp correlate_file_execution(since) do
    file_events = get_recent_events(since, [:file_create])
    process_events = get_recent_events(since, [:process_create])

    # Index file creations by path
    files_by_path = Enum.reduce(file_events, %{}, fn e, acc ->
      payload = e.payload || %{}
      path = payload["path"] || payload[:path]
      if path do
        Map.put(acc, {e.agent_id, String.downcase(path)}, e)
      else
        acc
      end
    end)

    # Find processes whose path matches a recently created file
    Enum.flat_map(process_events, fn proc_event ->
      payload = proc_event.payload || %{}
      path = payload["path"] || payload[:path]

      if path do
        key = {proc_event.agent_id, String.downcase(path)}
        case Map.get(files_by_path, key) do
          nil -> []
          file_event ->
            # File was created and then executed
            [%{
              type: :drop_and_execute,
              agent_id: proc_event.agent_id,
              severity: :high,
              severity_score: 80,
              description: "File dropped and executed: #{path}",
              file_event_id: file_event.id,
              process_event_id: proc_event.id,
              path: path,
              mitre_techniques: ["T1105", "T1059"],
              timestamp: DateTime.utc_now()
            }]
        end
      else
        []
      end
    end)
  end

  # ============================================================================
  # False Negative Detection
  # ============================================================================

  defp hunt_false_negatives(since) do
    # Look for events that should have triggered alerts but didn't
    events = get_recent_events(since, :all)

    # Find events with suspicious indicators but no associated alerts
    Enum.flat_map(events, fn event ->
      payload = event.payload || %{}
      cmdline = payload["cmdline"] || payload[:cmdline] || ""

      suspicious_indicators = [
        String.contains?(String.downcase(cmdline), "mimikatz"),
        String.contains?(String.downcase(cmdline), "invoke-mimikatz"),
        String.contains?(String.downcase(cmdline), "sekurlsa"),
        String.contains?(String.downcase(cmdline), "-nop -w hidden"),
        String.match?(cmdline, ~r/^MZ/),  # PE header in command line
      ]

      if Enum.any?(suspicious_indicators) do
        # Check if we already have an alert for this
        case check_alert_exists(event.id) do
          false ->
            [%{
              type: :potential_false_negative,
              agent_id: event.agent_id,
              event_id: event.id,
              severity: :critical,
              severity_score: 90,
              description: "Suspicious activity without corresponding alert detected",
              indicators: Enum.filter(suspicious_indicators, & &1),
              mitre_techniques: ["T1003", "T1059"],
              timestamp: DateTime.utc_now()
            }]
          true ->
            []
        end
      else
        []
      end
    end)
  end

  # ============================================================================
  # Attack Chain Analysis
  # ============================================================================

  defp hunt_attack_chains(since) do
    # Get events grouped by agent
    events = get_recent_events(since, :all)
    |> Enum.group_by(& &1.agent_id)

    Enum.flat_map(events, fn {agent_id, agent_events} ->
      chains = detect_attack_chains(agent_events)

      Enum.flat_map(chains, fn chain ->
        if length(chain.events) >= 3 do
          [%{
            type: :attack_chain,
            agent_id: agent_id,
            severity: :critical,
            severity_score: 95,
            description: "Attack chain detected: #{chain.description}",
            chain_events: Enum.map(chain.events, & &1.id),
            stages: chain.stages,
            mitre_techniques: chain.techniques,
            timestamp: DateTime.utc_now()
          }]
        else
          []
        end
      end)
    end)
  end

  defp detect_attack_chains(events) do
    # Sort by timestamp
    sorted = Enum.sort_by(events, & &1.timestamp, NaiveDateTime)

    # Look for known attack patterns
    chains = []

    # Pattern: Initial Access -> Execution -> Persistence
    initial_access = Enum.filter(sorted, fn e -> e.event_type in ["file_create", "email_attachment"] end)
    execution = Enum.filter(sorted, fn e -> e.event_type == "process_create" end)
    persistence = Enum.filter(sorted, fn e ->
      payload = e.payload || %{}
      path = payload["path"] || ""
      String.contains?(String.downcase(path), ["startup", "run", "services"])
    end)

    if length(initial_access) > 0 and length(execution) > 0 and length(persistence) > 0 do
      chain = %{
        events: Enum.take(initial_access, 1) ++ Enum.take(execution, 2) ++ Enum.take(persistence, 1),
        description: "Initial Access -> Execution -> Persistence",
        stages: [:initial_access, :execution, :persistence],
        techniques: ["T1566", "T1059", "T1547"]
      }
      [chain | chains]
    else
      chains
    end
  end

  # ============================================================================
  # Time Series Analysis
  # ============================================================================

  defp hunt_timeseries_anomalies(since) do
    # Get hourly event counts
    events = get_recent_events(since, :all)

    hourly_counts = events
    |> Enum.group_by(fn e ->
      NaiveDateTime.truncate(e.timestamp, :second)
      |> NaiveDateTime.to_date()
      |> Date.to_string()
    end)
    |> Enum.map(fn {date, evts} -> {date, length(evts)} end)
    |> Enum.sort_by(fn {date, _} -> date end)

    # Simple moving average anomaly detection
    if length(hourly_counts) >= 7 do
      counts = Enum.map(hourly_counts, fn {_, c} -> c end)
      moving_avg = calculate_moving_average(counts, 3)

      Enum.with_index(counts)
      |> Enum.drop(3)
      |> Enum.flat_map(fn {count, idx} ->
        avg = Enum.at(moving_avg, idx - 3, count)
        deviation = if avg > 0, do: (count - avg) / avg, else: 0

        if deviation > 1.5 do  # 150% increase
          [%{
            type: :timeseries_spike,
            severity: :medium,
            severity_score: 60,
            description: "Event volume spike detected: #{Float.round(deviation * 100, 1)}% above average",
            deviation_percent: deviation * 100,
            observed_count: count,
            expected_avg: avg,
            mitre_techniques: [],
            timestamp: DateTime.utc_now()
          }]
        else
          []
        end
      end)
    else
      []
    end
  end

  defp hunt_behavioral_drift(since) do
    # Compare recent behavior to baseline
    baselines = :ets.tab2list(@baseline_table) |> Enum.into(%{})

    if map_size(baselines) > 0 do
      events = get_recent_events(since, [:process_create])
      |> Enum.group_by(& &1.agent_id)

      Enum.flat_map(events, fn {agent_id, agent_events} ->
        baseline = Map.get(baselines, agent_id, %{})
        baseline_processes = Map.get(baseline, :processes, MapSet.new())

        current_processes = agent_events
        |> Enum.map(fn e ->
          payload = e.payload || %{}
          String.downcase(payload["name"] || payload[:name] || "")
        end)
        |> Enum.filter(& &1 != "")
        |> MapSet.new()

        new_processes = MapSet.difference(current_processes, baseline_processes)

        if MapSet.size(new_processes) > 5 do
          [%{
            type: :behavioral_drift,
            agent_id: agent_id,
            severity: :low,
            severity_score: 40,
            description: "#{MapSet.size(new_processes)} new processes observed",
            new_processes: MapSet.to_list(new_processes) |> Enum.take(10),
            mitre_techniques: [],
            timestamp: DateTime.utc_now()
          }]
        else
          []
        end
      end)
    else
      []
    end
  end

  # ============================================================================
  # Agent Investigation
  # ============================================================================

  defp perform_agent_investigation(agent_id, opts) do
    lookback = Keyword.get(opts, :lookback, @event_lookback_window * 2)
    since = DateTime.add(DateTime.utc_now(), -div(lookback, 1000), :second)

    # Get all events for this agent
    events = from(e in Event,
      where: e.agent_id == ^agent_id and e.timestamp >= ^since,
      order_by: [asc: e.timestamp]
    )
    |> Repo.all()

    if length(events) == 0 do
      {:error, :no_events}
    else
      findings = []

      # Pattern matching
      patterns = :ets.tab2list(@ttp_patterns_table)
      |> Enum.flat_map(fn {_category, pats} -> pats end)

      ttp_findings = Enum.flat_map(events, fn event ->
        match_event_against_patterns(event, patterns)
      end)
      findings = findings ++ ttp_findings

      # Process tree analysis
      case Correlator.get_process_tree(agent_id) do
        {:ok, _tree} ->
          # Add tree-based findings
          findings
        {:error, _} ->
          findings
      end

      {:ok, %{
        agent_id: agent_id,
        events_analyzed: length(events),
        findings: findings,
        timeline: build_timeline(events),
        risk_score: calculate_investigation_risk_score(findings)
      }}
    end
  end

  defp analyze_event_chain(agent_id, event_ids) do
    events = from(e in Event,
      where: e.agent_id == ^agent_id and e.id in ^event_ids,
      order_by: [asc: e.timestamp]
    )
    |> Repo.all()

    if length(events) == 0 do
      {:error, :events_not_found}
    else
      chains = detect_attack_chains(events)

      {:ok, %{
        events: events,
        chains: chains,
        timeline: build_timeline(events)
      }}
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp get_recent_events(since, :all) do
    from(e in Event,
      where: e.timestamp >= ^since,
      order_by: [asc: e.timestamp]
    )
    |> Repo.all()
  rescue
    _ -> []
  end

  defp get_recent_events(since, event_types) when is_list(event_types) do
    type_strings = Enum.map(event_types, &to_string/1)

    from(e in Event,
      where: e.timestamp >= ^since and e.event_type in ^type_strings,
      order_by: [asc: e.timestamp]
    )
    |> Repo.all()
  rescue
    _ -> []
  end

  defp load_patterns do
    Enum.each(@attack_patterns, fn {category, patterns} ->
      :ets.insert(@ttp_patterns_table, {category, patterns})
    end)
  end

  defp refresh_baselines do
    # In production, this would rebuild baselines from historical data
    Logger.debug("Baseline refresh triggered")
  end

  defp schedule_hunt(interval) do
    Process.send_after(self(), :periodic_hunt, interval)
  end

  defp schedule_deep_hunt(interval) do
    Process.send_after(self(), :deep_hunt, interval)
  end

  defp schedule_pattern_refresh(interval) do
    Process.send_after(self(), :refresh_patterns, interval)
  end

  defp store_findings(findings) do
    Enum.each(findings, fn finding ->
      :ets.insert(@hunt_results_table, {UUID.uuid4(), finding})
    end)
  end

  defp create_hunt_alerts(findings) do
    significant = Enum.filter(findings, fn f ->
      f.severity in [:high, :critical] or f.severity_score >= 70
    end)

    Enum.each(significant, fn finding ->
      # Extract the primary event_id for source_event_id
      event_id = finding[:event_id]
      event_ids = List.wrap(event_id || finding[:chain_events] || [])

      # Build a synthetic event from the hunt finding so Evidence.extract works
      finding_evidence = finding[:evidence] || %{}
      synthetic_event = %{
        payload: %{
          name: finding_evidence[:process_name],
          path: finding_evidence[:path],
          pid: finding_evidence[:pid],
          cmdline: finding_evidence[:cmdline],
          remote_ip: finding_evidence[:remote_ip],
          remote_port: finding_evidence[:remote_port],
          domain: finding_evidence[:domain],
          sha256: finding_evidence[:sha256],
          user: finding_evidence[:user]
        },
        event_type: finding[:event_type],
        agent_id: finding[:agent_id]
      }

      # Build a detection entry for Evidence.extract
      hunt_detection = %{
        type: :ttp_match,
        rule_name: finding[:pattern_name] || to_string(finding.type),
        description: finding.description,
        confidence: finding.severity_score / 100,
        mitre_techniques: finding.mitre_techniques || [],
        mitre_tactics: infer_tactics_from_techniques(finding.mitre_techniques || []),
        matched_pattern: finding_evidence[:cmdline],
        severity: finding.severity
      }

      # Use Evidence.extract for structured evidence
      evidence = Evidence.extract(synthetic_event, [hunt_detection])

      # Add hunt-specific context
      evidence = Map.put(evidence, :hunt_context, %{
        hunt_type: finding.type,
        pattern_name: finding[:pattern_name],
        severity_score: finding.severity_score,
        chain_events: finding[:chain_events]
      })

      # Build process chain from Storyline if we have agent_id and PID
      agent_id = finding[:agent_id]
      pid = finding_evidence[:pid]

      process_chain = if agent_id && pid do
        case Correlator.build_storyline(agent_id, pid) do
          {:ok, storyline} -> storyline.process_chain
          _ -> []
        end
      else
        []
      end

      # Generate contextual title using the centralized Evidence module builder
      title = Evidence.build_contextual_title(
        synthetic_event,
        [hunt_detection],
        finding.mitre_techniques
      )

      # Build detection_metadata from hunt finding
      detection_metadata = %{
        "rule_name" => finding[:pattern_name] || to_string(finding.type),
        "rule_type" => "dynamic_hunt",
        "confidence" => finding.severity_score / 100,
        "hunt_type" => to_string(finding.type),
        "event_type" => to_string(finding[:event_type] || "")
      }

      # Capture finding evidence as raw_event for forensic review
      raw_event = %{
        "finding_type" => to_string(finding.type),
        "pattern_name" => finding[:pattern_name],
        "severity_score" => finding.severity_score,
        "evidence" => finding[:evidence]
      }

      Alerts.create_alert(%{
        agent_id: agent_id,
        organization_id: finding[:organization_id] || OrgLookup.get_org_id(agent_id),
        severity: finding.severity,
        title: title,
        description: finding.description,
        source_event_id: event_id,
        event_ids: event_ids,
        evidence: evidence,
        process_chain: process_chain,
        raw_event: raw_event,
        detection_metadata: detection_metadata,
        mitre_tactics: infer_tactics_from_techniques(finding.mitre_techniques || []),
        mitre_techniques: finding.mitre_techniques || [],
        threat_score: finding.severity_score / 100
      })
    end)
  end

  defp infer_tactics_from_techniques(techniques) do
    techniques
    |> Enum.flat_map(fn technique ->
      case TamanduaServer.Detection.Mitre.get_technique(technique) do
        nil -> []
        tech -> tech.tactics
      end
    end)
    |> Enum.uniq()
  end

  # Map MITRE techniques or finding type to human-readable categories
  defp hunt_mitre_to_category(nil, finding_type), do: hunt_type_to_category(finding_type)
  defp hunt_mitre_to_category(technique, finding_type) do
    case technique do
      "T1003" <> _ -> "Credential Access"
      "T1055" <> _ -> "Process Injection"
      "T1059" <> _ -> "Command Execution"
      "T1021" <> _ -> "Lateral Movement"
      "T1047" <> _ -> "WMI Execution"
      "T1027" <> _ -> "Obfuscation"
      "T1105" <> _ -> "File Download"
      "T1071" <> _ -> "Command and Control"
      "T1486" <> _ -> "Ransomware"
      "T1490" <> _ -> "Recovery Inhibition"
      "T1070" <> _ -> "Defense Evasion"
      "T1218" <> _ -> "Signed Binary Abuse"
      "T1566" <> _ -> "Phishing"
      "T1547" <> _ -> "Persistence"
      "T1565" <> _ -> "Data Manipulation"
      _ -> hunt_type_to_category(finding_type)
    end
  end

  defp hunt_type_to_category(:ttp_match), do: "TTP Detection"
  defp hunt_type_to_category(:frequency_anomaly), do: "Statistical Anomaly"
  defp hunt_type_to_category(:entropy_anomaly), do: "Obfuscation"
  defp hunt_type_to_category(:process_network_correlation), do: "Process-Network Correlation"
  defp hunt_type_to_category(:drop_and_execute), do: "Dropped Executable"
  defp hunt_type_to_category(:attack_chain), do: "Attack Chain"
  defp hunt_type_to_category(:potential_false_negative), do: "Missed Detection"
  defp hunt_type_to_category(:deep_process_chain), do: "Deep Process Chain"
  defp hunt_type_to_category(:timeseries_spike), do: "Activity Spike"
  defp hunt_type_to_category(:behavioral_drift), do: "Behavioral Drift"
  defp hunt_type_to_category(_), do: "Threat Hunt"

  defp check_alert_exists(event_id) do
    # Check if alert exists for this event
    query = from(a in TamanduaServer.Alerts.Alert,
      where: ^event_id in a.event_ids,
      limit: 1
    )

    case Repo.one(query) do
      nil -> false
      _ -> true
    end
  rescue
    _ -> false
  end

  defp severity_to_score(:critical), do: 95
  defp severity_to_score(:high), do: 80
  defp severity_to_score(:medium), do: 60
  defp severity_to_score(:low), do: 40
  defp severity_to_score(_), do: 50

  defp calculate_shannon_entropy(string) when is_binary(string) and byte_size(string) > 0 do
    freqs = string
    |> String.graphemes()
    |> Enum.frequencies()

    total = String.length(string)

    -Enum.reduce(freqs, 0.0, fn {_char, count}, acc ->
      p = count / total
      acc + p * :math.log2(p)
    end) / :math.log2(256)
  end

  defp calculate_shannon_entropy(_), do: 0.0

  defp build_process_tree(events) do
    Enum.reduce(events, %{}, fn event, acc ->
      payload = event.payload || %{}
      pid = payload["pid"] || payload[:pid]
      ppid = payload["ppid"] || payload[:ppid]
      name = payload["name"] || payload[:name]

      if pid do
        Map.put(acc, pid, %{name: name, ppid: ppid, event_id: event.id})
      else
        acc
      end
    end)
  end

  defp calculate_chain_depth(tree, pid, depth) when depth > 10, do: depth

  defp calculate_chain_depth(tree, pid, depth) do
    case Map.get(tree, pid) do
      nil -> depth
      %{ppid: nil} -> depth
      %{ppid: ppid} -> calculate_chain_depth(tree, ppid, depth + 1)
    end
  end

  defp calculate_moving_average(values, window) do
    values
    |> Enum.chunk_every(window, 1, :discard)
    |> Enum.map(fn chunk -> Enum.sum(chunk) / length(chunk) end)
  end

  defp build_timeline(events) do
    Enum.map(events, fn event ->
      %{
        event_id: event.id,
        event_type: event.event_type,
        timestamp: event.timestamp,
        summary: summarize_event(event)
      }
    end)
  end

  defp summarize_event(event) do
    payload = event.payload || %{}
    case event.event_type do
      "process_create" -> "Process: #{payload["name"] || payload[:name]}"
      "file_create" -> "File created: #{payload["path"] || payload[:path]}"
      "network_connection" -> "Network: #{payload["remote_ip"] || payload[:remote_ip]}"
      _ -> event.event_type
    end
  end

  defp calculate_investigation_risk_score(findings) do
    if length(findings) == 0 do
      0
    else
      max_score = findings
      |> Enum.map(& &1.severity_score)
      |> Enum.max()

      # Boost score based on finding count
      boost = min(length(findings) * 2, 20)
      min(max_score + boost, 100)
    end
  end

  defp do_analyze_blind_spots(state, opts) do
    # Analyze detection coverage by examining what TTPs are not being detected
    time_range = Map.get(opts, :time_range, :last_7d)

    # Get current detection coverage from baselines
    baselines = :ets.tab2list(@baseline_table) |> Enum.into(%{})

    # Get TTP patterns we're monitoring
    ttp_patterns = :ets.tab2list(@ttp_patterns_table) |> Enum.into(%{})

    # Analyze coverage gaps
    mitre_tactics = [:initial_access, :execution, :persistence, :privilege_escalation,
                     :defense_evasion, :credential_access, :discovery, :lateral_movement,
                     :collection, :command_control, :exfiltration, :impact]

    coverage = Enum.map(mitre_tactics, fn tactic ->
      patterns = Map.get(ttp_patterns, tactic, [])
      has_baseline = Map.has_key?(baselines, tactic)

      %{
        tactic: tactic,
        pattern_count: length(patterns),
        has_baseline: has_baseline,
        coverage_score: calculate_tactic_coverage_score(patterns, has_baseline),
        gaps: identify_tactic_gaps(tactic, patterns)
      }
    end)

    uncovered_tactics = Enum.filter(coverage, &(&1.coverage_score < 50))

    %{
      time_range: time_range,
      total_tactics: length(mitre_tactics),
      covered_tactics: length(mitre_tactics) - length(uncovered_tactics),
      coverage_percentage: Float.round((1 - length(uncovered_tactics) / length(mitre_tactics)) * 100, 1),
      blind_spots: uncovered_tactics,
      recommendations: generate_coverage_recommendations(uncovered_tactics),
      hunt_cycle: state.hunt_cycle
    }
  end

  defp calculate_tactic_coverage_score(patterns, has_baseline) do
    base_score = if has_baseline, do: 30, else: 0
    pattern_score = min(length(patterns) * 15, 70)
    base_score + pattern_score
  end

  defp identify_tactic_gaps(tactic, patterns) do
    # Define expected patterns per tactic
    expected = %{
      initial_access: [:phishing, :exploit_public_app, :valid_accounts],
      execution: [:powershell, :cmd, :script_execution, :scheduled_task],
      persistence: [:registry_run_key, :scheduled_task, :service_creation],
      credential_access: [:lsass_access, :credential_dump, :keylogging]
    }

    expected_for_tactic = Map.get(expected, tactic, [])
    covered = Enum.map(patterns, & &1[:name] || &1[:type]) |> Enum.map(&to_string/1)

    expected_for_tactic
    |> Enum.filter(fn exp -> not Enum.any?(covered, &String.contains?(&1, to_string(exp))) end)
  end

  defp generate_coverage_recommendations(uncovered_tactics) do
    Enum.flat_map(uncovered_tactics, fn %{tactic: tactic} ->
      case tactic do
        :initial_access -> ["Add phishing detection rules", "Monitor external-facing services"]
        :execution -> ["Enable command-line logging", "Add script block logging"]
        :persistence -> ["Monitor registry run keys", "Track scheduled task creation"]
        :credential_access -> ["Enable LSASS protection monitoring", "Track credential access patterns"]
        _ -> ["Add detection rules for #{tactic}"]
      end
    end)
    |> Enum.uniq()
  end

  defp do_find_false_negatives(state, opts) do
    # Analyze historical data to find events that should have triggered alerts but didn't
    time_range = Map.get(opts, :time_range, :last_24h)
    since = case time_range do
      :last_hour -> DateTime.add(DateTime.utc_now(), -3600, :second)
      :last_24h -> DateTime.add(DateTime.utc_now(), -86400, :second)
      :last_7d -> DateTime.add(DateTime.utc_now(), -604800, :second)
      _ -> DateTime.add(DateTime.utc_now(), -86400, :second)
    end

    # Query events that match suspicious patterns but didn't generate alerts
    suspicious_events = hunt_ttp_patterns(since)
    |> Enum.filter(&(&1.severity_score >= 50))

    %{
      time_range: time_range,
      potential_false_negatives: length(suspicious_events),
      events: Enum.take(suspicious_events, 50),
      categories: suspicious_events
        |> Enum.group_by(& &1.category)
        |> Enum.map(fn {cat, evts} -> {cat, length(evts)} end)
        |> Map.new(),
      recommendations: [
        "Review events with severity >= 50 that didn't trigger alerts",
        "Consider lowering detection thresholds for high-risk TTPs",
        "Add correlation rules for multi-stage attacks"
      ],
      hunt_cycle: state.hunt_cycle
    }
  end

  defp do_proactive_hunt(state, opts) do
    # Perform a comprehensive proactive hunt
    focus_areas = Map.get(opts, :focus_areas, [:all])
    lookback = Map.get(opts, :lookback_hours, 24)

    since = DateTime.add(DateTime.utc_now(), -lookback * 3600, :second)

    findings = []

    # Hunt based on focus areas
    findings = if :all in focus_areas or :ttp in focus_areas do
      findings ++ hunt_ttp_patterns(since)
    else
      findings
    end

    findings = if :all in focus_areas or :anomaly in focus_areas do
      findings ++ hunt_statistical_anomalies(since)
    else
      findings
    end

    # Store findings
    Enum.each(findings, fn finding ->
      :ets.insert(@hunt_results_table, {{finding.id, finding.timestamp}, finding})
    end)

    # Update stats
    new_stats = %{state.stats |
      total_hunts: (state.stats[:total_hunts] || 0) + 1,
      total_findings: (state.stats[:total_findings] || 0) + length(findings)
    }

    new_state = %{state |
      last_hunt: DateTime.utc_now(),
      stats: new_stats
    }

    {findings, new_state}
  end

  defp extract_evidence(event, pattern) do
    payload = event.payload || %{}
    %{
      event_type: event.event_type,
      pattern_name: pattern.name,
      matched_fields: List.wrap(pattern.field),
      cmdline: String.slice(to_string(payload["cmdline"] || payload[:cmdline] || ""), 0, 200),
      path: payload["path"] || payload[:path],
      process_name: payload["name"] || payload[:name]
    }
  end

  defp infer_technique_from_anomaly("process_create"), do: ["T1059"]
  defp infer_technique_from_anomaly("network_connection"), do: ["T1071"]
  defp infer_technique_from_anomaly("file_create"), do: ["T1105"]
  defp infer_technique_from_anomaly("file_modify"), do: ["T1565"]
  defp infer_technique_from_anomaly(_), do: []

  # ============================================================================
  # Public API Wrapper Functions
  # ============================================================================

  @doc """
  Analyze blind spots in detection coverage.
  """
  def analyze_blind_spots(opts \\ %{}) do
    GenServer.call(__MODULE__, {:analyze_blind_spots, opts}, 60_000)
  end

  @doc """
  Find potential false negatives by analyzing historical data.
  """
  def find_false_negatives(opts \\ %{}) do
    GenServer.call(__MODULE__, {:find_false_negatives, opts}, 60_000)
  end

  @doc """
  Perform proactive threat hunting.
  """
  def proactive_hunt(opts \\ %{}) do
    GenServer.call(__MODULE__, {:proactive_hunt, opts}, 120_000)
  end

  @doc """
  Get the current status of the dynamic hunter.
  """
  def status do
    GenServer.call(__MODULE__, :status)
  end

  @doc """
  Get the detection feed with optional filters.
  Returns recent hunt findings as detection events.
  """
  @spec get_detection_feed(keyword() | map()) :: {:ok, [map()]}
  def get_detection_feed(opts \\ []) do
    limit = if is_list(opts), do: Keyword.get(opts, :limit, 50), else: Map.get(opts, :limit, 50)

    findings = try do
      :ets.tab2list(@hunt_results_table)
      |> Enum.map(fn {_key, finding} -> finding end)
      |> Enum.sort_by(& &1[:timestamp], {:desc, DateTime})
      |> Enum.take(limit)
      |> Enum.map(fn finding ->
        %{
          id: finding[:id] || UUID.uuid4(),
          timestamp: finding[:timestamp],
          rule_name: finding[:pattern_name] || finding[:description] || to_string(finding[:type]),
          rule_type: detect_rule_type(finding[:type]),
          severity: to_string(finding[:severity] || :medium),
          agent_id: finding[:agent_id],
          hostname: finding[:hostname],
          description: finding[:description] || "",
          confidence: finding[:severity_score] && finding[:severity_score] / 100.0,
          mitre_techniques: finding[:mitre_techniques] || []
        }
      end)
    rescue
      _ -> []
    end

    {:ok, findings}
  end

  @doc """
  Get emerging threats detected by the system.
  Groups recent findings by pattern to identify emerging threat trends.
  """
  @spec get_emerging_threats() :: {:ok, [map()]}
  def get_emerging_threats do
    threats = try do
      since = DateTime.add(DateTime.utc_now(), -7 * 24, :hour)

      :ets.tab2list(@hunt_results_table)
      |> Enum.map(fn {_key, finding} -> finding end)
      |> Enum.filter(fn f ->
        f[:timestamp] && DateTime.compare(f[:timestamp], since) != :lt
      end)
      |> Enum.group_by(fn f -> f[:pattern_name] || f[:description] || to_string(f[:type]) end)
      |> Enum.filter(fn {_name, occurrences} -> length(occurrences) >= 2 end)
      |> Enum.map(fn {name, occurrences} ->
        agents = occurrences |> Enum.map(& &1[:agent_id]) |> Enum.uniq() |> Enum.reject(&is_nil/1)
        first = Enum.min_by(occurrences, & &1[:timestamp], DateTime)
        max_severity = occurrences |> Enum.map(& &1[:severity_score] || 0) |> Enum.max()

        %{
          id: UUID.uuid4(),
          name: name,
          first_seen: first[:timestamp],
          occurrences: length(occurrences),
          affected_hosts: length(agents),
          risk_level: cond do
            max_severity >= 80 -> "critical"
            max_severity >= 60 -> "high"
            max_severity >= 40 -> "medium"
            true -> "low"
          end,
          mitre_techniques: occurrences |> Enum.flat_map(& &1[:mitre_techniques] || []) |> Enum.uniq(),
          indicators: occurrences |> Enum.flat_map(fn o ->
            evidence = o[:evidence] || %{}
            [evidence[:path], evidence[:cmdline]] |> Enum.reject(&is_nil/1)
          end) |> Enum.uniq() |> Enum.take(5)
        }
      end)
      |> Enum.sort_by(& &1[:occurrences], :desc)
    rescue
      _ -> []
    end

    {:ok, threats}
  end

  @doc """
  List all dynamic detection rules.
  Returns TTP patterns loaded in ETS as dynamic rules.
  """
  @spec list_dynamic_rules() :: {:ok, [map()]}
  def list_dynamic_rules do
    rules = try do
      :ets.tab2list(@ttp_patterns_table)
      |> Enum.flat_map(fn {category, patterns} ->
        Enum.map(patterns, fn pattern ->
          %{
            id: "#{category}_#{pattern.name}" |> String.replace(~r/\s+/, "_") |> String.downcase(),
            name: pattern.name,
            status: "active",
            generated_at: nil,
            triggered_count: 0,
            false_positive_rate: 0.0,
            based_on: to_string(category),
            description: "TTP pattern: #{pattern.name} (#{Enum.join(pattern.mitre, ", ")})"
          }
        end)
      end)
    rescue
      _ -> []
    end

    {:ok, rules}
  end

  defp detect_rule_type(:ttp_match), do: "ttp_pattern"
  defp detect_rule_type(:frequency_anomaly), do: "statistical"
  defp detect_rule_type(:entropy_anomaly), do: "statistical"
  defp detect_rule_type(:process_network_correlation), do: "correlation"
  defp detect_rule_type(:drop_and_execute), do: "correlation"
  defp detect_rule_type(:attack_chain), do: "chain_analysis"
  defp detect_rule_type(:potential_false_negative), do: "false_negative"
  defp detect_rule_type(:timeseries_spike), do: "statistical"
  defp detect_rule_type(:behavioral_drift), do: "behavioral"
  defp detect_rule_type(:deep_process_chain), do: "process_analysis"
  defp detect_rule_type(_), do: "dynamic"
end
